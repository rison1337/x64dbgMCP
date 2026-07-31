#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (__cdecl *fixture_add_fn)(int, int);

typedef struct mapped_image {
    BYTE *base;
    DWORD size;
    DWORD headers_size;
    BOOL relocations_applied;
    BOOL imports_resolved;
    BOOL tls_called;
#ifdef _WIN64
    PRUNTIME_FUNCTION runtime_functions;
    BOOL runtime_functions_registered;
#endif
} mapped_image;

static BOOL range_valid(SIZE_T file_size, DWORD offset, SIZE_T size)
{
    return (SIZE_T)offset <= file_size && size <= file_size - (SIZE_T)offset;
}

static BYTE *read_file_bytes(const char *path, DWORD *size_out)
{
    HANDLE file;
    LARGE_INTEGER length;
    BYTE *bytes;
    DWORD read_count = 0;

    *size_out = 0;
    file = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    if (!GetFileSizeEx(file, &length)
        || length.QuadPart <= 0
        || length.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(file);
        return NULL;
    }
    bytes = (BYTE *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)length.QuadPart);
    if (bytes == NULL) {
        CloseHandle(file);
        return NULL;
    }
    if (!ReadFile(file, bytes, (DWORD)length.QuadPart, &read_count, NULL)
        || read_count != (DWORD)length.QuadPart) {
        HeapFree(GetProcessHeap(), 0, bytes);
        CloseHandle(file);
        return NULL;
    }
    CloseHandle(file);
    *size_out = read_count;
    return bytes;
}

static DWORD section_protection(DWORD characteristics)
{
    BOOL executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (executable) {
        if (writable) {
            return PAGE_EXECUTE_READWRITE;
        }
        return readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }
    if (writable) {
        return readable ? PAGE_READWRITE : PAGE_WRITECOPY;
    }
    return readable ? PAGE_READONLY : PAGE_NOACCESS;
}

static BOOL apply_relocations(
    BYTE *image,
    PIMAGE_NT_HEADERS nt,
    mapped_image *result
)
{
    ULONG_PTR preferred = (ULONG_PTR)nt->OptionalHeader.ImageBase;
    ULONG_PTR actual = (ULONG_PTR)image;
    ULONG_PTR delta = actual - preferred;
    IMAGE_DATA_DIRECTORY directory;
    DWORD cursor = 0;

    if (delta == 0) {
        return TRUE;
    }
    directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_BASE_RELOCATION)) {
        return FALSE;
    }
    while (cursor + sizeof(IMAGE_BASE_RELOCATION) <= directory.Size) {
        PIMAGE_BASE_RELOCATION block =
            (PIMAGE_BASE_RELOCATION)(image + directory.VirtualAddress + cursor);
        DWORD entries_size;
        DWORD entry_count;
        DWORD index;
        PWORD entries;

        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)
            || cursor + block->SizeOfBlock > directory.Size) {
            return FALSE;
        }
        entries_size = block->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION);
        entry_count = entries_size / sizeof(WORD);
        entries = (PWORD)(block + 1);
        for (index = 0; index < entry_count; ++index) {
            WORD encoded = entries[index];
            WORD type = encoded >> 12;
            WORD offset = encoded & 0x0FFF;
            BYTE *target = image + block->VirtualAddress + offset;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }
#ifdef _WIN64
            if (type != IMAGE_REL_BASED_DIR64) {
                return FALSE;
            }
            *(ULONGLONG *)target += (ULONGLONG)delta;
#else
            if (type != IMAGE_REL_BASED_HIGHLOW) {
                return FALSE;
            }
            *(DWORD *)target += (DWORD)delta;
#endif
        }
        cursor += block->SizeOfBlock;
    }
    result->relocations_applied = TRUE;
    return TRUE;
}

static BOOL resolve_imports(
    BYTE *image,
    PIMAGE_NT_HEADERS nt,
    mapped_image *result
)
{
    IMAGE_DATA_DIRECTORY directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR descriptor;

    if (directory.VirtualAddress == 0 || directory.Size == 0) {
        result->imports_resolved = TRUE;
        return TRUE;
    }
    descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(image + directory.VirtualAddress);
    while (descriptor->Name != 0) {
        const char *module_name = (const char *)(image + descriptor->Name);
        HMODULE module = LoadLibraryA(module_name);
        PIMAGE_THUNK_DATA original;
        PIMAGE_THUNK_DATA resolved;

        if (module == NULL) {
            return FALSE;
        }
        original = descriptor->OriginalFirstThunk != 0
            ? (PIMAGE_THUNK_DATA)(image + descriptor->OriginalFirstThunk)
            : (PIMAGE_THUNK_DATA)(image + descriptor->FirstThunk);
        resolved = (PIMAGE_THUNK_DATA)(image + descriptor->FirstThunk);
        while (original->u1.AddressOfData != 0) {
            FARPROC procedure;
            if (IMAGE_SNAP_BY_ORDINAL(original->u1.Ordinal)) {
                procedure = GetProcAddress(
                    module,
                    (LPCSTR)IMAGE_ORDINAL(original->u1.Ordinal)
                );
            } else {
                PIMAGE_IMPORT_BY_NAME name =
                    (PIMAGE_IMPORT_BY_NAME)(image + original->u1.AddressOfData);
                procedure = GetProcAddress(module, (LPCSTR)name->Name);
            }
            if (procedure == NULL) {
                return FALSE;
            }
            resolved->u1.Function = (ULONG_PTR)procedure;
            ++original;
            ++resolved;
        }
        ++descriptor;
    }
    result->imports_resolved = TRUE;
    return TRUE;
}

static void call_tls_callbacks(
    BYTE *image,
    PIMAGE_NT_HEADERS nt,
    mapped_image *result
)
{
    IMAGE_DATA_DIRECTORY directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    PIMAGE_TLS_CALLBACK *callback;

    if (directory.VirtualAddress == 0 || directory.Size == 0) {
        return;
    }
#ifdef _WIN64
    callback = (PIMAGE_TLS_CALLBACK *)(ULONG_PTR)
        ((PIMAGE_TLS_DIRECTORY64)(image + directory.VirtualAddress))->AddressOfCallBacks;
#else
    callback = (PIMAGE_TLS_CALLBACK *)(ULONG_PTR)
        ((PIMAGE_TLS_DIRECTORY32)(image + directory.VirtualAddress))->AddressOfCallBacks;
#endif
    if (callback == NULL) {
        return;
    }
    while (*callback != NULL) {
        (*callback)((PVOID)image, DLL_PROCESS_ATTACH, NULL);
        ++callback;
        result->tls_called = TRUE;
    }
}

static BOOL protect_image(BYTE *image, PIMAGE_NT_HEADERS nt)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    WORD index;
    DWORD old_protection;

    for (index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        SIZE_T size = section[index].Misc.VirtualSize;
        DWORD protection = section_protection(section[index].Characteristics);
        if (size == 0) {
            size = section[index].SizeOfRawData;
        }
        if (size != 0
            && !VirtualProtect(
                image + section[index].VirtualAddress,
                size,
                protection,
                &old_protection
            )) {
            return FALSE;
        }
    }
    return FlushInstructionCache(GetCurrentProcess(), image, nt->OptionalHeader.SizeOfImage);
}

static FARPROC find_export(BYTE *image, PIMAGE_NT_HEADERS nt, const char *wanted)
{
    IMAGE_DATA_DIRECTORY directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exports;
    PDWORD names;
    PWORD ordinals;
    PDWORD functions;
    DWORD index;

    if (directory.VirtualAddress == 0 || directory.Size == 0) {
        return NULL;
    }
    exports = (PIMAGE_EXPORT_DIRECTORY)(image + directory.VirtualAddress);
    names = (PDWORD)(image + exports->AddressOfNames);
    ordinals = (PWORD)(image + exports->AddressOfNameOrdinals);
    functions = (PDWORD)(image + exports->AddressOfFunctions);
    for (index = 0; index < exports->NumberOfNames; ++index) {
        const char *name = (const char *)(image + names[index]);
        if (strcmp(name, wanted) == 0) {
            DWORD rva = functions[ordinals[index]];
            if (rva >= directory.VirtualAddress
                && rva < directory.VirtualAddress + directory.Size) {
                return NULL;
            }
            return (FARPROC)(image + rva);
        }
    }
    return NULL;
}

static BOOL map_image(
    const BYTE *file_bytes,
    DWORD file_size,
    mapped_image *result,
    PIMAGE_NT_HEADERS *nt_out
)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS source_nt;
    PIMAGE_SECTION_HEADER source_section;
    BYTE *image;
    WORD index;

    ZeroMemory(result, sizeof(*result));
    if (file_size < sizeof(IMAGE_DOS_HEADER)) {
        return FALSE;
    }
    dos = (PIMAGE_DOS_HEADER)file_bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE
        || dos->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)
        || !range_valid(file_size, (DWORD)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) {
        return FALSE;
    }
    source_nt = (PIMAGE_NT_HEADERS)(file_bytes + dos->e_lfanew);
    if (source_nt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
#ifdef _WIN64
    if (source_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
        || source_nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return FALSE;
    }
#else
    if (source_nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
        || source_nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return FALSE;
    }
#endif
    image = (BYTE *)VirtualAlloc(
        NULL,
        source_nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (image == NULL) {
        return FALSE;
    }
    if (!range_valid(
            file_size,
            0,
            source_nt->OptionalHeader.SizeOfHeaders
        )) {
        VirtualFree(image, 0, MEM_RELEASE);
        return FALSE;
    }
    CopyMemory(image, file_bytes, source_nt->OptionalHeader.SizeOfHeaders);
    source_section = IMAGE_FIRST_SECTION(source_nt);
    for (index = 0; index < source_nt->FileHeader.NumberOfSections; ++index) {
        DWORD raw_size = source_section[index].SizeOfRawData;
        if (raw_size == 0) {
            continue;
        }
        if (!range_valid(file_size, source_section[index].PointerToRawData, raw_size)
            || source_section[index].VirtualAddress + raw_size
                > source_nt->OptionalHeader.SizeOfImage) {
            VirtualFree(image, 0, MEM_RELEASE);
            return FALSE;
        }
        CopyMemory(
            image + source_section[index].VirtualAddress,
            file_bytes + source_section[index].PointerToRawData,
            raw_size
        );
    }
    result->base = image;
    result->size = source_nt->OptionalHeader.SizeOfImage;
    result->headers_size = source_nt->OptionalHeader.SizeOfHeaders;
    *nt_out = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    if (!apply_relocations(image, *nt_out, result)
        || !resolve_imports(image, *nt_out, result)) {
        VirtualFree(image, 0, MEM_RELEASE);
        ZeroMemory(result, sizeof(*result));
        return FALSE;
    }
#ifdef _WIN64
    {
        IMAGE_DATA_DIRECTORY exception_directory =
            (*nt_out)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exception_directory.VirtualAddress != 0
            && exception_directory.Size >= sizeof(RUNTIME_FUNCTION)) {
            result->runtime_functions =
                (PRUNTIME_FUNCTION)(image + exception_directory.VirtualAddress);
            result->runtime_functions_registered = RtlAddFunctionTable(
                result->runtime_functions,
                exception_directory.Size / (DWORD)sizeof(RUNTIME_FUNCTION),
                (DWORD64)(ULONG_PTR)image
            );
            if (!result->runtime_functions_registered) {
                VirtualFree(image, 0, MEM_RELEASE);
                ZeroMemory(result, sizeof(*result));
                return FALSE;
            }
        }
    }
#endif
    if (!protect_image(image, *nt_out)) {
        return FALSE;
    }
    call_tls_callbacks(image, *nt_out, result);
    if ((*nt_out)->OptionalHeader.AddressOfEntryPoint != 0) {
        BOOL (WINAPI *entry)(HINSTANCE, DWORD, LPVOID) =
            (BOOL (WINAPI *)(HINSTANCE, DWORD, LPVOID))
            (image + (*nt_out)->OptionalHeader.AddressOfEntryPoint);
        if (!entry((HINSTANCE)image, DLL_PROCESS_ATTACH, NULL)) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL destroy_headers(mapped_image *image)
{
    DWORD old_protection;
    DWORD ignored;
    if (!VirtualProtect(
            image->base,
            image->headers_size,
            PAGE_READWRITE,
            &old_protection
        )) {
        return FALSE;
    }
    SecureZeroMemory(image->base, image->headers_size);
    return VirtualProtect(
        image->base,
        image->headers_size,
        PAGE_NOACCESS,
        &ignored
    );
}

static int run_embedded_copy(
    const BYTE *file_bytes,
    DWORD file_size,
    DWORD hold_ms,
    BOOL debug_break
)
{
    const DWORD offset = 0x600;
    BYTE *allocation = (BYTE *)VirtualAlloc(
        NULL,
        (SIZE_T)file_size + offset,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (allocation == NULL) {
        return 20;
    }
    CopyMemory(allocation + offset, file_bytes, file_size);
    printf(
        "REFLECTIVE_EMBED_OK offset=0x%X size=%lu base=0x%p\n",
        offset,
        (unsigned long)file_size,
        (void *)(allocation + offset)
    );
    fflush(stdout);
    if (debug_break) {
        DebugBreak();
    }
    if (hold_ms != 0) {
        Sleep(hold_ms);
    }
    return 0;
}

static int run_smoke_load(const char *payload_path)
{
    HMODULE module = LoadLibraryA(payload_path);
    FARPROC export_address;
    fixture_add_fn fixture_add;
    int result;

    if (module == NULL) {
        fprintf(stderr, "smoke LoadLibrary failed error=%lu\n", GetLastError());
        return 30;
    }
    export_address = GetProcAddress(module, "FixtureAdd");
    if (export_address == NULL) {
        fprintf(stderr, "smoke GetProcAddress failed error=%lu\n", GetLastError());
        return 31;
    }
    fixture_add = (fixture_add_fn)export_address;
    result = fixture_add(19, 23);
    printf("MANUAL_DUMP_SMOKE_OK result=%d\n", result);
    fflush(stdout);
    FreeLibrary(module);
    return result == 42 ? 0 : 32;
}

int main(int argc, char **argv)
{
    const char *payload_path = "fixture_module.dll";
    BOOL embedded = FALSE;
    BOOL smoke = FALSE;
    BOOL erase_headers = FALSE;
    BOOL debug_break = FALSE;
    DWORD hold_ms = 0;
    DWORD file_size;
    BYTE *file_bytes;
    int index;
    mapped_image image;
    PIMAGE_NT_HEADERS nt;
    FARPROC export_address;
    fixture_add_fn fixture_add;
    int result;

    for (index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--payload") == 0 && index + 1 < argc) {
            payload_path = argv[++index];
        } else if (strcmp(argv[index], "--mode") == 0 && index + 1 < argc) {
            const char *mode = argv[++index];
            embedded = strcmp(mode, "embedded") == 0;
            smoke = strcmp(mode, "smoke") == 0;
            if (!embedded && !smoke && strcmp(mode, "manual") != 0) {
                fprintf(stderr, "unknown mode: %s\n", mode);
                return 2;
            }
        } else if (strcmp(argv[index], "--destroy-headers") == 0) {
            erase_headers = TRUE;
        } else if (strcmp(argv[index], "--debug-break") == 0) {
            debug_break = TRUE;
        } else if (strcmp(argv[index], "--hold-ms") == 0 && index + 1 < argc) {
            hold_ms = strtoul(argv[++index], NULL, 10);
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[index]);
            return 2;
        }
    }
    if (smoke) {
        return run_smoke_load(payload_path);
    }
    file_bytes = read_file_bytes(payload_path, &file_size);
    if (file_bytes == NULL) {
        fprintf(stderr, "payload read failed: %s error=%lu\n", payload_path, GetLastError());
        return 3;
    }
    if (embedded) {
        result = run_embedded_copy(file_bytes, file_size, hold_ms, debug_break);
        HeapFree(GetProcessHeap(), 0, file_bytes);
        return result;
    }
    if (!map_image(file_bytes, file_size, &image, &nt)) {
        fprintf(stderr, "manual map failed error=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, file_bytes);
        return 4;
    }
    export_address = find_export(image.base, nt, "FixtureAdd");
    if (export_address == NULL) {
        fprintf(stderr, "manual export resolution failed\n");
        HeapFree(GetProcessHeap(), 0, file_bytes);
        return 5;
    }
    fixture_add = (fixture_add_fn)export_address;
    result = fixture_add(19, 23);
    if (result != 42) {
        fprintf(stderr, "manual mapped export returned %d\n", result);
        HeapFree(GetProcessHeap(), 0, file_bytes);
        return 6;
    }
    if (erase_headers && !destroy_headers(&image)) {
        fprintf(stderr, "header destruction failed error=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, file_bytes);
        return 7;
    }
    printf(
        "MANUAL_MAP_OK result=%d headers=%s imports=%d relocations=%d "
        "base=0x%p size=%lu\n",
        result,
        erase_headers ? "destroyed" : "intact",
        image.imports_resolved ? 1 : 0,
        image.relocations_applied ? 1 : 0,
        (void *)image.base,
        (unsigned long)image.size
    );
    fflush(stdout);
    HeapFree(GetProcessHeap(), 0, file_bytes);
    if (debug_break) {
        DebugBreak();
    }
    if (hold_ms != 0) {
        Sleep(hold_ms);
    }
    return 0;
}
