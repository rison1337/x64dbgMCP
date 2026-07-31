#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

typedef struct _MCP_PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} MCP_PEB_LDR_DATA, *PMCP_PEB_LDR_DATA;

typedef struct _MCP_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PMCP_PEB_LDR_DATA Ldr;
} MCP_PEB, *PMCP_PEB;

typedef struct _MCP_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} MCP_UNICODE_STRING, *PMCP_UNICODE_STRING;

typedef struct _MCP_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    MCP_UNICODE_STRING FullDllName;
} MCP_LDR_DATA_TABLE_ENTRY, *PMCP_LDR_DATA_TABLE_ENTRY;

typedef DWORD (WINAPI *GET_CURRENT_PROCESS_ID_FN)(void);
typedef DWORD (WINAPI *GET_CURRENT_THREAD_ID_FN)(void);
typedef DWORD (WINAPI *GET_TICK_COUNT_FN)(void);
typedef HANDLE (WINAPI *GET_STD_HANDLE_FN)(DWORD);
typedef BOOL (WINAPI *WRITE_FILE_FN)(
    HANDLE,
    LPCVOID,
    DWORD,
    LPDWORD,
    LPOVERLAPPED
);
typedef BOOL (WINAPI *IS_DEBUGGER_PRESENT_FN)(void);
typedef VOID (NTAPI *RTL_EXIT_USER_PROCESS_FN)(NTSTATUS);

enum {
    SLOT_GET_CURRENT_PROCESS_ID = 0,
    SLOT_GET_CURRENT_THREAD_ID = 1,
    SLOT_GET_TICK_COUNT = 2,
    SLOT_GET_STD_HANDLE = 3,
    SLOT_WRITE_FILE = 4,
    SLOT_IS_DEBUGGER_PRESENT = 5,
    SLOT_RTL_EXIT_USER_PROCESS = 6,
    SLOT_TERMINATOR = 7
};

#pragma data_seg(push, ".resolver$data")
__declspec(dllexport)
volatile ULONG_PTR custom_import_table[8] = {0};
#pragma data_seg(pop)

#pragma code_seg(push, ".resolver$text")

static PMCP_PEB current_peb(void) {
#if defined(_WIN64)
    return (PMCP_PEB)(ULONG_PTR)__readgsqword(0x60);
#else
    return (PMCP_PEB)(ULONG_PTR)__readfsdword(0x30);
#endif
}

static WCHAR ascii_lower_w(WCHAR value) {
    if (value >= L'A' && value <= L'Z') {
        return (WCHAR)(value + (L'a' - L'A'));
    }
    return value;
}

static BOOL unicode_basename_equals(
    const MCP_UNICODE_STRING *full_name,
    const WCHAR *expected,
    USHORT expected_chars
) {
    USHORT full_chars;
    USHORT start;
    USHORT index;
    if (
        full_name == NULL
        || full_name->Buffer == NULL
        || (full_name->Length & 1U) != 0
    ) {
        return FALSE;
    }
    full_chars = (USHORT)(full_name->Length / sizeof(WCHAR));
    start = full_chars;
    while (start > 0) {
        WCHAR value = full_name->Buffer[start - 1];
        if (value == L'\\' || value == L'/') {
            break;
        }
        --start;
    }
    if ((USHORT)(full_chars - start) != expected_chars) {
        return FALSE;
    }
    for (index = 0; index < expected_chars; ++index) {
        if (
            ascii_lower_w(full_name->Buffer[start + index])
            != ascii_lower_w(expected[index])
        ) {
            return FALSE;
        }
    }
    return TRUE;
}

static HMODULE find_loaded_module(const WCHAR *name, USHORT name_chars) {
    PMCP_PEB peb = current_peb();
    PLIST_ENTRY head;
    PLIST_ENTRY link;
    if (peb == NULL || peb->Ldr == NULL) {
        return NULL;
    }
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (link = head->Flink; link != NULL && link != head; link = link->Flink) {
        PMCP_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            link,
            MCP_LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        if (unicode_basename_equals(&entry->FullDllName, name, name_chars)) {
            return (HMODULE)entry->DllBase;
        }
    }
    return NULL;
}

static DWORD fnv1a_ascii(const char *text) {
    DWORD value = 2166136261U;
    while (*text != '\0') {
        value ^= (BYTE)*text++;
        value *= 16777619U;
    }
    return value;
}

__declspec(dllexport) __declspec(noinline)
FARPROC __cdecl custom_resolve_export(HMODULE module, DWORD requested_hash) {
    const BYTE *base = (const BYTE *)module;
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS *nt;
    const IMAGE_DATA_DIRECTORY *directory;
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *names;
    const WORD *ordinals;
    const DWORD *functions;
    DWORD index;
    if (base == NULL) {
        return NULL;
    }
    dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return NULL;
    }
    nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    directory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory->VirtualAddress == 0 || directory->Size == 0) {
        return NULL;
    }
    exports = (const IMAGE_EXPORT_DIRECTORY *)(
        base + directory->VirtualAddress
    );
    names = (const DWORD *)(base + exports->AddressOfNames);
    ordinals = (const WORD *)(base + exports->AddressOfNameOrdinals);
    functions = (const DWORD *)(base + exports->AddressOfFunctions);
    for (index = 0; index < exports->NumberOfNames; ++index) {
        const char *name = (const char *)(base + names[index]);
        DWORD function_rva;
        if (fnv1a_ascii(name) != requested_hash) {
            continue;
        }
        if (ordinals[index] >= exports->NumberOfFunctions) {
            return NULL;
        }
        function_rva = functions[ordinals[index]];
        if (
            function_rva >= directory->VirtualAddress
            && function_rva < directory->VirtualAddress + directory->Size
        ) {
            /* Forwarders are intentionally fail-closed in this fixture. */
            return NULL;
        }
        return (FARPROC)(base + function_rva);
    }
    return NULL;
}

static BOOL import_table_ready(void) {
    DWORD index;
    for (index = 0; index < SLOT_TERMINATOR; ++index) {
        if (custom_import_table[index] == 0) {
            return FALSE;
        }
    }
    return custom_import_table[SLOT_TERMINATOR] == 0;
}

static BOOL resolve_import_table(void) {
    static const WCHAR kernelbase_name[] = L"kernelbase.dll";
    static const WCHAR ntdll_name[] = L"ntdll.dll";
    static const char *const names[SLOT_TERMINATOR] = {
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetTickCount",
        "GetStdHandle",
        "WriteFile",
        "IsDebuggerPresent",
        "RtlExitUserProcess"
    };
    HMODULE kernelbase = find_loaded_module(
        kernelbase_name,
        (USHORT)((sizeof(kernelbase_name) / sizeof(WCHAR)) - 1)
    );
    HMODULE ntdll = find_loaded_module(
        ntdll_name,
        (USHORT)((sizeof(ntdll_name) / sizeof(WCHAR)) - 1)
    );
    DWORD index;
    if (kernelbase == NULL || ntdll == NULL) {
        return FALSE;
    }
    for (index = 0; index < SLOT_TERMINATOR; ++index) {
        HMODULE source = index == SLOT_RTL_EXIT_USER_PROCESS
            ? ntdll
            : kernelbase;
        FARPROC address = custom_resolve_export(source, fnv1a_ascii(names[index]));
        if (address == NULL) {
            return FALSE;
        }
        custom_import_table[index] = (ULONG_PTR)address;
    }
    custom_import_table[SLOT_TERMINATOR] = 0;
    return TRUE;
}

void WINAPI custom_resolver_entry(void) {
    static const char marker[] =
        "CUSTOM_RESOLVER_OK hashes=7 slots=7 pid=1 tid=1 tick=1\n";
    DWORD written = 0;
    DWORD pid;
    DWORD tid;
    DWORD tick;
    HANDLE output;
    BOOL ok;
    RTL_EXIT_USER_PROCESS_FN exit_process;

    if (!import_table_ready() && !resolve_import_table()) {
        return;
    }
    exit_process = (RTL_EXIT_USER_PROCESS_FN)(
        ULONG_PTR
    )custom_import_table[SLOT_RTL_EXIT_USER_PROCESS];

    if (
        ((IS_DEBUGGER_PRESENT_FN)(
            ULONG_PTR
        )custom_import_table[SLOT_IS_DEBUGGER_PRESENT])()
    ) {
        __debugbreak();
    }

    pid = ((GET_CURRENT_PROCESS_ID_FN)(
        ULONG_PTR
    )custom_import_table[SLOT_GET_CURRENT_PROCESS_ID])();
    tid = ((GET_CURRENT_THREAD_ID_FN)(
        ULONG_PTR
    )custom_import_table[SLOT_GET_CURRENT_THREAD_ID])();
    tick = ((GET_TICK_COUNT_FN)(
        ULONG_PTR
    )custom_import_table[SLOT_GET_TICK_COUNT])();
    output = ((GET_STD_HANDLE_FN)(
        ULONG_PTR
    )custom_import_table[SLOT_GET_STD_HANDLE])(STD_OUTPUT_HANDLE);
    ok = ((WRITE_FILE_FN)(
        ULONG_PTR
    )custom_import_table[SLOT_WRITE_FILE])(
        output,
        marker,
        (DWORD)(sizeof(marker) - 1),
        &written,
        NULL
    );
    exit_process(
        (
            ok
            && written == (DWORD)(sizeof(marker) - 1)
            && pid != 0
            && tid != 0
            && tick != 0
        )
            ? 0
            : 93
    );
}

#pragma code_seg(pop)
