DEFAULT_API_FILTERS = [
    # File I/O
    "createfile", "readfile", "writefile", "deletefile", "movefile", "copyfile",
    "findfirstfile", "findnextfile", "getfileattributes", "setfileattributes",
    # Memory
    "virtualalloc", "virtualprotect", "virtualfree", "heapalloc", "heapfree",
    "writeprocessmemory", "readprocessmemory",
    # Process/thread
    "createprocess", "createthread", "createremotethread", "openprocess",
    "terminateprocess", "exitprocess", "shellexecute", "winexec",
    "loadlibrary", "getprocaddress", "freelibrary",
    # Registry
    "regopenkey", "regsetvalue", "regqueryvalue", "regcreatekey", "regdeletekey",
    # Network
    "connect", "send", "recv", "wsastartup", "socket", "bind", "listen",
    "accept", "closesocket", "internetopen", "internetconnect", "httpopenrequest",
    "httpsendrequest", "internetreadfile", "urlopen", "wsaconnect",
    # Crypto
    "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "crypthashdata",
    "bcrypt",
    # Anti-debug
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "ntsetinformationthread", "ntclose", "outputdebugstring",
    # Console (for CTF / keygens)
    "printf", "scanf", "gets", "puts", "fgets", "fopen", "fread", "fwrite",
    "getstdhandle", "writeconsole", "readconsole",
]

# Argument count by convention — default to 4 sampled args per call.
DEFAULT_API_ARG_COUNT = 4

API_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "strcmp": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "const char*", "direction": "in"},
            {"name": "right", "type": "const char*", "direction": "in"},
        ],
    },
    "strncmp": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "const char*", "direction": "in"},
            {"name": "right", "type": "const char*", "direction": "in"},
            {"name": "count", "type": "size_t", "direction": "in"},
        ],
    },
    "memcmp": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "const void*", "direction": "in"},
            {"name": "right", "type": "const void*", "direction": "in"},
            {"name": "count", "type": "size_t", "direction": "in"},
        ],
    },
    "wcscmp": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "const wchar_t*", "direction": "in"},
            {"name": "right", "type": "const wchar_t*", "direction": "in"},
        ],
    },
    "wcsncmp": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "const wchar_t*", "direction": "in"},
            {"name": "right", "type": "const wchar_t*", "direction": "in"},
            {"name": "count", "type": "size_t", "direction": "in"},
        ],
    },
    "lstrcmpa": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "LPCSTR", "direction": "in"},
            {"name": "right", "type": "LPCSTR", "direction": "in"},
        ],
    },
    "lstrcmpw": {
        "returnType": "int",
        "args": [
            {"name": "left", "type": "LPCWSTR", "direction": "in"},
            {"name": "right", "type": "LPCWSTR", "direction": "in"},
        ],
    },
    "getprocaddress": {
        "returnType": "FARPROC",
        "args": [
            {"name": "module", "type": "HMODULE", "direction": "in"},
            {"name": "name", "type": "LPCSTR", "direction": "in"},
        ],
    },
    "loadlibrarya": {
        "returnType": "HMODULE",
        "args": [{"name": "path", "type": "LPCSTR", "direction": "in"}],
    },
    "loadlibraryw": {
        "returnType": "HMODULE",
        "args": [{"name": "path", "type": "LPCWSTR", "direction": "in"}],
    },
    "loadlibraryexa": {
        "returnType": "HMODULE",
        "args": [
            {"name": "path", "type": "LPCSTR", "direction": "in"},
            {"name": "file", "type": "HANDLE", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
        ],
    },
    "loadlibraryexw": {
        "returnType": "HMODULE",
        "args": [
            {"name": "path", "type": "LPCWSTR", "direction": "in"},
            {"name": "file", "type": "HANDLE", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
        ],
    },
    "getprocaddressforcaller": {
        "returnType": "FARPROC",
        "args": [
            {"name": "module", "type": "HMODULE", "direction": "in"},
            {"name": "name", "type": "LPCSTR", "direction": "in"},
            {"name": "caller", "type": "PVOID", "direction": "in"},
        ],
    },
    "getmodulehandlea": {
        "returnType": "HMODULE",
        "args": [{"name": "moduleName", "type": "LPCSTR", "direction": "in"}],
    },
    "getmodulehandlew": {
        "returnType": "HMODULE",
        "args": [{"name": "moduleName", "type": "LPCWSTR", "direction": "in"}],
    },
    "closehandle": {
        "returnType": "BOOL",
        "args": [{"name": "handle", "type": "HANDLE", "direction": "in"}],
    },
    "createfilea": {
        "returnType": "HANDLE",
        "args": [
            {"name": "path", "type": "LPCSTR", "direction": "in"},
            {"name": "desiredAccess", "type": "DWORD", "direction": "in"},
            {"name": "shareMode", "type": "DWORD", "direction": "in"},
            {"name": "security", "type": "LPSECURITY_ATTRIBUTES", "direction": "in"},
            {"name": "creation", "type": "DWORD", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "template", "type": "HANDLE", "direction": "in"},
        ],
    },
    "createfilew": {
        "returnType": "HANDLE",
        "args": [
            {"name": "path", "type": "LPCWSTR", "direction": "in"},
            {"name": "desiredAccess", "type": "DWORD", "direction": "in"},
            {"name": "shareMode", "type": "DWORD", "direction": "in"},
            {"name": "security", "type": "LPSECURITY_ATTRIBUTES", "direction": "in"},
            {"name": "creation", "type": "DWORD", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "template", "type": "HANDLE", "direction": "in"},
        ],
    },
    "deletefilea": {
        "returnType": "BOOL",
        "args": [{"name": "path", "type": "LPCSTR", "direction": "in"}],
    },
    "deletefilew": {
        "returnType": "BOOL",
        "args": [{"name": "path", "type": "LPCWSTR", "direction": "in"}],
    },
    "getfilesize": {
        "returnType": "DWORD",
        "args": [
            {"name": "file", "type": "HANDLE", "direction": "in"},
            {"name": "high", "type": "LPDWORD", "direction": "out"},
        ],
    },
    "getfilesizeex": {
        "returnType": "BOOL",
        "args": [
            {"name": "file", "type": "HANDLE", "direction": "in"},
            {"name": "size", "type": "PLARGE_INTEGER", "direction": "out"},
        ],
    },
    "createeventa": {
        "returnType": "HANDLE",
        "args": [
            {"name": "security", "type": "LPSECURITY_ATTRIBUTES", "direction": "in"},
            {"name": "manualReset", "type": "BOOL", "direction": "in"},
            {"name": "initialState", "type": "BOOL", "direction": "in"},
            {"name": "name", "type": "LPCSTR", "direction": "in"},
        ],
    },
    "createeventw": {
        "returnType": "HANDLE",
        "args": [
            {"name": "security", "type": "LPSECURITY_ATTRIBUTES", "direction": "in"},
            {"name": "manualReset", "type": "BOOL", "direction": "in"},
            {"name": "initialState", "type": "BOOL", "direction": "in"},
            {"name": "name", "type": "LPCWSTR", "direction": "in"},
        ],
    },
    "setevent": {
        "returnType": "BOOL",
        "args": [{"name": "event", "type": "HANDLE", "direction": "in"}],
    },
    "resetevent": {
        "returnType": "BOOL",
        "args": [{"name": "event", "type": "HANDLE", "direction": "in"}],
    },
    "waitforsingleobject": {
        "returnType": "DWORD",
        "args": [
            {"name": "handle", "type": "HANDLE", "direction": "in"},
            {"name": "milliseconds", "type": "DWORD", "direction": "in"},
        ],
    },
    "waitformultipleobjects": {
        "returnType": "DWORD",
        "args": [
            {"name": "count", "type": "DWORD", "direction": "in"},
            {"name": "handles", "type": "const HANDLE*", "direction": "in"},
            {"name": "waitAll", "type": "BOOL", "direction": "in"},
            {"name": "milliseconds", "type": "DWORD", "direction": "in"},
        ],
    },
    "getcurrentprocessid": {
        "returnType": "DWORD",
        "args": [],
    },
    "getcurrentthreadid": {
        "returnType": "DWORD",
        "args": [],
    },
    "openprocess": {
        "returnType": "HANDLE",
        "args": [
            {"name": "desiredAccess", "type": "DWORD", "direction": "in"},
            {"name": "inheritHandle", "type": "BOOL", "direction": "in"},
            {"name": "processId", "type": "DWORD", "direction": "in"},
        ],
    },
    "terminateprocess": {
        "returnType": "BOOL",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "exitCode", "type": "UINT", "direction": "in"},
        ],
    },
    "virtualalloc": {
        "returnType": "LPVOID",
        "args": [
            {"name": "address", "type": "LPVOID", "direction": "in"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "allocationType", "type": "DWORD", "direction": "in"},
            {"name": "protect", "type": "DWORD", "direction": "in"},
        ],
    },
    "virtualalloc2": {
        "returnType": "PVOID",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "address", "type": "PVOID", "direction": "in"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "allocationType", "type": "ULONG", "direction": "in"},
            {"name": "protect", "type": "ULONG", "direction": "in"},
            {"name": "parameters", "type": "MEM_EXTENDED_PARAMETER*", "direction": "in"},
            {"name": "parameterCount", "type": "ULONG", "direction": "in"},
        ],
    },
    "virtualfree": {
        "returnType": "BOOL",
        "args": [
            {"name": "address", "type": "LPVOID", "direction": "in"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "freeType", "type": "DWORD", "direction": "in"},
        ],
    },
    "virtualprotect": {
        "returnType": "BOOL",
        "args": [
            {"name": "address", "type": "LPVOID", "direction": "in"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "newProtect", "type": "DWORD", "direction": "in"},
            {"name": "oldProtect", "type": "PDWORD", "direction": "out"},
        ],
    },
    "virtualquery": {
        "returnType": "SIZE_T",
        "args": [
            {"name": "address", "type": "LPCVOID", "direction": "in"},
            {"name": "buffer", "type": "PMEMORY_BASIC_INFORMATION", "direction": "out"},
            {"name": "length", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "getenvironmentstringsw": {
        "returnType": "LPWCH",
        "args": [],
    },
    "freeenvironmentstringsw": {
        "returnType": "BOOL",
        "args": [{"name": "environment", "type": "LPWCH", "direction": "in"}],
    },
    "multibytetowidechar": {
        "returnType": "int",
        "args": [
            {"name": "codePage", "type": "UINT", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "source", "type": "LPCCH", "direction": "in"},
            {"name": "sourceLength", "type": "int", "direction": "in"},
            {"name": "destination", "type": "LPWSTR", "direction": "out"},
            {"name": "destinationLength", "type": "int", "direction": "in"},
        ],
    },
    "widechartomultibyte": {
        "returnType": "int",
        "args": [
            {"name": "codePage", "type": "UINT", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "source", "type": "LPCWCH", "direction": "in"},
            {"name": "sourceLength", "type": "int", "direction": "in"},
            {"name": "destination", "type": "LPSTR", "direction": "out"},
            {"name": "destinationLength", "type": "int", "direction": "in"},
            {"name": "defaultChar", "type": "LPCSTR", "direction": "in"},
            {"name": "usedDefault", "type": "LPBOOL", "direction": "out"},
        ],
    },
    "socket": {
        "returnType": "SOCKET",
        "args": [
            {"name": "addressFamily", "type": "int", "direction": "in"},
            {"name": "type", "type": "int", "direction": "in"},
            {"name": "protocol", "type": "int", "direction": "in"},
        ],
    },
    "connect": {
        "returnType": "int",
        "args": [
            {"name": "socket", "type": "SOCKET", "direction": "in"},
            {"name": "name", "type": "const sockaddr*", "direction": "in"},
            {"name": "nameLength", "type": "int", "direction": "in"},
        ],
    },
    "send": {
        "returnType": "int",
        "args": [
            {"name": "socket", "type": "SOCKET", "direction": "in"},
            {"name": "buffer", "type": "const char*", "direction": "in"},
            {"name": "length", "type": "int", "direction": "in"},
            {"name": "flags", "type": "int", "direction": "in"},
        ],
    },
    "recv": {
        "returnType": "int",
        "args": [
            {"name": "socket", "type": "SOCKET", "direction": "in"},
            {"name": "buffer", "type": "char*", "direction": "out"},
            {"name": "length", "type": "int", "direction": "in"},
            {"name": "flags", "type": "int", "direction": "in"},
        ],
    },
    "closesocket": {
        "returnType": "int",
        "args": [{"name": "socket", "type": "SOCKET", "direction": "in"}],
    },
    "isdebuggerpresent": {
        "returnType": "BOOL",
        "args": [],
    },
    "checkremotedebuggerpresent": {
        "returnType": "BOOL",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "present", "type": "PBOOL", "direction": "out"},
        ],
    },
    "ntqueryinformationprocess": {
        "returnType": "NTSTATUS",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "class", "type": "PROCESSINFOCLASS", "direction": "in"},
            {"name": "buffer", "type": "PVOID", "direction": "out"},
            {"name": "length", "type": "ULONG", "direction": "in"},
            {"name": "returnLength", "type": "PULONG", "direction": "out"},
        ],
    },
    "readfile": {
        "returnType": "BOOL",
        "args": [
            {"name": "file", "type": "HANDLE", "direction": "in"},
            {"name": "buffer", "type": "LPVOID", "direction": "out"},
            {"name": "bytesToRead", "type": "DWORD", "direction": "in"},
            {"name": "bytesRead", "type": "LPDWORD", "direction": "out"},
            {"name": "overlapped", "type": "LPOVERLAPPED", "direction": "inout"},
        ],
    },
    "writefile": {
        "returnType": "BOOL",
        "args": [
            {"name": "file", "type": "HANDLE", "direction": "in"},
            {"name": "buffer", "type": "LPCVOID", "direction": "in"},
            {"name": "bytesToWrite", "type": "DWORD", "direction": "in"},
            {"name": "bytesWritten", "type": "LPDWORD", "direction": "out"},
            {"name": "overlapped", "type": "LPOVERLAPPED", "direction": "inout"},
        ],
    },
    "readprocessmemory": {
        "returnType": "BOOL",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "baseAddress", "type": "LPCVOID", "direction": "in"},
            {"name": "buffer", "type": "LPVOID", "direction": "out"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "bytesRead", "type": "SIZE_T*", "direction": "out"},
        ],
    },
    "getenvironmentvariablea": {
        "returnType": "DWORD",
        "args": [
            {"name": "name", "type": "LPCSTR", "direction": "in"},
            {"name": "buffer", "type": "LPSTR", "direction": "out"},
            {"name": "size", "type": "DWORD", "direction": "in"},
        ],
    },
    "getenvironmentvariablew": {
        "returnType": "DWORD",
        "args": [
            {"name": "name", "type": "LPCWSTR", "direction": "in"},
            {"name": "buffer", "type": "LPWSTR", "direction": "out"},
            {"name": "size", "type": "DWORD", "direction": "in"},
        ],
    },
    "getmodulefilenamea": {
        "returnType": "DWORD",
        "args": [
            {"name": "module", "type": "HMODULE", "direction": "in"},
            {"name": "path", "type": "LPSTR", "direction": "out"},
            {"name": "size", "type": "DWORD", "direction": "in"},
        ],
    },
    "getmodulefilenamew": {
        "returnType": "DWORD",
        "args": [
            {"name": "module", "type": "HMODULE", "direction": "in"},
            {"name": "path", "type": "LPWSTR", "direction": "out"},
            {"name": "size", "type": "DWORD", "direction": "in"},
        ],
    },
    "regqueryvalueexa": {
        "returnType": "LSTATUS",
        "args": [
            {"name": "key", "type": "HKEY", "direction": "in"},
            {"name": "valueName", "type": "LPCSTR", "direction": "in"},
            {"name": "reserved", "type": "LPDWORD", "direction": "in"},
            {"name": "type", "type": "LPDWORD", "direction": "out"},
            {"name": "data", "type": "LPBYTE", "direction": "out"},
            {"name": "dataSize", "type": "LPDWORD", "direction": "inout"},
        ],
    },
    "regqueryvalueexw": {
        "returnType": "LSTATUS",
        "args": [
            {"name": "key", "type": "HKEY", "direction": "in"},
            {"name": "valueName", "type": "LPCWSTR", "direction": "in"},
            {"name": "reserved", "type": "LPDWORD", "direction": "in"},
            {"name": "type", "type": "LPDWORD", "direction": "out"},
            {"name": "data", "type": "LPBYTE", "direction": "out"},
            {"name": "dataSize", "type": "LPDWORD", "direction": "inout"},
        ],
    },
    "heapalloc": {
        "returnType": "LPVOID",
        "args": [
            {"name": "heap", "type": "HANDLE", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "heaprealloc": {
        "returnType": "LPVOID",
        "args": [
            {"name": "heap", "type": "HANDLE", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "memory", "type": "LPVOID", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "heapfree": {
        "returnType": "BOOL",
        "args": [
            {"name": "heap", "type": "HANDLE", "direction": "in"},
            {"name": "flags", "type": "DWORD", "direction": "in"},
            {"name": "memory", "type": "LPVOID", "direction": "in"},
        ],
    },
    "rtlallocateheap": {
        "returnType": "PVOID",
        "args": [
            {"name": "heap", "type": "PVOID", "direction": "in"},
            {"name": "flags", "type": "ULONG", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "rtlreallocateheap": {
        "returnType": "PVOID",
        "args": [
            {"name": "heap", "type": "PVOID", "direction": "in"},
            {"name": "flags", "type": "ULONG", "direction": "in"},
            {"name": "memory", "type": "PVOID", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "rtlfreeheap": {
        "returnType": "BOOLEAN",
        "args": [
            {"name": "heap", "type": "PVOID", "direction": "in"},
            {"name": "flags", "type": "ULONG", "direction": "in"},
            {"name": "memory", "type": "PVOID", "direction": "in"},
        ],
    },
    "virtualallocex": {
        "returnType": "LPVOID",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "address", "type": "LPVOID", "direction": "in"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "allocationType", "type": "DWORD", "direction": "in"},
            {"name": "protect", "type": "DWORD", "direction": "in"},
        ],
    },
    "virtualfreeex": {
        "returnType": "BOOL",
        "args": [
            {"name": "process", "type": "HANDLE", "direction": "in"},
            {"name": "address", "type": "LPVOID", "direction": "in"},
            {"name": "size", "type": "SIZE_T", "direction": "in"},
            {"name": "freeType", "type": "DWORD", "direction": "in"},
        ],
    },
    "cotaskmemalloc": {
        "returnType": "LPVOID",
        "args": [{"name": "bytes", "type": "SIZE_T", "direction": "in"}],
    },
    "cotaskmemrealloc": {
        "returnType": "LPVOID",
        "args": [
            {"name": "memory", "type": "LPVOID", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "cotaskmemfree": {
        "returnType": "void",
        "args": [{"name": "memory", "type": "LPVOID", "direction": "in"}],
    },
    "localalloc": {
        "returnType": "HLOCAL",
        "args": [
            {"name": "flags", "type": "UINT", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "localrealloc": {
        "returnType": "HLOCAL",
        "args": [
            {"name": "memory", "type": "HLOCAL", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
            {"name": "flags", "type": "UINT", "direction": "in"},
        ],
    },
    "localfree": {
        "returnType": "HLOCAL",
        "args": [{"name": "memory", "type": "HLOCAL", "direction": "in"}],
    },
    "globalalloc": {
        "returnType": "HGLOBAL",
        "args": [
            {"name": "flags", "type": "UINT", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
        ],
    },
    "globalrealloc": {
        "returnType": "HGLOBAL",
        "args": [
            {"name": "memory", "type": "HGLOBAL", "direction": "in"},
            {"name": "bytes", "type": "SIZE_T", "direction": "in"},
            {"name": "flags", "type": "UINT", "direction": "in"},
        ],
    },
    "globalfree": {
        "returnType": "HGLOBAL",
        "args": [{"name": "memory", "type": "HGLOBAL", "direction": "in"}],
    },
    "malloc": {
        "returnType": "void*",
        "args": [{"name": "bytes", "type": "size_t", "direction": "in"}],
    },
    "calloc": {
        "returnType": "void*",
        "args": [
            {"name": "count", "type": "size_t", "direction": "in"},
            {"name": "elementSize", "type": "size_t", "direction": "in"},
        ],
    },
    "realloc": {
        "returnType": "void*",
        "args": [
            {"name": "memory", "type": "void*", "direction": "in"},
            {"name": "bytes", "type": "size_t", "direction": "in"},
        ],
    },
    "free": {
        "returnType": "void",
        "args": [{"name": "memory", "type": "void*", "direction": "in"}],
    },
}


def _api_signature(function: str) -> Dict[str, Any]:
    name = str(function or "").strip().lower()
    if "!" in name:
        name = name.rsplit("!", 1)[-1]
    name = re.sub(r"@\d+$", "", name).lstrip("_")
    signature = API_SIGNATURES.get(name)
    return dict(signature) if isinstance(signature, dict) else {}


COMPARISON_API_SPECS: Dict[str, Dict[str, Any]] = {
    "strcmp": {"encoding": "bytes", "terminated": True},
    "strncmp": {
        "encoding": "bytes",
        "terminated": False,
        "lengthArg": 2,
        "lengthUnit": 1,
    },
    "memcmp": {
        "encoding": "bytes",
        "terminated": False,
        "lengthArg": 2,
        "lengthUnit": 1,
    },
    "wcscmp": {"encoding": "utf16le", "terminated": True},
    "wcsncmp": {
        "encoding": "utf16le",
        "terminated": False,
        "lengthArg": 2,
        "lengthUnit": 2,
    },
    "lstrcmpa": {"encoding": "bytes", "terminated": True},
    "lstrcmpw": {"encoding": "utf16le", "terminated": True},
}


def _comparison_api_spec(function: str) -> Dict[str, Any]:
    name = _normalized_api_export_name(function)
    return dict(COMPARISON_API_SPECS.get(name) or {})


def _comparison_terminator_index(data: bytes, encoding: str) -> Optional[int]:
    if encoding == "utf16le":
        for index in range(0, max(0, len(data) - 1), 2):
            if data[index : index + 2] == b"\x00\x00":
                return index
        return None
    index = data.find(b"\x00")
    return index if index >= 0 else None


def _comparison_text_preview(data: bytes, encoding: str) -> Optional[str]:
    try:
        text = (
            data.decode("utf-16le", errors="strict")
            if encoding == "utf16le"
            else data.decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, ValueError):
        return None
    if not text:
        return ""
    printable = sum(1 for character in text if character.isprintable())
    if printable / len(text) < 0.85:
        return None
    return text[:256]


def _capture_comparison_operand(
    pointer: int,
    *,
    encoding: str,
    terminated: bool,
    requested_bytes: int,
    max_bytes: int,
) -> Dict[str, Any]:
    address = _normalize_hex(pointer) or hex(pointer)
    safe_max = max(1, min(int(max_bytes), 1_048_576))
    requested = safe_max if terminated else max(0, min(int(requested_bytes), safe_max))
    if not pointer:
        return {
            "ok": False,
            "address": address,
            "error": "null_pointer",
            "requestedBytes": requested,
        }
    if requested <= 0:
        return {
            "ok": True,
            "address": address,
            "requestedBytes": 0,
            "capturedBytes": 0,
            "logicalBytes": 0,
            "hex": "",
            "sha256": hashlib.sha256(b"").hexdigest().upper(),
            "terminated": False,
            "truncated": False,
            "encoding": encoding,
            "textPreview": "",
        }
    read = _read_memory_bytes(address, requested)
    if not read.get("ok"):
        return {
            "ok": False,
            "address": address,
            "requestedBytes": requested,
            "encoding": encoding,
            "error": str(read.get("error") or "memory_read_failed"),
        }
    raw = bytes(read.get("bytes") or b"")
    terminator_index = (
        _comparison_terminator_index(raw, encoding) if terminated else None
    )
    logical = raw[:terminator_index] if terminator_index is not None else raw
    was_terminated = terminator_index is not None
    truncated = bool(
        (terminated and not was_terminated and len(raw) >= safe_max)
        or (not terminated and int(requested_bytes) > safe_max)
    )
    return {
        "ok": True,
        "address": address,
        "requestedBytes": requested,
        "capturedBytes": len(raw),
        "logicalBytes": len(logical),
        "hex": logical.hex(),
        "sha256": hashlib.sha256(logical).hexdigest().upper(),
        "terminated": was_terminated,
        "truncated": truncated,
        "encoding": encoding,
        "textPreview": _comparison_text_preview(logical, encoding),
    }


def _capture_comparison_evidence(
    function: str,
    args: Sequence[Dict[str, Any]],
    max_bytes: int,
) -> Optional[Dict[str, Any]]:
    spec = _comparison_api_spec(function)
    if not spec:
        return None
    by_index = {
        int(item.get("index", -1)): item
        for item in args
        if isinstance(item, dict)
    }
    encoding = str(spec.get("encoding") or "bytes")
    terminated = bool(spec.get("terminated"))
    length_arg = spec.get("lengthArg")
    length_unit = max(1, int(spec.get("lengthUnit") or 1))
    element_count: Optional[int] = None
    requested_bytes = int(max_bytes)
    if length_arg is not None:
        element_count = max(
            0,
            _api_value_int((by_index.get(int(length_arg)) or {}).get("value")),
        )
        requested_bytes = element_count * length_unit
    operands = []
    for index in (0, 1):
        pointer = _api_value_int((by_index.get(index) or {}).get("value"))
        operand = _capture_comparison_operand(
            pointer,
            encoding=encoding,
            terminated=terminated,
            requested_bytes=requested_bytes,
            max_bytes=max_bytes,
        )
        operand["index"] = index
        operands.append(operand)
    return {
        "schema": "comparison-evidence-v1",
        "function": _normalized_api_export_name(function),
        "encoding": encoding,
        "lengthUnit": length_unit,
        "elementCount": element_count,
        "terminatedInput": terminated,
        "operands": operands,
        "capturedComplete": bool(
            all(item.get("ok") and not item.get("truncated") for item in operands)
        ),
        "returnConvention": "zero_means_equal",
    }


def _finalize_comparison_evidence(
    comparison: Optional[Dict[str, Any]],
    return_value: Any,
    return_event_seq: int,
) -> Optional[Dict[str, Any]]:
    if not isinstance(comparison, dict):
        return None
    numeric = _api_value_int(return_value)
    signed = numeric & 0xFFFFFFFF
    if signed & 0x80000000:
        signed -= 0x100000000
    return {
        **comparison,
        "result": {
            "raw": _unwrap_scalar_result(return_value).strip() or "0x0",
            "signed": signed,
            "equal": signed == 0,
            "returnEventSeq": int(return_event_seq or 0),
        },
    }


def _next_api_trace_id() -> str:
    with _RUNTIME_LOCK:
        seq = int(_RUNTIME_STATE.get("apiTraceSeq", 0)) + 1
        _RUNTIME_STATE["apiTraceSeq"] = seq
    return f"apitrace-{_CLIENT_INSTANCE_ID.split('-', 1)[0]}-{seq}"


def _clear_native_api_trace_evidence(trace_id: str) -> dict:
    envelope = _bridge_request(
        "POST",
        "ApiTrace/Clear",
        form_data={"traceId": str(trace_id or "").strip()},
        log=False,
    )
    if not envelope.ok:
        error = envelope.error or BridgeError(
            "BRIDGE_REQUEST_FAILED",
            "Native API trace clear failed.",
            endpoint="ApiTrace/Clear",
        )
        return {
            "ok": False,
            "errorCode": error.code,
            "error": error.message,
            "retryable": error.retryable,
            "details": dict(error.details or {}),
            "meta": dict(envelope.meta or {}),
        }
    payload = _coerce_json_payload(envelope.data)
    if isinstance(payload, dict):
        return payload
    return {
        "ok": False,
        "errorCode": "INVALID_RESPONSE",
        "error": "Native API trace clear returned a non-JSON response.",
        "rawResponse": str(envelope.data)[:2048],
        "meta": dict(envelope.meta or {}),
    }


def _configure_native_api_trace(
    trace_id: str,
    *,
    native_return_hooks: bool,
    entry_addresses: Optional[Sequence[str]] = None,
) -> dict:
    normalized_addresses = [
        str(_normalize_hex(address) or address).strip()
        for address in (entry_addresses or [])
        if str(_normalize_hex(address) or address).strip()
    ]
    envelope = _bridge_request(
        "POST",
        "ApiTrace/Configure",
        form_data={
            "traceId": str(trace_id or "").strip(),
            "nativeReturnHooks": "true" if native_return_hooks else "false",
            "entryAddresses": ",".join(normalized_addresses),
        },
        log=False,
    )
    if not envelope.ok:
        error = envelope.error or BridgeError(
            "BRIDGE_REQUEST_FAILED",
            "Native API trace configuration failed.",
            endpoint="ApiTrace/Configure",
        )
        return {
            "ok": False,
            "errorCode": error.code,
            "error": error.message,
            "retryable": error.retryable,
            "details": dict(error.details or {}),
            "meta": dict(envelope.meta or {}),
        }
    payload = _coerce_json_payload(envelope.data)
    if isinstance(payload, dict):
        return payload
    return {
        "ok": False,
        "errorCode": "INVALID_RESPONSE",
        "error": "Native API trace configuration returned a non-JSON response.",
        "rawResponse": str(envelope.data)[:2048],
        "meta": dict(envelope.meta or {}),
    }


def _release_native_api_return_hooks(trace_id: str) -> dict:
    envelope = _bridge_request(
        "POST",
        "ApiTrace/ReturnHooks/Release",
        form_data={"traceId": str(trace_id or "").strip()},
        log=False,
    )
    if not envelope.ok:
        error = envelope.error or BridgeError(
            "BRIDGE_REQUEST_FAILED",
            "Native API return-hook release failed.",
            endpoint="ApiTrace/ReturnHooks/Release",
        )
        return {
            "ok": False,
            "errorCode": error.code,
            "error": error.message,
            "retryable": error.retryable,
            "details": dict(error.details or {}),
            "meta": dict(envelope.meta or {}),
        }
    payload = _coerce_json_payload(envelope.data)
    if isinstance(payload, dict):
        return payload
    return {
        "ok": False,
        "errorCode": "INVALID_RESPONSE",
        "error": "Native API return-hook release returned a non-JSON response.",
        "rawResponse": str(envelope.data)[:2048],
        "meta": dict(envelope.meta or {}),
    }


def _record_native_api_entry(
    trace_id: str,
    api_address: str,
    module: str = "",
) -> dict:
    envelope = _bridge_request(
        "POST",
        "ApiTrace/Entry",
        form_data={
            "traceId": str(trace_id or "").strip(),
            "apiAddress": str(_normalize_hex(api_address) or api_address).strip(),
            "module": str(module or "").strip(),
        },
        log=False,
    )
    if not envelope.ok:
        error = envelope.error or BridgeError(
            "BRIDGE_REQUEST_FAILED",
            "Native API entry evidence submission failed.",
            endpoint="ApiTrace/Entry",
        )
        return {
            "ok": False,
            "errorCode": error.code,
            "error": error.message,
            "retryable": error.retryable,
            "details": dict(error.details or {}),
            "meta": dict(envelope.meta or {}),
        }
    payload = _coerce_json_payload(envelope.data)
    if isinstance(payload, dict):
        return payload
    return {
        "ok": False,
        "errorCode": "INVALID_RESPONSE",
        "error": "Native API entry route returned a non-JSON response.",
        "rawResponse": str(envelope.data)[:2048],
        "meta": dict(envelope.meta or {}),
    }


def _finalize_native_api_trace_evidence(trace_id: str) -> dict:
    envelope = _bridge_request(
        "POST",
        "ApiTrace/Finalize",
        form_data={"traceId": str(trace_id or "").strip()},
        log=False,
    )
    if not envelope.ok:
        error = envelope.error or BridgeError(
            "BRIDGE_REQUEST_FAILED",
            "Native API trace finalize failed.",
            endpoint="ApiTrace/Finalize",
        )
        return {
            "ok": False,
            "errorCode": error.code,
            "error": error.message,
            "retryable": error.retryable,
            "details": dict(error.details or {}),
            "meta": dict(envelope.meta or {}),
        }
    payload = _coerce_json_payload(envelope.data)
    if isinstance(payload, dict):
        return payload
    return {
        "ok": False,
        "errorCode": "INVALID_RESPONSE",
        "error": "Native API trace finalize returned a non-JSON response.",
        "rawResponse": str(envelope.data)[:2048],
        "meta": dict(envelope.meta or {}),
    }


def _get_api_trace(trace_id: str) -> Optional[Dict[str, Any]]:
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("apiTraces", {}))
    return traces.get(str(trace_id or "").strip())


def _update_api_trace(trace_id: str, updater: Callable[[Dict[str, Any]], None]) -> None:
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("apiTraces", {}))
        record = traces.get(trace_id)
        if record is None:
            return
        updater(record)
        traces[trace_id] = record
        _RUNTIME_STATE["apiTraces"] = traces


def _normalized_api_export_name(value: str) -> str:
    name = str(value or "").strip().lower()
    if "!" in name:
        name = name.rsplit("!", 1)[-1]
    return re.sub(r"@\d+$", "", name).lstrip("_")


def _api_export_matches_filters(
    module_name: str,
    function_name: str,
    filter_patterns: Sequence[str],
) -> bool:
    """Match legacy substrings plus opt-in exact ``=function`` filters."""

    if not filter_patterns:
        return True
    module = str(module_name or "").strip().lower()
    function = str(function_name or "").strip().lower()
    full_name = f"{module}!{function}"
    normalized_function = _normalized_api_export_name(function)
    for raw_pattern in filter_patterns:
        pattern = str(raw_pattern or "").strip().lower()
        if not pattern:
            continue
        if not pattern.startswith("="):
            if pattern in full_name:
                return True
            continue
        exact = pattern[1:].strip()
        if not exact:
            continue
        if "!" in exact:
            expected_module, expected_function = exact.rsplit("!", 1)
            if (
                module == expected_module
                and normalized_function
                == _normalized_api_export_name(expected_function)
            ):
                return True
        elif normalized_function == _normalized_api_export_name(exact):
            return True
    return False


def _enumerate_import_targets(
    modules: List[str],
    filter_patterns: List[str],
) -> List[Dict[str, Any]]:
    """Return list of {module, func, addr} for imports matching filter, dedup'd."""
    patterns_lower = [p.lower() for p in filter_patterns if p]
    modules_lower = [m.lower() for m in modules if m]
    targets: List[Dict[str, Any]] = []
    seen_addrs: set = set()
    try:
        module_list_result = GetModuleList()
        module_list = module_list_result.get("modules", []) if isinstance(module_list_result, dict) else []
    except Exception:
        return []
    debuggee_image = str(_get_current_debuggee_image_name() or "").lower()
    for mod in module_list:
        if not isinstance(mod, dict):
            continue
        mod_name = str(mod.get("name", "")).lower()
        # Always skip debuggee image — its exports aren't API calls, and
        # tracing them would mostly BP on inner functions.
        if mod_name == debuggee_image:
            continue
        # System DLLs only unless user asked for something specific.
        if modules_lower and mod_name not in modules_lower:
            continue
        # Enumerate exported functions via QuerySymbols.
        try:
            result = QuerySymbols(module=mod_name, offset=0, limit=50000)
            symbols = result.get("symbols", []) if isinstance(result, dict) else []
        except Exception:
            continue
        for sym in symbols:
            if not isinstance(sym, dict):
                continue
            sym_type = str(sym.get("type", "")).lower()
            # Only exported symbol RVAs identify executable function entry
            # points in the loaded module. Import RVAs identify IAT data slots;
            # placing an INT3 there corrupts the pointer and changes target
            # behavior instead of tracing it.
            if sym_type != "export":
                continue
            func_name = str(sym.get("name", ""))
            if not func_name:
                continue
            if patterns_lower and not _api_export_matches_filters(
                mod_name, func_name, patterns_lower
            ):
                continue
            rva = sym.get("rva")
            if rva is None:
                continue
            try:
                base = int(str(mod.get("base") or "0x0"), 16)
                rva_int = int(str(rva), 16) if isinstance(rva, str) else int(rva)
                addr = f"0x{base + rva_int:x}"
            except Exception:
                continue
            # Deduplicate: a function can be exported under multiple aliases
            # (A/W, forwarded names) all mapping to the same address.
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            targets.append({"module": mod_name, "func": func_name, "addr": addr})
    return targets


def _unwrap_scalar_result(val: Any) -> str:
    """Normalize x64dbg tool output to a bare string (extracts 'result' from dicts)."""
    if isinstance(val, dict):
        return str(val.get("result", ""))
    return str(val) if val is not None else ""


def _sample_api_args(bitness: int, arg_count: int) -> List[Dict[str, Any]]:
    """Read register/stack slots that hold the first N args of a typical call."""
    expressions: List[str] = []
    locations: List[Dict[str, Any]] = []
    if bitness == 64:
        reg_args = ["rcx", "rdx", "r8", "r9"]
        for i in range(min(arg_count, 4)):
            expressions.append(reg_args[i])
            locations.append({"index": i, "reg": reg_args[i]})
        for i in range(4, arg_count):
            offset = 0x28 + (i - 4) * 8
            expression = f"[rsp+0x{offset:x}]"
            expressions.append(expression)
            locations.append({"index": i, "stack": expression})
    else:
        for i in range(arg_count):
            offset = 4 + i * 4
            expression = f"[esp+0x{offset:x}]"
            expressions.append(expression)
            locations.append({"index": i, "stack": expression})
    try:
        batch = EvalBatch(json.dumps(expressions))
        items = batch.get("items", []) if isinstance(batch, dict) else []
        if len(items) == len(locations):
            batched: List[Dict[str, Any]] = []
            for location, item in zip(locations, items):
                if not isinstance(item, dict) or not item.get("success"):
                    continue
                value = item.get("value")
                if value is None:
                    value = item.get("valueHex")
                batched.append({**location, "value": str(value or "0x0")})
            if batched:
                return batched
    except Exception:
        pass

    # Compatibility fallback for legacy bridges without Eval/Batch.
    args: List[Dict[str, Any]] = []
    if bitness == 64:
        # Windows x64: rcx, rdx, r8, r9, then [rsp+0x28], [rsp+0x30], ...
        reg_args = ["rcx", "rdx", "r8", "r9"]
        for i in range(min(arg_count, 4)):
            try:
                val = _unwrap_scalar_result(RegisterGet(reg_args[i]))
                args.append({"index": i, "reg": reg_args[i], "value": val})
            except Exception:
                pass
        for i in range(4, arg_count):
            offset = 0x28 + (i - 4) * 8
            try:
                val = _unwrap_scalar_result(MiscParseExpression(f"[rsp+0x{offset:x}]"))
                args.append({"index": i, "stack": f"[rsp+0x{offset:x}]", "value": val})
            except Exception:
                pass
    else:
        # cdecl / stdcall: [esp+4], [esp+8], ...
        for i in range(arg_count):
            offset = 4 + i * 4
            try:
                val = _unwrap_scalar_result(MiscParseExpression(f"[esp+0x{offset:x}]"))
                args.append({"index": i, "stack": f"[esp+0x{offset:x}]", "value": val})
            except Exception:
                pass
    return args


def _api_arg_try_decode_string(value_hex: Any, max_chars: int = 64) -> Optional[str]:
    """If value looks like a pointer to an ASCII/UTF-16 string, return decoded text.

    MemoryIsValidPtr proved unreliable (returns False for valid image addrs in
    x64dbg), so we attempt ReadMemory directly and let it fail silently for
    non-pointer values. Tries ASCII then UTF-16.
    """
    # Normalize — callers may pass us wrapped dict / str / None.
    raw = _unwrap_scalar_result(value_hex).strip()
    if not raw or not raw.startswith("0x"):
        return None
    try:
        addr_int = int(raw, 16)
        # Skip tiny integers / obviously-not-pointer values.
        if addr_int == 0 or addr_int < 0x10000:
            return None
        # Helper: require at least 3 consecutive alphanumeric-or-space chars
        # at the start. Guards against random bytes that happen to pass a
        # printable-ratio test (HWNDs, handles, etc.).
        def _looks_like_real_string(text: str) -> bool:
            if not text or len(text) < 3:
                return False
            head = text[:6]
            alnum_or_space = sum(
                1 for c in head if c.isalnum() or c in " -_/."
            )
            if alnum_or_space < 3:
                return False
            printable = sum(1 for c in text if 32 <= ord(c) < 127)
            return printable / max(len(text), 1) > 0.85
        # Try ASCII first.
        read = ReadMemory(f"0x{addr_int:x}", max_chars, ty="ascii", max_chars=max_chars)
        if isinstance(read, dict) and read.get("ok"):
            text = str(read.get("text") or "")
            if _looks_like_real_string(text):
                return text
        # Try UTF-16 (Windows wide strings).
        read = ReadMemory(f"0x{addr_int:x}", max_chars * 2, ty="utf16", max_chars=max_chars)
        if isinstance(read, dict) and read.get("ok"):
            text = str(read.get("text") or "")
            if _looks_like_real_string(text):
                return f"L\"{text}\""
    except Exception:
        return None
    return None


def _api_value_int(value: Any) -> int:
    raw = _unwrap_scalar_result(value).strip()
    try:
        return int(raw, 0) if raw else 0
    except (TypeError, ValueError):
        try:
            return int(raw, 16) if raw else 0
        except (TypeError, ValueError):
            return 0


def _decode_api_return(
    function: str,
    value: Any,
    args: Optional[List[Dict[str, Any]]] = None,
    out_buffers: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Decode a raw ABI return without losing the original debugger value."""

    raw = _unwrap_scalar_result(value).strip() or "0x0"
    numeric = _api_value_int(raw)
    signature = _api_signature(function)
    return_type = str(signature.get("returnType") or "uintptr_t")
    lowered_type = return_type.casefold().replace("const ", "").strip()
    lowered_name = str(function or "").rsplit("!", 1)[-1].casefold()
    result: Dict[str, Any] = {
        "raw": raw,
        "type": return_type,
        "numeric": numeric,
        "hex": f"0x{numeric:x}",
    }

    if lowered_type in {"bool", "boolean"}:
        result.update(
            {
                "boolean": bool(numeric),
                "success": bool(numeric),
                "classification": "success" if numeric else "failure",
            }
        )
    elif lowered_type in {"int", "long", "short", "ssize_t", "intptr_t"}:
        signed = numeric & 0xFFFFFFFFFFFFFFFF
        if lowered_type in {"int", "long", "short"}:
            bits = 16 if lowered_type == "short" else 32
            signed = numeric & ((1 << bits) - 1)
            if signed & (1 << (bits - 1)):
                signed -= 1 << bits
        else:
            bits = 64
            if signed & (1 << 63):
                signed -= 1 << 64
        result["signed"] = signed
        result["classification"] = "success" if signed >= 0 else "failure"
    elif "ntstatus" in lowered_type or lowered_type in {"hresult", "lstatus"}:
        signed = numeric & 0xFFFFFFFF
        if signed & 0x80000000:
            signed -= 0x100000000
        result.update(
            {
                "signed": signed,
                "severity": (numeric >> 30) & 0x3,
                "facility": (numeric >> 16) & 0xFFF,
                "code": numeric & 0xFFFF,
                "success": signed >= 0,
                "classification": "success" if signed >= 0 else "failure",
            }
        )
    elif (
        "ptr" in lowered_type
        or "*" in lowered_type
        or lowered_type in {
            "farproc",
            "hmodule",
            "handle",
            "socket",
            "lpvoid",
            "pvoid",
            "size_t",
            "dword_ptr",
            "uintptr_t",
        }
    ):
        invalid_handle = (
            lowered_type == "handle" and numeric == 0xFFFFFFFFFFFFFFFF
        ) or (lowered_type == "handle" and numeric == 0xFFFFFFFF)
        result.update(
            {
                "address": raw,
                "isNull": numeric == 0,
                "isInvalidHandle": invalid_handle,
                "classification": (
                    "null"
                    if numeric == 0
                    else "invalid_handle"
                    if invalid_handle
                    else "non_null"
                ),
            }
        )
    else:
        result["classification"] = "numeric"

    if lowered_name in {"getprocaddress", "getprocaddressforcaller"}:
        result["resolvedAddress"] = raw
        result["resolved"] = numeric != 0
    elif lowered_name.startswith("loadlibrary") or lowered_name in {
        "getmodulehandlea",
        "getmodulehandlew",
    }:
        result["moduleBase"] = raw
        result["loaded"] = numeric != 0
    elif lowered_name == "getfilesize":
        result["low32"] = numeric & 0xFFFFFFFF
        high = _api_value_int(_api_arg_value(args or [], 1))
        result["combinedSize"] = (high << 32) | (numeric & 0xFFFFFFFF)
    elif lowered_name in {"getenvironmentvariablea", "getenvironmentvariablew"}:
        requested = _api_value_int(_api_arg_value(args or [], 2))
        result["bufferSize"] = requested
        result["requiredOrCopied"] = numeric
        result["truncated"] = bool(requested and numeric >= requested)

    buffers = [item for item in (out_buffers or []) if isinstance(item, dict)]
    if buffers:
        result["outBufferCount"] = len(buffers)
        result["outBufferFaults"] = sum(
            1
            for item in buffers
            if item.get("fault") or item.get("ok") is False
        )
        result["outBufferLabels"] = [
            str(item.get("label") or "")
            for item in buffers[:32]
            if str(item.get("label") or "")
        ]
    return result


def _api_arg_value(args: List[Dict[str, Any]], index: int) -> str:
    for item in args:
        if isinstance(item, dict) and int(item.get("index", -1)) == int(index):
            return str(item.get("value") or "")
    return ""


def _api_register_value(expression: str) -> str:
    try:
        payload = EvalBatch(json.dumps([expression]))
        items = payload.get("items", []) if isinstance(payload, dict) else []
        if items and isinstance(items[0], dict) and items[0].get("success"):
            return str(items[0].get("value") or items[0].get("valueHex") or "0x0")
    except Exception:
        pass
    return _unwrap_scalar_result(RegisterGet(expression))


def _api_trace_thread_id(state: Dict[str, Any]) -> int:
    session = state.get("session") if isinstance(state.get("session"), dict) else {}
    return int(
        state.get("threadId")
        or session.get("threadId")
        or (state.get("waitInfo") or {}).get("threadId")
        or 0
    )


def _api_trace_callstack(max_frames: int) -> List[Dict[str, Any]]:
    try:
        payload = _collect_call_stack(log=False)
        entries = payload.get("entries", []) if isinstance(payload, dict) else []
        return [dict(item) for item in entries[: max(0, int(max_frames))] if isinstance(item, dict)]
    except Exception:
        return []


def _api_callstack_matches(
    entries: List[Dict[str, Any]], caller_filter: str
) -> bool:
    pattern = str(caller_filter or "").strip().lower()
    if not pattern:
        return True
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        haystack = " ".join(
            str(entry.get(key) or "")
            for key in ("comment", "module", "function", "label", "symbol")
        ).lower()
        if pattern in haystack:
            return True
    return False


def _api_call_family(function: str) -> str:
    name = str(function or "").lower()
    normalized = _normalized_api_export_name(name)
    resource_catalog = globals().get("HEAP_RESOURCE_CATALOG", {})
    resource_spec = (
        resource_catalog.get(normalized)
        if isinstance(resource_catalog, dict)
        else None
    )
    if isinstance(resource_spec, dict):
        return f"resource_{resource_spec.get('op') or 'call'}"
    if "realloc" in name or "reallocate" in name:
        return "heap_realloc"
    if "heapfree" in name or "freeheap" in name:
        return "heap_free"
    if "heapalloc" in name or "allocateheap" in name:
        return "heap_alloc"
    return ""


def _api_wrapper_alias_key(function: str) -> str:
    """Return a conservative key for Win32 wrapper/extended API aliases.

    On x64 many one-argument wrappers tail-jump to their ``Ex`` variant and
    therefore keep the caller's return address.  On x86 the same wrapper is
    commonly implemented as a real nested call, so return-address equality is
    not sufficient to recognize one logical API invocation.  Normalize only
    conventional A/W and Ex suffixes and require the functions to be nested on
    the same thread before using this key.
    """

    name = str(function or "").strip().lower()
    if "!" in name:
        name = name.rsplit("!", 1)[-1]
    name = re.sub(r"@\d+$", "", name).lstrip("_")
    original = name
    if len(name) > 3 and name.endswith(("a", "w")):
        name = name[:-1]
    if len(name) > 4 and name.endswith("ex"):
        name = name[:-2]
    if len(name) > 3 and name.endswith(("a", "w")):
        name = name[:-1]
    return name if name and name != original else original


def _api_read_u32_pointer(pointer: str) -> Optional[int]:
    if _api_value_int(pointer) < 0x10000:
        return None
    try:
        payload = ReadMemory(pointer, 4, ty="hex", max_chars=8)
        raw = str(payload.get("hex") or "") if isinstance(payload, dict) else ""
        if len(raw) < 8:
            return None
        return int.from_bytes(bytes.fromhex(raw[:8]), "little", signed=False)
    except Exception:
        return None


def _capture_api_out_buffers(
    function: str,
    args: List[Dict[str, Any]],
    return_value: str,
    max_bytes: int,
) -> List[Dict[str, Any]]:
    """Capture bounded common Win32 output buffers immediately at API return."""

    name = str(function or "").lower()
    returned = _api_value_int(return_value)
    cap = max(0, min(int(max_bytes), 1_048_576))
    specs: List[Tuple[str, str, int, str, Dict[str, Any]]] = []

    if "getenvironmentvariablew" in name:
        pointer = _api_arg_value(args, 1)
        capacity_chars = _api_value_int(_api_arg_value(args, 2))
        actual_chars = min(capacity_chars, returned + 1) if returned > 0 else 0
        specs.append(("value", pointer, actual_chars * 2, "utf16", {"returnedChars": returned}))
    elif "getenvironmentvariablea" in name:
        pointer = _api_arg_value(args, 1)
        capacity = _api_value_int(_api_arg_value(args, 2))
        specs.append(("value", pointer, min(capacity, returned + 1) if returned > 0 else 0, "ascii", {"returnedChars": returned}))
    elif any(token in name for token in ("readfile", "internetreadfile")):
        pointer = _api_arg_value(args, 1)
        requested = _api_value_int(_api_arg_value(args, 2))
        bytes_read_pointer = _api_arg_value(args, 3)
        actual = _api_read_u32_pointer(bytes_read_pointer)
        specs.append(("buffer", pointer, min(requested, actual if actual is not None else requested), "hex", {"bytesRead": actual, "bytesReadPointer": bytes_read_pointer}))
    elif name.endswith("!recv") or name == "recv" or name.endswith(" recv"):
        pointer = _api_arg_value(args, 1)
        specs.append(("buffer", pointer, returned if 0 < returned < 0x80000000 else 0, "hex", {"bytesRead": returned}))
    elif "readprocessmemory" in name:
        pointer = _api_arg_value(args, 2)
        requested = _api_value_int(_api_arg_value(args, 3))
        bytes_read_pointer = _api_arg_value(args, 4)
        actual = _api_read_u32_pointer(bytes_read_pointer)
        specs.append(("buffer", pointer, min(requested, actual if actual is not None else requested), "hex", {"bytesRead": actual, "bytesReadPointer": bytes_read_pointer}))
    elif "getfilesizeex" in name:
        specs.append(
            (
                "size",
                _api_arg_value(args, 1),
                8,
                "hex",
                {"structure": "LARGE_INTEGER"},
            )
        )
    elif name.endswith("!getfilesize") or name == "getfilesize":
        specs.append(
            (
                "highSize",
                _api_arg_value(args, 1),
                4,
                "hex",
                {"structure": "DWORD"},
            )
        )
    elif "virtualprotect" in name:
        specs.append(
            (
                "oldProtect",
                _api_arg_value(args, 3),
                4,
                "hex",
                {"structure": "DWORD"},
            )
        )
    elif "checkremotedebuggerpresent" in name:
        specs.append(
            (
                "present",
                _api_arg_value(args, 1),
                4,
                "hex",
                {"structure": "BOOL"},
            )
        )
    elif "virtualquery" in name:
        requested = _api_value_int(_api_arg_value(args, 2))
        actual = returned if 0 < returned < 0x1000000 else requested
        specs.append(
            (
                "memoryInfo",
                _api_arg_value(args, 1),
                min(requested, actual),
                "hex",
                {"returnedBytes": returned},
            )
        )
    elif "multibytetowidechar" in name:
        requested = _api_value_int(_api_arg_value(args, 5))
        actual = returned * 2 if returned > 0 else 0
        specs.append(
            (
                "destination",
                _api_arg_value(args, 4),
                min(requested * 2, actual) if actual else 0,
                "utf16",
                {"returnedChars": returned},
            )
        )
    elif "widechartomultibyte" in name:
        requested = _api_value_int(_api_arg_value(args, 5))
        specs.append(
            (
                "destination",
                _api_arg_value(args, 4),
                min(requested, returned) if returned > 0 else 0,
                "ascii",
                {"returnedBytes": returned},
            )
        )
    elif "ntqueryinformationprocess" in name:
        requested = _api_value_int(_api_arg_value(args, 3))
        actual = _api_read_u32_pointer(_api_arg_value(args, 4))
        specs.append(
            (
                "processInfo",
                _api_arg_value(args, 2),
                min(requested, actual if actual is not None else requested),
                "hex",
                {"returnLength": actual, "returnLengthPointer": _api_arg_value(args, 4)},
            )
        )
    elif "getmodulefilenamew" in name:
        specs.append(("path", _api_arg_value(args, 1), (returned + 1) * 2 if returned else 0, "utf16", {"returnedChars": returned}))
    elif "getmodulefilenamea" in name:
        specs.append(("path", _api_arg_value(args, 1), returned + 1 if returned else 0, "ascii", {"returnedChars": returned}))
    elif "regqueryvalueex" in name:
        pointer = _api_arg_value(args, 4)
        size_pointer = _api_arg_value(args, 5)
        actual = _api_read_u32_pointer(size_pointer)
        specs.append(("data", pointer, actual or 0, "hex", {"bytesReturned": actual, "sizePointer": size_pointer}))

    captured: List[Dict[str, Any]] = []
    for label, pointer, requested_size, format_name, metadata in specs:
        pointer_value = _api_value_int(pointer)
        size = max(0, min(int(requested_size), cap))
        entry: Dict[str, Any] = {
            "label": label,
            "pointer": pointer or None,
            "requestedBytes": max(0, int(requested_size)),
            "capturedBytes": size,
            "truncated": int(requested_size) > size,
            **metadata,
        }
        if pointer_value < 0x10000 or size <= 0:
            entry.update(
                {
                    "ok": False,
                    "error": "Output buffer is null or empty.",
                    "fault": {
                        "code": "null_or_empty_output",
                        "address": pointer or None,
                        "requestedBytes": max(0, int(requested_size)),
                        "retryable": False,
                    },
                }
            )
        else:
            try:
                read = ReadMemory(
                    pointer,
                    size,
                    ty=format_name,
                    max_chars=min(cap, 65536),
                )
                entry["read"] = read
                entry["ok"] = bool(isinstance(read, dict) and read.get("ok"))
                if not entry["ok"]:
                    error = (
                        read.get("error")
                        if isinstance(read, dict)
                        else "ReadMemory returned a non-object response."
                    )
                    error_code = (
                        read.get("errorCode")
                        if isinstance(read, dict)
                        else "invalid_read_response"
                    )
                    if isinstance(error, dict):
                        error_code = error.get("code") or error_code
                        error = error.get("message") or str(error)
                    entry["fault"] = {
                        "code": str(error_code or "output_read_failed"),
                        "message": str(error or "Output buffer read failed."),
                        "address": pointer,
                        "requestedBytes": size,
                        "retryable": bool(
                            isinstance(read, dict) and read.get("retryable")
                        ),
                    }
            except Exception as exc:
                entry.update(
                    {
                        "ok": False,
                        "fault": {
                            "code": "output_read_exception",
                            "message": str(exc),
                            "exceptionType": type(exc).__name__,
                            "address": pointer,
                            "requestedBytes": size,
                            "retryable": False,
                        },
                    }
                )
        captured.append(entry)
    return captured


# Hard cap on BPs per API-trace session. 200+ BPs in user32 can hit every
# message loop and make the debugger unresponsive; caller should narrow filter.
MAX_API_TRACE_BREAKPOINTS = 200


def _install_api_trace_subscription_targets(
    trace_id: str,
    targets: List[Dict[str, Any]],
    source: str,
) -> dict:
    """Install newly discovered API entries under the trace ownership cap."""

    record = _get_api_trace(trace_id)
    if not record:
        return {"ok": False, "traceId": trace_id, "error": "Trace session not found"}
    target_map = dict(record.get("targetMap") or {})
    cap = max(
        1,
        min(
            int(record.get("maxTargets") or MAX_API_TRACE_BREAKPOINTS),
            500,
        ),
    )
    ownership_prefix = str(
        record.get("breakpointOwnershipPrefix") or "mcp_api_trace:"
    )
    snapshot = _collect_breakpoint_snapshot(log=False)
    existing_breakpoints = {
        _normalize_hex(item.get("addr")): item
        for item in snapshot.get("breakpoints", [])
        if isinstance(item, dict) and _normalize_hex(item.get("addr"))
    }
    native_hooks_enabled = bool(record.get("nativeReturnHooks"))
    added: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    owned: List[str] = []
    preexisting: List[str] = []
    for raw_target in targets:
        normalized = _normalize_hex(raw_target.get("addr"))
        if not normalized or normalized.lower() in target_map:
            continue
        if len(target_map) >= cap:
            failures.append(
                {
                    "addr": normalized,
                    "errorCode": "target_cap_reached",
                    "error": f"API trace target cap {cap} reached.",
                }
            )
            break
        target = dict(raw_target)
        target["addr"] = normalized
        target["source"] = str(source or "module-subscription")
        # Register the address before arming it.  This closes the small race
        # where x64dbg can report a newly armed breakpoint before the
        # ownership name has propagated to the plugin callback.
        if native_hooks_enabled:
            _configure_native_api_trace(
                trace_id,
                native_return_hooks=True,
                entry_addresses=[normalized],
            )
        existing = existing_breakpoints.get(normalized)
        existed = existing is not None
        if existed:
            success = True
            result_text = "Breakpoint already present"
        else:
            mutation = DebugSetBreakpoint(normalized)
            result_text = str(
                mutation.get("result") if isinstance(mutation, dict) else mutation
            )
            success = (
                "success" in result_text.lower()
                and "error" not in result_text.lower()
            )
        if not success:
            failures.append(
                {
                    "addr": normalized,
                    "module": target.get("module"),
                    "func": target.get("func"),
                    "error": result_text or "Failed to install breakpoint.",
                }
            )
            continue
        target_map[normalized.lower()] = target
        added.append(target)
        if existed:
            preexisting.append(normalized)
        else:
            owned.append(normalized)
            ExecCommand(
                f'SetBreakpointName {normalized}, "{ownership_prefix}{trace_id}:entry"'
            )

    if added or failures:
        def _commit(trace: Dict[str, Any]) -> None:
            current_map = dict(trace.get("targetMap") or {})
            current_map.update(
                {
                    str(item["addr"]).lower(): dict(item)
                    for item in added
                }
            )
            trace["targetMap"] = current_map
            target_addrs = list(trace.get("targetAddrs") or [])
            for item in added:
                if item["addr"] not in target_addrs:
                    target_addrs.append(item["addr"])
            trace["targetAddrs"] = target_addrs
            trace["targetCount"] = len(current_map)
            owned_addrs = list(trace.get("ownedEntryBreakpoints") or [])
            for address in owned:
                if address not in owned_addrs:
                    owned_addrs.append(address)
            trace["ownedEntryBreakpoints"] = owned_addrs
            preexisting_addrs = list(
                trace.get("preexistingEntryBreakpoints") or []
            )
            for address in preexisting:
                if address not in preexisting_addrs:
                    preexisting_addrs.append(address)
            trace["preexistingEntryBreakpoints"] = preexisting_addrs
            history = list(trace.get("targetSubscriptions") or [])
            history.append(
                {
                    "timestamp": _now_iso(),
                    "source": str(source or "module-subscription"),
                    "added": len(added),
                    "failed": len(failures),
                    "targets": [
                        {
                            "addr": item.get("addr"),
                            "module": item.get("module"),
                            "func": item.get("func"),
                        }
                        for item in added[:100]
                    ],
                }
            )
            trace["targetSubscriptions"] = history[-256:]
            trace["subscriptionFailures"] = int(
                trace.get("subscriptionFailures") or 0
            ) + len(failures)

        _update_api_trace(trace_id, _commit)
    native_registration: Dict[str, Any] = {
        "ok": True,
        "skipped": True,
        "reason": "No newly discovered entry targets.",
    }
    if added:
        current = _get_api_trace(trace_id) or {}
        native_registration = _configure_native_api_trace(
            trace_id,
            native_return_hooks=bool(current.get("nativeReturnHooks")),
            entry_addresses=[str(item.get("addr") or "") for item in added],
        )
        if not native_registration.get("ok"):
            _update_api_trace(
                trace_id,
                lambda trace: trace.update(
                    {
                        "nativeRegistrationFailures": int(
                            trace.get("nativeRegistrationFailures") or 0
                        )
                        + 1
                    }
                ),
            )
    return {
        "ok": not failures,
        "traceId": trace_id,
        "source": str(source or "module-subscription"),
        "added": len(added),
        "failed": len(failures),
        "targetCount": len(target_map),
        "targets": added,
        "failures": failures[:50],
        "nativeRegistration": native_registration,
    }


def _refresh_api_trace_module_subscriptions(trace_id: str) -> dict:
    """Discover matching exports from modules loaded after trace start."""

    record = _get_api_trace(trace_id)
    if not record:
        return {"ok": False, "traceId": trace_id, "error": "Trace session not found"}
    if not record.get("subscribeModules", True):
        return {"ok": True, "traceId": trace_id, "skipped": True, "added": 0}
    now = time.monotonic()
    previous = float(record.get("_lastModuleRefreshMonotonic") or 0.0)
    if previous and now - previous < 0.5:
        return {"ok": True, "traceId": trace_id, "throttled": True, "added": 0}
    fingerprint = ""
    try:
        module_payload = GetModuleList()
        module_items = (
            module_payload.get("modules", [])
            if isinstance(module_payload, dict)
            else []
        )
        fingerprint = "|".join(
            sorted(
                f"{str(item.get('name') or '').lower()}@"
                f"{str(_normalize_hex(item.get('base')) or '')}"
                for item in module_items
                if isinstance(item, dict)
            )
        )
    except Exception:
        fingerprint = ""
    previous_fingerprint = str(
        record.get("_moduleSubscriptionFingerprint") or ""
    )
    _update_api_trace(
        trace_id,
        lambda trace: trace.update(
            {
                "_lastModuleRefreshMonotonic": now,
                "_moduleSubscriptionFingerprint": fingerprint
                or previous_fingerprint,
            }
        ),
    )
    if fingerprint and fingerprint == previous_fingerprint:
        return {
            "ok": True,
            "traceId": trace_id,
            "unchanged": True,
            "added": 0,
        }
    targets = _enumerate_import_targets(
        list(record.get("modules") or []),
        list(record.get("filters") or []),
    )
    known = {
        str(address).lower()
        for address in (record.get("targetMap") or {}).keys()
    }
    new_targets = [
        item
        for item in targets
        if str(_normalize_hex(item.get("addr")) or "").lower() not in known
    ]
    return _install_api_trace_subscription_targets(
        trace_id,
        new_targets,
        "module-load-refresh",
    )


def _find_loaded_module_record(module_name: str) -> Optional[Dict[str, Any]]:
    """Resolve one loaded module by full path, basename, or basename stem."""

    requested = str(module_name or "").strip().casefold()
    if not requested:
        return None
    requested_base = os.path.basename(requested)
    requested_stem = os.path.splitext(requested_base)[0]
    try:
        payload = GetModuleList()
        modules = payload.get("modules", []) if isinstance(payload, dict) else []
    except Exception:
        modules = []
    for item in modules:
        if not isinstance(item, dict):
            continue
        raw_name = str(item.get("name") or "").strip().casefold()
        raw_path = str(item.get("path") or "").strip().casefold()
        candidates = {
            raw_name,
            raw_path,
            os.path.basename(raw_name),
            os.path.basename(raw_path),
        }
        candidates |= {
            os.path.splitext(candidate)[0]
            for candidate in list(candidates)
            if candidate
        }
        if (
            requested in candidates
            or requested_base in candidates
            or requested_stem in candidates
        ):
            return dict(item)
    return None


def _disk_export_rva(path: str, symbol_name: str) -> Optional[int]:
    """Return the exact named export RVA from a PE without loading it."""

    resolved = os.path.abspath(str(path or ""))
    requested = str(symbol_name or "").strip()
    if not resolved or not requested or not os.path.isfile(resolved):
        return None
    try:
        import pefile  # type: ignore

        pe = pefile.PE(resolved, fast_load=False)
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        for symbol in list(getattr(directory, "symbols", []) or []):
            raw_name = getattr(symbol, "name", None)
            name = (
                raw_name.decode("ascii", errors="strict")
                if isinstance(raw_name, bytes)
                else str(raw_name or "")
            )
            if name == requested:
                return int(getattr(symbol, "address", 0) or 0)
    except Exception:
        return None
    return None


def _resolve_loaded_module_symbol(
    module_record: Dict[str, Any],
    symbol_name: str,
) -> Optional[str]:
    """Resolve a loaded export with a disk-RVA fallback for custom images."""

    module_name = str(
        (module_record or {}).get("name")
        or os.path.basename(str((module_record or {}).get("path") or ""))
    )
    address = _resolve_remote_symbol_address(module_name, symbol_name)
    if address:
        return address
    module_base = _parse_int((module_record or {}).get("base"), 0) or 0
    export_rva = _disk_export_rva(
        str((module_record or {}).get("path") or ""),
        symbol_name,
    )
    if module_base and export_rva is not None:
        return f"0x{module_base + export_rva:x}"
    return None


def _parse_custom_api_trace_targets(custom_targets_json: str) -> Dict[str, Any]:
    """Validate and resolve explicit entry targets for non-standard APIs."""

    text = str(custom_targets_json or "").strip()
    if not text:
        return {
            "ok": True,
            "schema": "api-trace-custom-targets-v1",
            "targets": [],
            "count": 0,
        }
    try:
        specs = json.loads(text)
    except Exception as exc:
        return {
            "ok": False,
            "schema": "api-trace-custom-targets-v1",
            "error": f"custom_targets_json is not valid JSON: {exc}",
        }
    if not isinstance(specs, list):
        return {
            "ok": False,
            "schema": "api-trace-custom-targets-v1",
            "error": "custom_targets_json must be a JSON array",
        }
    if len(specs) > 64:
        return {
            "ok": False,
            "schema": "api-trace-custom-targets-v1",
            "error": "At most 64 custom targets are allowed",
            "count": len(specs),
        }

    targets: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    allowed_target_keys = {
        "module",
        "symbol",
        "rva",
        "address",
        "name",
        "kind",
        "resolver",
    }
    allowed_resolver_keys = {
        "keyArgIndex",
        "moduleArgIndex",
        "keyEncoding",
        "subscribeResolved",
        "requireExactExport",
    }
    allowed_encodings = {
        "raw",
        "fnv1a32",
        "crc32",
        "djb2-32",
        "ror13-add32",
        "custom",
    }
    for index, raw_spec in enumerate(specs):
        if not isinstance(raw_spec, dict):
            errors.append(
                {"index": index, "error": "target must be a JSON object"}
            )
            continue
        unknown = sorted(set(raw_spec) - allowed_target_keys)
        if unknown:
            errors.append(
                {
                    "index": index,
                    "error": "unknown target fields",
                    "fields": unknown,
                }
            )
            continue
        module_name = str(raw_spec.get("module") or "").strip()
        selectors = [
            key
            for key in ("symbol", "rva", "address")
            if str(raw_spec.get(key) or "").strip()
        ]
        if not module_name:
            errors.append({"index": index, "error": "module is required"})
            continue
        if len(selectors) != 1:
            errors.append(
                {
                    "index": index,
                    "error": "exactly one of symbol, rva, or address is required",
                }
            )
            continue
        module_record = _find_loaded_module_record(module_name)
        if not module_record:
            errors.append(
                {
                    "index": index,
                    "error": "module is not loaded",
                    "module": module_name,
                }
            )
            continue
        module_base = _parse_int(module_record.get("base"), 0) or 0
        module_size = _parse_int(module_record.get("size"), 0) or 0
        selector = selectors[0]
        if selector == "symbol":
            address_text = _resolve_loaded_module_symbol(
                module_record,
                str(raw_spec.get("symbol") or ""),
            )
            address = _parse_int(address_text, 0) or 0
        elif selector == "rva":
            rva = _parse_int(raw_spec.get("rva"), None)
            address = module_base + int(rva) if rva is not None else 0
        else:
            address = _parse_int(raw_spec.get("address"), 0) or 0
        if (
            not module_base
            or not module_size
            or not address
            or not (module_base <= address < module_base + module_size)
        ):
            errors.append(
                {
                    "index": index,
                    "error": "resolved target address is outside the loaded module",
                    "module": module_name,
                    "address": f"0x{address:x}" if address else None,
                }
            )
            continue
        kind = str(raw_spec.get("kind") or "callable").strip().casefold()
        if kind not in {"callable", "import-resolver"}:
            errors.append(
                {
                    "index": index,
                    "error": "kind must be callable or import-resolver",
                }
            )
            continue
        resolver_spec: Optional[Dict[str, Any]] = None
        raw_resolver = raw_spec.get("resolver")
        if kind == "import-resolver":
            if raw_resolver is None:
                raw_resolver = {}
            if not isinstance(raw_resolver, dict):
                errors.append(
                    {"index": index, "error": "resolver must be an object"}
                )
                continue
            resolver_unknown = sorted(
                set(raw_resolver) - allowed_resolver_keys
            )
            if resolver_unknown:
                errors.append(
                    {
                        "index": index,
                        "error": "unknown resolver fields",
                        "fields": resolver_unknown,
                    }
                )
                continue
            try:
                key_index = int(raw_resolver.get("keyArgIndex", 1))
                module_index = int(raw_resolver.get("moduleArgIndex", 0))
            except (TypeError, ValueError):
                errors.append(
                    {
                        "index": index,
                        "error": "resolver argument indexes must be integers",
                    }
                )
                continue
            if not (0 <= key_index <= 7) or not (-1 <= module_index <= 7):
                errors.append(
                    {
                        "index": index,
                        "error": "resolver argument indexes are out of range",
                    }
                )
                continue
            encoding = str(
                raw_resolver.get("keyEncoding") or "raw"
            ).strip().casefold()
            if encoding not in allowed_encodings:
                errors.append(
                    {
                        "index": index,
                        "error": "unsupported resolver keyEncoding",
                        "keyEncoding": encoding,
                    }
                )
                continue
            resolver_spec = {
                "keyArgIndex": key_index,
                "moduleArgIndex": module_index,
                "keyEncoding": encoding,
                "subscribeResolved": bool(
                    raw_resolver.get("subscribeResolved", True)
                ),
                "requireExactExport": bool(
                    raw_resolver.get("requireExactExport", True)
                ),
            }
        elif raw_resolver is not None:
            errors.append(
                {
                    "index": index,
                    "error": "resolver is only valid for kind=import-resolver",
                }
            )
            continue
        symbol_name = str(raw_spec.get("symbol") or "").strip()
        target_name = str(
            raw_spec.get("name")
            or symbol_name
            or f"custom_{address:x}"
        ).strip()
        targets.append(
            {
                "module": str(
                    module_record.get("name")
                    or os.path.basename(str(module_record.get("path") or ""))
                    or module_name
                ),
                "func": target_name,
                "addr": f"0x{address:x}",
                "rva": f"0x{address - module_base:x}",
                "source": "custom-target",
                "targetKind": kind,
                "resolverSpec": resolver_spec,
            }
        )
    return {
        "ok": not errors,
        "schema": "api-trace-custom-targets-v1",
        "targets": targets,
        "count": len(targets),
        "errors": errors,
    }


def _resolve_runtime_export_identity(address: Any) -> Dict[str, Any]:
    """Map a live pointer to an exact, non-forwarded PE export."""

    target = _parse_int(address, 0) or 0
    if target < 0x10000:
        return {
            "ok": False,
            "schema": "runtime-export-identity-v1",
            "reason": "invalid_address",
            "address": f"0x{target:x}",
        }
    try:
        import pefile  # type: ignore

        payload = GetModuleList()
        modules = payload.get("modules", []) if isinstance(payload, dict) else []
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-export-identity-v1",
            "reason": "module_catalog_unavailable",
            "address": f"0x{target:x}",
            "error": str(exc),
        }
    module = next(
        (
            item
            for item in modules
            if isinstance(item, dict)
            and (_parse_int(item.get("base"), 0) or 0) <= target
            < (_parse_int(item.get("base"), 0) or 0)
            + (_parse_int(item.get("size"), 0) or 0)
        ),
        None,
    )
    if not module:
        return {
            "ok": False,
            "schema": "runtime-export-identity-v1",
            "reason": "address_not_in_loaded_module",
            "address": f"0x{target:x}",
        }
    module_base = _parse_int(module.get("base"), 0) or 0
    export_rva = target - module_base
    path = os.path.abspath(str(module.get("path") or ""))
    if not path or not os.path.isfile(path):
        return {
            "ok": False,
            "schema": "runtime-export-identity-v1",
            "reason": "module_file_unavailable",
            "address": f"0x{target:x}",
            "module": module.get("name"),
            "exportRva": f"0x{export_rva:x}",
        }
    try:
        pe = pefile.PE(path, fast_load=False)
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        matches: List[Dict[str, Any]] = []
        for symbol in list(getattr(directory, "symbols", []) or []):
            if int(getattr(symbol, "address", 0) or 0) != export_rva:
                continue
            raw_name = getattr(symbol, "name", None)
            name = (
                raw_name.decode("ascii", errors="strict")
                if isinstance(raw_name, bytes)
                else str(raw_name or "")
            )
            forwarder = getattr(symbol, "forwarder", None)
            matches.append(
                {
                    "function": name or None,
                    "ordinal": int(getattr(symbol, "ordinal", 0) or 0),
                    "forwarder": (
                        forwarder.decode("ascii", errors="replace")
                        if isinstance(forwarder, bytes)
                        else str(forwarder or "")
                    )
                    or None,
                }
            )
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-export-identity-v1",
            "reason": "export_catalog_failed",
            "address": f"0x{target:x}",
            "module": module.get("name"),
            "exportRva": f"0x{export_rva:x}",
            "error": str(exc),
        }
    matches.sort(
        key=lambda item: (
            item.get("forwarder") is not None,
            item.get("function") is None,
            str(item.get("function") or "").casefold(),
            int(item.get("ordinal") or 0),
        )
    )
    exact = next(
        (item for item in matches if not item.get("forwarder")),
        None,
    )
    if not exact:
        return {
            "ok": False,
            "schema": "runtime-export-identity-v1",
            "reason": (
                "forwarded_export"
                if matches
                else "address_is_not_exact_export"
            ),
            "address": f"0x{target:x}",
            "module": str(
                module.get("name") or os.path.basename(path)
            ),
            "modulePath": path,
            "moduleBase": f"0x{module_base:x}",
            "exportRva": f"0x{export_rva:x}",
            "aliases": matches,
        }
    return {
        "ok": True,
        "schema": "runtime-export-identity-v1",
        "reason": "exact_export",
        "address": f"0x{target:x}",
        "module": str(module.get("name") or os.path.basename(path)),
        "modulePath": path,
        "moduleBase": f"0x{module_base:x}",
        "moduleSize": f"0x{(_parse_int(module.get('size'), 0) or 0):x}",
        "moduleSha256": (_sha256_file(path) or "").upper() or None,
        "exportRva": f"0x{export_rva:x}",
        "function": exact.get("function"),
        "ordinal": int(exact.get("ordinal") or 0),
        "aliases": matches,
    }


def _api_argument_at(call_record: Dict[str, Any], index: int) -> Dict[str, Any]:
    return next(
        (
            item
            for item in (call_record.get("args") or [])
            if isinstance(item, dict)
            and int(item.get("index", -1)) == int(index)
        ),
        {},
    )


def _subscribe_dynamic_resolver_target(
    trace_id: str,
    call_record: Dict[str, Any],
    return_value: Any,
) -> dict:
    """Observe resolver returns and optionally subscribe the resolved target."""

    function = str(call_record.get("func") or "").lower()
    resolver_spec = (
        dict(call_record.get("resolverSpec") or {})
        if isinstance(call_record.get("resolverSpec"), dict)
        else {}
    )
    is_custom_resolver = (
        str(call_record.get("targetKind") or "").casefold()
        == "import-resolver"
        or bool(resolver_spec)
    )
    if "getprocaddress" not in function and not is_custom_resolver:
        return {"ok": True, "traceId": trace_id, "skipped": True, "added": 0}
    record = _get_api_trace(trace_id) or {}
    if not record.get("discoverDynamicResolvers", True) and not is_custom_resolver:
        return {"ok": True, "traceId": trace_id, "skipped": True, "added": 0}
    address = _api_value_int(return_value)
    if address < 0x10000:
        return {
            "ok": not is_custom_resolver,
            "traceId": trace_id,
            "skipped": not is_custom_resolver,
            "reason": "resolver returned null/non-pointer",
            "added": 0,
        }
    if is_custom_resolver:
        key_index = int(resolver_spec.get("keyArgIndex", 1))
        module_index = int(resolver_spec.get("moduleArgIndex", 0))
        key_argument = _api_argument_at(call_record, key_index)
        module_argument = (
            _api_argument_at(call_record, module_index)
            if module_index >= 0
            else {}
        )
        identity = _resolve_runtime_export_identity(address)
        evidence = {
            "schema": "custom-import-resolver-observation-v1",
            "resolverCallSeq": int(call_record.get("seq") or 0),
            "resolverModule": call_record.get("module"),
            "resolverFunction": call_record.get("func"),
            "keyArgIndex": key_index,
            "requestKey": key_argument.get("value"),
            "requestKeyInt": _api_value_int(key_argument.get("value")),
            "keyEncoding": str(
                resolver_spec.get("keyEncoding") or "raw"
            ),
            "moduleArgIndex": module_index,
            "requestedModuleHandle": (
                module_argument.get("value") if module_index >= 0 else None
            ),
            "returnedTarget": f"0x{address:x}",
            "exactExport": bool(identity.get("ok")),
            "identity": identity,
        }
        require_exact = bool(
            resolver_spec.get("requireExactExport", True)
        )
        if require_exact and not identity.get("ok"):
            return {
                "ok": False,
                "traceId": trace_id,
                "source": "custom-resolver-return",
                "reason": "resolver return is not an exact PE export",
                "added": 0,
                "resolverEvidence": evidence,
            }
        symbol_name = str(
            identity.get("function")
            or (
                f"ordinal_{int(identity.get('ordinal') or 0)}"
                if int(identity.get("ordinal") or 0)
                else ""
            )
            or f"resolved_{address:x}"
        )
        if not bool(resolver_spec.get("subscribeResolved", True)):
            return {
                "ok": bool(identity.get("ok") or not require_exact),
                "traceId": trace_id,
                "source": "custom-resolver-return",
                "reason": "resolved target observed; subscription disabled",
                "symbol": symbol_name,
                "added": 0,
                "resolverEvidence": evidence,
            }
        patterns = [
            str(item).lower()
            for item in (record.get("filters") or [])
            if str(item).strip()
        ]
        if patterns and not any(
            pattern in symbol_name.lower() for pattern in patterns
        ):
            return {
                "ok": True,
                "traceId": trace_id,
                "source": "custom-resolver-return",
                "reason": "resolved symbol does not match trace filters",
                "symbol": symbol_name,
                "added": 0,
                "resolverEvidence": evidence,
            }
        installed = _install_api_trace_subscription_targets(
            trace_id,
            [
                {
                    "module": str(identity.get("module") or "dynamic"),
                    "func": symbol_name,
                    "addr": f"0x{address:x}",
                    "resolverCallSeq": int(call_record.get("seq") or 0),
                    "targetKind": "resolved-import",
                }
            ],
            "custom-resolver-return",
        )
        installed["resolverEvidence"] = evidence
        return installed
    argument = next(
        (
            item
            for item in (call_record.get("args") or [])
            if isinstance(item, dict) and int(item.get("index", -1)) == 1
        ),
        {},
    )
    preview = str(argument.get("stringPreview") or "").strip()
    if preview.startswith('L"') and preview.endswith('"'):
        preview = preview[2:-1]
    elif preview.startswith('"') and preview.endswith('"'):
        preview = preview[1:-1]
    if not preview:
        ordinal = _api_value_int(argument.get("value"))
        preview = f"ordinal_{ordinal}" if 0 < ordinal <= 0xFFFF else ""
    if not preview:
        return {
            "ok": True,
            "traceId": trace_id,
            "skipped": True,
            "reason": "resolver name unavailable",
            "added": 0,
        }
    patterns = [
        str(item).lower()
        for item in (record.get("filters") or [])
        if str(item).strip()
    ]
    if patterns and not any(pattern in preview.lower() for pattern in patterns):
        return {
            "ok": True,
            "traceId": trace_id,
            "skipped": True,
            "reason": "resolved symbol does not match trace filters",
            "symbol": preview,
            "added": 0,
        }
    module_name = "dynamic"
    try:
        payload = GetModuleList()
        for module in payload.get("modules", []) if isinstance(payload, dict) else []:
            if not isinstance(module, dict):
                continue
            base = int(str(module.get("base") or "0"), 0)
            size = int(str(module.get("size") or "0"), 0)
            if base and size and base <= address < base + size:
                module_name = str(module.get("name") or module_name).lower()
                break
    except Exception:
        pass
    return _install_api_trace_subscription_targets(
        trace_id,
        [
            {
                "module": module_name,
                "func": preview,
                "addr": f"0x{address:x}",
                "resolverCallSeq": int(call_record.get("seq") or 0),
            }
        ],
        "getprocaddress-return",
    )


@mcp.tool()
def StartApiTrace(
    modules_json: str = "",
    filter_json: str = "",
    arg_count: int = DEFAULT_API_ARG_COUNT,
    label: str = "",
    max_targets: int = MAX_API_TRACE_BREAKPOINTS,
    capture_returns: bool = True,
    capture_callstack: bool = True,
    max_callstack_frames: int = 16,
    max_out_bytes: int = 4096,
    caller_filter: str = "",
    decode_string_args: bool = True,
    collapse_nested_families: bool = False,
    subscribe_modules: bool = True,
    discover_dynamic_resolvers: bool = True,
    native_return_hooks: bool = True,
    custom_targets_json: str = "",
) -> dict:
    """
    Set up (but do not yet run) an API call trace session.

    Enumerates imports matching `filter_json` in `modules_json` and sets
    silent+continue-on-hit breakpoints on each target. Use RunApiTrace to
    drive the debuggee and collect calls.

    Args:
        modules_json: JSON array of module names (e.g. `["kernel32.dll","ws2_32.dll"]`).
            Empty → typical OS modules (kernel32/user32/advapi32/ws2_32/wininet/ntdll).
        filter_json: JSON array of substrings to match `module!func`.
            Empty → DEFAULT_API_FILTERS (file I/O, memory, process, net, crypto, etc.)
        custom_targets_json: Strict JSON array of explicit loaded-module
            targets. Each item selects exactly one symbol, RVA, or address.
            `kind="import-resolver"` records custom/hash resolver returns as
            exact PE exports using supplied resolver argument metadata.
        arg_count: Number of args to sample per call (default 4, max 8).
        label: Optional session label.
        max_targets: Max number of BPs to actually set (default 200). If the
            filter matches more, returns an error listing counts per module so
            the caller can narrow the filter.
        subscribe_modules: Periodically discover matching exports in modules
            that load after the trace starts.
        discover_dynamic_resolvers: Add a bounded owned breakpoint for a
            matching function pointer returned by GetProcAddress.
        native_return_hooks: Let the native breakpoint callback install and
            remove return hooks. Python remains a fail-safe if native
            scheduling is unavailable or rejects a hook.

    Returns summary: {ok, traceId, targetCount, modules, filters, warnings}.
    """
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging"):
        return {
            "ok": False,
            "error": "StartApiTrace requires an active debug session (not debugging)",
            "currentState": state.get("state"),
        }
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return {
            "ok": False,
            "error": "Authoritative bridge/session identity is unavailable.",
            "bridge": hello,
        }
    warnings: List[str] = []
    modules: List[str] = []
    if modules_json:
        try:
            parsed_modules = json.loads(modules_json)
            if isinstance(parsed_modules, list):
                modules = [str(m) for m in parsed_modules]
            else:
                warnings.append(f"modules_json must be a JSON array, got {type(parsed_modules).__name__}; using defaults")
        except Exception as e:
            warnings.append(f"modules_json JSON parse failed ({e}); using defaults")
    if not modules:
        modules = ["kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll",
                   "ws2_32.dll", "wininet.dll", "ntdll.dll", "ucrtbase.dll",
                   "msvcrt.dll"]
    filter_patterns: List[str] = []
    if filter_json:
        try:
            parsed_filter = json.loads(filter_json)
            if isinstance(parsed_filter, list):
                filter_patterns = [str(p) for p in parsed_filter]
            else:
                warnings.append(f"filter_json must be a JSON array, got {type(parsed_filter).__name__}; using defaults")
        except Exception as e:
            warnings.append(f"filter_json JSON parse failed ({e}); using defaults")
    if not filter_patterns:
        filter_patterns = list(DEFAULT_API_FILTERS)
    arg_count = max(1, min(int(arg_count or DEFAULT_API_ARG_COUNT), 8))
    max_callstack_frames = max(0, min(int(max_callstack_frames), 128))
    max_out_bytes = max(0, min(int(max_out_bytes), 1_048_576))
    custom_targets = _parse_custom_api_trace_targets(custom_targets_json)
    if not custom_targets.get("ok"):
        return {
            "ok": False,
            "error": "Invalid custom API trace targets",
            "customTargets": custom_targets,
            "warnings": warnings or None,
        }
    targets = _enumerate_import_targets(modules, filter_patterns)
    custom_target_items = list(custom_targets.get("targets") or [])
    # Explicit targets win on duplicate addresses because their resolver
    # semantics cannot be reconstructed from ordinary export enumeration.
    combined: Dict[str, Dict[str, Any]] = {
        str(_normalize_hex(item.get("addr")) or "").casefold(): item
        for item in targets
        if _normalize_hex(item.get("addr"))
    }
    for item in custom_target_items:
        normalized = str(_normalize_hex(item.get("addr")) or "").casefold()
        if normalized:
            combined[normalized] = item
    targets = list(combined.values())
    if not targets:
        return {
            "ok": False,
            "error": "No matching imports or custom targets found",
            "modules": modules,
            "filterCount": len(filter_patterns),
            "customTargets": custom_targets,
            "warnings": warnings or None,
        }
    # Hard cap to protect the debugger bridge.
    cap = max(1, min(int(max_targets or MAX_API_TRACE_BREAKPOINTS), 500))
    if len(targets) > cap:
        # Aggregate to help the user narrow down.
        per_module: Dict[str, int] = {}
        for t in targets:
            per_module[t["module"]] = per_module.get(t["module"], 0) + 1
        top_modules = sorted(per_module.items(), key=lambda kv: -kv[1])[:10]
        return {
            "ok": False,
            "error": f"{len(targets)} matches would exceed cap of {cap} BPs. Narrow your filter or modules.",
            "totalMatches": len(targets),
            "cap": cap,
            "topModules": [{"module": m, "count": n} for m, n in top_modules],
            "hint": "Pass narrower filter_json (e.g. [\"createfile\"] not [\"file\"]) or a specific module. You can also raise max_targets up to 500.",
            "warnings": warnings or None,
        }
    # Set silent BPs on each target. Use `command="DebugRun"` + silent flag so
    # the debugger continues automatically on each hit and we catch it in
    # RunApiTrace's WaitForPause loop. Actually simpler: use plain BP and let
    # RunApiTrace handle continuation.
    set_results: List[Dict[str, Any]] = []
    target_map: Dict[str, Dict[str, Any]] = {}
    successful_addrs: List[str] = []
    owned_entry_breakpoints: List[str] = []
    preexisting_entry_breakpoints: List[str] = []
    trace_id = _next_api_trace_id()
    native_reset = _clear_native_api_trace_evidence(trace_id)
    if not native_reset.get("ok"):
        warnings.append(
            "Native API evidence reset was unavailable: "
            + str(native_reset.get("error") or native_reset.get("errorCode"))
        )
    ownership_prefix = "mcp_api_trace:"
    breakpoint_snapshot = _collect_breakpoint_snapshot(log=False)
    existing_breakpoints = {
        _normalize_hex(item.get("addr")): item
        for item in breakpoint_snapshot.get("breakpoints", [])
        if isinstance(item, dict) and _normalize_hex(item.get("addr"))
    }
    for t in targets:
        try:
            normalized_addr = _normalize_hex(t["addr"]) or str(t["addr"])
            existing = existing_breakpoints.get(normalized_addr)
            existed = existing is not None
            existing_name = str((existing or {}).get("name") or "")
            if existed and existing_name.startswith(ownership_prefix):
                deleted = DebugDeleteBreakpoint(normalized_addr)
                deleted_ok, _ = _mutation_result_ok(deleted)
                if deleted_ok:
                    existed = False
                    existing = None
            r = "Breakpoint already present" if existed is True else DebugSetBreakpoint(t["addr"])
            # DebugSetBreakpoint returns a str like "Breakpoint set successfully"
            # or an "Error 500: ..." message. Only treat success as setting BP.
            result_text = str(r.get("result") if isinstance(r, dict) else r) or ""
            success = existed is True or (
                "success" in result_text.lower() and "error" not in result_text.lower()
            )
            if success:
                set_results.append({"addr": t["addr"], "func": t["func"], "result": result_text})
                target_map[str(t["addr"]).lower()] = t
                successful_addrs.append(t["addr"])
                if existed is True:
                    preexisting_entry_breakpoints.append(t["addr"])
                else:
                    owned_entry_breakpoints.append(t["addr"])
                    ExecCommand(
                        f'SetBreakpointName {normalized_addr}, "{ownership_prefix}{trace_id}:entry"'
                    )
            else:
                set_results.append({"addr": t["addr"], "func": t["func"], "error": result_text})
        except Exception as e:
            set_results.append({"addr": t["addr"], "func": t["func"], "error": str(e)})
    if not successful_addrs:
        return {
            "ok": False,
            "error": "No API breakpoints could be installed.",
            "matchedCount": len(targets),
            "breakpointFailures": [r for r in set_results if "error" in r][:50],
            "warnings": warnings or None,
        }
    native_return_hooks_requested = bool(
        capture_returns and native_return_hooks
    )
    native_configure = _configure_native_api_trace(
        trace_id,
        native_return_hooks=native_return_hooks_requested,
        entry_addresses=successful_addrs,
    )
    native_return_hooks_effective = bool(
        native_return_hooks_requested
        and native_configure.get("ok")
        and native_configure.get("nativeReturnHooks") is True
    )
    if native_return_hooks_requested and not native_return_hooks_effective:
        warnings.append(
            "Native return-hook scheduling was unavailable; "
            "Python breakpoint scheduling remains active: "
            + str(
                native_configure.get("error")
                or native_configure.get("errorCode")
                or "bridge did not enable nativeReturnHooks"
            )
        )
    trace_session = GetSessionBinding()
    record = {
        "traceId": trace_id,
        "label": str(label or ""),
        "createdAt": _now_iso(),
        "modules": modules,
        "filters": filter_patterns,
        "argCount": arg_count,
        "targetCount": len(successful_addrs),
        "maxTargets": cap,
        "targetAddrs": successful_addrs,
        "ownedEntryBreakpoints": owned_entry_breakpoints,
        "preexistingEntryBreakpoints": preexisting_entry_breakpoints,
        "breakpointOwnershipPrefix": ownership_prefix,
        "targetMap": target_map,
        "calls": [],
        "nextCallSeq": 0,
        "droppedCalls": 0,
        "pendingReturns": {},
        "filteredEntryCount": 0,
        "ownedReturnBreakpoints": [],
        "captureReturns": bool(capture_returns),
        "nativeReturnHooksRequested": native_return_hooks_requested,
        "nativeReturnHooks": native_return_hooks_effective,
        "nativeTraceConfigure": native_configure,
        "captureCallstack": bool(capture_callstack),
        "maxCallstackFrames": max_callstack_frames,
        "maxOutBytes": max_out_bytes,
        "callerFilter": str(caller_filter or "").strip().lower(),
        "decodeStringArgs": bool(decode_string_args),
        "collapseNestedFamilies": bool(collapse_nested_families),
        "subscribeModules": bool(subscribe_modules),
        "discoverDynamicResolvers": bool(discover_dynamic_resolvers),
        "customTargets": custom_target_items,
        "customTargetCount": len(custom_target_items),
        "targetSubscriptions": [],
        "subscriptionFailures": 0,
        "nativeEvidenceReset": native_reset,
        "session": trace_session,
        "running": False,
        "stopped": False,
    }
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("apiTraces", {}))
        traces[trace_id] = record
        # Prune oldest if over cap.
        if len(traces) > MAX_API_TRACE_SESSIONS:
            oldest = sorted(traces.values(), key=lambda r: r.get("createdAt") or "")[0]
            traces.pop(oldest.get("traceId"), None)
        _RUNTIME_STATE["apiTraces"] = traces
    return {
        "ok": True,
        "traceId": trace_id,
        "targetCount": len(successful_addrs),
        "matchedCount": len(targets),
        "modules": modules,
        "filterCount": len(filter_patterns),
        "breakpointsSet": len(owned_entry_breakpoints),
        "preexistingBreakpoints": len(preexisting_entry_breakpoints),
        "captureReturns": bool(capture_returns),
        "nativeReturnHooksRequested": native_return_hooks_requested,
        "nativeReturnHooks": native_return_hooks_effective,
        "nativeTraceConfigure": native_configure,
        "captureCallstack": bool(capture_callstack),
        "callerFilter": str(caller_filter or "").strip() or None,
        "collapseNestedFamilies": bool(collapse_nested_families),
        "subscribeModules": bool(subscribe_modules),
        "discoverDynamicResolvers": bool(discover_dynamic_resolvers),
        "customTargetCount": len(custom_target_items),
        "customTargets": custom_target_items,
        "nativeEvidenceReset": native_reset,
        "session": trace_session,
        "breakpointFailures": [r for r in set_results if "error" in r][:10],
        "warnings": warnings or None,
    }


@mcp.tool()
def RunApiTrace(
    trace_id: str,
    timeout_ms: int = 30000,
    max_calls: int = 1000,
    drain_returns: bool = True,
) -> dict:
    """
    Run the debuggee and collect API calls into the given trace session.

    Blocks until either `max_calls` calls are recorded, `timeout_ms` elapses,
    or the debuggee exits. Returns compact summary; use GetApiTraceLog for
    per-call details.
    """
    record = _get_api_trace(trace_id)
    if not record:
        return {"ok": False, "traceId": trace_id, "error": "Trace session not found"}
    arg_count = int(record.get("argCount") or DEFAULT_API_ARG_COUNT)
    bitness = _detect_debuggee_bitness()
    _update_api_trace(trace_id, lambda r: r.update({"running": True}))
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    call_count = 0
    return_count = 0
    alias_count = 0
    nested_count = 0
    module_targets_added = 0
    dynamic_targets_added = 0
    subscription_failures = 0
    exited = False
    foreign_stop: Optional[Dict[str, Any]] = None
    timed_out = False
    submission_error: Optional[str] = None
    try:
        while time.time() < deadline:
            current_record = _get_api_trace(trace_id) or {}
            if current_record.get("stopped"):
                break
            pending_before_resume = sum(
                len(items)
                for items in (current_record.get("pendingReturns") or {}).values()
            )
            if call_count >= max_calls and (
                not drain_returns or pending_before_resume == 0
            ):
                break
            if current_record.get("subscribeModules"):
                subscription = _refresh_api_trace_module_subscriptions(trace_id)
                module_targets_added += int(subscription.get("added") or 0)
                subscription_failures += int(subscription.get("failed") or 0)
                current_record = _get_api_trace(trace_id) or current_record
            resume_result = DebugRun()
            resume_ok, resume_error = _mutation_result_ok(resume_result)
            if not resume_ok:
                submission_error = resume_error or str(resume_result)
                break
            remaining_ms = max(0, int((deadline - time.time()) * 1000))
            if remaining_ms <= 0:
                break
            event = WaitForBreakpointDetailed(
                timeout_ms=min(remaining_ms, 700), poll_ms=25
            )
            nested_state = (
                event.get("state") if isinstance(event.get("state"), dict) else {}
            )
            state = {
                "state": nested_state.get("state"),
                "paused": nested_state.get("paused"),
                "running": nested_state.get("running"),
                "rip": event.get("rip") or nested_state.get("ip"),
                "eventSeq": event.get("eventSeq") or nested_state.get("eventSeq"),
                "threadId": event.get("threadId") or nested_state.get("threadId"),
                "stopReason": event.get("stopReason") or nested_state.get("stopReason"),
                "session": nested_state,
            }
            if state.get("state") in ("exited", "not_debugging") or (
                nested_state.get("initialized") and not nested_state.get("debugging")
            ):
                exited = True
                break
            if event.get("timedOut"):
                continue
            rip = _normalize_hex(state.get("rip"))
            if not rip:
                continue
            thread_id = _api_trace_thread_id(state)
            current_record = _get_api_trace(trace_id) or {}
            pending_returns = {
                str(addr).lower(): list(items)
                for addr, items in (current_record.get("pendingReturns") or {}).items()
            }

            pending_at_rip = pending_returns.get(rip.lower(), [])
            if pending_at_rip:
                pending_index = len(pending_at_rip) - 1
                if thread_id:
                    for index in range(len(pending_at_rip) - 1, -1, -1):
                        if int(pending_at_rip[index].get("threadId") or 0) == thread_id:
                            pending_index = index
                            break
                pending_call = pending_at_rip[pending_index]
                call_seq = int(pending_call.get("seq") or 0)
                calls = list(current_record.get("calls") or [])
                call_record = next(
                    (item for item in calls if int(item.get("seq") or 0) == call_seq),
                    {},
                )
                return_value = _api_register_value("cax")
                out_buffers = _capture_api_out_buffers(
                    str(call_record.get("func") or ""),
                    list(call_record.get("args") or []),
                    return_value,
                    int(current_record.get("maxOutBytes") or 0),
                )
                decoded_return = _decode_api_return(
                    str(call_record.get("func") or ""),
                    return_value,
                    list(call_record.get("args") or []),
                    out_buffers,
                )
                comparison_evidence = _finalize_comparison_evidence(
                    call_record.get("comparison"),
                    return_value,
                    int(state.get("eventSeq") or 0),
                )
                returned_at_ns = time.perf_counter_ns()
                entry_ns = int(call_record.get("_entryPerfNs") or returned_at_ns)
                pending_at_rip.pop(pending_index)
                pending_returns[rip.lower()] = pending_at_rip
                owned_returns = {
                    str(item).lower()
                    for item in current_record.get("ownedReturnBreakpoints", [])
                }
                delete_owned_return = not pending_at_rip and rip.lower() in owned_returns
                delete_result = None
                if delete_owned_return:
                    try:
                        delete_result = DebugDeleteBreakpoint(rip)
                    except Exception as exc:
                        delete_result = f"Error: {exc}"

                def _complete_return(
                    trace: Dict[str, Any],
                    seq=call_seq,
                    pending=pending_returns,
                    owned=owned_returns,
                    return_addr=rip,
                    ret_value=return_value,
                    buffers=out_buffers,
                    decoded=decoded_return,
                    comparison=comparison_evidence,
                    duration_ns=max(0, returned_at_ns - entry_ns),
                    return_thread=thread_id,
                    event_seq=int(state.get("eventSeq") or 0),
                    delete_bp=delete_owned_return,
                    delete_payload=delete_result,
                ) -> None:
                    updated_calls = list(trace.get("calls") or [])
                    for item in updated_calls:
                        if int(item.get("seq") or 0) != seq:
                            continue
                        item.update(
                            {
                                "returned": True,
                                "returnTimestamp": _now_iso(),
                                "returnEventSeq": event_seq,
                                "returnThreadId": return_thread,
                                "returnAddress": return_addr,
                                "returnValue": ret_value,
                                "returnDecoded": decoded,
                                "comparison": comparison,
                                "wallDurationMs": round(duration_ns / 1_000_000.0, 3),
                                "outBuffers": buffers,
                            }
                        )
                        item.pop("_entryPerfNs", None)
                        if delete_bp:
                            item["returnBreakpointDelete"] = delete_payload
                        break
                    trace["calls"] = updated_calls
                    trace["pendingReturns"] = {
                        addr: items for addr, items in pending.items() if items
                    }
                    if delete_bp:
                        owned.discard(return_addr.lower())
                    trace["ownedReturnBreakpoints"] = sorted(owned)

                _update_api_trace(trace_id, _complete_return)
                dynamic_subscription = _subscribe_dynamic_resolver_target(
                    trace_id,
                    call_record,
                    return_value,
                )
                if not dynamic_subscription.get("skipped"):
                    dynamic_targets_added += int(
                        dynamic_subscription.get("added") or 0
                    )
                    subscription_failures += int(
                        dynamic_subscription.get("failed") or 0
                    )

                    def _record_dynamic_subscription(
                        trace: Dict[str, Any],
                        seq=call_seq,
                        result=dict(dynamic_subscription),
                    ) -> None:
                        calls = list(trace.get("calls") or [])
                        for item in calls:
                            if int(item.get("seq") or 0) == seq:
                                item["dynamicTargetSubscription"] = result
                                break
                        trace["calls"] = calls

                    _update_api_trace(trace_id, _record_dynamic_subscription)
                return_count += 1
                continue

            target = (
                (current_record.get("targetMap") or {}).get(rip.lower())
            )
            if not target:
                session = state.get("session") if isinstance(state.get("session"), dict) else {}
                noise_event = {
                    "breakpointModule": session.get("breakpointModule"),
                    "breakpointName": session.get("breakpointName"),
                }
                if (
                    str(state.get("stopReason") or "").lower() == "breakpoint"
                    and _is_system_noise_breakpoint(noise_event)
                ):
                    continue
                foreign_stop = {
                    "rip": rip,
                    "eventSeq": state.get("eventSeq"),
                    "threadId": thread_id,
                    "stopReason": state.get("stopReason"),
                    "breakpointName": session.get("breakpointName"),
                    "breakpointModule": session.get("breakpointModule"),
                }
                break
            signature = _api_signature(str(target.get("func") or ""))
            signature_args = list(signature.get("args") or [])
            effective_arg_count = max(arg_count, len(signature_args))
            args = _sample_api_args(
                bitness,
                min(effective_arg_count, 8),
            )
            for argument in args:
                index = int(argument.get("index", -1))
                if 0 <= index < len(signature_args):
                    argument.update(
                        {
                            key: value
                            for key, value in signature_args[index].items()
                            if key in ("name", "type", "direction")
                        }
                    )
            current_record = _get_api_trace(trace_id) or {}
            if current_record.get("decodeStringArgs", True):
                for a in args:
                    s = _api_arg_try_decode_string(a.get("value", ""))
                    if s:
                        a["stringPreview"] = s
            comparison_evidence = _capture_comparison_evidence(
                str(target.get("func") or ""),
                args,
                int(current_record.get("maxOutBytes") or 4096),
            )
            call_stack = (
                _api_trace_callstack(
                    int(current_record.get("maxCallstackFrames") or 0)
                )
                if current_record.get("captureCallstack")
                else []
            )
            caller_filter = str(current_record.get("callerFilter") or "")
            if caller_filter and not _api_callstack_matches(call_stack, caller_filter):
                _update_api_trace(
                    trace_id,
                    lambda trace: trace.update(
                        {
                            "filteredEntryCount": int(
                                trace.get("filteredEntryCount") or 0
                            )
                            + 1
                        }
                    ),
                )
                continue
            native_entry_evidence = (
                _record_native_api_entry(
                    trace_id,
                    rip,
                    str(target.get("module") or ""),
                )
                if current_record.get("nativeReturnHooks")
                else {
                    "ok": True,
                    "skipped": True,
                    "reason": "Native return hooks are disabled.",
                }
            )

            # A number of Win32 APIs are thin wrappers around an A/W or Ex
            # variant.  x64 usually tail-jumps (same return address), whereas
            # x86 often performs a real nested call (different return address).
            # Treat the nested wrapper as an alias of the still-pending outer
            # call so the trace reports the caller-visible API exactly once.
            wrapper_key = _api_wrapper_alias_key(str(target.get("func") or ""))
            pending_sequences: List[int] = []
            for pending_items in (current_record.get("pendingReturns") or {}).values():
                for pending_item in pending_items:
                    pending_thread = int(pending_item.get("threadId") or 0)
                    if not thread_id or pending_thread == thread_id:
                        pending_sequences.append(int(pending_item.get("seq") or 0))
            wrapper_parent = None
            for existing_call in reversed(list(current_record.get("calls") or [])):
                existing_func = str(existing_call.get("func") or "")
                if (
                    int(existing_call.get("seq") or 0) in pending_sequences
                    and not existing_call.get("returned")
                    and existing_func.lower() != str(target.get("func") or "").lower()
                    and _api_wrapper_alias_key(existing_func) == wrapper_key
                ):
                    wrapper_parent = existing_call
                    break
            if wrapper_parent is not None:
                alias_entry = {
                    "module": target["module"],
                    "func": target["func"],
                    "addr": rip,
                    "entryEventSeq": int(state.get("eventSeq") or 0),
                    "threadId": thread_id,
                    "args": args,
                    "timestamp": _now_iso(),
                    "kind": "nested_wrapper",
                }

                def _append_wrapper_alias(
                    trace: Dict[str, Any],
                    seq=int(wrapper_parent.get("seq") or 0),
                    alias=alias_entry,
                ) -> None:
                    calls = list(trace.get("calls") or [])
                    for item in calls:
                        if int(item.get("seq") or 0) == seq:
                            aliases = list(item.get("aliases") or [])
                            aliases.append(alias)
                            item["aliases"] = aliases
                            break
                    trace["calls"] = calls

                _update_api_trace(trace_id, _append_wrapper_alias)
                alias_count += 1
                continue
            family = _api_call_family(str(target.get("func") or ""))
            if family and current_record.get("collapseNestedFamilies"):
                pending_sequences = []
                for pending_items in (current_record.get("pendingReturns") or {}).values():
                    for pending_item in pending_items:
                        if (
                            not thread_id
                            or int(pending_item.get("threadId") or 0) == thread_id
                        ):
                            pending_sequences.append(int(pending_item.get("seq") or 0))
                parent = None
                for existing_call in reversed(list(current_record.get("calls") or [])):
                    if (
                        int(existing_call.get("seq") or 0) in pending_sequences
                        and not existing_call.get("returned")
                        and bool(_api_call_family(str(existing_call.get("func") or "")))
                    ):
                        parent = existing_call
                        break
                if parent is not None:
                    nested_entry = {
                        "module": target["module"],
                        "func": target["func"],
                        "family": family,
                        "addr": rip,
                        "entryEventSeq": int(state.get("eventSeq") or 0),
                        "threadId": thread_id,
                        "args": args,
                        "timestamp": _now_iso(),
                    }

                    def _append_nested(
                        trace: Dict[str, Any],
                        parent_seq=int(parent.get("seq") or 0),
                        nested=nested_entry,
                    ) -> None:
                        calls = list(trace.get("calls") or [])
                        for item in calls:
                            if int(item.get("seq") or 0) == parent_seq:
                                nested_calls = list(item.get("nestedCalls") or [])
                                nested_calls.append(nested)
                                item["nestedCalls"] = nested_calls
                                break
                        trace["calls"] = calls

                    _update_api_trace(trace_id, _append_nested)
                    nested_count += 1
                    continue
            call_seq = int(current_record.get("nextCallSeq") or 0) + 1
            return_address = ""
            return_tracking_error = None
            owned_return = False
            capture_returns = bool(current_record.get("captureReturns", True))
            if capture_returns:
                return_address = _normalize_hex(StackPeek("0")) or ""
                if not return_address:
                    return_tracking_error = "Could not read the call return address."
                else:
                    pending = current_record.get("pendingReturns") or {}
                    pending_for_return = list(pending.get(return_address.lower()) or [])
                    alias_seq = 0
                    if thread_id:
                        for pending_item in reversed(pending_for_return):
                            if int(pending_item.get("threadId") or 0) == thread_id:
                                alias_seq = int(pending_item.get("seq") or 0)
                                break
                    if alias_seq:
                        alias_entry = {
                            "module": target["module"],
                            "func": target["func"],
                            "addr": rip,
                            "entryEventSeq": int(state.get("eventSeq") or 0),
                            "threadId": thread_id,
                            "args": args,
                            "timestamp": _now_iso(),
                        }

                        def _append_alias(
                            trace: Dict[str, Any],
                            seq=alias_seq,
                            alias=alias_entry,
                        ) -> None:
                            calls = list(trace.get("calls") or [])
                            for item in calls:
                                if int(item.get("seq") or 0) == seq:
                                    aliases = list(item.get("aliases") or [])
                                    aliases.append(alias)
                                    item["aliases"] = aliases
                                    break
                            trace["calls"] = calls

                        _update_api_trace(trace_id, _append_alias)
                        alias_count += 1
                        continue
                    already_pending = bool(pending_for_return)
                    existed = _breakpoint_exists(return_address)
                    if not already_pending and existed is not True:
                        set_return = DebugSetBreakpoint(return_address)
                        set_text = str(
                            set_return.get("result")
                            if isinstance(set_return, dict)
                            else set_return
                        )
                        if "success" in set_text.lower() and "error" not in set_text.lower():
                            owned_return = True
                            ownership_prefix = str(
                                current_record.get("breakpointOwnershipPrefix")
                                or "mcp_api_trace:"
                            )
                            ExecCommand(
                                f'SetBreakpointName {return_address}, "{ownership_prefix}{trace_id}:return"'
                            )
                        else:
                            return_tracking_error = set_text or "Failed to set return breakpoint."
            call_entry = {
                "seq": call_seq,
                "timestamp": _now_iso(),
                "entryEventSeq": int(state.get("eventSeq") or 0),
                "threadId": thread_id,
                "addr": rip,
                "module": target["module"],
                "func": target["func"],
                "targetSource": target.get("source"),
                "targetKind": target.get("targetKind"),
                "resolverSpec": target.get("resolverSpec"),
                "args": args,
                "comparison": comparison_evidence,
                "signature": signature or None,
                "callStack": call_stack,
                "returnAddress": return_address or None,
                "returned": False,
                "returnTrackingError": return_tracking_error,
                "nativeEntryEvidence": native_entry_evidence,
                "_entryPerfNs": time.perf_counter_ns(),
            }
            def _add_call(
                r: Dict[str, Any],
                entry=call_entry,
                return_addr=return_address,
                owns_return=owned_return,
            ) -> None:
                calls = list(r.get("calls") or [])
                calls.append(entry)
                if len(calls) > MAX_API_TRACE_CALLS:
                    dropped = len(calls) - MAX_API_TRACE_CALLS
                    calls = calls[-MAX_API_TRACE_CALLS:]
                    r["droppedCalls"] = int(r.get("droppedCalls") or 0) + dropped
                r["calls"] = calls
                r["nextCallSeq"] = int(entry["seq"])
                if return_addr and not entry.get("returnTrackingError"):
                    pending = {
                        str(addr).lower(): list(items)
                        for addr, items in (r.get("pendingReturns") or {}).items()
                    }
                    pending.setdefault(return_addr.lower(), []).append(
                        {"seq": entry["seq"], "threadId": entry["threadId"]}
                    )
                    r["pendingReturns"] = pending
                    if owns_return:
                        owned = {
                            str(item).lower()
                            for item in r.get("ownedReturnBreakpoints", [])
                        }
                        owned.add(return_addr.lower())
                        r["ownedReturnBreakpoints"] = sorted(owned)
            _update_api_trace(trace_id, _add_call)
            call_count += 1
        timed_out = time.time() >= deadline and not exited and foreign_stop is None
        if timed_out:
            current_state = _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            )
            if current_state.get("running"):
                DebugPause()
                WaitForPause(timeout_ms=2000, poll_ms=50)
    finally:
        _update_api_trace(trace_id, lambda r: r.update({"running": False}))
    current = _get_api_trace(trace_id) or {}
    total_calls = len(current.get("calls", []))
    counter: Dict[str, int] = {}
    for c in current.get("calls", []):
        key = f"{c.get('module')}!{c.get('func')}"
        counter[key] = counter.get(key, 0) + 1
    top_apis = sorted(counter.items(), key=lambda kv: -kv[1])[:15]
    pending_count = sum(
        len(items) for items in (current.get("pendingReturns") or {}).values()
    )
    return {
        "ok": total_calls > 0 and submission_error is None,
        "traceId": trace_id,
        "callsRecorded": call_count,
        "returnsRecorded": return_count,
        "aliasesCollapsed": alias_count,
        "nestedCallsCollapsed": nested_count,
        "moduleTargetsAdded": module_targets_added,
        "dynamicTargetsAdded": dynamic_targets_added,
        "subscriptionFailures": subscription_failures,
        "targetCount": int(current.get("targetCount") or 0),
        "totalCalls": total_calls,
        "pendingReturns": pending_count,
        "filteredEntries": int(current.get("filteredEntryCount") or 0),
        "exited": exited,
        "timedOut": timed_out,
        "foreignStop": foreign_stop,
        "submissionError": submission_error,
        "observed": total_calls > 0,
        "topApis": [{"api": k, "count": v} for k, v in top_apis],
        "error": submission_error
        or (None if total_calls > 0 else "No configured API breakpoint was observed."),
    }


@mcp.tool()
def GetNativeApiTraceEvidence(
    trace_id: str,
    after_seq: int = 0,
    limit: int = 100,
) -> dict:
    """Read native breakpoint entry/return evidence for an API trace session."""

    trace_id = str(trace_id or "").strip()
    if not trace_id:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "trace_id is required",
        }
    try:
        cursor = max(0, int(after_seq))
        page_limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "after_seq and limit must be integers.",
        }
    envelope = _bridge_request(
        "GET",
        "ApiTrace/Status",
        params={
            "traceId": trace_id,
            "afterSeq": str(cursor),
            "limit": str(page_limit),
        },
        log=False,
        guard="none",
        idempotent=True,
    )
    if not envelope.ok:
        error = envelope.error or BridgeError(
            "BRIDGE_REQUEST_FAILED",
            "Native API trace request failed.",
            endpoint="ApiTrace/Status",
        )
        return {
            "ok": False,
            "errorCode": error.code,
            "error": error.message,
            "retryable": error.retryable,
            "details": dict(error.details or {}),
            "meta": dict(envelope.meta or {}),
        }
    payload = _coerce_json_payload(envelope.data)
    if isinstance(payload, dict):
        record = _get_api_trace(trace_id) or {}
        target_map = {
            str(address).lower(): target
            for address, target in (record.get("targetMap") or {}).items()
            if isinstance(target, dict)
        }
        events = payload.get("events")
        if isinstance(events, list) and target_map:
            enriched_events: List[Any] = []
            for raw_event in events:
                if not isinstance(raw_event, dict):
                    enriched_events.append(raw_event)
                    continue
                event = dict(raw_event)
                api_address = _normalize_hex(
                    event.get("apiAddress")
                    or (
                        event.get("breakpointAddress")
                        if event.get("kind") == "entry"
                        else None
                    )
                )
                target = target_map.get(str(api_address or "").lower())
                if target:
                    event["apiModule"] = target.get("module")
                    event["apiFunction"] = target.get("func")
                    event["api"] = (
                        f"{target.get('module')}!{target.get('func')}"
                    )
                    signature = _api_signature(str(target.get("func") or ""))
                    if signature:
                        event["apiSignature"] = signature
                enriched_events.append(event)
            payload = dict(payload)
            payload["events"] = enriched_events
        return payload
    return {
        "ok": False,
        "errorCode": "INVALID_RESPONSE",
        "error": "Native API trace endpoint returned a non-JSON response.",
        "rawResponse": str(envelope.data)[:2048],
        "meta": dict(envelope.meta or {}),
    }


@mcp.tool()
def ClearNativeApiTraceEvidence(trace_id: str) -> dict:
    """Clear retained native API events and pending shadow-stack state."""

    trace_id = str(trace_id or "").strip()
    if not trace_id:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "trace_id is required",
        }
    return _clear_native_api_trace_evidence(trace_id)


@mcp.tool()
def FinalizeNativeApiTraceEvidence(trace_id: str) -> dict:
    """Mark native shadow-stack entries without a return as finalized/unresolved."""

    trace_id = str(trace_id or "").strip()
    if not trace_id:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "trace_id is required",
        }
    return _finalize_native_api_trace_evidence(trace_id)


@mcp.tool()
def StopApiTrace(trace_id: str, delete_breakpoints: bool = True) -> dict:
    """
    Stop a running API trace and optionally delete its breakpoints.
    """
    record = _get_api_trace(trace_id)
    if not record:
        return {"ok": False, "traceId": trace_id, "error": "Trace session not found"}
    native_finalized = _finalize_native_api_trace_evidence(trace_id)
    removed: List[str] = []
    removal_failures: List[Dict[str, Any]] = []
    native_owned_return_breakpoints = [
        str(item)
        for item in (
            native_finalized.get("ownedReturnBreakpoints") or []
            if isinstance(native_finalized, dict)
            else []
        )
        if str(item).strip()
    ]
    owned = list(
        dict.fromkeys(
            list(record.get("ownedEntryBreakpoints") or [])
            + list(record.get("ownedReturnBreakpoints") or [])
            + native_owned_return_breakpoints
        )
    )
    if delete_breakpoints:
        for addr in owned:
            try:
                result = DebugDeleteBreakpoint(addr)
                deleted_ok, deleted_error = _mutation_result_ok(result)
                if deleted_ok and _breakpoint_delete_succeeded(result):
                    removed.append(addr)
                else:
                    removal_failures.append(
                        {"addr": addr, "error": deleted_error or str(result)}
                    )
            except Exception as exc:
                removal_failures.append({"addr": addr, "error": str(exc)})
    native_return_hooks_release = (
        _release_native_api_return_hooks(trace_id)
        if record.get("nativeReturnHooks") and delete_breakpoints
        else {
            "ok": True,
            "skipped": True,
            "reason": (
                "breakpoint deletion was disabled"
                if record.get("nativeReturnHooks")
                else "native return hooks were not enabled"
            ),
        }
    )
    if not native_return_hooks_release.get("ok"):
        removal_failures.append(
            {
                "addr": None,
                "errorCode": (
                    native_return_hooks_release.get("errorCode")
                    or "native_return_hook_release_failed"
                ),
                "error": (
                    native_return_hooks_release.get("error")
                    or "Native return-hook ownership release failed."
                ),
            }
        )
    stopped_at = _now_iso()

    def _mark_stopped(trace: Dict[str, Any]) -> None:
        calls = list(trace.get("calls") or [])
        for call in calls:
            call.pop("_entryPerfNs", None)
            if not call.get("returned") and not call.get("returnTrackingError"):
                call["incomplete"] = True
                call["incompleteReason"] = "trace_stopped_before_return"
        trace.update(
            {
                "stopped": True,
                "stoppedAt": stopped_at,
                "calls": calls,
                "pendingReturns": {},
                "ownedReturnBreakpoints": [],
            }
        )

    _update_api_trace(trace_id, _mark_stopped)
    preserved = len(record.get("preexistingEntryBreakpoints") or [])
    return {
        "ok": not bool(removal_failures),
        "traceId": trace_id,
        "breakpointsRemoved": len(removed),
        "ownedBreakpoints": len(owned),
        "breakpointRemovalFailures": removal_failures,
        "cleanupDeferred": bool(removal_failures),
        "preexistingBreakpointsPreserved": preserved,
        "nativeFinalized": native_finalized,
        "nativeReturnHooksRelease": native_return_hooks_release,
        "nativeOwnedReturnBreakpoints": native_owned_return_breakpoints,
        "incompleteReturns": sum(
            1 for call in record.get("calls", []) if not call.get("returned")
        ),
        "totalCalls": len(record.get("calls", [])),
    }


@mcp.tool()
def GetApiTraceLog(
    trace_id: str,
    offset: int = 0,
    limit: int = 100,
    func_filter: str = "",
    after_seq: int = 0,
) -> dict:
    """
    Read API trace log with pagination.

    Args:
        trace_id: Session id from StartApiTrace.
        offset: Start index (0-based).
        limit: Max calls to return (default 100, max 5000).
        func_filter: Optional case-insensitive substring for "module!func".
    """
    record = _get_api_trace(trace_id)
    if not record:
        return {"ok": False, "traceId": trace_id, "error": "Trace session not found"}
    calls = list(record.get("calls", []))
    try:
        after_seq = max(0, int(after_seq))
    except (TypeError, ValueError):
        return {
            "ok": False,
            "traceId": trace_id,
            "errorCode": "INVALID_ARGUMENT",
            "error": "after_seq must be an integer.",
        }
    oldest_seq = int(calls[0].get("seq") or 0) if calls else 0
    latest_seq = int(calls[-1].get("seq") or 0) if calls else 0
    cursor_truncated = bool(
        after_seq > 0
        and oldest_seq > 0
        and after_seq + 1 < oldest_seq
    )
    if after_seq > 0:
        calls = [
            item for item in calls
            if int(item.get("seq") or 0) > after_seq
        ]
    if func_filter:
        flt = func_filter.lower()
        calls = [c for c in calls if flt in f"{c.get('module')}!{c.get('func')}".lower()]
    limit = max(1, min(int(limit), 5000))
    offset = max(0, int(offset))
    page = [
        {key: value for key, value in call.items() if not str(key).startswith("_")}
        for call in calls[offset:offset + limit]
    ]
    next_after_seq = (
        int(page[-1].get("seq") or after_seq)
        if page
        else after_seq
    )
    return {
        "ok": True,
        "traceId": trace_id,
        "total": len(calls),
        "offset": offset,
        "returned": len(page),
        "afterSeq": after_seq,
        "nextAfterSeq": next_after_seq,
        "oldestSeq": oldest_seq,
        "latestSeq": latest_seq,
        "cursorTruncated": cursor_truncated,
        "cursorExclusive": True,
        "droppedCalls": int(record.get("droppedCalls") or 0),
        "calls": page,
    }


def _decode_recovery_probe(
    value: str, value_format: str
) -> tuple[Optional[bytes], Optional[str]]:
    flavor = str(value_format or "utf8").strip().lower()
    raw = str(value or "")
    try:
        if flavor == "utf8":
            return raw.encode("utf-8"), None
        if flavor == "ascii":
            return raw.encode("ascii"), None
        if flavor in {"utf16", "utf16le"}:
            return raw.encode("utf-16le"), None
        if flavor == "hex":
            return bytes.fromhex("".join(raw.split())), None
        if flavor == "base64":
            return base64.b64decode(raw, validate=True), None
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        return None, f"probe could not be decoded as {flavor}: {exc}"
    return None, "probe_format must be utf8, ascii, utf16le, hex, or base64"


def _recovery_candidate_document(
    data: bytes,
    *,
    method: str,
    confidence: str,
    call: Dict[str, Any],
    expected_operand: int,
    probe_operand: Optional[int],
    xor_key: Optional[int] = None,
) -> Dict[str, Any]:
    encoding = str((call.get("comparison") or {}).get("encoding") or "bytes")
    result: Dict[str, Any] = {
        "method": method,
        "confidence": confidence,
        "candidateHex": data.hex(),
        "candidateBase64": base64.b64encode(data).decode("ascii"),
        "candidateByteCount": len(data),
        "candidateSha256": hashlib.sha256(data).hexdigest().upper(),
        "candidateText": _comparison_text_preview(data, encoding),
        "encoding": encoding,
        "traceCallSeq": int(call.get("seq") or 0),
        "entryEventSeq": int(call.get("entryEventSeq") or 0),
        "returnEventSeq": int(call.get("returnEventSeq") or 0),
        "module": call.get("module"),
        "function": call.get("func"),
        "callAddress": call.get("addr"),
        "threadId": int(call.get("threadId") or 0),
        "expectedOperand": int(expected_operand),
        "probeOperand": (
            int(probe_operand) if probe_operand is not None else None
        ),
        "comparisonEqual": bool(
            ((call.get("comparison") or {}).get("result") or {}).get("equal")
        ),
        "callStack": list(call.get("callStack") or []),
    }
    if xor_key is not None:
        result["xorKey"] = int(xor_key)
        result["xorKeyHex"] = f"0x{int(xor_key):02x}"
    return result


def _recover_candidates_from_comparison(
    call: Dict[str, Any],
    probe: bytes,
    transform: str,
    expected_operand: int,
) -> List[Dict[str, Any]]:
    comparison = call.get("comparison")
    if not isinstance(comparison, dict):
        return []
    operands = list(comparison.get("operands") or [])
    if len(operands) != 2 or not all(
        isinstance(item, dict) and item.get("ok") for item in operands
    ):
        return []
    try:
        buffers = [bytes.fromhex(str(item.get("hex") or "")) for item in operands]
    except ValueError:
        return []
    allowed = str(transform or "auto").strip().lower()
    candidates: List[Dict[str, Any]] = []
    expected_indexes = [expected_operand] if expected_operand in {0, 1} else [0, 1]
    if probe:
        for probe_index, observed in enumerate(buffers):
            candidate_index = 1 - probe_index
            if candidate_index not in expected_indexes:
                continue
            if allowed in {"auto", "identity"} and (
                observed == probe or observed.startswith(probe)
            ):
                candidates.append(
                    _recovery_candidate_document(
                        buffers[candidate_index],
                        method="identity-comparison",
                        confidence="exact",
                        call=call,
                        expected_operand=candidate_index,
                        probe_operand=probe_index,
                    )
                )
            if allowed in {"auto", "xor-byte"}:
                prefix_size = min(len(probe), len(observed))
                if prefix_size < 3:
                    continue
                keys = {
                    observed[index] ^ probe[index]
                    for index in range(prefix_size)
                }
                if len(keys) != 1:
                    continue
                key = next(iter(keys))
                if key == 0:
                    continue
                transformed_candidate = bytes(
                    value ^ key
                    for value in buffers[candidate_index][: len(probe)]
                )
                candidates.append(
                    _recovery_candidate_document(
                        transformed_candidate,
                        method="observed-single-byte-xor",
                        confidence="exact-transform",
                        call=call,
                        expected_operand=candidate_index,
                        probe_operand=probe_index,
                        xor_key=key,
                    )
                )
    elif expected_operand in {0, 1}:
        candidates.append(
            _recovery_candidate_document(
                buffers[expected_operand],
                method="selected-raw-operand",
                confidence="caller-selected",
                call=call,
                expected_operand=expected_operand,
                probe_operand=None,
            )
        )
    return candidates


def _write_comparison_recovery_evidence(
    payload: Dict[str, Any],
    output_path: str,
    overwrite: bool,
) -> Dict[str, Any]:
    target = Path(os.path.abspath(str(output_path or "")))
    if target.exists() and not overwrite:
        return {
            "ok": False,
            "schema": "comparison-secret-recovery-v1",
            "reason": "output_exists",
            "path": str(target),
        }
    body = {
        key: value
        for key, value in dict(payload or {}).items()
        if key != "evidenceSha256"
    }
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest().upper()
    document = {**body, "evidenceSha256": digest}
    temporary = target.with_name(
        target.name + f".tmp-{os.getpid()}-{time.time_ns()}"
    )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)
        return {
            "ok": True,
            "schema": "comparison-secret-recovery-v1",
            "path": str(target),
            "size": target.stat().st_size,
            "evidenceSha256": digest,
        }
    except Exception as exc:
        return {
            "ok": False,
            "schema": "comparison-secret-recovery-v1",
            "reason": "write_failed",
            "path": str(target),
            "error": str(exc),
        }
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


@mcp.tool()
def RecoverComparisonSecret(
    trace_id: str,
    probe: str = "",
    probe_format: str = "utf8",
    transform: str = "auto",
    expected_operand: int = -1,
    evidence_path: str = "",
    overwrite: bool = False,
) -> dict:
    """Recover comparison candidates from exact API-trace operand evidence.

    This consumes completed strcmp/strncmp/memcmp/wide-string calls. With a
    known probe it distinguishes the user-controlled operand and recovers a
    direct peer or a single-byte-XOR-transformed peer. A returned candidate
    must still be verified with an independent launch of the target.
    """

    record = _get_api_trace(trace_id)
    if not record:
        return {
            "ok": False,
            "schema": "comparison-secret-recovery-v1",
            "traceId": trace_id,
            "errorCode": "TRACE_NOT_FOUND",
            "error": "Trace session not found.",
        }
    try:
        expected_index = int(expected_operand)
    except (TypeError, ValueError):
        expected_index = -2
    if expected_index not in {-1, 0, 1}:
        return {
            "ok": False,
            "schema": "comparison-secret-recovery-v1",
            "traceId": trace_id,
            "errorCode": "INVALID_ARGUMENT",
            "error": "expected_operand must be -1 (auto), 0, or 1.",
        }
    normalized_transform = str(transform or "auto").strip().lower()
    if normalized_transform not in {"auto", "identity", "xor-byte", "raw"}:
        return {
            "ok": False,
            "schema": "comparison-secret-recovery-v1",
            "traceId": trace_id,
            "errorCode": "INVALID_ARGUMENT",
            "error": "transform must be auto, identity, xor-byte, or raw.",
        }
    probe_bytes, probe_error = _decode_recovery_probe(probe, probe_format)
    if probe_error:
        return {
            "ok": False,
            "schema": "comparison-secret-recovery-v1",
            "traceId": trace_id,
            "errorCode": "INVALID_ARGUMENT",
            "error": probe_error,
        }
    assert probe_bytes is not None
    calls = [
        item
        for item in list(record.get("calls") or [])
        if isinstance(item, dict)
        and isinstance(item.get("comparison"), dict)
        and isinstance((item.get("comparison") or {}).get("result"), dict)
    ]
    candidates: List[Dict[str, Any]] = []
    for call in calls:
        candidates.extend(
            _recover_candidates_from_comparison(
                call,
                probe_bytes,
                normalized_transform,
                expected_index,
            )
        )
    unique: List[Dict[str, Any]] = []
    seen = set()
    for candidate in candidates:
        identity = (
            candidate.get("method"),
            candidate.get("candidateHex"),
            candidate.get("traceCallSeq"),
        )
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(candidate)
    unique.sort(
        key=lambda item: (
            0 if item.get("confidence") == "exact" else 1,
            0 if item.get("confidence") == "exact-transform" else 1,
            int(item.get("traceCallSeq") or 0),
        )
    )
    evidence = {
        "schema": "comparison-secret-recovery-v1",
        "createdAt": _now_iso(),
        "traceId": trace_id,
        "traceLabel": record.get("label"),
        "session": record.get("session") or GetSessionBinding(),
        "probe": {
            "format": str(probe_format or "utf8").strip().lower(),
            "byteCount": len(probe_bytes),
            "sha256": hashlib.sha256(probe_bytes).hexdigest().upper(),
        },
        "transform": normalized_transform,
        "expectedOperand": expected_index,
        "comparisonCallCount": len(calls),
        "candidateCount": len(unique),
        "candidates": unique,
        "requiresIndependentValidation": True,
        "droppedCalls": int(record.get("droppedCalls") or 0),
    }
    write_result = None
    if str(evidence_path or "").strip():
        write_result = _write_comparison_recovery_evidence(
            evidence,
            evidence_path,
            overwrite,
        )
    ok = bool(unique) and not int(record.get("droppedCalls") or 0)
    if write_result is not None:
        ok = ok and bool(write_result.get("ok"))
    _log_event(
        "recover_comparison_secret",
        ok=ok,
        traceId=trace_id,
        comparisonCallCount=len(calls),
        candidateCount=len(unique),
        transform=normalized_transform,
    )
    return {
        "ok": ok,
        **evidence,
        "evidenceWrite": write_result,
        "reason": (
            "candidates_recovered"
            if unique
            else "no_probe_correlated_candidate"
        ),
    }


@mcp.tool()
def ListApiTraces() -> dict:
    """
    List all API trace sessions with summary.
    """
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("apiTraces", {}))
    items = []
    for tid, rec in sorted(traces.items(), key=lambda kv: kv[1].get("createdAt") or ""):
        items.append({
            "traceId": tid,
            "label": rec.get("label"),
            "createdAt": rec.get("createdAt"),
            "running": rec.get("running"),
            "stopped": rec.get("stopped"),
            "targetCount": rec.get("targetCount"),
            "nativeReturnHooks": bool(rec.get("nativeReturnHooks")),
            "subscribeModules": bool(rec.get("subscribeModules")),
            "discoverDynamicResolvers": bool(
                rec.get("discoverDynamicResolvers")
            ),
            "subscriptionCount": len(rec.get("targetSubscriptions") or []),
            "subscriptionFailures": int(
                rec.get("subscriptionFailures") or 0
            ),
            "totalCalls": len(rec.get("calls") or []),
            "droppedCalls": int(rec.get("droppedCalls") or 0),
        })
    return {"ok": True, "count": len(items), "traces": items}


# ---------------------------------------------------------------------------
# Heap tracker — specialized API tracer for HeapAlloc/Free
# ---------------------------------------------------------------------------

HEAP_RESOURCE_CATALOG: Dict[str, Dict[str, Any]] = {
    "heapalloc": {
        "op": "alloc", "family": "win32_heap", "sizeArgs": [2],
        "ownerArg": 0, "returnSemantics": "pointer",
    },
    "rtlallocateheap": {
        "op": "alloc", "family": "nt_heap", "sizeArgs": [2],
        "ownerArg": 0, "returnSemantics": "pointer",
    },
    "heaprealloc": {
        "op": "realloc", "family": "win32_heap", "addressArg": 2,
        "sizeArgs": [3], "ownerArg": 0, "returnSemantics": "pointer",
    },
    "rtlreallocateheap": {
        "op": "realloc", "family": "nt_heap", "addressArg": 2,
        "sizeArgs": [3], "ownerArg": 0, "returnSemantics": "pointer",
    },
    "heapfree": {
        "op": "free", "family": "win32_heap", "addressArg": 2,
        "ownerArg": 0, "returnSemantics": "bool",
    },
    "rtlfreeheap": {
        "op": "free", "family": "nt_heap", "addressArg": 2,
        "ownerArg": 0, "returnSemantics": "bool",
    },
    "virtualalloc": {
        "op": "alloc", "family": "virtual_memory", "sizeArgs": [1],
        "returnSemantics": "pointer",
    },
    "virtualalloc2": {
        "op": "alloc", "family": "virtual_memory", "sizeArgs": [2],
        "ownerArg": 0, "returnSemantics": "pointer",
    },
    "virtualallocex": {
        "op": "alloc", "family": "virtual_memory", "sizeArgs": [2],
        "ownerArg": 0, "returnSemantics": "pointer",
    },
    "virtualfree": {
        "op": "free", "family": "virtual_memory", "addressArg": 0,
        "sizeArgs": [1], "returnSemantics": "bool",
    },
    "virtualfreeex": {
        "op": "free", "family": "virtual_memory", "addressArg": 1,
        "sizeArgs": [2], "ownerArg": 0, "returnSemantics": "bool",
    },
    "cotaskmemalloc": {
        "op": "alloc", "family": "com_task", "sizeArgs": [0],
        "returnSemantics": "pointer",
    },
    "cotaskmemrealloc": {
        "op": "realloc", "family": "com_task", "addressArg": 0,
        "sizeArgs": [1], "returnSemantics": "pointer",
    },
    "cotaskmemfree": {
        "op": "free", "family": "com_task", "addressArg": 0,
        "returnSemantics": "void",
    },
    "localalloc": {
        "op": "alloc", "family": "local_memory", "sizeArgs": [1],
        "returnSemantics": "pointer",
    },
    "localrealloc": {
        "op": "realloc", "family": "local_memory", "addressArg": 0,
        "sizeArgs": [1], "returnSemantics": "pointer",
    },
    "localfree": {
        "op": "free", "family": "local_memory", "addressArg": 0,
        "returnSemantics": "null_success",
    },
    "globalalloc": {
        "op": "alloc", "family": "global_memory", "sizeArgs": [1],
        "returnSemantics": "pointer",
    },
    "globalrealloc": {
        "op": "realloc", "family": "global_memory", "addressArg": 0,
        "sizeArgs": [1], "returnSemantics": "pointer",
    },
    "globalfree": {
        "op": "free", "family": "global_memory", "addressArg": 0,
        "returnSemantics": "null_success",
    },
    "malloc": {
        "op": "alloc", "family": "crt", "sizeArgs": [0],
        "returnSemantics": "pointer",
    },
    "calloc": {
        "op": "alloc", "family": "crt", "sizeArgs": [0, 1],
        "sizeMode": "product", "returnSemantics": "pointer",
    },
    "realloc": {
        "op": "realloc", "family": "crt", "addressArg": 0,
        "sizeArgs": [1], "returnSemantics": "pointer",
    },
    "free": {
        "op": "free", "family": "crt", "addressArg": 0,
        "returnSemantics": "void",
    },
    # Common MSVC decorated scalar/array new/delete exports.
    "??2@yapeax_k@z": {
        "op": "alloc", "family": "cpp", "sizeArgs": [0],
        "returnSemantics": "pointer",
    },
    "??_u@yapeax_k@z": {
        "op": "alloc", "family": "cpp", "sizeArgs": [0],
        "returnSemantics": "pointer",
    },
    "??2@yapaxi@z": {
        "op": "alloc", "family": "cpp", "sizeArgs": [0],
        "returnSemantics": "pointer",
    },
    "??_u@yapaxi@z": {
        "op": "alloc", "family": "cpp", "sizeArgs": [0],
        "returnSemantics": "pointer",
    },
    "??3@yaxpeax@z": {
        "op": "free", "family": "cpp", "addressArg": 0,
        "returnSemantics": "void",
    },
    "??_v@yaxpeax@z": {
        "op": "free", "family": "cpp", "addressArg": 0,
        "returnSemantics": "void",
    },
    "??3@yaxpax@z": {
        "op": "free", "family": "cpp", "addressArg": 0,
        "returnSemantics": "void",
    },
    "??_v@yaxpax@z": {
        "op": "free", "family": "cpp", "addressArg": 0,
        "returnSemantics": "void",
    },
}

HEAP_RESOURCE_MODULES = [
    "kernel32.dll", "kernelbase.dll", "ntdll.dll",
    "ole32.dll", "combase.dll", "ucrtbase.dll", "msvcrt.dll",
    "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll",
]


def _normalize_heap_catalog(
    families_json: str,
    custom_allocators_json: str,
) -> Tuple[Optional[Dict[str, Dict[str, Any]]], Optional[str]]:
    selected_families: set[str] = set()
    if str(families_json or "").strip():
        try:
            parsed = json.loads(families_json)
        except Exception as exc:
            return None, f"families_json is invalid JSON: {exc}"
        if not isinstance(parsed, list):
            return None, "families_json must be a JSON array."
        selected_families = {
            str(item or "").strip().lower() for item in parsed if str(item or "").strip()
        }
        known = {
            str(item.get("family") or "") for item in HEAP_RESOURCE_CATALOG.values()
        }
        unknown = sorted(selected_families - known)
        if unknown:
            return None, f"Unknown heap/resource families: {', '.join(unknown)}"
    catalog = {
        name: dict(spec)
        for name, spec in HEAP_RESOURCE_CATALOG.items()
        if not selected_families
        or str(spec.get("family") or "") in selected_families
    }
    if not str(custom_allocators_json or "").strip():
        return catalog, None
    try:
        parsed_custom = json.loads(custom_allocators_json)
    except Exception as exc:
        return None, f"custom_allocators_json is invalid JSON: {exc}"
    if not isinstance(parsed_custom, list) or len(parsed_custom) > 32:
        return None, "custom_allocators_json must be an array with at most 32 entries."
    for index, raw in enumerate(parsed_custom):
        if not isinstance(raw, dict):
            return None, f"Custom allocator {index} must be an object."
        function = _normalized_api_export_name(str(raw.get("function") or ""))
        module = str(raw.get("module") or "").strip().lower()
        op = str(raw.get("op") or "").strip().lower()
        family = str(raw.get("family") or "custom").strip().lower()
        semantics = str(raw.get("returnSemantics") or "").strip().lower()
        if not function or not module or op not in {"alloc", "realloc", "free"}:
            return None, (
                f"Custom allocator {index} requires module, function and "
                "op=alloc|realloc|free."
            )
        if semantics not in {"pointer", "bool", "void", "null_success"}:
            return None, f"Custom allocator {index} has invalid returnSemantics."
        spec: Dict[str, Any] = {
            "module": module,
            "op": op,
            "family": family or "custom",
            "returnSemantics": semantics,
        }
        for field in ("addressArg", "ownerArg"):
            if raw.get(field) is None:
                continue
            try:
                value = int(raw[field])
            except (TypeError, ValueError):
                return None, f"Custom allocator {index} field {field} must be an integer."
            if value < 0 or value > 7:
                return None, f"Custom allocator {index} field {field} must be 0..7."
            spec[field] = value
        size_args = raw.get("sizeArgs", [])
        if not isinstance(size_args, list) or len(size_args) > 2:
            return None, f"Custom allocator {index} sizeArgs must contain at most two indices."
        try:
            normalized_size_args = [int(item) for item in size_args]
        except (TypeError, ValueError):
            return None, f"Custom allocator {index} sizeArgs must be integers."
        if any(item < 0 or item > 7 for item in normalized_size_args):
            return None, f"Custom allocator {index} sizeArgs must be 0..7."
        spec["sizeArgs"] = normalized_size_args
        spec["sizeMode"] = (
            "product" if str(raw.get("sizeMode") or "").lower() == "product" else "single"
        )
        catalog[f"{module}!{function}"] = spec
    return catalog, None


def _next_heap_trace_id() -> str:
    with _RUNTIME_LOCK:
        seq = int(_RUNTIME_STATE.get("heapTraceSeq", 0)) + 1
        _RUNTIME_STATE["heapTraceSeq"] = seq
    return f"heaptrace-{seq}"


@mcp.tool()
def StartHeapTrace(
    label: str = "",
    caller_filter: str = "",
    min_allocation_size: int = 0,
    max_allocation_size: int = 0,
    families_json: str = "",
    custom_allocators_json: str = "",
    strict_unknown_resources: bool = False,
    subscribe_modules: bool = True,
) -> dict:
    """
    Start a heap/resource lifecycle session over Win32/NT heap, virtual memory,
    COM task memory, Local/Global, CRT and common MSVC new/delete families.

    Returns {ok, heapTraceId, apiTraceId}. The underlying machinery uses the
    API tracer — to drive it, call RunApiTrace(apiTraceId). Live heap state
    is exposed via GetHeapState(heapTraceId).
    """
    catalog, catalog_error = _normalize_heap_catalog(
        families_json, custom_allocators_json
    )
    if catalog is None:
        return {"ok": False, "error": catalog_error or "Invalid allocator catalog."}
    if not catalog:
        return {"ok": False, "error": "The selected allocator catalog is empty."}
    filters = [f"={name}" for name in catalog]
    modules = list(HEAP_RESOURCE_MODULES)
    for spec in catalog.values():
        custom_module = str(spec.get("module") or "").strip().lower()
        if custom_module and custom_module not in modules:
            modules.append(custom_module)
    filter_json = json.dumps(filters)
    modules_json = json.dumps(modules)
    try:
        minimum_size = max(0, int(min_allocation_size))
        maximum_size = max(0, int(max_allocation_size))
    except (TypeError, ValueError):
        return {"ok": False, "error": "Allocation size filters must be integers."}
    if maximum_size and maximum_size < minimum_size:
        return {"ok": False, "error": "max_allocation_size must be zero or >= min_allocation_size."}
    api_result = StartApiTrace(
        modules_json=modules_json,
        filter_json=filter_json,
        arg_count=8,
        label=f"heap:{label}",
        max_targets=160,
        capture_returns=True,
        capture_callstack=True,
        max_callstack_frames=24,
        max_out_bytes=0,
        caller_filter=caller_filter,
        decode_string_args=False,
        collapse_nested_families=True,
        subscribe_modules=bool(subscribe_modules),
        discover_dynamic_resolvers=False,
    )
    if not api_result.get("ok"):
        return {"ok": False, "error": "Failed to set heap BPs", "detail": api_result}
    heap_id = _next_heap_trace_id()
    record = {
        "heapTraceId": heap_id,
        "apiTraceId": api_result["traceId"],
        "label": label,
        "createdAt": _now_iso(),
        "callerFilter": str(caller_filter or "").strip() or None,
        "minAllocationSize": minimum_size,
        "maxAllocationSize": maximum_size,
        "strictUnknownResources": bool(strict_unknown_resources),
        "subscribeModules": bool(subscribe_modules),
        "allocatorCatalog": catalog,
        "families": sorted(
            {
                str(item.get("family") or "unknown")
                for item in catalog.values()
            }
        ),
    }
    with _RUNTIME_LOCK:
        heaps = dict(_RUNTIME_STATE.get("heapTraces", {}))
        heaps[heap_id] = record
        if len(heaps) > MAX_HEAP_TRACE_SESSIONS:
            oldest = sorted(heaps.values(), key=lambda r: r.get("createdAt") or "")[0]
            heaps.pop(oldest["heapTraceId"], None)
        _RUNTIME_STATE["heapTraces"] = heaps
    return {
        "ok": True,
        "heapTraceId": heap_id,
        "apiTraceId": api_result["traceId"],
        "bpsSet": api_result.get("breakpointsSet"),
        "minAllocationSize": minimum_size,
        "maxAllocationSize": maximum_size or None,
        "families": record["families"],
        "allocatorCatalogCount": len(catalog),
        "strictUnknownResources": bool(strict_unknown_resources),
        "subscribeModules": bool(subscribe_modules),
    }


@mcp.tool()
def RunHeapTrace(
    heap_trace_id: str,
    timeout_ms: int = 30000,
    expected_allocations: int = 0,
    expected_reallocations: int = 0,
    expected_frees: int = 0,
    expected_anomalies: int = 0,
    stop_when_live_zero: bool = False,
    require_complete: bool = False,
    calls_per_iteration: int = 1,
    max_logical_events: int = 10000,
    stop_on_complete: bool = True,
) -> dict:
    """Drive a heap trace until explicit allocation lifecycle evidence is met."""

    with _RUNTIME_LOCK:
        heaps = dict(_RUNTIME_STATE.get("heapTraces", {}))
    heap = heaps.get(str(heap_trace_id or "").strip())
    if not heap:
        return {"ok": False, "error": "Heap trace not found"}
    api_trace_id = str(heap.get("apiTraceId") or "")
    deadline = time.time() + (max(0, int(timeout_ms)) / 1000.0)
    expected = {
        "allocations": max(0, int(expected_allocations)),
        "reallocations": max(0, int(expected_reallocations)),
        "frees": max(0, int(expected_frees)),
        "anomalies": max(0, int(expected_anomalies)),
    }
    last_run: Dict[str, Any] = {}
    state: Dict[str, Any] = {}
    iterations = 0
    criteria_met = False
    calls_batch = max(1, min(int(calls_per_iteration), 64))
    while time.time() < deadline and iterations < max(1, int(max_logical_events)):
        remaining_ms = max(1, int((deadline - time.time()) * 1000))
        last_run = RunApiTrace(
            api_trace_id,
            timeout_ms=min(remaining_ms, 10000),
            max_calls=calls_batch,
            drain_returns=True,
        )
        state = GetHeapState(heap_trace_id)
        iterations += 1
        counts_met = (
            int(state.get("allocCount") or 0) >= expected["allocations"]
            and int(state.get("reallocCount") or 0) >= expected["reallocations"]
            and int(state.get("freeCount") or 0) >= expected["frees"]
        )
        live_met = not stop_when_live_zero or (
            int(state.get("allocCount") or 0) > 0
            and int(state.get("liveAllocations") or 0) == 0
        )
        anomaly_met = int(
            sum((state.get("anomalyCounts") or {}).values())
        ) <= expected["anomalies"]
        complete_met = not require_complete or bool(
            state.get("evidenceComplete") is True
            and int(state.get("incompleteReturns") or 0) == 0
            and int(state.get("droppedCalls") or 0) == 0
        )
        has_explicit_goal = (
            any(expected.values())
            or bool(stop_when_live_zero)
            or bool(require_complete)
        )
        criteria_met = bool(
            has_explicit_goal and counts_met and live_met
            and anomaly_met and complete_met
        )
        if criteria_met or last_run.get("exited"):
            break
        foreign_stop = last_run.get("foreignStop")
        owned_trace_stop = bool(
            isinstance(foreign_stop, dict)
            and str(foreign_stop.get("breakpointName") or "").startswith(
                f"mcp_api_trace:{api_trace_id}:"
            )
        )
        if (
            (foreign_stop and not owned_trace_stop)
            or last_run.get("submissionError")
        ):
            break
        if last_run.get("timedOut") and time.time() >= deadline:
            break
    # Preserve a compact bridge-side view before StopApiTrace tears down the
    # native configuration.  Besides making release reports independently
    # auditable, this distinguishes a native callback loss from a Python
    # aggregation loss when a lifecycle event is missing.
    native_evidence = GetNativeApiTraceEvidence(
        api_trace_id,
        after_seq=0,
        limit=5000,
    )
    native_events = (
        list(native_evidence.get("events") or [])
        if isinstance(native_evidence, dict)
        else []
    )
    native_api_counts: Dict[str, int] = {}
    native_kind_counts: Dict[str, int] = {}
    native_thread_ids: set[int] = set()
    for native_event in native_events:
        if not isinstance(native_event, dict):
            continue
        kind = str(native_event.get("kind") or "unknown")
        native_kind_counts[kind] = native_kind_counts.get(kind, 0) + 1
        thread_id = int(native_event.get("threadId") or 0)
        if thread_id:
            native_thread_ids.add(thread_id)
        if kind == "entry":
            api_name = str(native_event.get("api") or "").strip()
            if api_name:
                native_api_counts[api_name] = native_api_counts.get(api_name, 0) + 1
    native_evidence_summary = {
        "ok": bool(
            isinstance(native_evidence, dict)
            and native_evidence.get("ok")
        ),
        "eventCount": int(
            native_evidence.get("eventCount") or len(native_events)
        ) if isinstance(native_evidence, dict) else len(native_events),
        "droppedEvents": int(native_evidence.get("droppedEvents") or 0)
        if isinstance(native_evidence, dict) else 0,
        "pendingCalls": int(native_evidence.get("pendingCalls") or 0)
        if isinstance(native_evidence, dict) else 0,
        "kindCounts": native_kind_counts,
        "threadIds": sorted(native_thread_ids),
        "topApis": [
            {"api": name, "count": count}
            for name, count in sorted(
                native_api_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )[:32]
        ],
        "error": (
            native_evidence.get("error")
            if isinstance(native_evidence, dict)
            else "Native evidence was not a mapping."
        ),
    }
    stop_result = None
    if stop_on_complete and (criteria_met or last_run.get("exited")):
        stop_result = StopApiTrace(api_trace_id, delete_breakpoints=True)
    timed_out = (
        not criteria_met and not last_run.get("exited") and time.time() >= deadline
    )
    return {
        "ok": bool(state.get("ok"))
        and (criteria_met or bool(last_run.get("exited")))
        and not bool(last_run.get("submissionError")),
        "heapTraceId": heap_trace_id,
        "apiTraceId": api_trace_id,
        "criteriaMet": criteria_met,
        "expected": expected,
        "stopWhenLiveZero": bool(stop_when_live_zero),
        "requireComplete": bool(require_complete),
        "callsPerIteration": calls_batch,
        "anomalyCount": int(sum((state.get("anomalyCounts") or {}).values())),
        "iterations": iterations,
        "timedOut": timed_out,
        "lastRun": last_run,
        "state": state,
        "nativeEvidenceSummary": native_evidence_summary,
        "stop": stop_result,
    }


def _heap_catalog_spec(
    catalog: Dict[str, Dict[str, Any]],
    module: str,
    function: str,
) -> Optional[Dict[str, Any]]:
    normalized_function = _normalized_api_export_name(function)
    full_name = f"{str(module or '').strip().lower()}!{normalized_function}"
    raw = catalog.get(full_name) or catalog.get(normalized_function)
    return dict(raw) if isinstance(raw, dict) else None


def _heap_requested_size(args: List[Dict[str, Any]], spec: Dict[str, Any]) -> int:
    indices = [int(item) for item in list(spec.get("sizeArgs") or [])]
    if not indices:
        return 0
    values = [_api_value_int(_api_arg_value(args, index)) for index in indices]
    if str(spec.get("sizeMode") or "") == "product":
        size = 1
        for value in values:
            size *= max(0, int(value))
        return size
    return max(0, int(values[0]))


def _heap_return_success(return_value: str, semantics: str) -> bool:
    value = _api_value_int(return_value)
    mode = str(semantics or "").strip().lower()
    if mode == "pointer":
        return value != 0
    if mode == "null_success":
        return value == 0
    if mode == "void":
        return True
    return value != 0


@mcp.tool()
def GetHeapState(heap_trace_id: str) -> dict:
    """Reduce returned allocator calls into live resources and lifecycle evidence."""

    with _RUNTIME_LOCK:
        heaps = dict(_RUNTIME_STATE.get("heapTraces", {}))
    heap = heaps.get(str(heap_trace_id or "").strip())
    if not heap:
        return {"ok": False, "error": "Heap trace not found"}
    api_trace = _get_api_trace(heap["apiTraceId"])
    if not api_trace:
        return {"ok": False, "error": "Associated API trace not found"}
    catalog = {
        str(name).lower(): dict(spec)
        for name, spec in (
            heap.get("allocatorCatalog") or HEAP_RESOURCE_CATALOG
        ).items()
        if isinstance(spec, dict)
    }
    minimum_size = int(heap.get("minAllocationSize") or 0)
    maximum_size = int(heap.get("maxAllocationSize") or 0)
    strict_unknown = bool(heap.get("strictUnknownResources"))
    live: Dict[str, Dict[str, Any]] = {}
    suppressed: set[str] = set()
    freed_addresses: Dict[str, Dict[str, Any]] = {}
    free_attempts: List[Dict[str, Any]] = []
    reallocations: List[Dict[str, Any]] = []
    logical_events: List[Dict[str, Any]] = []
    all_events: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []
    raw_counts = {"alloc": 0, "realloc": 0, "free": 0}
    family_counts: Dict[str, Dict[str, int]] = {}
    alloc_count = 0
    realloc_count = 0
    free_count = 0
    successful_free_count = 0
    failed_count = 0
    filtered_calls = 0
    incomplete_returns = 0
    unknown_calls = 0
    allocation_sequence = 0

    def size_allowed(size: int) -> bool:
        return size >= minimum_size and (
            maximum_size == 0 or size <= maximum_size
        )

    def add_anomaly(
        kind: str, event: Dict[str, Any], allocation: Optional[Dict[str, Any]] = None
    ) -> None:
        item = {
            "kind": kind,
            "seq": event.get("seq"),
            "op": event.get("op"),
            "addr": event.get("addr") or event.get("oldAddr"),
            "threadId": event.get("threadId"),
            "allocationId": (
                allocation.get("allocationId") if isinstance(allocation, dict) else None
            ),
        }
        anomalies.append(item)
        event.setdefault("anomalies", []).append(kind)

    for call in sorted(
        list(api_trace.get("calls") or []),
        key=lambda item: int(item.get("seq") or 0),
    ):
        module = str(call.get("module") or "")
        function = str(call.get("func") or "")
        spec = _heap_catalog_spec(catalog, module, function)
        if spec is None:
            unknown_calls += 1
            continue
        op = str(spec.get("op") or "")
        family = str(spec.get("family") or "unknown")
        raw_counts[op] = int(raw_counts.get(op, 0)) + 1
        family_counter = family_counts.setdefault(
            family, {"alloc": 0, "realloc": 0, "free": 0}
        )
        family_counter[op] = int(family_counter.get(op, 0)) + 1
        if not call.get("returned"):
            incomplete_returns += 1
            continue
        args = list(call.get("args") or [])
        return_value = str(call.get("returnValue") or "")
        requested_size = _heap_requested_size(args, spec)
        owner_index = spec.get("ownerArg")
        owner_value = (
            _normalize_hex(_api_arg_value(args, int(owner_index)))
            if owner_index is not None
            else None
        )
        success = _heap_return_success(
            return_value, str(spec.get("returnSemantics") or "")
        )
        base_event: Dict[str, Any] = {
            "seq": int(call.get("seq") or 0),
            "api": f"{module}!{function}",
            "func": function,
            "module": module,
            "op": op,
            "family": family,
            "threadId": int(call.get("threadId") or 0),
            "timestamp": call.get("timestamp"),
            "returnTimestamp": call.get("returnTimestamp"),
            "durationMs": call.get("durationMs"),
            "returnValue": return_value,
            "returnDecoded": call.get("returnDecoded"),
            "owner": owner_value,
            "requestedSize": requested_size,
            "size": hex(requested_size),
            "sizeDecimal": requested_size,
            "actualSize": None,
            "actualSizeKnown": False,
            "success": success,
            "callStack": call.get("callStack") or [],
        }
        if op == "alloc":
            address = (
                _normalize_hex(return_value)
                if success and _api_value_int(return_value)
                else None
            )
            event = {**base_event, "addr": address}
            if not success or not address:
                failed_count += 1
                event["status"] = "allocation_failed"
            elif not size_allowed(requested_size):
                filtered_calls += 1
                suppressed.add(address)
                event["status"] = "filtered"
                event["filtered"] = True
            else:
                previous = live.get(address)
                if previous is not None:
                    add_anomaly("address_reuse_while_live", event, previous)
                allocation_sequence += 1
                allocation_id = f"alloc-{allocation_sequence}"
                allocation = {
                    **event,
                    "status": "live",
                    "allocationId": allocation_id,
                    "allocationSeq": event["seq"],
                    "generation": allocation_sequence,
                    "parentAllocationId": None,
                    "originThreadId": event["threadId"],
                }
                event.update(
                    {
                        "status": "allocated",
                        "allocationId": allocation_id,
                        "generation": allocation_sequence,
                    }
                )
                live[address] = allocation
                freed_addresses.pop(address, None)
                alloc_count += 1
                logical_events.append(event)
            all_events.append(event)
            continue

        address_index = spec.get("addressArg")
        address_raw = (
            _api_arg_value(args, int(address_index))
            if address_index is not None
            else ""
        )
        old_address = _normalize_hex(address_raw) or str(address_raw or "")
        if _api_value_int(old_address) == 0:
            old_address = ""
        previous = live.get(old_address) if old_address else None

        if op == "realloc":
            new_address = (
                _normalize_hex(return_value)
                if success and _api_value_int(return_value)
                else None
            )
            event = {
                **base_event,
                "oldAddr": old_address or None,
                "newAddr": new_address,
                "addr": new_address,
                "wasKnown": previous is not None,
                "parentAllocationId": (
                    previous.get("allocationId") if previous else None
                ),
            }
            if not success or not new_address:
                failed_count += 1
                event["status"] = "reallocation_failed"
            elif not size_allowed(requested_size):
                filtered_calls += 1
                if old_address:
                    live.pop(old_address, None)
                    suppressed.discard(old_address)
                suppressed.add(new_address)
                event["status"] = "filtered"
                event["filtered"] = True
            else:
                if previous is None:
                    if old_address in freed_addresses:
                        add_anomaly("realloc_after_free", event)
                    elif strict_unknown:
                        add_anomaly("invalid_realloc", event)
                    else:
                        event["status"] = "external_realloc"
                conflicting = live.get(new_address)
                if conflicting is not None and new_address != old_address:
                    add_anomaly("address_reuse_while_live", event, conflicting)
                if old_address:
                    live.pop(old_address, None)
                    suppressed.discard(old_address)
                allocation_sequence += 1
                allocation_id = f"alloc-{allocation_sequence}"
                allocation = {
                    **event,
                    "status": "live",
                    "allocationId": allocation_id,
                    "allocationSeq": event["seq"],
                    "generation": allocation_sequence,
                    "originThreadId": (
                        int(previous.get("originThreadId") or 0)
                        if previous
                        else event["threadId"]
                    ),
                }
                event.update(
                    {
                        "status": "reallocated",
                        "allocationId": allocation_id,
                        "generation": allocation_sequence,
                    }
                )
                live[new_address] = allocation
                freed_addresses.pop(new_address, None)
                realloc_count += 1
                logical_events.append(event)
            reallocations.append(event)
            all_events.append(event)
            continue

        event = {
            **base_event,
            "addr": old_address or None,
            "wasKnown": previous is not None,
            "allocationId": (
                previous.get("allocationId") if previous else None
            ),
        }
        if not old_address:
            event["status"] = "null_free"
        elif old_address in suppressed:
            if success:
                suppressed.discard(old_address)
            event["status"] = "filtered"
            event["filtered"] = True
        else:
            if previous is None:
                if old_address in freed_addresses:
                    add_anomaly("double_free", event, freed_addresses[old_address])
                    event["status"] = "double_free"
                elif strict_unknown or not success:
                    add_anomaly("invalid_free", event)
                    event["status"] = "invalid_free"
                else:
                    event["status"] = "external_free"
            elif success:
                origin_thread = int(previous.get("originThreadId") or 0)
                if origin_thread and origin_thread != event["threadId"]:
                    add_anomaly("cross_thread_free", event, previous)
                live.pop(old_address, None)
                freed_addresses[old_address] = previous
                free_count += 1
                successful_free_count += 1
                event["status"] = "freed"
                event["allocation"] = previous
                logical_events.append(event)
            else:
                event["status"] = "free_failed"
        if not success:
            failed_count += 1
        free_attempts.append(event)
        all_events.append(event)

    anomaly_counts: Dict[str, int] = {}
    for anomaly in anomalies:
        kind = str(anomaly.get("kind") or "unknown")
        anomaly_counts[kind] = int(anomaly_counts.get(kind, 0)) + 1
    retained_events = all_events[-1000:]
    oldest_seq = int(retained_events[0].get("seq") or 0) if retained_events else 0
    latest_seq = int(retained_events[-1].get("seq") or 0) if retained_events else 0
    dropped_calls = int(api_trace.get("droppedCalls") or 0)
    return {
        "ok": True,
        "schema": "heap-resource-lifecycle-v2",
        "heapTraceId": heap_trace_id,
        "apiTraceId": heap["apiTraceId"],
        "families": list(heap.get("families") or []),
        "allocatorCatalogCount": len(catalog),
        "allocCount": alloc_count,
        "reallocCount": realloc_count,
        "freeCount": free_count,
        "successfulFreeCount": successful_free_count,
        "failedOperationCount": failed_count,
        "liveAllocations": len(live),
        "leakCount": len(live),
        "live": sorted(
            live.values(), key=lambda item: int(item.get("allocationSeq") or 0)
        )[-500:],
        "leaks": sorted(
            live.values(), key=lambda item: int(item.get("allocationSeq") or 0)
        )[-500:],
        "recentFrees": free_attempts[-500:],
        "recentReallocations": reallocations[-500:],
        "events": logical_events[-1000:],
        "allEvents": retained_events,
        "oldestSeq": oldest_seq,
        "latestSeq": latest_seq,
        "cursorExclusive": True,
        "droppedCalls": dropped_calls,
        "evidenceComplete": dropped_calls == 0 and incomplete_returns == 0,
        "anomalies": anomalies[-500:],
        "anomalyCounts": anomaly_counts,
        "rawApiCalls": raw_counts,
        "familyCalls": family_counts,
        "sizeFilter": {
            "minimum": minimum_size,
            "maximum": maximum_size or None,
            "filteredCalls": filtered_calls,
            "suppressedLiveResources": len(suppressed),
        },
        "unknownCatalogCalls": unknown_calls,
        "unknownResourcePolicy": (
            "strict" if strict_unknown else "external_baseline"
        ),
        "incompleteReturns": incomplete_returns,
        "returnTracking": True,
    }


# ---------------------------------------------------------------------------
# Native instruction trace / coverage backend
# ---------------------------------------------------------------------------


@mcp.tool()
def StartNativeTrace(
    mode: str = "both",
    range_start: str = "",
    range_size: int = 0,
    max_steps: int = 100000,
    max_events: int = 100000,
    max_unique: int = 100000,
    stop_on_limit: bool = True,
    enrich_events: bool = False,
    auto_resume_exceptions: bool = False,
) -> dict:
    """Arm the bridge's native ``CB_TRACEEXECUTE`` recorder.

    The recorder is bound to the exact guarded debug session and must be armed
    while the target is paused. ``instruction`` keeps the ordered CIP/thread
    tape, ``coverage`` keeps only address hit counts, and ``both`` keeps both.
    Optional ``range_start`` + ``range_size`` restrict evidence to one module or
    function while ``max_steps`` still bounds all executed trace steps.
    """

    normalized_mode = str(mode or "both").strip().lower()
    if normalized_mode not in ("instruction", "coverage", "both"):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "mode must be instruction, coverage, or both",
        }
    start = str(range_start or "").strip()
    try:
        size = int(range_size or 0)
        steps = int(max_steps)
        events = int(max_events)
        unique = int(max_unique)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "Trace limits and range_size must be integers.",
        }
    if bool(start) != bool(size > 0):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "range_start and a positive range_size must be supplied together.",
        }
    if not (1 <= steps <= 10_000_000):
        return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "max_steps must be 1..10000000"}
    if not (1 <= events <= 500_000) or not (1 <= unique <= 500_000):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "max_events and max_unique must be 1..500000",
        }
    hello = BridgeHello(refresh=True)
    capabilities = (
        (hello.get("identity") or {}).get("capabilities", {})
        if isinstance(hello, dict)
        else {}
    )
    if not isinstance(capabilities.get("nativeTrace"), dict):
        return {
            "ok": False,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": "The active bridge does not advertise nativeTrace support.",
        }
    params: Dict[str, Any] = {
        "mode": normalized_mode,
        "maxSteps": str(steps),
        "maxEvents": str(events),
        "maxUnique": str(unique),
        "stopOnLimit": "true" if stop_on_limit else "false",
        "enrichEvents": "true" if enrich_events else "false",
        "autoResumeExceptions": (
            "true" if auto_resume_exceptions else "false"
        ),
    }
    if start:
        params["rangeStart"] = start
        # Bridge address/size parsing follows x64dbg's hexadecimal-default
        # expression syntax.  Emit an explicit prefix so a Python integer such
        # as 159744 cannot be misread as 0x159744.
        params["rangeSize"] = hex(size)
    payload = _coerce_json_payload(safe_post("Trace/Start", params, log=False))
    if not isinstance(payload, dict):
        return {"ok": False, "error": str(payload)}
    _log_event(
        "native_trace_start",
        traceId=payload.get("traceId"),
        mode=normalized_mode,
        rangeStart=start or None,
        rangeSize=size or None,
        maxSteps=steps,
        autoResumeExceptions=bool(auto_resume_exceptions),
    )
    return payload


@mcp.tool()
def GetNativeTrace(
    trace_id: str,
    event_offset: int = 0,
    event_limit: int = 100,
    hit_offset: int = 0,
    hit_limit: int = 100,
    event_after_seq: int = 0,
    hit_after_revision: int = 0,
    detail: str = "",
) -> dict:
    """Read a trace using legacy offsets or independent event/hit watermarks.

    ``detail=summary`` keeps the explicitly requested event/hit page and
    removes only repeated trace-configuration fields. ``detail=full`` returns
    every historical field. Empty detail inherits the active tool profile.
    """

    detail_level, detail_error = _resolve_response_detail(detail)
    if detail_error:
        return detail_error
    trace_id = str(trace_id or "").strip()
    if not trace_id:
        return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "trace_id is required"}
    params = {
        "traceId": trace_id,
        "eventOffset": str(max(0, int(event_offset))),
        "eventLimit": str(max(0, min(int(event_limit), 5000))),
        "hitOffset": str(max(0, int(hit_offset))),
        "hitLimit": str(max(0, min(int(hit_limit), 5000))),
        "eventAfterSeq": str(max(0, int(event_after_seq))),
        "hitAfterRevision": str(max(0, int(hit_after_revision))),
    }
    payload = _coerce_json_payload(safe_get("Trace/Status", params, log=False))
    if not isinstance(payload, dict):
        return {"ok": False, "error": str(payload)}
    decorated = _decorate_native_trace_page(
        payload,
        requested_event_limit=max(0, min(int(event_limit), 5000)),
        requested_hit_limit=max(0, min(int(hit_limit), 5000)),
    )
    return (
        _compact_native_trace_page(decorated)
        if detail_level == "summary"
        else decorated
    )


@mcp.tool()
def WaitNativeTrace(
    trace_id: str,
    timeout_ms: int = 30000,
    poll_ms: int = 50,
) -> dict:
    """Wait for a native trace to finish without monopolizing the HTTP bridge."""

    trace_id = str(trace_id or "").strip()
    if not trace_id:
        return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "trace_id is required"}
    deadline = time.time() + (max(0, int(timeout_ms)) / 1000.0)
    last: Dict[str, Any] = {}
    while time.time() <= deadline:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        payload = _coerce_json_payload(
            safe_get(
                "Trace/Wait",
                {"traceId": trace_id, "timeoutMs": str(min(max(remaining_ms, 50), 700))},
                log=False,
            )
        )
        if not isinstance(payload, dict):
            return {"ok": False, "traceId": trace_id, "error": str(payload)}
        last = payload
        if payload.get("completed") or not payload.get("active"):
            payload["timedOut"] = False
            payload["timeoutMs"] = int(timeout_ms)
            return payload
        if time.time() >= deadline:
            break
        time.sleep(max(10, int(poll_ms)) / 1000.0)
    last.update({"ok": False, "traceId": trace_id, "timedOut": True, "timeoutMs": int(timeout_ms)})
    return last


@mcp.tool()
def StopNativeTrace(trace_id: str) -> dict:
    """Stop an armed native trace while preserving its retained evidence."""

    trace_id = str(trace_id or "").strip()
    payload = _coerce_json_payload(
        safe_post("Trace/Stop", {"traceId": trace_id}, log=False)
    )
    return payload if isinstance(payload, dict) else {"ok": False, "error": str(payload)}


@mcp.tool()
def ClearNativeTrace(trace_id: str) -> dict:
    """Delete retained native-trace evidence after the trace is no longer active."""

    trace_id = str(trace_id or "").strip()
    if not trace_id:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "trace_id is required",
        }
    payload = _coerce_json_payload(
        safe_post("Trace/Clear", {"traceId": trace_id}, log=False)
    )
    return payload if isinstance(payload, dict) else {"ok": False, "error": str(payload)}


@mcp.tool()
def RunNativeTrace(
    trace_id: str,
    condition: str = "0",
    step_mode: str = "into",
    max_steps: int = 0,
    timeout_ms: int = 30000,
    event_limit: int = 200,
    hit_limit: int = 1000,
    detail: str = "",
) -> dict:
    """Drive an armed native trace with x64dbg conditional tracing and return evidence.

    Summary mode returns progress/counts/cursors only; the retained evidence is
    read through ``GetNativeTrace``. Full mode preserves the historical nested
    command, wait and evidence objects.
    """

    detail_level, detail_error = _resolve_response_detail(detail)
    if detail_error:
        return detail_error

    def _trace_response(value: Dict[str, Any]) -> Dict[str, Any]:
        return _compact_native_trace_run(value) if detail_level == "summary" else value

    trace_id = str(trace_id or "").strip()
    initial = GetNativeTrace(trace_id, event_limit=0, hit_limit=0, detail="full")
    if not initial.get("ok") or not initial.get("active"):
        return _trace_response({
            "ok": False,
            "traceId": trace_id,
            "error": "Native trace is not active.",
            "status": initial,
        })
    configured_steps = int(initial.get("maxSteps") or 0)
    requested_steps = int(max_steps or configured_steps or 100000)
    mode = str(step_mode or "into").strip().lower().replace("_", "").replace("-", "")
    mode = {
        "stepinto": "into",
        "traceinto": "into",
        "stepover": "over",
        "traceover": "over",
    }.get(mode, mode)
    if mode not in ("into", "over"):
        return _trace_response({
            "ok": False,
            "traceId": trace_id,
            "errorCode": "INVALID_ARGUMENT",
            "error": "step_mode must be into, stepinto, over, or stepover",
        })
    command = (
        TraceOverConditional(condition=str(condition or "0"), max_steps=requested_steps)
        if mode == "over"
        else TraceIntoConditional(condition=str(condition or "0"), max_steps=requested_steps)
    )
    if not isinstance(command, dict) or not command.get("ok"):
        StopNativeTrace(trace_id)
        return _trace_response({
            "ok": False,
            "traceId": trace_id,
            "command": command,
            "error": "Trace command submission failed",
        })
    waited = WaitNativeTrace(trace_id=trace_id, timeout_ms=timeout_ms, poll_ms=25)
    if waited.get("timedOut"):
        StopNativeTrace(trace_id)
    evidence = GetNativeTrace(
        trace_id,
        event_offset=0,
        event_limit=max(0, min(int(event_limit), 5000)),
        hit_offset=0,
        hit_limit=max(0, min(int(hit_limit), 5000)),
        detail="full",
    )
    observed = int(evidence.get("matchedSteps") or 0)
    result = {
        "ok": bool(command.get("ok")) and observed > 0 and not bool(waited.get("timedOut")),
        "traceId": trace_id,
        "command": command,
        "wait": waited,
        "evidence": evidence,
        "observed": observed > 0,
    }
    if observed <= 0:
        result["error"] = "The trace command completed without a CB_TRACEEXECUTE event."
    return _trace_response(result)


# ---------------------------------------------------------------------------
# TraceRecord wrapper
# ---------------------------------------------------------------------------

def _next_trace_record_id() -> str:
    with _RUNTIME_LOCK:
        seq = int(_RUNTIME_STATE.get("traceRecordSeq", 0)) + 1
        _RUNTIME_STATE["traceRecordSeq"] = seq
    return f"trace-{seq}"


def _read_native_trace_hits(
    native_trace_id: str, max_items: int = 100000
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Read deterministic address-ordered hit pages with a hard client cap."""

    cap = max(0, min(int(max_items), 500000))
    offset = 0
    hits: List[Dict[str, Any]] = []
    last: Dict[str, Any] = {}
    while offset < cap:
        page_limit = min(5000, cap - offset)
        last = GetNativeTrace(
            native_trace_id,
            event_offset=0,
            event_limit=0,
            hit_offset=offset,
            hit_limit=page_limit,
            detail="full",
        )
        if not last.get("ok"):
            break
        page = [item for item in (last.get("hits") or []) if isinstance(item, dict)]
        hits.extend(page)
        offset += len(page)
        if not last.get("hitHasMore") or not page:
            break
    return last, hits


def _read_native_trace_events(
    native_trace_id: str, max_items: int = 100000
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Read an ordered native instruction tape using its exclusive cursor."""

    cap = max(0, min(int(max_items), 500000))
    after_seq = 0
    events: List[Dict[str, Any]] = []
    last: Dict[str, Any] = {}
    while len(events) < cap:
        page_limit = min(5000, cap - len(events))
        last = GetNativeTrace(
            native_trace_id,
            event_offset=0,
            event_limit=page_limit,
            hit_offset=0,
            hit_limit=0,
            event_after_seq=after_seq,
            hit_after_revision=0,
            detail="full",
        )
        if not isinstance(last, dict) or not last.get("ok"):
            break
        page = [item for item in (last.get("events") or []) if isinstance(item, dict)]
        events.extend(page)
        next_after = int(last.get("eventNextAfterSeq") or after_seq)
        if not page or next_after <= after_seq or not last.get("eventHasMore"):
            break
        after_seq = next_after
    return last, events


def _reconstruct_basic_block_coverage(
    events: List[Dict[str, Any]],
    module_base: int,
    module_size: int,
    image_identity: str,
    limit: int,
) -> dict:
    """Compatibility wrapper around the pure, version-aware core."""

    return reconstruct_basic_block_coverage(
        events,
        module_base,
        module_size,
        image_identity,
        limit,
    )


@mcp.tool()
def StartTraceRecord(
    mode: str = "bitmap",
    label: str = "",
    max_steps: int = 10_000_000,
    stop_on_limit: bool = False,
) -> dict:
    """
    Enable native instruction recording for the main module.

    The bridge keeps an enriched instruction tape and reconstructs basic
    blocks/edges from decoded branch boundaries. Legacy address-hit snapshots
    remain available through GetTraceRecord.

    Args:
        mode: "bitmap" (record unique addresses) or "hitcount" (addr → hits).
        label: Optional label for humans.
        max_steps: Hard native-instruction ceiling (1..10,000,000).
        stop_on_limit: Pause the target when the hard ceiling is reached.

    Returns {ok, traceId, nativeTraceId, mode, moduleBase, moduleSize,
    maxSteps}. Use RunTraceRecord to drive the armed native recorder.
    """
    mode_lower = str(mode or "bitmap").lower()
    if mode_lower not in ("bitmap", "hitcount"):
        return {"ok": False, "error": f"Unknown mode '{mode}'. Use bitmap or hitcount."}
    try:
        native_max_steps = max(1, min(int(max_steps), 10_000_000))
    except (TypeError, ValueError):
        return {"ok": False, "error": "max_steps must be an integer in 1..10000000"}
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging") or not state.get("paused"):
        return {"ok": False, "error": "StartTraceRecord requires a paused debug session"}
    module_base = _normalize_hex(_get_current_debuggee_module_base())
    if not module_base:
        return {"ok": False, "error": "Cannot determine debuggee module base"}
    module_record: Dict[str, Any] = {}
    module_payload = GetModuleList()
    for candidate in module_payload.get("modules", []) if isinstance(module_payload, dict) else []:
        if isinstance(candidate, dict) and _normalize_hex(candidate.get("base")) == module_base:
            module_record = candidate
            break
    module_size = int(_parse_int(module_record.get("size"), 0) or 0)
    if module_size <= 0:
        return {"ok": False, "error": "Cannot determine debuggee module size"}
    # Keep the native tape unfiltered at capture time.  A trace record can be
    # started while RIP is in a loader/CRT/system module (for example after a
    # previous bounded trace stopped).  Filtering only while reconstructing
    # the requested main-module coverage prevents that perfectly valid
    # lifecycle from producing an empty tape.
    native = StartNativeTrace(
        mode="both",
        range_start="",
        range_size=0,
        max_steps=native_max_steps,
        max_events=100_000,
        max_unique=500_000,
        stop_on_limit=bool(stop_on_limit),
        enrich_events=True,
        auto_resume_exceptions=True,
    )
    if not native.get("ok"):
        return native
    trace_id = _next_trace_record_id()
    record = {
        "traceId": trace_id,
        "nativeTraceId": native.get("traceId"),
        "backend": "cb_traceexecute_v1",
        "label": str(label or ""),
        "mode": mode_lower,
        "moduleBase": module_base,
        "moduleSize": module_size,
        "captureRange": "all",
        "imageSha256": str(
            ((state.get("session") or {}).get("imageSha256") or "")
        ).lower(),
        "createdAt": _now_iso(),
        "enabled": True,
        "observedAddrs": {},  # hex_addr -> hit count
    }
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
        traces[trace_id] = record
        if len(traces) > MAX_TRACE_RECORD_SESSIONS:
            oldest = sorted(traces.values(), key=lambda r: r.get("createdAt") or "")[0]
            traces.pop(oldest["traceId"], None)
        _RUNTIME_STATE["traceRecords"] = traces
    return {
        "ok": True,
        "traceId": trace_id,
        "nativeTraceId": native.get("traceId"),
        "backend": "cb_traceexecute_v1",
        "mode": mode_lower,
        "moduleBase": module_base,
        "moduleSize": hex(module_size),
        "maxSteps": native_max_steps,
        "note": "Native instruction tape with reconstructed basic-block/edge coverage. Call RunTraceRecord to drive it.",
    }


@mcp.tool()
def RunTraceRecord(trace_id: str, timeout_ms: int = 10000, max_hits: int = 2000) -> dict:
    """
    Run the debuggee while accumulating BB coverage into the given trace.
    Blocks until max_hits or timeout or debuggee exit.
    """
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
    record = traces.get(trace_id)
    if not record:
        return {"ok": False, "error": "Trace not found"}
    native_trace_id = str(record.get("nativeTraceId") or "")
    if not native_trace_id:
        return {"ok": False, "traceId": trace_id, "error": "Trace record has no native backend identity"}
    safe_steps = max(1, min(int(max_hits), 10_000_000))
    run = RunNativeTrace(
        trace_id=native_trace_id,
        condition="0",
        step_mode="into",
        max_steps=safe_steps,
        timeout_ms=timeout_ms,
        event_limit=0,
        hit_limit=0,
        detail="full",
    )
    status, hit_items = _read_native_trace_hits(native_trace_id, max_items=500000)
    observed = {
        str(item.get("ip")): int(item.get("hits") or 0)
        for item in hit_items
        if item.get("ip")
    }
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
        if trace_id in traces:
            traces[trace_id]["observedAddrs"] = observed
            traces[trace_id]["enabled"] = bool(status.get("active"))
            traces[trace_id]["lastRun"] = {
                "completed": status.get("completed"),
                "stopReason": status.get("stopReason"),
                "totalSteps": status.get("totalSteps"),
                "matchedSteps": status.get("matchedSteps"),
            }
        _RUNTIME_STATE["traceRecords"] = traces
    return {
        "ok": bool(run.get("ok")),
        "traceId": trace_id,
        "nativeTraceId": native_trace_id,
        "hitsRecorded": int(status.get("matchedSteps") or 0),
        "uniqueAddrs": int(status.get("uniqueAddresses") or len(observed)),
        "totalSteps": int(status.get("totalSteps") or 0),
        "stopReason": status.get("stopReason"),
        "run": run,
    }


@mcp.tool()
def StopTraceRecord(trace_id: str) -> dict:
    """
    Disable TraceRecord coverage (removes the memory BP).
    """
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
    record = traces.get(trace_id)
    if not record:
        return {"ok": False, "error": "Trace not found"}
    native_trace_id = str(record.get("nativeTraceId") or "")
    stopped = StopNativeTrace(native_trace_id) if native_trace_id else {"ok": False}
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
        if trace_id in traces:
            traces[trace_id]["enabled"] = False
        _RUNTIME_STATE["traceRecords"] = traces
    return {
        "ok": bool(stopped.get("ok")),
        "traceId": trace_id,
        "nativeTraceId": native_trace_id,
        "uniqueAddrs": int(stopped.get("uniqueAddresses") or len(record.get("observedAddrs", {}))),
        "native": stopped,
    }


@mcp.tool()
def GetTraceRecord(trace_id: str, include_addrs: bool = False, limit: int = 100) -> dict:
    """
    Return TraceRecord session info. By default returns summary; set
    include_addrs=true to include observed addresses (paginated by `limit`).
    """
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
    record = traces.get(trace_id)
    if not record:
        return {"ok": False, "error": "Trace not found"}
    native_trace_id = str(record.get("nativeTraceId") or "")
    native = (
        GetNativeTrace(
            native_trace_id,
            event_limit=0,
            hit_limit=max(0, min(int(limit), 5000)) if include_addrs else 0,
            detail="full",
        )
        if native_trace_id
        else {}
    )
    hit_items = native.get("hits", []) if isinstance(native, dict) else []
    result = {
        "ok": True,
        "traceId": trace_id,
        "nativeTraceId": native_trace_id or None,
        "backend": record.get("backend"),
        "label": record.get("label"),
        "mode": record.get("mode"),
        "moduleBase": record.get("moduleBase"),
        "moduleSize": hex(int(record.get("moduleSize") or 0)),
        "enabled": bool(native.get("active")) if native else record.get("enabled"),
        "createdAt": record.get("createdAt"),
        "uniqueAddrs": int(native.get("uniqueAddresses") or len(record.get("observedAddrs", {}))),
        "totalSteps": int(native.get("totalSteps") or 0),
        "matchedSteps": int(native.get("matchedSteps") or 0),
        "completed": native.get("completed"),
        "stopReason": native.get("stopReason"),
    }
    if include_addrs:
        result["topAddresses"] = sorted(
            [
                {"addr": item.get("ip"), "hits": int(item.get("hits") or 0)}
                for item in hit_items
            ],
            key=lambda item: (-item["hits"], str(item["addr"])),
        )[: max(1, int(limit))]
    return result


@mcp.tool()
def ReplayToAddress(target_addr: str, label_prefix: str = "") -> dict:
    """
    Pseudo-time-travel: find a saved state snapshot where rip/eip == target_addr
    and restore it. Must pair with snapshots saved during the original run —
    call SaveState at interesting points to build a replay timeline.

    Args:
        target_addr: Address to rewind to.
        label_prefix: Optional label prefix to restrict search (useful when
            you've tagged related snapshots).

    Returns {ok, snapshotId, restoredTo} or error with hint.
    """
    target = _normalize_hex(target_addr) or str(target_addr)
    with _RUNTIME_LOCK:
        snapshots = dict(_RUNTIME_STATE.get("stateSnapshots", {}))
    prefix_lower = str(label_prefix or "").lower()
    match = None
    for sid, snap in snapshots.items():
        if prefix_lower and not str(snap.get("label", "")).lower().startswith(prefix_lower):
            continue
        regs = snap.get("registers") or {}
        rip = regs.get("rip") or regs.get("eip")
        if rip and _normalize_hex(rip) == target:
            match = snap
            break
    if not match:
        return {
            "ok": False,
            "error": f"No snapshot found with rip=={target}. Save snapshots between DebugRun calls to build a replay timeline.",
            "totalSnapshots": len(snapshots),
            "hint": "Call SaveState() at interesting execution points (e.g. between steps) before looking for them via ReplayToAddress.",
        }
    restore = RestoreState(match["snapshotId"], restore_memory=True)
    return {
        "ok": restore.get("ok"),
        "snapshotId": match["snapshotId"],
        "restoredTo": target,
        "restoreResult": restore,
    }


@mcp.tool()
def GetBasicBlockCoverage(trace_id: str, limit: int = 100) -> dict:
    """
    Return coverage summary: covered instruction addresses grouped with
    module-relative offsets. Useful for fuzzing feedback.
    """
    with _RUNTIME_LOCK:
        traces = dict(_RUNTIME_STATE.get("traceRecords", {}))
    record = traces.get(trace_id)
    if not record:
        return {"ok": False, "error": "Trace not found"}
    module_base = int(str(record.get("moduleBase") or "0x0"), 16)
    # Lookup main module size for in-range check.
    # StartTraceRecord captured this while the image was live.  Preserve it
    # when coverage is queried after normal process exit, where GetModuleList
    # can no longer return the main image.
    module_size = int(_parse_int(record.get("moduleSize"), 0) or 0)
    try:
        image = _get_current_debuggee_image_name() or ""
        mod_list = GetModuleList()
        modules = mod_list.get("modules", []) if isinstance(mod_list, dict) else []
        for m in modules:
            if isinstance(m, dict) and str(m.get("name", "")).lower() == image.lower():
                live_size = int(_parse_int(m.get("size"), 0) or 0)
                if live_size > 0:
                    module_size = live_size
                break
    except Exception:
        module_size = 0
    native_trace_id = str(record.get("nativeTraceId") or "")
    native_events_status, native_events = (
        _read_native_trace_events(native_trace_id, max_items=100000)
        if native_trace_id
        else ({}, [])
    )
    native = (
        GetNativeTrace(
            native_trace_id,
            event_limit=0,
            hit_limit=max(1, min(int(limit), 5000)),
            detail="full",
        )
        if native_trace_id
        else {}
    )
    observed_items = native.get("hits", []) if isinstance(native, dict) else []
    if not observed_items:
        observed_items = [
            {"ip": addr, "hits": hits}
            for addr, hits in (record.get("observedAddrs", {}) or {}).items()
        ]
    entries = []
    for hit in sorted(
        observed_items,
        key=lambda item: (-int(item.get("hits") or 0), str(item.get("ip") or "")),
    )[: max(1, int(limit))]:
        addr = str(hit.get("ip") or "")
        hits = int(hit.get("hits") or 0)
        try:
            addr_int = int(str(addr), 16)
            entry = {"addr": addr, "hits": hits}
            if module_base:
                delta = addr_int - module_base
                if module_size and (delta < 0 or delta >= module_size):
                    entry["inModule"] = False
                    entry["offset"] = None
                else:
                    entry["inModule"] = True
                    entry["offset"] = f"0x{delta:x}"
            entries.append(entry)
        except Exception:
            entries.append({"addr": addr, "hits": hits})
    model = (
        _reconstruct_basic_block_coverage(
            native_events,
            module_base,
            module_size,
            str(record.get("imageSha256") or image or "runtime"),
            limit,
        )
        if native_events
        else {
            "coverageModel": "instruction-hit-fallback",
            "blocks": [],
            "edges": [],
            "blockCount": 0,
            "edgeCount": 0,
            "coveredInstructions": len(observed_items),
            "executedBlockHits": 0,
            "executedEdgeHits": 0,
            "eventCount": 0,
        }
    )
    return {
        "ok": True,
        "traceId": trace_id,
        "nativeTraceId": native_trace_id or None,
        "backend": record.get("backend"),
        "moduleBase": record.get("moduleBase"),
        "moduleSize": f"0x{module_size:x}" if module_size else None,
        "totalUnique": int(native.get("uniqueAddresses") or len(observed_items)),
        "totalSteps": int(native.get("totalSteps") or 0),
        "matchedSteps": int(native.get("matchedSteps") or 0),
        "entries": entries,
        **model,
        "eventCursorTruncated": bool(
            native_events_status.get("eventCursorTruncated")
        ),
        "eventDropped": int(native_events_status.get("droppedEvents") or 0),
        "eventTapeStatus": {
            "eventCount": int(native_events_status.get("eventCount") or 0),
            "eventReturned": int(native_events_status.get("eventReturned") or 0),
            "eventHasMore": bool(native_events_status.get("eventHasMore")),
            "eventAfterSeq": int(native_events_status.get("eventAfterSeq") or 0),
            "eventNextAfterSeq": int(
                native_events_status.get("eventNextAfterSeq") or 0
            ),
            "oldestEventSeq": int(native_events_status.get("oldestEventSeq") or 0),
            "latestEventSeq": int(native_events_status.get("latestEventSeq") or 0),
        },
    }


_COVERAGE_ARTIFACT_SCHEMA = "coverage-artifact-v1"


def _coverage_artifact_body(coverage: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a live coverage response into a stable hash+RVA artifact."""

    identity = str(
        coverage.get("stableIdentity")
        or coverage.get("imageSha256")
        or "runtime"
    ).strip().lower()
    reconstruction_schema = str(coverage.get("reconstructionSchema") or "")
    extended = bool(
        reconstruction_schema == "basic-block-edge-v2"
        or int(_parse_int(coverage.get("schemaVersion"), 1) or 1) >= 2
        or any(
            isinstance(item, dict)
            and (
                item.get("codeSha256")
                or item.get("selfModified")
                or item.get("baseStableKey")
            )
            for item in (coverage.get("blocks") or [])
        )
    )
    blocks: List[Dict[str, Any]] = []
    for raw in coverage.get("blocks") or []:
        if not isinstance(raw, dict):
            continue
        start = str(raw.get("startRva") or raw.get("rva") or "0x0")
        end = str(raw.get("endRva") or start)
        stable = str(raw.get("stableKey") or raw.get("id") or f"{identity}:{start}")
        block = {
            "stableKey": stable,
            "startRva": start,
            "endRva": end,
            "hits": int(raw.get("hits") or 0),
            "instructionCount": int(raw.get("instructionCount") or 0),
            "threadIds": sorted(
                {int(item) for item in (raw.get("threadIds") or [])}
            ),
        }
        if extended:
            block.update(
                {
                    "baseStableKey": str(raw.get("baseStableKey") or stable),
                    "instructionHits": int(
                        raw.get("instructionHits")
                        or raw.get("instructionCount")
                        or 0
                    ),
                    "codeSha256": str(raw.get("codeSha256") or "").upper(),
                    "codeVersion": max(
                        1, int(_parse_int(raw.get("codeVersion"), 1) or 1)
                    ),
                    "versionCountAtRva": max(
                        1,
                        int(_parse_int(raw.get("versionCountAtRva"), 1) or 1),
                    ),
                    "selfModified": bool(raw.get("selfModified")),
                }
            )
        blocks.append(block)
    blocks.sort(key=lambda item: item["stableKey"])
    edges: List[Dict[str, Any]] = []
    for raw in coverage.get("edges") or []:
        if not isinstance(raw, dict):
            continue
        source = str(raw.get("from") or "")
        target = str(raw.get("to") or "")
        if not source or not target:
            continue
        edge = {
            "from": source,
            "to": target,
            "hits": int(raw.get("hits") or 0),
            "kind": str(raw.get("kind") or "unknown"),
            "branchTargets": sorted(
                {str(item) for item in (raw.get("branchTargets") or [])}
            ),
        }
        if extended:
            edge["indirect"] = bool(raw.get("indirect"))
        edges.append(edge)
    edges.sort(key=lambda item: (item["from"], item["to"], item["kind"]))
    body = {
        "schema": _COVERAGE_ARTIFACT_SCHEMA,
        "schemaVersion": 2 if extended else 1,
        "coverageModel": str(
            coverage.get("coverageModel") or "basic-block-edge-v1"
        ),
        "stableIdentity": identity,
        "moduleBase": coverage.get("moduleBase"),
        "moduleSize": coverage.get("moduleSize"),
        "blocks": blocks,
        "edges": edges,
        "blockCount": len(blocks),
        "edgeCount": len(edges),
        "coveredInstructions": int(coverage.get("coveredInstructions") or 0),
        "executedBlockHits": int(coverage.get("executedBlockHits") or 0),
        "executedEdgeHits": int(coverage.get("executedEdgeHits") or 0),
        "sourceArtifactCount": max(1, int(coverage.get("sourceArtifactCount") or 1)),
    }
    if extended:
        body.update(
            {
                "reconstructionSchema": reconstruction_schema
                or "basic-block-edge-v2",
                "coveredInstructionVersions": int(
                    coverage.get("coveredInstructionVersions")
                    or coverage.get("coveredInstructions")
                    or 0
                ),
                "executedInstructionHits": int(
                    coverage.get("executedInstructionHits")
                    or sum(int(item.get("instructionHits") or 0) for item in blocks)
                ),
                "versionedBlockCount": int(
                    coverage.get("versionedBlockCount")
                    or sum(1 for item in blocks if item.get("selfModified"))
                ),
                "selfModifyingRvas": sorted(
                    {str(item) for item in (coverage.get("selfModifyingRvas") or [])}
                ),
                "indirectEdgeCount": int(
                    coverage.get("indirectEdgeCount")
                    or sum(1 for item in edges if item.get("indirect"))
                ),
                "exceptionEdgeCount": int(
                    coverage.get("exceptionEdgeCount")
                    or sum(1 for item in edges if item.get("kind") == "exception")
                ),
            }
        )
    return body


def _coverage_artifact_digest(body: Dict[str, Any]) -> str:
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest().upper()


def _coverage_artifact_input(raw: Any, label: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    value = raw
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError) as exc:
            return None, f"{label} is not valid JSON: {exc}"
    if isinstance(value, dict) and isinstance(value.get("artifact"), dict):
        value = value["artifact"]
    if not isinstance(value, dict):
        return None, f"{label} must be an artifact object or JSON object."
    if str(value.get("schema") or "") != _COVERAGE_ARTIFACT_SCHEMA:
        return None, f"{label} schema must be {_COVERAGE_ARTIFACT_SCHEMA}."
    body = _coverage_artifact_body(value)
    expected = str(value.get("artifactSha256") or "").upper()
    if expected and expected != _coverage_artifact_digest(body):
        return None, f"{label} artifactSha256 does not match its canonical body."
    return body, None


def _write_coverage_artifact(body: Dict[str, Any], output_path: str) -> Dict[str, Any]:
    if not str(output_path or "").strip():
        return {"written": False, "path": None}
    target = Path(os.path.abspath(str(output_path)))
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(body)
    payload["artifactSha256"] = _coverage_artifact_digest(body)
    payload["exportedAt"] = _now_iso()
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {"written": True, "path": str(target)}


@mcp.tool()
def ExportCoverageArtifact(
    trace_id: str,
    output_path: str = "",
    limit: int = 5000,
) -> dict:
    """Export stable hash+RVA basic-block/edge coverage for an active trace."""

    coverage = GetBasicBlockCoverage(trace_id, limit=max(1, min(int(limit), 5000)))
    if not coverage.get("ok"):
        return coverage
    body = _coverage_artifact_body(coverage)
    digest = _coverage_artifact_digest(body)
    try:
        written = _write_coverage_artifact(body, output_path)
    except (OSError, ValueError) as exc:
        return {
            "ok": False,
            "traceId": trace_id,
            "errorCode": "COVERAGE_EXPORT_FAILED",
            "error": str(exc),
        }
    return {
        "ok": True,
        "traceId": trace_id,
        "artifact": {**body, "artifactSha256": digest},
        "artifactSha256": digest,
        "output": written,
    }


@mcp.tool()
def MergeCoverageArtifacts(
    artifacts_json: str,
    output_path: str = "",
) -> dict:
    """Merge compatible coverage artifacts by stable block/edge identity."""

    try:
        parsed = json.loads(artifacts_json)
    except (TypeError, ValueError) as exc:
        return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": str(exc)}
    if isinstance(parsed, dict) and isinstance(parsed.get("artifacts"), list):
        parsed = parsed["artifacts"]
    if not isinstance(parsed, list) or not parsed:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "artifacts_json must contain a non-empty JSON array.",
        }
    artifacts: List[Dict[str, Any]] = []
    for index, raw in enumerate(parsed):
        artifact, error = _coverage_artifact_input(raw, f"artifacts[{index}]")
        if error:
            return {"ok": False, "errorCode": "INVALID_ARTIFACT", "error": error}
        assert artifact is not None
        artifacts.append(artifact)
    identities = {str(item.get("stableIdentity") or "") for item in artifacts}
    if len(identities) != 1:
        return {
            "ok": False,
            "errorCode": "IDENTITY_MISMATCH",
            "error": "Coverage artifacts must share stableIdentity (file SHA-256 + module RVA).",
            "identities": sorted(identities),
        }
    merged = dict(artifacts[0])
    block_map: Dict[str, Dict[str, Any]] = {}
    edge_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for artifact in artifacts:
        for block in artifact.get("blocks") or []:
            key = str(block["stableKey"])
            current = block_map.get(key)
            if current is None:
                block_map[key] = dict(block)
            else:
                current["hits"] += int(block.get("hits") or 0)
                current["instructionCount"] = max(
                    int(current.get("instructionCount") or 0),
                    int(block.get("instructionCount") or 0),
                )
                if "instructionHits" in current or "instructionHits" in block:
                    current["instructionHits"] = int(
                        current.get("instructionHits") or 0
                    ) + int(block.get("instructionHits") or 0)
                current["threadIds"] = sorted(
                    set(current.get("threadIds") or [])
                    | set(block.get("threadIds") or [])
                )
        for edge in artifact.get("edges") or []:
            key = (
                str(edge.get("from") or ""),
                str(edge.get("to") or ""),
                str(edge.get("kind") or "unknown"),
            )
            current = edge_map.get(key)
            if current is None:
                edge_map[key] = dict(edge)
            else:
                current["hits"] += int(edge.get("hits") or 0)
                current["branchTargets"] = sorted(
                    set(current.get("branchTargets") or [])
                    | set(edge.get("branchTargets") or [])
                )
    merged["blocks"] = sorted(block_map.values(), key=lambda item: item["stableKey"])
    merged["edges"] = sorted(
        edge_map.values(), key=lambda item: (item["from"], item["to"], item["kind"])
    )
    merged["blockCount"] = len(merged["blocks"])
    merged["edgeCount"] = len(merged["edges"])
    merged["coveredInstructions"] = sum(
        int(item.get("instructionCount") or 0) for item in merged["blocks"]
    )
    merged["executedBlockHits"] = sum(int(item.get("hits") or 0) for item in merged["blocks"])
    merged["executedEdgeHits"] = sum(int(item.get("hits") or 0) for item in merged["edges"])
    merged["sourceArtifactCount"] = len(artifacts)
    if int(merged.get("schemaVersion") or 1) >= 2:
        merged["coveredInstructionVersions"] = sum(
            int(item.get("instructionCount") or 0) for item in merged["blocks"]
        )
        merged["executedInstructionHits"] = sum(
            int(item.get("instructionHits") or 0) for item in merged["blocks"]
        )
        merged["versionedBlockCount"] = sum(
            1 for item in merged["blocks"] if item.get("selfModified")
        )
        merged["selfModifyingRvas"] = sorted(
            {
                str(item)
                for artifact in artifacts
                for item in (artifact.get("selfModifyingRvas") or [])
            }
        )
        merged["indirectEdgeCount"] = sum(
            1 for item in merged["edges"] if item.get("indirect")
        )
        merged["exceptionEdgeCount"] = sum(
            1 for item in merged["edges"] if item.get("kind") == "exception"
        )
    digest = _coverage_artifact_digest(merged)
    try:
        written = _write_coverage_artifact(merged, output_path)
    except (OSError, ValueError) as exc:
        return {"ok": False, "errorCode": "COVERAGE_EXPORT_FAILED", "error": str(exc)}
    return {
        "ok": True,
        "artifact": {**merged, "artifactSha256": digest},
        "artifactSha256": digest,
        "output": written,
    }


@mcp.tool()
def DiffCoverageArtifacts(
    baseline_json: str,
    candidate_json: str,
) -> dict:
    """Diff compatible coverage artifacts using stable block/edge keys."""

    baseline, baseline_error = _coverage_artifact_input(baseline_json, "baseline_json")
    candidate, candidate_error = _coverage_artifact_input(candidate_json, "candidate_json")
    if baseline_error or candidate_error:
        return {
            "ok": False,
            "errorCode": "INVALID_ARTIFACT",
            "error": baseline_error or candidate_error,
        }
    assert baseline is not None and candidate is not None
    if baseline["stableIdentity"] != candidate["stableIdentity"]:
        return {
            "ok": False,
            "errorCode": "IDENTITY_MISMATCH",
            "error": "Coverage artifacts must share stableIdentity.",
            "baselineIdentity": baseline["stableIdentity"],
            "candidateIdentity": candidate["stableIdentity"],
        }
    base_blocks = {str(item["stableKey"]): item for item in baseline.get("blocks") or []}
    cand_blocks = {str(item["stableKey"]): item for item in candidate.get("blocks") or []}
    base_edges = {
        (str(item.get("from")), str(item.get("to")), str(item.get("kind"))): item
        for item in baseline.get("edges") or []
    }
    cand_edges = {
        (str(item.get("from")), str(item.get("to")), str(item.get("kind"))): item
        for item in candidate.get("edges") or []
    }
    added_blocks = sorted(set(cand_blocks) - set(base_blocks))
    removed_blocks = sorted(set(base_blocks) - set(cand_blocks))
    changed_blocks = [
        {
            "stableKey": key,
            "baselineHits": int(base_blocks[key].get("hits") or 0),
            "candidateHits": int(cand_blocks[key].get("hits") or 0),
            "deltaHits": int(cand_blocks[key].get("hits") or 0)
            - int(base_blocks[key].get("hits") or 0),
        }
        for key in sorted(set(base_blocks) & set(cand_blocks))
        if int(base_blocks[key].get("hits") or 0)
        != int(cand_blocks[key].get("hits") or 0)
    ]
    added_edges = [list(key) for key in sorted(set(cand_edges) - set(base_edges))]
    removed_edges = [list(key) for key in sorted(set(base_edges) - set(cand_edges))]
    changed_edges = [
        {
            "from": key[0],
            "to": key[1],
            "kind": key[2],
            "baselineHits": int(base_edges[key].get("hits") or 0),
            "candidateHits": int(cand_edges[key].get("hits") or 0),
            "deltaHits": int(cand_edges[key].get("hits") or 0)
            - int(base_edges[key].get("hits") or 0),
        }
        for key in sorted(set(base_edges) & set(cand_edges))
        if int(base_edges[key].get("hits") or 0)
        != int(cand_edges[key].get("hits") or 0)
    ]
    return {
        "ok": True,
        "schema": "coverage-diff-v1",
        "stableIdentity": baseline["stableIdentity"],
        "addedBlocks": added_blocks,
        "removedBlocks": removed_blocks,
        "changedBlocks": changed_blocks,
        "addedEdges": added_edges,
        "removedEdges": removed_edges,
        "changedEdges": changed_edges,
        "summary": {
            "addedBlocks": len(added_blocks),
            "removedBlocks": len(removed_blocks),
            "changedBlocks": len(changed_blocks),
            "addedEdges": len(added_edges),
            "removedEdges": len(removed_edges),
            "changedEdges": len(changed_edges),
            "newlyCoveredBlocks": sum(
                1
                for key in set(base_blocks) & set(cand_blocks)
                if not int(base_blocks[key].get("hits") or 0)
                and int(cand_blocks[key].get("hits") or 0)
            ),
        },
    }


# ---------------------------------------------------------------------------
# OEP finder for packed executables
# ---------------------------------------------------------------------------
