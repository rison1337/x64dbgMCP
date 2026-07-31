#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdio.h>

typedef int (__cdecl *EAW_PAYLOAD_FN)(void);

#pragma section(".eaw", read, execute)
__declspec(allocate(".eaw")) __declspec(dllexport)
volatile unsigned char eaw_buffer[64] = {0};

__declspec(dllexport) __declspec(noinline)
void eaw_stage_write(void) {
    static const unsigned char payload[] = {
        0x6A, 0x2A, /* push 42 */
        0x58,       /* pop rax/eax */
        0xC3        /* ret */
    };
    __movsb(
        (unsigned char *)(ULONG_PTR)eaw_buffer,
        payload,
        sizeof(payload)
    );
    FlushInstructionCache(
        GetCurrentProcess(),
        (LPCVOID)(ULONG_PTR)eaw_buffer,
        sizeof(payload)
    );
}

__declspec(guard(nocf))
static int execute_generated_payload(void) {
    EAW_PAYLOAD_FN payload = (EAW_PAYLOAD_FN)(ULONG_PTR)eaw_buffer;
    return payload();
}

int main(void) {
    int result;
    eaw_stage_write();
    result = execute_generated_payload();
    printf(
        "EXECUTE_AFTER_WRITE_OK result=%d changed=4 executed=1\n",
        result
    );
    return result == 42 ? 0 : 94;
}
