#include <windows.h>
#include <stdio.h>

__declspec(noinline) static void mutate_watch_buffer(void);

__declspec(dllexport) volatile unsigned char g_watch_bytes[16] = {
    0x57, 0x41, 0x54, 0x43,
    0x48, 0x30, 0x30, 0x31,
    0xAA, 0xBB, 0xCC, 0xDD,
    0x11, 0x22, 0x33, 0x44
};

static void mutate_watch_buffer(void) {
    for (int index = 0; index < 16; ++index) {
        g_watch_bytes[index] ^= (unsigned char)(0x10 + index);
        Sleep(5);
    }
}

int main(void) {
    puts("watch_target ready");
    fflush(stdout);
    Sleep(3000);
    mutate_watch_buffer();
    Sleep(1500);
    return 0;
}
