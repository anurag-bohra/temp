#include <windows.h>
int main(void){ HMODULE h = LoadLibraryA("wininet.dll"); (void)h; VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE); return 0; }
