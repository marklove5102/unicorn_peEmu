#include <Windows.h>

extern "C" void mainCRTStartup()
{
    const char text[] = "Hello World!\n";
    DWORD written = 0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, sizeof(text) - 1, &written, nullptr);
    ExitProcess(0);
}
