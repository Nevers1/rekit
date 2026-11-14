#include <windows.h>
#include <string.h>

__declspec(dllexport) int win_add(int a, int b) { return a + b; }
__declspec(dllexport) int win_strlen(const char *s) { return (int)strlen(s); }
__declspec(dllexport) int win_mul(int a, int b) { return a * b; }

__declspec(dllexport) int win_probe(void) {
    int score = 0;
    if (IsDebuggerPresent()) score |= 1;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) score |= 2;
    DWORD t1 = GetTickCount();
    DWORD t2 = GetTickCount();
    if (t2 < t1) score |= 4;
    return score;
}
