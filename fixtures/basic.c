#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int t_add(int a, int b) { return a + b; }
int t_abs(int x) { return x < 0 ? -x : x; }
size_t t_strlen(const char *s) { return strlen(s); }
int t_strcmp(const char *a, const char *b) { return strcmp(a, b); }
int t_fmt(char *buf, int n) { return snprintf(buf, n, "%s-%d", "abc", 42); }

__attribute__((noinline))
int t_hello(void) {
    const char *msg = "hello from emulation";
    return (int)strlen(msg);
}

extern long ptrace(int, ...);
int ad_probe(void) {
    int score = 0;
    if (ptrace(0, 0, 0, 0) != 0) score |= 1;
    if (getppid() != 1) score |= 2;
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                if (pid != 0) score |= 4;
            }
        }
        fclose(f);
    } else {
        score |= 8;
    }
    return score;
}
