#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int t_add(int a, int b) { return a + b; }
int t_abs(int x) { return x < 0 ? -x : x; }
size_t t_strlen(const char *s) { return strlen(s); }
int t_strcmp(const char *a, const char *b) { return strcmp(a, b); }
int t_fmt(char *buf, int n) { return snprintf(buf, n, "%s-%d", "abc", 42); }

/* Floating point on purpose: AArch64 hypot is the case Unicorn cannot run
 * (no FP support in a bare machine), while QEMU returns 5 for (3, 4). */
double t_hypot(double a, double b) { return hypot(a, b); }

/* Returns a pointer: the return value is an address, and `--read-ret` is what
 * turns it into the string it points at. */
const char *t_dup(void) { return strdup("emulated string"); }

/* Mixed argument kinds: 3 + 2.5 + 4 = 9.5, so an emulator that puts the
 * double in an integer register (or the pointer in a float one) is obvious. */
double t_mix(int n, double x, const char *s) { return n + x + (double)strlen(s); }

/* Every libm call the emulator answers itself, in one number: 4 + 8 + 3 + 1
 * + 2 + 5 + 0 + 2.5 + 3 + 16 = 44.5. */
double t_math(void) {
    return sqrt(16.0) + pow(2.0, 3.0) + fmod(7.0, 4.0) + floor(1.7)
         + ceil(1.2) + hypot(3.0, 4.0) + sin(0.0) + fabs(-2.5)
         + (double)sqrtf(9.0f) + (double)powf(2.0f, 4.0f);
}

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
