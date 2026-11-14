// Functions that behave differently across their input, so a sweep has
// something to find: a threshold, a keygen target, and a crash.
//
// These are the three shapes `rekit fuzz` is built around — a curve with a
// step, a function that returns 1 only for one input, and one that overruns a
// buffer for large inputs. Without them the fuzzer's output cannot be checked
// against anything.

int step(int n) {
    if (n < 10) {
        return 0;
    }
    if (n < 20) {
        return 1;
    }
    return 2;
}

// Only 0x1337 returns 1: the shape of a licence check.
int keygen(int n) {
    return n == 0x1337 ? 1 : 0;
}

// Overruns a four-byte buffer on purpose; the crash is the point.
int overrun(int n) {
    char buf[4];
    for (int i = 0; i < n; i++) {
        buf[i] = 'A';
    }
    return buf[0];
}

// Reads through a null pointer for one input only.
int nullread(int n) {
    if (n == 7) {
        volatile char *p = (volatile char *)0;
        return *p;
    }
    return n * 2;
}
