// A host that calls into hooklib, so `rekit hook --mode spawn` has something
// real to attach to: the hook fires on a genuine process, not a mock.

#include <stdio.h>

int hooked(int n);
int untouched(int n);

int main(void) {
    printf("start\n");
    fflush(stdout);
    for (int i = 1; i <= 3; i++) {
        printf("hooked(%d) = %d\n", i, hooked(i));
        fflush(stdout);
    }
    printf("untouched(10) = %d\n", untouched(10));
    fflush(stdout);
    return 0;
}
