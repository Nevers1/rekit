// A library whose export is hooked by rekit's own tests and examples: the
// function is small enough that the expected output is obvious, and it is
// called more than once so a hook that only fires once is caught.

int hooked(int n) {
    return n * 3;
}

int untouched(int n) {
    return n + 1;
}
