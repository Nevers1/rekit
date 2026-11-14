/* An IFUNC, the way glibc picks `memcpy` at load time.
 *
 * The slot for `chosen` does not hold a function: it holds a resolver, and
 * what the resolver returns is the function to call. An emulator that treats
 * the slot as a plain symbol lands in the resolver with the caller's arguments
 * and gets a plausible, wrong answer.
 */

static int impl_a(void) { return 11; }
static int impl_b(void) { return 22; }

static void *pick_b(void) { return impl_b; }

int chosen(void) __attribute__((ifunc("pick_b")));

/* Proves the slot is used: the call goes through the resolver's answer. */
int ifunc_call(void) { return chosen() + 1; }

/* A plain function next to it, so a broken resolve is visible by contrast. */
int plain(void) { return impl_a() + 1; }
