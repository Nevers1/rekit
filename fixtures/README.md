# Emulation fixtures

Small shared libraries with known answers, used to check that `rekit-emu`
actually executes code instead of guessing at it.

Build them with `./build.sh` (cross compilers are optional; missing ones are
skipped). The outputs are ignored by git.

## What each function must return

`libbasic.so` (x86-64, Linux):

| Call | Expected |
| --- | --- |
| `t_add 3 4` | 7 |
| `t_abs -5` | 5 |
| `t_strlen "Hello, RE!"` | 10 |
| `t_strcmp "abc" "abd"` | -1 |
| `t_hypot 3.0 4.0` | 5.0 with `--as-double` (imports `hypot` from libm) |
| `t_mix 3 2.5 "abcd"` | 9.5 with `--as-double` (int, double and pointer arguments) |
| `t_math` | 44.5 with `--as-double` (every libm call the emulator answers) |
| `t_dup` | a pointer to `"emulated string"`, shown by `--read-ret` |
| `ad_probe` | **0** |

`libbasic-arm64.so` (AArch64, Linux): same values, same zero from `ad_probe`.

`t_hypot` used to be the engine-choice example — Unicorn answered 0 because it
has no libm behind the import — and now it is the check that libm is answered
in-process, on both architectures:

```console
$ rekit emulate libbasic-arm64.so --symbol t_hypot --args 3.0,4.0 --as-double
return    0x0 (0) as double 5
calls     hypot x1
```

`engine=qemu` is still the fallback for what Unicorn cannot execute at all
(VFP/NEON on ARM32, TLS, anything that reaches deep into libc).

`--read-ret 16` on `t_dup` prints the string the returned pointer leads to,
which is the difference between "it returned an address" and "it built this".

Arguments carry their kind: `3` is an integer, `3.0` and `f:3` are doubles, and
`str:...` is a pointer to a string on the emulated heap. Integer and
floating-point arguments go to different registers, so `t_mix 3 2.5 "abcd"`
returns 9.5 only if both landed where the ABI says.

`win32.dll` / `win64.dll` (PE32 / PE32+):

| Call | Expected |
| --- | --- |
| `win_add 3 4` | 7 |
| `win_mul 6 7` | 42 |
| `win_strlen "Hello, RE!"` | 10 |
| `win_probe` | **0** |

`ad_probe` and `win_probe` are the interesting ones: each returns a bitmask of
"the analysis environment looks wrong", and every bit must stay clear.

```console
$ rekit emulate libbasic.so --symbol ad_probe
return    0x0 (0)
calls     ptrace x1, getppid x1, fopen x1, fgets x2, strncmp x1, fclose x1
files     /proc/self/status
```

If that prints anything other than 0, a check got through: `--no-vfs` turns off
the fake filesystem, and the `files` line shows what was read.

## JNI fixtures

`libjni.so` (x86-64) and `libjni-arm64.so` (AArch64) are the same source built
twice: a native method that drives a `JNIEnv` the way a real one does, without
`jni.h` so the fixture builds anywhere.

`jni_probe` returns a bitmask of what went wrong, so **0** means every call
behaved. It asks for the version, finds a class, gets a method id, round-trips
a string through `NewStringUTF`/`GetStringUTFChars`, checks the length, asks
whether an exception is pending, registers natives, reads the `JavaVM` and
compares two references.

```console
$ rekit emulate libjni.so --symbol jni_probe --args env
return    0x0 (0)
calls     GetVersion x1, FindClass x1, GetMethodID x1, NewStringUTF x1, GetStringUTFChars x1, ...
note      JNIEnv at 0x31100000: JNI calls are answered (strings round-trip, no exception is pending)

$ rekit emulate libjni.so --symbol jni_probe --args 0
return    0x100 (256)     # no environment: the first check fails, as it should
```

`Java_com_example_Foo_probe` is the same function under the name a real library
would export, and needs no `env` argument — the environment is supplied because
of the name. That is the only case where a zero first argument is replaced: a
function called with a literal zero keeps it.

## IFUNC fixtures

`libifunc.so` (x86-64) and `libifunc-arm64.so` (AArch64) put an IFUNC next to
an ordinary function, which is how glibc chooses `memcpy` on load: the slot
holds a resolver, and the resolver's return value is the function.

| Call | Expected |
| --- | --- |
| `ifunc_call` | 23 (`impl_b` 22 + 1) |
| `plain` | 12 (`impl_a` 11 + 1) |

An emulator that mistakes the slot for the function calls the resolver with the
caller's arguments and returns its result — a plausible address, not 23. The
relocation shape differs by linker: `IRELATIVE` for a local IFUNC, a
`GLOB_DAT`/`JUMP_SLOT` to an `IFUNC` symbol for an exported one, and only the
second is easy to miss because the symbol type is what gives it away.

```console
$ rekit emulate libifunc.so --symbol ifunc_call
return    0x17 (23)
```

## Fuzzing fixtures

`libfuzz.so` (x86-64, Linux) holds four functions whose behaviour depends on
the number passed in, so a sweep has something real to find.

| Call | Expected |
| --- | --- |
| `step n` | 0 for `n < 10`, 1 for `10..19`, 2 from `20` |
| `keygen n` | 1 only for `n == 0x1337` (4919), 0 otherwise |
| `overrun n` | `'A'` for `1..4`, then the stack canary fires and calls `__stack_chk_fail` |
| `nullread n` | `n * 2`, except `n == 7`, which reads address 0 |

```console
$ rekit fuzz libfuzz.so --symbol step --mode sweep --start 0 --end 30 --step 5
distinct returns: 3
             0: 2 values, 0..5
             1: 2 values, 10..15
             2: 3 values, 20..30
transitions:
  input 5 -> 10: return 0 -> 1
  input 15 -> 20: return 1 -> 2
```

`magic --target 1` on `keygen` finds input `4919`; `crash` on `overrun` lists
inputs `5..8` with `__stack_chk_fail`, and `crash` on `nullread` names `7` with
`read at 0x0`.

## Hook fixtures

`libhooklib.so` exports two functions, and `hookhost` calls one of them three
times — a hook that fires once and stops is wrong, so the count is checked too.

| Call | Expected |
| --- | --- |
| `hooked n` | `n * 3` |
| `untouched n` | `n + 1` |

```console
$ rekit hook libhooklib.so --symbol hooked --args 1 --mode spawn --spawn ./hookhost
[+] hooked @ 0x7fa5886970e9
start
hooked(1) = 3
hooked(2) = 6
hooked(3) = 9
untouched(10) = 11
[->] hooked(a0=0x1)
[<-] hooked = 0x3
[->] hooked(a0=0x2)
[<-] hooked = 0x6
[->] hooked(a0=0x3)
[<-] hooked = 0x9
[frida] process ended: process-terminated
```

Three `[->]` lines, three `[<-]` lines, and nothing for `untouched`: attaching to
the wrong export would show up as extra or missing lines rather than a plausible
but wrong result.

## Web fixtures

`web/` is text, not a binary, so it needs no build step: three files with known
answers for the four web tools.

| File | Holds |
| --- | --- |
| `app.js` | two hosts, two API routes, a query string, a GraphQL query, an AWS key, a password, a random token and a JWT |
| `index.html` | a protocol-relative script, a form action, and two asset paths that must be filtered out |
| `words.txt` | four words, the third of which is the JWT's secret |

```console
$ rekit endpoints fixtures/web
## URLs: 4
  //cdn.example.net/static/app.js          (app.js:4, and index.html)
  https://api.example.com/v2               (app.js:3)
  https://api.example.com/v2/login?client=web
  https://forms.example.com/submit

## Paths and API routes: 2
  /api/v2/profile
  /api/v2/sessions?page=1&size=20

## Parameters: 3
  client, page, size

## GraphQL: 1
  query GetProfile
```

Assets are absent on purpose: `/assets/avatar.png`, `/assets/logo.png` and
`/favicon.ico` are in the fixtures and must not appear. The full URL passed to
`fetch` shows up once, as a URL, not again as a path.

```console
$ rekit secrets fixtures/web --reveal
## critical (1)
  AWS access key ID: AKIAIOSFODNN7EXAMPLE

## medium (1)
  Password in code: hunter2hunter2

## low (2)
  JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi…
  high entropy (5.23): Zk9xS2pM4vQ8wR1tY6uI0oP3aS7dF5gH2jK4lN6bV8cX
```

The token is elided above; the tool prints it whole. Without `--reveal` the
values are masked (`AKIAIO••••••••MPLE`), and the context line is masked with
them. Four findings come from three pattern hits
and one entropy hit: the JWT is not reported twice, because a value is counted
once whatever matched it.

A live Stripe key is deliberately not in the fixture. Shaped like a real one it
would be blocked by GitHub's push protection, which is the correct behaviour —
so that rule is unit-tested with a value built at runtime instead.

The JWT is jwt.io's example, signed with `your-256-bit-secret`:

```console
$ rekit jwt "$TOKEN" --secret your-256-bit-secret
## Signature
  the signature matches this secret

$ rekit jwt "$TOKEN" --wordlist fixtures/web/words.txt
## Cracking
SECRET FOUND: "your-256-bit-secret"
tried 3 of 4 in 0.0s
```

`tried 3 of 4` is the check that the crack path really iterates: the fourth word
is never needed.

## Memory dumps

No dump ships here: a real image is gigabytes and belongs to whoever captured
it. The wrapper is checked against an image volatility cannot identify, which
is the honest case — it must answer with requirements, not a crash.

```console
$ head -c 1M /dev/urandom > /tmp/fake.raw
$ rekit memdump /tmp/fake.raw --list --limit 5
dump: fake.raw
plugins: 181
  windows.amcache.Amcache               Extract information on executed applications from the AmCache (deprecated).
  ...

$ rekit memdump /tmp/fake.raw --plugin linux.pslist
volatility3 linux.pslist — fake.raw
Volatility 3 Framework 2.28.0
Unsatisfied requirement plugins.PsList.kernel.layer_name:
...
A translation layer requirement was not fulfilled.
```

The plugin list proves the interpreter and `volatility3.cli.main` entry path
work; the requirement text proves `-f` reached volatility, since otherwise it
complains about a missing file rather than an unidentifiable one.

`REKIT_VOL_PYTHON` overrides the interpreter. Without it, the venv that pipx
created is found by asking it to `import volatility3`, not by trusting the
`vol` shim on `$PATH` — a moved venv leaves that shim in place, broken, and
looking installed.
