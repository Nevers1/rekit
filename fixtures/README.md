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
| `ad_probe` | **0** |

`libbasic-arm64.so` (AArch64, Linux): same values, same zero from `ad_probe`.

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
