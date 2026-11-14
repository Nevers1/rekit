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
