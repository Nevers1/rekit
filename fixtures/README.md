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
