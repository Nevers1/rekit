# rekit

Static binary analysis for **humans and coding agents**. One binary, no runtime,
no Python, no JVM.

`rekit` answers the questions an agent actually asks before it can do anything
useful: what is this file, what is inside it, what does it import, is it packed,
is it fighting back.

```console
$ rekit info "ClientGUI.dll"
path      /home/floppa/Downloads/Telegram Desktop/system/ClientGUI.dll
format    PE32+ 64 little (x86-64)
size      26.1 MiB (27361280 bytes)
sha256    87495cae027bc7cf6dccb5af1c4eb50e7b4f278f8756b2e8c8ee4a0343ace255
entry     0x3d5c2c
sections  10
  .text                0x1000          4117504 bytes  r-x ent 6.51
  .mmshell             0x3ef000           4096 bytes  r-x ent 4.83
  .rdata               0x3f0000        9203200 bytes  r-- ent 7.89
  .data                0xcb7000         270848 bytes  rw- ent 4.25
  .pdata               0xcfa000         195072 bytes  r-- ent 7.94
  .mmstate             0xd2a000            512 bytes  rw- ent 0.45
  .vmp0                0xd2b000       13515776 bytes  r-x ent 7.10
  .rsrc                0x1a0f000           512 bytes  r-- ent 4.73
```

That `.vmp0` section is not a guess: `rekit entropy` names the protector.

```console
$ rekit entropy "ClientGUI.dll"
file entropy 7.4559
verdict      packed (VMProtect)
packers      VMProtect
```

No emulator was started, nothing was executed, and the file was never trusted.

## Why another one

Most binary tooling is a shell script around `rabin2`, `readelf`, `objdump`,
`jadx` and a Python venv. Agents pay for every one of those: process spawn cost,
missing tools, broken shebangs, parsing human output back into structure.

`rekit` is a single Rust binary that parses the formats itself:

- **One dependency tree, zero runtime.** `cargo install` and you are done.
- **Never panics on hostile input.** Every parser here can be fed garbage; the
  failure mode is "format unknown", not a crash. A malformed file is the normal
  case in this domain, not the edge case.
- **`path::inner` built in.** Reaching a `.so` inside an APK is not a separate
  extraction step for the caller.
- **MCP first.** The same code is a CLI and a Model Context Protocol server over
  stdio, so an agent gets structured answers instead of screen-scraping.

## Install

```sh
cargo install --git https://github.com/Nevers1/rekit rekit-cli
```

That gives you the analysis core. `emulate` lives in a separate binary
(`rekit-emu`, GPL-2.0 because it links Unicorn); install it only if you want
emulation:

```sh
cargo install --git https://github.com/Nevers1/rekit rekit-emu
```

Or from a checkout:

```sh
cargo install --path crates/rekit-cli
cargo build --release -p rekit-emu   # optional, adds `emulate`
```

`rekit emulate` looks for `rekit-emu` next to its own executable, then on the
`PATH`; point `REKIT_EMU` at it to override both.

## Use it from an agent

Point any MCP client at `rekit mcp`:

```sh
# OpenCode
opencode mcp add rekit --global -- rekit mcp
```

```jsonc
// Claude Desktop / Cursor / Zed — mcpServers entry
{
  "mcpServers": {
    "rekit": {
      "command": "rekit",
      "args": ["mcp"]
    }
  }
}
```

The tools are `info`, `strings`, `grep`, `hex`, `entropy`, `imports`, `exports`,
`antidebug`, `scan`, `archive`, `manifest`, `apktool`, `resources`, `decompile`,
`javap`, `dotnet`, `ghidra`, `ida`, `disasm`, `r2`, `asm`, `diff`, `patch`,
`binwalk`, `emulate`, `emulate_list`, `fuzz`, `hook`, `memdump`, `endpoints`,
`secrets`, `jwt`, `http` and `doctor`; clients prefix them with the server name,
so the agent sees `rekit_info`.

The server also ships usage instructions in the `initialize` response, so the
model learns `path::inner` and the `grep` pattern syntax without you writing a
paragraph in the system prompt.

## Tools

| Tool | Question it answers |
| --- | --- |
| `info` | What format, arch, bitness, entry point, sections, entropy per section? What next? |
| `strings` | What printable text is in here (ASCII and UTF-16LE), at which offsets? |
| `grep` | Where are these bytes (hex, `"quoted text"`, a word) — or, in `mode=text`, which line says this: line numbers, regex, case folding, context. |
| `hex` | Hex dump of a range, to verify bytes before patching. With `bytes` it finds a signature and dumps the first hit. |
| `entropy` | Is it packed? Which protector? Any RWX or high-entropy code? |
| `imports` | What can it do — imported symbols with their library, filterable by name. |
| `exports` | What does it offer — exported symbols with addresses, filterable. An archive is answered with its entry list. |
| `antidebug` | Is it fighting analysis? Scored verdict, not a wall of matches. |
| `scan` | Mass scanning without decompiling: known crypto constants, your own constant (`--value`), imports grouped by purpose, and a probe of every export. |
| `archive` | What is inside this APK/JAR/zip/tar.gz, so I can pick a `path::inner`. |
| `manifest` | The decoded `AndroidManifest.xml` of an APK: package, version, permissions, exported components. No apktool, no unpacking. |
| `apktool` | The whole package decoded: readable manifest, `res/values`, layouts, smali. Cached, and searchable by `pattern`. |
| `resources` | What an APK's zip holds — resource groups, layouts, drawables, assets — and one named XML decoded in place. |
| `decompile` | jadx to Java, cached. Lists classes, returns one class source by name, or searches the whole tree by `pattern` in one call. |
| `javap` | JVM bytecode with the constant pool, for a `.class` or a class inside a jar. |
| `dotnet` | A .NET assembly to exact C# through `ilspycmd`: list types, or decompile one. |
| `ghidra` | Native code to C through Ghidra headless, analysed once and reopened from its project. |
| `ida` | The same for IDA's Hex-Rays, through `idalib` and a cached `.i64`. |
| `disasm` | Disassembly by symbol or address range (llvm-objdump, objdump fallback). |
| `r2` | One r2 shot: functions, `aflj`, pseudo-C, xrefs, imports, sections. |
| `asm` | Assemble instructions to bytes, or write them in after `expect` matches. |
| `diff` | What changed between two versions: functions added, removed, modified. |
| `patch` | Write bytes at an offset, but only after `expect` matches what is already there. Keeps a copy of the file in the cache first, then asks rabin2 whether it still parses. |
| `binwalk` | Embedded files and firmware signatures, optionally narrowed by `signatures` and carved out. |
| `emulate_list` | Which functions can be called, with addresses and architecture. |
| `emulate` | Run one function in a sandboxed CPU and get the real return value — through the anti-debug checks, with a JNIEnv when it is a native method, or in a real QEMU process when Unicorn cannot execute the code. |
| `fuzz` | The same call over a range of inputs: where the return changes, which input is the key, which one crashes. |
| `hook` | A Frida script that logs a function's real arguments and return value; optionally runs the process. |
| `memdump` | What a RAM image holds, through volatility3: processes, sockets, command lines, files, hives, shell history. |
| `endpoints` | What a frontend bundle talks to: URLs, API routes, query parameters, GraphQL operations, with file and line. |
| `secrets` | Keys and tokens committed by accident, by shape and by entropy. Masked unless `reveal` is set. |
| `jwt` | What a token claims, whether its signature is checked, and whether an HS secret falls to a wordlist. |
| `http` | One request with method, headers, body, proxy and redirects, plus the curl that repeats it. |
| `browser` | A real headless Chrome: what the page actually did — the DOM after scripts, the network table, the console, cookies, storage, a screenshot, a PDF. Click, fill, wait. |
| `doctor` | Which external tools exist and their versions, so a missing dependency is explained. |

## CLI

Same tools, same output:

```sh
rekit info app.apk::lib/arm64-v8a/libnative.so
rekit archive app.apk
rekit strings libnative.so --min 6 --filter http --limit 50
rekit grep libnative.so -- 'de ad be ef'
rekit grep app.apk::res/values/strings.xml 'https://' --mode text --context 1
rekit grep smali 'invoke.*getDeviceId' --mode text --regex
rekit hex libnative.so --offset 0x2a8 --length 64
rekit antidebug libnative.so
rekit scan libnative.so --kind apis
rekit scan libnative.so --kind const --value 0xDEADBEEF --width 4
rekit scan libnative.so --kind probe --arg 42 --limit 20
rekit imports libnative.so --limit 20
rekit manifest app.apk::AndroidManifest.xml
rekit decompile app.apk --class com.example.MainActivity
rekit decompile app.apk --pattern "getDeviceId" --limit 20
rekit disasm libnative.so --symbol JNI_OnLoad
rekit r2 libnative.so --kind pdc --target entry0
rekit patch libnative.so --offset 0x2a8 --bytes "90 90" --expect "f3 0f"
rekit patch libnative.so --offset 0x2a8 --string "AAAA-BBBB" --expect "00 00 00 00 00 00 00 00 00 00"
rekit patch libnative.so --offset 0x2a8 --nop 4 --expect "f3 0f 1e fa"
rekit binwalk firmware.bin --extract
rekit emulate libnative.so --symbol check_license --args 'str:"AAAA-BBBB"'
rekit emulate-list libnative.so --filter check
rekit fuzz libnative.so --symbol check_license --mode magic --start 0 --end 65535 --target 1
rekit hook libnative.so --symbol check_license --mode spawn --spawn ./app
rekit memdump mem.raw --plugin windows.pslist --args "--pid 1234"
rekit ghidra libnative.so --symbol JNI_OnLoad
rekit ida libnative.so --symbol JNI_OnLoad
rekit dotnet tool.dll --type Demo.Checker
rekit javap classes --class com.example.Foo
rekit apktool app.apk --pattern "https://"
rekit asm "mov eax, 1; ret" --path libnative.so --patch --offset 0x2a8 --expect "f3 0f"
rekit diff old.so new.so
rekit endpoints dist/app.js
rekit secrets dist --min-severity high
rekit jwt "$TOKEN" --wordlist rockyou.txt
rekit http https://api.example.com/v2/login --method POST --json '{"user":"a","pass":"b"}'
rekit browser https://app.example.com --action snapshot --output shot.png
rekit browser https://app.example.com --action requests
rekit browser https://app.example.com --action eval --js 'document.cookie'
rekit browser https://app.example.com --action click --selector '#login' --js 'document.title'
rekit doctor
```

`--json` on `info`, `entropy` and `antidebug` gives machine-readable output.

## Archives and caching

A spec may contain several `::` steps and is resolved right to left:

```
firmware.bin::rootfs.tar.gz::bin/busybox
```

Extracted members land in `~/.cache/rekit` (`$REKIT_CACHE` or
`$XDG_CACHE_HOME/rekit` to move it). Only the **file name** of the requested
entry is used for the cache path, so a hostile entry called `../../etc/passwd`
cannot escape the cache directory.

Supported containers: zip (APK, JAR, IPA payloads), tar.gz, plain gz.

`patch` and `asm --patch` also write into the cache: a copy of the file lands in
`backups/` before the first byte changes, keyed by path, size and mtime so two
patches of the same version do not pile up. `--no-backup` skips it. After the
write the file is handed back to rabin2 — if it parsed before and refuses now,
the header took the hit and the answer says so.

## Four decompilers, one contract

`ghidra`, `ida`, `dotnet` and `javap` all answer "what does this function do",
so they take the same three things: `--symbol` for a name, `--address` in hex,
or neither for a list. Two details are handled here rather than left to the
caller:

- **Ghidra rebases ELF images by `0x100000`**, so an address copied from
  `disasm` or `info` matches nothing in it. It is retried as image base +
  offset, and the answer says so instead of pretending.
- **A jar goes on the classpath itself.** Putting the directory that holds it
  on `-cp` does not make `javap` look inside, which is why the old script never
  read a jar at all; a missing class answers with the dotted names the archive
  does contain.

Addresses are always hex: `0x2040` and `2040` both mean `0x2040`. Reading `2040`
as decimal would silently decompile a different function, which is worse than
refusing.

## Running it, not guessing

Reading decompiled C tells you what a check *looks like*. It does not tell you
what it *returns* for the input you care about, and obfuscated licence, password
and integrity checks are exactly where that gap costs hours.

`emulate` executes one function of the binary in Unicorn and prints what comes
back. Nothing from the file is trusted: it is loaded into a private address
space, and everything that would leave it — libc, syscalls, Win32, `/proc` — is
answered by the harness instead.

```console
$ rekit emulate libbasic.so --symbol ad_probe
arch      x86_64 / linux
target    ad_probe at 0x4000126c
stop      returned
return    0x0 (0)
calls     ptrace x1, getppid x1, fopen x1, fgets x2, strncmp x1, fclose x1
files     /proc/self/status
```

`ad_probe` is the usual anti-debug kit: `ptrace(PTRACE_TRACEME)`, a `getppid`
check, and `TracerPid` read out of `/proc/self/status`. On a real machine it
returns a non-zero bitmask; here it returns **0**, because each check is given
the answer a clean machine would give:

| Check | What the guest sees |
| --- | --- |
| `ptrace(PTRACE_TRACEME)` | 0 — nobody is tracing |
| `TracerPid` in `/proc/self/status` | 0, and the file is readable |
| `getppid()` | 1 |
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | 0 / 0 |
| `GetTickCount`, `QueryPerformanceCounter`, `clock_gettime` | a clock that moves forward |
| `getrandom`, `/dev/urandom` | plausible, deterministic bytes |
| `android.os` properties via `__system_property_get` | `ro.debuggable=0`, `ro.build.tags=release-keys` |

Arguments follow the ABI, so a 32-bit `cdecl` function gets its arguments on the
stack and a Win64 one in `rcx, rdx, r8, r9` with shadow space:

```console
$ rekit emulate win64.dll --symbol win_add --args 3,4
arch      x86_64 / windows
target    win_add at 0x3b9511450
stop      returned
return    0x7 (7)
```

Strings are written into the emulated heap; quote them when they contain a
comma, because the argument list itself is comma separated:

```console
$ rekit emulate libbasic.so --symbol t_strlen --args 'str:"Hello, RE!"'
return    0xa (10)
```

The same works for AArch64, ARM and 32-bit PE. An argument carries its type:
`3` is an integer, `3.0` (or `f:3`) is a double, `str:...` is a pointer to a
string on the emulated heap. `--as-double` reads the result from the floating
point register instead of the general purpose one, so `t_hypot 3.0 4.0` answers
`5` on both x86-64 and AArch64 without leaving Unicorn.

### Seeing inside the run

The return value is one number. When the number is not the answer — a check that
fails for the wrong reason, a decryption whose output you want — the run can
report what it left behind:

```console
$ rekit emulate libbasic.so --symbol t_fmt --args 0x20001000,32 \
    --regs rax,rdi --read '0x20001000:32:buf' --trace
arch      x86_64 / linux
target    t_fmt at 0x4000121f
stop      returned
return    0x6 (6)
calls     snprintf x1
reg       rax 0x6
reg       rdi 0x20001000
read      buf 0x20001000 6162632d34320000…
            |abc-42..........|
trace     0x4000121f  push rbp
trace     0x40001220  mov rbp, rsp
trace     0x40001223  sub rsp, 0x10
```

- `--regs rax,rdi` reads registers **after** the function returns. Names are the
  ones from the disassembly: `rax`, `eax`, `x0`, `r7`, `sp`, `pc`, `lr`.
- `--read addr:size:label` reads memory after the run — a decryption buffer, a
  global the function wrote, the stack. The label is optional. `0x…` and decimal
  both work, and a range that is not mapped is reported as such rather than
  failing the run.
- `--read-ret 64` does the same at the returned pointer. A function that builds
  a string, fills a struct or decrypts in place answers with an address, and
  the address alone says nothing:

  ```console
  $ rekit emulate libbasic.so --symbol t_dup --read-ret 16
  return    0x20000000 (536870912)
  calls     strdup x1
  read      ret 0x20000000 656d756c6174656420737472696e6700
              |emulated string.|
  ```
- `--trace` records executed addresses and shows the first 24 disassembled, which
  is how "it stops at 0x401123" becomes "it takes the wrong branch after the
  compare".

For code with no import table to rewrite — a static binary, a function copied
out of a packer — `--stub addr=name[:ret]` says what an address *is*:

```console
$ rekit emulate libbasic.so --symbol t_strlen --args 'str:hello' \
    --stub '0x40001050=strlen:3'
return    0x3 (3)
calls     strlen x1
stub      strlen -> 0x3 (forced)
```

The address is answered as if it were a call to that import: arguments are read
per the ABI, a real `strlen` is computed, and `:ret` replaces the result. A
forced value is **ignored** for allocators and file openers (`malloc`, `calloc`,
`fopen`, …) and the report says so — returning 0 from `malloc` would make the
guest dereference NULL, which is never what "pretend it succeeded" means.

`fuzz` takes the same `--stub`, so one sweep can run against a binary whose
calls were never linked.

### IFUNC: a function chosen at load time

glibc does not export one `memcpy`: the slot holds a resolver, and what the
resolver returns is the function to call, picked by the CPU features the machine
has. Treating that slot as a symbol address lands in the resolver with the
caller's arguments — an answer that looks like a pointer and is wrong. rekit
calls the resolver first, in the same Unicorn instance, and writes its answer
into the slot. Both relocation shapes are handled: `IRELATIVE` for a local
IFUNC, and a `GLOB_DAT`/`JUMP_SLOT` to a symbol whose type is `IFUNC` for an
exported one, which is what gcc emits for a `__attribute__((ifunc(...)))`.

### What emulation cannot do

Honest limits, because a wrong number is worse than no number:

- **Only the function you name is emulated.** Anything it calls that is not an
  imported libc/Win32 function must live in the same binary; a call into an
  unresolved library address is where it stops.
- **Packer stubs and VMProtect are out of scope.** The bytes have to be real
  instructions for the CPU to run them.
- **The virtual filesystem is a fixed set**: `/proc/self/status`, `/proc/self/maps`,
  `/proc/self/cmdline`, `/dev/urandom`, `/dev/null`. Anything else is "no such
  file", which is a signal in itself: turn `--no-vfs` on to see which read the
  code misses.
- **Remote attestation is still remote.** Play Integrity, SafetyNet, and any
  check that asks a server are not answered by emulating the client.
- **Checksums of the file itself** see the file as it is on disk. Patch first,
  then emulate, or the sum will not match.
- **Floating point on 32-bit ARM** (VFP/NEON) is not executable by Unicorn 2.1;
  use `--engine qemu` with `qemu-arm-static` and an ARM cross compiler, or
  `r2` / `disasm` there. On x86-64 and AArch64 floating point is fine, and the
  libm imports are computed rather than reported missing.

### When Unicorn is the wrong engine

Unicorn runs instructions; QEMU runs a program. For code that needs a real
loader — thread-local storage, constructors, NEON on 32-bit ARM, a call that
reaches into libc instead of through an import — `--engine qemu` starts the
function in a real process under `qemu-aarch64-static`, through a small harness
that `dlopen`s the file and `dlsym`s the symbol.

```console
$ rekit emulate libbasic-arm64.so --symbol t_hypot --args 3.0,4.0 --as-double
arch      arm64 / linux
return    0x0 (0) as double 5
calls     hypot x1

$ rekit emulate libbasic-arm64.so --symbol t_hypot --args 3.0,4.0 --as-double --engine qemu
arch      aarch64 / linux
engine    qemu (real process)
stop      returned
return    5 (as double)
env       -L /usr/aarch64-linux-gnu ~/.cache/rekit/qemu/harness64-da30b53d libbasic-arm64.so t_hypot 3 4
```

libm is answered inside Unicorn (`sqrt`, `pow`, `fmod`, `hypot`, `floor`,
`sin`, and the `f` variants), and an argument carries its kind — `3` is an
integer, `3.0` and `f:3` are doubles, `str:...` is a pointer — so a function
taking both an `int` and a `double` gets each in the register its ABI names.
What still needs the real process: VFP/NEON on 32-bit ARM, thread-local state,
constructors, and a call that reaches deep into libc instead of through an
import.

The harness is built once with `aarch64-linux-gnu-gcc` and cached in
`~/.cache/rekit/qemu` under a name that carries the hash of its source, so an
edited harness cannot leave a stale binary behind. `--sysroot` points at the
target's libc when it is not `/usr/aarch64-linux-gnu`, and `--harness` supplies
a prebuilt one. Two consequences are worth knowing before choosing it:

- **A symbol is required.** The harness looks the function up by name, because
  an address inside an unloaded shared object means nothing to `dlopen`. An
  `--address` alone is refused with that explanation rather than guessed at.
- **Only numbers cross.** A string argument would need an address in the guest,
  and inventing one gives a confident wrong answer, so string arguments are
  listed as ignored. Pass the pointer yourself if you need one.

### Native methods: a JNIEnv without a JVM

An Android library's exports are mostly `Java_...` functions whose first
argument is a `JNIEnv*`, and that argument is the whole reason they cannot be
run outside an app: `env->functions->FindClass(...)` is a load from a table
that does not exist. `emulate` supplies one, because JNI is a table of function
pointers and a table of pointers is exactly what a fake VM can hand out.

```console
$ rekit emulate libjni.so --symbol jni_probe --args env
arch      x86_64 / linux
target    jni_probe at 0x40001129
stop      returned
return    0x0 (0)
calls     GetVersion x1, FindClass x1, GetMethodID x1, NewStringUTF x1, GetStringUTFChars x1, strcmp x1, ... IsSameObject x1
note      JNIEnv at 0x31100000: JNI calls are answered (strings round-trip, no exception is pending)
```

The `env` argument is the fake environment. It is also supplied automatically
for a symbol that starts with `Java_`, since a native method always takes one —
but **only** then, or when the caller writes `env`: substituting a pointer for
every zero first argument would turn `t_abs(0)` into a large number.

What is answered with a real answer rather than a convenient zero:

| JNI call | Answer |
| --- | --- |
| `NewStringUTF` then `GetStringUTFChars` | the same text that was passed in, so a string comparison means something |
| `GetStringUTFLength`, `GetStringLength` | the length of that text |
| `ExceptionOccurred`, `ExceptionCheck` | NULL / 0 — nothing was thrown inside the emulator |
| `GetVersion` | 1.6 |
| `RegisterNatives` | `JNI_OK` |
| `FindClass`, `GetMethodID`, `NewObject` | stable pseudo-references, so identity comparisons behave |
| `Call*Method`, `Get*Field` | 0 — the Java side is not there |

The last row is the honest limit: an `int` return of 0 is plausible, an object
return of 0 is NULL, and code that dereferences it faults. That is a visible
failure rather than a plausible wrong answer, which is the trade this tool makes
everywhere else too.


### One function, many inputs

`emulate` answers one input. `fuzz` answers the range, in one process: the
binary is loaded once and the function called per value in a fresh machine, so
a function that writes to its own globals cannot taint the next input.

```console
$ rekit fuzz libfuzz.so --symbol step --mode sweep --start 0 --end 30 --step 5
fuzz  mode sweep  step at 0x40001109
x86_64/linux  range 0..30 step 5
runs: 7
distinct returns: 3
             0: 2 values, 0..5
             1: 2 values, 10..15
             2: 3 values, 20..30
transitions:
  input 5 -> 10: return 0 -> 1
  input 15 -> 20: return 1 -> 2
```

Four modes, one question each:

| Mode | Question |
| --- | --- |
| `probe` | What happens for this one input? |
| `sweep` | Where does the answer change? |
| `magic` | Which input returns the value I want? `--target 1` is the keygen for a licence check. |
| `crash` | Which inputs make it fault, and at which address? |

A crash carries the access type, the address and the instruction that made it:
Unicorn's own error says only "read from unmapped memory", so a memory hook
records the rest. A run that stops without touching bad memory is reported with
the import it called instead — a stack canary that fires is `__stack_chk_fail`,
not a buffer overrun.

A sweep is the same static address called with different numbers, so a function
that no number can crash answers "nothing crashed", which is also an answer.

### Hooks: what really gets passed

Emulation is still offline. `hook` writes a Frida script that attaches to a
running process and prints the arguments and return value of the function as it
is actually called:

```console
$ rekit hook libhooklib.so --symbol hooked --mode spawn --spawn ./host
[+] hooked @ 0x7fa5886970e9
[->] hooked(a0=0x1)
[<-] hooked = 0x3
```

The generated script runs unchanged on Frida 16 and 17: 17 replaced
`Module.findExportByName` with `Module.getGlobalExportByName`, so both are
tried. `mode=spawn` drives Frida's Python API rather than its REPL, because the
REPL exits when its stdin closes and takes every message still in flight with
it — the hook attached, then printed nothing.

For a stripped binary, `--address 0x11bd` hooks by file address. The offset into
the mapped module is computed from the binary's image base, which is the part a
shared object (`0`) and a PE (`0x140000000`, or whatever its linker picked)
disagree about.

## The other half: web material

An APK is not only native code, and a target is not only an app. The same
investigation usually reaches a frontend bundle: `dist/`, `assets/`, a JS blob
pulled out of a device. That material has no sections or imports — the useful
facts are in strings, and the questions are different. Four tools answer them,
and all four take a file, a directory walked recursively, or an
`archive::inner` spec, so a bundle inside an APK needs no manual unpacking.

```console
$ rekit endpoints fixtures/web
# fixtures/web
files: 3, read: 1 KB

## URLs: 4
  //cdn.example.net/static/app.js
      fixtures/web/app.js:4 (+1)
  https://api.example.com/v2
      fixtures/web/app.js:3
  https://api.example.com/v2/login?client=web
      fixtures/web/app.js:7
  https://forms.example.com/submit
      fixtures/web/index.html:6

## Paths and API routes: 2
  /api/v2/profile
      fixtures/web/app.js:13
  /api/v2/sessions?page=1&size=20
      fixtures/web/app.js:16

## Parameters: 3
  client
      fixtures/web/app.js:7
...
```

The patterns are deliberately loose, because a minified bundle quotes strings
five ways and an exact grammar finds nothing. The junk filter is what keeps the
report readable: `/assets/logo.png` and `/favicon.ico` are not endpoints, and a
URL handed to `fetch` is listed once, as a URL, rather than again as a path.

`secrets` runs two passes: a table of about thirty credential shapes (AWS,
GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, private keys, …) and an
entropy pass over quoted strings that matched no shape at all — which is what
catches a token format nobody wrote a rule for yet.

```
$ rekit secrets fixtures/web
hits: 4 (patterns: 3, entropy: 1), values masked (reveal=true to show them)
files: 3

## critical (1)
  AWS access key ID: AKIAIO••••••••MPLE
      fixtures/web/app.js:23
      const AWS_KEY = "AKIAIO••••••••MPLE";

## medium (1)
  Password in code: hunter••••••••ter2
      fixtures/web/app.js:24
      const DB = { password: "hunter••••••••ter2" };

## low (2)
  JWT: eyJhbG••••••••sw5c
  high entropy (5.23): Zk9xS2••••••••V8cX
```

Values are masked by default, and the context line is masked with them —
printing the line unchanged would defeat the mask. `--reveal` exists for a key
that is already known dead. A value is counted once, so the token matched by the
JWT shape is not reported again by the entropy pass, and the entropy pass is
skipped entirely when the severity floor is above `low`, because it can only
ever produce lows.

`jwt` decodes, then asks what the token trusts:

```console
$ rekit jwt "$TOKEN" --secret your-256-bit-secret
## Claims
  issued: 2018-01-18T01:30:22Z (expired 3222.6 days ago)
  sub: 1234567890

## Signature
  the signature matches this secret

## What to look at
  - HS256 — a symmetric secret, so it can be guessed from a wordlist (see wordlist)
```

`alg=none`, `jku`/`x5u` pointing at someone else's key set, and a `kid` that
looks like path traversal are reported as warnings, because those are the shapes
that turn a token into an authentication bypass. `--wordlist` tries an HS256/384/512
secret against a list and says how many words it got through; the HMAC is twenty
lines over `sha2`, so no dependency tree arrives for one function.

`http` is the request a plain fetch cannot make: a POST with a JSON body, someone
else's cookie, a proxy to the staging host, a redirect left unfollowed.

```console
$ rekit http https://api.example.com/v2/login --method POST --json '{"user":"a","pass":"b"}'
# POST https://api.example.com/v2/login
## Response
  200  126 B  31 ms

## Headers
HTTP/1.1 200 OK
  Content-Type: application/json
...
## Repeat
curl -i -X POST -H 'Content-Type: application/json' --data '{"user":"a","pass":"b"}' -L 'https://api.example.com/v2/login'
```

It shells out to `curl` rather than linking a TLS stack: HTTPS in-process would
add a large dependency tree to a tool whose point is one static binary, and
`curl` is on every machine that would run this. Only `http://` and `https://`
are accepted (`file://` and `gopher://` are refused before curl sees them), a
header containing a newline is rejected instead of used to smuggle a second
request, and the printed status is the one that was actually returned, with the
redirect target named when there was one.

These four are English like the rest of the output; the old plugin's Russian
wording was translated so the reports read consistently.

## A browser, for what the bundle cannot say

Static analysis says an endpoint exists in the code. It cannot say which request
fires on load, with which cookie, and what came back. That difference is where an
access-control bug lives, so `browser` drives a real headless Chrome over the
DevTools protocol:

```console
$ rekit browser https://app.example.com --action snapshot --output shot.png
title     Sign in
url       https://app.example.com/login?next=/dash
shot      shot.png

text
  Sign in to continue
  Email  Password  Continue

requests
  GET     200     12 kB Document  https://app.example.com/login?next=/dash
  POST    401      211 B Fetch     https://app.example.com/api/v2/session
  GET     200      38 kB Script    https://app.example.com/static/app.js
```

Every action is one call: `text`, `dom`/`html`, `title`, `eval` (run JS),
`requests`, `console`, `cookies`, `set-cookie`, `links`, `storage`, `screenshot`,
`pdf`, `click`, `fill`, `wait`, `snapshot`. `snapshot` is the summary — title,
text, screenshot and the first requests — and is usually the one to start with.
`--filter login` narrows `requests`, `console` and `links` to rows containing
that text (case-insensitive), which is how a page with forty scripts stays
readable. `click` and `fill` take a `--js` that runs *after* the interaction, so
the answer to "what changed" is in the same call:

```console
$ rekit browser https://app.example.com --action click --selector '#login' --js 'location.pathname'
/dash
```

Headers, cookies and a user agent can be set before the page loads, which is how
a request is repeated with the token a bundle hardcoded:

```console
$ rekit browser https://app.example.com --action eval \
    --header 'Authorization: Bearer eyJ…' --cookie 'sid=abc; domain=app.example.com' \
    --js 'fetch("/api/v2/me").then(r => r.text())'
```

The browser is started with a throwaway profile under `~/.cache/rekit/chrome`,
on a port it picks itself, and is killed on the way out — a page never sees the
user's cookies, and nothing is left behind. `--headed` shows the window for the
cases where a screenshot is not enough; `--cdp-url 9222` (or a full `ws://` url)
attaches to a browser that is already running and leaves it running afterwards,
which is the way to drive a multi-step flow across calls. `--keep-profile` keeps
the profile for inspection, and `--ignore-cert` accepts a staging certificate.

There is no WebSocket library and no async runtime: CDP is a handful of masked
frames over TCP on `127.0.0.1`, so the client is about three hundred lines and
the binary stays one file. Dialogs (`alert`, `confirm`) are accepted
automatically — a page that greets you with `alert("debugger")` would otherwise
block the renderer forever.

What it does not do: Firefox (no CDP), TLS to a remote DevTools endpoint
(`wss://` is refused), and it cannot see requests made before it attached.
A page that keeps a connection open never fires `load`; that is reported as a
timeout after the DOM is still read, rather than as a failure.

## Memory dumps

A disk image and a RAM image answer different questions: the disk says what was
installed, the RAM says what was running, what it was connected to, and what
was typed. `memdump` drives [volatility3](https://github.com/volatilityfoundation/volatility3)
over an image, so those questions are one call each.

volatility3 is a Python package, and its `vol` command is the part that breaks:
a pipx shim carries an absolute shebang, and when the venv moves the shim
survives and still fails, which looks exactly like "installed". So the
interpreter is found by asking it to `import volatility3` — `$REKIT_VOL_PYTHON`,
then the pipx and uv venvs, then `python3` — and the package is entered through
`volatility3.cli.main`, because it ships no usable `__main__`.

```console
$ rekit memdump mem.raw
dump: mem.raw
plugins: 181

  windows.amcache.Amcache               Extract information on executed applications from the AmCache (deprecated).
  windows.bigpools.BigPools             List big page pools.
  windows.callbacks.Callbacks           Lists kernel callbacks and notification routines.
  ...

common plugins:
  windows.info                          which build this dump is from
  windows.pslist                        processes
  windows.pstree                        process tree
  windows.netscan                       sockets and connections
  windows.cmdline                       command lines of running processes
  windows.filescan                      file objects in memory
  windows.registry.hivelist             registry hives
  linux.pslist                          processes
  linux.bash                            shell history
  linux.netscan                         sockets and connections

pass plugin=windows.pslist (and args="--pid 1234") to run one; the short form of a name is enough
```

The plugin list is the one thing volatility prints only inside its `--help`
text, so it is parsed from there: descriptions that wrap are joined back, and
the OS plugins are moved above the framework's own. `filter` narrows it by
regex when you know roughly what you want.

```console
$ rekit memdump mem.raw --plugin windows.pslist --args "--pid 1234"
volatility3 windows.pslist — mem.raw
Volatility 3 Framework 2.28.0
PID    PPID   ImageFileName   Offset(V) ...
```

Analysis runs with `--offline`: symbol tables are normally fetched over the
network when one is missing, and a download that takes minutes is
indistinguishable from a hang from the caller's side. Symbols have to be
present already (`-s`, or a `symbols/` directory next to the dump). An image
volatility cannot identify — a truncated dump, or a random file — answers with
its own requirement text rather than a guess, which is the honest result:

```
Unsatisfied requirement plugins.PsList.kernel.layer_name:
A translation layer requirement was not fulfilled.  Please verify that:
        A file was provided to create this layer (by -f, --single-location or by config)
        The file is a valid memory image and was acquired cleanly
```

A dump can come out of an archive like any other path, so
`evidence.zip::mem.raw` works, and the header says where it came from.

## What it does not do yet

Honest scope for `0.1`.

- **Formats are parsed in Rust**: ELF, PE, Mach-O, zip, tar.gz, gz, Android
  binary XML, plus magic-byte detection for DEX, JAR, APK, wasm, PDF, SQLite and
  Android boot images. Nothing is executed and no external tool is needed.
- **Disassembly, decompilation, carving, hooks, HTTP and memory are wrappers**
  around `llvm-objdump`, `r2`, `jadx`, `apktool`, `binwalk`, Ghidra, IDA,
  `ilspycmd`, `javap`, `frida`, `curl`, Chrome and volatility3. `doctor` reports
  what is missing instead of failing later.
- `--engine qemu` is a wrapper too, around qemu-user-static and a
  cross-compiled harness; it runs one function, not the program.
- `endpoints`, `secrets`, `jwt` and the DevTools client are pure Rust: no
  external library, no TLS stack. Only `http` and `browser` leave the machine,
  and only to the URL they were given.
- DEX, JVM and .NET get format detection and offsets, not structure: use
  `decompile`, `javap` or `dotnet` for the readable view.
- `ar`/`deb` payloads are recognised but not unpacked.
- No unpacking of VMProtect/Themida. `rekit` tells you a binary is packed; it
  does not defeat the packer.
- Emulation is function level, not program level: `emulate` and `fuzz` call the
  function you name. `hook` runs the whole program, but only through Frida, and
  only on the host it runs on.
- JNI is answered, not executed: the environment is a table of pointers, so
  string round-trips and exception checks are real, but `Call*Method` returns 0
  because there is no Java object behind the reference.
- `endpoints` and `secrets` read text: a route found in a bundle is not proof
  that it exists, and a key is reported by its shape — a high-entropy string
  that is really a hash, or a live key that matches no known shape, can still be
  wrong. `browser` answers the behavioural question, but one call is one page
  load: a flow that spans several pages needs `--cdp-url` to attach and drive it
  across calls.
- `memdump` needs volatility3 and the symbol table for the image's kernel. It
  is a wrapper, not a parser: an image volatility cannot identify gets its
  requirement text back, and no attempt is made to guess a profile.

Next on the list: program-level emulation, so a binary can be run until a
specific branch instead of only one function at a time.

## Development

```sh
cargo test          # unit tests, no fixtures needed
cargo clippy --all-targets
cargo build --release
```

Tests are deliberately built on generated input, so `cargo test` works on a
fresh clone with no samples.

## License

`rekit` core, CLI, MCP server and the web crate are **MIT**. See
[LICENSE](LICENSE).

`rekit-emu` is a separate binary under **GPL-2.0** (`crates/rekit-emu/LICENSE`),
because it links [Unicorn](https://www.unicorn-engine.org/), which is GPL-2.0.
Keeping emulation in its own process is deliberate: the MIT part never links
GPL code, and the GPL part never gets in the way of using `rekit` itself.

If you redistribute both together, the combined distribution has to satisfy
both licenses — GPL-2.0 for `rekit-emu`, MIT for the rest.
