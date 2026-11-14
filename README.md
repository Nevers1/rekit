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
`binwalk`, `emulate`, `emulate_list`, `fuzz`, `hook` and `doctor`; clients prefix
them with the server name, so the agent sees `rekit_info`.

The server also ships usage instructions in the `initialize` response, so the
model learns `path::inner` and the `grep` pattern syntax without you writing a
paragraph in the system prompt.

## Tools

| Tool | Question it answers |
| --- | --- |
| `info` | What format, arch, bitness, entry point, sections, entropy per section? What next? |
| `strings` | What printable text is in here (ASCII and UTF-16LE), at which offsets? |
| `grep` | Where are these bytes? Hex, `"quoted text"` or a word. |
| `hex` | Hex dump of a range, to verify bytes before patching. |
| `entropy` | Is it packed? Which protector? Any RWX or high-entropy code? |
| `imports` | What can it do — imported symbols with their library. |
| `exports` | What does it offer — exported symbols with addresses. |
| `antidebug` | Is it fighting analysis? Scored verdict, not a wall of matches. |
| `scan` | Crypto constants (AES S-box, SHA-256 K, ChaCha sigma) and imports grouped into anti/crypto/net/mem/priv. |
| `archive` | What is inside this APK/JAR/zip/tar.gz, so I can pick a `path::inner`. |
| `manifest` | The decoded `AndroidManifest.xml` of an APK: package, version, permissions, exported components. No apktool, no unpacking. |
| `apktool` | The whole package decoded: readable manifest, `res/values`, layouts, smali. Cached, and searchable by `pattern`. |
| `resources` | What an APK's zip holds — resource groups, layouts, drawables, assets — and one named XML decoded in place. |
| `decompile` | jadx to Java, cached. Lists classes, or returns one class source by name. |
| `javap` | JVM bytecode with the constant pool, for a `.class` or a class inside a jar. |
| `dotnet` | A .NET assembly to exact C# through `ilspycmd`: list types, or decompile one. |
| `ghidra` | Native code to C through Ghidra headless, analysed once and reopened from its project. |
| `ida` | The same for IDA's Hex-Rays, through `idalib` and a cached `.i64`. |
| `disasm` | Disassembly by symbol or address range (llvm-objdump, objdump fallback). |
| `r2` | One r2 shot: functions, `aflj`, pseudo-C, xrefs, imports, sections. |
| `asm` | Assemble instructions to bytes, or write them in after `expect` matches. |
| `diff` | What changed between two versions: functions added, removed, modified. |
| `patch` | Write bytes at an offset, but only after `expect` matches what is already there. |
| `binwalk` | Embedded files and firmware signatures, optionally carved out. |
| `emulate_list` | Which functions can be called, with addresses and architecture. |
| `emulate` | Run one function in a sandboxed CPU and get the real return value — through the anti-debug checks. |
| `fuzz` | The same call over a range of inputs: where the return changes, which input is the key, which one crashes. |
| `hook` | A Frida script that logs a function's real arguments and return value; optionally runs the process. |
| `doctor` | Which external tools exist and their versions, so a missing dependency is explained. |

## CLI

Same tools, same output:

```sh
rekit info app.apk::lib/arm64-v8a/libnative.so
rekit archive app.apk
rekit strings libnative.so --min 6 --filter http --limit 50
rekit grep libnative.so -- 'de ad be ef'
rekit hex libnative.so --offset 0x2a8 --length 64
rekit antidebug libnative.so
rekit scan libnative.so --kind apis
rekit imports libnative.so --limit 20
rekit manifest app.apk::AndroidManifest.xml
rekit decompile app.apk --class com.example.MainActivity
rekit disasm libnative.so --symbol JNI_OnLoad
rekit r2 libnative.so --kind pdc --target entry0
rekit patch libnative.so --offset 0x2a8 --bytes "90 90" --expect "f3 0f"
rekit binwalk firmware.bin --extract
rekit emulate libnative.so --symbol check_license --args 'str:"AAAA-BBBB"'
rekit emulate-list libnative.so --filter check
rekit fuzz libnative.so --symbol check_license --mode magic --start 0 --end 65535 --target 1
rekit hook libnative.so --symbol check_license --mode spawn --spawn ./app
rekit ghidra libnative.so --symbol JNI_OnLoad
rekit ida libnative.so --symbol JNI_OnLoad
rekit dotnet tool.dll --type Demo.Checker
rekit javap classes --class com.example.Foo
rekit apktool app.apk --pattern "https://"
rekit asm "mov eax, 1; ret" --path libnative.so --patch --offset 0x2a8 --expect "f3 0f"
rekit diff old.so new.so
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

The same works for AArch64, ARM and 32-bit PE. `--as-double` reads the result
from the floating point register instead of the general purpose one.

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
  use `r2` or `disasm` there.


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

## What it does not do yet

Honest scope for `0.1`.

- **Formats are parsed in Rust**: ELF, PE, Mach-O, zip, tar.gz, gz, Android
  binary XML, plus magic-byte detection for DEX, JAR, APK, wasm, PDF, SQLite and
  Android boot images. Nothing is executed and no external tool is needed.
- **Disassembly, decompilation, carving and hooks are wrappers** around
  `llvm-objdump`, `r2`, `jadx`, `apktool`, `binwalk`, Ghidra, IDA, `ilspycmd`,
  `javap` and `frida`. `doctor` reports what is missing instead of failing
  later.
- DEX, JVM and .NET get format detection and offsets, not structure: use
  `decompile`, `javap` or `dotnet` for the readable view.
- `ar`/`deb` payloads are recognised but not unpacked.
- No unpacking of VMProtect/Themida. `rekit` tells you a binary is packed; it
  does not defeat the packer.
- Emulation is function level, not program level: `emulate` and `fuzz` call the
  function you name. `hook` runs the whole program, but only through Frida, and
  only on the host it runs on.
- JNI is not emulated: a function that expects a real `JNIEnv` gets none, so
  native code calling back into Java faults instead of answering.

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

`rekit` core, CLI and MCP server are **MIT**. See [LICENSE](LICENSE).

`rekit-emu` is a separate binary under **GPL-2.0** (`crates/rekit-emu/LICENSE`),
because it links [Unicorn](https://www.unicorn-engine.org/), which is GPL-2.0.
Keeping emulation in its own process is deliberate: the MIT part never links
GPL code, and the GPL part never gets in the way of using `rekit` itself.

If you redistribute both together, the combined distribution has to satisfy
both licenses — GPL-2.0 for `rekit-emu`, MIT for the rest.
