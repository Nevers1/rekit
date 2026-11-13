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

Or from a checkout:

```sh
cargo install --path crates/rekit-cli
```

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

Tools are named `info`, `strings`, `grep`, `hex`, `entropy`, `imports`,
`exports`, `antidebug`, `scan`, `archive`, `manifest`, `decompile`, `disasm`,
`r2`, `patch`, `binwalk` and `doctor`; clients prefix them with the server
name, so the agent sees `rekit_info`.

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
| `decompile` | jadx to Java, cached. Lists classes, or returns one class source by name. |
| `disasm` | Disassembly by symbol or address range (llvm-objdump, objdump fallback). |
| `r2` | One r2 shot: functions, `aflj`, pseudo-C, xrefs, imports, sections. |
| `patch` | Write bytes at an offset, but only after `expect` matches what is already there. |
| `binwalk` | Embedded files and firmware signatures, optionally carved out. |
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

## What it does not do yet

Honest scope for `0.1`: everything here is static.

- **Formats are parsed in Rust**: ELF, PE, Mach-O, zip, tar.gz, gz, Android
  binary XML, plus magic-byte detection for DEX, JAR, APK, wasm, PDF, SQLite and
  Android boot images. Nothing is executed and no external tool is needed.
- **Disassembly, decompilation and carving are wrappers** around `llvm-objdump`,
  `r2`, `jadx`, `apktool`, `binwalk`, `frida` and `vol`. `doctor` reports what is
  missing instead of failing later.
- DEX, JVM and .NET get format detection and offsets, not structure: use
  `decompile` (jadx) or `ilspycmd` for the decompiled view. `ilspycmd` is not
  installed here, so `doctor` marks it missing.
- `ar`/`deb` payloads are recognised but not unpacked.
- No emulation, no unpacking of VMProtect/Themida. `rekit` tells you a binary is
  packed; it does not defeat the packer.

The next step is emulation with a virtualized environment, so an agent can run a
function behind an anti-debug check and get the real return value.

## Development

```sh
cargo test          # unit tests, no fixtures needed
cargo clippy --all-targets
cargo build --release
```

Tests are deliberately built on generated input, so `cargo test` works on a
fresh clone with no samples.

## License

MIT. See [LICENSE](LICENSE).
