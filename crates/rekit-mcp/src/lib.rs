//! rekit-mcp — a Model Context Protocol server over stdio.
//!
//! The transport is deliberately hand written: MCP is a line oriented
//! JSON-RPC 2.0 conversation, and keeping it here means no SDK version drift
//! and no dependency beyond `serde_json`.
//!
//! Tool names are bare (`info`, `strings`, ...). A client prefixes them with
//! the server name, so in OpenCode they show up as `rekit_info`, `rekit_strings`.

// The catalogue is one `json!` literal per tool inside one array, and the
// macro expands recursively: the default limit of 128 is not enough for
// thirty-three schemas.
#![recursion_limit = "512"]

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

use rekit_core as core;
use rekit_web as web;

/// Injected into the agent's system prompt by clients that support it.
pub const INSTRUCTIONS: &str = "\
rekit analyzes binaries. Every path argument accepts `path::inner` to reach a \
file inside an archive, for example `app.apk::lib/arm64-v8a/libnative.so` or \
`firmware.bin::rootfs.tar.gz::bin/busybox`. Prefer `info` first: it tells the \
format, architecture and whether the file is packed. `grep` searches raw bytes \
and accepts `\"text\"` or hex such as `de ad be ef`. Start with a small `limit` \
and raise it only when needed. For Android, `manifest` decodes binary XML in \
place and `decompile` runs jadx; `disasm`, `r2`, `binwalk` and `patch` need the \
external tools that `doctor` lists. `patch` always requires `expect`. For web \
material, `endpoints`, `secrets`, `jwt` and `http` take the same `::` spec, so a \
bundle inside an APK needs no unpacking; `secrets` masks values unless `reveal` \
is set. `emulate` runs one function: arguments are numbers or `str:\"text\"`, `env` \
passes the fake JNIEnv, and `engine=qemu` runs a real ARM process when Unicorn \
cannot execute the code (AArch64 floating point, TLS, constructors).";

/// Start serving on stdin/stdout. Returns when the client closes the pipe.
pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(err) => {
                emit(
                    &mut stdout,
                    json!({"jsonrpc": "2.0", "id": Value::Null,
                           "error": {"code": -32700, "message": err.to_string()}}),
                );
                continue;
            }
        };

        // Notifications carry no id and expect no answer.
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let response = match method {
            "initialize" => {
                let protocol = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2025-06-18")
                    .to_string();
                Ok(json!({
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "rekit", "version": core::VERSION},
                    "instructions": INSTRUCTIONS
                }))
            }
            "tools/list" => Ok(json!({ "tools": tools() })),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                match call_tool(name, &args) {
                    Ok(text) => Ok(json!({
                        "content": [{"type": "text", "text": text}],
                        "isError": false
                    })),
                    // A tool failure is content, not a protocol error: the agent
                    // must be able to read the message and try something else.
                    Err(err) => Ok(json!({
                        "content": [{"type": "text", "text": format!("error: {err}")}],
                        "isError": true
                    })),
                }
            }
            "resources/list" => Ok(json!({ "resources": [] })),
            "prompts/list" => Ok(json!({ "prompts": [] })),
            "ping" => Ok(json!({})),
            other => Err(anyhow!("unknown method {other}")),
        };

        match response {
            Ok(result) => emit(
                &mut stdout,
                json!({"jsonrpc": "2.0", "id": id, "result": result}),
            ),
            Err(err) => emit(
                &mut stdout,
                json!({"jsonrpc": "2.0", "id": id,
                       "error": {"code": -32601, "message": err.to_string()}}),
            ),
        }
    }
    Ok(())
}

fn emit(out: &mut impl Write, value: Value) {
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": properties, "required": required})
}

/// Tool catalogue. Descriptions are written for a reader that has never seen a
/// binary parser: say what the tool answers, not how it works.
pub fn tools() -> Value {
    json!([
        {
            "name": "info",
            "description": "Format, architecture, bitness, entry point, sections with per-file entropy, and next-step hints for a PE/ELF/Mach-O file or an archive (APK, JAR, zip, tar.gz). Call this before anything else.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "file path, may contain path::inner"}
            }), &["path"])
        },
        {
            "name": "strings",
            "description": "Printable strings from a binary, ASCII and UTF-16LE, with file offsets. Filtering is case-insensitive substring.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "min": {"type": "integer", "description": "minimum length, default 4"},
                "filter": {"type": "string", "description": "case-insensitive substring"},
                "limit": {"type": "integer", "description": "default 200"}
            }), &["path"])
        },
        {
            "name": "grep",
            "description": "Search a file two ways. mode=bytes (default) answers \"where are these bytes\": hex (`de ad be ef`), a quoted literal (`\"BuildConfig\"`) or a plain word, with offsets and ASCII context — right for binaries. mode=text answers \"which line says this\": line numbers with surrounding lines, regex and case folding — right for jadx output, smali, JS and strings dumps.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "pattern": {"type": "string"},
                "mode": {"type": "string", "enum": ["bytes", "text"], "description": "default bytes"},
                "regex": {"type": "boolean", "description": "mode=text: treat the pattern as a regex"},
                "ignore_case": {"type": "boolean", "description": "ignore case, both modes"},
                "limit": {"type": "integer", "description": "default 50"},
                "context": {"type": "integer", "description": "bytes around each hit (bytes mode) or lines around it (text mode), default 16 / 2"}
            }), &["path", "pattern"])
        },
        {
            "name": "hex",
            "description": "Hex dump of a byte range with ASCII column, like xxd. Use it to verify bytes before patching. With `bytes` it instead hunts that signature, lists the offsets and dumps the first hit.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "offset": {"type": "integer", "description": "decimal or 0x-prefixed, default 0"},
                "length": {"type": "integer", "description": "default 256, max 8192"},
                "bytes": {"type": "string", "description": "signature to look for instead, hex '4d5a9000' or \"MZ\""},
                "limit": {"type": "integer", "description": "with bytes: how many offsets to list, default 50"}
            }), &["path"])
        },
        {
            "name": "entropy",
            "description": "Shannon entropy per section plus packer fingerprints (UPX, VMProtect, Themida, Enigma, ASPack, MPRESS, ConfuserEx, .NET Reactor) and layout anomalies such as RWX sections or executable high-entropy code.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "limit": {"type": "integer", "description": "how many sections to print, default 20"}
            }), &["path"])
        },
        {
            "name": "imports",
            "description": "Imported symbols with the library they come from. The quickest way to see what a binary can actually do.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "filter": {"type": "string", "description": "case-insensitive substring of the name, applied before the limit"},
                "limit": {"type": "integer", "description": "default 200"}
            }), &["path"])
        },
        {
            "name": "exports",
            "description": "Exported symbols with addresses, for shared libraries and DLLs. An archive is answered with its entry list instead, so an APK does not come back as \"not a binary\".",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "filter": {"type": "string", "description": "case-insensitive substring of the name, applied before the limit"},
                "limit": {"type": "integer", "description": "default 200"}
            }), &["path"])
        },
        {
            "name": "antidebug",
            "description": "Static anti-debug and anti-tamper signals: suspicious imports (ptrace, IsDebuggerPresent, NtQueryInformationProcess, __system_property_get) and strings (TracerPid, frida, xposed, magisk, goldfish), with a score and verdict.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "limit": {"type": "integer", "description": "how many findings per group, default 60"}
            }), &["path"])
        },
        {
            "name": "scan",
            "description": "Three scans in one, no decompilation needed. kind=const: with `value` it finds where your constant sits in the code (both byte orders, naming the function when rabin2 knows one), without it it reports known crypto constants (AES S-box, SHA-256 K, ChaCha sigma, Base64 alphabet). kind=apis groups imports into anti/crypto/net/mem/file/procmem/ui/priv/other. kind=probe calls every exported function once with a trial argument and shows which return something — the quickest way to find where the interesting code is. kind=all does const and apis.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "kind": {"type": "string", "enum": ["const", "apis", "probe", "all"], "description": "default apis"},
                "value": {"type": "string", "description": "kind=const: the constant to find, e.g. 0xDEADBEEF, 1234 or 0x5A,0x5B"},
                "width": {"type": "integer", "description": "kind=const: how many bytes the constant occupies, default 4"},
                "category": {"type": "string", "description": "kind=apis: only this group (anti, crypto, net, mem, file, procmem, ui, priv)"},
                "arg": {"type": "string", "description": "kind=probe: trial argument, default 1"},
                "limit": {"type": "integer", "description": "default 60"},
                "json": {"type": "boolean", "description": "kind=probe: print the emulator's own JSON"}
            }), &["path"])
        },
        {
            "name": "archive",
            "description": "List members of an archive (APK, JAR, zip, tar.gz) with sizes. Use it to pick the `path::inner` you want before calling info.",
            "inputSchema": schema(json!({
                "path": {"type": "string"}
            }), &["path"])
        },
        {
            "name": "disasm",
            "description": "Disassemble a function or an address range with llvm-objdump (objdump as fallback). Give `symbol`, or `address` plus `length`, or neither to start at the entry point.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "symbol": {"type": "string", "description": "function name exported by the binary"},
                "address": {"type": "string", "description": "hex start address, e.g. 0x4010 or 4192"},
                "length": {"type": "integer", "description": "bytes to disassemble when address is given, default 256"}
            }), &["path"])
        },
        {
            "name": "r2",
            "description": "Radare2 one-shot analysis: kind=functions (list), json (aflj), pdc (pseudo-C of `target`), xrefs (who calls `target`), imports, sections.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "kind": {"type": "string", "enum": ["functions", "json", "pdc", "xrefs", "imports", "sections"], "description": "default functions"},
                "target": {"type": "string", "description": "symbol or address for pdc/xrefs, default entry0"}
            }), &["path"])
        },
        {
            "name": "decompile",
            "description": "Decompile a dex/apk to Java with jadx (cached). Without `class` or `pattern` it lists the generated files; with `class` it returns that file's source; with `pattern` it searches the whole decompiled tree by line — one call instead of decompile-then-grep.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "apk, dex, jar or a path::inner spec"},
                "class": {"type": "string", "description": "fully qualified class name, e.g. com.example.Foo"},
                "pattern": {"type": "string", "description": "search the decompiled tree for this"},
                "regex": {"type": "boolean", "description": "treat pattern as a regex"},
                "ignore_case": {"type": "boolean"},
                "limit": {"type": "integer", "description": "files to list, or matches to report; default 100"}
            }), &["path"])
        },
        {
            "name": "ghidra",
            "description": "Decompile native code (PE/ELF/Mach-O) to C with Ghidra headless. `symbol` matches a name (exact first, then partial), `address` picks a function by hex address, neither lists the functions. The project is cached per input, so the first call takes minutes and later ones seconds. reanalyze=true forces a fresh analysis.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "binary, or path::inner inside an archive"},
                "symbol": {"type": "string", "description": "function name or part of it"},
                "address": {"type": "string", "description": "hex address, e.g. 0x401010"},
                "limit": {"type": "integer", "description": "functions to decompile when matching by name, default 20"},
                "reanalyze": {"type": "boolean", "description": "ignore the cached project and analyse again"}
            }), &["path"])
        },
        {
            "name": "ida",
            "description": "Decompile native code to C with IDA and Hex-Rays (idalib) — the best quality on obfuscated code. Same symbol/address convention as `ghidra`. Needs IDA 9.x with idalib; the database is cached per input.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "symbol": {"type": "string", "description": "function name or part of it"},
                "address": {"type": "string", "description": "hex address, e.g. 0x2040"},
                "limit": {"type": "integer", "description": "functions to decompile, default 10"}
            }), &["path"])
        },
        {
            "name": "dotnet",
            "description": "Decompile a .NET assembly to C# with ilspycmd. `type` returns one type in full; `pattern` searches the decompiled tree (cached per input); neither lists the generated files. Only works on managed assemblies — a native binary gets a pointer to ghidra/ida.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "dll/exe, or app.apk::Assembly-CSharp.dll"},
                "type": {"type": "string", "description": "type name to decompile, e.g. System.Console"},
                "pattern": {"type": "string", "description": "text to search in the C# code"},
                "regex": {"type": "boolean", "description": "treat pattern as a regular expression"},
                "limit": {"type": "integer", "description": "max matches, default 60"}
            }), &["path"])
        },
        {
            "name": "javap",
            "description": "JVM bytecode with javap: signatures, constants, and with code=true the bytecode of every method. A bare .class needs no class name (it is read from the file); a jar or apk does.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": ".class, jar, or archive::entry"},
                "class": {"type": "string", "description": "fully qualified class name, e.g. com.example.Foo"},
                "method": {"type": "string", "description": "show only this method"},
                "code": {"type": "boolean", "description": "bytecode instead of signatures, default true"},
                "limit": {"type": "integer", "description": "max lines, default 200"}
            }), &["path"])
        },
        {
            "name": "manifest",
            "description": "Decode AndroidManifest.xml from an APK (binary AXML) into readable XML in place, without apktool. Plain text manifests pass through.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "AndroidManifest.xml or app.apk::AndroidManifest.xml"}
            }), &["path"])
        },
        {
            "name": "apktool",
            "description": "Decode an APK into smali, resources and a readable AndroidManifest with apktool. `pattern` searches the decoded tree (file:line:text) and the cache path can be handed to `grep`. The decode is cached per APK, so only the first call is slow.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "path to .apk"},
                "pattern": {"type": "string", "description": "text to search in the decoded apk"},
                "limit": {"type": "integer", "description": "max matches, default 60"}
            }), &["path"])
        },
        {
            "name": "resources",
            "description": "What is inside an APK's zip: resource groups and counts, layouts, drawables, assets, XML. `kind` picks a group and `name` filters it; naming one XML returns it decoded. Cheaper than a full apktool decode.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": ".apk"},
                "kind": {"type": "string", "enum": ["list", "strings", "layout", "drawable", "asset", "xml"], "description": "default list"},
                "name": {"type": "string", "description": "resource name filter, e.g. app_name or activity_main"}
            }), &["path"])
        },
        {
            "name": "binwalk",
            "description": "Map embedded files and firmware signatures (binwalk). extract=true unwraps them into the rekit cache and lists what came out; signatures narrows the scan to the types you care about.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "extract": {"type": "boolean", "description": "default false"},
                "signatures": {"type": "string", "description": "comma separated file types to look for only, e.g. 'png,zip,exe'"},
                "limit": {"type": "integer", "description": "how many rows of the map to print, default 120"}
            }), &["path"])
        },
        {
            "name": "patch",
            "description": "Write bytes into a file at an offset. `expect` is mandatory and must equal what is currently there: a mismatch aborts and reports the real bytes. A copy of the file is kept in the rekit cache first (backup=false skips that), and afterwards rabin2 is asked whether the file still parses. Use hex with `hex` first.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "offset": {"type": "string", "description": "hex or decimal offset"},
                "bytes": {"type": "string", "description": "hex bytes to write, e.g. '90 90'"},
                "string": {"type": "string", "description": "alternative to bytes: text, written with a trailing NUL"},
                "nop": {"type": "integer", "description": "alternative to bytes: how many 0x90 bytes to write"},
                "expect": {"type": "string", "description": "hex bytes that must be present now, same length as the patch"},
                "backup": {"type": "boolean", "description": "copy the file to the cache first (default true)"}
            }), &["path", "offset", "expect"])
        },
        {
            "name": "emulate",
            "description": "Actually execute one function from a PE/ELF/Mach-O in a sandboxed CPU and report what it returns. This is the only tool that gives facts instead of guesses about obfuscated licence, password, integrity and anti-debug checks: ptrace returns 0, TracerPid is 0, no debugger is present, time advances, random bytes look real. Call `emulate_list` first when you do not know the function name. Arguments go in a string: numbers may be hex, strings are written str:\"text\" with quotes when they contain commas, and `env` passes the fake JNIEnv (supplied automatically for a symbol starting with Java_). engine=qemu runs the function in a real process instead, which is the only way to run AArch64 floating point, TLS and constructors, but it needs a symbol and takes numbers only.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "file path; archive members must be extracted first, so pass a real file"},
                "symbol": {"type": "string", "description": "exported function name"},
                "address": {"type": "string", "description": "hex address to call instead of a name"},
                "entry": {"type": "boolean", "description": "call the binary entry point"},
                "args": {"type": "string", "description": "comma separated: 1,0x20,str:\"hello, world\""},
                "max_insns": {"type": "integer", "description": "instruction budget, default 2000000"},
                "timeout_ms": {"type": "integer", "description": "wall clock budget, default 10000"},
                "vfs": {"type": "boolean", "description": "answer file reads with a fake /proc and /dev (default true); turn off to see what the code complains about"},
                "as_double": {"type": "boolean", "description": "read the result from the floating point register"},
                "thumb": {"type": "boolean", "description": "target is Thumb code (ARM only)"},
                "engine": {"type": "string", "enum": ["unicorn", "qemu"], "description": "unicorn (default) executes the code in a sandbox; qemu runs a real process, which is the only way to run AArch64 floating point, TLS and constructors"},
                "sysroot": {"type": "string", "description": "qemu: target sysroot for the dynamic loader, e.g. /usr/aarch64-linux-gnu"},
                "harness": {"type": "string", "description": "qemu: a prebuilt harness instead of the cached one"},
                "regs": {"type": "string", "description": "registers to report after the run, e.g. 'rax,rdi' or 'x0,x1'"},
                "read_ranges": {"type": "string", "description": "memory to read back after the run: 'addr:size:label', comma separated. This is how you see what the function decrypted into a buffer"},
                "trace": {"type": "boolean", "description": "record executed instructions and show the first 24 disassembled; use it to see where a check actually goes"},
                "stubs": {"type": "string", "description": "answer an address with an import call: '0x401040=strlen' or '0x401040=strlen:32' to force the value. Lets a static binary be emulated without its import table"},
                "json": {"type": "boolean", "description": "return the raw report instead of a summary"}
            }), &["path"])
        },
        {
            "name": "hook",
            "description": "Generate a Frida script that logs the arguments and return value of a native function when it is actually called — the one thing static analysis cannot tell you. mode=gen prints the script (Frida 16 and 17 compatible); mode=spawn writes it and runs a local command under Frida, returning what it printed.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "binary, so the generator can see its arch, exports and image base"},
                "symbol": {"type": "string", "description": "exported function to hook"},
                "address": {"type": "string", "description": "hex file address instead of a name (for stripped binaries)"},
                "module": {"type": "string", "description": "module name as Frida sees it; defaults to the file name"},
                "args": {"type": "integer", "description": "how many arguments to log, default 4"},
                "onEnter": {"type": "string", "description": "extra JS to run in onEnter"},
                "onLeave": {"type": "string", "description": "extra JS to run in onLeave"},
                "mode": {"type": "string", "enum": ["gen", "spawn"], "description": "default gen"},
                "spawn": {"type": "string", "description": "spawn: the command to start, e.g. /usr/bin/app --flag"}
            }), &["symbol"])
        },
        {
            "name": "fuzz",
            "description": "Run one function over many inputs in the emulator. probe explains a single call; sweep calls it once per value and reports where the return changes (the thresholds); magic finds the input that returns a chosen value, which is a keygen for licence checks; crash finds inputs that make it fault, with the address it touched. Much stronger than guessing from decompiled code.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "file path; archive members must be extracted first"},
                "symbol": {"type": "string", "description": "function to call"},
                "address": {"type": "string", "description": "hex address instead of a name"},
                "mode": {"type": "string", "enum": ["probe", "sweep", "magic", "crash"], "description": "default probe"},
                "args": {"type": "string", "description": "probe: arguments for one call, e.g. 42 or str:hello"},
                "start": {"type": "integer", "description": "first value, may be negative (default 0)"},
                "end": {"type": "integer", "description": "last value, inclusive (default 4096)"},
                "step": {"type": "integer", "description": "step between values (default 1)"},
                "target": {"type": "string", "description": "magic: the return value to look for, decimal or 0x hex (default 1)"},
                "limit": {"type": "integer", "description": "max runs (default 500)"},
                "vfs": {"type": "boolean", "description": "answer file reads with a fake /proc (default true)"},
                "thumb": {"type": "boolean", "description": "target is Thumb code (ARM only)"},
                "stubs": {"type": "string", "description": "answer an address with an import call: '0x401040=strlen[:ret]'"},
                "json": {"type": "boolean", "description": "return the emulator's raw JSON"}
            }), &["path"])
        },
        {
            "name": "emulate_list",
            "description": "Functions that `emulate` can call, with addresses and the detected architecture. Use this to pick a target.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "filter": {"type": "string", "description": "substring of the name"},
                "json": {"type": "boolean"}
            }), &["path"])
        },
        {
            "name": "asm",
            "description": "Assemble instructions into machine code and optionally write them into the file. `mode=asm` returns the bytes; `mode=patch` writes them at an offset and, like `patch`, demands `expect` so a wrong offset is refused. The base address matters: `jmp 0x1005` assembles differently at 0x1000 and at 0x2000, so pass the address the code will run at. Architecture comes from `path` when given, otherwise from `arch`/`bits`.",
            "inputSchema": schema(json!({
                "code": {"type": "string", "description": "instructions separated by ';' or newlines, e.g. 'mov eax, 1; ret'"},
                "path": {"type": "string", "description": "binary to take the architecture from; required for mode=patch"},
                "arch": {"type": "string", "description": "x86 | aarch64 | arm | mips, when no path is given"},
                "bits": {"type": "integer", "description": "32 or 64, when no path is given"},
                "address": {"type": "string", "description": "assembly base address for relative jumps, default 0x1000"},
                "mode": {"type": "string", "description": "asm (bytes only) | patch (write into the file)"},
                "offset": {"type": "string", "description": "mode=patch: file offset"},
                "expect": {"type": "string", "description": "mode=patch: hex bytes that must be there now"},
                "backup": {"type": "boolean", "description": "mode=patch: copy the file to the cache first (default true)"}
            }), &["code"])
        },
        {
            "name": "diff",
            "description": "Compare two builds of the same binary: added, removed, changed and merely moved functions, plus new and gone strings. Functions are matched by name, and by instruction structure when names are stripped, so a code shift does not look like a change. Use it to answer 'what did the update actually change'.",
            "inputSchema": schema(json!({
                "old": {"type": "string"},
                "new": {"type": "string"},
                "mode": {"type": "string", "description": "summary (default) | funcs | strings | full"},
                "limit": {"type": "integer", "description": "how many lines per section, default 80"}
            }), &["old", "new"])
        },
        {
            "name": "endpoints",
            "description": "Pull every URL, absolute path, API route, query parameter and GraphQL operation out of a JS bundle, HTML page or JSON, with the file and line where each appears. The first thing to run on a frontend bundle or on an APK's assets: it answers what the app talks to without executing anything. Takes a file, a directory (walked recursively) or an archive::inner spec.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "file, directory, or apk/zip::inner"},
                "kind": {"type": "string", "enum": ["all", "url", "path", "param", "graphql"], "description": "what to look for, default all"},
                "filter": {"type": "string", "description": "regex; only matching values are kept"},
                "limit": {"type": "integer", "description": "max distinct values per group, default 300"}
            }), &["path"])
        },
        {
            "name": "secrets",
            "description": "Find keys and tokens committed by accident: AWS, GCP, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, private keys and about thirty more shapes, plus an entropy pass over quoted strings that match no shape at all. Values are masked unless reveal=true, because a report that prints a live key in full leaks it again.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "file, directory, or apk/zip::inner"},
                "minSeverity": {"type": "string", "enum": ["critical", "high", "medium", "low"], "description": "lowest severity to report, default low"},
                "entropy": {"type": "number", "description": "entropy threshold for the second pass, default 4.3; 0 disables it"},
                "reveal": {"type": "boolean", "description": "show values in full, default false"},
                "limit": {"type": "integer", "description": "max findings, default 200"}
            }), &["path"])
        },
        {
            "name": "jwt",
            "description": "Read a JWT: header, payload, claims in human terms, and what its signature actually trusts. Points out alg=none, HS* secrets worth guessing, jku/x5u pointing at someone else's key, and kid traversal. With secret it checks the signature; with wordlist it tries to crack it. Pass token for one token or path to find tokens in files.",
            "inputSchema": schema(json!({
                "token": {"type": "string", "description": "the JWT itself"},
                "path": {"type": "string", "description": "or a file/directory/archive to find tokens in"},
                "secret": {"type": "string", "description": "check the signature against this secret"},
                "wordlist": {"type": "string", "description": "wordlist to crack an HS256/384/512 secret with"},
                "limit": {"type": "integer", "description": "how many words to try, default 200000"}
            }), &[])
        },
        {
            "name": "http",
            "description": "One HTTP request with full control: method, headers, body, redirects, proxy, timeout. Prints the status, headers, body and a ready curl command for repeating it. This is the tool for the requests a plain fetch cannot make — the POST with a JSON body, the one with someone else's cookie, the one through a proxy.",
            "inputSchema": schema(json!({
                "url": {"type": "string", "description": "full http:// or https:// URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], "description": "default GET"},
                "headers": {"type": "object", "description": "headers as an object, e.g. {\"Authorization\": \"Bearer ...\"}", "additionalProperties": {"type": "string"}},
                "body": {"type": "string", "description": "request body as-is"},
                "json": {"type": "object", "description": "body as a JSON object; also sets Content-Type"},
                "redirect": {"type": "boolean", "description": "follow redirects, default true"},
                "timeout": {"type": "integer", "description": "timeout in ms, default 20000"},
                "proxy": {"type": "string", "description": "proxy, e.g. socks5://127.0.0.1:1300"},
                "save": {"type": "string", "description": "write the response body to this file"},
                "bodyOnly": {"type": "boolean", "description": "print the body alone"}
            }), &["url"])
        },
        {
            "name": "memdump",
            "description": "Analyze a memory dump through volatility3: processes, sockets, command lines, open files, registry hives, shell history. Plugins are named as volatility names them (windows.pslist, windows.netscan, linux.bash). With no plugin it lists what this dump supports. A dump can come from an archive::inner spec like any other path.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "the dump: raw, vmem, dmp, core, lmp or lime"},
                "plugin": {"type": "string", "description": "volatility3 plugin, e.g. windows.pslist"},
                "args": {"type": "string", "description": "extra plugin arguments, e.g. \"--pid 1234\""},
                "list": {"type": "boolean", "description": "list available plugins"},
                "filter": {"type": "string", "description": "regex for the plugin list"},
                "limit": {"type": "integer", "description": "max lines of output, default 120"}
            }), &["path"])
        },
        {
            "name": "doctor",
            "description": "Which external tools are installed (r2, jadx, apktool, ilspycmd, binwalk, frida, vol) and their versions. Call this when a wrapper tool reports a missing dependency.",
            "inputSchema": schema(json!({}), &[])
        }
    ])
}

pub fn call_tool(name: &str, args: &Value) -> Result<String> {
    match name {
        "info" => render_info(&str_arg(args, "path")?),
        "strings" => {
            let path = str_arg(args, "path")?;
            let min = num_arg(args, "min", 4) as usize;
            let limit = num_arg(args, "limit", 200) as usize;
            let filter = opt_str(args, "filter");
            render_strings(&path, min, filter.as_deref(), limit)
        }
        "grep" => {
            let path = str_arg(args, "path")?;
            let pattern = str_arg(args, "pattern")?;
            let limit = num_arg(args, "limit", 50) as usize;
            let regex = args.get("regex").and_then(Value::as_bool).unwrap_or(false);
            let ignore_case = args
                .get("ignore_case")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mode = match opt_str(args, "mode") {
                Some(mode) if mode == "bytes" && regex => bail!(
                    "regex only works in mode=text: bytes are bytes, and a regex over them \
                     is a different tool"
                ),
                Some(mode) => mode,
                // A regex only makes sense line by line; asking for one is an
                // unambiguous request for text mode.
                None if regex => "text".to_string(),
                None => "bytes".to_string(),
            };
            if mode == "text" {
                let context = match args.get("context") {
                    Some(Value::Null) | None => 2,
                    Some(v) => v.as_u64().unwrap_or(2) as usize,
                };
                let opts = core::search::Options {
                    regex,
                    ignore_case,
                    context,
                    limit,
                };
                core::search::text(&path, &pattern, &opts)
            } else {
                let context = match args.get("context") {
                    Some(Value::Null) | None => 16,
                    Some(v) => v.as_u64().unwrap_or(16) as usize,
                };
                render_grep(&path, &pattern, limit, context, ignore_case)
            }
        }
        "hex" => {
            let path = str_arg(args, "path")?;
            let offset = num_arg(args, "offset", 0);
            let length = (num_arg(args, "length", 256) as usize).min(8192);
            match opt_str(args, "bytes") {
                None => Ok(core::hexdump::dump(&path, offset, length)?),
                Some(needle) => {
                    let limit = (num_arg(args, "limit", 50) as usize).clamp(1, 5_000);
                    let hits = core::hexdump::find(&path, &needle, limit, 0, false)?;
                    if hits.is_empty() {
                        return Ok(format!("{needle} not found\n"));
                    }
                    let mut out = format!("{} of {needle}\n", hits.len());
                    for hit in &hits {
                        out.push_str(&format!("  0x{:08x}\n", hit.offset));
                    }
                    out.push_str(&format!(
                        "\nfirst hit, 128 bytes\n{}",
                        core::hexdump::dump(&path, hits[0].offset, 128)?
                    ));
                    Ok(out)
                }
            }
        }
        "entropy" => {
            let limit = (num_arg(args, "limit", 20) as usize).clamp(1, 1_000);
            render_entropy(&str_arg(args, "path")?, limit)
        }
        "imports" => {
            let path = str_arg(args, "path")?;
            let limit = num_arg(args, "limit", 200) as usize;
            let filter = opt_str(args, "filter");
            render_symbols(
                &core::symbols::imports(&path, limit, filter.as_deref())?,
                limit,
                &title_with_filter("imports", filter.as_deref()),
            )
        }
        "exports" => {
            let path = str_arg(args, "path")?;
            let limit = num_arg(args, "limit", 200) as usize;
            let filter = opt_str(args, "filter");
            // The plugin answered "what is in this zip" from the same tool, and
            // asking an APK for its exports is a common slip — so an archive is
            // answered as an archive instead of "not a PE/ELF/Mach-O".
            let resolved = core::resolve::resolve(&path)?;
            match core::resolve::list_entries(&resolved) {
                Ok(entries) => Ok(render_entries(&entries, filter.as_deref(), limit)),
                Err(_) => render_symbols(
                    &core::symbols::exports(&path, limit, filter.as_deref())?,
                    limit,
                    &title_with_filter("exports", filter.as_deref()),
                ),
            }
        }
        "antidebug" => {
            let limit = (num_arg(args, "limit", 60) as usize).clamp(1, 1_000);
            render_antidebug(&str_arg(args, "path")?, limit)
        }
        "scan" => {
            let path = str_arg(args, "path")?;
            let kind = opt_str(args, "kind")
                .or_else(|| opt_str(args, "mode"))
                .unwrap_or_else(|| "apis".to_string());
            let limit = (num_arg(args, "limit", 60) as usize).clamp(1, 5_000);
            match kind.as_str() {
                "const" => match opt_str(args, "value") {
                    Some(value) => {
                        let width = num_arg(args, "width", 4) as usize;
                        core::scan::const_value(&path, &value, width, limit)
                    }
                    None => render_consts(&path, limit),
                },
                "apis" => render_apis(&path, opt_str(args, "category").as_deref(), limit),
                "probe" => core::scan::probe(
                    &path,
                    &opt_str(args, "arg").unwrap_or_else(|| "1".to_string()),
                    limit,
                    args.get("json").and_then(Value::as_bool).unwrap_or(false),
                ),
                "all" => {
                    let mut out = render_consts(&path, limit)?;
                    out.push_str(&render_apis(&path, None, limit)?);
                    Ok(out)
                }
                other => bail!(
                    "unknown kind {other:?}: const (with or without value), apis, probe or all"
                ),
            }
        }
        "archive" => render_archive(&str_arg(args, "path")?),
        "disasm" => {
            let path = str_arg(args, "path")?;
            let symbol = opt_str(args, "symbol");
            let address = match args.get("address") {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_u64().or_else(|| v.as_str().and_then(parse_number)) {
                    Some(n) => Some(n),
                    None => bail!("address must be a number or a hex string"),
                },
            };
            let length = (num_arg(args, "length", 256) as usize).clamp(16, 65_536);
            core::external::disasm(&path, symbol.as_deref(), address, length)
        }
        "r2" => {
            let path = str_arg(args, "path")?;
            let kind = opt_str(args, "kind").unwrap_or_else(|| "functions".to_string());
            let target = opt_str(args, "target");
            core::external::r2(&path, &kind, target.as_deref())
        }
        "decompile" => {
            let path = str_arg(args, "path")?;
            let class = opt_str(args, "class");
            let pattern = opt_str(args, "pattern");
            let regex = args.get("regex").and_then(Value::as_bool).unwrap_or(false);
            let ignore_case = args
                .get("ignore_case")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let limit = (num_arg(args, "limit", 100) as usize).clamp(1, 5_000);
            core::external::decompile(
                &path,
                class.as_deref(),
                limit,
                pattern.as_deref(),
                regex,
                ignore_case,
            )
        }
        "ghidra" => {
            let path = str_arg(args, "path")?;
            let symbol = opt_str(args, "symbol");
            let address = opt_str(args, "address");
            let limit = (num_arg(args, "limit", 20) as usize).clamp(1, 200);
            let reanalyze = args
                .get("reanalyze")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            core::ghidra::decompile(
                &path,
                symbol.as_deref(),
                address.as_deref(),
                limit,
                reanalyze,
            )
        }
        "ida" => {
            let path = str_arg(args, "path")?;
            let symbol = opt_str(args, "symbol");
            let address = opt_str(args, "address");
            let limit = (num_arg(args, "limit", 10) as usize).clamp(1, 100);
            core::ida::decompile(&path, symbol.as_deref(), address.as_deref(), limit)
        }
        "dotnet" => {
            let path = str_arg(args, "path")?;
            let ty = opt_str(args, "type");
            let pattern = opt_str(args, "pattern");
            let regex = args.get("regex").and_then(Value::as_bool).unwrap_or(false);
            let limit = (num_arg(args, "limit", 60) as usize).clamp(1, 5_000);
            core::dotnet::decompile(&path, ty.as_deref(), pattern.as_deref(), regex, limit)
        }
        "javap" => {
            let path = str_arg(args, "path")?;
            let class = opt_str(args, "class");
            let method = opt_str(args, "method");
            let code = args.get("code").and_then(Value::as_bool).unwrap_or(true);
            let limit = (num_arg(args, "limit", 200) as usize).clamp(1, 20_000);
            core::javap::decompile(&path, class.as_deref(), method.as_deref(), code, limit)
        }
        "apktool" => {
            let path = str_arg(args, "path")?;
            let pattern = opt_str(args, "pattern");
            let limit = (num_arg(args, "limit", 60) as usize).clamp(1, 5_000);
            core::apktool::decode(&path, pattern.as_deref(), limit)
        }
        "resources" => {
            let path = str_arg(args, "path")?;
            let kind = opt_str(args, "kind").unwrap_or_else(|| "list".to_string());
            let name = opt_str(args, "name");
            core::resources::list(&path, &kind, name.as_deref())
        }
        "manifest" => core::axml::render(&str_arg(args, "path")?),
        "binwalk" => {
            let path = str_arg(args, "path")?;
            let extract = args
                .get("extract")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let signatures = opt_str(args, "signatures");
            let limit = (num_arg(args, "limit", 120) as usize).clamp(1, 5_000);
            core::external::binwalk(&path, extract, signatures.as_deref(), limit)
        }
        "patch" => {
            let path = str_arg(args, "path")?;
            let offset = match args.get("offset") {
                Some(v) => match v.as_u64().or_else(|| v.as_str().and_then(parse_number)) {
                    Some(n) => n,
                    None => bail!("offset must be a number or a hex string"),
                },
                None => bail!("missing required argument \"offset\""),
            };
            let expects = str_arg(args, "expect")?;
            let expect = core::hexdump::parse_pattern(&expects)?;
            let bytes = core::patch::payload(
                opt_str(args, "bytes").as_deref(),
                opt_str(args, "string").as_deref(),
                args.get("nop").and_then(Value::as_u64),
            )?;
            let backup = args.get("backup").and_then(Value::as_bool).unwrap_or(true);
            let res = core::patch::apply(&path, offset, &bytes, &expect, backup)?;
            let mut out = format!(
                "patched {} at 0x{:x}: {} -> {} ({} bytes)\n",
                res.path, res.offset, res.before, res.after, res.size
            );
            if let Some(backup) = &res.backup {
                out.push_str(&format!("backup: {backup}\n"));
            }
            match res.reparses {
                Some(true) => out.push_str("check: rabin2 still parses the file\n"),
                Some(false) => out.push_str(
                    "WARNING: rabin2 no longer parses the file — the header, not just \
                     the code, was probably hit\n",
                ),
                None => {}
            }
            Ok(out)
        }
        "hook" => {
            let req = core::hook::Request {
                path: opt_str(args, "path"),
                symbol: opt_str(args, "symbol"),
                address: opt_str(args, "address"),
                module: opt_str(args, "module"),
                args: num_arg(args, "args", 4) as usize,
                on_enter: opt_str(args, "onEnter"),
                on_leave: opt_str(args, "onLeave"),
                mode: opt_str(args, "mode").unwrap_or_else(|| "gen".to_string()),
                spawn: opt_str(args, "spawn"),
            };
            core::hook::run(&req)
        }
        "fuzz" => {
            let req = core::fuzz::Request {
                path: str_arg(args, "path")?,
                symbol: opt_str(args, "symbol"),
                address: opt_str(args, "address"),
                mode: opt_str(args, "mode").unwrap_or_else(|| "probe".to_string()),
                args: opt_str(args, "args").unwrap_or_default(),
                start: args.get("start").and_then(Value::as_i64).unwrap_or(0),
                end: args.get("end").and_then(Value::as_i64).unwrap_or(4096),
                step: args.get("step").and_then(Value::as_i64).unwrap_or(1),
                target: opt_str(args, "target").unwrap_or_else(|| "1".to_string()),
                limit: num_arg(args, "limit", 500) as usize,
                vfs: args.get("vfs").and_then(Value::as_bool).unwrap_or(true),
                thumb: args.get("thumb").and_then(Value::as_bool).unwrap_or(false),
                stubs: str_list(args, "stubs"),
                json: args.get("json").and_then(Value::as_bool).unwrap_or(false),
            };
            core::fuzz::run(&req)
        }
        "emulate" => {
            let path = core::emulate::prepare_path(&str_arg(args, "path")?)?;
            let address = match args.get("address") {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_u64().or_else(|| v.as_str().and_then(parse_number)) {
                    Some(n) => Some(n),
                    None => bail!("address must be a number or a hex string"),
                },
            };
            let req = core::emulate::Request {
                path,
                symbol: opt_str(args, "symbol"),
                address,
                entry: args.get("entry").and_then(Value::as_bool).unwrap_or(false),
                args: opt_str(args, "args").unwrap_or_default(),
                max_insns: num_arg(args, "max_insns", 2_000_000),
                timeout_ms: num_arg(args, "timeout_ms", 10_000),
                vfs: args.get("vfs").and_then(Value::as_bool).unwrap_or(true),
                as_double: args
                    .get("as_double")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                thumb: args.get("thumb").and_then(Value::as_bool).unwrap_or(false),
                engine: opt_str(args, "engine").unwrap_or_else(|| "unicorn".to_string()),
                sysroot: opt_str(args, "sysroot"),
                harness: opt_str(args, "harness"),
                read_ranges: str_list(args, "read_ranges"),
                regs: str_list(args, "regs"),
                trace: args.get("trace").and_then(Value::as_bool).unwrap_or(false),
                stubs: str_list(args, "stubs"),
                json: args.get("json").and_then(Value::as_bool).unwrap_or(false),
            };
            core::emulate::run_request(&req)
        }
        "emulate_list" => {
            let path = core::emulate::prepare_path(&str_arg(args, "path")?)?;
            core::emulate::list(
                &path,
                opt_str(args, "filter").as_deref(),
                args.get("json").and_then(Value::as_bool).unwrap_or(false),
            )
        }
        "asm" => {
            let code = str_arg(args, "code")?;
            let mode = opt_str(args, "mode").unwrap_or_else(|| "asm".to_string());
            let address = match args.get("address") {
                None | Some(Value::Null) => 0x1000,
                Some(v) => v
                    .as_u64()
                    .or_else(|| v.as_str().and_then(parse_number))
                    .ok_or_else(|| anyhow!("address must be a number or a hex string"))?,
            };
            let arch = opt_str(args, "arch");
            let bits = args.get("bits").and_then(Value::as_u64).map(|n| n as u32);

            if mode == "patch" {
                let path = opt_str(args, "path").ok_or_else(|| {
                    anyhow!("mode=patch needs path: it names both the target and the architecture")
                })?;
                let offset = match args.get("offset") {
                    None | Some(Value::Null) => {
                        bail!("mode=patch needs offset: where in the file to write")
                    }
                    Some(v) => v
                        .as_u64()
                        .or_else(|| v.as_str().and_then(parse_number))
                        .ok_or_else(|| anyhow!("offset must be a number or a hex string"))?,
                };
                let expect = opt_str(args, "expect");
                let backup = args.get("backup").and_then(Value::as_bool).unwrap_or(true);
                let res = core::asm::assemble_and_patch(
                    &path,
                    &code,
                    arch.as_deref(),
                    bits,
                    address,
                    &core::asm::Spot {
                        offset,
                        expect: expect.as_deref(),
                        backup,
                    },
                )?;
                let mut out = format!(
                    "assembled {}\nwritten   {} at 0x{:x}: {} -> {} ({} bytes)\n",
                    line_for(&res.assembly),
                    res.patch.path,
                    res.patch.offset,
                    res.patch.before,
                    res.patch.after,
                    res.patch.size
                );
                if let Some(backup) = &res.patch.backup {
                    out.push_str(&format!("backup: {backup}\n"));
                }
                if res.patch.reparses == Some(false) {
                    out.push_str("WARNING: rabin2 no longer parses the file\n");
                }
                Ok(out)
            } else {
                let (arch, bits) = match opt_str(args, "path") {
                    Some(path) => {
                        let info = core::analyze(&path)?;
                        (arch.unwrap_or(info.arch), bits.unwrap_or(info.bits))
                    }
                    None => (
                        arch.unwrap_or_else(|| "x86".to_string()),
                        bits.unwrap_or(64),
                    ),
                };
                let res = core::asm::assemble(&code, &arch, bits, address)?;
                Ok(format!("{}\n", line_for(&res)))
            }
        }
        "diff" => {
            let report = core::diff::compare(&str_arg(args, "old")?, &str_arg(args, "new")?)?;
            let mode = opt_str(args, "mode").unwrap_or_else(|| "summary".to_string());
            let limit = (num_arg(args, "limit", 80) as usize).clamp(1, 5_000);
            Ok(core::diff::render(&report, &mode, limit))
        }
        "endpoints" => {
            let req = web::endpoints::Request {
                path: str_arg(args, "path")?,
                kind: opt_str(args, "kind").unwrap_or_else(|| "all".to_string()),
                filter: opt_str(args, "filter"),
                limit: num_arg(args, "limit", 300) as usize,
            };
            web::endpoints::run(&req)
        }
        "secrets" => {
            let req = web::secrets::Request {
                path: str_arg(args, "path")?,
                min_severity: opt_str(args, "minSeverity").unwrap_or_else(|| "low".to_string()),
                entropy: args.get("entropy").and_then(Value::as_f64).unwrap_or(4.3),
                reveal: args.get("reveal").and_then(Value::as_bool).unwrap_or(false),
                limit: num_arg(args, "limit", 200) as usize,
            };
            web::secrets::run(&req)
        }
        "jwt" => {
            let req = web::jwt::Request {
                token: opt_str(args, "token"),
                path: opt_str(args, "path"),
                secret: opt_str(args, "secret"),
                wordlist: opt_str(args, "wordlist"),
                limit: num_arg(args, "limit", 200_000) as usize,
            };
            web::jwt::run(&req)
        }
        "http" => {
            let headers = args
                .get("headers")
                .and_then(Value::as_object)
                .map(|map| {
                    map.iter()
                        .filter_map(|(key, value)| {
                            value.as_str().map(|value| (key.clone(), value.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let req = web::http::Request {
                url: str_arg(args, "url")?,
                method: opt_str(args, "method").unwrap_or_else(|| "GET".to_string()),
                headers,
                body: opt_str(args, "body"),
                json: args.get("json").filter(|value| !value.is_null()).cloned(),
                redirect: args
                    .get("redirect")
                    .and_then(Value::as_bool)
                    .unwrap_or(true),
                timeout_ms: num_arg(args, "timeout", web::http::DEFAULT_TIMEOUT_MS),
                proxy: opt_str(args, "proxy"),
                save: opt_str(args, "save"),
                body_only: args
                    .get("bodyOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            };
            web::http::run(&req)
        }
        "memdump" => {
            let req = core::memdump::Request {
                path: str_arg(args, "path")?,
                plugin: opt_str(args, "plugin"),
                args: opt_str(args, "args"),
                list: args.get("list").and_then(Value::as_bool).unwrap_or(false),
                filter: opt_str(args, "filter"),
                limit: num_arg(args, "limit", 120) as usize,
            };
            core::memdump::run(&req)
        }
        "doctor" => render_doctor(),
        other => bail!("unknown tool {other:?}"),
    }
}

fn str_arg(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing required argument {key:?}"))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

fn num_arg(args: &Value, key: &str, default: u64) -> u64 {
    args.get(key)
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(parse_number)))
        .unwrap_or(default)
}

/// A list argument: either a JSON array of strings or one comma separated
/// string, since both read naturally in a tool call and the old plugin used
/// the comma form.
fn str_list(args: &Value, key: &str) -> Vec<String> {
    match args.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Some(Value::String(text)) => text
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

fn render_info(path: &str) -> Result<String> {
    let info = core::analyze(path)?;
    let mut out = String::new();
    out.push_str(&format!("path      {}\n", info.resolved));
    let mut kind = info.format.clone();
    if info.bits > 0 {
        kind.push_str(&format!(" {}", info.bits));
    }
    if info.endian != "?" {
        kind.push_str(&format!(" {}", info.endian));
    }
    if info.arch != "unknown" {
        kind.push_str(&format!(" ({})", info.arch));
    }
    out.push_str(&format!("format    {kind}\n"));
    out.push_str(&format!(
        "size      {} ({} bytes)\n",
        info.size_human, info.size
    ));
    out.push_str(&format!("sha256    {}\n", info.sha256));
    if let Some(entry) = info.entry {
        out.push_str(&format!("entry     0x{entry:x}\n"));
    }
    out.push_str(&format!("sections  {}\n", info.sections.len()));
    for sect in &info.sections {
        let entropy = sect
            .entropy
            .map(|e| format!(" ent {e:.2}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {:<20} 0x{:<10x} {:>10} bytes  {}{}\n",
            sect.name, sect.addr, sect.size, sect.perms, entropy
        ));
    }
    if !info.hints.is_empty() {
        out.push_str("hints\n");
        for hint in &info.hints {
            out.push_str(&format!("  - {hint}\n"));
        }
    }
    Ok(out)
}

fn render_strings(path: &str, min: usize, filter: Option<&str>, limit: usize) -> Result<String> {
    let found = core::strings::scan(path, min, filter, limit)?;
    let mut out = format!("{} strings", found.len());
    if found.len() >= limit {
        out.push_str(&format!(" (limit {limit} reached, raise it for more)"));
    }
    out.push('\n');
    for item in &found {
        out.push_str(&format!(
            "0x{:08x}  {:<5} {:?}\n",
            item.offset, item.kind, item.text
        ));
    }
    Ok(out)
}

fn render_grep(
    path: &str,
    pattern: &str,
    limit: usize,
    context: usize,
    ignore_case: bool,
) -> Result<String> {
    let hits = core::hexdump::find(path, pattern, limit, context, ignore_case)?;
    if hits.is_empty() {
        return Ok(format!("no matches for {pattern:?}"));
    }
    let mut out = format!("{} matches\n", hits.len());
    if hits.len() >= limit {
        out.push_str(&format!("(limit {limit} reached, raise it for more)\n"));
    }
    for hit in &hits {
        out.push_str(&format!("0x{:08x}  {}\n", hit.offset, hit.context));
    }
    Ok(out)
}

fn render_entropy(path: &str, limit: usize) -> Result<String> {
    let report = core::entropy::analyze_entropy(path)?;
    let mut out = format!(
        "file entropy {:.4}\nverdict      {}\n",
        report.file_entropy, report.verdict
    );
    if !report.packers.is_empty() {
        out.push_str(&format!("packers      {}\n", report.packers.join(", ")));
    }
    if !report.sections.is_empty() {
        out.push_str(&format!("sections: {}\n", report.sections.len()));
        for sect in report.sections.iter().take(limit) {
            out.push_str(&format!(
                "  {:<20} {:>10} bytes  ent {:.2}{}\n",
                sect.name,
                sect.size,
                sect.entropy,
                if sect.executable { "  exec" } else { "" }
            ));
        }
    }
    if report.sections.len() > limit {
        out.push_str(&format!(
            "  ... {} more sections (raise limit)\n",
            report.sections.len() - limit
        ));
    }
    if !report.anomalies.is_empty() {
        out.push_str("anomalies\n");
        for anomaly in &report.anomalies {
            out.push_str(&format!("  - {anomaly}\n"));
        }
    }
    Ok(out)
}

fn render_symbols(symbols: &[core::symbols::Sym], limit: usize, title: &str) -> Result<String> {
    let mut out = format!("{} {title}\n", symbols.len());
    if symbols.len() >= limit {
        out.push_str(&format!("(limit {limit} reached, raise it for more)\n"));
    }
    for sym in symbols {
        let addr = sym
            .addr
            .map(|a| format!("0x{a:x}"))
            .unwrap_or_else(|| "-".to_string());
        let lib = sym
            .lib
            .as_ref()
            .map(|l| format!("  [{l}]"))
            .unwrap_or_default();
        out.push_str(&format!(
            "{addr:>12}  {:<6} {}{}\n",
            sym.kind, sym.name, lib
        ));
    }
    Ok(out)
}

fn render_antidebug(path: &str, limit: usize) -> Result<String> {
    let report = core::antidebug::scan(path)?;
    let mut out = format!("score   {}\nverdict {}\n", report.score, report.verdict);
    if report.signals.is_empty() {
        return Ok(out);
    }
    out.push_str(&format!("signals: {}\n", report.signals.len()));
    for signal in report.signals.iter().take(limit) {
        out.push_str(&format!(
            "  [{:<6}] {:<28} {}\n",
            signal.kind, signal.value, signal.why
        ));
    }
    if report.signals.len() > limit {
        out.push_str(&format!(
            "  ... {} more (raise limit)\n",
            report.signals.len() - limit
        ));
    }
    Ok(out)
}

fn render_consts(path: &str, limit: usize) -> Result<String> {
    let hits = core::scan::consts(path, limit)?;
    let mut out = format!("known crypto constants: {}\n", hits.len());
    for hit in &hits {
        out.push_str(&format!("  0x{:08x}  {}\n", hit.offset, hit.name));
    }
    Ok(out)
}

fn render_apis(path: &str, category: Option<&str>, limit: usize) -> Result<String> {
    let apis = core::scan::apis(path, category)?;
    if apis.is_empty() {
        return Ok(format!(
            "apis: nothing{} matches — the binary may have no imports, or be stripped\n",
            match category {
                Some(category) => format!(" in {category}"),
                None => String::new(),
            }
        ));
    }
    let mut out = String::new();
    let per_group = limit.min(40);
    for (group, names) in &apis {
        out.push_str(&format!("apis/{group} ({})\n", names.len()));
        for name in names.iter().take(per_group) {
            out.push_str(&format!("  {name}\n"));
        }
        if names.len() > per_group {
            out.push_str(&format!("  ... {} more\n", names.len() - per_group));
        }
    }
    Ok(out)
}

fn line_for(a: &core::asm::Assembly) -> String {
    format!(
        "arch      {}/{}   address {:#x}\ncode      {} instructions, {} bytes\nbytes     {}\n",
        a.arch, a.bits, a.address, a.instructions, a.length, a.spaced
    )
}

fn render_doctor() -> Result<String> {
    let tools = core::external::doctor();
    let mut out = String::new();
    let missing: Vec<&str> = tools.iter().filter(|t| !t.found).map(|t| t.name).collect();
    out.push_str(&format!(
        "{}/{} tools available\n",
        tools.len() - missing.len(),
        tools.len()
    ));
    for tool in &tools {
        let mark = if tool.found { "ok " } else { "---" };
        let version = tool.version.as_deref().unwrap_or("");
        out.push_str(&format!(
            "  {mark} {:<14} {:<44} {}\n",
            tool.name, tool.purpose, version
        ));
    }
    if !missing.is_empty() {
        out.push_str(&format!("missing: {}\n", missing.join(", ")));
    }
    Ok(out)
}

fn render_archive(path: &str) -> Result<String> {
    let entries = core::resolve::list_entries(std::path::Path::new(path))?;
    Ok(render_entries(&entries, None, 500))
}

fn render_entries(
    entries: &[core::resolve::ArchiveEntry],
    filter: Option<&str>,
    limit: usize,
) -> String {
    let kept: Vec<_> = match filter {
        Some(needle) => {
            let needle = needle.to_lowercase();
            entries
                .iter()
                .filter(|e| e.name.to_lowercase().contains(&needle))
                .collect()
        }
        None => entries.iter().collect(),
    };
    if kept.is_empty() {
        return match filter {
            Some(needle) => format!(
                "nothing in the archive matches {needle:?} ({} entries total)\n",
                entries.len()
            ),
            None => format!("{} entries\n", entries.len()),
        };
    }
    let mut out = match filter {
        Some(needle) => format!(
            "{} of {} entries match {needle:?}\n",
            kept.len(),
            entries.len()
        ),
        None => format!("{} entries\n", entries.len()),
    };
    for entry in kept.iter().take(limit) {
        out.push_str(&format!("{:>12}  {}\n", entry.size, entry.name));
    }
    if kept.len() > limit {
        out.push_str(&format!("... {} more\n", kept.len() - limit));
    }
    out
}

fn title_with_filter(title: &str, filter: Option<&str>) -> String {
    match filter {
        Some(needle) => format!("{title} matching {needle:?}"),
        None => title.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_has_unique_names() {
        let tools = tools();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
        assert_eq!(names.len(), 34);
    }

    #[test]
    fn numbers_accept_hex_strings() {
        assert_eq!(num_arg(&json!({"offset": "0x40"}), "offset", 0), 64);
        assert_eq!(num_arg(&json!({"offset": 40}), "offset", 0), 40);
        assert_eq!(num_arg(&json!({}), "offset", 7), 7);
    }

    #[test]
    fn missing_path_is_a_readable_error() {
        let err = call_tool("info", &json!({})).unwrap_err().to_string();
        assert!(err.contains("path"));
    }
}
