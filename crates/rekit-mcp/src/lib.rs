//! rekit-mcp — a Model Context Protocol server over stdio.
//!
//! The transport is deliberately hand written: MCP is a line oriented
//! JSON-RPC 2.0 conversation, and keeping it here means no SDK version drift
//! and no dependency beyond `serde_json`.
//!
//! Tool names are bare (`info`, `strings`, ...). A client prefixes them with
//! the server name, so in OpenCode they show up as `rekit_info`, `rekit_strings`.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

use rekit_core as core;

/// Injected into the agent's system prompt by clients that support it.
pub const INSTRUCTIONS: &str = "\
rekit analyzes binaries. Every path argument accepts `path::inner` to reach a \
file inside an archive, for example `app.apk::lib/arm64-v8a/libnative.so` or \
`firmware.bin::rootfs.tar.gz::bin/busybox`. Prefer `info` first: it tells the \
format, architecture and whether the file is packed. `grep` searches raw bytes \
and accepts `\"text\"` or hex such as `de ad be ef`. Start with a small `limit` \
and raise it only when needed. For Android, `manifest` decodes binary XML in \
place and `decompile` runs jadx; `disasm`, `r2`, `binwalk` and `patch` need the \
external tools that `doctor` lists. `patch` always requires `expect`.";

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
            "description": "Search raw bytes. Pattern is hex (`de ad be ef`, `deadbeef`), a quoted literal (`\"BuildConfig\"`), or a plain word. Returns offsets with ASCII context.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "pattern": {"type": "string"},
                "limit": {"type": "integer", "description": "default 50"},
                "context": {"type": "integer", "description": "bytes around each hit, default 16"}
            }), &["path", "pattern"])
        },
        {
            "name": "hex",
            "description": "Hex dump of a byte range with ASCII column, like xxd. Use it to verify bytes before patching.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "offset": {"type": "integer", "description": "decimal or 0x-prefixed, default 0"},
                "length": {"type": "integer", "description": "default 256, max 8192"}
            }), &["path"])
        },
        {
            "name": "entropy",
            "description": "Shannon entropy per section plus packer fingerprints (UPX, VMProtect, Themida, Enigma, ASPack, MPRESS, ConfuserEx, .NET Reactor) and layout anomalies such as RWX sections or executable high-entropy code.",
            "inputSchema": schema(json!({
                "path": {"type": "string"}
            }), &["path"])
        },
        {
            "name": "imports",
            "description": "Imported symbols with the library they come from. The quickest way to see what a binary can actually do.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "limit": {"type": "integer", "description": "default 200"}
            }), &["path"])
        },
        {
            "name": "exports",
            "description": "Exported symbols with addresses, for shared libraries and DLLs.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "limit": {"type": "integer", "description": "default 200"}
            }), &["path"])
        },
        {
            "name": "antidebug",
            "description": "Static anti-debug and anti-tamper signals: suspicious imports (ptrace, IsDebuggerPresent, NtQueryInformationProcess, __system_property_get) and strings (TracerPid, frida, xposed, magisk, goldfish), with a score and verdict.",
            "inputSchema": schema(json!({
                "path": {"type": "string"}
            }), &["path"])
        },
        {
            "name": "scan",
            "description": "Two scans in one. kind=const finds crypto constants (AES S-box, SHA-256 K, ChaCha sigma, Base64 alphabet) with offsets; kind=apis groups imports into anti/crypto/net/mem/priv. kind=all returns both.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "kind": {"type": "string", "enum": ["const", "apis", "all"], "description": "default all"},
                "limit": {"type": "integer", "description": "default 50 constants"}
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
            "description": "Decompile a dex/apk to Java with jadx (cached). Without `class` it lists the generated files; with `class` it returns that file's source.",
            "inputSchema": schema(json!({
                "path": {"type": "string", "description": "apk, dex, jar or a path::inner spec"},
                "class": {"type": "string", "description": "fully qualified class name, e.g. com.example.Foo"},
                "limit": {"type": "integer", "description": "files to list, default 100"}
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
            "name": "binwalk",
            "description": "Map embedded files and firmware signatures (binwalk). extract=true unwraps them into the rekit cache.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "extract": {"type": "boolean", "description": "default false"}
            }), &["path"])
        },
        {
            "name": "patch",
            "description": "Write bytes into a file at an offset. `expect` is mandatory and must equal what is currently there: a mismatch aborts and reports the real bytes. Use hex with `hex` first.",
            "inputSchema": schema(json!({
                "path": {"type": "string"},
                "offset": {"type": "string", "description": "hex or decimal offset"},
                "bytes": {"type": "string", "description": "hex bytes to write, e.g. '90 90'"},
                "expect": {"type": "string", "description": "hex bytes that must be present now"}
            }), &["path", "offset", "bytes", "expect"])
        },
        {
            "name": "emulate",
            "description": "Actually execute one function from a PE/ELF/Mach-O in a sandboxed CPU and report what it returns. This is the only tool that gives facts instead of guesses about obfuscated licence, password, integrity and anti-debug checks: ptrace returns 0, TracerPid is 0, no debugger is present, time advances, random bytes look real. Call `emulate_list` first when you do not know the function name. Arguments go in a string: numbers may be hex, strings are written str:\"text\" with quotes when they contain commas.",
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
                "json": {"type": "boolean", "description": "return the raw report instead of a summary"}
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
            let context = num_arg(args, "context", 16) as usize;
            render_grep(&path, &pattern, limit, context)
        }
        "hex" => {
            let path = str_arg(args, "path")?;
            let offset = num_arg(args, "offset", 0);
            let length = (num_arg(args, "length", 256) as usize).min(8192);
            Ok(core::hexdump::dump(&path, offset, length)?)
        }
        "entropy" => render_entropy(&str_arg(args, "path")?),
        "imports" => {
            let path = str_arg(args, "path")?;
            let limit = num_arg(args, "limit", 200) as usize;
            render_symbols(&core::symbols::imports(&path, limit)?, limit, "imports")
        }
        "exports" => {
            let path = str_arg(args, "path")?;
            let limit = num_arg(args, "limit", 200) as usize;
            render_symbols(&core::symbols::exports(&path, limit)?, limit, "exports")
        }
        "antidebug" => render_antidebug(&str_arg(args, "path")?),
        "scan" => {
            let path = str_arg(args, "path")?;
            let kind = opt_str(args, "kind").unwrap_or_else(|| "all".to_string());
            let limit = num_arg(args, "limit", 50) as usize;
            render_scan(&path, &kind, limit)
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
            let limit = (num_arg(args, "limit", 100) as usize).clamp(1, 5_000);
            core::external::decompile(&path, class.as_deref(), limit)
        }
        "manifest" => core::axml::render(&str_arg(args, "path")?),
        "binwalk" => {
            let path = str_arg(args, "path")?;
            let extract = args
                .get("extract")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            core::external::binwalk(&path, extract)
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
            let bytes = str_arg(args, "bytes")?;
            let expect = str_arg(args, "expect")?;
            let res = core::patch::apply_hex(&path, offset, &bytes, &expect)?;
            Ok(format!(
                "patched {} at 0x{:x}: {} -> {} ({} bytes)\n",
                res.path, res.offset, res.before, res.after, res.size
            ))
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

fn render_grep(path: &str, pattern: &str, limit: usize, context: usize) -> Result<String> {
    let hits = core::hexdump::find(path, pattern, limit, context)?;
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

fn render_entropy(path: &str) -> Result<String> {
    let report = core::entropy::analyze_entropy(path)?;
    let mut out = format!(
        "file entropy {:.4}\nverdict      {}\n",
        report.file_entropy, report.verdict
    );
    if !report.packers.is_empty() {
        out.push_str(&format!("packers      {}\n", report.packers.join(", ")));
    }
    if !report.sections.is_empty() {
        out.push_str("sections\n");
        for sect in &report.sections {
            out.push_str(&format!(
                "  {:<20} {:>10} bytes  ent {:.2}{}\n",
                sect.name,
                sect.size,
                sect.entropy,
                if sect.executable { "  exec" } else { "" }
            ));
        }
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

fn render_antidebug(path: &str) -> Result<String> {
    let report = core::antidebug::scan(path)?;
    let mut out = format!("score   {}\nverdict {}\n", report.score, report.verdict);
    if report.signals.is_empty() {
        return Ok(out);
    }
    out.push_str("signals\n");
    for signal in &report.signals {
        out.push_str(&format!(
            "  [{:<6}] {:<28} {}\n",
            signal.kind, signal.value, signal.why
        ));
    }
    Ok(out)
}

fn render_scan(path: &str, kind: &str, limit: usize) -> Result<String> {
    let mut out = String::new();
    if kind == "const" || kind == "all" {
        let hits = core::scan::consts(path, limit)?;
        out.push_str(&format!("constants: {}\n", hits.len()));
        for hit in &hits {
            out.push_str(&format!("  0x{:08x}  {}\n", hit.offset, hit.name));
        }
    }
    if kind == "apis" || kind == "all" {
        let apis = core::scan::apis(path)?;
        if apis.is_empty() {
            out.push_str("apis: no interesting imports\n");
        }
        for (category, names) in &apis {
            out.push_str(&format!("apis/{category} ({})\n", names.len()));
            for name in names.iter().take(40) {
                out.push_str(&format!("  {name}\n"));
            }
            if names.len() > 40 {
                out.push_str(&format!("  ... {} more\n", names.len() - 40));
            }
        }
    }
    Ok(out)
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
    match core::emulate::available() {
        Some(path) => out.push_str(&format!("  ok  {:<14} {:<44} {}\n", "rekit-emu", "execute a function in a sandboxed CPU", path.display())),
        None => out.push_str("  --- rekit-emu       execute a function in a sandboxed CPU\n"),
    }
    if !missing.is_empty() {
        out.push_str(&format!("missing: {}\n", missing.join(", ")));
    }
    Ok(out)
}

fn render_archive(path: &str) -> Result<String> {
    let entries = core::resolve::list_entries(std::path::Path::new(path))?;
    let mut out = format!("{} entries\n", entries.len());
    for entry in entries.iter().take(500) {
        out.push_str(&format!("{:>12}  {}\n", entry.size, entry.name));
    }
    if entries.len() > 500 {
        out.push_str(&format!("... {} more\n", entries.len() - 500));
    }
    Ok(out)
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
        assert_eq!(names.len(), 19);
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
