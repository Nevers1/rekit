use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;

/// rekit — binary analysis for humans and agents.
#[derive(Parser)]
#[command(
    name = "rekit",
    version,
    about = "Static analysis for binaries and archives"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Format, architecture, sections, and what to do next.
    Info {
        /// File path; `path::inner` reaches inside an archive.
        path: String,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Search raw bytes: hex, "quoted text" or a word.
    Grep {
        path: String,
        pattern: String,
        /// bytes (where are these bytes) or text (which line says this);
        /// a regex implies text.
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        regex: bool,
        #[arg(long)]
        ignore_case: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Bytes around each hit, or lines around it in text mode.
        #[arg(long)]
        context: Option<usize>,
    },
    /// Hex dump of a byte range.
    Hex {
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 256)]
        length: usize,
        /// Signature to hunt instead of dumping: hex bytes or "text".
        #[arg(long)]
        bytes: Option<String>,
    },
    /// Printable strings, ASCII and UTF-16LE.
    Strings {
        path: String,
        #[arg(long, default_value_t = 4)]
        min: usize,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Shannon entropy and packer fingerprints.
    Entropy {
        path: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Imported symbols.
    Imports {
        path: String,
        /// Case-insensitive substring of the name.
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Exported symbols.
    Exports {
        path: String,
        /// Case-insensitive substring of the name.
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Static anti-debug and anti-tamper signals.
    Antidebug {
        path: String,
        #[arg(long, default_value_t = 60)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Crypto constants and grouped imports.
    Scan {
        path: String,
        #[arg(long, default_value = "apis")]
        kind: String,
        /// kind=const: the constant to find.
        #[arg(long)]
        value: Option<String>,
        /// kind=const: how many bytes the constant occupies.
        #[arg(long, default_value_t = 4)]
        width: usize,
        /// kind=apis: only this group.
        #[arg(long)]
        category: Option<String>,
        /// kind=probe: trial argument.
        #[arg(long, default_value = "1")]
        arg: String,
        #[arg(long, default_value_t = 60)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// List archive members.
    Archive { path: String },
    /// Disassemble a function or an address range.
    Disasm {
        path: String,
        #[arg(long)]
        symbol: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 256)]
        length: usize,
    },
    /// Radare2 one-shot analysis.
    R2 {
        path: String,
        #[arg(long, default_value = "functions")]
        kind: String,
        #[arg(long)]
        target: Option<String>,
    },
    /// Decompile a dex/apk to Java with jadx (cached).
    Decompile {
        path: String,
        #[arg(long)]
        class: Option<String>,
        /// Search the decompiled tree instead of listing it.
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long)]
        regex: bool,
        #[arg(long)]
        ignore_case: bool,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Decode an APK into smali and resources with apktool.
    Apktool {
        path: String,
        /// Text to search in the decoded tree.
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long, default_value_t = 60)]
        limit: usize,
    },
    /// What an APK contains: resource groups, layouts, assets.
    Resources {
        path: String,
        /// list | strings | layout | drawable | asset | xml
        #[arg(long, default_value = "list")]
        kind: String,
        /// Resource name filter, e.g. app_name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Decode an Android binary manifest.
    Manifest { path: String },
    /// Decompile native code to C with Ghidra.
    Ghidra {
        path: String,
        /// Function name or part of it.
        #[arg(long)]
        symbol: Option<String>,
        /// Function address in hex, e.g. 0x401010.
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        reanalyze: bool,
    },
    /// Decompile native code to C with IDA and Hex-Rays.
    Ida {
        path: String,
        #[arg(long)]
        symbol: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Decompile a .NET assembly to C#.
    Dotnet {
        path: String,
        /// Type to decompile in full.
        #[arg(long = "type")]
        ty: Option<String>,
        #[arg(long)]
        pattern: Option<String>,
        #[arg(long)]
        regex: bool,
        #[arg(long, default_value_t = 60)]
        limit: usize,
    },
    /// JVM bytecode with javap.
    Javap {
        path: String,
        #[arg(long)]
        class: Option<String>,
        #[arg(long)]
        method: Option<String>,
        /// Signatures only instead of bytecode.
        #[arg(long)]
        signatures: bool,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Embedded files and firmware signatures.
    Binwalk {
        path: String,
        #[arg(long)]
        extract: bool,
        /// Comma separated file types to look for only, e.g. "png,zip".
        #[arg(long)]
        signatures: Option<String>,
        #[arg(long, default_value_t = 120)]
        limit: usize,
    },
    /// Write bytes at an offset, refusing to proceed on an unexpected value.
    Patch {
        path: String,
        #[arg(long)]
        offset: String,
        /// Hex bytes, e.g. "90 90".
        #[arg(long, conflicts_with_all = ["string", "nop"])]
        bytes: Option<String>,
        /// Text to write instead of --bytes, with a trailing NUL.
        #[arg(long, conflicts_with_all = ["bytes", "nop"])]
        string: Option<String>,
        /// Write this many 0x90 bytes instead of --bytes.
        #[arg(long, conflicts_with_all = ["bytes", "string"])]
        nop: Option<u64>,
        #[arg(long)]
        expect: String,
        /// Skip the copy in the cache that is made before writing.
        #[arg(long)]
        no_backup: bool,
    },
    /// Assemble instructions into bytes, and optionally write them into the file.
    Asm {
        /// Instructions separated by `;` or newlines.
        code: String,
        /// Binary to take the architecture from; required with --patch.
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long)]
        bits: Option<u32>,
        /// Assembly base address, which decides relative jumps.
        #[arg(long, default_value = "0x1000")]
        address: String,
        /// Write the result into the file at --offset.
        #[arg(long)]
        patch: bool,
        #[arg(long)]
        offset: Option<String>,
        #[arg(long)]
        expect: Option<String>,
        /// Skip the copy in the cache that is made before writing.
        #[arg(long)]
        no_backup: bool,
    },
    /// What changed between two builds of the same binary.
    Diff {
        old: String,
        new: String,
        /// summary | funcs | strings | full
        #[arg(long, default_value = "summary")]
        mode: String,
        #[arg(long, default_value_t = 80)]
        limit: usize,
    },
    /// Call one function in a sandboxed CPU and print what it returns.
    Emulate {
        path: String,
        #[arg(long)]
        symbol: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        entry: bool,
        /// Comma separated: `1,0x20,3.5,str:"hello, world"`. A decimal point
        /// (or `f:`) makes an argument a double, which the ABI passes in the
        /// floating-point registers.
        #[arg(long, default_value = "", allow_hyphen_values = true)]
        args: String,
        #[arg(long, default_value_t = 2_000_000)]
        max_insns: u64,
        #[arg(long, default_value_t = 10_000)]
        timeout_ms: u64,
        /// Accept the emulated filesystem (default true).
        #[arg(long)]
        no_vfs: bool,
        /// Read the return value from the FP register.
        #[arg(long)]
        as_double: bool,
        /// Target is Thumb code (ARM only).
        #[arg(long)]
        thumb: bool,
        /// unicorn (default) or qemu.
        #[arg(long, default_value = "unicorn")]
        engine: String,
        /// qemu: target sysroot, e.g. /usr/aarch64-linux-gnu.
        #[arg(long)]
        sysroot: Option<String>,
        /// qemu: a prebuilt harness instead of the cached one.
        #[arg(long)]
        harness: Option<String>,
        /// Registers to report after the run, e.g. rax,rdi.
        #[arg(long, default_value = "")]
        regs: String,
        /// Read memory after the run: addr:size:label, repeatable.
        #[arg(long = "read", value_name = "ADDR:SIZE:LABEL")]
        read_ranges: Vec<String>,
        /// Read this many bytes at the returned pointer.
        #[arg(long, value_name = "BYTES")]
        read_ret: Option<usize>,
        /// Record executed instructions and show the head of the trace.
        #[arg(long)]
        trace: bool,
        /// Answer an address with an import call: addr=name[:ret], repeatable.
        #[arg(long = "stub", value_name = "ADDR=NAME[:RET]")]
        stubs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Generate a Frida hook script for a function.
    Hook {
        path: Option<String>,
        /// Exported function to hook.
        #[arg(long)]
        symbol: Option<String>,
        /// Hex file address instead of a name.
        #[arg(long)]
        address: Option<String>,
        /// Module name as Frida sees it.
        #[arg(long)]
        module: Option<String>,
        /// How many arguments to log.
        #[arg(long, default_value_t = 4)]
        args: usize,
        /// Extra JS for onEnter.
        #[arg(long)]
        on_enter: Option<String>,
        /// Extra JS for onLeave.
        #[arg(long)]
        on_leave: Option<String>,
        /// gen | spawn
        #[arg(long, default_value = "gen")]
        mode: String,
        /// spawn: command to start under Frida.
        #[arg(long)]
        spawn: Option<String>,
    },
    /// Run one function over many inputs: probe, sweep, magic, crash.
    Fuzz {
        path: String,
        /// Function to call.
        #[arg(long)]
        symbol: Option<String>,
        /// Hex address instead of a name.
        #[arg(long)]
        address: Option<String>,
        /// probe | sweep | magic | crash
        #[arg(long, default_value = "probe")]
        mode: String,
        /// probe: arguments for one call, e.g. 42 or str:hello.
        #[arg(long)]
        args: Option<String>,
        /// First value, may be negative.
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
        start: i64,
        /// Last value, inclusive.
        #[arg(long, default_value_t = 4096, allow_hyphen_values = true)]
        end: i64,
        /// Step between values.
        #[arg(long, default_value_t = 1, allow_hyphen_values = true)]
        step: i64,
        /// magic: the return value to look for, decimal or 0x hex.
        #[arg(long, default_value = "1")]
        target: String,
        /// Maximum number of runs.
        #[arg(long, default_value_t = 500)]
        limit: usize,
        /// Do not answer file reads: only the binary's own memory exists.
        #[arg(long)]
        no_vfs: bool,
        /// Target is Thumb code (ARM only).
        #[arg(long)]
        thumb: bool,
        /// Answer an address with an import call: addr=name[:ret], repeatable.
        #[arg(long = "stub", value_name = "ADDR=NAME[:RET]")]
        stubs: Vec<String>,
        /// Print the emulator's raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the functions `emulate` can call.
    EmulateList {
        path: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// What a frontend bundle talks to: URLs, API routes, parameters, GraphQL.
    Endpoints {
        path: String,
        /// all | url | path | param | graphql
        #[arg(long, default_value = "all")]
        kind: String,
        /// Only keep values matching this regex.
        #[arg(long)]
        filter: Option<String>,
        /// Max distinct values per group.
        #[arg(long, default_value_t = 300)]
        limit: usize,
    },
    /// Keys and tokens committed by accident, with an entropy pass.
    Secrets {
        path: String,
        /// critical | high | medium | low
        #[arg(long = "min-severity", default_value = "low")]
        min_severity: String,
        /// Entropy threshold for the second pass; 0 disables it.
        #[arg(long, default_value_t = 4.3)]
        entropy: f64,
        /// Show values in full.
        #[arg(long)]
        reveal: bool,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Read a JWT, check its signature, or crack its secret.
    Jwt {
        /// The token itself.
        token: Option<String>,
        /// Or a file/directory/archive to find tokens in.
        #[arg(long)]
        path: Option<String>,
        /// Check the signature against this secret.
        #[arg(long)]
        secret: Option<String>,
        /// Crack an HS256/384/512 secret with this wordlist.
        #[arg(long)]
        wordlist: Option<String>,
        /// How many words to try.
        #[arg(long, default_value_t = 200_000)]
        limit: usize,
    },
    /// One HTTP request with full control, printed with a repeatable curl.
    Http {
        url: String,
        #[arg(long, default_value = "GET")]
        method: String,
        /// Header as "Name: value"; repeatable.
        #[arg(long)]
        header: Vec<String>,
        /// Request body as-is.
        #[arg(long)]
        body: Option<String>,
        /// Body as a JSON string; also sets Content-Type.
        #[arg(long)]
        json: Option<String>,
        /// Do not follow redirects.
        #[arg(long)]
        no_redirect: bool,
        /// Timeout in milliseconds.
        #[arg(long, default_value_t = 20_000)]
        timeout: u64,
        #[arg(long)]
        proxy: Option<String>,
        /// Write the response body to this file.
        #[arg(long)]
        save: Option<String>,
        /// Print the body alone.
        #[arg(long)]
        body_only: bool,
    },
    /// Load a page in headless Chrome and report what it did.
    Browser {
        url: String,
        /// text | dom | html | title | eval | requests | console | cookies |
        /// set-cookie | links | storage | screenshot | pdf | click | fill |
        /// wait | snapshot
        #[arg(long, default_value = "text")]
        action: String,
        /// action=eval: the JavaScript to run.
        #[arg(long)]
        js: Option<String>,
        /// CSS selector for dom/text/click/fill/wait.
        #[arg(long)]
        selector: Option<String>,
        /// action=fill: the text to put in the field.
        #[arg(long)]
        value: Option<String>,
        /// CSS selector to wait for after loading.
        #[arg(long)]
        wait: Option<String>,
        #[arg(long, default_value_t = 1366)]
        width: u32,
        #[arg(long, default_value_t = 900)]
        height: u32,
        /// Screenshot the whole page, not just the viewport.
        #[arg(long)]
        full_page: bool,
        /// Where to write a screenshot or pdf.
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        /// Only rows containing this text (requests, console, links).
        #[arg(long)]
        filter: Option<String>,
        /// Extra header for every request: "Name: value"; repeatable.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
        /// Cookie to set before loading: "name=value; domain=…"; repeatable.
        #[arg(long = "cookie")]
        cookies: Vec<String>,
        #[arg(long)]
        user_agent: Option<String>,
        /// Attach to a running browser instead of starting one.
        #[arg(long)]
        cdp_url: Option<String>,
        /// Show the window instead of running headless.
        #[arg(long)]
        headed: bool,
        /// Keep the throwaway profile for inspection.
        #[arg(long)]
        keep_profile: bool,
        /// Accept invalid TLS certificates.
        #[arg(long)]
        ignore_cert: bool,
        #[arg(long)]
        json: bool,
    },
    /// Analyze a memory dump through volatility3.
    Memdump {
        /// The dump (raw, vmem, dmp, core, lmp, lime), or archive::inner.
        path: String,
        /// volatility3 plugin, e.g. windows.pslist.
        #[arg(long)]
        plugin: Option<String>,
        /// Extra plugin arguments, e.g. "--pid 1234".
        #[arg(long, allow_hyphen_values = true)]
        args: Option<String>,
        /// List the available plugins and stop.
        #[arg(long)]
        list: bool,
        /// Only list plugins matching this regex.
        #[arg(long)]
        filter: Option<String>,
        /// Max lines of output.
        #[arg(long, default_value_t = 120)]
        limit: usize,
    },
    /// Which external tools are installed.
    Doctor,
    /// Run the MCP server on stdin/stdout.
    Mcp,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Command::Mcp = cli.command {
        return rekit_mcp::serve();
    }

    let text = match cli.command {
        Command::Mcp => unreachable!(),
        Command::Info { path, json: false } => render("info", json!({ "path": path }))?,
        Command::Info { path, json: true } => {
            serde_json::to_string_pretty(&rekit_core::analyze(&path)?)?
        }
        Command::Grep {
            path,
            pattern,
            mode,
            regex,
            ignore_case,
            limit,
            context,
        } => render(
            "grep",
            json!({
                "path": path,
                "pattern": pattern,
                "mode": mode,
                "regex": regex,
                "ignore_case": ignore_case,
                "limit": limit,
                "context": context,
            }),
        )?,
        Command::Hex {
            path,
            offset,
            length,
            bytes,
        } => render(
            "hex",
            json!({"path": path, "offset": offset, "length": length, "bytes": bytes}),
        )?,
        Command::Strings {
            path,
            min,
            filter,
            limit,
        } => render(
            "strings",
            json!({"path": path, "min": min, "filter": filter, "limit": limit}),
        )?,
        Command::Entropy {
            path,
            limit,
            json: false,
        } => render("entropy", json!({"path": path, "limit": limit}))?,
        Command::Entropy {
            path, json: true, ..
        } => serde_json::to_string_pretty(&rekit_core::entropy::analyze_entropy(&path)?)?,
        Command::Imports {
            path,
            filter,
            limit,
        } => render(
            "imports",
            json!({"path": path, "filter": filter, "limit": limit}),
        )?,
        Command::Exports {
            path,
            filter,
            limit,
        } => render(
            "exports",
            json!({"path": path, "filter": filter, "limit": limit}),
        )?,
        Command::Antidebug {
            path,
            limit,
            json: false,
        } => render("antidebug", json!({"path": path, "limit": limit}))?,
        Command::Antidebug {
            path, json: true, ..
        } => serde_json::to_string_pretty(&rekit_core::antidebug::scan(&path)?)?,
        Command::Scan {
            path,
            kind,
            value,
            width,
            category,
            arg,
            limit,
            json,
        } => render(
            "scan",
            json!({
                "path": path,
                "kind": kind,
                "value": value,
                "width": width,
                "category": category,
                "arg": arg,
                "limit": limit,
                "json": json,
            }),
        )?,
        Command::Archive { path } => render("archive", json!({"path": path}))?,
        Command::Disasm {
            path,
            symbol,
            address,
            length,
        } => render(
            "disasm",
            json!({"path": path, "symbol": symbol, "address": address, "length": length}),
        )?,
        Command::R2 { path, kind, target } => {
            render("r2", json!({"path": path, "kind": kind, "target": target}))?
        }
        Command::Decompile {
            path,
            class,
            pattern,
            regex,
            ignore_case,
            limit,
        } => render(
            "decompile",
            json!({
                "path": path,
                "class": class,
                "pattern": pattern,
                "regex": regex,
                "ignore_case": ignore_case,
                "limit": limit,
            }),
        )?,
        Command::Apktool {
            path,
            pattern,
            limit,
        } => render(
            "apktool",
            json!({"path": path, "pattern": pattern, "limit": limit}),
        )?,
        Command::Resources { path, kind, name } => render(
            "resources",
            json!({"path": path, "kind": kind, "name": name}),
        )?,
        Command::Manifest { path } => render("manifest", json!({"path": path}))?,
        Command::Ghidra {
            path,
            symbol,
            address,
            limit,
            reanalyze,
        } => render(
            "ghidra",
            json!({
                "path": path,
                "symbol": symbol,
                "address": address,
                "limit": limit,
                "reanalyze": reanalyze,
            }),
        )?,
        Command::Ida {
            path,
            symbol,
            address,
            limit,
        } => render(
            "ida",
            json!({"path": path, "symbol": symbol, "address": address, "limit": limit}),
        )?,
        Command::Dotnet {
            path,
            ty,
            pattern,
            regex,
            limit,
        } => render(
            "dotnet",
            json!({
                "path": path,
                "type": ty,
                "pattern": pattern,
                "regex": regex,
                "limit": limit,
            }),
        )?,
        Command::Javap {
            path,
            class,
            method,
            signatures,
            limit,
        } => render(
            "javap",
            json!({
                "path": path,
                "class": class,
                "method": method,
                "code": !signatures,
                "limit": limit,
            }),
        )?,
        Command::Binwalk {
            path,
            extract,
            signatures,
            limit,
        } => render(
            "binwalk",
            json!({
                "path": path,
                "extract": extract,
                "signatures": signatures,
                "limit": limit,
            }),
        )?,
        Command::Patch {
            path,
            offset,
            bytes,
            string,
            nop,
            expect,
            no_backup,
        } => render(
            "patch",
            json!({
                "path": path,
                "offset": offset,
                "bytes": bytes,
                "string": string,
                "nop": nop,
                "expect": expect,
                "backup": !no_backup,
            }),
        )?,
        Command::Asm {
            code,
            path,
            arch,
            bits,
            address,
            patch,
            offset,
            expect,
            no_backup,
        } => render(
            "asm",
            json!({
                "code": code,
                "path": path,
                "arch": arch,
                "bits": bits,
                "address": address,
                "mode": if patch { "patch" } else { "asm" },
                "offset": offset,
                "expect": expect,
                "backup": !no_backup,
            }),
        )?,
        Command::Diff {
            old,
            new,
            mode,
            limit,
        } => render(
            "diff",
            json!({"old": old, "new": new, "mode": mode, "limit": limit}),
        )?,
        Command::Emulate {
            path,
            symbol,
            address,
            entry,
            args,
            max_insns,
            timeout_ms,
            no_vfs,
            as_double,
            thumb,
            engine,
            sysroot,
            harness,
            regs,
            read_ranges,
            read_ret,
            trace,
            stubs,
            json,
        } => render(
            "emulate",
            json!({
                "path": path,
                "symbol": symbol,
                "address": address,
                "entry": entry,
                "args": args,
                "max_insns": max_insns,
                "timeout_ms": timeout_ms,
                "vfs": !no_vfs,
                "as_double": as_double,
                "thumb": thumb,
                "engine": engine,
                "sysroot": sysroot,
                "harness": harness,
                "regs": regs,
                "read_ranges": read_ranges,
                "read_ret": read_ret,
                "trace": trace,
                "stubs": stubs,
                "json": json,
            }),
        )?,
        Command::Hook {
            path,
            symbol,
            address,
            module,
            args,
            on_enter,
            on_leave,
            mode,
            spawn,
        } => render(
            "hook",
            json!({
                "path": path,
                "symbol": symbol,
                "address": address,
                "module": module,
                "args": args,
                "onEnter": on_enter,
                "onLeave": on_leave,
                "mode": mode,
                "spawn": spawn,
            }),
        )?,
        Command::Fuzz {
            path,
            symbol,
            address,
            mode,
            args,
            start,
            end,
            step,
            target,
            limit,
            no_vfs,
            thumb,
            stubs,
            json,
        } => render(
            "fuzz",
            json!({
                "path": path,
                "symbol": symbol,
                "address": address,
                "mode": mode,
                "args": args,
                "start": start,
                "end": end,
                "step": step,
                "target": target,
                "limit": limit,
                "vfs": !no_vfs,
                "thumb": thumb,
                "stubs": stubs,
                "json": json,
            }),
        )?,
        Command::EmulateList { path, filter, json } => {
            print!(
                "{}",
                rekit_core::emulate::list(&path, filter.as_deref(), json)?
            );
            return Ok(());
        }
        Command::Endpoints {
            path,
            kind,
            filter,
            limit,
        } => render(
            "endpoints",
            json!({"path": path, "kind": kind, "filter": filter, "limit": limit}),
        )?,
        Command::Secrets {
            path,
            min_severity,
            entropy,
            reveal,
            limit,
        } => render(
            "secrets",
            json!({
                "path": path,
                "minSeverity": min_severity,
                "entropy": entropy,
                "reveal": reveal,
                "limit": limit,
            }),
        )?,
        Command::Jwt {
            token,
            path,
            secret,
            wordlist,
            limit,
        } => render(
            "jwt",
            json!({
                "token": token,
                "path": path,
                "secret": secret,
                "wordlist": wordlist,
                "limit": limit,
            }),
        )?,
        Command::Http {
            url,
            method,
            header,
            body,
            json: json_body,
            no_redirect,
            timeout,
            proxy,
            save,
            body_only,
        } => {
            // `--header "Name: value"` is what a person types; the tool wants
            // the pair split, and a header without a colon is a mistake worth
            // naming rather than sending.
            let mut headers = serde_json::Map::new();
            for line in header {
                let (name, value) = line
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("--header {line:?} is not \"Name: value\""))?;
                headers.insert(name.trim().to_string(), json!(value.trim()));
            }
            let json_value = match json_body {
                Some(text) => Some(
                    serde_json::from_str::<serde_json::Value>(&text)
                        .map_err(|err| anyhow::anyhow!("--json is not valid JSON: {err}"))?,
                ),
                None => None,
            };
            render(
                "http",
                json!({
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "body": body,
                    "json": json_value,
                    "redirect": !no_redirect,
                    "timeout": timeout,
                    "proxy": proxy,
                    "save": save,
                    "bodyOnly": body_only,
                }),
            )?
        }
        Command::Browser {
            url,
            action,
            js,
            selector,
            value,
            wait,
            width,
            height,
            full_page,
            output,
            timeout_ms,
            filter,
            headers,
            cookies,
            user_agent,
            cdp_url,
            headed,
            keep_profile,
            ignore_cert,
            json: as_json,
        } => render(
            "browser",
            json!({
                "url": url,
                "action": action,
                "js": js,
                "selector": selector,
                "value": value,
                "wait": wait,
                "width": width,
                "height": height,
                "full_page": full_page,
                "output": output,
                "timeout_ms": timeout_ms,
                "filter": filter,
                "headers": headers,
                "cookies": cookies,
                "user_agent": user_agent,
                "cdp_url": cdp_url,
                "headless": !headed,
                "keep_profile": keep_profile,
                "ignore_cert": ignore_cert,
                "json": as_json,
            }),
        )?,
        Command::Memdump {
            path,
            plugin,
            args,
            list,
            filter,
            limit,
        } => render(
            "memdump",
            json!({
                "path": path,
                "plugin": plugin,
                "args": args,
                "list": list,
                "filter": filter,
                "limit": limit,
            }),
        )?,
        Command::Doctor => render("doctor", json!({}))?,
    };

    print!("{text}");
    Ok(())
}

fn render(tool: &str, args: serde_json::Value) -> Result<String> {
    rekit_mcp::call_tool(tool, &args)
}
