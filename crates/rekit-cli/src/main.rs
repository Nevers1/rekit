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
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = 16)]
        context: usize,
    },
    /// Hex dump of a byte range.
    Hex {
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = 256)]
        length: usize,
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
        #[arg(long)]
        json: bool,
    },
    /// Imported symbols.
    Imports {
        path: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Exported symbols.
    Exports {
        path: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// Static anti-debug and anti-tamper signals.
    Antidebug {
        path: String,
        #[arg(long)]
        json: bool,
    },
    /// Crypto constants and grouped imports.
    Scan {
        path: String,
        #[arg(long, default_value = "all")]
        kind: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
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
        #[arg(long, default_value_t = 100)]
        limit: usize,
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
    },
    /// Write bytes at an offset, refusing to proceed on an unexpected value.
    Patch {
        path: String,
        #[arg(long)]
        offset: String,
        #[arg(long)]
        bytes: String,
        #[arg(long)]
        expect: String,
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
        /// Comma separated: `1,0x20,str:"hello, world"`.
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
            limit,
            context,
        } => render(
            "grep",
            json!({"path": path, "pattern": pattern, "limit": limit, "context": context}),
        )?,
        Command::Hex {
            path,
            offset,
            length,
        } => render(
            "hex",
            json!({"path": path, "offset": offset, "length": length}),
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
        Command::Entropy { path, json: false } => render("entropy", json!({"path": path}))?,
        Command::Entropy { path, json: true } => {
            serde_json::to_string_pretty(&rekit_core::entropy::analyze_entropy(&path)?)?
        }
        Command::Imports { path, limit } => {
            render("imports", json!({"path": path, "limit": limit}))?
        }
        Command::Exports { path, limit } => {
            render("exports", json!({"path": path, "limit": limit}))?
        }
        Command::Antidebug { path, json: false } => render("antidebug", json!({"path": path}))?,
        Command::Antidebug { path, json: true } => {
            serde_json::to_string_pretty(&rekit_core::antidebug::scan(&path)?)?
        }
        Command::Scan { path, kind, limit } => {
            render("scan", json!({"path": path, "kind": kind, "limit": limit}))?
        }
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
        Command::Decompile { path, class, limit } => render(
            "decompile",
            json!({"path": path, "class": class, "limit": limit}),
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
        Command::Binwalk { path, extract } => {
            render("binwalk", json!({"path": path, "extract": extract}))?
        }
        Command::Patch {
            path,
            offset,
            bytes,
            expect,
        } => render(
            "patch",
            json!({"path": path, "offset": offset, "bytes": bytes, "expect": expect}),
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
        Command::Doctor => render("doctor", json!({}))?,
    };

    print!("{text}");
    Ok(())
}

fn render(tool: &str, args: serde_json::Value) -> Result<String> {
    rekit_mcp::call_tool(tool, &args)
}
