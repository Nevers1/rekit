//! rekit-emu — run one function from a binary and print what it returns.
//!
//! This is a sidecar for `rekit`. It links Unicorn (GPL-2.0), so it carries
//! its own GPL-2.0 license while the `rekit` core stays MIT. The protocol is
//! plain command line plus, with `--json`, one JSON object on stdout.

mod emu;
mod imports;
mod jni;
mod loader;
mod syscalls;
mod vfs;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use emu::{Arg, Machine, Options, Override, ReadRange};

#[derive(Parser)]
#[command(
    name = "rekit-emu",
    version,
    about = "Emulate one function from an ELF, PE or Mach-O and print the real return value",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load a binary and call one function inside it.
    Run(RunArgs),
    /// List the functions this binary exports, with addresses.
    List(ListArgs),
    /// Call one function once per value in a range.
    Sweep(SweepArgs),
    /// Call every exported function once, with the same trial argument.
    Probe(ProbeArgs),
}

#[derive(Parser)]
struct RunArgs {
    /// Binary to load. This reads a real file, so extract archive members
    /// first (`rekit`'s `path::inner` resolution happens on its side).
    path: PathBuf,

    /// Exported function to call.
    #[arg(long, conflicts_with = "address")]
    symbol: Option<String>,

    /// Address to call, in hex or decimal.
    #[arg(long, value_parser = parse_address)]
    address: Option<u64>,

    /// Call the binary entry point.
    #[arg(long)]
    entry: bool,

    /// Arguments, comma separated: `1,0x20,str:hello`.
    #[arg(long, default_value = "", allow_hyphen_values = true)]
    args: String,

    /// Print one JSON object instead of the human summary.
    #[arg(long)]
    json: bool,

    /// Stop after this many instructions (0 means no limit).
    #[arg(long, default_value_t = 2_000_000)]
    max_insns: u64,

    /// Wall clock limit in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,

    /// Read the return value as a double from the FP register.
    #[arg(long)]
    as_double: bool,

    /// Treat the target as Thumb code (ARM only).
    #[arg(long)]
    thumb: bool,

    /// Do not answer file reads: only the binary's own memory exists.
    #[arg(long)]
    no_vfs: bool,

    /// Registers to report after the run, e.g. `rax,rbx,rcx`.
    #[arg(long, default_value = "")]
    regs: String,

    /// Read memory after the run: `addr:size:label`, repeatable.
    #[arg(long = "read", value_name = "ADDR:SIZE:LABEL")]
    read_ranges: Vec<String>,

    /// Read this many bytes at the returned pointer, e.g. `--read-ret 64`.
    #[arg(long, value_name = "BYTES")]
    read_ret: Option<usize>,

    /// Record executed instructions and print the first few.
    #[arg(long)]
    trace: bool,

    /// Answer this address with an import call: `0x401040=strlen[:32]`, repeatable.
    #[arg(long = "stub", value_name = "ADDR=NAME[:RET]")]
    stubs: Vec<String>,
}

#[derive(Parser)]
struct ListArgs {
    path: PathBuf,
    /// Only names containing this substring.
    #[arg(long)]
    filter: Option<String>,
    /// Print JSON.
    #[arg(long)]
    json: bool,
}

/// Call one function once per value in a range.
///
/// This exists so a sweep is one process, not one per input: loading a binary
/// costs more than calling a small function, and the fuzzer's result is the
/// whole range, not a single call.
#[derive(Parser)]
struct SweepArgs {
    /// Binary to load.
    path: PathBuf,

    /// Exported function to call.
    #[arg(long, conflicts_with = "address")]
    symbol: Option<String>,

    /// Address to call, in hex or decimal.
    #[arg(long, value_parser = parse_address)]
    address: Option<u64>,

    /// First value (may be negative).
    #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
    from: i64,

    /// Last value, inclusive (may be negative).
    #[arg(long, default_value_t = 4096, allow_hyphen_values = true)]
    to: i64,

    /// Step between values.
    #[arg(long, default_value_t = 1, allow_hyphen_values = true)]
    step: i64,

    /// Maximum number of runs.
    #[arg(long, default_value_t = 500)]
    limit: usize,

    /// Print one JSON object instead of the human table.
    #[arg(long)]
    json: bool,

    /// Stop after this many instructions per run (0 means no limit).
    #[arg(long, default_value_t = 2_000_000)]
    max_insns: u64,

    /// Wall clock limit per run in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    timeout_ms: u64,

    /// Treat the target as Thumb code (ARM only).
    #[arg(long)]
    thumb: bool,

    /// Do not answer file reads: only the binary's own memory exists.
    #[arg(long)]
    no_vfs: bool,

    /// Answer this address with an import call: `0x401040=strlen[:32]`, repeatable.
    #[arg(long = "stub", value_name = "ADDR=NAME[:RET]")]
    stubs: Vec<String>,
}

/// One call per exported function, in one process.
///
/// This is the answer to "where is the interesting function": it does not claim
/// what any of them do, only which ones return something, which ones fall over
/// on a trial argument and which ones never come back.
#[derive(Parser)]
struct ProbeArgs {
    /// Binary to load.
    path: PathBuf,

    /// Trial argument, same syntax as `run --args`.
    #[arg(long, default_value = "1", allow_hyphen_values = true)]
    arg: String,

    /// How many functions to call, in address order.
    #[arg(long, default_value_t = 120)]
    limit: usize,

    /// Print one JSON object instead of the human table.
    #[arg(long)]
    json: bool,

    /// Stop after this many instructions per function (0 means no limit).
    #[arg(long, default_value_t = 20_000)]
    max_insns: u64,

    /// Wall clock limit per function in milliseconds.
    #[arg(long, default_value_t = 500)]
    timeout_ms: u64,

    /// Treat the targets as Thumb code (ARM only).
    #[arg(long)]
    thumb: bool,

    /// Do not answer file reads: only the binary's own memory exists.
    #[arg(long)]
    no_vfs: bool,
}

fn parse_address(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let value = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse::<u64>()
    };
    value.map_err(|_| format!("not a number: {text}"))
}

/// Split on commas that are not inside quotes, so `str:"Hello, world"` works.
fn split_args(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in text.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ',' if !quoted => {
                out.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() || !out.is_empty() {
        out.push(current.trim().to_string());
    }
    out.retain(|s| !s.is_empty());
    out
}

fn parse_args(text: &str) -> Result<Vec<Arg>> {
    let mut out = Vec::new();
    for token in split_args(text) {
        if token == "env" {
            out.push(Arg::Env);
            continue;
        }
        if let Some(rest) = token.strip_prefix("str:") {
            let value = rest.trim().trim_matches('"').to_string();
            out.push(Arg::Str(value));
            continue;
        }
        // `f:3` is a double that happens to be written without a point; a
        // token that has one is a double on sight.
        if let Some(rest) = token.strip_prefix("f:") {
            let value = rest
                .trim()
                .parse::<f64>()
                .with_context(|| format!("bad float argument {token}"))?;
            out.push(Arg::Float(value));
            continue;
        }
        if token.contains('.') || token.contains('e') || token.contains('E') {
            if let Ok(value) = token.parse::<f64>() {
                out.push(Arg::Float(value));
                continue;
            }
        }
        let value = if let Some(hex) = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).with_context(|| format!("bad hex argument {token}"))?
        } else if let Ok(v) = token.parse::<u64>() {
            v
        } else if let Ok(v) = token.parse::<i64>() {
            v as u64
        } else {
            bail!("argument {token:?} is neither a number nor str:...");
        };
        out.push(Arg::Num(value));
    }
    Ok(out)
}

/// `addr:size:label,addr:size` — the label is optional and defaults to the
/// address, because most reads exist to answer "what is at 0x… now".
fn parse_reads(specs: &[String]) -> Result<Vec<ReadRange>> {
    let mut out = Vec::new();
    for item in specs.iter().flat_map(|s| split_args(s)) {
        let mut parts = item.splitn(3, ':');
        let addr_text = parts.next().unwrap_or_default();
        let addr = parse_address(addr_text)
            .map_err(|err| anyhow::anyhow!("bad read address {addr_text:?}: {err}"))?;
        let size_text = parts.next().unwrap_or("64");
        let size: usize = size_text
            .trim()
            .parse()
            .with_context(|| format!("bad read size {size_text:?} in {item:?}"))?;
        if size == 0 {
            bail!("read of 0 bytes at {addr_text}: ask for at least one");
        }
        let label = parts
            .next()
            .map(str::to_string)
            .unwrap_or_else(|| format!("0x{addr:x}"));
        out.push(ReadRange { addr, size, label });
    }
    // An empty `--read ""` should mean "none", not one unparseable entry.
    out.retain(|r| r.size > 0);
    Ok(out)
}

fn parse_regs(spec: &str) -> Vec<String> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `0x401040=strlen:32` — the address is answered as if it were a call to that
/// import, and 32 is the value it returns instead of the stub's own answer.
fn parse_stubs(specs: &[String]) -> Result<HashMap<u64, Override>> {
    let mut out = HashMap::new();
    for item in specs.iter().flat_map(|s| split_args(s)) {
        let Some((addr_text, rest)) = item.split_once('=') else {
            bail!("stub {item:?} is not addr=name: give `0x401040=strlen[:32]`");
        };
        let addr = parse_address(addr_text.trim())
            .map_err(|err| anyhow::anyhow!("bad stub address {addr_text:?}: {err}"))?;
        let (name, ret) = match rest.rsplit_once(':') {
            Some((name, ret)) => {
                let ret = parse_address(ret.trim()).map_err(|err| {
                    anyhow::anyhow!("bad forced return {ret:?} in stub {item:?}: {err}")
                })?;
                (name.trim(), Some(ret))
            }
            None => (rest.trim(), None),
        };
        if name.is_empty() {
            bail!("stub {item:?} has no import name");
        }
        out.insert(
            addr,
            Override {
                name: name.to_string(),
                ret,
            },
        );
    }
    Ok(out)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("rekit-emu: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::List(args) => list(args),
        Command::Run(args) => run_one(args),
        Command::Sweep(args) => sweep(args),
        Command::Probe(args) => probe(args),
    }
}

fn read_binary(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn list(args: ListArgs) -> Result<ExitCode> {
    let bytes = read_binary(&args.path)?;
    let loaded =
        loader::load(&bytes).with_context(|| format!("cannot parse {}", args.path.display()))?;
    let mut names: Vec<(String, u64)> = loaded
        .symbols
        .iter()
        .filter(|(name, _)| match &args.filter {
            Some(f) => name.contains(f.as_str()),
            None => true,
        })
        .cloned()
        .collect();
    names.sort_by(|a, b| a.0.cmp(&b.0));
    if args.json {
        let rows: Vec<serde_json::Value> = names
            .iter()
            .map(|(name, addr)| serde_json::json!({ "name": name, "address": format!("0x{addr:x}") }))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "arch": loaded.arch.name(),
                "platform": loaded.platform.name(),
                "format": loaded.format,
                "base": format!("0x{:x}", loaded.base),
                "symbols": rows,
            }))?
        );
    } else {
        for (name, addr) in &names {
            println!("{addr:#012x}  {name}");
        }
        eprintln!("{} symbols", names.len());
    }
    Ok(ExitCode::SUCCESS)
}

fn run_one(args: RunArgs) -> Result<ExitCode> {
    let bytes = read_binary(&args.path)?;
    let loaded =
        loader::load(&bytes).with_context(|| format!("cannot parse {}", args.path.display()))?;

    let (target, symbol) =
        resolve_target(&loaded, args.symbol.as_deref(), args.address, args.entry)?;

    let cargs = parse_args(&args.args)?;
    let opts = Options {
        max_insns: args.max_insns,
        timeout_ms: args.timeout_ms,
        vfs: !args.no_vfs,
        as_double: args.as_double,
        thumb: args.thumb,
        trace: args.trace,
        regs: parse_regs(&args.regs),
        read_ranges: parse_reads(&args.read_ranges)?,
        read_ret: args.read_ret.unwrap_or(0),
        overrides: parse_stubs(&args.stubs)?,
    };

    let mut machine = Machine::new(loaded, &opts)?;
    let report = machine.run(target, symbol.as_deref(), &cargs, &opts)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("arch      {} / {}", report.arch, report.platform);
        match &report.symbol {
            Some(name) => println!("target    {name} at {}", report.address),
            None => println!("target    {}", report.address),
        }
        println!("stop      {}", report.stop);
        match report.ret.f64 {
            Some(f) => println!(
                "return    {} ({}) as double {f}",
                report.ret.hex, report.ret.i64
            ),
            None => println!("return    {} ({})", report.ret.hex, report.ret.i64),
        }
        if !report.calls.is_empty() {
            let calls: Vec<String> = report
                .calls
                .iter()
                .map(|c| format!("{} x{}", c.name, c.count))
                .collect();
            println!("calls     {}", calls.join(", "));
        }
        if !report.unimplemented.is_empty() {
            println!("not implemented  {}", report.unimplemented.join(", "));
        }
        if !report.files.is_empty() {
            println!("files     {}", report.files.join(", "));
        }
        if !report.output.is_empty() {
            println!("output    {}", report.output.trim_end());
        }
        for (name, value) in &report.regs {
            println!("reg       {name} {value}");
        }
        for read in &report.reads {
            match (&read.hex, &read.error) {
                (Some(hex), _) => {
                    println!("read      {} {} {}", read.label, read.addr, hex);
                    if let Some(ascii) = &read.ascii {
                        println!("            |{ascii}|");
                    }
                }
                (None, Some(error)) => println!("read      {} {} {error}", read.label, read.addr),
                _ => {}
            }
        }
        for line in &report.disasm {
            println!("trace     {line}");
        }
        for line in &report.overrides {
            println!("stub      {line}");
        }
        for note in &report.notes {
            println!("note      {note}");
        }
        println!("elapsed   {} ms", report.elapsed_ms);
    }

    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Turn `--symbol` / `--address` / `--entry` into an address, naming the
/// symbol when it was a name. The "did you mean" list matters here: a fuzz
/// sweep against a misspelt export otherwise reports zero runs.
fn resolve_target(
    loaded: &loader::Loaded,
    symbol: Option<&str>,
    address: Option<u64>,
    entry: bool,
) -> Result<(u64, Option<String>)> {
    if let Some(address) = address {
        return Ok((address, None));
    }
    if let Some(name) = symbol {
        return match loaded.find_symbol(name) {
            Some(addr) => Ok((addr, Some(name.to_string()))),
            None => {
                let mut close: Vec<&str> = loaded
                    .symbols
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .filter(|n| n.contains(name))
                    .take(10)
                    .collect();
                close.sort_unstable();
                let hint = if close.is_empty() {
                    String::new()
                } else {
                    format!("; did you mean: {}", close.join(", "))
                };
                bail!("symbol {name:?} is not exported by this file{hint}");
            }
        };
    }
    if entry {
        return Ok((loaded.entry, None));
    }
    bail!("pass --symbol, --address or --entry")
}

/// One value per run, each in a fresh machine: a function that writes to its
/// own globals must not change the answer for the next input.
fn sweep(args: SweepArgs) -> Result<ExitCode> {
    if args.step <= 0 {
        bail!("--step must be positive");
    }
    if args.limit == 0 {
        bail!("--limit must be at least 1");
    }
    if args.from > args.to {
        bail!("--from {} is greater than --to {}", args.from, args.to);
    }

    let bytes = read_binary(&args.path)?;
    let parsed =
        loader::load(&bytes).with_context(|| format!("cannot parse {}", args.path.display()))?;
    let (target, symbol) = resolve_target(&parsed, args.symbol.as_deref(), args.address, false)?;
    drop(parsed);

    let vfs = !args.no_vfs;
    let stubs = parse_stubs(&args.stubs)?;

    let mut results: Vec<(i64, emu::Report)> = Vec::new();
    let mut value = args.from;
    while value <= args.to && results.len() < args.limit {
        let loaded = loader::load(&bytes)?;
        // A sweep has no trace and no register dump: the answer is one line per
        // input, and paying for the code hook on every instruction would make
        // every run slower for information nobody reads.
        let opts = Options {
            max_insns: args.max_insns,
            timeout_ms: args.timeout_ms,
            vfs,
            as_double: false,
            thumb: args.thumb,
            trace: false,
            regs: Vec::new(),
            read_ranges: Vec::new(),
            read_ret: 0,
            overrides: stubs.clone(),
        };
        let mut machine = Machine::new(loaded, &opts)?;
        let report = machine.run(target, symbol.as_deref(), &[Arg::Num(value as u64)], &opts)?;
        results.push((value, report));
        match value.checked_add(args.step) {
            Some(next) => value = next,
            None => break,
        }
    }

    if results.is_empty() {
        bail!("no runs: check --from, --to and --limit");
    }

    if args.json {
        // Each row repeats what the envelope already says (arch, address), so
        // only what changes per run is kept — a 500-run sweep is otherwise
        // megabytes of identical keys.
        let rows: Vec<serde_json::Value> = results
            .iter()
            .map(|(value, report)| {
                serde_json::json!({
                    "value": value,
                    "ok": report.ok,
                    "stop": report.stop,
                    "return": report.ret,
                    "fault": report.fault,
                    "calls": report.calls,
                    "unimplemented": report.unimplemented,
                    "notes": report.notes,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "arch": results[0].1.arch,
                "platform": results[0].1.platform,
                "address": results[0].1.address,
                "symbol": symbol,
                "runs": rows,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }

    for (value, report) in &results {
        let fault = match &report.fault {
            Some(fault) => format!(
                "  fault: {} at {:#x} (size {}) from pc {:#x}",
                fault.access, fault.address, fault.size, fault.pc
            ),
            None => String::new(),
        };
        println!(
            "{value:>12}  {:<14} return {} ({}){fault}",
            report.stop, report.ret.hex, report.ret.i64
        );
    }
    if results.len() >= args.limit && args.from + (args.limit as i64) * args.step <= args.to {
        eprintln!("stopped at --limit {}", args.limit);
    }

    Ok(ExitCode::SUCCESS)
}

struct ProbeRow {
    name: String,
    address: u64,
    report: Option<emu::Report>,
    error: Option<String>,
}

fn probe(args: ProbeArgs) -> Result<ExitCode> {
    if args.limit == 0 {
        bail!("--limit must be at least 1");
    }
    let bytes = read_binary(&args.path)?;
    let parsed =
        loader::load(&bytes).with_context(|| format!("cannot parse {}", args.path.display()))?;

    // Address order is stable and groups neighbours (a class's methods land
    // next to each other), which is what makes the output readable.
    let mut targets: Vec<(String, u64)> = parsed.symbols.clone();
    targets.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    targets.truncate(args.limit);
    let arch = parsed.arch.name();
    let platform = parsed.platform.name();
    drop(parsed);

    if targets.is_empty() {
        bail!("no exported functions: a stripped binary gives probe nothing to call");
    }

    let cargs = parse_args(&args.arg)?;
    let mut rows: Vec<ProbeRow> = Vec::new();
    for (name, address) in &targets {
        let mut row = ProbeRow {
            name: name.clone(),
            address: *address,
            report: None,
            error: None,
        };
        match loader::load(&bytes).and_then(|loaded| {
            let opts = Options {
                max_insns: args.max_insns,
                timeout_ms: args.timeout_ms,
                vfs: !args.no_vfs,
                as_double: false,
                thumb: args.thumb,
                trace: false,
                regs: Vec::new(),
                read_ranges: Vec::new(),
                read_ret: 0,
                overrides: HashMap::new(),
            };
            let mut machine = Machine::new(loaded, &opts)?;
            machine.run(*address, Some(name), &cargs, &opts)
        }) {
            Ok(report) => row.report = Some(report),
            // One function the emulator cannot even start must not lose the
            // other 119 answers.
            Err(err) => row.error = Some(format!("{err:#}")),
        }
        rows.push(row);
    }

    if args.json {
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|row| {
                let address = format!("0x{:x}", row.address);
                match &row.report {
                    Some(report) => serde_json::json!({
                        "name": row.name,
                        "address": address,
                        "ok": report.ok,
                        "stop": report.stop,
                        "return": report.ret,
                        "fault": report.fault,
                        "unimplemented": report.unimplemented,
                    }),
                    None => serde_json::json!({
                        "name": row.name,
                        "address": address,
                        "ok": false,
                        "error": row.error,
                    }),
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "arch": arch,
                "platform": platform,
                "arg": args.arg,
                "runs": json_rows,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }

    for row in &rows {
        let verdict = match (&row.report, &row.error) {
            (_, Some(error)) => format!("could not start: {error}"),
            (Some(report), _) => match (&report.fault, report.ok) {
                (Some(fault), _) => format!("fault {} at {:#x}", fault.access, fault.address),
                (None, false) => report.stop.clone(),
                (None, true) => format!("return {} ({})", report.ret.hex, report.ret.i64),
            },
            (None, None) => "no report".to_string(),
        };
        println!("{:>12}  {:<40} {verdict}", row.address, row.name);
    }
    eprintln!("{} functions probed", rows.len());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_double_argument_is_recognised_by_its_shape() {
        let args = parse_args("3,3.5,f:7,1e9").unwrap();
        assert!(matches!(args[0], Arg::Num(3)));
        assert!(matches!(args[1], Arg::Float(v) if v == 3.5));
        // `f:7` is a double written without a point, which the parser cannot
        // guess at.
        assert!(matches!(args[2], Arg::Float(v) if v == 7.0));
        assert!(matches!(args[3], Arg::Float(v) if v == 1e9));
    }

    #[test]
    fn splits_plain_arguments() {
        assert_eq!(split_args("1,0x20,3"), vec!["1", "0x20", "3"]);
        assert!(split_args("").is_empty());
        assert!(split_args("  ,  ").is_empty());
    }

    #[test]
    fn keeps_commas_inside_quotes() {
        assert_eq!(
            split_args(r#"1,str:"Hello, RE!",2"#),
            vec!["1", r#"str:"Hello, RE!""#, "2"]
        );
    }

    #[test]
    fn parses_numbers_and_strings() {
        let args = parse_args(r#"3,0x10,-1,str:"a,b""#).unwrap();
        assert_eq!(args.len(), 4);
        assert!(matches!(args[0], Arg::Num(3)));
        assert!(matches!(args[1], Arg::Num(16)));
        assert!(matches!(args[2], Arg::Num(n) if n == u64::MAX));
        match &args[3] {
            Arg::Str(s) => assert_eq!(s, "a,b"),
            _ => panic!("expected a string argument"),
        }
    }

    #[test]
    fn an_env_argument_is_recognised() {
        let args = parse_args("env,1").unwrap();
        assert!(matches!(args[0], Arg::Env));
        assert!(matches!(args[1], Arg::Num(1)));
    }

    #[test]
    fn rejects_garbage_arguments() {
        assert!(parse_args("1,nonsense").is_err());
    }

    #[test]
    fn parses_hex_and_decimal_addresses() {
        assert_eq!(parse_address("0x4010").unwrap(), 0x4010);
        assert_eq!(parse_address("4192").unwrap(), 4192);
        assert!(parse_address("0xzz").is_err());
    }

    #[test]
    fn a_read_needs_an_address_a_size_and_gets_a_label() {
        let reads = parse_reads(&["0x20001000:16:buf".into(), "0x20:8".into()]).unwrap();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].addr, 0x20001000);
        assert_eq!(reads[0].size, 16);
        assert_eq!(reads[0].label, "buf");
        // No label: the address is the label, because that is what was asked.
        assert_eq!(reads[1].label, "0x20");
    }

    #[test]
    fn a_zero_length_read_is_refused() {
        assert!(parse_reads(&["0x2000:0".into()]).is_err());
    }

    #[test]
    fn registers_are_split_and_trimmed() {
        assert_eq!(parse_regs(" rax, rdi ,"), vec!["rax", "rdi"]);
        assert!(parse_regs("").is_empty());
    }

    #[test]
    fn a_stub_may_name_the_value_to_return() {
        let stubs = parse_stubs(&["0x401040=strlen".into(), "0x401050=strlen:32".into()]).unwrap();
        assert_eq!(stubs.len(), 2);
        assert_eq!(stubs[&0x401040].name, "strlen");
        assert_eq!(stubs[&0x401040].ret, None);
        assert_eq!(stubs[&0x401050].ret, Some(32));
    }

    #[test]
    fn a_stub_without_a_name_is_refused() {
        assert!(parse_stubs(&["0x401040".into()]).is_err());
        assert!(parse_stubs(&["0x401040=:1".into()]).is_err());
    }
}
