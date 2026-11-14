//! rekit-emu — run one function from a binary and print what it returns.
//!
//! This is a sidecar for `rekit`. It links Unicorn (GPL-2.0), so it carries
//! its own GPL-2.0 license while the `rekit` core stays MIT. The protocol is
//! plain command line plus, with `--json`, one JSON object on stdout.

mod emu;
mod imports;
mod loader;
mod syscalls;
mod vfs;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use emu::{Arg, Machine, Options};

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
        if let Some(rest) = token.strip_prefix("str:") {
            let value = rest.trim().trim_matches('"').to_string();
            out.push(Arg::Str(value));
            continue;
        }
        let value = if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
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
    }
}

fn read_binary(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
}

fn list(args: ListArgs) -> Result<ExitCode> {
    let bytes = read_binary(&args.path)?;
    let loaded = loader::load(&bytes).with_context(|| format!("cannot parse {}", args.path.display()))?;
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

    let (target, symbol) = if let Some(address) = args.address {
        (address, None)
    } else if let Some(name) = &args.symbol {
        match loaded.find_symbol(name) {
            Some(addr) => (addr, Some(name.clone())),
            None => {
                let mut close: Vec<&str> = loaded
                    .symbols
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .filter(|n| n.contains(name.as_str()))
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
        }
    } else if args.entry {
        (loaded.entry, None)
    } else {
        bail!("pass --symbol, --address or --entry");
    };

    let cargs = parse_args(&args.args)?;
    let opts = Options {
        max_insns: args.max_insns,
        timeout_ms: args.timeout_ms,
        vfs: !args.no_vfs,
        as_double: args.as_double,
        thumb: args.thumb,
    };

    let mut machine = Machine::new(loaded, opts.vfs)?;
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
            Some(f) => println!("return    {} ({}) as double {f}", report.ret.hex, report.ret.i64),
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_garbage_arguments() {
        assert!(parse_args("1,nonsense").is_err());
    }

    #[test]
    fn parses_hex_and_decimal_addresses() {
        assert_eq!(parse_address("0x4010").unwrap(), 0x4010);
        assert_eq!(parse_address("4192").unwrap(), 4192);
        assert!(parse_address("0xzz").is_err());
    }
}
