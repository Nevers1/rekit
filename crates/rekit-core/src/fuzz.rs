//! One function, many inputs: probe, sweep, magic, crash.
//!
//! The work happens in `rekit-emu`: a sweep is a single process that loads the
//! binary once and calls the function per value, because loading costs more
//! than calling a small function and a sweep of five hundred inputs would
//! otherwise pay that price five hundred times. This module only decides the
//! range, parses the report and turns a table of runs into the answer the
//! caller actually asked for — where the behaviour changes, which input
//! returns the magic value, which one crashes.
//!
//! Each run gets a fresh machine inside the emulator, so a function that
//! writes to its own globals cannot taint the next input.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::decompilers::parse_address;
use crate::emulate::{
    find_binary, prepare_path, require_available, run_request, Request as Emulate,
};
use crate::external::run as spawn;

/// A sweep trades precision for coverage: a function that never returns would
/// otherwise burn the full instruction budget on every input.
const SWEEP_MAX_INSNS: u64 = 200_000;
const SWEEP_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_LIMIT: usize = 500;

#[derive(Debug, Clone)]
pub struct Request {
    pub path: String,
    pub symbol: Option<String>,
    pub address: Option<String>,
    /// probe | sweep | magic | crash
    pub mode: String,
    /// probe only: `42`, `0x20`, `str:hello`
    pub args: String,
    pub start: i64,
    pub end: i64,
    pub step: i64,
    /// magic only: the value the function should return.
    pub target: String,
    pub limit: usize,
    pub vfs: bool,
    pub thumb: bool,
    /// Print the emulator's own JSON instead of a summary.
    pub json: bool,
}

impl Default for Request {
    fn default() -> Self {
        Request {
            path: String::new(),
            symbol: None,
            address: None,
            mode: "probe".to_string(),
            args: String::new(),
            start: 0,
            end: 4096,
            step: 1,
            target: "1".to_string(),
            limit: DEFAULT_LIMIT,
            vfs: true,
            thumb: false,
            json: false,
        }
    }
}

/// One call of the function.
#[derive(Debug, Deserialize, Default)]
struct Report {
    #[serde(default)]
    arch: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    stop: String,
    #[serde(rename = "return", default)]
    ret: Ret,
    #[serde(default)]
    output: String,
    #[serde(default)]
    calls: Vec<Call>,
    #[serde(default)]
    unimplemented: Vec<String>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    fault: Option<Fault>,
    #[serde(default)]
    elapsed_ms: u64,
    /// Present in a sweep row, absent from a single run.
    #[serde(default)]
    value: Option<i64>,
    #[serde(default)]
    ok: bool,
}

#[derive(Debug, Deserialize, Default)]
struct Ret {
    #[serde(default)]
    hex: String,
    #[serde(rename = "i64", default)]
    signed: i64,
    #[serde(rename = "u64", default)]
    unsigned: u64,
    #[serde(default)]
    f64: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Call {
    #[serde(default)]
    name: String,
    #[serde(default)]
    count: u64,
}

/// Where the emulation hit memory it should not have. The address is the
/// useful part: it says whether an input overran a buffer or dereferenced a
/// value that came from the input.
#[derive(Debug, Deserialize)]
struct Fault {
    access: String,
    address: u64,
    size: u64,
    pc: u64,
}

/// What a sweep prints: the header plus one row per value.
#[derive(Debug, Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    arch: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    runs: Vec<Report>,
}

pub fn run(req: &Request) -> Result<String> {
    let mode = req.mode.trim().to_ascii_lowercase();
    let mode = if mode.is_empty() {
        "probe".to_string()
    } else {
        mode
    };
    if !matches!(mode.as_str(), "probe" | "sweep" | "magic" | "crash") {
        bail!("unknown mode {mode:?}: use probe, sweep, magic or crash");
    }
    if req
        .symbol
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
        && req.address.is_none()
    {
        bail!("pass symbol or address: a run needs a function to call");
    }
    if req.symbol.is_some() && req.address.is_some() {
        bail!("pass either symbol or address, not both");
    }

    require_available()?;
    let path = prepare_path(&req.path)?;

    match mode.as_str() {
        "probe" => probe(&path, req),
        _ => sweep(&path, req, &mode),
    }
}

fn probe(path: &str, req: &Request) -> Result<String> {
    let args = match req.args.trim() {
        "" => "0".to_string(),
        args => args.to_string(),
    };
    let inner = Emulate {
        path: path.to_string(),
        symbol: req.symbol.clone().filter(|s| !s.trim().is_empty()),
        address: match &req.address {
            Some(address) => Some(parse_address(address)?),
            None => None,
        },
        entry: false,
        args: args.clone(),
        max_insns: 0,
        timeout_ms: 0,
        vfs: req.vfs,
        as_double: false,
        thumb: req.thumb,
        json: true,
    };
    let raw = run_request(&inner)?;
    if req.json {
        return Ok(ensure_newline(raw));
    }

    let report: Report = serde_json::from_str(&raw)
        .context("rekit-emu printed something that is not a run report")?;

    let mut out = format!("fuzz: {path}  mode probe\n");
    out.push_str(&format!(
        "{}/{}  target {}  input {args}\n",
        if report.arch.is_empty() {
            "?"
        } else {
            report.arch.as_str()
        },
        if report.platform.is_empty() {
            "?"
        } else {
            report.platform.as_str()
        },
        describe_target(&report),
    ));
    out.push_str(&format!("stop: {}\n", report.stop));
    out.push_str(&format!("return: {}\n", describe_return(&report.ret)));
    if !report.calls.is_empty() {
        let calls: Vec<String> = report
            .calls
            .iter()
            .map(|call| format!("{} x{}", call.name, call.count))
            .collect();
        out.push_str(&format!("calls: {}\n", calls.join(", ")));
    }
    if !report.unimplemented.is_empty() {
        out.push_str(&format!(
            "not implemented: {}\n",
            report.unimplemented.join(", ")
        ));
    }
    if !report.files.is_empty() {
        out.push_str(&format!("files read: {}\n", report.files.join(", ")));
    }
    if let Some(fault) = &report.fault {
        out.push_str(&format!("{}\n", describe_fault(fault)));
    }
    if !report.output.trim().is_empty() {
        out.push_str(&format!("output:\n{}\n", report.output.trim_end()));
    }
    for note in &report.notes {
        out.push_str(&format!("note: {note}\n"));
    }
    out.push_str(&format!("elapsed: {} ms\n", report.elapsed_ms));
    Ok(out)
}

fn sweep(path: &str, req: &Request, mode: &str) -> Result<String> {
    if req.step < 1 {
        bail!("step must be at least 1, not {}", req.step);
    }
    if req.end < req.start {
        bail!("start {} is greater than end {}", req.start, req.end);
    }
    let limit = req.limit.clamp(1, 100_000);
    let exe = find_binary().context(
        "rekit-emu is not installed; build it with `cargo build --release -p rekit-emu` \
         or point REKIT_EMU at the binary",
    )?;

    let mut args: Vec<String> = vec![
        "sweep".into(),
        path.to_string(),
        "--json".into(),
        "--from".into(),
        req.start.to_string(),
        "--to".into(),
        req.end.to_string(),
        "--step".into(),
        req.step.to_string(),
        "--limit".into(),
        limit.to_string(),
        "--max-insns".into(),
        SWEEP_MAX_INSNS.to_string(),
        "--timeout-ms".into(),
        SWEEP_TIMEOUT_MS.to_string(),
    ];
    match req
        .symbol
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(symbol) => {
            args.push("--symbol".into());
            args.push(symbol.to_string());
        }
        None => {
            let address = parse_address(req.address.as_deref().unwrap_or_default())?;
            args.push("--address".into());
            args.push(format!("0x{address:x}"));
        }
    }
    if req.thumb {
        args.push("--thumb".into());
    }
    if !req.vfs {
        args.push("--no-vfs".into());
    }

    // Every run is bounded, so the whole sweep is too: one budget per run plus
    // room for the process to start and parse its arguments.
    // The target is validated before the sweep runs: searching for a value the
    // caller mistyped would waste the whole range and then answer "not found".
    let magic_target = if mode == "magic" {
        Some(parse_target(&req.target)?)
    } else {
        None
    };

    let expected = expected_runs(req, limit) as u64;
    let budget = Duration::from_millis(expected * (SWEEP_TIMEOUT_MS + 500) + 30_000);
    let tool = exe.to_string_lossy().to_string();
    let raw = spawn(&tool, &args, budget)?;
    if req.json {
        return Ok(ensure_newline(raw));
    }

    let env: Envelope = serde_json::from_str(&raw)
        .context("rekit-emu printed something that is not a sweep report")?;
    let wanted = expected_runs(req, limit);
    Ok(render_sweep(
        req,
        mode,
        &env,
        wanted < total_runs(req),
        magic_target,
    ))
}

/// How many runs the request asks for, after the limit.
fn expected_runs(req: &Request, limit: usize) -> usize {
    total_runs(req).min(limit)
}

/// How many values the range holds, before the limit.
fn total_runs(req: &Request) -> usize {
    if req.step < 1 || req.end < req.start {
        return 0;
    }
    let count = (req.end - req.start) / req.step + 1;
    count.max(0) as usize
}

fn render_sweep(
    req: &Request,
    mode: &str,
    env: &Envelope,
    truncated: bool,
    magic_target: Option<u64>,
) -> String {
    let mut out = format!("fuzz  mode {mode}  {}\n", describe_target_env(env));
    out.push_str(&format!(
        "{}/{}  range {}..{} step {}\n",
        if env.arch.is_empty() {
            "?"
        } else {
            env.arch.as_str()
        },
        if env.platform.is_empty() {
            "?"
        } else {
            env.platform.as_str()
        },
        req.start,
        req.end,
        req.step
    ));
    out.push_str(&format!(
        "runs: {}{}\n",
        env.runs.len(),
        if truncated {
            format!(" (limit {})", req.limit)
        } else {
            String::new()
        }
    ));
    if env.runs.is_empty() {
        out.push_str("no runs happened — check the range\n");
        return out;
    }

    let crashes: Vec<&Report> = env.runs.iter().filter(|run| !run.ok).collect();

    if mode == "magic" {
        return render_magic(req, env, out, &crashes, magic_target.unwrap_or(1));
    }
    if mode == "crash" {
        return render_crash(env, out, &crashes);
    }

    // Group by return value, keeping first-appearance order so the table reads
    // like the range does.
    let mut groups: Vec<(i64, Vec<i64>)> = Vec::new();
    for run in env.runs.iter().filter(|run| run.ok) {
        let value = run.value.unwrap_or_default();
        match groups.iter_mut().find(|(ret, _)| *ret == run.ret.signed) {
            Some((_, values)) => values.push(value),
            None => groups.push((run.ret.signed, vec![value])),
        }
    }

    if groups.is_empty() {
        out.push_str("every run failed — mode crash shows where\n");
        return out;
    }
    out.push_str(&format!("distinct returns: {}\n", groups.len()));
    for (ret, values) in &groups {
        let (low, high) = (
            values.iter().min().copied().unwrap_or_default(),
            values.iter().max().copied().unwrap_or_default(),
        );
        if values.len() == 1 {
            out.push_str(&format!("  {ret:>12}: 1 value ({low})\n"));
        } else {
            out.push_str(&format!(
                "  {ret:>12}: {} values, {low}..{high}\n",
                values.len()
            ));
        }
    }

    // The thresholds are the point of a sweep: a table of ranges says what the
    // function returns, the transitions say where that answer changes.
    let transitions = transitions(env, req.step);
    if !transitions.is_empty() {
        out.push_str("transitions:\n");
        for line in transitions.iter().take(20) {
            out.push_str(&format!("  {line}\n"));
        }
        if transitions.len() > 20 {
            out.push_str(&format!("  ... {} more\n", transitions.len() - 20));
        }
    }

    if !crashes.is_empty() {
        out.push_str(&format!("\ncrashes: {}\n", crashes.len()));
        for line in crash_lines(&crashes, 10) {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}

fn render_magic(
    req: &Request,
    env: &Envelope,
    mut out: String,
    crashes: &[&Report],
    target: u64,
) -> String {
    let hits: Vec<&Report> = env
        .runs
        .iter()
        .filter(|run| run.ok && (run.ret.unsigned == target || run.ret.signed == target as i64))
        .collect();

    out.push_str(&format!("looking for a return of {}\n", req.target));
    if hits.is_empty() {
        out.push_str(&format!(
            "nothing in {}..{} returns it\n",
            req.start, req.end
        ));
        let mut seen: Vec<i64> = Vec::new();
        for run in env.runs.iter().filter(|run| run.ok) {
            if !seen.contains(&run.ret.signed) {
                seen.push(run.ret.signed);
            }
        }
        if seen.is_empty() {
            out.push_str("no run returned anything — mode crash shows where they stop\n");
        } else {
            let shown: Vec<String> = seen.iter().take(20).map(i64::to_string).collect();
            out.push_str(&format!("reachable returns: {}\n", shown.join(", ")));
            if seen.len() > 20 {
                out.push_str(&format!("  ... {} more\n", seen.len() - 20));
            }
        }
        if !crashes.is_empty() {
            out.push_str(&format!("\ncrashes: {}\n", crashes.len()));
            for line in crash_lines(crashes, 10) {
                out.push_str(&format!("  {line}\n"));
            }
        }
        out.push_str(
            "If the function wants a pointer rather than a number, probe it with \
             args=str:text.\n",
        );
        return out;
    }

    out.push_str(&format!("found {} input(s):\n", hits.len()));
    for run in hits.iter().take(30) {
        out.push_str(&format!(
            "  input {} -> {}\n",
            run.value.unwrap_or_default(),
            describe_return(&run.ret)
        ));
    }
    if hits.len() > 30 {
        out.push_str(&format!("... {} more\n", hits.len() - 30));
    }
    out
}

fn render_crash(env: &Envelope, mut out: String, crashes: &[&Report]) -> String {
    out.push_str(&format!(
        "crashes: {} of {}\n",
        crashes.len(),
        env.runs.len()
    ));
    if crashes.is_empty() {
        out.push_str(
            "nothing crashed in this range. A function that ignores its input \
             cannot be fuzzed this way; different import stubs or a pointer \
             argument may be needed.\n",
        );
        return out;
    }
    for run in crashes.iter().take(20) {
        out.push_str(&format!("\ninput {}\n", run.value.unwrap_or_default()));
        out.push_str(&format!("  stopped: {}\n", run.stop));
        if let Some(fault) = &run.fault {
            out.push_str(&format!("  {}\n", describe_fault(fault)));
        }
        if !run.calls.is_empty() {
            out.push_str(&format!("  calls: {}\n", describe_calls(run)));
        }
        if !run.unimplemented.is_empty() {
            out.push_str(&format!(
                "  not implemented: {}\n",
                run.unimplemented.join(", ")
            ));
        }
        for note in &run.notes {
            // With a recorded fault the note only repeats it.
            if run.fault.is_some() && note.starts_with("emulation stopped") {
                continue;
            }
            out.push_str(&format!("  note: {note}\n"));
        }
    }
    if crashes.len() > 20 {
        out.push_str(&format!("\n... {} more crashed\n", crashes.len() - 20));
    }
    out
}

/// Adjacent runs that disagree: the input where the answer changes.
///
/// Only genuinely neighbouring values count. Reporting a change across a gap
/// — a crashed input, a coarser step — would point at a boundary that was
/// never observed.
fn transitions(env: &Envelope, step: i64) -> Vec<String> {
    let mut out = Vec::new();
    let mut previous: Option<&Report> = None;
    for run in env.runs.iter() {
        if !run.ok {
            previous = None;
            continue;
        }
        if let Some(before) = previous {
            let adjacent = run.value.unwrap_or_default() - before.value.unwrap_or_default() == step;
            if adjacent && before.ret.signed != run.ret.signed {
                out.push(format!(
                    "input {} -> {}: return {} -> {}",
                    before.value.unwrap_or_default(),
                    run.value.unwrap_or_default(),
                    before.ret.signed,
                    run.ret.signed
                ));
            }
        }
        previous = Some(run);
    }
    out
}

fn crash_lines(crashes: &[&Report], limit: usize) -> Vec<String> {
    crashes
        .iter()
        .take(limit)
        .map(|run| {
            let input = run.value.unwrap_or_default();
            match &run.fault {
                Some(fault) => format!(
                    "input {input}: {} at {:#x} from pc {:#x}",
                    fault.access, fault.address, fault.pc
                ),
                // Not every stop is a bad memory access: a stack canary fires
                // by calling __stack_chk_fail, and the import that was reached
                // is the only clue to why the run ended.
                None if !run.calls.is_empty() => {
                    format!(
                        "input {input}: {} (called {})",
                        run.stop,
                        describe_calls(run)
                    )
                }
                None => format!("input {input}: {}", run.stop),
            }
        })
        .collect()
}

fn describe_calls(run: &Report) -> String {
    run.calls
        .iter()
        .map(|call| format!("{} x{}", call.name, call.count))
        .collect::<Vec<_>>()
        .join(", ")
}

fn describe_target(report: &Report) -> String {
    match report.symbol.as_deref() {
        Some(symbol) => format!("{symbol} at {}", report.address),
        None => report.address.clone(),
    }
}

fn describe_target_env(env: &Envelope) -> String {
    match env.symbol.as_deref() {
        Some(symbol) => format!("{symbol} at {}", env.address),
        None => env.address.clone(),
    }
}

fn describe_fault(fault: &Fault) -> String {
    format!(
        "fault: {} at {:#x} (size {}) from pc {:#x}",
        fault.access, fault.address, fault.size, fault.pc
    )
}

fn describe_return(ret: &Ret) -> String {
    let hex = if ret.hex.is_empty() {
        format!("{:#x}", ret.unsigned)
    } else {
        ret.hex.clone()
    };
    let mut text = format!("{hex} ({})", ret.signed);
    if let Some(value) = ret.f64 {
        text.push_str(&format!(" as double {value}"));
    }
    text
}

/// `1`, `0x1337` and `-1` all name a return value; hex is what a decompiler
/// shows for a magic constant, decimal is what a person types.
fn parse_target(text: &str) -> Result<u64> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(1);
    }
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|err| anyhow::anyhow!("target {text:?} is not hex: {err}"))
    } else if let Ok(value) = trimmed.parse::<i64>() {
        Ok(value as u64)
    } else {
        u64::from_str_radix(trimmed, 16)
            .map_err(|_| anyhow::anyhow!("target {text:?} is neither a number nor hex"))
    };
    parsed
}

fn ensure_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(json: &str) -> Envelope {
        serde_json::from_str(json).unwrap()
    }

    fn request() -> Request {
        Request {
            path: "x".into(),
            symbol: Some("step".into()),
            target: "1".into(),
            ..Request::default()
        }
    }

    const STEPPED: &str = r#"{
        "arch": "x86_64", "platform": "linux",
        "address": "0x40001150", "symbol": "step",
        "runs": [
            {"value": 0, "ok": true, "stop": "returned", "return": {"hex": "0x0", "i64": 0, "u64": 0}, "calls": [], "unimplemented": [], "notes": []},
            {"value": 5, "ok": true, "stop": "returned", "return": {"hex": "0x0", "i64": 0, "u64": 0}, "calls": [], "unimplemented": [], "notes": []},
            {"value": 10, "ok": true, "stop": "returned", "return": {"hex": "0x1", "i64": 1, "u64": 1}, "calls": [], "unimplemented": [], "notes": []},
            {"value": 15, "ok": true, "stop": "returned", "return": {"hex": "0x1", "i64": 1, "u64": 1}, "calls": [], "unimplemented": [], "notes": []}
        ]
    }"#;

    const WITH_CRASH: &str = r#"{
        "arch": "x86_64", "platform": "linux",
        "address": "0x40001180", "symbol": "nullread",
        "runs": [
            {"value": 6, "ok": true, "stop": "returned", "return": {"hex": "0xc", "i64": 12, "u64": 12}, "calls": [], "unimplemented": [], "notes": []},
            {"value": 7, "ok": false, "stop": "fault", "return": {"hex": "0x0", "i64": 0, "u64": 0},
             "fault": {"access": "read", "address": 0, "size": 1, "pc": 1073746358},
             "calls": [], "unimplemented": [], "notes": []},
            {"value": 8, "ok": true, "stop": "returned", "return": {"hex": "0x10", "i64": 16, "u64": 16}, "calls": [], "unimplemented": [], "notes": []}
        ]
    }"#;

    #[test]
    fn a_sweep_groups_returns_and_names_the_threshold() {
        let mut req = request();
        req.step = 5;
        let text = render_sweep(&req, "sweep", &envelope(STEPPED), false, None);
        assert!(text.contains("distinct returns: 2"));
        assert!(text.contains("0: 2 values, 0..5"));
        assert!(text.contains("1: 2 values, 10..15"));
        assert!(text.contains("input 5 -> 10: return 0 -> 1"));
    }

    #[test]
    fn a_sweep_reports_crashes_with_the_address() {
        let text = render_sweep(&request(), "sweep", &envelope(WITH_CRASH), false, None);
        assert!(text.contains("crashes: 1"));
        assert!(text.contains("input 7: read at 0x0 from pc 0x400011b6"));
        // Input 6 and 8 return different values, but 7 crashed in between, so
        // there is no observed boundary to report.
        assert!(!text.contains("transitions:"));
    }

    #[test]
    fn crash_mode_shows_each_fault() {
        let env = envelope(WITH_CRASH);
        let crashes: Vec<&Report> = env.runs.iter().filter(|run| !run.ok).collect();
        let text = render_crash(&env, String::new(), &crashes);
        assert!(text.contains("crashes: 1 of 3"));
        assert!(text.contains("input 7"));
        assert!(text.contains("stopped: fault"));
        assert!(text.contains("read at 0x0 (size 1) from pc 0x400011b6"));
    }

    #[test]
    fn crash_mode_says_so_when_nothing_crashed() {
        let env = envelope(STEPPED);
        let crashes: Vec<&Report> = env.runs.iter().filter(|run| !run.ok).collect();
        let text = render_crash(&env, String::new(), &crashes);
        assert!(text.contains("crashes: 0 of 4"));
        assert!(text.contains("nothing crashed"));
    }

    #[test]
    fn magic_finds_the_input_that_returns_the_target() {
        let env = envelope(STEPPED);
        let req = request();
        let text = render_magic(&req, &env, String::new(), &[], 1);
        assert!(text.contains("found 2 input(s)"));
        assert!(text.contains("input 10 -> 0x1 (1)"));
    }

    #[test]
    fn magic_without_a_hit_lists_what_is_reachable() {
        let env = envelope(STEPPED);
        let req = request();
        let text = render_magic(&req, &env, String::new(), &[], 0x1337);
        assert!(text.contains("nothing in 0..4096 returns it"));
        assert!(text.contains("reachable returns: 0, 1"));
        assert!(text.contains("args=str:text"));
    }

    #[test]
    fn targets_are_decimal_or_hex() {
        assert_eq!(parse_target("1").unwrap(), 1);
        assert_eq!(parse_target("0x1337").unwrap(), 0x1337);
        assert_eq!(parse_target("").unwrap(), 1);
        assert_eq!(parse_target("-1").unwrap(), u64::MAX);
        // A licence check often compares against a constant that only makes
        // sense in one of the two bases; guessing decimal when hex was meant
        // would silently search for the wrong value.
        assert!(parse_target("zzz").is_err());
    }

    #[test]
    fn the_range_count_and_the_limit_are_honoured() {
        let mut req = request();
        req.start = 0;
        req.end = 30;
        req.step = 5;
        assert_eq!(total_runs(&req), 7);
        assert_eq!(expected_runs(&req, 3), 3);

        req.step = 1;
        req.end = 4;
        assert_eq!(total_runs(&req), 5);
        assert_eq!(expected_runs(&req, 500), 5);

        req.end = -1;
        assert_eq!(total_runs(&req), 0);
    }

    #[test]
    fn a_negative_range_is_counted() {
        let mut req = request();
        req.start = -3;
        req.end = 3;
        req.step = 1;
        assert_eq!(total_runs(&req), 7);
    }

    #[test]
    fn a_double_result_is_shown_as_a_double() {
        let ret = Ret {
            hex: "0x4014000000000000".into(),
            signed: 4616189618054758400,
            unsigned: 4616189618054758400,
            f64: Some(5.0),
        };
        assert!(describe_return(&ret).contains("as double 5"));
    }
}
