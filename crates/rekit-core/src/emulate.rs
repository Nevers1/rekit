//! Call one function inside a binary and report what it returns.
//!
//! The work happens in `rekit-emu`, a separate binary that links Unicorn
//! (GPL-2.0). Keeping it out of process is what lets the rest of rekit stay
//! MIT: nothing here links or embeds the emulator, it only spawns it and
//! formats the JSON it prints.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use crate::external::{run, which};

/// Where to find the sidecar: an explicit override, then next to this
/// executable (how a release ships), then the PATH.
pub fn find_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("REKIT_EMU") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["rekit-emu", "rekit-emu.exe"] {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    which("rekit-emu")
}

#[derive(Debug, Clone, Default)]
pub struct Request {
    /// File on disk; archive members must be extracted first.
    pub path: String,
    pub symbol: Option<String>,
    pub address: Option<u64>,
    pub entry: bool,
    /// `1,0x20,str:hello`
    pub args: String,
    pub max_insns: u64,
    pub timeout_ms: u64,
    pub vfs: bool,
    pub as_double: bool,
    pub thumb: bool,
    /// `unicorn` (default) or `qemu`.
    pub engine: String,
    /// qemu: target sysroot for the dynamic loader.
    pub sysroot: Option<String>,
    /// qemu: a prebuilt harness instead of the cached one.
    pub harness: Option<String>,
    /// Read memory after the run, `addr:size:label` entries.
    pub read_ranges: Vec<String>,
    /// Read this many bytes at the returned pointer.
    pub read_ret: usize,
    /// Registers to report after the run.
    pub regs: Vec<String>,
    /// Record executed instructions and show the head of the trace.
    pub trace: bool,
    /// Answer an address with an import call, `addr=name[:ret]`.
    pub stubs: Vec<String>,
    /// Return the raw JSON report instead of the rendered summary.
    pub json: bool,
}

pub fn run_request(req: &Request) -> Result<String> {
    let engine = req.engine.trim().to_ascii_lowercase();
    let extras = req.trace
        || !req.regs.is_empty()
        || !req.read_ranges.is_empty()
        || req.read_ret > 0
        || !req.stubs.is_empty();
    if engine == "qemu" && extras {
        bail!(
            "trace, regs, read_ranges, read_ret and stubs only work with engine=unicorn: \
             qemu runs a real process and rekit-emu cannot hook it"
        );
    }
    if engine == "qemu" {
        // QEMU runs a real process, so it needs a real file rather than a
        // member name, and it formats its own answer.
        let path = crate::resolve::resolve(&req.path)?;
        return crate::qemu::run(&crate::qemu::Request {
            path: path.display().to_string(),
            symbol: req.symbol.clone(),
            args: req.args.clone(),
            as_double: req.as_double,
            sysroot: req.sysroot.clone(),
            harness: req.harness.clone(),
            json: req.json,
        });
    }
    if !engine.is_empty() && engine != "unicorn" {
        bail!(
            "engine {engine:?} is not one of unicorn, qemu: unicorn executes the function \
             in a sandbox, qemu runs a real process for the code unicorn cannot execute"
        );
    }
    let exe = find_binary().ok_or_else(|| {
        anyhow!(
            "rekit-emu is not installed; build it with `cargo build --release -p rekit-emu` \
             or point REKIT_EMU at the binary"
        )
    })?;

    let mut args: Vec<String> = vec!["run".into(), req.path.clone(), "--json".into()];
    if let Some(symbol) = &req.symbol {
        args.push("--symbol".into());
        args.push(symbol.clone());
    }
    if let Some(address) = req.address {
        args.push("--address".into());
        args.push(format!("0x{address:x}"));
    }
    if req.entry {
        args.push("--entry".into());
    }
    if !req.args.is_empty() {
        args.push("--args".into());
        args.push(req.args.clone());
    }
    if req.max_insns != 0 {
        args.push("--max-insns".into());
        args.push(req.max_insns.to_string());
    }
    if req.timeout_ms != 0 {
        args.push("--timeout-ms".into());
        args.push(req.timeout_ms.to_string());
    }
    if !req.vfs {
        args.push("--no-vfs".into());
    }
    if req.as_double {
        args.push("--as-double".into());
    }
    if req.thumb {
        args.push("--thumb".into());
    }
    if req.trace {
        args.push("--trace".into());
    }
    if !req.regs.is_empty() {
        args.push("--regs".into());
        args.push(req.regs.join(","));
    }
    // One flag per range rather than a joined list: the label may itself
    // contain a comma, and the sidecar splits each value on its own.
    for range in &req.read_ranges {
        args.push("--read".into());
        args.push(range.clone());
    }
    if req.read_ret > 0 {
        args.push("--read-ret".into());
        args.push(req.read_ret.to_string());
    }
    for stub in &req.stubs {
        args.push("--stub".into());
        args.push(stub.clone());
    }

    // The emulator enforces its own deadline; this is only a backstop for a
    // process that fails to start or ignores it.
    let budget = Duration::from_millis(req.timeout_ms.max(1_000) + 15_000);
    let tool = exe.to_string_lossy().to_string();
    let raw = run(&tool, &args, budget)?;
    if req.json {
        return Ok(raw);
    }
    match serde_json::from_str::<Value>(&raw) {
        Ok(report) => Ok(render(&report)),
        // A crash before the report is printed leaves stderr only, and `run`
        // already turned that into an error. Anything else is unexpected
        // output; show it rather than swallowing it.
        Err(_) => Ok(raw),
    }
}

fn render(report: &Value) -> String {
    let mut out = String::new();
    let arch = report.get("arch").and_then(Value::as_str).unwrap_or("?");
    let platform = report
        .get("platform")
        .and_then(Value::as_str)
        .unwrap_or("?");
    out.push_str(&format!("arch      {arch} / {platform}\n"));
    match report.get("symbol").and_then(Value::as_str) {
        Some(symbol) => out.push_str(&format!(
            "target    {symbol} at {}\n",
            report.get("address").and_then(Value::as_str).unwrap_or("?")
        )),
        None => out.push_str(&format!(
            "target    {}\n",
            report.get("address").and_then(Value::as_str).unwrap_or("?")
        )),
    }
    out.push_str(&format!(
        "stop      {}\n",
        report.get("stop").and_then(Value::as_str).unwrap_or("?")
    ));
    if let Some(ret) = report.get("return") {
        let hex = ret.get("hex").and_then(Value::as_str).unwrap_or("?");
        let signed = ret.get("i64").and_then(Value::as_i64).unwrap_or(0);
        match ret.get("f64").and_then(Value::as_f64) {
            Some(f) => out.push_str(&format!("return    {hex} ({signed}) as double {f}\n")),
            None => out.push_str(&format!("return    {hex} ({signed})\n")),
        }
    }
    if let Some(calls) = report.get("calls").and_then(Value::as_array) {
        if !calls.is_empty() {
            let text: Vec<String> = calls
                .iter()
                .map(|c| {
                    format!(
                        "{} x{}",
                        c.get("name").and_then(Value::as_str).unwrap_or("?"),
                        c.get("count").and_then(Value::as_u64).unwrap_or(0)
                    )
                })
                .collect();
            out.push_str(&format!("calls     {}\n", text.join(", ")));
        }
    }
    if let Some(unknown) = report.get("unimplemented").and_then(Value::as_array) {
        if !unknown.is_empty() {
            let text: Vec<&str> = unknown.iter().filter_map(Value::as_str).collect();
            out.push_str(&format!("not implemented  {}\n", text.join(", ")));
        }
    }
    if let Some(files) = report.get("files").and_then(Value::as_array) {
        if !files.is_empty() {
            let text: Vec<&str> = files.iter().filter_map(Value::as_str).collect();
            out.push_str(&format!("files     {}\n", text.join(", ")));
        }
    }
    if let Some(output) = report.get("output").and_then(Value::as_str) {
        if !output.trim().is_empty() {
            out.push_str(&format!("output    {}\n", output.trim_end()));
        }
    }
    for (name, value) in report
        .get("regs")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        out.push_str(&format!(
            "reg       {name} {}\n",
            value.as_str().unwrap_or("?")
        ));
    }
    for read in report
        .get("reads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let label = read.get("label").and_then(Value::as_str).unwrap_or("?");
        let addr = read.get("addr").and_then(Value::as_str).unwrap_or("?");
        match read.get("hex").and_then(Value::as_str) {
            Some(hex) => {
                out.push_str(&format!("read      {label} {addr} {hex}\n"));
                if let Some(ascii) = read.get("ascii").and_then(Value::as_str) {
                    out.push_str(&format!("            |{ascii}|\n"));
                }
            }
            None => {
                let error = read
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unreadable");
                out.push_str(&format!("read      {label} {addr} {error}\n"));
            }
        }
    }
    for line in report
        .get("disasm")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(line) = line.as_str() {
            out.push_str(&format!("trace     {line}\n"));
        }
    }
    for line in report
        .get("overrides")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(line) = line.as_str() {
            out.push_str(&format!("stub      {line}\n"));
        }
    }
    for note in report
        .get("notes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(note) = note.as_str() {
            out.push_str(&format!("note      {note}\n"));
        }
    }
    out.push_str(&format!(
        "elapsed   {} ms\n",
        report
            .get("elapsed_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    ));
    out
}

/// List callable functions, so an agent can pick a target without guessing.
pub fn list(spec: &str, filter: Option<&str>, json: bool) -> Result<String> {
    let exe = find_binary().ok_or_else(|| {
        anyhow!("rekit-emu is not installed; build it with `cargo build --release -p rekit-emu`")
    })?;
    let mut args: Vec<String> = vec!["list".into(), spec.to_string()];
    if let Some(filter) = filter {
        args.push("--filter".into());
        args.push(filter.to_string());
    }
    if json {
        args.push("--json".into());
    }
    let tool = exe.to_string_lossy().to_string();
    run(&tool, &args, Duration::from_secs(30)).with_context(|| format!("cannot run {tool}"))
}

/// `doctor` entry: whether emulation is available at all.
pub fn available() -> Option<PathBuf> {
    find_binary()
}

pub fn require_available() -> Result<()> {
    if find_binary().is_none() {
        bail!(
            "rekit-emu was not found next to this binary or on PATH; \
             build it with `cargo build --release -p rekit-emu`"
        );
    }
    Ok(())
}

/// Used by the CLI to pass through a path that may point inside an archive.
pub fn prepare_path(spec: &str) -> Result<String> {
    Ok(crate::resolve::resolve(spec)?.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_returned_report() {
        let report: Value = serde_json::from_str(
            r#"{
                "ok": true,
                "arch": "x86_64",
                "platform": "linux",
                "symbol": "ad_probe",
                "address": "0x4000126c",
                "stop": "returned",
                "return": {"hex": "0x0", "i64": 0, "u64": 0},
                "output": "",
                "calls": [{"name": "ptrace", "count": 1}],
                "unimplemented": [],
                "notes": [],
                "elapsed_ms": 3
            }"#,
        )
        .unwrap();
        let text = render(&report);
        assert!(text.contains("x86_64 / linux"));
        assert!(text.contains("target    ad_probe at 0x4000126c"));
        assert!(text.contains("stop      returned"));
        assert!(text.contains("return    0x0 (0)"));
        assert!(text.contains("ptrace x1"));
        assert!(text.contains("elapsed   3 ms"));
    }

    #[test]
    fn renders_a_double_result() {
        let report: Value = serde_json::from_str(
            r#"{
                "ok": true, "arch": "arm64", "platform": "linux",
                "address": "0x40000980", "stop": "returned",
                "return": {"hex": "0x4014000000000000", "i64": 4616189618054758400,
                           "u64": 4616189618054758400, "f64": 5.0},
                "elapsed_ms": 0
            }"#,
        )
        .unwrap();
        let text = render(&report);
        assert!(text.contains("as double 5"));
        assert!(text.contains("target    0x40000980"));
    }

    #[test]
    fn renders_unimplemented_imports() {
        let report: Value = serde_json::from_str(
            r#"{
                "ok": false, "arch": "x86", "platform": "windows",
                "address": "0x401000", "stop": "fault",
                "return": {"hex": "0x0", "i64": 0, "u64": 0},
                "unimplemented": ["SomeApi"],
                "notes": ["emulation stopped: cpu exception"], "elapsed_ms": 7
            }"#,
        )
        .unwrap();
        let text = render(&report);
        assert!(text.contains("stop      fault"));
        assert!(text.contains("not implemented  SomeApi"));
        assert!(text.contains("note      emulation stopped"));
    }
}
