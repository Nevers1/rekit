//! Thin wrappers around the tools that already exist on the machine.
//!
//! rekit parses formats itself, but disassembly, decompilation and firmware
//! carving are better served by the established tools. The point here is to
//! give an agent one call instead of knowing six CLIs, their flags and their
//! output shapes — and to fail with a readable message when one is missing.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::info::analyze;
use crate::resolve::resolve;
use crate::util::sha256_hex;

/// How much command output is worth returning to a model.
const OUTPUT_CAP: usize = 60_000;
/// How much is worth parsing. A sweep of 500 runs is a few hundred kilobytes
/// of JSON, and cutting it at the display limit leaves a document that no
/// parser accepts — the failure then looks like a broken emulator.
const PARSE_CAP: usize = 32 << 20;

pub fn which(tool: &str) -> Option<PathBuf> {
    if tool.contains('/') {
        let path = PathBuf::from(tool);
        return path.is_file().then_some(path);
    }
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).collect())
        .unwrap_or_default();
    // `dotnet tool install -g` drops its binaries in ~/.dotnet/tools and does
    // not add it to PATH, so ilspycmd would look installed-by-absence.
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".dotnet").join("tools"));
    }
    dirs.into_iter()
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

/// One finished command, with both streams kept apart.
///
/// Ghidra and IDA report progress on stdout but errors on stderr, and they
/// sometimes exit non-zero after doing the work anyway — so the caller needs
/// to see both before deciding the run failed.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub timed_out: bool,
}

/// Run a command, capture both streams, and never hang: the process is killed
/// when the deadline passes.
pub fn capture(
    tool: &str,
    args: &[String],
    timeout: Duration,
    env: &[(&str, String)],
    cwd: Option<&Path>,
) -> Result<Output> {
    capture_with(tool, args, timeout, env, cwd, OUTPUT_CAP)
}

/// The same, with room for output that is meant to be parsed rather than read.
fn capture_with(
    tool: &str,
    args: &[String],
    timeout: Duration,
    env: &[(&str, String)],
    cwd: Option<&Path>,
    cap_bytes: usize,
) -> Result<Output> {
    let exe = which(tool).ok_or_else(|| anyhow!("{tool} is not installed"))?;

    let mut command = Command::new(&exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("cannot start {}", exe.display()))?;

    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None => {
                if started.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };

    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    Ok(Output {
        stdout: cap(String::from_utf8_lossy(&stdout).to_string(), cap_bytes),
        stderr: cap(String::from_utf8_lossy(&stderr).to_string(), cap_bytes),
        success: status.map(|s| s.success()).unwrap_or(false),
        timed_out,
    })
}

/// Run a command whose stdout is machine-readable, keeping the whole answer.
pub fn run_parsed(tool: &str, args: &[String], timeout: Duration) -> Result<String> {
    let out = capture_with(tool, args, timeout, &[], None, PARSE_CAP)?;
    if out.timed_out {
        bail!("{tool} timed out after {}s", timeout.as_secs());
    }
    if !out.success && out.stdout.trim().is_empty() {
        bail!("{tool} failed: {}", out.stderr.trim());
    }
    Ok(out.stdout)
}

/// Run a command and return its stdout, turning a failure into an error.
pub fn run(tool: &str, args: &[String], timeout: Duration) -> Result<String> {
    let out = capture(tool, args, timeout, &[], None)?;
    if out.timed_out {
        bail!("{tool} timed out after {}s", timeout.as_secs());
    }
    if !out.success && out.stdout.trim().is_empty() {
        bail!("{tool} failed: {}", out.stderr.trim());
    }
    Ok(out.stdout)
}

fn cap(text: String, limit: usize) -> String {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n... output truncated at {} bytes ({} total)",
        &text[..end],
        limit,
        text.len()
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub purpose: &'static str,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// What is installed and what is missing, so a failure is explained up front.
///
/// Two kinds of tool live here: commands found in PATH, and installations
/// found by their layout (Ghidra, IDA, the emulation binary). Both are
/// reported the same way, because "is ida there" is the question being asked.
pub fn doctor() -> Vec<Tool> {
    const TOOLS: &[(&str, &str)] = &[
        ("llvm-objdump", "disassembly, all formats"),
        ("objdump", "disassembly fallback"),
        ("r2", "function list, pseudo-C, xrefs"),
        ("jadx", "dex and apk to Java"),
        ("apktool", "full apk decode to smali and resources"),
        ("javap", "JVM bytecode"),
        ("ilspycmd", ".NET to C#"),
        ("binwalk", "embedded files and firmware carving"),
        ("rasm2", "assembler behind the asm tool"),
        ("frida", "dynamic instrumentation scripts"),
        (
            "qemu-aarch64-static",
            "engine=qemu: AArch64 as a real process",
        ),
        (
            "aarch64-linux-gnu-gcc",
            "engine=qemu: builds the dlopen harness",
        ),
        ("vol", "memory dumps"),
        ("curl", "the http tool: TLS, proxies, redirects"),
    ];

    let mut tools: Vec<Tool> = TOOLS
        .iter()
        .map(|(name, purpose)| {
            let found = which(name).is_some();
            let version = if found {
                // A version line is a line with a number in it: several tools
                // print a usage banner first, and "Usage: javap <options>" is
                // not a version.
                run(name, &["--version".to_string()], Duration::from_secs(5))
                    .ok()
                    .and_then(|out| {
                        out.lines()
                            .find(|line| line.chars().any(|c| c.is_ascii_digit()))
                            .map(str::to_string)
                    })
                    .map(|line| line.trim().chars().take(70).collect())
            } else {
                None
            };
            Tool {
                name,
                purpose,
                found,
                version,
            }
        })
        .collect();

    for (name, purpose, at) in [
        (
            "ghidra",
            "native code to C (headless)",
            crate::ghidra::home(),
        ),
        ("ida", "native code to C (Hex-Rays)", crate::ida::home()),
        (
            "rekit-emu",
            "execute a function in a sandboxed CPU",
            crate::emulate::available(),
        ),
    ] {
        tools.push(Tool {
            name,
            purpose,
            found: at.is_some(),
            version: at.map(|path| path.display().to_string()),
        });
    }

    tools
}

pub fn disasm(
    spec: &str,
    symbol: Option<&str>,
    address: Option<u64>,
    length: usize,
) -> Result<String> {
    let path = resolve(spec)?;
    let llvm = which("llvm-objdump").is_some();
    let tool = if llvm { "llvm-objdump" } else { "objdump" };
    if !llvm && which("objdump").is_none() {
        bail!("neither llvm-objdump nor objdump is installed");
    }

    let mut args: Vec<String> = vec!["-d".to_string()];
    if let Some(sym) = symbol {
        args.push(if llvm {
            format!("--disassemble-symbols={sym}")
        } else {
            format!("--disassemble={sym}")
        });
    } else {
        let start = match address {
            Some(addr) => addr,
            None => analyze(spec)?.entry.unwrap_or(0),
        };
        args.push(format!("--start-address=0x{start:x}"));
        args.push(format!("--stop-address=0x{:x}", start + length as u64));
    }
    args.push(path.display().to_string());

    run(tool, &args, Duration::from_secs(120))
}

pub fn r2(spec: &str, kind: &str, target: Option<&str>) -> Result<String> {
    let path = resolve(spec)?;
    let script = match kind {
        "functions" => "aaa; afl".to_string(),
        "json" => "aaa; aflj".to_string(),
        "pdc" => format!("aaa; s {}; pdc", target.unwrap_or("entry0")),
        "xrefs" => format!("aaa; axt @ {}", target.unwrap_or("entry0")),
        "imports" => "ii".to_string(),
        "sections" => "iS".to_string(),
        other => {
            bail!("unknown kind {other:?}: use functions, json, pdc, xrefs, imports, sections")
        }
    };
    let args = vec![
        "-q".to_string(),
        "-e".to_string(),
        "scr.color=false".to_string(),
        "-c".to_string(),
        script,
        path.display().to_string(),
    ];
    run("r2", &args, Duration::from_secs(180))
}

/// jadx is slow and writes a tree, so results are cached per input file.
pub fn decompile(spec: &str, class: Option<&str>, limit: usize) -> Result<String> {
    let path = resolve(spec)?;
    let meta = std::fs::metadata(&path)?;
    let stamp = format!(
        "{}:{}:{}",
        path.display(),
        meta.len(),
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let out_dir =
        crate::resolve::cache_root().join(format!("jadx-{}", &sha256_hex(stamp.as_bytes())[..16]));
    let marker = out_dir.join(".rekit-done");

    if !marker.exists() {
        std::fs::create_dir_all(&out_dir)?;
        let args = vec![
            "-d".to_string(),
            out_dir.display().to_string(),
            "--no-res".to_string(),
            path.display().to_string(),
        ];
        run("jadx", &args, Duration::from_secs(900))?;
        std::fs::write(&marker, b"ok")?;
    }

    let mut files = Vec::new();
    collect_java(&out_dir, &mut files, 0)?;
    files.sort();

    if let Some(class) = class {
        let wanted = format!("{class}.java");
        let hit = files
            .iter()
            .find(|f| f.file_name().map(|n| n == wanted.as_str()).unwrap_or(false))
            .or_else(|| files.iter().find(|f| f.to_string_lossy().contains(class)))
            .ok_or_else(|| anyhow!("class {class:?} not found in the decompiled output"))?;
        let text = std::fs::read_to_string(hit)?;
        return Ok(cap(text, OUTPUT_CAP));
    }

    let mut out = format!("{} java files\n", files.len());
    for file in files.iter().take(limit) {
        let rel = file.strip_prefix(&out_dir).unwrap_or(file);
        out.push_str(&format!("  {}\n", rel.display()));
    }
    if files.len() > limit {
        out.push_str(&format!("... {} more\n", files.len() - limit));
    }
    out.push_str("pass class=<Name> to read one file\n");
    Ok(out)
}

fn collect_java(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
    if depth > 12 || out.len() > 20_000 {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_java(&path, out, depth + 1)?;
        } else if path.extension().map(|e| e == "java").unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(())
}

pub fn binwalk(spec: &str, extract: bool) -> Result<String> {
    let path = resolve(spec)?;
    let mut args: Vec<String> = Vec::new();
    if extract {
        args.push("-e".to_string());
        args.push("-C".to_string());
        args.push(crate::resolve::cache_root().display().to_string());
    }
    args.push(path.display().to_string());
    run("binwalk", &args, Duration::from_secs(600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_sh() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-tool-xyz").is_none());
    }

    #[test]
    fn run_reports_missing_tool() {
        let err = run(
            "definitely-not-a-real-tool-xyz",
            &[],
            Duration::from_secs(1),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not installed"));
    }

    #[test]
    fn run_captures_stdout_and_enforces_timeout() {
        let out = run(
            "sh",
            &["-c".to_string(), "echo hi".to_string()],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(out.trim(), "hi");

        let err = run(
            "sh",
            &["-c".to_string(), "sleep 5".to_string()],
            Duration::from_millis(200),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("timed out"));
    }
}
