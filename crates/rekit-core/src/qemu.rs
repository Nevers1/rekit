//! Calling a function through QEMU instead of Unicorn.
//!
//! Unicorn executes instructions; QEMU executes a program. That difference
//! matters for the code Unicorn cannot run at all: AArch64 floating point,
//! thread-local storage, real constructors, calls into libc. There the answer
//! from Unicorn is an exception, and the honest next step is a real process.
//!
//! The price is a cross toolchain: the function has to be reached through the
//! dynamic loader, so a small C harness is compiled for the target, run under
//! `qemu-aarch64-static`, and asked to `dlopen` the file and `dlsym` the
//! symbol. The harness is cached — it does not change between runs — and the
//! target's own environment is supplied with `-L <sysroot>`.
//!
//! Only numbers cross this boundary. A string argument would need an address
//! in the guest, and inventing one would produce a confident wrong answer, so
//! string arguments are reported as ignored rather than guessed at.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::external::{capture, which};

const TIMEOUT: Duration = Duration::from_secs(120);

pub struct Request {
    /// Absolute path of the file to load.
    pub path: String,
    /// Function name; QEMU reaches it through `dlsym`, so a name is required.
    pub symbol: Option<String>,
    /// `1,0x20,str:"hello, world"`
    pub args: String,
    pub as_double: bool,
    pub sysroot: Option<String>,
    pub harness: Option<String>,
    /// Return the report as JSON instead of a summary.
    pub json: bool,
}

/// The target ABI as the harness sees it.
#[derive(Debug)]
struct Abi {
    arch: String,
    bits: u32,
    qemu: PathBuf,
    cc: &'static str,
    default_sysroot: Option<&'static str>,
}

pub fn run(req: &Request) -> Result<String> {
    let started = Instant::now();
    let file = Path::new(&req.path);
    if !file.is_file() {
        bail!("{} is not a file", file.display());
    }
    let symbol = req
        .symbol
        .as_deref()
        .map(str::trim)
        .filter(|symbol| !symbol.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "engine=qemu needs a function name: the harness loads the file with dlopen \
                 and looks the symbol up with dlsym, and an address inside an unloaded \
                 shared object means nothing to it. Pass a symbol, or use the unicorn engine."
            )
        })?;

    let info = crate::info::analyze(&req.path)?;
    let abi = abi_for(&info.arch, info.bits)?;

    let sysroot = req
        .sysroot
        .as_deref()
        .map(str::trim)
        .filter(|sysroot| !sysroot.is_empty())
        .map(str::to_string)
        .or_else(|| abi.default_sysroot.map(str::to_string));

    let harness = match req
        .harness
        .as_deref()
        .map(str::trim)
        .filter(|harness| !harness.is_empty())
    {
        Some(path) => PathBuf::from(path),
        None => build_harness(&abi)?,
    };

    let mut numbers: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for item in split_list(&req.args) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.starts_with("str:") {
            skipped.push(item.to_string());
        } else {
            numbers.push(item.to_string());
        }
    }

    let mut argv: Vec<String> = Vec::new();
    if let Some(sysroot) = &sysroot {
        argv.push("-L".to_string());
        argv.push(sysroot.clone());
    }
    // The harness flag goes after the harness: QEMU reads its own options up
    // to that point, and `-d` there would be QEMU's debug switch.
    argv.push(harness.display().to_string());
    if req.as_double {
        argv.push("-d".to_string());
    }
    let absolute = file
        .canonicalize()
        .unwrap_or_else(|_| file.to_path_buf())
        .display()
        .to_string();
    argv.push(absolute);
    argv.push(symbol.to_string());
    argv.extend(numbers.iter().cloned());

    let qemu = abi.qemu.display().to_string();
    let out =
        capture(&qemu, &argv, TIMEOUT, &[], None).with_context(|| format!("cannot run {qemu}"))?;

    let mut warnings: Vec<String> = Vec::new();
    if !skipped.is_empty() {
        warnings.push(format!(
            "string arguments ignored ({}): QEMU takes numbers only",
            skipped.join(", ")
        ));
    }
    if sysroot.is_none() {
        warnings.push(
            "no sysroot: the target's dynamic loader and libc will not be found, \
             so a dynamically linked file cannot start"
                .to_string(),
        );
    }

    let (ret, err) = match parse(&out.stdout) {
        Some(parsed) => parsed,
        None => {
            let detail = format!("{}{}", out.stderr.trim(), out.stdout.trim());
            let detail = if detail.trim().is_empty() {
                if out.timed_out {
                    format!("no answer within {}s", TIMEOUT.as_secs())
                } else {
                    "the harness printed nothing".to_string()
                }
            } else {
                detail.trim().chars().take(600).collect()
            };
            (None, Some(detail))
        }
    };

    let returned = ret
        .as_deref()
        .map(|value| render_return(value, req.as_double));
    if req.json {
        let report = serde_json::json!({
            "engine": "qemu",
            "arch": abi.arch,
            "platform": "linux",
            "symbol": symbol,
            "stop": if ret.is_some() { "returned" } else { "did not run" },
            "return": returned,
            "error": err,
            "qemu": qemu,
            "env": argv.join(" "),
            "warnings": warnings,
            "elapsed_ms": started.elapsed().as_millis() as u64,
        });
        return Ok(serde_json::to_string_pretty(&report)?);
    }

    let mut text = String::new();
    text.push_str(&format!("arch      {} / linux\n", abi.arch));
    text.push_str("engine    qemu (real process)\n");
    text.push_str(&format!("target    {symbol}\n"));
    match &returned {
        Some(value) => {
            text.push_str("stop      returned\n");
            text.push_str(&format!("return    {value}\n"));
        }
        None => {
            text.push_str("stop      did not run\n");
            text.push_str("return    none\n");
        }
    }
    text.push_str(&format!("qemu      {qemu}\n"));
    text.push_str(&format!("env       {}\n", argv.join(" ")));
    if let Some(err) = err {
        text.push_str(&format!("error     {err}\n"));
    }
    for warning in warnings {
        text.push_str(&format!("warn      {warning}\n"));
    }
    text.push_str(&format!("elapsed   {} ms\n", started.elapsed().as_millis()));
    Ok(text)
}

fn abi_for(arch: &str, bits: u32) -> Result<Abi> {
    let arch = arch.to_ascii_lowercase();
    if !(arch.contains("arm") || arch.contains("aarch64")) {
        bail!(
            "engine=qemu is for ARM only, and this file is {arch}/{bits}. \
             Unicorn handles x86 and works here — leave the engine at unicorn."
        );
    }
    if bits == 64 {
        let qemu = qemu_binary("qemu-aarch64-static")?;
        Ok(Abi {
            arch: "aarch64".to_string(),
            bits,
            qemu,
            cc: "aarch64-linux-gnu-gcc",
            default_sysroot: Some("/usr/aarch64-linux-gnu"),
        })
    } else {
        let qemu = qemu_binary("qemu-arm-static")?;
        Ok(Abi {
            arch: "arm".to_string(),
            bits,
            qemu,
            cc: "arm-linux-gnueabihf-gcc",
            default_sysroot: None,
        })
    }
}

fn qemu_binary(name: &str) -> Result<PathBuf> {
    let system = PathBuf::from("/usr/bin").join(name);
    if system.is_file() {
        return Ok(system);
    }
    which(name).ok_or_else(|| {
        anyhow::anyhow!(
            "{name} is not installed, and engine=qemu needs it. \
             Install qemu-user-static, or leave the engine at unicorn."
        )
    })
}

/// The harness, compiled once per architecture and kept in the cache.
fn build_harness(abi: &Abi) -> Result<PathBuf> {
    let dir = crate::resolve::cache_root().join("qemu");
    // The source's hash is in the name, so editing the harness cannot leave an
    // old binary looking like a current one.
    let tag = crate::util::sha256_hex(HARNESS_C.as_bytes());
    let binary = dir.join(format!("harness{}-{}", abi.bits, &tag[..8]));
    if binary.is_file() {
        return Ok(binary);
    }
    let cc = which(abi.cc).ok_or_else(|| {
        anyhow::anyhow!(
            "no harness for {} and no {} to build one with. Install the cross compiler \
             (a package such as gcc-aarch64-linux-gnu), or pass a prebuilt harness.",
            abi.arch,
            abi.cc
        )
    })?;
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let source = dir.join(format!("harness{}.c", abi.bits));
    std::fs::write(&source, HARNESS_C)
        .with_context(|| format!("cannot write {}", source.display()))?;
    let out = capture(
        &cc.display().to_string(),
        &[
            "-O1".to_string(),
            "-o".to_string(),
            binary.display().to_string(),
            source.display().to_string(),
            "-ldl".to_string(),
        ],
        TIMEOUT,
        &[],
        None,
    )?;
    if !out.success {
        bail!(
            "{} could not build the harness:\n{}",
            abi.cc,
            out.stderr.trim().chars().take(400).collect::<String>()
        );
    }
    Ok(binary)
}

/// `ret=<value> err=<text>` from the harness, keeping an empty error empty.
fn parse(stdout: &str) -> Option<(Option<String>, Option<String>)> {
    let start = stdout.find("ret=")?;
    let rest = &stdout[start + 4..];
    let (value, after) = match rest.find(char::is_whitespace) {
        Some(end) => (&rest[..end], &rest[end..]),
        None => (rest, ""),
    };
    let err = after
        .trim_start()
        .strip_prefix("err=")
        .map(|err| err.trim().to_string())
        .filter(|err| !err.is_empty());
    // The harness prints `ret=0 err=dlopen: ...` for a file it could not load;
    // that is not a return value of zero.
    let value = err.is_none().then(|| value.to_string());
    Some((value, err))
}

fn render_return(value: &str, as_double: bool) -> String {
    if as_double {
        return match value.parse::<f64>() {
            Ok(number) => format!("{number} (as double)"),
            Err(_) => format!("{value} (as double)"),
        };
    }
    match value.parse::<i64>() {
        Ok(number) => format!("{number} ({:#x})", number as u64),
        Err(_) => value.to_string(),
    }
}

/// Split a comma-separated argument string, keeping quoted commas inside one
/// argument: `str:"Hello, world",1` is two arguments.
fn split_list(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in text.chars() {
        match quote {
            Some(open) if ch == open => {
                quote = None;
                current.push(ch);
            }
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                current.push(ch);
            }
            None if ch == ',' => {
                out.push(std::mem::take(&mut current));
            }
            None => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out.retain(|item| !item.trim().is_empty());
    out
}

const HARNESS_C: &str = r#"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef long (*fn_t)(long, long, long, long);
typedef double (*dbl_t)(double, double);

int main(int argc, char **argv) {
    int off = (argc > 1 && !strcmp(argv[1], "-d")) ? 1 : 0;
    if (argc < 3 + off) return 2;
    void *h = dlopen(argv[1 + off], RTLD_NOW);
    if (!h) { printf("ret=0 err=dlopen: %s\n", dlerror()); return 0; }
    dlerror();
    fn_t f = (fn_t)dlsym(h, argv[2 + off]);
    const char *e = dlerror();
    if (!f || e) { printf("ret=0 err=dlsym: %s\n", e ? e : "no error"); return 0; }
    long a[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4 && i + 3 + off < argc; i++) a[i] = strtol(argv[i + 3 + off], NULL, 0);
    if (off) { printf("ret=%.6f err=\n", ((dbl_t)f)((double)a[0], (double)a[1])); return 0; }
    long r = f(a[0], a[1], a[2], a[3]);
    printf("ret=%ld err=\n", r);
    return 0;
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_return_value_and_an_empty_error_are_told_apart() {
        let (value, err) = parse("ret=7 err=\n").unwrap();
        assert_eq!(value.as_deref(), Some("7"));
        assert!(err.is_none());
    }

    #[test]
    fn a_load_failure_is_an_error_rather_than_a_zero_return() {
        let (value, err) = parse("ret=0 err=dlopen: libmissing.so: cannot open\n").unwrap();
        assert!(value.is_none());
        assert!(err.unwrap().contains("cannot open"));
    }

    #[test]
    fn a_missing_marker_is_no_answer() {
        assert!(parse("qemu: could not open interpreter\n").is_none());
    }

    #[test]
    fn quoted_commas_stay_inside_one_argument() {
        assert_eq!(
            split_list(r#"1,str:"Hello, world",0x20"#),
            vec!["1", r#"str:"Hello, world""#, "0x20"]
        );
        assert_eq!(split_list(""), Vec::<String>::new());
        assert_eq!(split_list(" 1 , 2 "), vec![" 1 ", " 2 "]);
    }

    #[test]
    fn a_double_is_printed_as_a_double() {
        assert_eq!(render_return("5.000000", true), "5 (as double)");
        assert_eq!(render_return("7", false), "7 (0x7)");
        assert_eq!(render_return("-3", false), "-3 (0xfffffffffffffffd)");
    }

    #[test]
    fn an_x86_file_is_refused_with_a_reason() {
        let err = abi_for("x86_64", 64).unwrap_err().to_string();
        assert!(err.contains("ARM only"));
        assert!(err.contains("unicorn"));
    }
}
