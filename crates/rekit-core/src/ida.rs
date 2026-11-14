//! IDA + Hex-Rays through idalib.
//!
//! IDA has no CLI decompiler and no binary in PATH: the supported interface is
//! idalib, a Python package that needs `IDADIR` and `PYTHONPATH` pointing into
//! the IDA install. Finding a Python that can actually `import idapro` is the
//! fragile part — pyenv shims exist but lack the module — so it is probed once
//! by running the import, not by trusting the name.
//!
//! The database is created next to the file it analyses, so the input is copied
//! into the cache first and the `.i64` is keyed by the input's identity.

use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::decompilers::{error_lines, key, needle, take_lines};
use crate::external::capture;
use crate::info::analyze;
use crate::resolve::resolve;

const IDA_DEC: &str = r#"import sys
import idapro

db_in, target, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
idapro.open_database(db_in, True)

import ida_auto, ida_funcs, ida_hexrays, ida_idaapi, ida_name, idautils
ida_auto.auto_wait()

lines = []

def dump(ea):
    f = ida_funcs.get_func(ea)
    if f is None:
        return None
    try:
        cf = ida_hexrays.decompile(ea)
        body = str(cf)
    except Exception as e:
        body = "(decompile failed: %s)" % e
    return "== %s @ %#x size=%d ==\n%s" % (
        ida_funcs.get_func_name(ea), ea, f.end_ea - f.start_ea, body)

if target == "@LIST":
    n = 0
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        lines.append("%#x  %s  size=%d" % (ea, ida_funcs.get_func_name(ea),
                     f.end_ea - f.start_ea if f else 0))
        n += 1
    lines.append("TOTAL=%d" % n)
elif target.startswith("@"):
    ea = int(target[1:], 16)
    f = ida_funcs.get_func(ea)
    lines.append(dump(f.start_ea) if f else "no function at %#x" % ea)
else:
    ea_exact = ida_name.get_name_ea(0, target)
    cands = []
    if ea_exact != ida_idaapi.BADADDR:
        cands = [ea_exact]
    else:
        for ea in idautils.Functions():
            if target in ida_funcs.get_func_name(ea):
                cands.append(ea)
    n = 0
    for ea in cands[:40]:
        d = dump(ea)
        if d:
            lines.append(d)
            n += 1
    if n == 0:
        lines.append("no function matching '%s'" % target)
    else:
        lines.append("MATCHED=%d%s" % (n, "" if ea_exact != ida_idaapi.BADADDR else " (partial)"))

idapro.close_database(save=True)
open(out_path, "w").write("\n".join(lines))
print("written %d chars" % sum(len(x) for x in lines))
"#;

/// Where an IDA install lives: it is identified by its Python package.
pub fn home() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("IDA_DIR") {
        candidates.push(PathBuf::from(dir));
    }
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        candidates.push(PathBuf::from(config).join("opencode").join("ida"));
    } else if let Some(home) = std::env::var_os("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join(".config")
                .join("opencode")
                .join("ida"),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join("ida"));
    }
    candidates.extend(["/opt/ida", "/opt/ida-9.3"].into_iter().map(PathBuf::from));
    first_with_a_package(candidates)
}

fn first_with_a_package(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    candidates
        .into_iter()
        .find(|dir| dir.join("python").join("idaapi.py").is_file())
}

fn environment(home: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("IDADIR", home.display().to_string()),
        (
            "PYTHONPATH",
            home.join("idalib").join("python").display().to_string(),
        ),
    ]
}

/// A Python that can import `idapro`, verified by importing it.
///
/// The probe runs outside the working directory: a stray `struct.py` or
/// `json.py` there would shadow the standard library and the import would fail
/// for a reason that has nothing to do with IDA.
fn python(home: &Path) -> Option<PathBuf> {
    let env = environment(home);
    let cwd = std::env::temp_dir();
    for candidate in [
        "/usr/bin/python3",
        "/usr/bin/python3.13",
        "/usr/bin/python3.12",
        "python3",
    ] {
        let Ok(out) = capture(
            candidate,
            &["-c".to_string(), "import idapro".to_string()],
            Duration::from_secs(60),
            &env,
            Some(&cwd),
        ) else {
            continue;
        };
        if out.success {
            return crate::external::which(candidate);
        }
    }
    None
}

pub fn decompile(
    spec: &str,
    symbol: Option<&str>,
    address: Option<&str>,
    limit: usize,
) -> Result<String> {
    let home = home().ok_or_else(|| {
        anyhow!(
            "IDA not found. Looked for python/idaapi.py in $IDA_DIR, \
             ~/.config/opencode/ida, ~/ida, /opt/ida and /opt/ida-9.3.\n\
             IDA 9.x with idalib is required. Set IDA_DIR=/path/to/ida if it \
             lives elsewhere. Without IDA: `ghidra` is nearly as good, `r2` is faster."
        )
    })?;
    let py = python(&home).ok_or_else(|| {
        anyhow!(
            "no python can import idapro.\nCheck by hand:\n  \
             IDADIR={} PYTHONPATH={} python3 -c \"import idapro\"\n\
             Activate idalib with: python3 {}",
            home.display(),
            home.join("idalib").join("python").display(),
            home.join("idalib")
                .join("python")
                .join("py-activate-idalib.py")
                .display()
        )
    })?;

    let path = resolve(spec)?;
    let info = analyze(spec)?;
    crate::decompilers::native_only(
        &path.display().to_string(),
        &info.format,
        info.hints.iter().any(|hint| hint.contains(".NET assembly")),
    )?;

    let target = needle(symbol, address)?;
    let limit = limit.clamp(1, 100);

    let cache = crate::resolve::cache_root();
    std::fs::create_dir_all(&cache)?;
    let key = key(&path);
    let extension = path
        .extension()
        .map(|ext| format!(".{}", ext.to_string_lossy()))
        .unwrap_or_default();
    let source = cache.join(format!("ida-{key}{extension}"));
    let database = PathBuf::from(format!("{}.i64", source.display()));

    let fresh = !database.exists();
    if fresh {
        std::fs::copy(&path, &source)?;
        std::fs::remove_file(&database).ok();
    }

    let script = cache.join("ida_dec.py");
    std::fs::write(&script, IDA_DEC)?;

    let out_file = cache.join(format!("ida-{key}.txt"));
    let listing = run_ida(
        &py,
        &home,
        &script,
        &source,
        &out_file,
        &target,
        Duration::from_secs(900),
    )?;

    let head = format!(
        "IDA (Hex-Rays): {}\ndatabase: {} ({})\n",
        path.display(),
        database.display(),
        if fresh { "created" } else { "cached" }
    );

    let body = listing;
    let body = body.trim_end();

    if body.contains("no function matching") || body.contains("no function at") {
        let names = run_ida(
            &py,
            &home,
            &script,
            &source,
            &out_file,
            "@LIST",
            Duration::from_secs(600),
        )
        .unwrap_or_default();
        return Ok(format!(
            "{head}{}\n\nname did not match. Functions in this binary:\n{}",
            body.trim(),
            take_lines(&names, 40)
        ));
    }

    Ok(format!(
        "{head}\n{}\n",
        take_lines(body.trim_end(), limit * 30)
    ))
}

fn run_ida(
    py: &Path,
    home: &Path,
    script: &Path,
    source: &Path,
    out_file: &Path,
    target: &str,
    timeout: Duration,
) -> Result<String> {
    let _ = std::fs::remove_file(out_file);
    let args = vec![
        script.display().to_string(),
        source.display().to_string(),
        target.to_string(),
        out_file.display().to_string(),
    ];
    let out = capture(
        &py.display().to_string(),
        &args,
        timeout,
        &environment(home),
        None,
    )?;
    if out.timed_out {
        bail!(
            "IDA did not finish within {}s — try `ghidra`, it is faster",
            timeout.as_secs()
        );
    }
    match std::fs::read_to_string(out_file) {
        Ok(text) if !text.trim().is_empty() => Ok(text),
        _ => bail!(
            "IDA produced no output:\n{}",
            error_lines(&format!("{}\n{}", out.stdout, out.stderr), 12)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_agrees_with_the_call() {
        assert!(IDA_DEC.contains("sys.argv[1], sys.argv[2], sys.argv[3]"));
        assert!(IDA_DEC.contains("ida_hexrays.decompile"));
        assert!(IDA_DEC.contains("no function matching"));
    }

    #[test]
    fn the_environment_points_inside_the_install() {
        let home = Path::new("/opt/ida");
        let env = environment(home);
        assert!(env.contains(&("IDADIR", "/opt/ida".to_string())));
        assert!(env.contains(&("PYTHONPATH", "/opt/ida/idalib/python".to_string())));
    }

    #[test]
    fn an_install_is_recognised_by_its_python_package() {
        let base = std::env::temp_dir().join("rekit-ida-layout");
        let _ = std::fs::remove_dir_all(&base);
        let empty = base.join("empty");
        let real = base.join("real");
        std::fs::create_dir_all(real.join("python")).unwrap();
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(real.join("python").join("idaapi.py"), b"").unwrap();

        assert_eq!(first_with_a_package(vec![empty, real.clone()]), Some(real));
        assert_eq!(first_with_a_package(vec![base.join("empty")]), None);

        let _ = std::fs::remove_dir_all(&base);
    }
}
