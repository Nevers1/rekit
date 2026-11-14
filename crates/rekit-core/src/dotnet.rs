//! .NET assemblies, decompiled to C# with ilspycmd.
//!
//! C# from metadata is not a reconstruction: field names, types and control
//! flow are all there, so this beats any native decompiler on managed code.
//! The price is that ilspycmd is a dotnet tool — installed outside PATH, slow
//! on first run, and picky about the installed runtime — so the environment is
//! pinned here (roll-forward) and the tree it writes is cached per input file.

use anyhow::{bail, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::decompilers::{cache_dir, error_lines, take_lines};
use crate::external::which;
use crate::resolve::resolve;

/// ilspycmd targets .NET 8 while the machine may only have a newer runtime;
/// without roll-forward it refuses to start at all.
fn environment() -> Vec<(&'static str, String)> {
    vec![("DOTNET_ROLL_FORWARD", "LatestMajor".to_string())]
}

/// A PE with a CLR runtime header is managed. The `BSJB` metadata signature is
/// the fallback for files goblin cannot parse.
pub fn is_dotnet(data: &[u8]) -> bool {
    if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(data) {
        if let Some(header) = &pe.header.optional_header {
            if header.data_directories.get_clr_runtime_header().is_some() {
                return true;
            }
        }
    }
    data.windows(4).any(|window| window == b"BSJB")
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    pub file: String,
    pub line: usize,
    pub text: String,
}

pub fn decompile(
    spec: &str,
    ty: Option<&str>,
    pattern: Option<&str>,
    regex: bool,
    limit: usize,
) -> Result<String> {
    if which("ilspycmd").is_none() {
        bail!(
            "ilspycmd is not installed. It is a dotnet tool:\n  \
             dotnet tool install -g ilspycmd\n\
             (rekit also looks in ~/.dotnet/tools, which is not on PATH by default)"
        );
    }
    let path = resolve(spec)?;
    let data = std::fs::read(&path)?;
    if !is_dotnet(&data) {
        bail!(
            "{} is not a .NET assembly: no CLR runtime header.\n\
             For native code use `ghidra`, `ida` or `r2`.",
            path.display()
        );
    }

    if let Some(ty) = ty.map(str::trim).filter(|t| !t.is_empty()) {
        return decompile_type(&path, ty, limit);
    }

    let out_dir = cache_dir("ilspy", &path, "");
    let marker = out_dir.join(".rekit-done");
    if !marker.exists() {
        std::fs::create_dir_all(&out_dir)?;
        let args = vec![
            "-o".to_string(),
            out_dir.display().to_string(),
            "-p".to_string(),
            "--disable-updatecheck".to_string(),
            path.display().to_string(),
        ];
        let out = crate::external::capture(
            "ilspycmd",
            &args,
            Duration::from_secs(600),
            &environment(),
            None,
        )?;
        if out.timed_out {
            bail!("ilspycmd did not finish within 10 minutes");
        }
        if !out.success && !out_dir.exists() {
            bail!("ilspycmd failed:\n{}", error_lines(&out.stderr, 12));
        }
        std::fs::write(&marker, b"ok")?;
    }

    let files = collect(&out_dir, "cs", 0);
    let Some(pattern) = pattern.map(str::trim).filter(|p| !p.is_empty()) else {
        let mut out = format!(
            "C# cache: {}\nsource files: {}\n",
            out_dir.display(),
            files.len()
        );
        out.push_str(
            "pass pattern=<text> to search the code, or type=<Name> to decompile one type\n",
        );
        for file in files.iter().take(40) {
            out.push_str(&format!("  {}\n", relative(&out_dir, file)));
        }
        if files.len() > 40 {
            out.push_str(&format!("... {} more\n", files.len() - 40));
        }
        return Ok(out);
    };

    let matcher = if regex {
        regex::Regex::new(pattern)?
    } else {
        regex::Regex::new(&regex::escape(pattern))?
    };
    let hits = search(&out_dir, &files, &matcher, limit)?;
    if hits.is_empty() {
        let mut out = format!(
            "no match for {pattern:?} in {}\nsource files: {}\nexamples:\n",
            out_dir.display(),
            files.len()
        );
        for file in files.iter().take(20) {
            out.push_str(&format!("  {}\n", relative(&out_dir, file)));
        }
        return Ok(out);
    }

    let mut out = format!("C# matches: {}\n", hits.len());
    for hit in &hits {
        out.push_str(&format!("{}:{}: {}\n", hit.file, hit.line, hit.text));
    }
    Ok(out)
}

fn decompile_type(path: &Path, ty: &str, limit: usize) -> Result<String> {
    let args = vec![
        "-t".to_string(),
        ty.to_string(),
        "--disable-updatecheck".to_string(),
        path.display().to_string(),
    ];
    let out = crate::external::capture(
        "ilspycmd",
        &args,
        Duration::from_secs(300),
        &environment(),
        None,
    )?;
    if out.timed_out {
        bail!("ilspycmd did not finish within 5 minutes");
    }
    let text = format!("{}\n{}", out.stdout, out.stderr);

    if out.stdout.trim().is_empty() {
        if looks_missing(&text) {
            return Ok(type_help(path, ty));
        }
        bail!("ilspycmd failed:\n{}", error_lines(&text, 12));
    }
    if looks_missing(&text) && out.stdout.trim().len() < 200 {
        return Ok(type_help(path, ty));
    }

    Ok(format!(
        "C# from {}\n\n{}",
        path.display(),
        take_lines(out.stdout.trim_end(), limit)
    ))
}

fn looks_missing(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("could not find")
        || lower.contains("no type found")
        || lower.contains("not find type")
}

/// `ilspycmd -l` prefixes every name with its kind ("Class Demo.Checker"), but
/// `-t` wants the bare name — so the prefix is stripped before it is offered
/// for copying.
fn strip_kind(line: &str) -> &str {
    for kind in [
        "Class ",
        "Interface ",
        "Struct ",
        "Enum ",
        "Delegate ",
        "Record ",
    ] {
        if let Some(rest) = line.strip_prefix(kind) {
            return rest.trim();
        }
    }
    line
}

/// A wrong type name is common enough that the answer is a list, not an error.
fn type_help(path: &Path, ty: &str) -> String {
    let args = vec![
        "-l".to_string(),
        "c".to_string(),
        "--disable-updatecheck".to_string(),
        path.display().to_string(),
    ];
    let classes = crate::external::capture(
        "ilspycmd",
        &args,
        Duration::from_secs(180),
        &environment(),
        None,
    )
    .map(|out| out.stdout)
    .unwrap_or_default();

    let names: Vec<String> = classes
        .lines()
        .map(|line| strip_kind(line.trim()).to_string())
        .filter(|line| !line.is_empty())
        .collect();
    let simple = ty.rsplit('.').next().unwrap_or(ty).to_ascii_lowercase();
    let near: Vec<&String> = names
        .iter()
        .filter(|name| {
            name.rsplit('.')
                .next()
                .unwrap_or(name)
                .to_ascii_lowercase()
                .contains(&simple)
        })
        .take(30)
        .collect();

    let mut out = format!(
        "type {ty:?} not found. Types in the assembly: {}\n",
        names.len()
    );
    if near.is_empty() {
        out.push_str("first types:\n");
        for name in names.iter().take(30) {
            out.push_str(&format!("  {name}\n"));
        }
    } else {
        out.push_str("similar:\n");
        for name in near {
            out.push_str(&format!("  {name}\n"));
        }
    }
    out
}

fn relative(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn collect(dir: &Path, extension: &str, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_into(dir, extension, depth, &mut out);
    out.sort();
    out
}

fn collect_into(dir: &Path, extension: &str, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 12 || out.len() > 20_000 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_into(&path, extension, depth + 1, out);
        } else if path
            .extension()
            .map(|ext| ext == extension)
            .unwrap_or(false)
        {
            out.push(path);
        }
    }
}

fn search(
    base: &Path,
    files: &[PathBuf],
    matcher: &regex::Regex,
    limit: usize,
) -> Result<Vec<Match>> {
    let mut hits = Vec::new();
    for file in files {
        if hits.len() >= limit {
            break;
        }
        let Ok(text) = std::fs::read(file) else {
            continue;
        };
        let text = String::from_utf8_lossy(&text);
        for (number, line) in text.lines().enumerate() {
            if matcher.is_match(line) {
                hits.push(Match {
                    file: relative(base, file),
                    line: number + 1,
                    text: line.trim().to_string(),
                });
                if hits.len() >= limit {
                    break;
                }
            }
        }
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_metadata_signature() {
        assert!(is_dotnet(b"\x4d\x5a....\x00BSJB\x00"));
        assert!(!is_dotnet(b"\x7fELF and nothing else"));
    }

    #[test]
    fn finds_lines_and_skips_binary_noise() {
        let dir = std::env::temp_dir().join("rekit-dotnet-search");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("sub/A.cs"),
            "class A {\n  void Check() { /* license_check */ }\n}\n",
        )
        .unwrap();
        std::fs::write(dir.join("B.cs"), "class B {}\n").unwrap();

        let files = collect(&dir, "cs", 0);
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|f| f.ends_with("sub/A.cs")));

        let matcher = regex::Regex::new("license_check").unwrap();
        let hits = search(&dir, &files, &matcher, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 2);
        assert_eq!(hits[0].file, "sub/A.cs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn type_kinds_are_stripped_from_the_listing() {
        assert_eq!(strip_kind("Class Demo.Checker"), "Demo.Checker");
        assert_eq!(strip_kind("Interface IFoo"), "IFoo");
        assert_eq!(strip_kind("Demo.Plain"), "Demo.Plain");
        assert_eq!(strip_kind("Class <Module>"), "<Module>");
    }

    #[test]
    fn a_wrong_type_name_is_recognised() {
        assert!(looks_missing("error: Could not find type X"));
        assert!(looks_missing("No type found"));
        assert!(!looks_missing("public class Foo { }"));
    }

    #[test]
    fn relative_paths_survive_a_prefix() {
        assert_eq!(
            relative(Path::new("/a/b"), Path::new("/a/b/c/d.cs")),
            "c/d.cs"
        );
    }
}
