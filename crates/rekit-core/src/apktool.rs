//! Full APK decoding with apktool.
//!
//! jadx answers "what does the code do"; apktool answers "what is in this
//! package" — a readable AndroidManifest, `res/values/strings.xml` with the
//! strings the code refers to by id, layouts, themes, and smali. Nothing here
//! parses AXML itself: apktool already does it correctly, and its cache is
//! where a later `grep` or `read` can go.
//!
//! The decode is slow (seconds to minutes) and deterministic for a given
//! file, so it is cached by content identity and reused.

use anyhow::{bail, Result};
use std::path::Path;

use crate::decompilers::{cache_dir, error_lines, take_lines};
use crate::external::{capture, which};
use crate::resolve::resolve;
use std::time::Duration;

/// Is this entry a text file worth searching?
///
/// `res/drawable/*.png` and `assets/*.so` are searched by `grep` in the old
/// plugin and produce nothing but noise, so they are skipped by extension.
fn is_text(path: &Path) -> bool {
    const TEXT: &[&str] = &[
        "xml",
        "smali",
        "txt",
        "json",
        "yml",
        "yaml",
        "properties",
        "html",
        "js",
        "css",
        "md",
        "csv",
        "ini",
        "cfg",
        "conf",
        "pro",
    ];
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            let ext = ext.to_ascii_lowercase();
            TEXT.contains(&ext.as_str())
        })
        .unwrap_or(false)
}

/// Recursively collect text files, skipping the build noise apktool leaves.
fn walk(dir: &Path, depth: usize, out: &mut Vec<std::path::PathBuf>) {
    if depth > 24 || out.len() > 200_000 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, depth + 1, out);
        } else if is_text(&path) {
            out.push(path);
        }
    }
}

/// Find a literal string in every text file under `root`.
///
/// Returns `file:line: text` with paths relative to `root`, so a hit can be
/// handed straight back to `read` or `grep`.
fn search(root: &Path, needle: &str, limit: usize) -> Vec<String> {
    let mut files = Vec::new();
    walk(root, 0, &mut files);
    files.sort();

    let mut hits = Vec::new();
    for file in files {
        if hits.len() >= limit {
            break;
        }
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .display()
            .to_string();
        for (number, line) in text.lines().enumerate() {
            if line.contains(needle) {
                hits.push(format!("{rel}:{}: {}", number + 1, line.trim()));
                if hits.len() >= limit {
                    break;
                }
            }
        }
    }
    hits
}

fn sorted_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            // The completion marker is rekit's bookkeeping, not apktool output.
            if name.starts_with('.') {
                return None;
            }
            Some(if entry.path().is_dir() {
                format!("{name}/")
            } else {
                name
            })
        })
        .collect();
    names.sort();
    names
}

pub fn decode(spec: &str, pattern: Option<&str>, limit: usize) -> Result<String> {
    if which("apktool").is_none() {
        bail!("apktool is not installed, e.g. `pacman -S apktool`");
    }
    let path = resolve(spec)?;
    let is_apk = path
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("apk"))
        .unwrap_or(false);
    if !is_apk {
        bail!(
            "{} is not an .apk — apktool decodes packages only",
            path.display()
        );
    }

    let out_dir = cache_dir("apktool", &path, "");
    let marker = out_dir.join(".rekit-done");
    let mut fresh = false;
    if !marker.exists() {
        // A previous run may have died halfway; `-f` overwrites files but
        // leaves the ones it no longer produces.
        if out_dir.exists() {
            std::fs::remove_dir_all(&out_dir)?;
        }
        std::fs::create_dir_all(&out_dir)?;
        let args = vec![
            "d".to_string(),
            "-f".to_string(),
            "-o".to_string(),
            out_dir.display().to_string(),
            path.display().to_string(),
        ];
        let out = capture("apktool", &args, Duration::from_secs(600), &[], None)?;
        if out.timed_out {
            bail!("apktool did not finish within 10 minutes");
        }
        if !out.success && !out_dir.exists() {
            bail!("apktool failed:\n{}", error_lines(&out.stderr, 12));
        }
        std::fs::write(&marker, b"ok")?;
        fresh = true;
    }

    let head = format!(
        "apktool cache: {}{}\n",
        out_dir.display(),
        if fresh { " (decoded)" } else { " (reused)" }
    );

    let pattern = pattern.map(str::trim).filter(|p| !p.is_empty());
    let Some(pattern) = pattern else {
        let top = sorted_names(&out_dir);
        let smali = sorted_names(&out_dir.join("smali"));
        let mut out = head;
        out.push_str(&format!(
            "top level:\n{}\n\nsmali entries:\n{}\n",
            take_lines(&top.join("\n"), 30),
            take_lines(&smali.join("\n"), 30)
        ));
        out.push_str("\nsearch it with pattern=<text>, or point `grep` at the cache path\n");
        return Ok(out);
    };

    let limit = limit.clamp(1, 5_000);
    let hits = search(&out_dir, pattern, limit);
    if hits.is_empty() {
        return Ok(format!("no match for {pattern:?}\n{head}"));
    }
    let mut out = format!("{head}matches: {}\n", hits.len());
    out.push_str(&take_lines(&hits.join("\n"), limit));
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_extensions_are_the_ones_apktool_writes() {
        assert!(is_text(Path::new("a/strings.xml")));
        assert!(is_text(Path::new("a/Foo.smali")));
        assert!(is_text(Path::new("a/notes.JSON")));
        assert!(!is_text(Path::new("a/icon.png")));
        assert!(!is_text(Path::new("a/lib.so")));
        assert!(!is_text(Path::new("a/no-extension")));
    }

    #[test]
    fn search_reports_relative_paths_and_line_numbers() {
        let root = std::env::temp_dir().join("rekit-apktool-search");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("res/values")).unwrap();
        std::fs::create_dir_all(root.join("res/drawable")).unwrap();
        std::fs::write(
            root.join("res/values/strings.xml"),
            "<?xml version=\"1.0\"?>\n<resources>\n  <string name=\"app_name\">Secret</string>\n</resources>\n",
        )
        .unwrap();
        // A binary file with the same bytes must not show up as a hit.
        std::fs::write(root.join("res/drawable/i.png"), b"Secret").unwrap();

        let hits = search(&root, "Secret", 10);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].starts_with("res/values/strings.xml:3:"));
        assert!(hits[0].contains("app_name"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn search_honours_the_limit() {
        let root = std::env::temp_dir().join("rekit-apktool-limit");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let body: String = (0..20).map(|i| format!("hit {i}\n")).collect();
        std::fs::write(root.join("a.smali"), body).unwrap();

        assert_eq!(search(&root, "hit", 5).len(), 5);
        assert_eq!(search(&root, "absent", 5).len(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn directories_are_marked_in_the_listing() {
        let root = std::env::temp_dir().join("rekit-apktool-names");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("smali")).unwrap();
        std::fs::write(root.join("apktool.yml"), b"x").unwrap();

        let names = sorted_names(&root);
        assert_eq!(names, vec!["apktool.yml".to_string(), "smali/".to_string()]);

        let _ = std::fs::remove_dir_all(&root);
    }
}
