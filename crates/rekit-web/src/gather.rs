//! Getting the text out of a file, a directory or an archive.
//!
//! A frontend bundle is rarely one file: `dist/` holds hundreds, and an APK
//! holds its own `assets/`. Every web tool wants the same thing — the text of
//! everything relevant, with enough of a name to say where a finding came
//! from. Doing this once here means the four tools differ only in what they
//! look for.
//!
//! Binary files are skipped rather than sniffed: a bundle that happens to
//! contain a PNG would otherwise fill the report with base64 noise and make a
//! secret hit look plausible when it is not.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// How much text is worth returning to a model.
pub const MAX_OUT: usize = 60_000;
/// The line budget a report gets unless it asks for another.
pub const MAX_LINES: usize = 400;
/// A file larger than this is not a bundle, it is data.
const MAX_FILE: u64 = 8 * 1024 * 1024;
/// The whole walk is bounded too, so pointing at `/` does not read the disk.
const MAX_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 4000;
/// Directories whose contents are dependencies or history, never the target.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".cache",
    ".venv",
    "venv",
];

/// One readable text, with the line index computed once.
pub struct Src {
    pub name: String,
    pub text: String,
    /// Byte offset at which each line starts.
    lines: Vec<usize>,
}

impl Src {
    pub fn new(name: String, text: String) -> Src {
        let mut lines = vec![0];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                lines.push(offset + 1);
            }
        }
        Src { name, text, lines }
    }

    /// 1-based line number of a byte offset.
    ///
    /// Binary search over the precomputed starts: a bundle with hundreds of
    /// matches would otherwise re-scan megabytes per hit.
    pub fn line_of(&self, index: usize) -> usize {
        match self.lines.binary_search(&index) {
            Ok(index) => index + 1,
            Err(next) => next,
        }
    }

    /// The text of a line, trimmed and cut short.
    pub fn line_text(&self, line: usize) -> String {
        // A line past the end has no text; returning the first one would make
        // a context line look plausible while pointing at the wrong place.
        let Some(start) = line
            .checked_sub(1)
            .and_then(|index| self.lines.get(index))
            .copied()
        else {
            return String::new();
        };
        let end = self
            .lines
            .get(line)
            .copied()
            .unwrap_or(self.text.len())
            .min(self.text.len());
        if start >= end {
            return String::new();
        }
        self.text[start..end].trim().chars().take(200).collect()
    }
}

pub struct Gathered {
    pub srcs: Vec<Src>,
    /// How an archive member was reached, if it was.
    pub note: Option<String>,
    pub skipped: usize,
}

pub fn gather(spec: &str) -> Result<Gathered> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("path is empty");
    }

    let (target, note) = match spec.split_once("::") {
        Some((outer, _)) => {
            let path = crate::resolve_spec(spec)?;
            let base = Path::new(outer)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| outer.to_string());
            (path, Some(format!("extracted from {base}")))
        }
        None => (PathBuf::from(spec), None),
    };

    let meta =
        fs::metadata(&target).with_context(|| format!("cannot read {}", target.display()))?;

    if meta.is_dir() {
        Ok(Gathered {
            srcs: walk(&target)?,
            note,
            skipped: 0,
        })
    } else if meta.is_file() {
        let name = target
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| target.display().to_string());
        match read_text(&target, meta.len()) {
            Some(text) => Ok(Gathered {
                srcs: vec![Src::new(name, text)],
                note,
                skipped: 0,
            }),
            None => Ok(Gathered {
                srcs: Vec::new(),
                note,
                skipped: 1,
            }),
        }
    } else {
        bail!("{} is neither a file nor a directory", target.display());
    }
}

/// Read a file as text, or `None` when it is binary or too large.
fn read_text(path: &Path, size: u64) -> Option<String> {
    if size == 0 || size > MAX_FILE {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    // A NUL byte in the header is the cheapest reliable "this is not text"
    // test, and it is what keeps images out of the report.
    if bytes.iter().take(2048).any(|byte| *byte == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn walk(root: &Path) -> Result<Vec<Src>> {
    let cwd = std::env::current_dir().ok();
    let mut srcs = Vec::new();
    let mut total: u64 = 0;
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        if srcs.len() >= MAX_FILES || total >= MAX_TOTAL {
            break;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            // A directory we cannot read is not worth failing the whole run
            // over; it is skipped like a binary file.
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
            if is_dir {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            let size = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
            let Some(text) = read_text(&path, size) else {
                continue;
            };
            total += text.len() as u64;
            let display = match &cwd {
                Some(cwd) => match path.strip_prefix(cwd) {
                    Ok(relative) => relative.display().to_string(),
                    Err(_) => path.display().to_string(),
                },
                None => path.display().to_string(),
            };
            srcs.push(Src::new(display, text));
        }
    }

    srcs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(srcs)
}

/// Cut text to a line and byte budget, saying what was dropped.
pub fn cap(text: &str, max_lines: usize) -> String {
    let clean: String = text.chars().filter(|c| *c != '\0').collect();
    let lines: Vec<&str> = clean.lines().collect();
    if clean.len() <= MAX_OUT && lines.len() <= max_lines {
        return clean.trim_end().to_string();
    }
    let kept = lines.len().min(max_lines);
    let mut out = lines[..kept].join("\n");
    let dropped = lines.len() - kept;
    if dropped > 0 {
        out.push_str(&format!("\n... {dropped} more lines (narrow the filter)"));
    }
    if out.len() > MAX_OUT {
        let mut end = MAX_OUT;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str("\n... truncated at the output limit");
    }
    out
}

/// A named group of findings, ordered by how often each value appears.
///
/// A value seen in twenty places is more likely to be a real route than one
/// seen once in a comment, so the ordering is the point.
pub struct Groups {
    items: Vec<(String, Vec<String>)>,
    index: std::collections::HashMap<String, usize>,
    limit: usize,
}

impl Groups {
    pub fn new(limit: usize) -> Groups {
        Groups {
            items: Vec::new(),
            index: std::collections::HashMap::new(),
            limit: limit.max(1),
        }
    }

    pub fn add(&mut self, value: String, at: String) {
        match self.index.get(&value) {
            Some(&slot) => {
                let places = &mut self.items[slot].1;
                if places.len() < 8 && !places.contains(&at) {
                    places.push(at);
                }
            }
            None => {
                if self.items.len() >= self.limit {
                    return;
                }
                self.index.insert(value.clone(), self.items.len());
                self.items.push((value, vec![at]));
            }
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Keep only values the pattern matches.
    pub fn retain(&mut self, regex: &regex::Regex) {
        self.items.retain(|(value, _)| regex.is_match(value));
    }

    pub fn dump(&self, title: &str, shown: usize) -> String {
        if self.items.is_empty() {
            return String::new();
        }
        let mut rows: Vec<&(String, Vec<String>)> = self.items.iter().collect();
        rows.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

        let mut out = format!("\n## {title}: {}\n", self.items.len());
        for (value, places) in rows.iter().take(shown) {
            let first = places.first().cloned().unwrap_or_default();
            let more = if places.len() > 1 {
                format!(" (+{})", places.len() - 1)
            } else {
                String::new()
            };
            out.push_str(&format!("  {value}\n      {first}{more}\n"));
        }
        if rows.len() > shown {
            out.push_str(&format!("  ... {} more\n", rows.len() - shown));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_numbers_are_one_based_and_exact() {
        let src = Src::new("x".into(), "first\nsecond\n\nfourth\n".into());
        assert_eq!(src.line_of(0), 1);
        assert_eq!(src.line_of(5), 1);
        assert_eq!(src.line_of(6), 2);
        assert_eq!(src.line_of(13), 3);
        assert_eq!(src.line_of(14), 4);
        assert_eq!(src.line_of(20), 4);
        // The trailing newline opens an empty last line, which is where a
        // match at the very end of the text lands.
        assert_eq!(src.line_of(21), 5);
    }

    #[test]
    fn a_line_is_trimmed_and_cut() {
        let long = format!("   {}   ", "a".repeat(300));
        let src = Src::new("x".into(), format!("{long}\nnext\n"));
        let text = src.line_text(1);
        assert_eq!(text.len(), 200);
        assert!(!text.starts_with(' '));
        assert_eq!(src.line_text(2), "next");
        assert_eq!(src.line_text(99), "");
    }

    #[test]
    fn groups_keep_the_first_place_and_count_the_rest() {
        let mut groups = Groups::new(10);
        groups.add("/api/login".into(), "a.js:1".into());
        groups.add("/api/login".into(), "b.js:2".into());
        groups.add("/api/login".into(), "a.js:1".into());
        groups.add("/api/user".into(), "c.js:9".into());
        assert_eq!(groups.len(), 2);
        let text = groups.dump("Paths", 10);
        assert!(text.contains("## Paths: 2"));
        // The value with two places is listed first.
        let first = text.find("/api/login").unwrap();
        let second = text.find("/api/user").unwrap();
        assert!(first < second);
        // A repeat from the same place is not counted twice.
        assert!(text.contains("a.js:1 (+1)"));
    }

    #[test]
    fn a_filter_removes_values() {
        let mut groups = Groups::new(10);
        groups.add("/api/login".into(), "a.js:1".into());
        groups.add("/static/x".into(), "a.js:2".into());
        groups.retain(&regex::Regex::new("api").unwrap());
        assert_eq!(groups.len(), 1);
    }

    #[test]
    fn output_is_capped_and_says_so() {
        let text = (0..500)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = cap(&text, 400);
        assert!(out.contains("... 100 more lines"));
        assert_eq!(out.lines().count(), 401);
    }

    #[test]
    fn binary_and_empty_files_are_skipped() {
        let dir = std::env::temp_dir().join(format!("rekit-gather-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("app.js"), "fetch('/api/x')\n").unwrap();
        fs::write(dir.join("logo.png"), [0x89, b'P', b'N', b'G', 0, 0, 1]).unwrap();
        fs::write(dir.join("empty.js"), "").unwrap();
        let got = gather(dir.to_string_lossy().as_ref()).unwrap();
        assert_eq!(got.srcs.len(), 1);
        assert!(got.srcs[0].name.ends_with("app.js"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skipped_directories_stay_out() {
        let dir = std::env::temp_dir().join(format!("rekit-skip-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("node_modules/lib"));
        fs::write(dir.join("app.js"), "x").unwrap();
        fs::write(dir.join("node_modules/lib/index.js"), "y").unwrap();
        let got = gather(dir.to_string_lossy().as_ref()).unwrap();
        assert_eq!(got.srcs.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
