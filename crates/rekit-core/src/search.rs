//! Text search, line by line — the thing `grep -n -C` did in the plugin.
//!
//! Byte search (`hexdump::find`) answers "where are these bytes", which is the
//! right question for a binary and the wrong one for jadx output, smali, a JS
//! bundle or a strings dump: there the offset is useless and the line number is
//! the address. Both live side by side because both get asked.

use anyhow::{Context, Result};
use regex::RegexBuilder;
use std::path::{Path, PathBuf};

use crate::util::read_spec;

pub struct Options {
    /// Treat the pattern as a regex instead of a literal.
    pub regex: bool,
    pub ignore_case: bool,
    /// Lines of context before and after a match.
    pub context: usize,
    /// How many matching lines to report.
    pub limit: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            regex: false,
            ignore_case: false,
            context: 2,
            limit: 50,
        }
    }
}

enum Matcher {
    /// The needle, stored already folded when the search ignores case.
    Plain {
        needle: String,
        folded: bool,
    },
    Re(regex::Regex),
}

impl Matcher {
    fn build(pattern: &str, opts: &Options) -> Result<Self> {
        if opts.regex {
            if pattern.is_empty() {
                anyhow::bail!("empty regex");
            }
            let re = RegexBuilder::new(pattern)
                .case_insensitive(opts.ignore_case)
                // A line is small, so the default limit is plenty; the guard is
                // here because a caller-supplied regex can still backtrack on a
                // pathological line and hang the whole call.
                .size_limit(1 << 20)
                .build()
                .with_context(|| format!("{pattern:?} is not a valid regex"))?;
            return Ok(Matcher::Re(re));
        }
        if pattern.is_empty() {
            anyhow::bail!("empty pattern");
        }
        Ok(Matcher::Plain {
            needle: match opts.ignore_case {
                true => pattern.to_lowercase(),
                false => pattern.to_string(),
            },
            folded: opts.ignore_case,
        })
    }

    fn hits(&self, line: &str) -> bool {
        match self {
            Matcher::Plain {
                needle,
                folded: false,
            } => line.contains(needle.as_str()),
            Matcher::Plain {
                needle,
                folded: true,
            } => line.to_lowercase().contains(needle.as_str()),
            Matcher::Re(re) => re.is_match(line),
        }
    }
}

/// Search one file, given as a rekit spec (`archive::member` included).
pub fn text(spec: &str, pattern: &str, opts: &Options) -> Result<String> {
    let matcher = Matcher::build(pattern, opts)?;
    let (path, data) = read_spec(spec)?;
    let body = String::from_utf8_lossy(&data);
    let label = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| spec.to_string());
    Ok(scan(label, &body, pattern, &matcher, opts))
}

/// Search a tree of files, naming each hit by its path relative to `root`.
///
/// This is what makes `decompile pattern=...` one call instead of "decompile,
/// then find the cache directory, then grep it by hand".
pub fn tree(root: &Path, files: &[PathBuf], pattern: &str, opts: &Options) -> Result<String> {
    let matcher = Matcher::build(pattern, opts)?;
    let mut blocks = Vec::new();
    let mut total = 0usize;
    for file in files {
        if total >= opts.limit {
            break;
        }
        let Ok(data) = std::fs::read(file) else {
            continue;
        };
        let body = String::from_utf8_lossy(&data);
        let label = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .to_string();
        let mut budget = opts.limit - total;
        let block = scan_limited(label, &body, pattern, &matcher, opts, &mut budget);
        total = opts.limit - budget;
        if !block.is_empty() {
            blocks.push(block);
        }
    }
    if blocks.is_empty() {
        return Ok(format!(
            "no matches for {pattern:?} in {} files\n",
            files.len()
        ));
    }
    let mut out = format!("{total} matches for {pattern:?}\n");
    for block in blocks {
        out.push_str(&block);
    }
    if total >= opts.limit {
        out.push_str(&format!(
            "(limit {} reached, raise it for more)\n",
            opts.limit
        ));
    }
    Ok(out)
}

fn scan(label: String, body: &str, pattern: &str, matcher: &Matcher, opts: &Options) -> String {
    let mut budget = opts.limit;
    let block = scan_limited(label, body, pattern, matcher, opts, &mut budget);
    if block.is_empty() {
        return format!("no matches for {pattern:?}\n");
    }
    block
}

fn scan_limited(
    label: String,
    body: &str,
    pattern: &str,
    matcher: &Matcher,
    opts: &Options,
    budget: &mut usize,
) -> String {
    // A trailing newline is a terminator, not an empty last line: printing it
    // as context would suggest content the file does not have.
    let body = body.strip_suffix('\n').unwrap_or(body);
    let lines: Vec<&str> = body.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    let matched: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| matcher.hits(line))
        .map(|(i, _)| i)
        .collect();
    if matched.is_empty() {
        return String::new();
    }

    let mut out = format!(
        "{label}: {} {} for {pattern:?}\n",
        matched.len(),
        match matched.len() {
            1 => "matching line",
            _ => "matching lines",
        }
    );
    let mut shown_to = 0usize; // first line number already printed
    let mut printed = 0usize;
    for &index in &matched {
        if printed >= *budget {
            out.push_str("  ... (limit reached)\n");
            break;
        }
        printed += 1;
        // 1-based numbers, clamped to the first and last line.
        let from = index.saturating_sub(opts.context);
        let to = (index + opts.context + 1).min(lines.len());
        if from > shown_to && shown_to > 0 {
            out.push_str("  --\n");
        }
        let start = from.max(shown_to);
        for (offset, line) in lines[start..to].iter().enumerate() {
            let number = start + offset + 1;
            let sep = if number == index + 1 { ':' } else { '-' };
            out.push_str(&format!("  {number}{sep} {line}\n"));
        }
        shown_to = to;
    }
    *budget = budget.saturating_sub(printed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One file per test: the tests run in parallel, and a shared name lets one
    /// truncate the file another is reading.
    fn sample(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("rekit-search-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, "alpha\nbeta\nGAMMA\ndelta\nepsilon\ngamma again\n").unwrap();
        path
    }

    #[test]
    fn finds_a_literal_and_shows_the_line_number() {
        let p = sample("literal.txt");
        let out = text(
            &p.display().to_string(),
            "gamma",
            &Options {
                ignore_case: true,
                context: 1,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(out.contains("2 matching lines"), "{out}");
        assert!(out.contains("3: GAMMA"), "{out}");
        assert!(out.contains("6: gamma again"), "{out}");
        assert!(out.contains("2- beta"), "context before GAMMA: {out}");
        assert!(out.contains("4- delta"), "context after GAMMA: {out}");
    }

    #[test]
    fn regex_mode_needs_a_valid_pattern() {
        let p = sample("regex.txt");
        let opts = Options {
            regex: true,
            ..Options::default()
        };
        let out = text(&p.display().to_string(), "^a.*a$", &opts).unwrap();
        assert!(out.contains("alpha"), "{out}");
        assert!(!out.contains("3: GAMMA"), "the anchor must hold: {out}");

        let err = text(&p.display().to_string(), "([unclosed", &opts)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid regex"), "{err}");
    }

    #[test]
    fn plain_mode_is_not_a_regex() {
        let p = sample("plain.txt");
        let out = text(&p.display().to_string(), "a.*a", &Options::default()).unwrap();
        assert!(out.contains("no matches"), "{out}");
    }

    #[test]
    fn the_limit_stops_the_walk() {
        let p = sample("limit.txt");
        let opts = Options {
            ignore_case: true,
            limit: 1,
            ..Options::default()
        };
        let out = text(&p.display().to_string(), "a", &opts).unwrap();
        assert!(out.contains("limit reached"), "{out}");
    }

    #[test]
    fn tree_mode_names_the_file() {
        let p = sample("tree.txt");
        let root = p.parent().unwrap();
        let out = tree(root, std::slice::from_ref(&p), "beta", &Options::default()).unwrap();
        assert!(out.contains("tree.txt:"), "{out}");
        assert!(out.contains("2: beta"), "{out}");
    }
}
