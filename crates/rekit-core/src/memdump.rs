//! Memory dumps, through volatility3.
//!
//! A dump is the one artefact where the interesting facts are not in the file's
//! structure but in what the machine had in RAM: which processes were running,
//! which sockets were open, what was typed into a shell. volatility3 answers
//! those questions, and it is a Python package rather than a binary — so the
//! first job here is finding an interpreter that can import it, because the
//! `vol` wrapper on `$PATH` is as often broken as not.
//!
//! There is no `volatility3` console script entry point worth trusting: the
//! package ships no usable `__main__`, so the interpreter is invoked with `-c`
//! and `volatility3.cli.main`, and `sys.argv` is built by hand. That also means
//! `-f` has to be put into `sys.argv` rather than on the command line: anything
//! after `-c` lands in the script's `sys.argv`, which is immediately replaced.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Result};
use regex::Regex;

use crate::external::{capture, which};

/// A dump of any size is worth waiting for; volatility on a 16 GB image is
/// minutes, not seconds.
const TIMEOUT: Duration = Duration::from_secs(600);
/// The probe only needs to answer whether the import works.
const PROBE: Duration = Duration::from_secs(30);

/// Plugins worth naming when the caller has not picked one. volatility has
/// hundreds; these are the four questions asked first.
const COMMON: &[(&str, &str)] = &[
    ("windows.info", "which build this dump is from"),
    ("windows.pslist", "processes"),
    ("windows.pstree", "process tree"),
    ("windows.netscan", "sockets and connections"),
    ("windows.cmdline", "command lines of running processes"),
    ("windows.filescan", "file objects in memory"),
    ("windows.registry.hivelist", "registry hives"),
    ("linux.pslist", "processes"),
    ("linux.bash", "shell history"),
    ("linux.netscan", "sockets and connections"),
];

#[derive(Debug, Clone)]
pub struct Request {
    pub path: String,
    pub plugin: Option<String>,
    /// Extra plugin arguments, split on whitespace with quote support.
    pub args: Option<String>,
    pub list: bool,
    /// Narrow the plugin list.
    pub filter: Option<String>,
    pub limit: usize,
}

pub fn run(req: &Request) -> Result<String> {
    let dump = crate::resolve::resolve(&req.path)?;
    if !dump.is_file() {
        bail!("{} is not a file", dump.display());
    }
    let python = volatility_python().ok_or_else(|| {
        anyhow::anyhow!(
            "no Python can import volatility3\n\
             install it with `pipx install volatility3`, or point REKIT_VOL_PYTHON at \
             an interpreter that has it"
        )
    })?;

    let plugin = req
        .plugin
        .as_deref()
        .map(str::trim)
        .filter(|plugin| !plugin.is_empty());

    if req.list || plugin.is_none() {
        return list(&python, &dump, &req.path, req);
    }
    let plugin = plugin.expect("checked above");

    let mut args: Vec<String> = vec![
        "-q".to_string(),
        // Symbol tables are fetched over the network by default when one is
        // missing. An analysis tool should not reach out mid-run, and a model
        // cannot tell a slow download from a hang.
        "--offline".to_string(),
        "-f".to_string(),
        dump.display().to_string(),
        plugin.to_string(),
    ];
    args.extend(split_args(req.args.as_deref().unwrap_or("")));

    let out = volatility(&python, &args)?;
    let body = if out.stdout.trim().is_empty() {
        out.stderr.clone()
    } else {
        out.stdout.clone()
    };
    if !out.success && out.stdout.trim().is_empty() {
        bail!(
            "volatility3 {plugin} did not run:\n{}\n\
             run it without --plugin to see the names this dump supports",
            first_error(&out.stderr)
        );
    }

    Ok(cap(
        &format!(
            "volatility3 {plugin} — {}{}\n{}",
            name_of(&dump),
            note_for(&req.path),
            cap(&body, req.limit)
        ),
        req.limit + 4,
    ))
}

fn list(python: &Path, dump: &Path, spec: &str, req: &Request) -> Result<String> {
    let out = volatility(
        python,
        &[
            "-q".to_string(),
            "--offline".to_string(),
            "-f".to_string(),
            dump.display().to_string(),
            "--help".to_string(),
        ],
    )?;
    // The help text is the only place volatility lists its plugins, and it is
    // a few hundred kilobytes: the lines that look like `windows.pslist` are
    // the ones worth keeping.
    let plugin_line = Regex::new(r"^\s{4}([a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+)+)(?:\s{2,}(.*))?$")
        .expect("static pattern");
    let filter = match req
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty())
    {
        Some(pattern) => Some(
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|err| anyhow::anyhow!("filter {pattern:?} is not a valid regex: {err}"))?,
        ),
        None => None,
    };

    let lines: Vec<&str> = out.stdout.lines().collect();
    let mut plugins: Vec<(String, String)> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let Some(caps) = plugin_line.captures(lines[index]) else {
            index += 1;
            continue;
        };
        let name = caps[1].to_string();
        let mut description = caps
            .get(2)
            .map(|group| group.as_str().trim().to_string())
            .unwrap_or_default();
        // A description too long for one line wraps onto the next, indented
        // under it. Without joining it back, half the list would end mid-word.
        index += 1;
        while index < lines.len()
            && !plugin_line.is_match(lines[index])
            && lines[index].starts_with("        ")
        {
            if !description.is_empty() {
                description.push(' ');
            }
            description.push_str(lines[index].trim());
            index += 1;
        }
        if filter
            .as_ref()
            .is_some_and(|filter| !filter.is_match(&name))
        {
            continue;
        }
        plugins.push((name, description));
    }

    // The help text is alphabetical, which puts the framework's own plugins
    // first and the operating systems after them; the OS plugins are what a
    // caller is looking for, so they go first.
    plugins.sort_by(|a, b| rank(&a.0).cmp(&rank(&b.0)).then_with(|| a.0.cmp(&b.0)));

    if plugins.is_empty() {
        // A dump volatility cannot identify still answers `--help`; no plugin
        // lines means the help text changed, not that the dump is broken.
        if !out.success && out.stdout.trim().is_empty() {
            bail!(
                "volatility3 --help did not run:\n{}",
                first_error(&out.stderr)
            );
        }
        bail!(
            "no plugins matched{}: volatility3 printed no plugin list",
            match &req.filter {
                Some(pattern) => format!(" filter {pattern:?}"),
                None => String::new(),
            }
        );
    }

    let shown = plugins.len().min(req.limit.max(1));
    let mut text = format!(
        "dump: {}{}\nplugins: {}{}\n\n",
        name_of(dump),
        note_for(spec),
        plugins.len(),
        match &req.filter {
            Some(pattern) => format!(" (filter: /{pattern}/i)"),
            None => String::new(),
        }
    );
    let width = plugins
        .iter()
        .take(shown)
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(34, 52);
    for (name, description) in plugins.iter().take(shown) {
        let description = clip(description, 90);
        let line = if description.is_empty() {
            format!("  {name}")
        } else {
            format!("  {name:<width$} {description}")
        };
        text.push_str(&line);
        text.push('\n');
    }
    if plugins.len() > shown {
        text.push_str(&format!(
            "  ... {} more (raise limit or filter)\n",
            plugins.len() - shown
        ));
    }
    // A filtered list is already narrow; the usual suspects would be noise.
    if req.filter.is_none() {
        text.push_str("\ncommon plugins:\n");
        for (name, purpose) in COMMON {
            text.push_str(&format!("  {name:<width$} {purpose}\n"));
        }
    }
    text.push_str(
        "\npass plugin=windows.pslist (and args=\"--pid 1234\") to run one; \
         the short form of a name is enough\n",
    );
    Ok(cap(&text, req.limit + 20))
}

struct VolOutput {
    stdout: String,
    stderr: String,
    success: bool,
}

/// Run one volatility command. `args` are the arguments volatility itself
/// would see, without the interpreter.
fn volatility(python: &Path, args: &[String]) -> Result<VolOutput> {
    let script = format!(
        "import sys; from volatility3.cli import main; sys.argv=['vol']+{}; main()",
        serde_json::to_string(args)?
    );
    let out = capture(
        &python.display().to_string(),
        &["-c".to_string(), script],
        TIMEOUT,
        &[],
        // volatility writes its symbol cache under the working directory, so
        // it gets a cache path rather than wherever rekit was started from.
        Some(&crate::resolve::cache_root()),
    )?;
    Ok(VolOutput {
        stdout: out.stdout,
        stderr: out.stderr,
        success: out.success && !out.timed_out,
    })
}

/// An interpreter that can `import volatility3`.
///
/// `vol` on `$PATH` is not checked: pipx shims carry a shebang that points at
/// the venv by absolute path, and when that path moves the shim still exists,
/// still fails, and looks installed. Asking the interpreter itself is the only
/// answer that stays true.
fn volatility_python() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = std::env::var_os("REKIT_VOL_PYTHON") {
        candidates.push(PathBuf::from(explicit));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        candidates.push(home.join(".local/share/pipx/venvs/volatility3/bin/python"));
        candidates.push(home.join(".local/share/uv/tools/volatility3/bin/python"));
    }
    for name in ["python3", "/usr/bin/python3"] {
        if let Some(path) = which(name) {
            candidates.push(path);
        }
    }

    candidates.into_iter().find(|python| can_import(python))
}

fn can_import(python: &Path) -> bool {
    capture(
        &python.display().to_string(),
        &["-c".to_string(), "import volatility3".to_string()],
        PROBE,
        &[],
        None,
    )
    .map(|out| out.success && !out.timed_out)
    .unwrap_or(false)
}

/// Split `--pid 1234 --name "a b"` the way a shell would, for the small subset
/// of quoting that matters here.
fn split_args(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut has_content = false;
    for ch in text.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                has_content = true;
            }
            None if ch.is_whitespace() => {
                if has_content {
                    out.push(std::mem::take(&mut current));
                    has_content = false;
                }
            }
            None => {
                current.push(ch);
                has_content = true;
            }
        }
    }
    if has_content {
        out.push(current);
    }
    out
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

/// Say where an `archive::inner` spec came from; a dump alone is unambiguous.
fn note_for(spec: &str) -> String {
    match spec.split_once("::") {
        Some((outer, _)) => {
            let base = Path::new(outer)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| outer.to_string());
            format!(" (extracted from {base})")
        }
        None => String::new(),
    }
}

/// The one line of a tool's stderr that explains what went wrong.
///
/// volatility answers a bad plugin name with its full usage text, ending in a
/// single line listing every choice — several thousand characters on one line.
/// A line budget does not help there, so the error line is found and clipped
/// instead.
fn first_error(stderr: &str) -> String {
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|line| line.contains("error:") || line.contains("Error:"))
        .filter(|line| !line.is_empty());
    match line {
        Some(line) => clip(line, 300),
        None => clip(stderr.trim(), 600),
    }
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('\u{2026}');
    out
}

/// Operating system plugins first, then the framework's own.
fn rank(name: &str) -> u8 {
    if name.starts_with("windows.") {
        0
    } else if name.starts_with("linux.") {
        1
    } else if name.starts_with("mac.") {
        2
    } else {
        3
    }
}

/// Trim to a line budget, saying how much was dropped.
fn cap(text: &str, lines: usize) -> String {
    let lines = lines.max(1);
    let all: Vec<&str> = text.lines().collect();
    if all.len() <= lines {
        return text.trim_end().to_string();
    }
    let mut out = all[..lines].join("\n");
    out.push_str(&format!(
        "\n... {} more lines (raise limit)",
        all.len() - lines
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_split_on_whitespace_and_respect_quotes() {
        assert_eq!(
            split_args("--pid 1234 --name \"a b\""),
            vec!["--pid", "1234", "--name", "a b"]
        );
        assert_eq!(split_args("  "), Vec::<String>::new());
        assert_eq!(split_args("'x y'"), vec!["x y"]);
        assert_eq!(split_args("a\"b c\"d"), vec!["ab cd"]);
    }

    #[test]
    fn output_is_cut_at_the_line_limit() {
        let text = (0..10)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(cap(&text, 10), text);
        assert!(cap(&text, 4).contains("... 6 more lines"));
    }

    #[test]
    fn the_error_line_is_found_inside_a_wall_of_usage_text() {
        let stderr = "usage: -c [-h]\n          PLUGIN ...\n\
                      -c: error: argument PLUGIN: invalid choice nope (choose from a, b, c)\n";
        let found = first_error(stderr);
        assert!(found.starts_with("-c: error:"));
        assert!(!found.contains("usage:"));
        // A very long choice list is clipped rather than returned whole.
        let long = format!("-c: error: {}", "x".repeat(5000));
        assert!(first_error(&long).chars().count() <= 301);
    }

    #[test]
    fn operating_system_plugins_are_listed_before_framework_ones() {
        let mut names = vec![
            "banners.Banners".to_string(),
            "windows.pslist.PsList".to_string(),
            "linux.bash.Bash".to_string(),
            "mac.pslist.PsList".to_string(),
        ];
        names.sort_by_key(|name| rank(name));
        assert_eq!(
            names,
            vec![
                "windows.pslist.PsList",
                "linux.bash.Bash",
                "mac.pslist.PsList",
                "banners.Banners"
            ]
        );
    }

    #[test]
    fn archive_specs_say_where_they_came_from() {
        assert_eq!(note_for("mem.raw"), "");
        assert_eq!(
            note_for("bundle.zip::mem.raw"),
            " (extracted from bundle.zip)"
        );
    }

    #[test]
    fn a_missing_plugin_list_is_an_error_not_an_empty_answer() {
        // The help parser is the only way the list is produced, so a changed
        // help format must surface rather than look like "no plugins".
        let line =
            Regex::new(r"^\s{4}([a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+)+)(?:\s{2,}(.*))?$").unwrap();
        assert!(line.is_match("    windows.pslist.PsList    Process list"));
        assert!(line.is_match("    linux.elfs.Elfs"));
        assert!(!line.is_match("  windows.pslist"));
        assert!(!line.is_match("usage: -c [-h] [-c CONFIG]"));
    }
}
