//! Ghidra headless: native code decompiled to C.
//!
//! Ghidra has no binary in PATH and no CLI of its own — the supported way in
//! is `analyzeHeadless` plus a post-script, which means four things have to be
//! right at once: the project directory, the program name, the script path and
//! a stale `.lock` from an earlier crash. Each of those produces a confusing
//! failure on its own, so they are handled here rather than at every call.
//!
//! The analysis itself is cached: a project keyed by the input file is created
//! once and reopened with `-noanalysis` afterwards, which takes seconds instead
//! of minutes.

use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::decompilers::{error_lines, needle, take_lines};
use crate::external::capture;
use crate::info::analyze;
use crate::resolve::resolve;

const GH_DECOMPILE: &str = r#"//@category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import java.io.*;

public class GhDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) { println("usage: GhDecompile <out> <needle|@LIST> <limit>"); return; }
        String outPath = args[0];
        String needle = args[1];
        int limit = Integer.parseInt(args[2]);

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(currentProgram);

        StringBuilder sb = new StringBuilder();
        if (needle.isEmpty() || needle.equals("@LIST")) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int n = 0;
            while (it.hasNext() && n < 4000) {
                Function f = it.next();
                sb.append(f.getEntryPoint()).append("  ").append(f.getName())
                  .append("  size=").append(f.getBody().getNumAddresses()).append('\n');
                n++;
            }
            sb.append("TOTAL=").append(n).append('\n');
        } else if (needle.startsWith("@")) {
            Address given = toAddr(needle.substring(1));
            Function f = find(given);
            if (f == null) {
                // Ghidra rebases ELF images (0x100000 by default), so an address
                // copied from objdump, r2 or `info` lands below the image base
                // and matches nothing. Retry it as an offset into the image.
                Address rebased = currentProgram.getImageBase().add(given.getOffset());
                f = find(rebased);
                if (f != null) {
                    sb.append("address ").append(given).append(" read as ")
                      .append(rebased).append(" (image base + offset)\n");
                }
            }
            if (f == null) { sb.append("no function at ").append(given).append('\n'); }
            else {
                sb.append("== ").append(f.getName()).append(" @ ").append(f.getEntryPoint())
                  .append(" size=").append(f.getBody().getNumAddresses()).append(" ==\n");
                sb.append(decomp(di, f));
            }
        } else {
            // Exact names first: searching for "main" would otherwise find
            // __libc_start_main and decompile the wrong function.
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            java.util.List<Function> exact = new java.util.ArrayList<>();
            java.util.List<Function> partial = new java.util.ArrayList<>();
            while (it.hasNext()) {
                Function f = it.next();
                if (f.getName().equals(needle)) exact.add(f);
                else if (f.getName().contains(needle)) partial.add(f);
            }
            java.util.List<Function> use = !exact.isEmpty() ? exact : partial;
            int n = 0;
            for (Function f : use) {
                if (n >= limit) break;
                sb.append("== ").append(f.getName()).append(" @ ").append(f.getEntryPoint())
                  .append(" size=").append(f.getBody().getNumAddresses()).append(" ==\n");
                sb.append(decomp(di, f));
                n++;
            }
            if (n == 0) { sb.append("no function matching '").append(needle).append("'\n"); }
            else {
                sb.append("MATCHED=").append(n).append(exact.isEmpty() ? " (partial names)" : " (exact)").append('\n');
            }
        }

        di.dispose();
        PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outPath), "UTF-8"));
        pw.print(sb);
        pw.close();
        println("written " + sb.length() + " chars to " + outPath);
    }

    private Function find(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(a);
        return f;
    }

    private String decomp(DecompInterface di, Function f) {
        if (f == null) return "(null)\n";
        DecompileResults r = di.decompileFunction(f, 90, monitor);
        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
            return r.getDecompiledFunction().getC() + "\n\n";
        }
        return "(decompile failed: " + (r != null ? r.getErrorMessage() : "null") + ")\n\n";
    }
}
"#;

/// Ghidra lives outside PATH, so it is located by its layout, not by name.
pub fn home() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("GHIDRA_DIR") {
        candidates.push(PathBuf::from(dir));
    }
    candidates.extend(
        ["/opt/ghidra", "/usr/share/ghidra", "/opt/ghidra_11"]
            .into_iter()
            .map(PathBuf::from),
    );
    candidates
        .into_iter()
        .find(|dir| dir.join("support").join("analyzeHeadless").is_file())
}

/// Ghidra refuses any path element that starts with '.', so the obvious home
/// for this cache — `~/.cache/rekit` — cannot hold a project at all. The
/// workspace therefore sits in the home directory (no dot in any element),
/// and `REKIT_GHIDRA_DIR` overrides it.
pub fn workspace() -> PathBuf {
    if let Some(dir) = std::env::var_os("REKIT_GHIDRA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(home).join("rekit-ghidra");
        if dot_free(&candidate) {
            return candidate;
        }
    }
    PathBuf::from("/tmp/rekit-ghidra")
}

fn dot_free(path: &Path) -> bool {
    path.components()
        .all(|part| !part.as_os_str().to_string_lossy().starts_with('.'))
}

/// One analysed Ghidra project plus the script that reads it: enough state that
/// a call only has to say what it wants.
struct Session<'a> {
    headless: &'a Path,
    project_dir: &'a Path,
    project: String,
    program: String,
    scripts: &'a Path,
    out_file: &'a Path,
}

impl Session<'_> {
    /// Run the post-script and return what it wrote, or a readable failure.
    ///
    /// `import` decides the mode: with a file the program is analysed first,
    /// without one the existing analysis is reopened as is.
    fn run(
        &self,
        needle: &str,
        limit: usize,
        import: Option<&Path>,
        timeout: Duration,
    ) -> Result<String> {
        let mut args = vec![self.project_dir.display().to_string(), self.project.clone()];
        match import {
            Some(path) => {
                args.push("-import".to_string());
                args.push(path.display().to_string());
                args.push("-analysisTimeoutPerFile".to_string());
                args.push("300".to_string());
            }
            None => {
                args.push("-process".to_string());
                args.push(self.program.clone());
                args.push("-noanalysis".to_string());
            }
        }
        args.extend([
            "-scriptPath".to_string(),
            self.scripts.display().to_string(),
            "-postScript".to_string(),
            "GhDecompile.java".to_string(),
            self.out_file.display().to_string(),
            needle.to_string(),
            limit.to_string(),
        ]);

        let _ = std::fs::remove_file(self.out_file);

        let out = capture(
            &self.headless.display().to_string(),
            &args,
            timeout,
            &[],
            None,
        )?;
        if out.timed_out {
            bail!(
                "Ghidra did not finish within {}s — `r2` answers faster",
                timeout.as_secs()
            );
        }

        let log = format!("{}\n{}", out.stdout, out.stderr);
        let body = std::fs::read_to_string(self.out_file).ok();
        match body {
            Some(text) if !text.trim().is_empty() => Ok(text),
            _ => bail!("Ghidra produced no output:\n{}", error_lines(&log, 15)),
        }
    }

    /// Everything the program contains — the answer to a name that matched
    /// nothing, since the caller cannot guess what the symbol is really called.
    fn listing(&self) -> String {
        self.run("@LIST", 4000, None, Duration::from_secs(600))
            .unwrap_or_default()
    }
}

pub fn decompile(
    spec: &str,
    symbol: Option<&str>,
    address: Option<&str>,
    limit: usize,
    reanalyze: bool,
) -> Result<String> {
    let home = home().ok_or_else(|| {
        anyhow!(
            "Ghidra not found. Looked in /opt/ghidra and /usr/share/ghidra for \
             support/analyzeHeadless.\nSet GHIDRA_DIR=/path/to/ghidra if it lives \
             elsewhere. Without Ghidra: `r2` is much faster and needs no install."
        )
    })?;
    let headless = home.join("support").join("analyzeHeadless");

    let path = resolve(spec)?;
    let info = analyze(spec)?;
    crate::decompilers::native_only(
        &path.display().to_string(),
        &info.format,
        info.hints.iter().any(|hint| hint.contains(".NET assembly")),
    )?;

    let needle = needle(symbol, address)?;
    let limit = limit.clamp(1, 200);

    let scripts = workspace().join("scripts");
    std::fs::create_dir_all(&scripts)?;
    let script = scripts.join("GhDecompile.java");
    // Always rewritten: Ghidra caches compiled script bundles by file name and
    // would otherwise keep running an older version of this script.
    std::fs::write(&script, GH_DECOMPILE)?;

    // Project identity is the input's content, not its path, so the same `so`
    // reached through an apk and directly share one analysis.
    let project_dir = workspace().join("projects");
    std::fs::create_dir_all(&project_dir)?;
    let key = crate::decompilers::key(&path);
    let project = format!("p_{key}");
    let analyzed = project_dir.join(format!("{project}.gpr")).exists();
    // A crashed run leaves `<project>.lock` and every later run then dies with
    // "Unable to lock project!" — the lock belongs to no live process.
    let _ = std::fs::remove_file(project_dir.join(format!("{project}.lock")));

    let out_file = crate::resolve::cache_root()
        .join("ghidra")
        .join(format!("{key}.txt"));
    let program = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "program".to_string());
    let reopen = analyzed && !reanalyze;

    let session = Session {
        headless: &headless,
        project_dir: &project_dir,
        project: project.clone(),
        program,
        scripts: &scripts,
        out_file: &out_file,
    };

    let body = session.run(
        &needle,
        limit,
        if reopen { None } else { Some(&path) },
        Duration::from_secs(900),
    )?;

    let head = format!(
        "Ghidra: {}{}\nproject: {}{}\n",
        path.display(),
        if info.format.is_empty() || info.format == "unknown" {
            String::new()
        } else {
            format!(" ({})", info.format)
        },
        project,
        if reopen { " (cached)" } else { " (created)" }
    );

    if body.contains("no function matching") || body.contains("no function at") {
        return Ok(format!(
            "{head}{}\n\nname did not match. Functions in this binary:\n{}",
            body.trim(),
            take_lines(&session.listing(), 40)
        ));
    }

    Ok(format!(
        "{head}\n{}\n",
        take_lines(body.trim_end(), limit * 30)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_workspaces_never_contain_a_dotted_element() {
        assert!(dot_free(Path::new("/home/u/rekit-ghidra")));
        assert!(!dot_free(Path::new("/home/u/.cache/rekit")));
        assert!(!dot_free(Path::new("/home/u/.cache")));
        assert!(dot_free(&workspace()));
    }

    #[test]
    fn the_script_matches_what_we_invoke() {
        assert!(GH_DECOMPILE.contains("public class GhDecompile extends GhidraScript"));
        assert!(GH_DECOMPILE.contains("getScriptArgs()"));
        // The script reads three arguments and the caller always passes three.
        assert!(GH_DECOMPILE.contains("args.length < 3"));
    }
}
