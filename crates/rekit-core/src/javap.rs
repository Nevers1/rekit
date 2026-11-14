//! `javap` — JVM bytecode.
//!
//! javap wants a *class name*, not a path, for anything inside a jar; for a
//! bare `.class` it is happy with the file. Rather than make the caller
//! remember that, the name is recovered from the class file itself: its
//! constant pool holds `this_class` as `a/b/C`, which is exactly what javap
//! expects once the slashes become dots.

use anyhow::{bail, Result};
use std::path::Path;

use crate::decompilers::take_lines;
use crate::external::{run, which};
use crate::resolve::resolve;
use std::time::Duration;

/// Read `this_class` out of a class file's constant pool.
///
/// Only the two entry kinds that matter are decoded: UTF-8 strings and Class
/// references. Every other tag is skipped by its fixed width, with the
/// long/double special case (they occupy two pool slots).
pub fn class_name(data: &[u8]) -> Option<String> {
    if data.len() < 10 || &data[..4] != b"\xca\xfe\xba\xbe" {
        return None;
    }
    let be16 = |at: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
    };

    let count = be16(8)? as usize;
    let mut at = 10;
    let mut utf8: Vec<Option<String>> = vec![None; count.max(1)];
    let mut classes: Vec<Option<u16>> = vec![None; count.max(1)];

    let mut i = 1;
    while i < count {
        let tag = *data.get(at)?;
        at += 1;
        match tag {
            1 => {
                let len = be16(at)? as usize;
                at += 2;
                let text = std::str::from_utf8(data.get(at..at + len)?).ok()?;
                utf8[i] = Some(text.to_string());
                at += len;
            }
            7 => {
                classes[i] = Some(be16(at)?);
                at += 2;
            }
            8 | 16 | 19 | 20 => at += 2,
            15 => at += 3,
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => at += 4,
            5 | 6 => {
                at += 8;
                i += 1; // long and double take two pool slots
            }
            _ => return None,
        }
        i += 1;
    }

    // After the pool: access_flags (u2), then this_class (u2).
    let this_class = be16(at + 2)? as usize;
    let name_index = (*classes.get(this_class)?)? as usize;
    utf8.get(name_index)?
        .clone()
        .map(|name| name.replace('/', "."))
}

/// Is this text a method signature line, as javap prints them?
fn is_signature(line: &str) -> bool {
    line.contains('(') && line.trim_end().ends_with([';', ')'])
}

/// Keep one method's block: from its signature to the next line at the same
/// or lower indentation. Works for both `-s` (signatures) and `-c` (bytecode).
fn slice_method(body: &str, method: &str) -> Option<String> {
    let lines: Vec<&str> = body.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.contains(method) && is_signature(line))?;
    let indent = lines[start].len() - lines[start].trim_start().len();
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| {
            let line = *line;
            !line.trim().is_empty() && line.len() - line.trim_start().len() <= indent
        })
        .map(|(i, _)| i)
        .unwrap_or(lines.len());
    Some(lines[start..end].join("\n"))
}

/// javap says nothing useful when it cannot find a class — it prints usage on
/// stderr, which is easy to lose. The answer here is a name to copy, so the
/// entries of the archive are offered as dotted class names.
fn not_found(path: &Path, name: Option<&str>, archive: bool) -> String {
    let mut out = format!("javap could not read {}.\n", path.display());
    match name {
        Some(name) => out.push_str(&format!("class {name:?} was not found in it.\n")),
        None => out.push_str(
            "no class name was given, and this file is not a .class: for a jar or \
             an apk pass `class` as a dotted name, e.g. com.example.Foo.\n",
        ),
    }

    if archive {
        if let Ok(entries) = crate::resolve::list_entries(path) {
            let classes: Vec<String> = entries
                .iter()
                .filter(|entry| entry.name.ends_with(".class"))
                .map(|entry| entry.name.trim_end_matches(".class").replace('/', "."))
                .collect();

            let simple =
                name.map(|name| name.rsplit('.').next().unwrap_or(name).to_ascii_lowercase());
            let near: Vec<&String> = classes
                .iter()
                .filter(|class| match &simple {
                    Some(simple) => class.to_ascii_lowercase().contains(simple),
                    None => true,
                })
                .take(20)
                .collect();

            if !classes.is_empty() {
                out.push_str(&format!("classes in the archive: {}\n", classes.len()));
                if !near.is_empty() {
                    out.push_str("similar:\n");
                    for class in near {
                        out.push_str(&format!("  {class}\n"));
                    }
                } else {
                    out.push_str("first classes:\n");
                    for class in classes.iter().take(20) {
                        out.push_str(&format!("  {class}\n"));
                    }
                }
            }
        }
    }

    out.push_str("For dex/apk bytecode `decompile` gives Java source.\n");
    out
}

fn signatures(body: &str) -> Vec<String> {
    body.lines()
        .filter(|line| is_signature(line))
        .map(|line| format!("  {}", line.trim()))
        .take(40)
        .collect()
}

pub fn decompile(
    spec: &str,
    class: Option<&str>,
    method: Option<&str>,
    code: bool,
    limit: usize,
) -> Result<String> {
    if which("javap").is_none() {
        bail!("javap is not installed: it comes with the JDK, e.g. `pacman -S jdk-openjdk`");
    }
    let path = resolve(spec)?;
    let is_class_file = path
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("class"))
        .unwrap_or(false);

    let name = match class.map(str::trim).filter(|c| !c.is_empty()) {
        Some(name) => Some(name.to_string()),
        None if is_class_file => std::fs::read(&path).ok().and_then(|d| class_name(&d)),
        None => None,
    };

    let flags: Vec<String> = if code {
        vec!["-p".into(), "-c".into(), "-constants".into()]
    } else {
        vec!["-p".into(), "-s".into()]
    };

    // A jar has to go on the classpath itself: putting the *directory* that
    // holds it on `-cp` does not make javap look inside the jar, which is why
    // `-cp /tmp/com.example.Foo` finds nothing at all.
    let is_archive = matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .as_deref(),
        Some("jar" | "zip" | "apk" | "aar")
    );
    let classpath = if is_archive {
        path.display().to_string()
    } else {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .display()
            .to_string()
    };

    let mut body = String::new();
    if is_class_file {
        // javap reads the file directly, which sidesteps classpath games.
        let mut args = flags.clone();
        args.push(path.display().to_string());
        body = run("javap", &args, Duration::from_secs(120)).unwrap_or_default();
    }
    if body.trim().is_empty() {
        if let Some(name) = &name {
            let mut args = flags.clone();
            args.push("-cp".into());
            args.push(classpath.clone());
            args.push(name.clone());
            body = run("javap", &args, Duration::from_secs(300)).unwrap_or_default();
            if body.trim().is_empty() && is_class_file {
                // A class file outside a package also answers to its bare stem.
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let mut args = flags;
                    args.extend(["-cp".to_string(), classpath.clone(), stem.to_string()]);
                    body = run("javap", &args, Duration::from_secs(120)).unwrap_or_default();
                }
            }
        }
    }

    if body.trim().is_empty() {
        return Ok(not_found(&path, name.as_deref(), is_archive));
    }

    let body = match method.map(str::trim).filter(|m| !m.is_empty()) {
        None => body,
        Some(method) => match slice_method(&body, method) {
            Some(block) => block,
            None => {
                let mut out = format!("method {method:?} not found. Available:\n");
                for line in signatures(&body) {
                    out.push_str(&line);
                    out.push('\n');
                }
                out
            }
        },
    };

    let mut out = format!("javap: {}\n", path.display());
    out.push_str(&take_lines(body.trim_end(), limit));
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest class file that still has a `this_class` pointing at a
    /// UTF-8 entry: magic, versions, two constant pool entries, header.
    fn synthetic_class(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\xca\xfe\xba\xbe");
        out.extend_from_slice(&[0, 0]); // minor
        out.extend_from_slice(&[0, 52]); // major
        out.extend_from_slice(&3u16.to_be_bytes()); // pool count
        out.push(1); // Utf8
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(7); // Class
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0x0021u16.to_be_bytes()); // access_flags
        out.extend_from_slice(&2u16.to_be_bytes()); // this_class
        out.extend_from_slice(&0u16.to_be_bytes()); // super_class
        out
    }

    #[test]
    fn reads_the_class_name_from_the_constant_pool() {
        let data = synthetic_class("com/example/Foo");
        assert_eq!(class_name(&data).as_deref(), Some("com.example.Foo"));
    }

    #[test]
    fn rejects_files_that_are_not_classes() {
        assert_eq!(class_name(b"\x7fELF not a class"), None);
        assert_eq!(class_name(b""), None);
    }

    #[test]
    fn long_entries_occupy_two_pool_slots() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\xca\xfe\xba\xbe");
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&5u16.to_be_bytes()); // pool: 1=long, 2=unused, 3=Utf8, 4=Class
        data.push(5); // Long
        data.extend_from_slice(&[0; 8]);
        data.push(1);
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(b"a/B");
        data.push(7);
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&[0x21, 0]); // access
        data.extend_from_slice(&4u16.to_be_bytes()); // this_class
        data.extend_from_slice(&[0, 0]);
        assert_eq!(class_name(&data).as_deref(), Some("a.B"));
    }

    #[test]
    fn a_missing_class_offers_dotted_names_from_the_archive() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("rekit-javap-archive");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let jar = dir.join("a.jar");

        {
            let file = std::fs::File::create(&jar).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("com/example/Foo.class", opts).unwrap();
            zw.write_all(b"x").unwrap();
            zw.finish().unwrap();
        }

        let text = not_found(&jar, Some("com.example.Bar"), true);
        assert!(text.contains("com.example.Bar\" was not found"));
        assert!(text.contains("classes in the archive: 1"));
        assert!(text.contains("  com.example.Foo"));
        // A name that does not resemble anything falls back to the first list.
        let text = not_found(&jar, Some("zzz"), true);
        assert!(text.contains("first classes:"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn method_slicing_stops_at_the_next_signature() {
        let body = "\
public class Foo {
  public void a();
    Code:
       0: return

  public void b();
    Code:
       0: return
}";
        let block = slice_method(body, "a()").unwrap();
        assert!(block.contains("a()"));
        assert!(block.contains("0: return"));
        assert!(!block.contains("b()"));
    }

    #[test]
    fn missing_method_lists_the_available_ones() {
        let body = "  public void a();\n  public void b();\n";
        assert!(slice_method(body, "c()").is_none());
        let sigs = signatures(body);
        assert_eq!(sigs.len(), 2);
        assert!(sigs[0].contains("a()"));
    }
}
