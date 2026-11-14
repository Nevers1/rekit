//! What is inside an APK's resources, without decoding the whole package.
//!
//! `apktool` answers the same question but costs a full decode; listing a zip
//! costs nothing and usually settles the question: is there a `res/values`
//! at all, which density variants exist, is the payload in `assets`. When one
//! XML is named exactly, it is decoded in place, because the binary layout is
//! the thing a caller cannot read.

use anyhow::{bail, Result};

use crate::decompilers::take_lines;
use crate::resolve::{list_entries, resolve};

/// The groups a caller can ask for. `list` summarises everything else.
const KINDS: &[&str] = &["strings", "layout", "drawable", "asset", "xml"];

fn matches(kind: &str, entry: &str) -> bool {
    match kind {
        "strings" => entry.starts_with("res/values"),
        "layout" => entry.starts_with("res/layout"),
        "drawable" => entry.starts_with("res/drawable"),
        "asset" => entry.starts_with("assets/"),
        "xml" => entry.ends_with(".xml"),
        _ => false,
    }
}

pub fn list(spec: &str, kind: &str, name: Option<&str>) -> Result<String> {
    let path = resolve(spec)?;
    let is_apk = path
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("apk"))
        .unwrap_or(false);
    if !is_apk {
        bail!(
            "{} is not an .apk — this reads the zip layout of a package",
            path.display()
        );
    }

    let entries = list_entries(&path)?;
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    let res: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| name.starts_with("res/"))
        .collect();
    let assets: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| name.starts_with("assets/"))
        .collect();

    let kind = kind.trim();
    let kind = if kind.is_empty() { "list" } else { kind };
    if kind != "list" && !KINDS.contains(&kind) {
        bail!("unknown kind {kind:?}: use list, {}", KINDS.join(", "));
    }

    let head = format!(
        "{}\nentries: {}, resources: {}, assets: {}\n",
        path.display(),
        names.len(),
        res.len(),
        assets.len()
    );

    if kind == "list" {
        let mut groups: Vec<(String, usize)> = Vec::new();
        let mut direct = 0usize;
        for entry in &res {
            // Obfuscated packages put files straight into res/ with names like
            // `-1.xml`; each would otherwise become a "group" of one.
            match entry.trim_start_matches("res/").split_once('/') {
                None => direct += 1,
                Some((group, _)) => match groups.iter_mut().find(|(name, _)| name == group) {
                    Some((_, count)) => *count += 1,
                    None => groups.push((group.to_string(), 1)),
                },
            }
        }
        groups.sort();

        let mut out = head;
        out.push_str("groups:\n");
        for (group, count) in &groups {
            out.push_str(&format!("  {group}: {count}\n"));
        }
        if direct > 0 {
            out.push_str(&format!("  (directly under res/): {direct}\n"));
        }
        if groups.is_empty() && direct == 0 {
            out.push_str("  (no res/ entries)\n");
        }
        out.push_str(&format!(
            "\nassets: {}\n{}\n",
            assets.len(),
            take_lines(
                &assets
                    .iter()
                    .take(30)
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n"),
                20
            )
        ));
        // APKs built normally have no res/values: strings are compiled into
        // resources.arsc, and expecting strings.xml there wastes a call.
        if !res.iter().any(|entry| entry.contains("values")) {
            out.push_str(
                "\nno res/values in the archive: the strings are compiled into \
                 resources.arsc. `apktool` decodes it into res/values/*.xml.\n",
            );
        }
        return Ok(out);
    }

    let pool: Vec<&str> = res.iter().copied().chain(assets.iter().copied()).collect();
    let mut found: Vec<&str> = pool
        .iter()
        .copied()
        .filter(|entry| matches(kind, entry))
        .collect();

    if let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) {
        found.retain(|entry| entry.contains(name));
        if found.is_empty() {
            let near: Vec<&str> = pool
                .iter()
                .copied()
                .filter(|entry| entry.contains(name))
                .take(20)
                .collect();
            let mut out = format!("{head}no resource matching {name:?} in {kind}\n");
            if near.is_empty() {
                out.push_str("nothing similar either — kind=list shows what is there\n");
            } else {
                out.push_str(&format!("similar:\n{}\n", near.join("\n")));
            }
            return Ok(out);
        }
    }

    if found.is_empty() {
        return Ok(format!("{head}no {kind} entries\n"));
    }

    // One exact XML named by the caller is answered with its contents: the
    // point of asking for a layout by name is to read it.
    if found.len() == 1 && found[0].ends_with(".xml") {
        let target = found[0];
        match crate::axml::render(&format!("{spec}::{target}")) {
            Ok(xml) => {
                return Ok(format!(
                    "{head}{target}\n\n{}",
                    take_lines(xml.trim_end(), 400)
                ))
            }
            Err(err) => {
                return Ok(format!(
                    "{head}{target}\n(could not decode: {err})\nuse `apktool` for the decoded tree"
                ))
            }
        }
    }

    let mut out = format!("{head}{kind}: {}\n", found.len());
    found.sort();
    out.push_str(&take_lines(&found.join("\n"), 60));
    out.push('\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_match_the_directories_they_name() {
        assert!(matches("strings", "res/values/strings.xml"));
        assert!(matches("strings", "res/values-ru/strings.xml"));
        assert!(matches("layout", "res/layout/activity_main.xml"));
        assert!(matches("layout", "res/layout-v21/activity_main.xml"));
        assert!(matches("drawable", "res/drawable-xhdpi/icon.png"));
        assert!(matches("asset", "assets/config.json"));
        assert!(matches("xml", "AndroidManifest.xml"));

        assert!(!matches("layout", "res/values/strings.xml"));
        assert!(!matches("asset", "res/raw/thing.bin"));
    }

    #[test]
    fn a_listing_of_a_real_zip_is_summarised() {
        use std::io::Write;

        let dir = std::env::temp_dir().join("rekit-resources-zip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let apk = dir.join("a.apk");

        {
            let file = std::fs::File::create(&apk).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for name in [
                "AndroidManifest.xml",
                "resources.arsc",
                "res/layout/activity_main.xml",
                "res/drawable/icon.png",
                "assets/app.js",
            ] {
                zw.start_file(name, opts).unwrap();
                zw.write_all(b"x").unwrap();
            }
            zw.finish().unwrap();
        }

        let text = list(apk.to_str().unwrap(), "list", None).unwrap();
        assert!(text.contains("resources: 2, assets: 1"));
        assert!(text.contains("layout: 1"));
        assert!(text.contains("drawable: 1"));
        assert!(text.contains("resources.arsc"));

        let text = list(apk.to_str().unwrap(), "layout", None).unwrap();
        assert!(text.contains("res/layout/activity_main.xml"));

        let text = list(apk.to_str().unwrap(), "strings", Some("app_name")).unwrap();
        assert!(text.contains("no resource matching"));
        assert!(text.contains("kind=list"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_kinds_are_refused_with_the_list() {
        let dir = std::env::temp_dir().join("rekit-resources-kind");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let apk = dir.join("a.apk");
        std::fs::write(&apk, b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();

        let err = list(apk.to_str().unwrap(), "colour", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown kind"));
        assert!(err.contains("strings"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_apk_is_refused() {
        let dir = std::env::temp_dir().join("rekit-resources-notapk");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let jar = dir.join("a.jar");
        std::fs::write(&jar, b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();

        let err = list(jar.to_str().unwrap(), "list", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not an .apk"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
