//! `path::inner` resolution.
//!
//! An agent rarely points at a `.so` directly; it points at an APK, an IPA or a
//! firmware image. The spec `app.apk::lib/arm64-v8a/libnative.so` resolves to a
//! real file in the cache, so every other primitive only ever sees a plain path.
//!
//! Nesting works: `fw.bin::rootfs.tar.gz::bin/busybox` is resolved right to
//! left, each step materialising the next layer.
//!
//! Only the *file name* of the requested entry is used for the cache path, so a
//! hostile entry name such as `../../etc/passwd` cannot escape the cache dir.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Resolve a spec that may contain one or more `::` steps.
pub fn resolve(spec: &str) -> Result<PathBuf> {
    match spec.split_once("::") {
        None => Ok(PathBuf::from(spec)),
        Some((outer, inner)) => {
            let outer_path = resolve(outer)?;
            materialize(&outer_path, inner)
                .with_context(|| format!("{}::{inner}", outer_path.display()))
        }
    }
}

pub fn cache_root() -> PathBuf {
    if let Ok(dir) = std::env::var("REKIT_CACHE") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(dir).join("rekit");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache").join("rekit")
}

fn store(name: &str, outer: &Path, data: &[u8]) -> Result<PathBuf> {
    let dir = cache_root();
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;

    let key = format!("{}::{name}", outer.display());
    let hash = crate::util::sha256_hex(key.as_bytes());
    let base = Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "entry".to_string());
    let out = dir.join(format!("{}-{base}", &hash[..16]));

    if !out.exists() {
        let tmp = out.with_extension("part");
        fs::write(&tmp, data).with_context(|| format!("cannot write {}", tmp.display()))?;
        fs::rename(&tmp, &out).with_context(|| format!("cannot move into {}", out.display()))?;
    }
    Ok(out)
}

fn materialize(outer: &Path, inner: &str) -> Result<PathBuf> {
    let data = fs::read(outer).with_context(|| format!("cannot read {}", outer.display()))?;

    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return from_zip(&data, inner, outer);
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        return from_gzip(&data, inner, outer);
    }
    bail!(
        "{} is not a supported archive (zip, tar.gz, gz)",
        outer.display()
    )
}

fn from_zip(data: &[u8], inner: &str, outer: &Path) -> Result<PathBuf> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))
        .with_context(|| format!("{} is not a valid zip", outer.display()))?;

    let mut exact = None;
    let mut suffix = None;
    for i in 0..archive.len() {
        let name = archive.name_for_index(i).unwrap_or_default().to_string();
        if name == inner {
            exact = Some(i);
            break;
        }
        if suffix.is_none() && (name.ends_with(&format!("/{inner}")) || name.ends_with(inner)) {
            suffix = Some(i);
        }
    }
    let idx = exact
        .or(suffix)
        .ok_or_else(|| anyhow!("{inner:?} not found in {}", outer.display()))?;

    let name = archive
        .name_for_index(idx)
        .ok_or_else(|| anyhow!("entry {idx} has no name"))?
        .to_string();
    let mut file = archive.by_index(idx)?;
    let mut buf = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut buf)?;
    store(&name, outer, &buf)
}

fn from_gzip(data: &[u8], inner: &str, outer: &Path) -> Result<PathBuf> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .with_context(|| format!("{} is not valid gzip", outer.display()))?;

    // A tar archive is recognisable by the `ustar` magic at offset 257.
    if buf.len() > 262 && &buf[257..262] == b"ustar" {
        let mut tar = tar::Archive::new(std::io::Cursor::new(buf.as_slice()));
        let mut exact: Option<(String, Vec<u8>)> = None;
        let mut suffix: Option<(String, Vec<u8>)> = None;
        for entry in tar.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path()?.to_string_lossy().to_string();
            let hit =
                path == inner || path.ends_with(&format!("/{inner}")) || path.ends_with(inner);
            if !hit {
                continue;
            }
            let mut body = Vec::new();
            entry.read_to_end(&mut body)?;
            if path == inner {
                exact = Some((path, body));
                break;
            }
            suffix.get_or_insert((path, body));
        }
        let (name, body) = exact
            .or(suffix)
            .ok_or_else(|| anyhow!("{inner:?} not found in {}", outer.display()))?;
        return store(&name, outer, &body);
    }

    // Plain .gz: the payload is a single file, named after the outer file.
    let name = outer
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "payload".to_string());
    store(&name, outer, &buf)
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub size: u64,
    pub compressed: u64,
}

/// List the members of an archive without extracting anything.
pub fn list_entries(path: &Path) -> Result<Vec<ArchiveEntry>> {
    let data = fs::read(path)?;
    let mut out = Vec::new();

    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&data))?;
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            if file.is_dir() {
                continue;
            }
            out.push(ArchiveEntry {
                name: file.name().to_string(),
                size: file.size(),
                compressed: file.compressed_size(),
            });
        }
        return Ok(out);
    }

    if data.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = flate2::read::GzDecoder::new(data.as_slice());
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        if buf.len() > 262 && &buf[257..262] == b"ustar" {
            let mut tar = tar::Archive::new(std::io::Cursor::new(buf.as_slice()));
            for entry in tar.entries()? {
                let entry = entry?;
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                out.push(ArchiveEntry {
                    name: entry.path()?.to_string_lossy().to_string(),
                    size: entry.header().size()?,
                    compressed: 0,
                });
            }
            return Ok(out);
        }
    }

    bail!(
        "{} is not a supported archive (zip, tar.gz, gz)",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn plain_path_resolves_to_itself() {
        assert_eq!(resolve("/tmp/x").unwrap(), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn zip_entry_is_extracted_and_cached() {
        let dir = std::env::temp_dir().join("rekit-resolve-test");
        let _ = fs::create_dir_all(&dir);
        let zip_path = dir.join("sample.zip");

        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("lib/arm64-v8a/libx.so", opts).unwrap();
            zw.write_all(b"\x7fELFpayload").unwrap();
            zw.finish().unwrap();
        }

        let spec = format!("{}::lib/arm64-v8a/libx.so", zip_path.display());
        let out = resolve(&spec).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"\x7fELFpayload");
        assert!(out.starts_with(cache_root()));
    }

    #[test]
    fn missing_entry_is_an_error() {
        let dir = std::env::temp_dir().join("rekit-resolve-test");
        let _ = fs::create_dir_all(&dir);
        let zip_path = dir.join("sample2.zip");
        {
            let file = fs::File::create(&zip_path).unwrap();
            let mut zw = zip::ZipWriter::new(file);
            zw.start_file("a.so", zip::write::FileOptions::<()>::default())
                .unwrap();
            zw.write_all(b"x").unwrap();
            zw.finish().unwrap();
        }
        let spec = format!("{}::nope.so", zip_path.display());
        assert!(resolve(&spec).is_err());
    }
}
