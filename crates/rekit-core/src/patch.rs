//! Byte patching with a mandatory `expect` — the same contract as `re_patch`.
//!
//! Patching is the one operation that destroys data if it goes to the wrong
//! place, so the caller must state what it believes is there. A mismatch is an
//! error, not a warning, and it reports what was actually found.
//!
//! Two safety nets sit around the write. A copy of the file is put in the cache
//! before the first byte changes, and afterwards the file is handed back to
//! rabin2: if it parsed the file before the patch and refuses to parse it now,
//! the header was most likely hit. Neither is fatal — a backup of a 2 GB
//! firmware is cheap insurance, and refusing to patch because rabin2 is not
//! installed would make the tool unusable on machines without radare2.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::external::{self, which};
use crate::hexdump::parse_pattern;
use crate::resolve::{cache_root, resolve};
use crate::util::sha256_hex;

#[derive(Debug, Clone, Serialize)]
pub struct PatchResult {
    pub path: String,
    pub offset: u64,
    pub size: usize,
    pub before: String,
    pub after: String,
    /// Where the pre-patch copy went, when one was made.
    pub backup: Option<String>,
    /// `Some(false)` means rabin2 parsed the file before the patch and no
    /// longer does: the header, not just the code, took the hit.
    pub reparses: Option<bool>,
}

pub fn apply(
    spec: &str,
    offset: u64,
    bytes: &[u8],
    expect: &[u8],
    backup: bool,
) -> Result<PatchResult> {
    if bytes.is_empty() {
        bail!("refusing to patch with an empty byte string");
    }
    if expect.len() != bytes.len() {
        bail!(
            "expect is {} bytes but the patch is {} bytes: they must match, \
             that is the whole point of the check",
            expect.len(),
            bytes.len()
        );
    }

    let path = resolve(spec)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("cannot open {} for writing", path.display()))?;

    let size = file.metadata()?.len();
    if offset.saturating_add(bytes.len() as u64) > size {
        bail!(
            "patch at {offset:#x} ({} bytes) runs past the end of the file ({size} bytes)",
            bytes.len()
        );
    }

    file.seek(SeekFrom::Start(offset))?;
    let mut before = vec![0u8; bytes.len()];
    file.read_exact(&mut before)?;

    if before != expect {
        bail!(
            "expect mismatch at {offset:#x}: wanted {}, found {}",
            hex(expect),
            hex(&before)
        );
    }

    // The backup has to happen before the first byte lands, and the "did it
    // parse" answer has to come from the untouched file — rabin2 reads the
    // header, which is exactly what a careless patch destroys.
    let backup_path = if backup {
        Some(save_copy(&path)?)
    } else {
        None
    };
    let parsed_before = parses(&path);

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.flush()?;
    drop(file);

    let reparses = if parsed_before == Some(true) {
        parses(&path)
    } else {
        None
    };

    Ok(PatchResult {
        path: path.display().to_string(),
        offset,
        size: bytes.len(),
        before: hex(&before),
        after: hex(bytes),
        backup: backup_path.map(|p| p.display().to_string()),
        reparses,
    })
}

pub fn apply_hex(
    spec: &str,
    offset: u64,
    bytes_hex: &str,
    expect_hex: &str,
    backup: bool,
) -> Result<PatchResult> {
    let bytes = parse_pattern(bytes_hex)?;
    let expect = parse_pattern(expect_hex)?;
    apply(spec, offset, &bytes, &expect, backup)
}

/// What to write, from whichever of the three forms the caller gave.
///
/// `bytes` is hex, `string` is text and gets a NUL appended (patching a string
/// usually means its terminator too, and a shorter replacement would leave the
/// tail of the old string behind), `nop` is a count of `0x90`.
pub fn payload(bytes: Option<&str>, text: Option<&str>, nop: Option<u64>) -> Result<Vec<u8>> {
    if let Some(hex) = bytes {
        let bytes = parse_pattern(hex)?;
        if bytes.is_empty() {
            bail!("`bytes` parsed to nothing: give hex such as \"90 90\"");
        }
        return Ok(bytes);
    }
    if let Some(text) = text {
        let mut out = text.as_bytes().to_vec();
        out.push(0);
        return Ok(out);
    }
    if let Some(n) = nop {
        if n == 0 {
            bail!("`nop` is a count: it must be at least 1");
        }
        if n > 1 << 20 {
            bail!("`nop` of {n} bytes is not a patch, it is a rewrite");
        }
        return Ok(vec![0x90; n as usize]);
    }
    bail!("nothing to write: pass `bytes` (hex), `string` (text) or `nop` (how many NOPs)")
}

/// Copy the file into the cache, under a name that identifies this version of
/// it. Patching the same file twice does not pile up copies: the key includes
/// size and mtime, both of which the first patch changes.
fn save_copy(path: &Path) -> Result<PathBuf> {
    let meta = fs::metadata(path)?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let key = format!("{}:{}:{mtime}", path.display(), meta.len());
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "binary".to_string());

    let dir = cache_root().join("backups");
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let hash = sha256_hex(key.as_bytes());
    let dest = dir.join(format!("{name}-{}.bak", &hash[..12]));
    if !dest.exists() {
        fs::copy(path, &dest)
            .with_context(|| format!("cannot back {} up to {}", path.display(), dest.display()))?;
    }
    Ok(dest)
}

/// Whether rabin2 still understands the file. `None` means there is no rabin2
/// to ask, which is not the same as "broken".
fn parses(path: &Path) -> Option<bool> {
    which("rabin2")?;
    let args = ["-I".to_string(), path.display().to_string()];
    let out = external::run("rabin2", &args, Duration::from_secs(60)).ok()?;
    Some(out.contains("arch"))
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("rekit-patch-test");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn patch_applies_with_matching_expect() {
        let p = temp("ok.bin");
        std::fs::write(&p, b"AAAABBBBCCCC").unwrap();
        let res = apply_hex(&p.display().to_string(), 4, "de ad", "42 42", true).unwrap();
        assert_eq!(res.before, "42 42");
        assert_eq!(std::fs::read(&p).unwrap(), b"AAAA\xde\xadBBCCCC");
    }

    #[test]
    fn patch_refuses_on_mismatch() {
        let p = temp("bad.bin");
        std::fs::write(&p, b"AAAABBBBCCCC").unwrap();
        let err = apply_hex(&p.display().to_string(), 4, "de ad", "43 43", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expect mismatch"));
        assert_eq!(std::fs::read(&p).unwrap(), b"AAAABBBBCCCC");
    }

    #[test]
    fn patch_refuses_past_the_end() {
        let p = temp("short.bin");
        std::fs::write(&p, b"AA").unwrap();
        assert!(apply_hex(&p.display().to_string(), 1, "de ad", "41 41", true).is_err());
    }

    #[test]
    fn backup_holds_the_original_bytes() {
        let p = temp("backed.bin");
        std::fs::write(&p, b"AAAABBBB").unwrap();
        let res = apply_hex(&p.display().to_string(), 0, "de ad", "41 41", true).unwrap();
        let backup = res.backup.expect("a backup path");
        assert_eq!(std::fs::read(&backup).unwrap(), b"AAAABBBB");
        assert_eq!(std::fs::read(&p).unwrap(), b"\xde\xadAABBBB");
    }

    #[test]
    fn backup_can_be_switched_off() {
        let p = temp("nobackup.bin");
        std::fs::write(&p, b"AAAABBBB").unwrap();
        let res = apply_hex(&p.display().to_string(), 0, "de ad", "41 41", false).unwrap();
        assert!(res.backup.is_none());
    }

    #[test]
    fn payload_understands_hex_text_and_nops() {
        assert_eq!(
            payload(Some("de ad"), None, None).unwrap(),
            vec![0xde, 0xad]
        );
        assert_eq!(payload(None, Some("hi"), None).unwrap(), b"hi\0");
        assert_eq!(payload(None, None, Some(3)).unwrap(), vec![0x90; 3]);
        assert!(payload(None, None, None).is_err());
        assert!(payload(None, None, Some(0)).is_err());
    }
}
