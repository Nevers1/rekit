//! Byte patching with a mandatory `expect` — the same contract as `re_patch`.
//!
//! Patching is the one operation that destroys data if it goes to the wrong
//! place, so the caller must state what it believes is there. A mismatch is an
//! error, not a warning, and it reports what was actually found.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::hexdump::parse_pattern;
use crate::resolve::resolve;

#[derive(Debug, Clone, Serialize)]
pub struct PatchResult {
    pub path: String,
    pub offset: u64,
    pub size: usize,
    pub before: String,
    pub after: String,
}

pub fn apply(spec: &str, offset: u64, bytes: &[u8], expect: &[u8]) -> Result<PatchResult> {
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

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.flush()?;

    Ok(PatchResult {
        path: path.display().to_string(),
        offset,
        size: bytes.len(),
        before: hex(&before),
        after: hex(bytes),
    })
}

pub fn apply_hex(
    spec: &str,
    offset: u64,
    bytes_hex: &str,
    expect_hex: &str,
) -> Result<PatchResult> {
    let bytes = parse_pattern(bytes_hex)?;
    let expect = parse_pattern(expect_hex)?;
    apply(spec, offset, &bytes, &expect)
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

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("rekit-patch-test");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn patch_applies_with_matching_expect() {
        let p = temp("ok.bin");
        std::fs::write(&p, b"AAAABBBBCCCC").unwrap();
        let res = apply_hex(&p.display().to_string(), 4, "de ad", "42 42").unwrap();
        assert_eq!(res.before, "42 42");
        assert_eq!(std::fs::read(&p).unwrap(), b"AAAA\xde\xadBBCCCC");
    }

    #[test]
    fn patch_refuses_on_mismatch() {
        let p = temp("bad.bin");
        std::fs::write(&p, b"AAAABBBBCCCC").unwrap();
        let err = apply_hex(&p.display().to_string(), 4, "de ad", "43 43")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expect mismatch"));
        assert_eq!(std::fs::read(&p).unwrap(), b"AAAABBBBCCCC");
    }

    #[test]
    fn patch_refuses_past_the_end() {
        let p = temp("short.bin");
        std::fs::write(&p, b"AA").unwrap();
        assert!(apply_hex(&p.display().to_string(), 1, "de ad", "41 41").is_err());
    }
}
