use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::resolve::resolve;

/// Resolve a `path::inner` spec and read the result.
pub fn read_spec(spec: &str) -> Result<(PathBuf, Vec<u8>)> {
    let path = resolve(spec).with_context(|| format!("cannot resolve {spec}"))?;
    let data = std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok((path, data))
}

/// Shannon entropy of a byte slice, in bits per byte (0.0 ..= 8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Bytes that belong to a printable ASCII string.
pub fn printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Human readable byte size.
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros_is_zero() {
        assert_eq!(shannon(&[0u8; 64]), 0.0);
    }

    #[test]
    fn entropy_of_all_bytes_is_eight() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert!((shannon(&data) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
