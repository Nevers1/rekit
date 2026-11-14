//! Pieces the decompiler wrappers share.
//!
//! Ghidra and IDA have the same calling contract — a symbol name, an address,
//! or "list everything" — and both are slow enough that a failed run must
//! never be mistaken for a successful one which found nothing. The helpers
//! here keep that contract identical in both, so an agent that learned one
//! tool already knows the other.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// What to ask a decompiler for.
///
/// The `@` prefix is the plugin's convention and it is kept because it is
/// unambiguous: a symbol named `LIST` cannot be confused with the listing.
pub fn needle(symbol: Option<&str>, address: Option<&str>) -> Result<String> {
    match (symbol, address) {
        (Some(_), Some(_)) => bail!("pass either symbol or address, not both"),
        (_, Some(address)) => Ok(format!("@{:#x}", parse_address(address)?)),
        (Some(symbol), None) if !symbol.trim().is_empty() => Ok(symbol.trim().to_string()),
        _ => Ok("@LIST".to_string()),
    }
}

/// Decompiler addresses are hex, always: `0x2040` and `2040` both mean 0x2040.
///
/// Reading `2040` as decimal would silently decompile a different function,
/// which is worse than refusing.
pub fn parse_address(text: &str) -> Result<u64> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("address {text:?} is not hex: pass it as 0x2040 or 2040");
    }
    u64::from_str_radix(digits, 16).map_err(|e| anyhow_string(e, text))
}

fn anyhow_string(err: std::num::ParseIntError, text: &str) -> anyhow::Error {
    anyhow::anyhow!("address {text:?} does not fit in 64 bits: {err}")
}

/// Cut text to `limit` lines, saying how many were dropped.
pub fn take_lines(text: &str, limit: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= limit {
        return text.to_string();
    }
    format!(
        "{}\n... {} more lines",
        lines[..limit].join("\n"),
        lines.len() - limit
    )
}

/// The lines worth showing when a tool fails: everything else is its own noise.
pub fn error_lines(log: &str, limit: usize) -> String {
    let hits: Vec<&str> = log
        .lines()
        .filter(|line| {
            line.contains("ERROR")
                || line.contains("Exception")
                || line.contains("Traceback")
                || line.contains("Caused by")
                || line.starts_with("error:")
                || line.contains("not found")
        })
        .take(limit)
        .collect();
    if hits.is_empty() {
        take_lines(log.trim(), limit)
    } else {
        hits.join("\n")
    }
}

/// Ghidra and IDA both read native code only; say what to use instead rather
/// than let the tool fail with an import error.
pub fn native_only(name: &str, format: &str, dotnet: bool) -> Result<()> {
    if dotnet {
        bail!("{name} is a .NET assembly: there is no native code to decompile. Use `dotnet`.");
    }
    let native =
        format.starts_with("ELF") || format.starts_with("PE") || format.starts_with("Mach-O");
    if !native {
        bail!("{name} is {format}: Ghidra and IDA take native PE/ELF/Mach-O code only.");
    }
    Ok(())
}

/// Identity of an input file for cache keys: path, size and mtime, hashed.
pub fn key(path: &Path) -> String {
    let meta = std::fs::metadata(path).ok();
    let stamp = format!(
        "{}:{}:{}",
        path.display(),
        meta.as_ref().map(|m| m.len()).unwrap_or(0),
        meta.as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    crate::util::sha256_hex(stamp.as_bytes())[..16].to_string()
}

/// A cache directory named after the input's identity, not its path: the same
/// binary reached through two archives must reuse one expensive analysis.
pub fn cache_dir(prefix: &str, path: &Path, suffix: &str) -> PathBuf {
    crate::resolve::cache_root().join(format!("{prefix}-{}{suffix}", key(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needle_prefers_the_address_and_marks_listing() {
        assert_eq!(needle(None, None).unwrap(), "@LIST");
        assert_eq!(needle(Some("main"), None).unwrap(), "main");
        assert_eq!(needle(None, Some("0x2040")).unwrap(), "@0x2040");
        assert_eq!(needle(None, Some("2040")).unwrap(), "@0x2040");
        assert!(needle(Some("main"), Some("2040")).is_err());
    }

    #[test]
    fn addresses_are_hex_not_decimal() {
        assert_eq!(parse_address("0x10").unwrap(), 16);
        assert_eq!(parse_address("10").unwrap(), 16);
        assert_eq!(parse_address(" 401000 ").unwrap(), 0x401000);
        assert!(parse_address("zzz").is_err());
        assert!(parse_address("").is_err());
    }

    #[test]
    fn long_output_is_cut_with_a_count() {
        assert_eq!(take_lines("a\nb", 5), "a\nb");
        let cut = take_lines("a\nb\nc\nd", 2);
        assert!(cut.starts_with("a\nb"));
        assert!(cut.contains("2 more lines"));
    }

    #[test]
    fn only_native_formats_get_through() {
        assert!(native_only("a", "ELF", false).is_ok());
        assert!(native_only("a", "PE32+", false).is_ok());
        assert!(native_only("a", "Mach-O (universal)", false).is_ok());

        let err = native_only("a", "dex", false).unwrap_err().to_string();
        assert!(err.contains("native PE/ELF/Mach-O"));

        let err = native_only("a", "PE32+", true).unwrap_err().to_string();
        assert!(err.contains("`dotnet`"));
    }

    #[test]
    fn errors_are_picked_out_of_the_noise() {
        let log = "INFO: starting\nERROR: cannot open\nINFO: done";
        assert_eq!(error_lines(log, 5), "ERROR: cannot open");
        assert_eq!(error_lines("plain failure text", 5), "plain failure text");
    }
}
