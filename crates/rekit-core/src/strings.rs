use anyhow::Result;
use serde::Serialize;

use crate::util::{printable, read_spec};

#[derive(Debug, Clone, Serialize)]
pub struct Found {
    pub offset: u64,
    pub text: String,
    pub kind: &'static str,
}

/// Extract printable strings. Both ASCII and UTF-16LE, because Windows binaries
/// and .NET assemblies keep most of their useful text in wide chars.
pub fn scan(spec: &str, min: usize, filter: Option<&str>, limit: usize) -> Result<Vec<Found>> {
    let (_, data) = read_spec(spec)?;
    let min = min.max(1);
    let needle = filter.map(|f| f.to_lowercase());
    let mut out = Vec::new();

    let mut run_start = 0usize;
    let mut run_len = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            if run_len == 0 {
                run_start = i;
            }
            run_len += 1;
            continue;
        }
        if run_len >= min {
            push(
                &mut out,
                &data[run_start..run_start + run_len],
                run_start,
                "ascii",
                needle.as_deref(),
                limit,
            );
        }
        run_len = 0;
        if out.len() >= limit {
            break;
        }
    }
    if run_len >= min && out.len() < limit {
        push(
            &mut out,
            &data[run_start..run_start + run_len],
            run_start,
            "ascii",
            needle.as_deref(),
            limit,
        );
    }

    // UTF-16LE: printable byte followed by a zero byte.
    let mut i = 0usize;
    while i + 1 < data.len() && out.len() < limit {
        // A zero low byte is also the terminator of a preceding ASCII string,
        // so `d\0w\0...` must not be read as a wide string starting mid-word.
        let clean_start = i == 0 || !printable(data[i - 1]);
        if clean_start && printable(data[i]) && data[i + 1] == 0 {
            let start = i;
            let mut text = String::new();
            while i + 1 < data.len() && printable(data[i]) && data[i + 1] == 0 {
                text.push(data[i] as char);
                i += 2;
            }
            if text.len() >= min {
                let lc = text.to_lowercase();
                if needle.as_ref().map(|n| lc.contains(n)).unwrap_or(true) {
                    out.push(Found {
                        offset: start as u64,
                        text,
                        kind: "utf16",
                    });
                }
            }
        } else {
            i += 1;
        }
    }

    Ok(out)
}

fn push(
    out: &mut Vec<Found>,
    bytes: &[u8],
    offset: usize,
    kind: &'static str,
    needle: Option<&str>,
    limit: usize,
) {
    if out.len() >= limit {
        return;
    }
    let text = String::from_utf8_lossy(bytes).to_string();
    if let Some(n) = needle {
        if !text.to_lowercase().contains(n) {
            return;
        }
    }
    out.push(Found {
        offset: offset as u64,
        text,
        kind,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_and_utf16() {
        let dir = std::env::temp_dir().join("rekit-strings-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("s.bin");
        let mut data = b"\x00\x01hello world\x00".to_vec();
        for c in "wide string".chars() {
            data.push(c as u8);
            data.push(0);
        }
        std::fs::write(&p, &data).unwrap();

        let found = scan(&p.display().to_string(), 4, None, 100).unwrap();
        assert!(found.iter().any(|f| f.text == "hello world"));
        assert!(found
            .iter()
            .any(|f| f.text == "wide string" && f.kind == "utf16"));

        let filtered = scan(&p.display().to_string(), 4, Some("WIDE"), 100).unwrap();
        assert_eq!(filtered.len(), 1);
    }
}
