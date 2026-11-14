use anyhow::{bail, Result};
use serde::Serialize;

use crate::util::read_spec;

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub offset: u64,
    pub context: String,
}

/// Classic hex dump, aligned the way `xxd -g1` prints it.
pub fn dump(spec: &str, offset: u64, len: usize) -> Result<String> {
    let (_, data) = read_spec(spec)?;
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    if start >= data.len() {
        bail!(
            "offset {offset:#x} is past the end (file is {} bytes)",
            data.len()
        );
    }
    let end = start.saturating_add(len.max(1)).min(data.len());
    let chunk = &data[start..end];

    let mut out = String::with_capacity(chunk.len() * 4 + 16);
    for (i, row) in chunk.chunks(16).enumerate() {
        let addr = start + i * 16;
        out.push_str(&format!("{addr:08x}  "));
        for (j, b) in row.iter().enumerate() {
            out.push_str(&format!("{b:02x} "));
            if j == 7 {
                out.push(' ');
            }
        }
        for j in row.len()..16 {
            out.push_str("   ");
            if j == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for b in row {
            out.push(if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    Ok(out)
}

/// Find a byte pattern. Accepts `de ad be ef`, `deadbeef` or `"text"`.
pub fn parse_pattern(pattern: &str) -> Result<Vec<u8>> {
    let trimmed = pattern.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return Ok(trimmed.as_bytes()[1..trimmed.len() - 1].to_vec());
    }
    let hex: String = trimmed
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '_' && *c != ':')
        .collect();
    let looks_hex =
        !hex.is_empty() && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit());
    if looks_hex {
        let mut out = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            out.push(u8::from_str_radix(&hex[i..i + 2], 16)?);
        }
        return Ok(out);
    }
    if trimmed.is_empty() {
        bail!("empty pattern");
    }
    Ok(trimmed.as_bytes().to_vec())
}

/// All offsets where the pattern occurs, with a short context around each hit.
///
/// `ignore_case` folds ASCII only: a byte pattern is bytes, and there is no
/// locale to argue with.
pub fn find(
    spec: &str,
    pattern: &str,
    limit: usize,
    context: usize,
    ignore_case: bool,
) -> Result<Vec<Hit>> {
    let (_, data) = read_spec(spec)?;
    let mut needle = parse_pattern(pattern)?;
    if needle.is_empty() {
        bail!("empty pattern");
    }
    if ignore_case {
        needle.make_ascii_lowercase();
    }

    let matches_at = |i: usize| -> bool {
        let window = &data[i..i + needle.len()];
        match ignore_case {
            true => window
                .iter()
                .zip(needle.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b)),
            false => window == needle.as_slice(),
        }
    };

    let mut hits = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= data.len() {
        if matches_at(i) {
            let from = i.saturating_sub(context);
            let to = (i + needle.len() + context).min(data.len());
            hits.push(Hit {
                offset: i as u64,
                context: render_context(&data[from..to]),
            });
            if hits.len() >= limit {
                break;
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    Ok(hits)
}

fn render_context(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        out.push(if (0x20..0x7f).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_kinds() {
        assert_eq!(parse_pattern("de ad").unwrap(), vec![0xde, 0xad]);
        assert_eq!(
            parse_pattern("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_pattern("\"dead\"").unwrap(), b"dead".to_vec());
        // Unquoted all-hex is bytes; text is either quoted or has non-hex chars.
        assert_eq!(parse_pattern("dead").unwrap(), vec![0xde, 0xad]);
        assert_eq!(parse_pattern("hello").unwrap(), b"hello".to_vec());
        assert_eq!(
            parse_pattern("BuildConfig").unwrap(),
            b"BuildConfig".to_vec()
        );
    }

    #[test]
    fn dump_and_find() {
        let dir = std::env::temp_dir().join("rekit-hex-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("h.bin");
        std::fs::write(&p, b"AAAABBBBCCCC").unwrap();
        let spec = p.display().to_string();

        let text = dump(&spec, 0, 16).unwrap();
        assert!(text.contains("00000000"));
        assert!(text.contains("|AAAABBBBCCCC"));

        let hits = find(&spec, "\"BBBB\"", 10, 2, false).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 4);
    }
}
