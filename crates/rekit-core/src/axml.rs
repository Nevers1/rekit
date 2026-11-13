//! Android binary XML (AXML) reader.
//!
//! `AndroidManifest.xml` inside an APK is not text. `apktool` decodes it into a
//! directory tree; this reads it in place, which is what an agent needs when it
//! only wants the package name, the permissions and the exported components.

use anyhow::{bail, Result};

use crate::util::read_spec;

const RES_STRING_POOL: u16 = 0x0001;
const RES_XML: u16 = 0x0003;
const RES_XML_START_NAMESPACE: u16 = 0x0100;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const RES_XML_END_ELEMENT: u16 = 0x0103;
const RES_XML_CDATA: u16 = 0x0104;

const NO_INDEX: u32 = u32::MAX;

/// Decode a manifest: binary AXML, or plain text passed through untouched.
pub fn render(spec: &str) -> Result<String> {
    let (_, data) = read_spec(spec)?;

    if data.first() == Some(&b'<') {
        return Ok(String::from_utf8_lossy(&data).to_string());
    }
    if data.len() < 8 {
        bail!("too short to be a manifest");
    }
    let doc_type = u16_at(&data, 0);
    if doc_type != RES_XML {
        bail!(
            "not an Android binary XML (leading chunk is {doc_type:#06x}, expected {RES_XML:#06x})"
        );
    }

    let mut strings: Vec<String> = Vec::new();
    let mut prefixes: Vec<(u32, String)> = Vec::new();
    let mut out = String::new();
    let mut depth = 0usize;
    let mut pos = 8usize;
    let mut open = 0usize;

    while pos + 8 <= data.len() {
        let chunk_type = u16_at(&data, pos);
        let header_size = u16_at(&data, pos + 2) as usize;
        let chunk_size = u32_at(&data, pos + 4) as usize;
        if chunk_size < 8 || pos + chunk_size > data.len() || header_size < 8 {
            break;
        }
        let chunk = &data[pos..pos + chunk_size];

        match chunk_type {
            RES_STRING_POOL => strings = parse_string_pool(chunk)?,
            RES_XML_START_NAMESPACE => {
                if header_size + 8 <= chunk.len() {
                    let prefix = u32_at(chunk, header_size);
                    let uri = u32_at(chunk, header_size + 4);
                    prefixes.push((uri, string_at(&strings, prefix)));
                }
            }
            RES_XML_START_ELEMENT => {
                let body = &chunk[header_size..];
                if body.len() < 20 {
                    break;
                }
                let name = string_at(&strings, u32_at(body, 4));
                let attr_start = u16_at(body, 8) as usize;
                let attr_size = u16_at(body, 10) as usize;
                let attr_count = u16_at(body, 12) as usize;

                out.push_str(&"  ".repeat(depth));
                out.push('<');
                out.push_str(&name);
                for i in 0..attr_count {
                    let off = attr_start + i * attr_size;
                    if off + 20 > body.len() {
                        break;
                    }
                    let ns = u32_at(body, off);
                    let attr_name = string_at(&strings, u32_at(body, off + 4));
                    let raw = u32_at(body, off + 8);
                    let data_type = body[off + 15];
                    let value_raw = u32_at(body, off + 16);
                    let value = format_value(&strings, raw, data_type, value_raw);

                    out.push(' ');
                    if ns != NO_INDEX {
                        if let Some((_, prefix)) = prefixes.iter().find(|(uri, _)| *uri == ns) {
                            if !prefix.is_empty() {
                                out.push_str(prefix);
                                out.push(':');
                            }
                        }
                    }
                    out.push_str(&attr_name);
                    out.push_str("=\"");
                    out.push_str(&value.replace('"', "&quot;"));
                    out.push('"');
                }
                // Self closing is indistinguishable in AXML, so print as a
                // balanced tag: an agent reading this wants the tree, not markup.
                out.push_str(">\n");
                depth += 1;
                open += 1;
            }
            RES_XML_END_ELEMENT => {
                depth = depth.saturating_sub(1);
                open = open.saturating_sub(1);
                let name = chunk
                    .get(header_size..)
                    .filter(|b| b.len() >= 8)
                    .map(|b| string_at(&strings, u32_at(b, 4)))
                    .unwrap_or_default();
                out.push_str(&"  ".repeat(depth));
                out.push_str("</");
                out.push_str(&name);
                out.push_str(">\n");
            }
            RES_XML_CDATA if header_size + 4 <= chunk.len() => {
                let text = string_at(&strings, u32_at(chunk, header_size));
                out.push_str(&"  ".repeat(depth));
                out.push_str(&text);
                out.push('\n');
            }
            _ => {}
        }

        pos += chunk_size;
    }

    // Close whatever was left open if the file was truncated.
    while open > 0 {
        depth = depth.saturating_sub(1);
        out.push_str(&"  ".repeat(depth));
        out.push_str("</...>\n");
        open -= 1;
    }

    Ok(out)
}

fn parse_string_pool(chunk: &[u8]) -> Result<Vec<String>> {
    if chunk.len() < 28 {
        bail!("string pool is too short");
    }
    let count = u32_at(chunk, 8) as usize;
    let flags = u32_at(chunk, 16);
    let strings_start = u32_at(chunk, 20) as usize;
    let utf8 = flags & 0x100 != 0;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off_pos = 28 + i * 4;
        if off_pos + 4 > chunk.len() {
            break;
        }
        let offset = strings_start + u32_at(chunk, off_pos) as usize;
        if offset >= chunk.len() {
            out.push(String::new());
            continue;
        }
        out.push(if utf8 {
            read_utf8_string(&chunk[offset..])
        } else {
            read_utf16_string(&chunk[offset..])
        });
    }
    Ok(out)
}

fn read_utf8_string(data: &[u8]) -> String {
    let mut i = 0usize;
    // Two length fields: character count then byte count, each 1 or 2 bytes.
    for _ in 0..2 {
        if i >= data.len() {
            return String::new();
        }
        if data[i] & 0x80 != 0 {
            i += 2;
        } else {
            i += 1;
        }
    }
    let end = data[i..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| i + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[i..end]).to_string()
}

fn read_utf16_string(data: &[u8]) -> String {
    let mut i = 0usize;
    let mut len = u16_at(data, 0) as usize;
    i += 2;
    if len & 0x8000 != 0 {
        len = ((len & 0x7fff) << 16) | u16_at(data, 2) as usize;
        i += 2;
    }
    let mut units = Vec::with_capacity(len);
    for k in 0..len {
        let at = i + k * 2;
        if at + 2 > data.len() {
            break;
        }
        units.push(u16_at(data, at));
    }
    String::from_utf16_lossy(&units)
}

fn format_value(strings: &[String], raw: u32, data_type: u8, data: u32) -> String {
    if raw != NO_INDEX {
        if let Some(s) = strings.get(raw as usize) {
            if !s.is_empty() {
                return s.clone();
            }
        }
    }
    match data_type {
        0x03 => strings
            .get(data as usize)
            .cloned()
            .unwrap_or_else(|| format!("@string/{data:#x}")),
        0x01 => format!("@{data:#010x}"),
        0x02 => format!("?{data:#010x}"),
        0x04 => f32::from_bits(data).to_string(),
        0x05 => format!("{}dp", f32::from_bits(data)),
        0x06 => format!("{:.2}%", f32::from_bits(data) * 100.0),
        0x10 => data.to_string(),
        0x11 => format!("{data:#x}"),
        0x12 => (data != 0).to_string(),
        _ => format!("{data:#x}"),
    }
}

fn string_at(strings: &[String], index: u32) -> String {
    if index == NO_INDEX {
        return String::new();
    }
    strings.get(index as usize).cloned().unwrap_or_default()
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn u32_at(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_manifest_passes_through() {
        let dir = std::env::temp_dir().join("rekit-axml-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("AndroidManifest.xml");
        std::fs::write(&p, b"<manifest package=\"com.example\"/>").unwrap();
        let out = render(&p.display().to_string()).unwrap();
        assert!(out.contains("com.example"));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let dir = std::env::temp_dir().join("rekit-axml-test");
        let p = dir.join("junk.xml");
        std::fs::write(&p, vec![0x42u8; 64]).unwrap();
        assert!(render(&p.display().to_string()).is_err());
    }
}
