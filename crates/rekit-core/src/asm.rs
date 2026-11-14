//! Assembling instructions into bytes, and optionally writing them into a file.
//!
//! Keystone is the obvious engine — it is what the Python plugin used — but
//! keystone is GPLv2, and linking it into this MIT crate would relicense the
//! whole workspace. rasm2 understands the same syntax, sits behind the `r2`
//! tool that already exists here, and as a separate process cannot affect our
//! license at all.
//!
//! Assembly is address sensitive: `jmp 0x1005` assembles differently at 0x1000
//! and at 0x2000, so the base address is part of the input, not a detail.

use anyhow::{bail, Result};
use serde::Serialize;
use std::time::Duration;

use crate::external::{run, which};
use crate::hexdump::parse_pattern;
use crate::info::analyze;
use crate::patch::{self, PatchResult};
use crate::resolve::resolve;

#[derive(Debug, Clone, Serialize)]
pub struct Assembly {
    pub arch: String,
    pub bits: u32,
    pub address: u64,
    pub instructions: usize,
    pub length: usize,
    pub hex: String,
    pub spaced: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsmPatch {
    pub assembly: Assembly,
    pub patch: PatchResult,
}

/// rasm2's names are not the ones rekit reports: aarch64 is `arm` with 64
/// bits, and 32-bit ARM is plain `arm` too.
fn rasm2_target(arch: &str, bits: u32) -> (&'static str, u32) {
    // A name that states its width wins; otherwise the caller's `bits` decides.
    // Treating plain `x86` as always 32 silently dropped an x86-64 request.
    match arch.to_ascii_lowercase().as_str() {
        "aarch64" | "arm64" => ("arm", 64),
        "arm32" => ("arm", 32),
        "arm" => ("arm", if bits >= 64 { 64 } else { 32 }),
        "mips64" => ("mips", 64),
        "mips" => ("mips", if bits >= 64 { 64 } else { 32 }),
        "i386" | "i686" => ("x86", 32),
        _ => ("x86", if bits >= 64 { 64 } else { 32 }),
    }
}

fn normalise(code: &str) -> Vec<String> {
    code.replace("\\n", "\n")
        .split([';', '\n'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn assemble(code: &str, arch: &str, bits: u32, address: u64) -> Result<Assembly> {
    let lines = normalise(code);
    if lines.is_empty() {
        bail!("no instructions to assemble");
    }
    if which("rasm2").is_none() {
        bail!(
            "rasm2 is not installed: it is part of radare2. \
             Install it, or write the bytes out by hand with `patch`."
        );
    }

    let (target, target_bits) = rasm2_target(arch, bits);
    let args = vec![
        "-a".to_string(),
        target.to_string(),
        "-b".to_string(),
        target_bits.to_string(),
        "-s".to_string(),
        format!("{address:#x}"),
        lines.join(";"),
    ];

    let raw = run("rasm2", &args, Duration::from_secs(30))?;
    let hex: String = raw
        .trim()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.is_empty() || hex.len() % 2 != 0 {
        bail!("rasm2 returned {raw:?}, which is not a byte string");
    }

    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;

    Ok(Assembly {
        arch: if target == "arm" && target_bits == 64 {
            "aarch64".to_string()
        } else {
            arch.to_string()
        },
        bits: target_bits,
        address,
        instructions: lines.len(),
        length: bytes.len(),
        spaced: bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        hex,
    })
}

/// Where to write, and how carefully.
pub struct Spot<'a> {
    pub offset: u64,
    /// What must already be there. `None` makes the tool report the real bytes
    /// instead of writing, so the retry is a copy-paste.
    pub expect: Option<&'a str>,
    /// Keep a copy of the file in the cache before writing.
    pub backup: bool,
}

/// Assemble, then write the result into the file.
///
/// The `expect` contract is the same one `patch` enforces: without it nothing
/// is written, and the caller is shown what is actually there so the retry is
/// a copy-paste.
pub fn assemble_and_patch(
    spec: &str,
    code: &str,
    arch: Option<&str>,
    bits: Option<u32>,
    address: u64,
    spot: &Spot<'_>,
) -> Result<AsmPatch> {
    let (arch, bits) = match (arch, bits) {
        (Some(arch), Some(bits)) => (arch.to_string(), bits),
        _ => {
            let info = analyze(spec)?;
            let arch = arch.map(str::to_string).unwrap_or(info.arch.clone());
            let bits = bits.unwrap_or(info.bits);
            (arch, bits)
        }
    };

    let assembly = assemble(code, &arch, bits, address)?;
    let bytes = (0..assembly.hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&assembly.hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;

    let expect = match spot.expect {
        Some(expect) => parse_pattern(expect)?,
        None => {
            let path = resolve(spec)?;
            let data = std::fs::read(&path)?;
            let start = spot.offset as usize;
            let end = start.saturating_add(bytes.len()).min(data.len());
            if start < data.len() {
                bail!(
                    "no expect given: at {:#x} the file currently holds {}, \
                     pass expect with that value to confirm the spot",
                    spot.offset,
                    data[start..end]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
            bail!("offset {:#x} is past the end of the file", spot.offset);
        }
    };

    let patch = patch::apply(spec, spot.offset, &bytes, &expect, spot.backup)?;
    Ok(AsmPatch { assembly, patch })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_rekit_arch_names_to_rasm2() {
        assert_eq!(rasm2_target("aarch64", 64), ("arm", 64));
        assert_eq!(rasm2_target("arm", 32), ("arm", 32));
        assert_eq!(rasm2_target("arm", 64), ("arm", 64));
        assert_eq!(rasm2_target("x86", 32), ("x86", 32));
        assert_eq!(rasm2_target("x86", 64), ("x86", 64));
        assert_eq!(rasm2_target("x86-64", 64), ("x86", 64));
        assert_eq!(rasm2_target("i686", 64), ("x86", 32));
        assert_eq!(rasm2_target("mips", 32), ("mips", 32));
        assert_eq!(rasm2_target("mips", 64), ("mips", 64));
    }

    #[test]
    fn splits_instructions_on_semicolons_and_newlines() {
        assert_eq!(normalise("nop; ret\\nnop"), vec!["nop", "ret", "nop"]);
        assert!(normalise("  ;  ").is_empty());
    }

    #[test]
    fn assembles_x86_and_arm() {
        if which("rasm2").is_none() {
            return;
        }
        let x86 = assemble("mov eax, 1; ret", "x86-64", 64, 0x1000).unwrap();
        assert_eq!(x86.hex, "b801000000c3");
        assert_eq!(x86.instructions, 2);
        assert_eq!(x86.spaced, "b8 01 00 00 00 c3");

        let arm = assemble("mov x0, #1; ret", "aarch64", 64, 0).unwrap();
        assert_eq!(arm.hex, "200080d2c0035fd6");
    }

    #[test]
    fn relative_jumps_depend_on_the_base_address() {
        if which("rasm2").is_none() {
            return;
        }
        let here = assemble("jmp 0x1005", "x86-64", 64, 0x1000).unwrap();
        let there = assemble("jmp 0x2005", "x86-64", 64, 0x2000).unwrap();
        assert_eq!(here.hex, there.hex);
        assert_eq!(here.hex, "eb03");
    }

    #[test]
    fn empty_code_is_an_error() {
        assert!(assemble("   ", "x86-64", 64, 0).is_err());
    }
}
