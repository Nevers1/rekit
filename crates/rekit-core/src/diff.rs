//! Structural comparison of two builds of the same binary.
//!
//! A byte hash of a function is the wrong unit: `lea rdi, [rip+X]` shifts when
//! anything above it grows, so two identical functions look different after a
//! rebuild. What actually matters is the shape — which instructions, with which
//! operands — and whether a reference points inside the image (that is the same
//! object after a shift) or to a constant (that is a real change).
//!
//! So each function is disassembled with capstone, its operands normalised into
//! `A` (an address inside the image), `[RIPREL]` (a pc-relative reference) or
//! `I:n` (a literal), and only then hashed. Two builds agree on a function when
//! their normalised strings agree.
//!
//! capstone is BSD-3, so unlike keystone or unicorn it can live in this crate.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use capstone::prelude::*;

use crate::external::run;
use crate::info::analyze;
use crate::strings;
use crate::util::{read_spec, sha256_hex};

/// How much of a function is worth looking at. Beyond this the tail is
/// usually padding, and reading it would drag the next function in.
const CODE_CAP: usize = 512;

/// r2 analysis is a fallback for stripped builds, and it is not cheap.
const MAX_FUNCS: usize = 20_000;

#[derive(Debug, Clone, Serialize)]
pub struct FuncEntry {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub old_functions: usize,
    pub new_functions: usize,
    pub old_string_count: usize,
    pub new_string_count: usize,
    pub canonicalised: bool,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub moved: Vec<String>,
    pub added_unnamed: Vec<String>,
    pub new_strings: Vec<String>,
    pub gone_strings: Vec<String>,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.changed.is_empty()
            && self.moved.is_empty()
            && self.added_unnamed.is_empty()
            && self.new_strings.is_empty()
    }
}

struct Index {
    funcs: Vec<FuncEntry>,
    strings: BTreeSet<String>,
    canonicalised: bool,
}

fn engine(arch: &str, bits: u32) -> Option<Capstone> {
    let builder = Capstone::new();
    let cs = match arch.to_ascii_lowercase().as_str() {
        "x86-64" | "x86" | "i386" | "i686" => {
            let mode = if bits >= 64 {
                arch::x86::ArchMode::Mode64
            } else {
                arch::x86::ArchMode::Mode32
            };
            builder.x86().mode(mode).build().ok()?
        }
        "aarch64" | "arm64" => builder
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .ok()?,
        "arm" | "arm32" => builder.arm().mode(arch::arm::ArchMode::Arm).build().ok()?,
        "mips" | "mips64" => builder
            .mips()
            .mode(if bits >= 64 {
                arch::mips::ArchMode::Mips64
            } else {
                arch::mips::ArchMode::Mips32
            })
            .build()
            .ok()?,
        _ => return None,
    };
    Some(cs)
}

fn parse_int(text: &str) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let value = match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => i64::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<i64>().ok()?,
    };
    Some(if negative { -value } else { value })
}

/// The canonical form: instruction shape with addresses flattened away.
fn canon(code: &[u8], vaddr: u64, cs: &Capstone, lo: u64, hi: u64) -> Option<String> {
    let insns = cs.disasm_all(code, vaddr).ok()?;
    let mut parts = Vec::new();
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let ops = insn.op_str().unwrap_or("");
        let mut rendered = Vec::new();
        for part in ops.split(',') {
            let mut p = part.trim().to_string();
            if p.is_empty() {
                continue;
            }
            if let Some(val) = parse_int(&p) {
                p = if val >= 0 && (val as u64) >= lo && (val as u64) <= hi {
                    "A".to_string()
                } else {
                    format!("I:{}", (val as u64) & 0xFFFF)
                };
            }
            // A pc-relative displacement moves with the code, so its numeric
            // value says nothing about the change.
            if p.contains("[rip") || p.contains("[pc") {
                p = "[RIPREL]".to_string();
            }
            rendered.push(p);
        }
        parts.push(
            format!("{mnemonic} {}", rendered.join(" "))
                .trim()
                .to_string(),
        );
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("|"))
    }
}

/// Cut a function at its first exit.
///
/// Trimming on the 0xC3 byte would be wrong: a lot of functions end with a
/// tail `jmp`, not a `ret`, and such a cut swallows the next function whole —
/// which then "changes" whenever its neighbour does.
fn trim_to_end(code: &[u8], vaddr: u64, cs: Option<&Capstone>) -> Vec<u8> {
    let Some(cs) = cs else {
        return code[..code.len().min(CODE_CAP)].to_vec();
    };
    let Ok(insns) = cs.disasm_all(code, vaddr) else {
        return code[..code.len().min(CODE_CAP)].to_vec();
    };
    let mut out = Vec::new();
    for insn in insns.iter() {
        out.extend_from_slice(insn.bytes());
        let mnemonic = insn.mnemonic().unwrap_or("");
        if matches!(mnemonic, "ret" | "jmp" | "ud2") || out.len() >= CODE_CAP {
            break;
        }
    }
    if out.is_empty() {
        code[..code.len().min(CODE_CAP)].to_vec()
    } else {
        out
    }
}

struct Section {
    addr: u64,
    size: u64,
    offset: u64,
}

fn vaddr_to_off(sections: &[Section], baddr: u64, vaddr: u64) -> Option<usize> {
    for s in sections {
        if s.size == 0 {
            continue;
        }
        if s.addr <= vaddr && vaddr < s.addr.saturating_add(s.size) {
            return Some((s.offset + (vaddr - s.addr)) as usize);
        }
    }
    vaddr.checked_sub(baddr).map(|off| off as usize)
}

/// Functions that still have symbols, straight out of the format parser.
fn native_functions(data: &[u8]) -> Vec<(String, u64, u64)> {
    use goblin::Object;

    let mut out = Vec::new();
    match Object::parse(data) {
        Ok(Object::Elf(elf)) => {
            for (syms, strtab) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
                for sym in syms.iter() {
                    if !sym.is_function() || sym.st_value == 0 {
                        continue;
                    }
                    let Some(name) = strtab.get_at(sym.st_name) else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    out.push((name.to_string(), sym.st_value, sym.st_size));
                }
            }
        }
        Ok(Object::PE(pe)) => {
            for exp in &pe.exports {
                if let Some(name) = exp.name {
                    out.push((
                        name.to_string(),
                        (pe.image_base as u64).saturating_add(exp.rva as u64),
                        exp.size as u64,
                    ));
                }
            }
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => {
            for sym in macho.symbols() {
                let Ok((name, nlist)) = sym else { continue };
                if name.is_empty() || nlist.n_value == 0 {
                    continue;
                }
                out.push((name.to_string(), nlist.n_value, 0));
            }
        }
        _ => {}
    }
    out
}

/// Stripped builds keep almost no symbols, so r2 recovers the boundaries.
fn r2_functions(path: &std::path::Path) -> Vec<(String, u64, u64)> {
    let args = vec![
        "-q".to_string(),
        "-e".to_string(),
        "scr.color=0".to_string(),
        "-c".to_string(),
        "aaa; aflj".to_string(),
        path.display().to_string(),
    ];
    let Ok(out) = run("r2", &args, Duration::from_secs(120)) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(out.trim()) else {
        return Vec::new();
    };
    let Some(arr) = value.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|f| {
            let name = f.get("name")?.as_str()?.to_string();
            let addr = f.get("addr")?.as_u64()?;
            let size = f
                .get("size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            Some((name, addr, size))
        })
        .collect()
}

fn collect(spec: &str) -> Result<Index> {
    let (path, data) = read_spec(spec)?;
    let info = analyze(spec)?;

    let sections: Vec<Section> = info
        .sections
        .iter()
        .filter(|s| s.size > 0)
        .map(|s| Section {
            addr: s.addr,
            size: s.size,
            offset: s.offset,
        })
        .collect();

    let baddr = sections
        .iter()
        .map(|s| s.addr)
        .filter(|a| *a > 0)
        .min()
        .unwrap_or(0);

    // The image range decides what counts as "an address inside the binary".
    // It has to cover .data and .bss too: references to globals look like
    // constants otherwise, and then differ between builds for no reason.
    let mut lo = baddr;
    let mut hi = baddr + 0x1000;
    for s in &sections {
        lo = lo.min(s.addr);
        hi = hi.max(s.addr.saturating_add(s.size));
    }

    let cs = engine(&info.arch, info.bits);
    let mut entries = native_functions(&data);
    if entries.len() < 8 {
        let recovered = r2_functions(&path);
        if recovered.len() > entries.len() {
            entries = recovered;
        }
    }
    entries.truncate(MAX_FUNCS);

    let mut funcs = Vec::with_capacity(entries.len());
    for (name, addr, size) in entries {
        let code = match vaddr_to_off(&sections, baddr, addr) {
            Some(off) if off < data.len() => {
                let window = &data[off..off + CODE_CAP.min(data.len() - off)];
                if size > 0 {
                    &window[..(size as usize).min(window.len())]
                } else {
                    window
                }
            }
            _ => continue,
        };

        let trimmed = if size > 0 {
            code.to_vec()
        } else {
            trim_to_end(code, addr, cs.as_ref())
        };

        let canonical = cs.as_ref().and_then(|cs| canon(&trimmed, addr, cs, lo, hi));
        let basis = match &canonical {
            Some(text) => text.as_bytes().to_vec(),
            None => trimmed.clone(),
        };
        funcs.push(FuncEntry {
            name,
            addr,
            size,
            hash: sha256_hex(&basis)[..16].to_string(),
        });
    }

    let strings = strings::scan(spec, 6, None, 20_000)
        .unwrap_or_default()
        .into_iter()
        .map(|f| f.text)
        .collect::<BTreeSet<_>>();

    Ok(Index {
        funcs,
        strings,
        canonicalised: cs.is_some(),
    })
}

fn is_real_name(name: &str) -> bool {
    !name.starts_with("sub_") && !name.starts_with("fcn.")
}

fn by_name(index: &Index) -> BTreeMap<String, &FuncEntry> {
    index
        .funcs
        .iter()
        .filter(|f| is_real_name(&f.name))
        .map(|f| (f.name.clone(), f))
        .collect()
}

pub fn compare(old_spec: &str, new_spec: &str) -> Result<Report> {
    let old = collect(old_spec).with_context(|| format!("cannot index {old_spec}"))?;
    let new = collect(new_spec).with_context(|| format!("cannot index {new_spec}"))?;

    let old_by_name = by_name(&old);
    let new_by_name = by_name(&new);

    let old_hashes: BTreeSet<&str> = old.funcs.iter().map(|f| f.hash.as_str()).collect();
    let new_hashes: BTreeSet<&str> = new.funcs.iter().map(|f| f.hash.as_str()).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut moved = Vec::new();
    let mut added_unnamed = Vec::new();

    for (name, func) in &new_by_name {
        match old_by_name.get(name) {
            None => {
                // A function that lost its name but kept its body is not new.
                if !old_hashes.contains(func.hash.as_str()) {
                    added.push(format!("+ {name} @ {:#x} size={}", func.addr, func.size));
                }
            }
            Some(previous) => {
                if previous.hash != func.hash {
                    changed.push(format!(
                        "~ {name}: {:#x} -> {:#x}, size {} -> {}",
                        previous.addr, func.addr, previous.size, func.size
                    ));
                } else if previous.addr != func.addr {
                    moved.push(format!(
                        "= {name}: address moved {:#x} -> {:#x}",
                        previous.addr, func.addr
                    ));
                }
            }
        }
    }

    for (name, func) in &old_by_name {
        if !new_by_name.contains_key(name) && !new_hashes.contains(func.hash.as_str()) {
            removed.push(format!("- {name} @ {:#x} size={}", func.addr, func.size));
        }
    }

    for func in new.funcs.iter().filter(|f| !is_real_name(&f.name)) {
        if !old_hashes.contains(func.hash.as_str()) {
            added_unnamed.push(format!(
                "+ {} @ {:#x} size={}",
                func.name, func.addr, func.size
            ));
        }
    }

    let new_strings: Vec<String> = new
        .strings
        .difference(&old.strings)
        .filter(|s| s.len() >= 6)
        .cloned()
        .collect();
    let gone_strings: Vec<String> = old
        .strings
        .difference(&new.strings)
        .filter(|s| s.len() >= 6)
        .cloned()
        .collect();

    Ok(Report {
        old_functions: old.funcs.len(),
        new_functions: new.funcs.len(),
        old_string_count: old.strings.len(),
        new_string_count: new.strings.len(),
        canonicalised: old.canonicalised && new.canonicalised,
        added,
        removed,
        changed,
        moved,
        added_unnamed,
        new_strings,
        gone_strings,
    })
}

pub fn render(report: &Report, mode: &str, limit: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "old        {} functions, {} strings\n",
        report.old_functions, report.old_string_count
    ));
    out.push_str(&format!(
        "new        {} functions, {} strings\n",
        report.new_functions, report.new_string_count
    ));
    out.push_str(&format!(
        "matching   {}\n",
        if report.canonicalised {
            "instruction structure, addresses normalised"
        } else {
            "WARNING: capstone unavailable, raw bytes — shifted code will look changed"
        }
    ));
    out.push_str(&format!(
        "added      {} functions (+{} unnamed)\n",
        report.added.len(),
        report.added_unnamed.len()
    ));
    out.push_str(&format!("removed    {} functions\n", report.removed.len()));
    out.push_str(&format!("changed    {} functions\n", report.changed.len()));
    out.push_str(&format!("moved      {} functions\n", report.moved.len()));
    out.push_str(&format!(
        "strings    +{} new, -{} gone\n",
        report.new_strings.len(),
        report.gone_strings.len()
    ));

    let push = |out: &mut String, title: &str, items: &[String], take: usize| {
        if items.is_empty() {
            return;
        }
        out.push_str(&format!("\n-- {title} --\n"));
        for line in items.iter().take(take) {
            out.push_str(line);
            out.push('\n');
        }
        if items.len() > take {
            out.push_str(&format!("... {} more\n", items.len() - take));
        }
    };

    match mode {
        "strings" => {
            push(&mut out, "new strings", &report.new_strings, limit);
            push(&mut out, "gone strings", &report.gone_strings, limit);
        }
        "funcs" => {
            push(&mut out, "changed", &report.changed, limit);
            push(&mut out, "added", &report.added, limit);
            push(&mut out, "added (unnamed)", &report.added_unnamed, 20);
            push(&mut out, "removed", &report.removed, limit);
            push(&mut out, "moved", &report.moved, 20);
        }
        "full" => {
            push(&mut out, "changed", &report.changed, limit);
            push(&mut out, "added", &report.added, limit);
            push(&mut out, "added (unnamed)", &report.added_unnamed, 20);
            push(&mut out, "removed", &report.removed, limit);
            push(&mut out, "moved", &report.moved, 20);
            push(&mut out, "new strings", &report.new_strings, 40);
            push(&mut out, "gone strings", &report.gone_strings, 40);
        }
        _ => {
            if !report.changed.is_empty() {
                push(&mut out, "changed", &report.changed, 10);
            }
            out.push_str("\nre-run with mode=funcs or mode=strings for the lists\n");
        }
    }

    if report.is_empty() {
        out.push_str("\nno differences found\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_hex_numbers() {
        assert_eq!(parse_int("16"), Some(16));
        assert_eq!(parse_int("-1"), Some(-1));
        assert_eq!(parse_int("0x4010"), Some(0x4010));
        assert_eq!(parse_int("nonsense"), None);
    }

    #[test]
    fn address_inside_the_image_becomes_a_constant_marker() {
        let code = [0x48, 0xb8, 0x10, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cs = engine("x86-64", 64).unwrap();
        let text = canon(&code, 0x1000, &cs, 0x400000, 0x500000).unwrap();
        assert!(
            text.contains('A'),
            "expected an in-image address marker: {text}"
        );
    }

    #[test]
    fn same_shape_different_literal_hashes_differently() {
        let cs = engine("x86-64", 64).unwrap();
        let a = [0xb8, 0x01, 0x00, 0x00, 0x00];
        let b = [0xb8, 0x02, 0x00, 0x00, 0x00];
        let ta = canon(&a, 0x1000, &cs, 0x400000, 0x500000).unwrap();
        let tb = canon(&b, 0x1000, &cs, 0x400000, 0x500000).unwrap();
        assert_ne!(ta, tb);
    }

    #[test]
    fn trimming_stops_at_the_first_exit() {
        let cs = engine("x86-64", 64).unwrap();
        let code = [0x90, 0xc3, 0x90, 0x90];
        let trimmed = trim_to_end(&code, 0x1000, Some(&cs));
        assert_eq!(trimmed, vec![0x90, 0xc3]);
    }

    #[test]
    fn real_names_filter_out_generated_ones() {
        assert!(is_real_name("check_license"));
        assert!(!is_real_name("sub_401000"));
        assert!(!is_real_name("fcn.00401000"));
    }
}
