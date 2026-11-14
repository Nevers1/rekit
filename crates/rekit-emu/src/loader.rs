//! Turning a binary on disk into something an emulator can execute.
//!
//! The loader does not try to be a linker. It maps what the file says should be
//! mapped, records the relocations that would otherwise be filled in by the
//! dynamic loader, and hands both to `emu`, which applies them once the import
//! stubs have addresses.

use anyhow::{bail, Result};
use goblin::Object;

/// Where a position independent image is placed. High enough not to collide
/// with the stack, the heap or the stub page, low enough to stay in 32 bits.
pub const PIC_BASE: u64 = 0x4000_0000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
}

impl Arch {
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
        }
    }

    pub fn ptr_size(self) -> u64 {
        match self {
            Arch::X86 | Arch::Arm => 4,
            Arch::X86_64 | Arch::Arm64 => 8,
        }
    }

    pub fn is_64(self) -> bool {
        self.ptr_size() == 8
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    Linux,
    Windows,
    Mac,
}

impl Platform {
    pub fn name(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::Mac => "macos",
        }
    }
}

/// A loaded segment: where it goes and what bytes it starts with.
pub struct Segment {
    pub addr: u64,
    pub data: Vec<u8>,
    pub mem_size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelocKind {
    /// value = base + addend
    Relative,
    /// value = symbol address + addend
    Absolute,
    /// value = symbol address; used for GOT / IAT slots
    Slot,
    /// value = the result of calling the resolver the addend points at.
    /// glibc's `IFUNC`: the slot holds a function that chooses one at load
    /// time (`memcpy` picks a variant by CPU features this way).
    Ifunc,
}

pub struct Reloc {
    /// Absolute address of the word to patch.
    pub addr: u64,
    pub kind: RelocKind,
    /// Imported or internal symbol this relocation refers to.
    pub sym: Option<String>,
    pub addend: i64,
    /// True for 32-bit REL relocations, where the addend lives in memory.
    pub implicit_addend: bool,
    /// The symbol is an IFUNC, so its address is a resolver, not the function.
    ///
    /// A linker usually emits `IRELATIVE` for a local IFUNC and a plain
    /// `GLOB_DAT`/`JUMP_SLOT` to an `IFUNC` symbol for an exported one, and the
    /// second shape is indistinguishable from an ordinary import unless the
    /// symbol type is looked at.
    pub ifunc: bool,
}

/// One imported function pointer that the loader wants filled in.
pub struct ImportSlot {
    pub name: String,
    pub addr: u64,
}

pub struct Loaded {
    pub arch: Arch,
    pub platform: Platform,
    pub base: u64,
    pub entry: u64,
    pub segments: Vec<Segment>,
    /// Defined functions, absolute addresses, in declaration order.
    pub symbols: Vec<(String, u64)>,
    /// Relocations that still need a value.
    pub relocs: Vec<Reloc>,
    /// Slots the dynamic loader would fill with import addresses (Mach-O IAT).
    pub import_slots: Vec<ImportSlot>,
    pub format: &'static str,
}

impl Loaded {
    /// Look up a function address. Accepts the name with or without the Mach-O
    /// leading underscore.
    pub fn find_symbol(&self, name: &str) -> Option<u64> {
        let trimmed = name.strip_prefix('_').unwrap_or(name);
        self.symbols
            .iter()
            .find(|(n, _)| n == name)
            .or_else(|| self.symbols.iter().find(|(n, _)| n == trimmed))
            .or_else(|| {
                let underscored = format!("_{trimmed}");
                self.symbols.iter().find(|(n, _)| n == &underscored)
            })
            .map(|(_, addr)| *addr)
    }
}

pub fn load(bytes: &[u8]) -> Result<Loaded> {
    match Object::parse(bytes)? {
        Object::Elf(elf) => load_elf(&elf, bytes),
        Object::PE(pe) => load_pe(&pe, bytes),
        Object::Mach(mach) => match mach {
            goblin::mach::Mach::Binary(macho) => load_macho(&macho, bytes),
            goblin::mach::Mach::Fat(_) => bail!(
                "this is a fat Mach-O; extract one architecture first \
                 (lipo -thin arm64 in.dylib -output out.dylib)"
            ),
        },
        Object::Archive(_) => bail!("this is an archive, not an executable; pick a member first"),
        Object::Unknown(magic) => bail!("unknown format (magic {magic:#x})"),
        _ => bail!("unsupported object format"),
    }
}

fn load_elf(elf: &goblin::elf::Elf, bytes: &[u8]) -> Result<Loaded> {
    use goblin::elf::{header, program_header, sym};

    let arch = match elf.header.e_machine {
        header::EM_386 => Arch::X86,
        header::EM_X86_64 => Arch::X86_64,
        header::EM_ARM => Arch::Arm,
        header::EM_AARCH64 => Arch::Arm64,
        other => bail!("unsupported ELF machine {other}"),
    };

    let base = if elf.header.e_type == header::ET_DYN {
        PIC_BASE
    } else {
        0
    };

    let mut segments = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != program_header::PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let start = ph.p_offset as usize;
        let end = start.saturating_add(ph.p_filesz as usize).min(bytes.len());
        let data = if start < end {
            bytes[start..end].to_vec()
        } else {
            Vec::new()
        };
        segments.push(Segment {
            addr: base + ph.p_vaddr,
            data,
            mem_size: ph.p_memsz,
        });
    }

    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // Each symbol table indexes its own string table; mixing them yields
    // plausible-looking but wrong names.
    let tables: [(&goblin::elf::Symtab, &goblin::strtab::Strtab); 2] =
        [(&elf.dynsyms, &elf.dynstrtab), (&elf.syms, &elf.strtab)];
    for (table, strtab) in tables {
        for s in table.iter() {
            let Some(name) = strtab.get_at(s.st_name) else {
                continue;
            };
            if name.is_empty() || s.st_shndx == 0 {
                continue;
            }
            let kind = s.st_type();
            if kind != sym::STT_FUNC && kind != sym::STT_GNU_IFUNC {
                continue;
            }
            if s.st_value == 0 {
                continue;
            }
            if seen.insert(name.to_string()) {
                symbols.push((name.to_string(), base + s.st_value));
            }
        }
    }

    let mut relocs = Vec::new();
    let mut push = |r_offset: u64,
                    r_type: u32,
                    sym_name: Option<String>,
                    addend: i64,
                    implicit: bool,
                    ifunc: bool| {
        let (kind, implicit_addend) = classify_elf_reloc(arch, r_type, implicit);
        let Some(kind) = kind else { return };
        relocs.push(Reloc {
            addr: base + r_offset,
            kind,
            sym: sym_name,
            addend,
            implicit_addend,
            ifunc,
        });
    };

    // `STT_GNU_IFUNC` is 10 in every ELF psABI that has it.
    const STT_IFUNC: u8 = 10;
    let ifunc_at = |sym: usize| -> bool {
        elf.dynsyms
            .get(sym)
            .map(|s| s.st_type() == STT_IFUNC)
            .unwrap_or(false)
    };

    for r in &elf.dynrelas {
        let name = elf
            .dynsyms
            .get(r.r_sym)
            .and_then(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_string));
        push(
            r.r_offset,
            r.r_type,
            name,
            r.r_addend.unwrap_or(0),
            false,
            ifunc_at(r.r_sym),
        );
    }
    for r in &elf.dynrels {
        let name = elf
            .dynsyms
            .get(r.r_sym)
            .and_then(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_string));
        push(r.r_offset, r.r_type, name, 0, true, ifunc_at(r.r_sym));
    }
    for r in &elf.pltrelocs {
        let name = elf
            .dynsyms
            .get(r.r_sym)
            .and_then(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_string));
        // `pltrelocs` can be either REL or RELA; goblin exposes the same
        // fields on both.
        let addend = r.r_addend.unwrap_or(0);
        push(
            r.r_offset,
            r.r_type,
            name,
            addend,
            r.r_addend.is_none(),
            ifunc_at(r.r_sym),
        );
    }

    Ok(Loaded {
        arch,
        platform: Platform::Linux,
        base,
        entry: base + elf.entry,
        segments,
        symbols,
        relocs,
        import_slots: Vec::new(),
        format: "elf",
    })
}

fn classify_elf_reloc(arch: Arch, r_type: u32, implicit: bool) -> (Option<RelocKind>, bool) {
    use RelocKind::*;
    let (kind, mi) = match arch {
        Arch::X86_64 => match r_type {
            1 => (Some(Absolute), false), // R_X86_64_64
            6 | 7 => (Some(Slot), false), // GLOB_DAT / JUMP_SLOT
            8 => (Some(Relative), false), // RELATIVE
            37 => (Some(Ifunc), false),   // IRELATIVE
            _ => (None, false),
        },
        Arch::X86 => match r_type {
            1 => (Some(Absolute), implicit), // R_386_32
            6 | 7 => (Some(Slot), false),    // GLOB_DAT / JMP_SLOT
            8 => (Some(Relative), implicit), // RELATIVE
            42 => (Some(Ifunc), implicit),   // R_386_IRELATIVE
            _ => (None, false),
        },
        Arch::Arm => match r_type {
            2 => (Some(Absolute), implicit),  // R_ARM_ABS32
            21 | 22 => (Some(Slot), false),   // GLOB_DAT / JUMP_SLOT
            23 => (Some(Relative), implicit), // RELATIVE
            160 => (Some(Ifunc), implicit),   // R_ARM_IRELATIVE
            _ => (None, false),
        },
        Arch::Arm64 => match r_type {
            257 => (Some(Absolute), false),     // R_AARCH64_ABS64
            1025 | 1026 => (Some(Slot), false), // GLOB_DAT / JUMP_SLOT
            1027 => (Some(Relative), false),    // RELATIVE
            1032 => (Some(Ifunc), false),       // R_AARCH64_IRELATIVE
            _ => (None, false),
        },
    };
    (kind, mi)
}

fn load_pe(pe: &goblin::pe::PE, file: &[u8]) -> Result<Loaded> {
    let arch = if pe.is_64 { Arch::X86_64 } else { Arch::X86 };
    let base = pe.image_base as u64;

    let mut segments = Vec::new();
    // The headers are readable at the image base and a few programs do look at
    // them, so map them too.
    if let Some(opt) = &pe.header.optional_header {
        let size = (opt.windows_fields.size_of_headers as usize).min(file.len());
        if size > 0 {
            segments.push(Segment {
                addr: base,
                data: file[..size].to_vec(),
                mem_size: size as u64,
            });
        }
    }
    for s in &pe.sections {
        let raw_start = (s.pointer_to_raw_data as usize).min(file.len());
        let raw_size = (s.size_of_raw_data as usize).min(file.len() - raw_start);
        segments.push(Segment {
            addr: base + s.virtual_address as u64,
            data: file[raw_start..raw_start + raw_size].to_vec(),
            mem_size: (s.virtual_size as u64).max(s.size_of_raw_data as u64),
        });
    }

    let mut symbols = Vec::new();
    for e in &pe.exports {
        if let Some(name) = e.name {
            if e.rva != 0 {
                symbols.push((name.to_string(), base + e.rva as u64));
            }
        }
    }

    let mut import_slots = Vec::new();
    if let Some(opt) = &pe.header.optional_header {
        if let Some(dir) = opt.data_directories.get_import_table() {
            if dir.virtual_address != 0 {
                parse_pe_imports(pe, file, dir.virtual_address, &mut import_slots, base)?;
            }
        }
    }

    Ok(Loaded {
        arch,
        platform: Platform::Windows,
        base,
        entry: base + pe.entry as u64,
        segments,
        symbols,
        relocs: Vec::new(),
        import_slots,
        format: "pe",
    })
}

fn parse_pe_imports(
    pe: &goblin::pe::PE,
    file: &[u8],
    table_rva: u32,
    slots: &mut Vec<ImportSlot>,
    image_base: u64,
) -> Result<()> {
    let Some(off) = pe_rva_to_offset(pe, table_rva as usize) else {
        return Ok(());
    };
    let desc_bytes = &file[off.min(file.len())..];
    let ptr = if pe.is_64 { 8 } else { 4 };

    let mut pos = 0usize;
    loop {
        if pos + 20 > desc_bytes.len() {
            break;
        }
        let desc = &desc_bytes[pos..pos + 20];
        let orig_thunk = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
        let first_thunk = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);
        if orig_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let lookup = if orig_thunk != 0 {
            orig_thunk
        } else {
            first_thunk
        };
        let mut i = 0u64;
        while let Some(entry_off) = pe_rva_to_offset(pe, lookup as usize + (i as usize) * ptr) {
            let Some(raw) = file.get(entry_off..entry_off + ptr) else {
                break;
            };
            let value = if ptr == 8 {
                u64::from_le_bytes(raw.try_into().unwrap())
            } else {
                u32::from_le_bytes(raw.try_into().unwrap()) as u64
            };
            if value == 0 {
                break;
            }
            let name = if value & (1 << (ptr * 8 - 1)) != 0 {
                format!("ordinal_{}", value & 0xffff)
            } else {
                let rva = (value & 0x7fff_ffff) as usize;
                match pe_rva_to_offset(pe, rva + 2) {
                    Some(o) => file
                        .get(o..)
                        .and_then(|b| {
                            let end = b.iter().take(256).position(|c| *c == 0)?;
                            std::str::from_utf8(&b[..end]).ok().map(str::to_string)
                        })
                        .unwrap_or_default(),
                    None => String::new(),
                }
            };
            if !name.is_empty() {
                slots.push(ImportSlot {
                    name,
                    addr: image_base + first_thunk as u64 + i * ptr as u64,
                });
            }
            i += 1;
        }
        pos += 20;
    }
    Ok(())
}

fn pe_rva_to_offset(pe: &goblin::pe::PE, rva: usize) -> Option<usize> {
    for s in &pe.sections {
        let start = s.virtual_address as usize;
        let span = (s.virtual_size as usize).max(s.size_of_raw_data as usize);
        if rva >= start && rva < start + span {
            let delta = rva - start;
            if delta < s.size_of_raw_data as usize {
                return Some(s.pointer_to_raw_data as usize + delta);
            }
            return None;
        }
    }
    // Fall back to the headers for low RVAs.
    if rva < 0x1000 {
        return Some(rva);
    }
    None
}

fn load_macho(macho: &goblin::mach::MachO, _file: &[u8]) -> Result<Loaded> {
    use goblin::mach::constants::cputype;

    let arch = match macho.header.cputype() {
        cputype::CPU_TYPE_X86 => Arch::X86,
        cputype::CPU_TYPE_X86_64 => Arch::X86_64,
        cputype::CPU_TYPE_ARM => Arch::Arm,
        cputype::CPU_TYPE_ARM64 => Arch::Arm64,
        other => bail!("unsupported Mach-O CPU type {other}"),
    };

    // dylibs are linked at 0; move them out of the zero page so a NULL
    // dereference still faults.
    let min_vmaddr = macho
        .segments
        .iter()
        .filter(|s| s.filesize > 0)
        .map(|s| s.vmaddr)
        .min()
        .unwrap_or(0);
    let base = if min_vmaddr < 0x1000 { PIC_BASE } else { 0 };

    let mut segments = Vec::new();
    for s in &macho.segments {
        if s.vmaddr == 0 && s.filesize == 0 {
            continue;
        }
        segments.push(Segment {
            addr: base + s.vmaddr,
            data: s.data.to_vec(),
            mem_size: s.vmsize.max(s.filesize),
        });
    }

    let mut symbols = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for sym in macho.symbols().flatten() {
        let (name, nlist) = sym;
        if nlist.is_stab() || nlist.is_undefined() || nlist.n_value == 0 {
            continue;
        }
        let clean = name.strip_prefix('_').unwrap_or(name);
        if clean.is_empty() {
            continue;
        }
        if seen.insert(clean.to_string()) {
            symbols.push((clean.to_string(), base + nlist.n_value));
        }
    }

    let mut import_slots = Vec::new();
    for imp in macho.imports().unwrap_or_default() {
        if imp.address != 0 {
            import_slots.push(ImportSlot {
                name: imp.name.to_string(),
                addr: base + imp.address,
            });
        }
    }

    Ok(Loaded {
        arch,
        platform: Platform::Mac,
        base,
        entry: base + macho.entry,
        segments,
        symbols,
        relocs: Vec::new(),
        import_slots,
        format: "macho",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ifunc_relocation_is_recognised_on_every_arch() {
        for (arch, r_type) in [
            (Arch::X86_64, 37),
            (Arch::X86, 42),
            (Arch::Arm, 160),
            (Arch::Arm64, 1032),
        ] {
            let (kind, _) = classify_elf_reloc(arch, r_type, false);
            assert_eq!(kind, Some(RelocKind::Ifunc), "{}", arch.name());
        }
    }
}
