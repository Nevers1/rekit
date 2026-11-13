use anyhow::Result;
use goblin::Object;
use serde::Serialize;

use crate::util::{human_size, read_spec, sha256_hex, shannon};

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u64,
    pub perms: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Info {
    pub spec: String,
    pub resolved: String,
    pub size: u64,
    pub size_human: String,
    pub sha256: String,
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub endian: String,
    pub entry: Option<u64>,
    pub sections: Vec<Section>,
    pub hints: Vec<String>,
}

/// Everything a caller needs before choosing a heavier tool.
pub fn analyze(spec: &str) -> Result<Info> {
    let (path, data) = read_spec(spec)?;
    let mut info = Info {
        spec: spec.to_string(),
        resolved: path.display().to_string(),
        size: data.len() as u64,
        size_human: human_size(data.len() as u64),
        sha256: sha256_hex(&data),
        format: "unknown".to_string(),
        arch: "unknown".to_string(),
        bits: 0,
        endian: "?".to_string(),
        entry: None,
        sections: Vec::new(),
        hints: Vec::new(),
    };

    match Object::parse(&data) {
        Ok(Object::Elf(elf)) => {
            info.format = "ELF".to_string();
            info.bits = if elf.is_64 { 64 } else { 32 };
            info.endian = if elf.little_endian { "little" } else { "big" }.to_string();
            info.arch = elf_arch(elf.header.e_machine).to_string();
            info.entry = Some(elf.entry);
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                if name.is_empty() {
                    continue; // the null section
                }
                info.sections.push(Section {
                    name,
                    addr: sh.sh_addr,
                    size: sh.sh_size,
                    offset: sh.sh_offset,
                    perms: elf_perms(sh.sh_flags),
                    entropy: slice_entropy(&data, sh.sh_offset, sh.sh_size),
                });
            }
            if !elf.libraries.is_empty() {
                info.hints
                    .push(format!("needed: {}", elf.libraries.join(", ")));
            }
        }
        Ok(Object::PE(pe)) => {
            info.format = if pe.is_64 { "PE32+" } else { "PE32" }.to_string();
            info.bits = if pe.is_64 { 64 } else { 32 };
            info.endian = "little".to_string();
            info.arch = pe_arch(pe.header.coff_header.machine).to_string();
            info.entry = Some(pe.entry as u64);
            for sec in &pe.sections {
                let name = sec.name().unwrap_or("?").to_string();
                info.sections.push(Section {
                    name,
                    addr: sec.virtual_address as u64,
                    size: sec.size_of_raw_data as u64,
                    offset: sec.pointer_to_raw_data as u64,
                    perms: pe_perms(sec.characteristics),
                    entropy: slice_entropy(
                        &data,
                        sec.pointer_to_raw_data as u64,
                        sec.size_of_raw_data as u64,
                    ),
                });
            }
            if data.windows(4).any(|w| w == b"BSJB") {
                info.hints
                    .push(".NET assembly metadata found: decompile with ilspycmd".to_string());
            }
            if !pe.libraries.is_empty() {
                info.hints
                    .push(format!("imports from: {}", pe.libraries.join(", ")));
            }
        }
        Ok(Object::Mach(mach)) => match mach {
            goblin::mach::Mach::Binary(macho) => fill_macho(&mut info, &macho, &data),
            goblin::mach::Mach::Fat(fat) => {
                info.format = "Mach-O (universal)".to_string();
                let mut slices = Vec::new();
                for arch in fat.iter_arches().flatten() {
                    slices.push(macho_arch(arch.cputype));
                }
                info.hints.push(format!("slices: {}", slices.join(", ")));
                if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(0) {
                    fill_macho(&mut info, &macho, &data);
                    info.format = "Mach-O (universal)".to_string();
                }
            }
        },
        Ok(Object::Archive(_)) => {
            info.format = "ar archive".to_string();
            info.hints
                .push("static library: list members with `ar t`".to_string());
        }
        _ => sniff(&data, &mut info),
    }

    if info.format == "unknown" {
        sniff(&data, &mut info);
    }

    // Packed binaries are usually the interesting ones; say it up front.
    if info.sections.iter().any(|s| s.name.starts_with("UPX")) {
        info.hints
            .push("UPX sections: binary is compressed, unpack before analysis".to_string());
    }

    Ok(info)
}

fn fill_macho(info: &mut Info, macho: &goblin::mach::MachO, data: &[u8]) {
    info.format = if macho.is_object_file() {
        "Mach-O object"
    } else {
        "Mach-O"
    }
    .to_string();
    info.bits = if macho.is_64 { 64 } else { 32 };
    info.endian = if macho.little_endian { "little" } else { "big" }.to_string();
    info.arch = macho_arch(macho.header.cputype).to_string();
    info.entry = Some(macho.entry);

    for seg in macho.segments.iter() {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (sect, _) in sections {
            let name = sect.name().unwrap_or("?").to_string();
            let perms = if seg.initprot & 4 != 0 {
                "r-x"
            } else if seg.initprot & 2 != 0 {
                "rw-"
            } else {
                "r--"
            };
            info.sections.push(Section {
                name,
                addr: sect.addr,
                size: sect.size,
                offset: sect.offset as u64,
                perms: perms.to_string(),
                entropy: slice_entropy(data, sect.offset as u64, sect.size),
            });
        }
    }
}

fn slice_entropy(data: &[u8], offset: u64, size: u64) -> Option<f64> {
    let start = usize::try_from(offset).ok()?;
    if size == 0 || start >= data.len() {
        return None;
    }
    let end = (start + size as usize).min(data.len());
    Some(shannon(&data[start..end]))
}

fn elf_perms(flags: u64) -> String {
    let mut p = String::with_capacity(3);
    p.push(if flags & 0x2 != 0 { 'r' } else { '-' });
    p.push(if flags & 0x1 != 0 { 'w' } else { '-' });
    p.push(if flags & 0x4 != 0 { 'x' } else { '-' });
    p
}

fn pe_perms(ch: u32) -> String {
    let mut p = String::with_capacity(3);
    p.push(if ch & 0x4000_0000 != 0 { 'r' } else { '-' });
    p.push(if ch & 0x8000_0000 != 0 { 'w' } else { '-' });
    p.push(if ch & 0x2000_0000 != 0 { 'x' } else { '-' });
    p
}

pub fn elf_arch(machine: u16) -> &'static str {
    match machine {
        0x03 => "i386",
        0x3e => "x86-64",
        0x28 => "arm32",
        0xb7 => "aarch64",
        0xf3 => "riscv",
        0x08 => "mips",
        0x14 => "ppc",
        0x15 => "ppc64",
        0x16 => "s390",
        0x2b => "sparc",
        _ => "unknown",
    }
}

fn pe_arch(machine: u16) -> &'static str {
    match machine {
        0x014c => "i386",
        0x8664 => "x86-64",
        0x01c0 | 0x01c4 => "arm32",
        0xaa64 => "arm64",
        0x0200 => "ia64",
        _ => "unknown",
    }
}

fn macho_arch(cputype: u32) -> &'static str {
    match cputype {
        7 => "i386",
        0x0100_0007 => "x86-64",
        12 => "arm32",
        0x0100_000c => "arm64",
        0x0200_000c => "arm64_32",
        18 => "ppc",
        0x0100_0012 => "ppc64",
        _ => "unknown",
    }
}

/// Magic-byte detection for things goblin does not parse (APK, DEX, archives).
fn sniff(data: &[u8], info: &mut Info) {
    let magic = |m: &[u8]| data.starts_with(m);

    if magic(b"PK\x03\x04") || magic(b"PK\x05\x06") {
        info.format = "zip".to_string();
        if let Ok(archive) = zip::ZipArchive::new(std::io::Cursor::new(data)) {
            let mut names = Vec::new();
            for i in 0..archive.len().min(4096) {
                if let Some(name) = archive.name_for_index(i) {
                    names.push(name.to_string());
                }
            }
            let apk = names.iter().any(|n| n == "AndroidManifest.xml");
            let dex = names.iter().any(|n| n.ends_with(".dex"));
            let jar = names
                .iter()
                .any(|n| n.ends_with(".class") || n == "META-INF/MANIFEST.MF");
            if apk && dex {
                info.format = "APK".to_string();
                info.hints.push(
                    "APK: use path::inner to reach lib/<abi>/lib*.so or classes*.dex".to_string(),
                );
            } else if jar {
                info.format = "JAR".to_string();
                info.hints
                    .push("JVM archive: use rekit on path::inner".to_string());
            } else {
                info.hints
                    .push(format!("zip archive, {} entries", names.len()));
            }
        }
    } else if magic(b"dex\n") {
        info.format = "DEX".to_string();
        info.hints
            .push("dalvik bytecode: decompile with jadx".to_string());
    } else if magic(b"\x1f\x8b") {
        info.format = "gzip".to_string();
    } else if magic(b"\xca\xfe\xba\xbe") {
        // cafebabe is both a Java class and a fat Mach-O header; the major
        // version disambiguates them.
        let major = u16::from_be_bytes([
            data.get(6).copied().unwrap_or(0),
            data.get(7).copied().unwrap_or(0),
        ]);
        if (45..=70).contains(&major) {
            info.format = "Java class".to_string();
            info.bits = 32;
            info.endian = "big".to_string();
            info.hints.push("JVM bytecode: use javap".to_string());
        } else {
            info.format = "Mach-O (universal)".to_string();
        }
    } else if magic(b"\x00asm") {
        info.format = "WebAssembly".to_string();
    } else if magic(b"%PDF") {
        info.format = "PDF".to_string();
    } else if magic(b"SQLite format 3\x00") {
        info.format = "SQLite".to_string();
    } else if magic(b"ANDROID!") {
        info.format = "Android boot image".to_string();
    } else if magic(b"\x7fELF") {
        info.format = "ELF".to_string();
        info.bits = if data.get(4) == Some(&2) { 64 } else { 32 };
    } else if magic(b"MZ") {
        info.format = "PE".to_string();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_exe_is_elf_on_linux() {
        let exe = std::env::current_exe().unwrap();
        let info = analyze(&exe.display().to_string()).unwrap();
        assert_eq!(info.format, "ELF");
        assert_eq!(info.bits, 64);
        assert!(!info.sections.is_empty());
        assert_eq!(info.sha256.len(), 64);
    }

    #[test]
    fn garbage_does_not_panic() {
        let dir = std::env::temp_dir().join("rekit-info-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("junk.bin");
        std::fs::write(&p, vec![0x41u8; 4096]).unwrap();
        let info = analyze(&p.display().to_string()).unwrap();
        assert_eq!(info.format, "unknown");
    }
}
