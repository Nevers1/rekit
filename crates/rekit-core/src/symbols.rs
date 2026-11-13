use anyhow::{bail, Result};
use goblin::Object;
use serde::Serialize;

use crate::util::read_spec;

#[derive(Debug, Clone, Serialize)]
pub struct Sym {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lib: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<u64>,
    pub kind: String,
}

/// Symbols this binary needs from the outside world.
pub fn imports(spec: &str, limit: usize) -> Result<Vec<Sym>> {
    let (_, data) = read_spec(spec)?;
    let mut out = Vec::new();

    match Object::parse(&data)? {
        Object::Elf(elf) => {
            for sym in elf.dynsyms.iter() {
                if sym.st_shndx != 0 {
                    continue; // defined here, not an import
                }
                let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                out.push(Sym {
                    name: name.to_string(),
                    lib: None,
                    addr: None,
                    kind: if sym.is_function() { "func" } else { "data" }.to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
            // Remember which shared objects provide them.
            if !elf.libraries.is_empty() && out.len() < limit {
                out.push(Sym {
                    name: format!("[libraries] {}", elf.libraries.join(", ")),
                    lib: None,
                    addr: None,
                    kind: "note".to_string(),
                });
            }
        }
        Object::PE(pe) => {
            for imp in &pe.imports {
                out.push(Sym {
                    name: imp.name.to_string(),
                    lib: Some(imp.dll.to_string()),
                    addr: Some(imp.ordinal as u64),
                    kind: "import".to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            for imp in macho.imports()? {
                out.push(Sym {
                    name: imp.name.to_string(),
                    lib: if imp.dylib.is_empty() {
                        None
                    } else {
                        Some(imp.dylib.to_string())
                    },
                    addr: Some(imp.offset),
                    kind: if imp.is_lazy { "lazy" } else { "bind" }.to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(0) {
                for imp in macho.imports()? {
                    out.push(Sym {
                        name: imp.name.to_string(),
                        lib: None,
                        addr: Some(imp.offset),
                        kind: "bind".to_string(),
                    });
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        _ => bail!("{spec}: not a PE/ELF/Mach-O binary"),
    }

    Ok(out)
}

/// Symbols this binary offers to others.
pub fn exports(spec: &str, limit: usize) -> Result<Vec<Sym>> {
    let (_, data) = read_spec(spec)?;
    let mut out = Vec::new();

    match Object::parse(&data)? {
        Object::Elf(elf) => {
            for sym in elf.dynsyms.iter() {
                if sym.st_shndx == 0 {
                    continue; // undefined here
                }
                if sym.st_bind() != goblin::elf::sym::STB_GLOBAL
                    && sym.st_bind() != goblin::elf::sym::STB_WEAK
                {
                    continue;
                }
                let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                out.push(Sym {
                    name: name.to_string(),
                    lib: None,
                    addr: Some(sym.st_value),
                    kind: if sym.is_function() { "func" } else { "data" }.to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Object::PE(pe) => {
            for exp in &pe.exports {
                out.push(Sym {
                    name: exp
                        .name
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("#{}", exp.rva)),
                    lib: None,
                    addr: exp.offset.map(|o| o as u64),
                    kind: "export".to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            for exp in macho.exports()? {
                out.push(Sym {
                    name: exp.name,
                    lib: None,
                    addr: Some(exp.offset),
                    kind: "export".to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            if let Ok(goblin::mach::SingleArch::MachO(macho)) = fat.get(0) {
                for exp in macho.exports()? {
                    out.push(Sym {
                        name: exp.name,
                        lib: None,
                        addr: Some(exp.offset),
                        kind: "export".to_string(),
                    });
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        _ => bail!("{spec}: not a PE/ELF/Mach-O binary"),
    }

    Ok(out)
}

/// Import names only — what the anti-debug and capability scans care about.
pub fn import_names(spec: &str) -> Result<Vec<String>> {
    Ok(imports(spec, 20_000)?
        .into_iter()
        .filter(|s| s.kind != "note")
        .map(|s| s.name)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libc_is_resolvable_on_linux() {
        let names = match import_names("/lib/x86_64-linux-gnu/libc.so.6") {
            Ok(n) => n,
            Err(_) => return, // fixture absent on this distro
        };
        assert!(names
            .iter()
            .any(|n| n.starts_with("strlen") || n.contains("malloc")));
    }
}
