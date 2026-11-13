use anyhow::Result;
use serde::Serialize;

use crate::info::analyze;
use crate::util::{read_spec, shannon};

#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    pub name: String,
    pub entropy: f64,
    pub size: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub spec: String,
    pub file_entropy: f64,
    pub sections: Vec<SectionEntropy>,
    pub packers: Vec<String>,
    pub anomalies: Vec<String>,
    pub verdict: String,
}

const SECTION_MARKERS: &[(&str, &str)] = &[
    ("upx0", "UPX"),
    ("upx1", "UPX"),
    ("upx2", "UPX"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".themida", "Themida"),
    (".winlice", "Themida"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".mpress1", "MPRESS"),
    (".mpress2", "MPRESS"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    (".perplex", "Perplex"),
    (".packed", "generic packer"),
];

const STRING_MARKERS: &[(&str, &str)] = &[
    ("UPX!", "UPX"),
    ("VMProtect", "VMProtect"),
    ("Themida", "Themida"),
    ("Enigma protector", "Enigma"),
    ("ConfuserEx", "ConfuserEx"),
    (".NET Reactor", ".NET Reactor"),
    ("Obsidium", "Obsidium"),
    ("Safengine", "Safengine"),
    ("Armadillo", "Armadillo"),
];

pub fn analyze_entropy(spec: &str) -> Result<Report> {
    let (_, data) = read_spec(spec)?;
    let info = analyze(spec)?;

    let mut packers: Vec<String> = Vec::new();
    let mut sections = Vec::new();
    for sect in &info.sections {
        let named = sect.name.to_ascii_lowercase();
        for (marker, name) in SECTION_MARKERS {
            if named.contains(marker) {
                push_unique(&mut packers, name);
            }
        }
        sections.push(SectionEntropy {
            name: sect.name.clone(),
            entropy: sect.entropy.unwrap_or(0.0),
            size: sect.size,
            executable: sect.perms.contains('x'),
        });
    }

    for (marker, name) in STRING_MARKERS {
        if contains_ci(&data, marker) {
            push_unique(&mut packers, name);
        }
    }

    let mut anomalies = Vec::new();
    for sect in &sections {
        if sect.executable && sect.entropy > 7.2 && sect.size >= 1024 {
            anomalies.push(format!(
                "executable section {} has entropy {:.2} — packed or encrypted code",
                sect.name, sect.entropy
            ));
        }
        if !sect.executable && sect.entropy > 7.4 && sect.size >= 4096 {
            anomalies.push(format!(
                "data section {} has entropy {:.2} — compressed payload",
                sect.name, sect.entropy
            ));
        }
    }
    if info.sections.iter().any(|s| s.perms == "rwx") {
        anomalies.push("section with rwx permissions — self-modifying code".to_string());
    }
    if info.sections.len() > 30 {
        anomalies.push(format!(
            "{} sections — unusual, typical packer trait",
            info.sections.len()
        ));
    }

    let file_entropy = shannon(&data);
    let verdict = if !packers.is_empty() {
        format!("packed ({})", packers.join(", "))
    } else if !anomalies.is_empty() {
        "suspicious: high entropy or unusual layout".to_string()
    } else if file_entropy > 7.2 {
        "high entropy without known packer: compressed or encrypted data".to_string()
    } else {
        "no packing signs".to_string()
    };

    Ok(Report {
        spec: spec.to_string(),
        file_entropy,
        sections,
        packers,
        anomalies,
        verdict,
    })
}

fn push_unique(v: &mut Vec<String>, value: &str) {
    if !v.iter().any(|x| x == value) {
        v.push(value.to_string());
    }
}

pub(crate) fn contains_ci(haystack: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    if n.is_empty() || haystack.len() < n.len() {
        return false;
    }
    haystack.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_has_low_entropy() {
        let dir = std::env::temp_dir().join("rekit-entropy-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.bin");
        std::fs::write(&p, "hello world, hello world, hello world".repeat(50)).unwrap();

        let report = analyze_entropy(&p.display().to_string()).unwrap();
        assert!(report.file_entropy < 5.0);
        assert!(report.packers.is_empty());
        assert_eq!(report.verdict, "no packing signs");
    }

    #[test]
    fn random_bytes_look_packed() {
        let dir = std::env::temp_dir().join("rekit-entropy-test");
        let p = dir.join("r.bin");
        let data: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        std::fs::write(&p, &data).unwrap();

        let report = analyze_entropy(&p.display().to_string()).unwrap();
        assert!(report.file_entropy > 7.0);
    }

    #[test]
    fn case_insensitive_needle() {
        assert!(contains_ci(b"...vmprotect...", "VMProtect"));
        assert!(!contains_ci(b"short", "VMProtect"));
    }
}
