use anyhow::{bail, Result};
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use crate::external::{run_parsed, which};
use crate::symbols::import_names;
use crate::util::read_spec;

#[derive(Debug, Clone, Serialize)]
pub struct ConstHit {
    pub name: &'static str,
    pub offset: u64,
}

/// Well known constants. Their presence tells more about a binary than any
/// string: an AES S-box means real cryptography, not a base64 encoder.
const MARKERS: &[(&str, &[u8])] = &[
    (
        "AES S-box",
        &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5],
    ),
    (
        "AES inverse S-box",
        &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38],
    ),
    (
        "SHA-256 round constants",
        &[0x42, 0x8a, 0x2f, 0x98, 0xd4, 0x28, 0x51, 0x4d],
    ),
    (
        "SHA-512 round constants",
        &[0x42, 0x8f, 0x98, 0x28, 0xd7, 0x28, 0xae, 0x22],
    ),
    (
        "MD5 initial state",
        &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    ),
    (
        "CRC32 table",
        &[0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77],
    ),
    ("ChaCha/Salsa20 sigma", b"expand 32-byte k"),
    (
        "Base64 alphabet",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    ),
    ("TEA/XXTEA delta", &[0xb9, 0x79, 0x37, 0x9e]),
    (
        "Blowfish P-array start",
        &[0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3],
    ),
    ("zlib header", &[0x78, 0x9c]),
];

pub fn consts(spec: &str, limit: usize) -> Result<Vec<ConstHit>> {
    let (_, data) = read_spec(spec)?;
    let mut hits = Vec::new();
    for (name, needle) in MARKERS {
        let mut i = 0usize;
        while i + needle.len() <= data.len() {
            if &data[i..i + needle.len()] == *needle {
                hits.push(ConstHit {
                    name,
                    offset: i as u64,
                });
                if hits.len() >= limit {
                    return Ok(hits);
                }
                i += needle.len();
            } else {
                i += 1;
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    Ok(hits)
}

/// Import names grouped by what they let a binary do.
const KINDS: &[(&str, &[&str])] = &[
    (
        "anti",
        &[
            "ptrace",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "GetTickCount",
            "QueryPerformanceCounter",
            "sysctl",
            "__system_property_get",
            "prctl",
        ],
    ),
    (
        "crypto",
        &[
            "Crypt", "BCrypt", "Ncrypt", "EVP_", "AES_", "SHA", "MD5", "RC4", "SSL_", "TLS_",
            "mbedtls_", "gcry_", "sodium_", "PEM_",
        ],
    ),
    (
        "net",
        &[
            "socket",
            "connect",
            "send",
            "recv",
            "bind",
            "listen",
            "accept",
            "getaddrinfo",
            "gethostbyname",
            "WSAStartup",
            "InternetOpen",
            "Http",
            "WinHttp",
            "curl_",
            "inet_",
            "res_query",
        ],
    ),
    (
        "mem",
        &[
            "malloc",
            "calloc",
            "realloc",
            "free",
            "mmap",
            "mprotect",
            "VirtualAlloc",
            "VirtualProtect",
            "HeapAlloc",
            "HeapCreate",
            "memcpy",
            "memmove",
            "LocalAlloc",
        ],
    ),
    (
        "file",
        &[
            "fopen",
            "open",
            "fread",
            "read",
            "fwrite",
            "write",
            "fclose",
            "close",
            "stat",
            "unlink",
            "remove",
            "mkdir",
            "rmdir",
            "rename",
            "opendir",
            "readdir",
            "seek",
            "truncate",
            "access",
            "chmod",
            "chown",
            "fseek",
            "ftell",
            "CreateFile",
            "ReadFile",
            "WriteFile",
            "DeleteFile",
        ],
    ),
    (
        "procmem",
        &[
            "CreateRemoteThread",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "VirtualAlloc",
            "VirtualProtect",
            "NtAllocate",
            "NtWrite",
            "NtRead",
            "OpenProcess",
            "NtOpenProcess",
            "LoadLibrary",
            "GetProcAddress",
            "GetModuleHandle",
            "rundll",
        ],
    ),
    (
        "ui",
        &[
            "MessageBox",
            "CreateWindow",
            "DialogBox",
            "RegOpen",
            "RegQuery",
            "RegSet",
            "ShellExecute",
            "CreateProcess",
            "WinExec",
            "GetWindowText",
            "wsprintf",
        ],
    ),
    (
        "priv",
        &[
            "setuid",
            "setgid",
            "system",
            "popen",
            "exec",
            "fork",
            "CreateProcess",
            "ShellExecute",
            "WinExec",
            "LoadLibrary",
            "GetProcAddress",
            "dlopen",
            "dlsym",
            "AdjustTokenPrivileges",
            "OpenProcessToken",
        ],
    ),
];

/// Import names grouped by what they let the binary do.
///
/// `category` narrows the answer to one group; an unknown name is an error
/// listing the real ones, because silently returning nothing reads as "no
/// matches" and sends the caller looking for a different problem.
pub fn apis(spec: &str, category: Option<&str>) -> Result<BTreeMap<&'static str, Vec<String>>> {
    if let Some(wanted) = category {
        if !KINDS.iter().any(|(kind, _)| *kind == wanted) {
            let known: Vec<&str> = KINDS.iter().map(|(kind, _)| *kind).collect();
            bail!(
                "unknown category {wanted:?}: pick one of {}",
                known.join(", ")
            );
        }
    }

    let names = import_names(spec)?;
    let mut out: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for name in &names {
        let mut placed = false;
        for (kind, needles) in KINDS {
            if needles.iter().any(|needle| name.contains(needle)) {
                placed = true;
                let bucket = out.entry(kind).or_default();
                if bucket.len() < 200 && !bucket.contains(name) {
                    bucket.push(name.clone());
                }
            }
        }
        if !placed {
            let bucket = out.entry("other").or_default();
            if bucket.len() < 200 && !bucket.contains(name) {
                bucket.push(name.clone());
            }
        }
    }

    if let Some(wanted) = category {
        out.retain(|kind, _| *kind == wanted);
    }
    Ok(out)
}

/// A function with a file offset, so a constant found in the file can be named.
struct Func {
    name: String,
    vaddr: u64,
    paddr: u64,
    size: u64,
}

#[derive(Deserialize)]
struct RabinSymbol {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    vaddr: u64,
    #[serde(default)]
    paddr: u64,
    #[serde(default)]
    size: u64,
}

/// The function table, when radare2 can give one.
///
/// No rabin2 is not an error: `const` still reports where the constant lives,
/// it just cannot say which function that is — which is normal for a stripped
/// binary anyway.
fn functions(path: &Path) -> Vec<Func> {
    if which("rabin2").is_none() {
        return Vec::new();
    }
    let args = ["-sj".to_string(), path.display().to_string()];
    let Ok(text) = run_parsed("rabin2", &args, Duration::from_secs(180)) else {
        return Vec::new();
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let Some(symbols) = doc.get("symbols").and_then(|s| s.as_array()) else {
        return Vec::new();
    };
    symbols
        .iter()
        .filter_map(|value| serde_json::from_value::<RabinSymbol>(value.clone()).ok())
        .filter(|sym| sym.kind == "FUNC" && sym.size > 0 && !sym.name.is_empty())
        .map(|sym| Func {
            name: sym.name,
            vaddr: sym.vaddr,
            paddr: sym.paddr,
            size: sym.size,
        })
        .collect()
}

/// Find a caller-supplied constant in the code.
///
/// Both byte orders are searched: the compiler's choice is not visible from
/// here, and a constant that only appears big-endian would otherwise look
/// absent. `width` is the constant's size in bytes, not the register's — a
/// 32-bit immediate stored in `rax` still occupies four bytes.
pub fn const_value(spec: &str, value: &str, width: usize, limit: usize) -> Result<String> {
    if !matches!(width, 1 | 2 | 4 | 8) {
        bail!("width must be 1, 2, 4 or 8 bytes, not {width}");
    }
    let numbers = parse_numbers(value)?;
    if numbers.is_empty() {
        bail!("give a constant: 1234, 0xDEADBEEF, or bytes as 0x5A,0x5B");
    }
    for number in &numbers {
        if width < 8 && *number >= (1u64 << (width * 8)) {
            bail!("{number:#x} does not fit in {width} bytes: raise width or check the value");
        }
    }

    let (path, data) = read_spec(spec)?;
    let funcs = functions(&path);
    let mut hits: Vec<String> = Vec::new();
    let mut searched = 0usize;

    for number in &numbers {
        let le = number.to_le_bytes();
        let be = number.to_be_bytes();
        for (order, pattern) in [("LE", &le[..width]), ("BE", &be[8 - width..])] {
            let mut i = 0usize;
            while i + pattern.len() <= data.len() {
                searched += 1;
                if &data[i..i + pattern.len()] == pattern {
                    hits.push(describe_hit(&funcs, i as u64, *number, width, order));
                    i += pattern.len();
                } else {
                    i += 1;
                }
                if hits.len() >= limit {
                    break;
                }
            }
            if hits.len() >= limit {
                break;
            }
        }
        if hits.len() >= limit {
            break;
        }
    }

    let label = numbers
        .iter()
        .map(|n| format!("{n:#x}"))
        .collect::<Vec<_>>()
        .join(", ");
    if hits.is_empty() {
        return Ok(format!(
            "constant {label} ({width} bytes) not found in {} ({searched} positions, LE and BE)\n\
             it may be built from parts, or live in .rodata — try `strings` or `hex bytes`\n",
            path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| spec.to_string())
        ));
    }
    let mut out = format!("constant {label} ({width} bytes): {} hits\n", hits.len());
    for hit in &hits {
        out.push_str(&format!("  {hit}\n"));
    }
    if hits.len() >= limit {
        out.push_str(&format!("... limit {limit} reached\n"));
    }
    Ok(out)
}

fn describe_hit(funcs: &[Func], offset: u64, number: u64, width: usize, order: &str) -> String {
    let bytes: Vec<String> = match order {
        "LE" => number.to_le_bytes()[..width]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        _ => number.to_be_bytes()[8 - width..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    };
    let owner = funcs
        .iter()
        .find(|f| f.paddr > 0 && offset >= f.paddr && offset < f.paddr + f.size)
        .map(|f| format!("{}+{:#x} @ {:#x}", f.name, offset - f.paddr, f.vaddr))
        .unwrap_or_else(|| "not in a known function".to_string());
    format!(
        "0x{offset:08x}  {order}{}  {}  {owner}",
        width * 8,
        bytes.join(" ")
    )
}

fn parse_numbers(value: &str) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for token in value.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        let parsed = match token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => token.parse::<u64>(),
        };
        let parsed = parsed.map_err(|_| anyhow::anyhow!("{token:?} is not a number"))?;
        out.push(parsed);
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ProbeEnvelope {
    arch: String,
    platform: String,
    arg: String,
    runs: Vec<ProbeRun>,
}

#[derive(Deserialize)]
struct ProbeRun {
    name: String,
    address: String,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    stop: String,
    #[serde(rename = "return", default)]
    ret: Option<ProbeReturn>,
    #[serde(default)]
    fault: Option<ProbeFault>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ProbeReturn {
    hex: String,
    i64: i64,
}

#[derive(Deserialize)]
struct ProbeFault {
    access: String,
    address: u64,
}

/// Call every exported function once with the same trial argument.
///
/// One process, one load per call: the emulator does the loop, because a
/// hundred separate `run` invocations would spend most of their time parsing
/// the same binary.
pub fn probe(spec: &str, arg: &str, limit: usize, json: bool) -> Result<String> {
    let exe = crate::emulate::find_binary().ok_or_else(|| {
        anyhow::anyhow!(
            "rekit-emu is not installed; build it with `cargo build --release -p rekit-emu`"
        )
    })?;
    let path = crate::emulate::prepare_path(spec)?;
    let mut args: Vec<String> = vec![
        "probe".to_string(),
        path,
        "--arg".to_string(),
        arg.to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    // Always ask for JSON: the summary below is built from it, and asking for
    // the human table would mean parsing the table back.
    args.push("--json".to_string());
    let tool = exe.to_string_lossy().to_string();
    let text = run_parsed(&tool, &args, Duration::from_secs(600))
        .map_err(|err| anyhow::anyhow!("probe failed: {err}"))?;
    if json {
        return Ok(text);
    }
    let envelope: ProbeEnvelope = serde_json::from_str(&text)
        .map_err(|err| anyhow::anyhow!("cannot read the emulator's report: {err}"))?;

    let ran: Vec<&ProbeRun> = envelope
        .runs
        .iter()
        .filter(|r| r.ok && r.error.is_none() && r.fault.is_none())
        .collect();
    // Neither returned nor faulted: it hit the instruction or time budget. Not
    // interesting on its own, but the count is, because a binary where most
    // functions never return is a binary the emulator cannot help with.
    let stuck: Vec<&ProbeRun> = envelope
        .runs
        .iter()
        .filter(|r| !r.ok && r.error.is_none() && r.fault.is_none())
        .collect();
    let faults: Vec<&ProbeRun> = envelope.runs.iter().filter(|r| r.fault.is_some()).collect();
    let errors: Vec<&ProbeRun> = envelope.runs.iter().filter(|r| r.error.is_some()).collect();
    let non_zero: Vec<&ProbeRun> = ran
        .iter()
        .copied()
        .filter(|r| r.ret.as_ref().map(|v| v.i64 != 0).unwrap_or(false))
        .collect();

    let mut out = format!(
        "probe {} on {} / {} with arg {}: {} functions\n",
        spec,
        envelope.arch,
        envelope.platform,
        envelope.arg,
        envelope.runs.len()
    );
    out.push_str(&format!(
        "returned {}   non-zero {}   faults {}   never returned {}   did not start {}\n",
        ran.len(),
        non_zero.len(),
        faults.len(),
        stuck.len(),
        errors.len()
    ));
    if !non_zero.is_empty() {
        out.push_str(&format!("\nnon-zero returns ({}):\n", non_zero.len()));
        for run in non_zero.iter().take(limit) {
            let ret = run.ret.as_ref().expect("filtered on a return value");
            out.push_str(&format!("  {}  {}  {}\n", run.address, run.name, ret.hex));
        }
    }
    if !faults.is_empty() {
        out.push_str(&format!("\nfaults ({}):\n", faults.len()));
        for run in faults.iter().take(limit) {
            let fault = run.fault.as_ref().expect("filtered on a fault");
            out.push_str(&format!(
                "  {}  {}  {} at {:#x}\n",
                run.address, run.name, fault.access, fault.address
            ));
        }
    }
    if !stuck.is_empty() {
        out.push_str(&format!("\nnever returned ({}):\n", stuck.len()));
        for run in stuck.iter().take(12) {
            out.push_str(&format!("  {}  {}  {}\n", run.address, run.name, run.stop));
        }
    }
    if !errors.is_empty() {
        out.push_str(&format!("\ndid not start ({}):\n", errors.len()));
        for run in errors.iter().take(12) {
            out.push_str(&format!(
                "  {}  {}: {}\n",
                run.address,
                run.name,
                run.error.as_deref().unwrap_or("unknown")
            ));
        }
    }
    if non_zero.is_empty() {
        out.push_str(
            "\nnothing returned non-zero: try another arg, or take a name that looks \n\
             interesting and read it with `emulate` — the return value alone is only a hint\n",
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aes_sbox() {
        let dir = std::env::temp_dir().join("rekit-scan-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("crypto.bin");
        let mut data = vec![0u8; 32];
        data.extend_from_slice(&[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]);
        std::fs::write(&p, &data).unwrap();

        let hits = consts(&p.display().to_string(), 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "AES S-box");
        assert_eq!(hits[0].offset, 32);
    }
}
