use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

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

pub fn apis(spec: &str) -> Result<BTreeMap<&'static str, Vec<String>>> {
    let names = import_names(spec)?;
    let mut out: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for name in &names {
        for (kind, needles) in KINDS {
            if needles.iter().any(|n| name.contains(n)) {
                let bucket = out.entry(kind).or_default();
                if bucket.len() < 200 && !bucket.contains(name) {
                    bucket.push(name.clone());
                }
            }
        }
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
