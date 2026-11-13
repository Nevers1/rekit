use anyhow::Result;
use serde::Serialize;

use crate::entropy::contains_ci;
use crate::symbols::import_names;
use crate::util::read_spec;

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub kind: &'static str,
    pub value: String,
    pub why: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub score: u32,
    pub verdict: String,
    pub signals: Vec<Signal>,
}

/// Imports that a normal application has no reason to call.
const API_MARKERS: &[(&str, &str)] = &[
    ("ptrace", "traces or is traced by another process"),
    (
        "IsDebuggerPresent",
        "asks Windows whether a debugger is attached",
    ),
    ("CheckRemoteDebuggerPresent", "checks for a remote debugger"),
    (
        "NtQueryInformationProcess",
        "query process info, classic anti-debug",
    ),
    (
        "ZwQueryInformationProcess",
        "query process info, classic anti-debug",
    ),
    (
        "OutputDebugString",
        "detects a debugger by the exception it raises",
    ),
    (
        "GetTickCount",
        "measures elapsed time, detects single stepping",
    ),
    (
        "QueryPerformanceCounter",
        "high resolution timing, detects breakpoints",
    ),
    ("sysctl", "reads process flags on macOS/iOS"),
    (
        "__system_property_get",
        "reads ro.debuggable / ro.secure on Android",
    ),
    (
        "dl_iterate_phdr",
        "enumerates loaded modules, looks for frida/xposed",
    ),
    ("prctl", "PR_SET_DUMPABLE tricks"),
    ("inotify_init", "watches its own files for tampering"),
    ("getrandom", "may be used for anti-emulation entropy checks"),
];

const STRING_MARKERS: &[(&str, &str)] = &[
    ("TracerPid", "reads /proc/self/status to spot a tracer"),
    ("/proc/self/status", "process status introspection"),
    (
        "/proc/self/maps",
        "module list check, looks for injected libraries",
    ),
    ("frida", "Frida instrumentation framework"),
    ("gum-js-loop", "Frida runtime thread"),
    ("gadget", "Frida gadget injection"),
    ("xposed", "Xposed framework"),
    ("substrate", "Cydia Substrate"),
    ("magisk", "Magisk root"),
    ("goldfish", "Android emulator"),
    ("ranchu", "Android emulator"),
    ("qemud", "Android emulator socket"),
    ("ro.debuggable", "Android debug flag"),
    ("ro.secure", "Android security flag"),
    ("test-keys", "Android test build detection"),
    ("LD_PRELOAD", "preload based hooking"),
    ("IsDebuggerPresent", "debugger check by name"),
    ("SeDebugPrivilege", "asks for debug privilege"),
];

pub fn scan(spec: &str) -> Result<Report> {
    let (_, data) = read_spec(spec)?;
    let mut signals = Vec::new();

    let imports = import_names(spec).unwrap_or_default();
    for (marker, why) in API_MARKERS {
        if let Some(hit) = imports.iter().find(|name| name.contains(marker)) {
            signals.push(Signal {
                kind: "import",
                value: hit.clone(),
                why,
            });
        }
    }

    for (marker, why) in STRING_MARKERS {
        if contains_ci(&data, marker) {
            signals.push(Signal {
                kind: "string",
                value: marker.to_string(),
                why,
            });
        }
    }

    let imports_hit = signals.iter().filter(|s| s.kind == "import").count() as u32;
    let strings_hit = signals.iter().filter(|s| s.kind == "string").count() as u32;
    let score = (imports_hit * 12 + strings_hit * 8).min(100);
    let verdict = match score {
        0 => "no anti-debug or anti-tamper signals",
        1..=24 => "light: single isolated check",
        25..=59 => "medium: several checks, expect resistance",
        _ => "heavy: packed or heavily instrumented binary",
    };

    Ok(Report {
        score,
        verdict: verdict.to_string(),
        signals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_are_found_in_text() {
        let dir = std::env::temp_dir().join("rekit-ad-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("probe.bin");
        std::fs::write(&p, b"....TracerPid....frida..../proc/self/maps....").unwrap();

        let report = scan(&p.display().to_string()).unwrap();
        assert!(report.score >= 24);
        assert!(report.signals.iter().any(|s| s.value == "TracerPid"));
        assert_eq!(report.signals.len(), 3);
    }

    #[test]
    fn clean_binary_is_clean() {
        let dir = std::env::temp_dir().join("rekit-ad-test");
        let p = dir.join("clean.bin");
        std::fs::write(&p, b"just some ordinary payload bytes here").unwrap();
        let report = scan(&p.display().to_string()).unwrap();
        assert_eq!(report.score, 0);
    }
}
