//! Text this repository did not expect to hold: a frontend bundle, a leaked
//! key, a token.
//!
//! The binary tools in `rekit-core` work on format structure — sections,
//! imports, symbols. A JavaScript bundle has none of that: the useful material
//! is buried in strings, and the questions are different. Where does the app
//! talk to? What secrets were committed by accident? What does this token
//! claim, and is its signature actually checked?
//!
//! All four tools take a file, a directory (walked recursively) or an
//! `archive::inner` spec, because the interesting bundle is usually inside an
//! APK or a zip.

pub mod browser;
pub mod cdp;
pub mod endpoints;
pub mod gather;
pub mod http;
pub mod jwt;
pub mod secrets;
pub mod ws;

pub use gather::{cap, gather, Gathered, Src};

/// Resolve an `archive::inner` spec to a real file, so the rest of the crate
/// only ever sees plain paths.
pub fn resolve_spec(spec: &str) -> anyhow::Result<std::path::PathBuf> {
    rekit_core::resolve::resolve(spec)
}

/// Where rekit keeps things it has to write: extracted archives, decompiled
/// sources, browser profiles.
pub fn cache_dir(name: &str) -> std::path::PathBuf {
    rekit_core::resolve::cache_root().join(name)
}

/// Look for an executable on PATH. `which` is a shell builtin on some systems
/// and missing on others, so the lookup is done here.
pub fn find_in_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
