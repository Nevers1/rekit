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

pub mod endpoints;
pub mod gather;
pub mod http;
pub mod jwt;
pub mod secrets;

pub use gather::{cap, gather, Gathered, Src};

/// Resolve an `archive::inner` spec to a real file, so the rest of the crate
/// only ever sees plain paths.
pub fn resolve_spec(spec: &str) -> anyhow::Result<std::path::PathBuf> {
    rekit_core::resolve::resolve(spec)
}
