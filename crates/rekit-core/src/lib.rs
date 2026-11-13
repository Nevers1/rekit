//! rekit-core — primitives for analyzing untrusted binaries.
//!
//! Everything here takes bytes from a file the user pointed at and must never
//! panic on malformed input: a hostile file is the normal case, not the edge
//! case. Parsing failures degrade to magic-byte detection instead of errors.

pub mod antidebug;
pub mod axml;
pub mod entropy;
pub mod external;
pub mod hexdump;
pub mod info;
pub mod patch;
pub mod resolve;
pub mod scan;
pub mod strings;
pub mod symbols;
pub mod util;

pub use info::{analyze, Info, Section};
pub use resolve::resolve;
pub use util::read_spec;

/// Version of the analysis surface, reported by the MCP server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
