//! rekit-core — primitives for analyzing untrusted binaries.
//!
//! Everything here takes bytes from a file the user pointed at and must never
//! panic on malformed input: a hostile file is the normal case, not the edge
//! case. Parsing failures degrade to magic-byte detection instead of errors.

pub mod antidebug;
pub mod apktool;
pub mod asm;
pub mod axml;
pub mod decompilers;
pub mod diff;
pub mod dotnet;
pub mod emulate;
pub mod entropy;
pub mod external;
pub mod ghidra;
pub mod hexdump;
pub mod ida;
pub mod info;
pub mod javap;
pub mod patch;
pub mod resolve;
pub mod resources;
pub mod scan;
pub mod strings;
pub mod symbols;
pub mod util;

pub use info::{analyze, Info, Section};
pub use resolve::resolve;
pub use util::read_spec;

/// Version of the analysis surface, reported by the MCP server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
