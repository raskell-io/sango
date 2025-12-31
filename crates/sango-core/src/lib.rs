//! Sango Core - Shared analysis library for web endpoint diagnostics
//!
//! This crate contains pure analysis logic that can be shared between
//! the CLI (native) and WASM (browser) builds. All functions here work
//! on already-fetched content - no HTTP clients or platform-specific code.

pub mod aeo;
pub mod content;
pub mod headers;
pub mod seo;
pub mod techstack;
pub mod types;

pub use aeo::{analyze_aeo, AeoAnalysis};
pub use content::{analyze_content, ContentAnalysis};
pub use headers::{analyze_headers, HeadersAnalysis};
pub use seo::{analyze_seo, SeoAnalysis};
pub use techstack::{analyze_techstack, TechStackAnalysis};
pub use types::*;
