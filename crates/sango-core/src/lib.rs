//! Sango Core - Shared analysis library for web endpoint diagnostics
//!
//! This crate contains pure analysis logic that can be shared between
//! the CLI (native) and WASM (browser) builds. All functions here work
//! on already-fetched content - no HTTP clients or platform-specific code.

pub mod types;
pub mod seo;
pub mod aeo;
pub mod techstack;
pub mod headers;
pub mod content;

pub use types::*;
pub use seo::{analyze_seo, SeoAnalysis};
pub use aeo::{analyze_aeo, AeoAnalysis};
pub use techstack::{analyze_techstack, TechStackAnalysis};
pub use headers::{analyze_headers, HeadersAnalysis};
pub use content::{analyze_content, ContentAnalysis};
