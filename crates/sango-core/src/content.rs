//! Content analysis
//!
//! Analyzes response content type, size, and encoding.

use serde::{Deserialize, Serialize};

use crate::types::format_size;

/// Result of content analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContentAnalysis {
    /// Response size in bytes
    pub size_bytes: u64,
    /// Human-readable size
    pub size_formatted: String,
    /// Detected MIME type
    pub mime_type: Option<String>,
    /// Character encoding
    pub charset: Option<String>,
    /// Whether compression was used
    pub is_compressed: bool,
    /// Compression algorithm
    pub compression: Option<String>,
}

/// Content information for analysis
#[derive(Debug, Clone, Default)]
pub struct ContentInfo {
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content-Encoding header
    pub content_encoding: Option<String>,
    /// Content-Length header
    pub content_length: Option<u64>,
    /// Actual body size
    pub body_size: u64,
}

/// Analyze content from response information
pub fn analyze_content(info: ContentInfo) -> ContentAnalysis {
    let size_bytes = info.body_size;
    let size_formatted = format_size(size_bytes);

    let (mime_type, charset) = parse_content_type(info.content_type.as_deref());
    let (is_compressed, compression) = parse_content_encoding(info.content_encoding.as_deref());

    ContentAnalysis {
        size_bytes,
        size_formatted,
        mime_type,
        charset,
        is_compressed,
        compression,
    }
}

fn parse_content_type(content_type: Option<&str>) -> (Option<String>, Option<String>) {
    let ct = match content_type {
        Some(ct) => ct,
        None => return (None, None),
    };

    let mut parts = ct.split(';');
    let mime_type = parts.next().map(|s| s.trim().to_string());

    let charset = parts.find_map(|part| {
        let part = part.trim().to_lowercase();
        part.strip_prefix("charset=")
            .map(|s| s.trim_matches('"').to_string())
    });

    (mime_type, charset)
}

fn parse_content_encoding(encoding: Option<&str>) -> (bool, Option<String>) {
    match encoding {
        Some(enc) if !enc.is_empty() && enc.to_lowercase() != "identity" => {
            (true, Some(enc.to_string()))
        }
        _ => (false, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_parsing() {
        let (mime, charset) = parse_content_type(Some("text/html; charset=utf-8"));
        assert_eq!(mime, Some("text/html".to_string()));
        assert_eq!(charset, Some("utf-8".to_string()));
    }

    #[test]
    fn test_compression_detection() {
        let (compressed, algo) = parse_content_encoding(Some("gzip"));
        assert!(compressed);
        assert_eq!(algo, Some("gzip".to_string()));
    }

    #[test]
    fn test_size_formatting() {
        let info = ContentInfo {
            body_size: 1536,
            ..Default::default()
        };
        let result = analyze_content(info);
        assert!(result.size_formatted.contains("KB"));
    }
}
