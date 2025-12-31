//! Shared types for Sango analysis

use serde::{Deserialize, Serialize};

/// Issue severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational only
    Low,
    /// Should be fixed
    Medium,
    /// Important to fix
    High,
    /// Must be fixed immediately
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// A detected issue with severity and recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    /// Severity level
    pub severity: Severity,
    /// Category (e.g., "security", "seo", "performance")
    pub category: String,
    /// Issue description
    pub message: String,
    /// Optional recommendation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

impl Issue {
    /// Create a new issue
    pub fn new(
        severity: Severity,
        category: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category: category.into(),
            message: message.into(),
            recommendation: None,
        }
    }

    /// Add a recommendation
    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = Some(recommendation.into());
        self
    }
}

/// Format bytes as human-readable size
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;

    if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Extract domain from URL
pub fn extract_domain(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_lowercase()
}
