//! AEO (AI Engine Optimization) analysis
//!
//! Analyzes content for AI/LLM readability and structured data depth.

use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};

use crate::types::{Issue, Severity};

/// Result of AEO analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeoAnalysis {
    /// AEO score (0-100)
    pub score: u8,
    /// Readiness level (Poor, Basic, Good, Excellent)
    pub readiness: String,
    /// Number of JSON-LD blocks
    pub json_ld_count: usize,
    /// Schema.org types found
    pub schema_types: Vec<String>,
    /// Has llms.txt file (must be checked separately via HTTP)
    pub has_llms_txt: bool,
    /// Text-to-HTML ratio (0.0 to 1.0)
    pub text_ratio: f32,
    /// Semantic HTML score (0-100)
    pub semantic_score: u8,
    /// Word count
    pub word_count: usize,
    /// Detected issues
    pub issues: Vec<Issue>,
}

/// Configuration for AEO analysis
#[derive(Debug, Clone, Default)]
pub struct AeoConfig {
    /// Whether llms.txt was found (checked externally)
    pub has_llms_txt: bool,
}

/// Analyze AEO signals from HTML content
pub fn analyze_aeo(html: &str, config: AeoConfig) -> AeoAnalysis {
    let document = Html::parse_document(html);

    let json_ld_blocks = extract_json_ld_blocks(&document);
    let json_ld_count = json_ld_blocks.len();
    let schema_types = extract_schema_types(&json_ld_blocks);
    let text_ratio = calculate_text_ratio(html, &document);
    let semantic_score = calculate_semantic_score(&document);
    let word_count = count_words(&document);

    // Calculate score
    let mut score: u8 = 0;
    if json_ld_count > 0 {
        score += 25;
    }
    if !schema_types.is_empty() {
        score += 15;
    }
    if config.has_llms_txt {
        score += 10;
    }
    if text_ratio > 0.15 {
        score += 15;
    } else if text_ratio > 0.05 {
        score += 10;
    }
    if semantic_score >= 70 {
        score += 20;
    } else if semantic_score >= 50 {
        score += 10;
    }
    if word_count > 300 {
        score += 15;
    } else if word_count > 100 {
        score += 10;
    }

    let readiness = match score {
        80..=100 => "Excellent",
        60..=79 => "Good",
        40..=59 => "Basic",
        _ => "Poor",
    }
    .to_string();

    let issues = generate_issues(
        json_ld_count,
        text_ratio,
        semantic_score,
        word_count,
        config.has_llms_txt,
    );

    AeoAnalysis {
        score,
        readiness,
        json_ld_count,
        schema_types,
        has_llms_txt: config.has_llms_txt,
        text_ratio,
        semantic_score,
        word_count,
        issues,
    }
}

fn extract_json_ld_blocks(document: &Html) -> Vec<String> {
    Selector::parse("script[type='application/ld+json']")
        .map(|sel| {
            document
                .select(&sel)
                .map(|el| el.text().collect::<String>())
                .collect()
        })
        .unwrap_or_default()
}

fn extract_schema_types(blocks: &[String]) -> Vec<String> {
    let mut types = Vec::new();
    for block in blocks {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(block) {
            extract_types_from_json(&json, &mut types);
        }
    }
    types.sort();
    types.dedup();
    types
}

fn extract_types_from_json(value: &serde_json::Value, types: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(t) = map.get("@type") {
                match t {
                    serde_json::Value::String(s) => types.push(s.clone()),
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            if let serde_json::Value::String(s) = item {
                                types.push(s.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
            for v in map.values() {
                extract_types_from_json(v, types);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_types_from_json(item, types);
            }
        }
        _ => {}
    }
}

fn calculate_text_ratio(html: &str, document: &Html) -> f32 {
    let total_len = html.len() as f32;
    if total_len == 0.0 {
        return 0.0;
    }

    let text_len: usize = document.root_element().text().map(|t| t.trim().len()).sum();

    text_len as f32 / total_len
}

fn calculate_semantic_score(document: &Html) -> u8 {
    let mut score: u8 = 0;

    let semantic_elements = [
        ("main", 15),
        ("article", 15),
        ("header", 10),
        ("nav", 10),
        ("footer", 10),
        ("section", 10),
        ("aside", 5),
        ("figure", 5),
        ("figcaption", 5),
    ];

    for (element, points) in semantic_elements {
        if let Ok(selector) = Selector::parse(element) {
            if document.select(&selector).next().is_some() {
                score = score.saturating_add(points);
            }
        }
    }

    score.min(100)
}

fn count_words(document: &Html) -> usize {
    document
        .root_element()
        .text()
        .flat_map(|t| t.split_whitespace())
        .count()
}

fn generate_issues(
    json_ld_count: usize,
    text_ratio: f32,
    semantic_score: u8,
    word_count: usize,
    has_llms_txt: bool,
) -> Vec<Issue> {
    let mut issues = Vec::new();

    if json_ld_count == 0 {
        issues.push(
            Issue::new(
                Severity::Medium,
                "aeo",
                "No JSON-LD structured data for AI understanding",
            )
            .with_recommendation("Add Schema.org JSON-LD for better AI comprehension"),
        );
    }

    if text_ratio < 0.1 {
        issues.push(
            Issue::new(
                Severity::Low,
                "aeo",
                format!("Low text-to-HTML ratio ({:.1}%)", text_ratio * 100.0),
            )
            .with_recommendation("Increase meaningful text content relative to markup"),
        );
    }

    if semantic_score < 50 {
        issues.push(
            Issue::new(
                Severity::Low,
                "aeo",
                format!("Low semantic HTML usage ({}%)", semantic_score),
            )
            .with_recommendation("Use semantic elements (article, section, nav, etc.)"),
        );
    }

    if word_count < 100 {
        issues.push(
            Issue::new(
                Severity::Low,
                "aeo",
                format!("Low word count ({} words)", word_count),
            )
            .with_recommendation("Consider adding more substantive content"),
        );
    }

    if !has_llms_txt {
        issues.push(
            Issue::new(Severity::Low, "aeo", "No llms.txt file found")
                .with_recommendation("Consider adding /llms.txt for AI agent instructions"),
        );
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_ld_extraction() {
        let html = r#"
            <html><head>
                <script type="application/ld+json">{"@type": "Organization", "name": "Test"}</script>
            </head></html>
        "#;
        let result = analyze_aeo(html, AeoConfig::default());
        assert_eq!(result.json_ld_count, 1);
        assert!(result.schema_types.contains(&"Organization".to_string()));
    }

    #[test]
    fn test_semantic_score() {
        let html = r#"
            <html><body>
                <header>Header</header>
                <main><article>Content</article></main>
                <footer>Footer</footer>
            </body></html>
        "#;
        let result = analyze_aeo(html, AeoConfig::default());
        assert!(result.semantic_score >= 40);
    }
}
