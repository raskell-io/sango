//! AEO (AI Engine Optimization) analysis
//!
//! Evaluates how well an endpoint is optimized for AI agents and LLM-powered search.
//!
//! - Structured data analysis (JSON-LD, Schema.org)
//! - AI-readiness signals (llms.txt, ai-plugin.json)
//! - Content accessibility for AI extraction
//! - API discoverability (OpenAPI, GraphQL)

use anyhow::{Context, Result};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::Serialize;
use std::time::Duration;

use super::tls::Severity;

/// Result of AEO analysis
#[derive(Debug, Serialize)]
pub struct AeoResult {
    /// Structured data analysis
    pub structured_data: StructuredDataAnalysis,
    /// AI-specific endpoints and files
    pub ai_endpoints: AiEndpoints,
    /// Content structure for AI extraction
    pub content_structure: ContentStructure,
    /// API discoverability
    pub api_discovery: ApiDiscovery,
    /// AEO readiness score (0-100)
    pub score: u8,
    /// AEO readiness level
    pub readiness: AeoReadiness,
    /// Detected issues
    pub issues: Vec<AeoIssue>,
}

/// AEO readiness level
#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum AeoReadiness {
    /// Excellent - optimized for AI agents
    Excellent,
    /// Good - most AI-friendly features present
    Good,
    /// Basic - minimal AI support
    Basic,
    /// Poor - not optimized for AI
    Poor,
}

impl std::fmt::Display for AeoReadiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeoReadiness::Excellent => write!(f, "Excellent"),
            AeoReadiness::Good => write!(f, "Good"),
            AeoReadiness::Basic => write!(f, "Basic"),
            AeoReadiness::Poor => write!(f, "Poor"),
        }
    }
}

/// Structured data analysis
#[derive(Debug, Serialize, Clone, Default)]
pub struct StructuredDataAnalysis {
    /// JSON-LD blocks found
    pub json_ld_blocks: Vec<JsonLdBlock>,
    /// Total Schema.org types found
    pub schema_types: Vec<String>,
    /// Has Organization schema
    pub has_organization: bool,
    /// Has WebSite schema
    pub has_website: bool,
    /// Has WebPage schema
    pub has_webpage: bool,
    /// Has Article/BlogPosting schema
    pub has_article: bool,
    /// Has Product schema
    pub has_product: bool,
    /// Has FAQPage schema
    pub has_faq: bool,
    /// Has BreadcrumbList schema
    pub has_breadcrumb: bool,
    /// Has HowTo schema
    pub has_howto: bool,
    /// Rich snippet eligibility
    pub rich_snippet_eligible: bool,
    /// Validation issues with structured data
    pub validation_issues: Vec<String>,
}

/// A single JSON-LD block
#[derive(Debug, Serialize, Clone)]
pub struct JsonLdBlock {
    /// The @type value(s)
    pub types: Vec<String>,
    /// Whether it has @context
    pub has_context: bool,
    /// Whether the JSON is valid
    pub is_valid_json: bool,
    /// Key properties found
    pub properties: Vec<String>,
    /// Raw content preview (first 200 chars)
    pub preview: String,
}

/// AI-specific endpoints
#[derive(Debug, Serialize, Clone, Default)]
pub struct AiEndpoints {
    /// llms.txt file info
    pub llms_txt: Option<LlmsTxtInfo>,
    /// llms-full.txt file info
    pub llms_full_txt: Option<LlmsTxtInfo>,
    /// ChatGPT plugin manifest
    pub ai_plugin: Option<AiPluginInfo>,
    /// .well-known/ai-plugin.json
    pub well_known_ai_plugin: Option<AiPluginInfo>,
    /// robots.txt AI-specific rules
    pub robots_ai_rules: Option<RobotsAiRules>,
}

/// llms.txt file information
#[derive(Debug, Serialize, Clone)]
pub struct LlmsTxtInfo {
    /// Whether the file exists
    pub exists: bool,
    /// HTTP status code
    pub status_code: u16,
    /// Content length
    pub content_length: usize,
    /// Title/name if found
    pub title: Option<String>,
    /// Description if found
    pub description: Option<String>,
    /// Number of sections
    pub section_count: usize,
    /// URLs/links found
    pub link_count: usize,
    /// Sample content (first 500 chars)
    pub preview: String,
}

/// AI plugin manifest information
#[derive(Debug, Serialize, Clone)]
pub struct AiPluginInfo {
    /// Whether the manifest exists
    pub exists: bool,
    /// HTTP status code
    pub status_code: u16,
    /// Plugin name
    pub name: Option<String>,
    /// Plugin description
    pub description: Option<String>,
    /// Has auth configuration
    pub has_auth: bool,
    /// API type (openapi, etc.)
    pub api_type: Option<String>,
    /// API URL
    pub api_url: Option<String>,
    /// Is valid JSON
    pub is_valid: bool,
}

/// robots.txt AI-specific rules
#[derive(Debug, Serialize, Clone)]
pub struct RobotsAiRules {
    /// User-agents that mention AI/GPT/Claude/etc.
    pub ai_user_agents: Vec<String>,
    /// Whether AI bots are blocked
    pub blocks_ai_bots: bool,
    /// Whether AI bots are explicitly allowed
    pub allows_ai_bots: bool,
    /// Specific rules found
    pub rules: Vec<String>,
}

/// Content structure analysis
#[derive(Debug, Serialize, Clone, Default)]
pub struct ContentStructure {
    /// Text to HTML ratio (0.0 - 1.0)
    pub text_ratio: f32,
    /// Whether content is easily extractable
    pub is_extractable: bool,
    /// Main content element found (article, main, etc.)
    pub has_main_content: bool,
    /// Semantic HTML usage score (0-100)
    pub semantic_score: u8,
    /// Uses article element
    pub has_article: bool,
    /// Uses section elements
    pub has_sections: bool,
    /// Uses nav element
    pub has_nav: bool,
    /// Uses aside element
    pub has_aside: bool,
    /// Uses header/footer
    pub has_header_footer: bool,
    /// Uses figure/figcaption
    pub has_figures: bool,
    /// Code blocks found
    pub code_block_count: usize,
    /// Tables found
    pub table_count: usize,
    /// Lists found (ul/ol)
    pub list_count: usize,
    /// Word count estimate
    pub word_count: usize,
    /// Reading time estimate (minutes)
    pub reading_time_minutes: u8,
}

/// API discoverability
#[derive(Debug, Serialize, Clone, Default)]
pub struct ApiDiscovery {
    /// OpenAPI/Swagger documentation
    pub openapi: Option<OpenApiInfo>,
    /// GraphQL endpoint
    pub graphql: Option<GraphQLInfo>,
    /// API documentation link
    pub docs_url: Option<String>,
    /// Developer portal link
    pub developer_url: Option<String>,
}

/// OpenAPI information
#[derive(Debug, Serialize, Clone)]
pub struct OpenApiInfo {
    /// Endpoint URL
    pub url: String,
    /// HTTP status
    pub status_code: u16,
    /// OpenAPI version
    pub version: Option<String>,
    /// API title
    pub title: Option<String>,
    /// Is valid spec
    pub is_valid: bool,
}

/// GraphQL information
#[derive(Debug, Serialize, Clone)]
pub struct GraphQLInfo {
    /// Endpoint URL
    pub url: String,
    /// HTTP status
    pub status_code: u16,
    /// Introspection enabled
    pub introspection_enabled: bool,
    /// GraphiQL/Playground available
    pub has_playground: bool,
}

/// An AEO issue
#[derive(Debug, Serialize, Clone)]
pub struct AeoIssue {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub recommendation: Option<String>,
}

/// Common AI bot user agents
const AI_BOT_AGENTS: &[&str] = &[
    "GPTBot",
    "ChatGPT-User",
    "Google-Extended",
    "CCBot",
    "anthropic-ai",
    "Claude-Web",
    "Bytespider",
    "Diffbot",
    "FacebookBot",
    "PerplexityBot",
    "YouBot",
];

/// Check AEO
pub async fn check_aeo(target: &str, timeout: Duration) -> Result<AeoResult> {
    let base_url = normalize_url(target);

    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("Failed to build HTTP client")?;

    // Fetch main page for content analysis
    let response = client
        .get(&base_url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (compatible; Sango/1.0; +https://github.com/raskell-io/sango)",
        )
        .send()
        .await
        .context(format!("Failed to fetch {}", base_url))?;

    let body = response.text().await.unwrap_or_default();
    let document = Html::parse_document(&body);

    // Analyze structured data
    let structured_data = analyze_structured_data(&document, &body);

    // Check AI-specific endpoints
    let ai_endpoints = check_ai_endpoints(&client, &base_url).await;

    // Analyze content structure
    let content_structure = analyze_content_structure(&document, &body);

    // Check API discoverability
    let api_discovery = check_api_discovery(&client, &base_url, &document).await;

    // Generate issues
    let issues = generate_issues(
        &structured_data,
        &ai_endpoints,
        &content_structure,
        &api_discovery,
    );

    // Calculate score
    let score = calculate_score(
        &structured_data,
        &ai_endpoints,
        &content_structure,
        &api_discovery,
    );

    // Determine readiness level
    let readiness = determine_readiness(score);

    Ok(AeoResult {
        structured_data,
        ai_endpoints,
        content_structure,
        api_discovery,
        score,
        readiness,
        issues,
    })
}

/// Normalize target to base URL
fn normalize_url(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Analyze structured data in detail
fn analyze_structured_data(document: &Html, _body: &str) -> StructuredDataAnalysis {
    let mut analysis = StructuredDataAnalysis::default();

    // Find all JSON-LD blocks
    if let Ok(selector) = Selector::parse("script[type='application/ld+json']") {
        for element in document.select(&selector) {
            let content = element.text().collect::<String>();
            let block = parse_json_ld(&content);

            // Track schema types
            for t in &block.types {
                if !analysis.schema_types.contains(t) {
                    analysis.schema_types.push(t.clone());
                }

                // Check for specific types
                let t_lower = t.to_lowercase();
                if t_lower.contains("organization") {
                    analysis.has_organization = true;
                }
                if t_lower.contains("website") {
                    analysis.has_website = true;
                }
                if t_lower.contains("webpage") {
                    analysis.has_webpage = true;
                }
                if t_lower.contains("article")
                    || t_lower.contains("blogposting")
                    || t_lower.contains("newsarticle")
                {
                    analysis.has_article = true;
                }
                if t_lower.contains("product") {
                    analysis.has_product = true;
                }
                if t_lower.contains("faqpage") {
                    analysis.has_faq = true;
                }
                if t_lower.contains("breadcrumb") {
                    analysis.has_breadcrumb = true;
                }
                if t_lower.contains("howto") {
                    analysis.has_howto = true;
                }
            }

            analysis.json_ld_blocks.push(block);
        }
    }

    // Check for rich snippet eligibility
    analysis.rich_snippet_eligible = analysis.has_faq
        || analysis.has_howto
        || analysis.has_product
        || analysis.has_article
        || analysis.has_breadcrumb;

    // Validate structured data
    if analysis.json_ld_blocks.is_empty() {
        analysis
            .validation_issues
            .push("No JSON-LD structured data found".to_string());
    } else {
        for (i, block) in analysis.json_ld_blocks.iter().enumerate() {
            if !block.is_valid_json {
                analysis
                    .validation_issues
                    .push(format!("JSON-LD block {} has invalid JSON", i + 1));
            }
            if !block.has_context {
                analysis
                    .validation_issues
                    .push(format!("JSON-LD block {} missing @context", i + 1));
            }
        }
    }

    analysis
}

/// Parse a single JSON-LD block
fn parse_json_ld(content: &str) -> JsonLdBlock {
    let trimmed = content.trim();

    // Check if valid JSON
    let is_valid_json = serde_json::from_str::<serde_json::Value>(trimmed).is_ok();

    // Extract @type values
    let mut types = Vec::new();
    extract_json_values(trimmed, "@type", &mut types);

    // Check for @context
    let has_context = trimmed.contains("\"@context\"") || trimmed.contains("'@context'");

    // Extract key properties
    let mut properties = Vec::new();
    for prop in [
        "name",
        "description",
        "url",
        "image",
        "author",
        "datePublished",
        "mainEntity",
    ] {
        if trimmed.contains(&format!("\"{}\"", prop)) {
            properties.push(prop.to_string());
        }
    }

    // Create preview
    let preview = if trimmed.len() > 200 {
        format!("{}...", &trimmed[..200])
    } else {
        trimmed.to_string()
    };

    JsonLdBlock {
        types,
        has_context,
        is_valid_json,
        properties,
        preview,
    }
}

/// Extract values for a specific JSON key
fn extract_json_values(content: &str, key: &str, values: &mut Vec<String>) {
    let search_key = format!("\"{}\"", key);
    let mut search_start = 0;

    while let Some(key_pos) = content[search_start..].find(&search_key) {
        let abs_pos = search_start + key_pos + search_key.len();
        if abs_pos >= content.len() {
            break;
        }

        let after = &content[abs_pos..];
        // Skip whitespace and colon
        let value_start = after.find(':').map(|p| p + 1).unwrap_or(0);
        if value_start >= after.len() {
            break;
        }

        let value_content = after[value_start..].trim_start();

        // Extract the value
        if value_content.starts_with('"') {
            // String value
            if let Some(end) = value_content[1..].find('"') {
                let value = &value_content[1..end + 1];
                if !values.contains(&value.to_string()) {
                    values.push(value.to_string());
                }
            }
        } else if value_content.starts_with('[') {
            // Array - extract string values
            if let Some(end) = value_content.find(']') {
                let array_content = &value_content[1..end];
                for part in array_content.split(',') {
                    let part = part.trim().trim_matches('"');
                    if !part.is_empty() && !values.contains(&part.to_string()) {
                        values.push(part.to_string());
                    }
                }
            }
        }

        search_start = abs_pos;
    }
}

/// Check AI-specific endpoints
async fn check_ai_endpoints(client: &Client, base_url: &str) -> AiEndpoints {
    let mut endpoints = AiEndpoints::default();

    // Check llms.txt
    endpoints.llms_txt = check_llms_txt(client, &format!("{}/llms.txt", base_url)).await;

    // Check llms-full.txt
    endpoints.llms_full_txt = check_llms_txt(client, &format!("{}/llms-full.txt", base_url)).await;

    // Check ai-plugin.json
    endpoints.ai_plugin =
        check_ai_plugin(client, &format!("{}/.well-known/ai-plugin.json", base_url)).await;

    // Check robots.txt for AI rules
    endpoints.robots_ai_rules =
        check_robots_ai_rules(client, &format!("{}/robots.txt", base_url)).await;

    endpoints
}

/// Check llms.txt file
async fn check_llms_txt(client: &Client, url: &str) -> Option<LlmsTxtInfo> {
    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status_code = response.status().as_u16();

    if !response.status().is_success() {
        return Some(LlmsTxtInfo {
            exists: false,
            status_code,
            content_length: 0,
            title: None,
            description: None,
            section_count: 0,
            link_count: 0,
            preview: String::new(),
        });
    }

    let content = match response.text().await {
        Ok(t) => t,
        Err(_) => return None,
    };

    let content_length = content.len();

    // Parse llms.txt format
    // Format: # Title, > Description, ## Sections, - Links
    let mut title = None;
    let mut description = None;
    let mut section_count = 0;
    let mut link_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# ") && title.is_none() {
            title = Some(trimmed[2..].to_string());
        } else if trimmed.starts_with("> ") && description.is_none() {
            description = Some(trimmed[2..].to_string());
        } else if trimmed.starts_with("## ") {
            section_count += 1;
        } else if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            if trimmed.contains("http://") || trimmed.contains("https://") || trimmed.contains("](")
            {
                link_count += 1;
            }
        }
    }

    let preview = if content.len() > 500 {
        format!("{}...", &content[..500])
    } else {
        content.clone()
    };

    Some(LlmsTxtInfo {
        exists: true,
        status_code,
        content_length,
        title,
        description,
        section_count,
        link_count,
        preview,
    })
}

/// Check ai-plugin.json
async fn check_ai_plugin(client: &Client, url: &str) -> Option<AiPluginInfo> {
    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status_code = response.status().as_u16();

    if !response.status().is_success() {
        return Some(AiPluginInfo {
            exists: false,
            status_code,
            name: None,
            description: None,
            has_auth: false,
            api_type: None,
            api_url: None,
            is_valid: false,
        });
    }

    let content = match response.text().await {
        Ok(t) => t,
        Err(_) => return None,
    };

    // Parse JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);

    match parsed {
        Ok(json) => Some(AiPluginInfo {
            exists: true,
            status_code,
            name: json
                .get("name_for_human")
                .or_else(|| json.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            description: json
                .get("description_for_human")
                .or_else(|| json.get("description"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            has_auth: json.get("auth").is_some(),
            api_type: json
                .get("api")
                .and_then(|api| api.get("type"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            api_url: json
                .get("api")
                .and_then(|api| api.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            is_valid: true,
        }),
        Err(_) => Some(AiPluginInfo {
            exists: true,
            status_code,
            name: None,
            description: None,
            has_auth: false,
            api_type: None,
            api_url: None,
            is_valid: false,
        }),
    }
}

/// Check robots.txt for AI-specific rules
async fn check_robots_ai_rules(client: &Client, url: &str) -> Option<RobotsAiRules> {
    let response = match client.get(url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return None,
    };

    let content = match response.text().await {
        Ok(t) => t,
        Err(_) => return None,
    };

    let mut rules = RobotsAiRules {
        ai_user_agents: Vec::new(),
        blocks_ai_bots: false,
        allows_ai_bots: false,
        rules: Vec::new(),
    };

    let mut current_agent: Option<String> = None;
    let mut is_ai_agent = false;

    for line in content.lines() {
        let trimmed = line.trim().to_lowercase();

        if trimmed.starts_with("user-agent:") {
            let agent = trimmed[11..].trim().to_string();

            // Check if this is an AI-related agent
            is_ai_agent = AI_BOT_AGENTS
                .iter()
                .any(|bot| agent.contains(&bot.to_lowercase()));

            if is_ai_agent {
                rules.ai_user_agents.push(agent.clone());
            }
            current_agent = Some(agent);
        } else if is_ai_agent && current_agent.is_some() {
            if trimmed.starts_with("disallow:") {
                let path = trimmed[9..].trim();
                if path == "/" || path.is_empty() {
                    rules.blocks_ai_bots = true;
                }
                rules.rules.push(format!(
                    "{}: Disallow: {}",
                    current_agent.as_ref().unwrap(),
                    path
                ));
            } else if trimmed.starts_with("allow:") {
                rules.allows_ai_bots = true;
                let path = trimmed[6..].trim();
                rules.rules.push(format!(
                    "{}: Allow: {}",
                    current_agent.as_ref().unwrap(),
                    path
                ));
            }
        }
    }

    if rules.ai_user_agents.is_empty() && rules.rules.is_empty() {
        None
    } else {
        Some(rules)
    }
}

/// Analyze content structure for AI extraction
fn analyze_content_structure(document: &Html, body: &str) -> ContentStructure {
    let mut structure = ContentStructure::default();

    // Calculate text ratio
    let text_content = extract_text_content(document);
    let text_len = text_content.len() as f32;
    let html_len = body.len() as f32;
    structure.text_ratio = if html_len > 0.0 {
        text_len / html_len
    } else {
        0.0
    };

    // Word count and reading time
    structure.word_count = text_content.split_whitespace().count();
    structure.reading_time_minutes = ((structure.word_count as f32 / 200.0).ceil() as u8).max(1);

    // Check for semantic elements
    structure.has_main_content =
        check_element_exists(document, "main") || check_element_exists(document, "article");
    structure.has_article = check_element_exists(document, "article");
    structure.has_sections = check_element_exists(document, "section");
    structure.has_nav = check_element_exists(document, "nav");
    structure.has_aside = check_element_exists(document, "aside");
    structure.has_header_footer =
        check_element_exists(document, "header") && check_element_exists(document, "footer");
    structure.has_figures = check_element_exists(document, "figure");

    // Count content elements
    structure.code_block_count = count_elements(document, "pre, code");
    structure.table_count = count_elements(document, "table");
    structure.list_count = count_elements(document, "ul, ol");

    // Calculate semantic score
    structure.semantic_score = calculate_semantic_score(&structure);

    // Determine if content is easily extractable
    structure.is_extractable =
        structure.text_ratio > 0.1 && structure.has_main_content && structure.word_count > 50;

    structure
}

/// Extract text content from document
fn extract_text_content(document: &Html) -> String {
    // Try to get main content first
    let selectors = ["main", "article", "body"];

    for sel in selectors {
        if let Ok(selector) = Selector::parse(sel) {
            if let Some(element) = document.select(&selector).next() {
                return element.text().collect::<Vec<_>>().join(" ");
            }
        }
    }

    String::new()
}

/// Check if an element exists
fn check_element_exists(document: &Html, selector_str: &str) -> bool {
    if let Ok(selector) = Selector::parse(selector_str) {
        document.select(&selector).next().is_some()
    } else {
        false
    }
}

/// Count elements matching a selector
fn count_elements(document: &Html, selector_str: &str) -> usize {
    if let Ok(selector) = Selector::parse(selector_str) {
        document.select(&selector).count()
    } else {
        0
    }
}

/// Calculate semantic HTML score
fn calculate_semantic_score(structure: &ContentStructure) -> u8 {
    let mut score = 0u8;

    if structure.has_main_content {
        score += 20;
    }
    if structure.has_article {
        score += 15;
    }
    if structure.has_sections {
        score += 15;
    }
    if structure.has_nav {
        score += 10;
    }
    if structure.has_header_footer {
        score += 15;
    }
    if structure.has_aside {
        score += 5;
    }
    if structure.has_figures {
        score += 10;
    }
    if structure.text_ratio > 0.15 {
        score += 10;
    }

    score.min(100)
}

/// Check API discoverability
async fn check_api_discovery(client: &Client, base_url: &str, document: &Html) -> ApiDiscovery {
    let mut discovery = ApiDiscovery::default();

    // Check common OpenAPI paths
    let openapi_paths = [
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/api/openapi.json",
        "/api/swagger.json",
        "/api-docs",
        "/docs/openapi.json",
    ];

    for path in openapi_paths {
        if let Some(info) = check_openapi(client, &format!("{}{}", base_url, path)).await {
            if info.status_code == 200 {
                discovery.openapi = Some(info);
                break;
            }
        }
    }

    // Check for GraphQL endpoint
    let graphql_paths = ["/graphql", "/api/graphql", "/query"];
    for path in graphql_paths {
        if let Some(info) = check_graphql(client, &format!("{}{}", base_url, path)).await {
            if info.status_code == 200 {
                discovery.graphql = Some(info);
                break;
            }
        }
    }

    // Look for documentation links in the page
    if let Ok(selector) = Selector::parse("a[href]") {
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                let href_lower = href.to_lowercase();
                let text = element.text().collect::<String>().to_lowercase();

                if (href_lower.contains("/docs")
                    || href_lower.contains("/documentation")
                    || text.contains("documentation")
                    || text.contains("api docs"))
                    && discovery.docs_url.is_none()
                {
                    discovery.docs_url = Some(href.to_string());
                }

                if (href_lower.contains("/developer") || text.contains("developer"))
                    && discovery.developer_url.is_none()
                {
                    discovery.developer_url = Some(href.to_string());
                }
            }
        }
    }

    discovery
}

/// Check for OpenAPI spec
async fn check_openapi(client: &Client, url: &str) -> Option<OpenApiInfo> {
    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status_code = response.status().as_u16();

    if !response.status().is_success() {
        return None;
    }

    let content = match response.text().await {
        Ok(t) => t,
        Err(_) => return None,
    };

    // Try to parse as JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);

    match parsed {
        Ok(json) => {
            let version = json
                .get("openapi")
                .or_else(|| json.get("swagger"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let title = json
                .get("info")
                .and_then(|info| info.get("title"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            Some(OpenApiInfo {
                url: url.to_string(),
                status_code,
                version,
                title,
                is_valid: true,
            })
        }
        Err(_) => {
            // Might be YAML
            Some(OpenApiInfo {
                url: url.to_string(),
                status_code,
                version: None,
                title: None,
                is_valid: content.contains("openapi:") || content.contains("swagger:"),
            })
        }
    }
}

/// Check for GraphQL endpoint
async fn check_graphql(client: &Client, url: &str) -> Option<GraphQLInfo> {
    // Try introspection query
    let introspection_query = r#"{"query": "{ __schema { types { name } } }"}"#;

    let response = match client
        .post(url)
        .header("Content-Type", "application/json")
        .body(introspection_query)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status_code = response.status().as_u16();

    if !response.status().is_success() {
        return None;
    }

    let content = match response.text().await {
        Ok(t) => t,
        Err(_) => return None,
    };

    let introspection_enabled = content.contains("__schema") || content.contains("types");
    let has_playground = content.contains("graphiql") || content.contains("playground");

    Some(GraphQLInfo {
        url: url.to_string(),
        status_code,
        introspection_enabled,
        has_playground,
    })
}

/// Generate AEO issues
fn generate_issues(
    structured_data: &StructuredDataAnalysis,
    ai_endpoints: &AiEndpoints,
    content_structure: &ContentStructure,
    _api_discovery: &ApiDiscovery,
) -> Vec<AeoIssue> {
    let mut issues = Vec::new();

    // Structured data issues
    if structured_data.json_ld_blocks.is_empty() {
        issues.push(AeoIssue {
            severity: Severity::Medium,
            category: "structured-data".to_string(),
            message: "No JSON-LD structured data found".to_string(),
            recommendation: Some(
                "Add JSON-LD with Schema.org vocabulary for better AI understanding".to_string(),
            ),
        });
    } else {
        if !structured_data.has_organization && !structured_data.has_website {
            issues.push(AeoIssue {
                severity: Severity::Low,
                category: "structured-data".to_string(),
                message: "Missing Organization or WebSite schema".to_string(),
                recommendation: Some("Add Organization schema to identify your brand".to_string()),
            });
        }
    }

    for validation_issue in &structured_data.validation_issues {
        if validation_issue.contains("invalid JSON") {
            issues.push(AeoIssue {
                severity: Severity::High,
                category: "structured-data".to_string(),
                message: validation_issue.clone(),
                recommendation: Some("Fix JSON syntax errors in structured data".to_string()),
            });
        }
    }

    // AI endpoints issues
    match &ai_endpoints.llms_txt {
        None | Some(LlmsTxtInfo { exists: false, .. }) => {
            issues.push(AeoIssue {
                severity: Severity::Low,
                category: "ai-endpoints".to_string(),
                message: "No llms.txt file found".to_string(),
                recommendation: Some(
                    "Add /llms.txt to provide AI-friendly site summary".to_string(),
                ),
            });
        }
        _ => {}
    }

    if let Some(ref rules) = ai_endpoints.robots_ai_rules {
        if rules.blocks_ai_bots {
            issues.push(AeoIssue {
                severity: Severity::Medium,
                category: "ai-access".to_string(),
                message: format!(
                    "AI bots are blocked in robots.txt ({})",
                    rules.ai_user_agents.join(", ")
                ),
                recommendation: Some(
                    "Consider allowing AI bots if you want AI-powered search visibility"
                        .to_string(),
                ),
            });
        }
    }

    // Content structure issues
    if !content_structure.has_main_content {
        issues.push(AeoIssue {
            severity: Severity::Medium,
            category: "content-structure".to_string(),
            message: "No main content element found (<main> or <article>)".to_string(),
            recommendation: Some(
                "Use semantic HTML elements for better content extraction".to_string(),
            ),
        });
    }

    if content_structure.text_ratio < 0.1 {
        issues.push(AeoIssue {
            severity: Severity::Low,
            category: "content-structure".to_string(),
            message: format!(
                "Low text-to-HTML ratio ({:.1}%)",
                content_structure.text_ratio * 100.0
            ),
            recommendation: Some("Increase meaningful text content relative to markup".to_string()),
        });
    }

    if content_structure.semantic_score < 50 {
        issues.push(AeoIssue {
            severity: Severity::Low,
            category: "content-structure".to_string(),
            message: format!(
                "Low semantic HTML score ({}%)",
                content_structure.semantic_score
            ),
            recommendation: Some(
                "Use more semantic HTML elements (article, section, nav, etc.)".to_string(),
            ),
        });
    }

    // Sort by severity
    issues.sort_by(|a, b| b.severity.cmp(&a.severity));

    issues
}

/// Calculate AEO score
fn calculate_score(
    structured_data: &StructuredDataAnalysis,
    ai_endpoints: &AiEndpoints,
    content_structure: &ContentStructure,
    _api_discovery: &ApiDiscovery,
) -> u8 {
    let mut score: i32 = 0;

    // Structured data (max 35 points)
    if !structured_data.json_ld_blocks.is_empty() {
        score += 15;
        if structured_data.has_organization || structured_data.has_website {
            score += 5;
        }
        if structured_data.rich_snippet_eligible {
            score += 10;
        }
        if structured_data.validation_issues.is_empty() {
            score += 5;
        }
    }

    // AI endpoints (max 25 points)
    if let Some(ref llms) = ai_endpoints.llms_txt {
        if llms.exists {
            score += 15;
            if llms.section_count > 0 {
                score += 5;
            }
        }
    }
    if let Some(ref plugin) = ai_endpoints.ai_plugin {
        if plugin.exists && plugin.is_valid {
            score += 10;
        }
    }
    // Bonus for not blocking AI bots
    if ai_endpoints
        .robots_ai_rules
        .as_ref()
        .map(|r| !r.blocks_ai_bots)
        .unwrap_or(true)
    {
        score += 5;
    }

    // Content structure (max 30 points)
    score += (content_structure.semantic_score as i32 * 20 / 100).min(20);
    if content_structure.is_extractable {
        score += 10;
    }

    // API discoverability (max 10 points)
    if _api_discovery.openapi.is_some() {
        score += 5;
    }
    if _api_discovery.graphql.is_some() {
        score += 5;
    }

    score.clamp(0, 100) as u8
}

/// Determine AEO readiness level
fn determine_readiness(score: u8) -> AeoReadiness {
    match score {
        80..=100 => AeoReadiness::Excellent,
        60..=79 => AeoReadiness::Good,
        40..=59 => AeoReadiness::Basic,
        _ => AeoReadiness::Poor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_ld() {
        let content =
            r#"{"@context": "https://schema.org", "@type": "Organization", "name": "Test"}"#;
        let block = parse_json_ld(content);

        assert!(block.is_valid_json);
        assert!(block.has_context);
        assert!(block.types.contains(&"Organization".to_string()));
        assert!(block.properties.contains(&"name".to_string()));
    }

    #[test]
    fn test_parse_json_ld_array_type() {
        let content = r#"{"@type": ["Organization", "LocalBusiness"]}"#;
        let block = parse_json_ld(content);

        assert!(block.types.contains(&"Organization".to_string()));
        assert!(block.types.contains(&"LocalBusiness".to_string()));
    }

    #[test]
    fn test_extract_json_values() {
        let content = r#"{"@type": "Article", "name": "Test"}"#;
        let mut types = Vec::new();
        extract_json_values(content, "@type", &mut types);

        assert!(types.contains(&"Article".to_string()));
    }

    #[test]
    fn test_semantic_score() {
        let structure = ContentStructure {
            has_main_content: true,
            has_article: true,
            has_sections: true,
            has_nav: true,
            has_header_footer: true,
            text_ratio: 0.2,
            ..Default::default()
        };

        let score = calculate_semantic_score(&structure);
        assert!(score >= 70);
    }

    #[test]
    fn test_determine_readiness() {
        assert_eq!(determine_readiness(85), AeoReadiness::Excellent);
        assert_eq!(determine_readiness(70), AeoReadiness::Good);
        assert_eq!(determine_readiness(50), AeoReadiness::Basic);
        assert_eq!(determine_readiness(30), AeoReadiness::Poor);
    }

    #[test]
    fn test_aeo_score_calculation() {
        let structured_data = StructuredDataAnalysis {
            json_ld_blocks: vec![JsonLdBlock {
                types: vec!["Organization".to_string()],
                has_context: true,
                is_valid_json: true,
                properties: vec!["name".to_string()],
                preview: String::new(),
            }],
            has_organization: true,
            rich_snippet_eligible: true,
            ..Default::default()
        };

        let ai_endpoints = AiEndpoints {
            llms_txt: Some(LlmsTxtInfo {
                exists: true,
                status_code: 200,
                content_length: 1000,
                title: Some("Test".to_string()),
                description: None,
                section_count: 3,
                link_count: 5,
                preview: String::new(),
            }),
            ..Default::default()
        };

        let content_structure = ContentStructure {
            semantic_score: 80,
            is_extractable: true,
            ..Default::default()
        };

        let api_discovery = ApiDiscovery::default();

        let score = calculate_score(
            &structured_data,
            &ai_endpoints,
            &content_structure,
            &api_discovery,
        );
        assert!(score >= 60);
    }
}
