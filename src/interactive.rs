//! Interactive TUI mode for exploring probe results
//!
//! Provides a navigable interface for exploring diagnostic results with
//! contextual help explaining what each metric means and why it matters.

use std::io;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};

use crate::probe::ProbeResult;

/// Section of the probe results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Overview,
    Tls,
    Http,
    Headers,
    Latency,
    Discovery,
    TechStack,
    Seo,
    Aeo,
    Content,
}

impl Section {
    fn name(&self) -> &'static str {
        match self {
            Section::Overview => "Overview",
            Section::Tls => "TLS/SSL",
            Section::Http => "HTTP Protocol",
            Section::Headers => "Security Headers",
            Section::Latency => "Latency",
            Section::Discovery => "Discovery",
            Section::TechStack => "Tech Stack",
            Section::Seo => "SEO",
            Section::Aeo => "AEO",
            Section::Content => "Content",
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            Section::Overview => "◉",
            Section::Tls => "🔒",
            Section::Http => "⇄",
            Section::Headers => "🛡",
            Section::Latency => "⏱",
            Section::Discovery => "🔍",
            Section::TechStack => "⚙",
            Section::Seo => "📊",
            Section::Aeo => "🤖",
            Section::Content => "📄",
        }
    }

    fn help_title(&self) -> &'static str {
        match self {
            Section::Overview => "What is this report?",
            Section::Tls => "What is TLS/SSL?",
            Section::Http => "What is HTTP Protocol Analysis?",
            Section::Headers => "What are Security Headers?",
            Section::Latency => "What is Latency Breakdown?",
            Section::Discovery => "What is Discovery?",
            Section::TechStack => "What is Tech Stack Detection?",
            Section::Seo => "What is SEO Analysis?",
            Section::Aeo => "What is AEO Analysis?",
            Section::Content => "What is Content Analysis?",
        }
    }

    fn help_text(&self) -> &'static str {
        match self {
            Section::Overview => r#"SANGO EDGE DIAGNOSTICS

Sango performs read-only, non-invasive diagnostic checks against web endpoints to assess their health, security, and discoverability.

HOW IT WORKS:
• Makes standard HTTPS connections (like a browser)
• Inspects TLS certificates and negotiated protocols
• Analyzes HTTP response headers
• Parses HTML for SEO/AEO signals
• Probes common paths (robots.txt, sitemap.xml)
• Never modifies anything - purely observational

WHY USE IT:
• Verify production deployments are healthy
• Check security header configuration
• Audit SEO/AEO readiness before launch
• Debug connectivity and protocol issues
• Get operator-focused, actionable insights

HEALTH STATUS:
• Healthy - No critical or high severity issues
• Degraded - Medium/low severity issues found
• Unhealthy - Critical or high severity issues
• Unknown - Probe couldn't complete"#,

            Section::Tls => r#"TLS (TRANSPORT LAYER SECURITY)

TLS encrypts the connection between browsers and your server, protecting data in transit.

WHAT SANGO CHECKS:

Certificate Validity
  Connects using rustls (a modern TLS library) and validates the certificate chain against trusted root CAs. Checks expiration dates.

TLS Version
  Reports the negotiated TLS version (1.2, 1.3). TLS 1.3 is preferred for better security and performance.

Cipher Suite
  Shows which encryption algorithm was negotiated. Weak ciphers (RC4, 3DES, export ciphers) are flagged.

ALPN (Application-Layer Protocol Negotiation)
  Shows if HTTP/2 was negotiated during TLS handshake. Indicates modern protocol support.

Certificate Chain
  Validates the full chain from leaf to root. Missing intermediates cause browser warnings.

WHY IT MATTERS:
• Expired certificates break user trust
• Weak TLS versions are vulnerable to attacks
• Missing intermediates cause mobile failures
• ALPN enables HTTP/2 for better performance"#,

            Section::Http => r#"HTTP PROTOCOL ANALYSIS

Analyzes the HTTP protocol capabilities and behavior of the endpoint.

WHAT SANGO CHECKS:

HTTP Version
  The protocol version used for the response (HTTP/1.1, HTTP/2). HTTP/2 enables multiplexing and header compression.

Status Code
  The response status (200 OK, 301 redirect, etc.). Unexpected codes indicate configuration issues.

HTTP/2 Support
  Whether the server supports HTTP/2 protocol. HTTP/2 significantly improves page load times.

HTTP/3 (QUIC) Advertisement
  Checks for Alt-Svc header indicating HTTP/3 support. HTTP/3 uses UDP for even faster connections.

Redirect Chain
  Follows and reports redirects. Excessive redirects add latency. HTTP→HTTPS redirects should use 301.

WHY IT MATTERS:
• HTTP/2 reduces latency by ~30-50%
• HTTP/3 improves mobile/lossy connections
• Redirect chains add cumulative latency
• Protocol support affects Core Web Vitals"#,

            Section::Headers => r#"SECURITY HEADERS

HTTP response headers that instruct browsers to enable security protections.

WHAT SANGO CHECKS:

HSTS (Strict-Transport-Security)
  Forces browsers to use HTTPS for future visits. 'preload' gets your domain into browser preload lists.

CSP (Content-Security-Policy)
  Controls what resources (scripts, styles, images) can load. Prevents XSS attacks.

X-Frame-Options
  Prevents your site from being embedded in iframes. Stops clickjacking attacks.

X-Content-Type-Options
  'nosniff' prevents browsers from guessing content types. Stops MIME-sniffing attacks.

COOP/COEP (Cross-Origin Policies)
  Enables cross-origin isolation for SharedArrayBuffer and high-resolution timers.

Referrer-Policy
  Controls what URL information is sent when navigating away.

WHY IT MATTERS:
• Missing HSTS allows downgrade attacks
• No CSP enables XSS vulnerabilities
• These headers are easy wins for security
• Many are required for compliance (PCI, SOC2)"#,

            Section::Latency => r#"LATENCY BREAKDOWN

Measures the time spent in each phase of establishing a connection and receiving content.

WHAT SANGO MEASURES:

DNS Lookup
  Time to resolve hostname to IP address. Slow DNS adds latency to every new connection.

TCP Connect
  Time to establish TCP connection (3-way handshake). Indicates network distance to server.

TLS Handshake
  Time for TLS negotiation and certificate validation. TLS 1.3 is faster than 1.2.

TTFB (Time to First Byte)
  Time from request sent to first byte received. Indicates server processing time.

Total
  Sum of all phases. This is the minimum time before any content renders.

HOW IT'S MEASURED:
  Sango makes a real HTTPS request and precisely measures each phase using system timing APIs.

WHY IT MATTERS:
• DNS: Consider DNS prefetching
• TCP: CDN brings servers closer
• TLS: HTTP/2 connection reuse helps
• TTFB: Optimize backend/caching
• These directly impact Core Web Vitals"#,

            Section::Discovery => r#"DISCOVERY ANALYSIS

Discovers the structure and configuration of a web property through standard, non-invasive probing.

WHAT SANGO CHECKS:

robots.txt
  Instructions for web crawlers. Shows which paths are allowed/blocked, sitemap references, and crawl-delay directives.

sitemap.xml
  Lists URLs for search engines. Checks both direct and sitemap index files. Reports URL count and last-modified dates.

Common Paths
  Probes standard endpoints: /api, /graphql, /health, /metrics, /.well-known/*, /favicon.ico, etc.

Well-Known Endpoints
  Checks /.well-known/ for security.txt, apple-app-site-association, assetlinks.json, etc.

HOW IT WORKS:
  Makes HEAD or GET requests to standard paths. Only reads publicly accessible URLs - never attempts authentication.

WHY IT MATTERS:
• robots.txt misconfig can hide your site from search
• Missing sitemap hurts SEO crawl efficiency
• Exposed /metrics or /health may leak info
• security.txt helps security researchers contact you"#,

            Section::TechStack => r#"TECHNOLOGY STACK DETECTION

Identifies the technologies powering the endpoint through passive fingerprinting.

WHAT SANGO DETECTS:

Server
  Web server software from Server header (nginx, Apache, Cloudflare, etc.)

CDN
  Content Delivery Network from headers and behavior (Cloudflare, Fastly, Akamai, Vercel, etc.)

Frameworks
  JavaScript frameworks (React, Vue, Next.js, Nuxt) from HTML patterns, script signatures, and meta tags.

CMS
  Content Management Systems (WordPress, Drupal, Shopify, Webflow) from generator tags and known paths.

JavaScript Libraries
  Common libraries (jQuery, Lodash, etc.) from script patterns.

Analytics
  Tracking services (Google Analytics, Segment, etc.) from script includes.

HOW IT WORKS:
  Analyzes HTTP headers, HTML content, and script patterns. No active exploitation - just reads what's publicly sent.

WHY IT MATTERS:
• Outdated versions may have vulnerabilities
• Exposed version info aids attackers
• Helps understand maintenance requirements
• CDN detection confirms edge deployment"#,

            Section::Seo => r#"SEO (SEARCH ENGINE OPTIMIZATION)

Analyzes signals that affect how search engines understand and rank your pages.

WHAT SANGO CHECKS:

Title Tag
  The <title> element. Should be 30-60 characters. Shown in search results and browser tabs.

Meta Description
  The meta description. Should be 120-160 characters. Used as search result snippet.

Canonical URL
  The rel="canonical" link. Prevents duplicate content issues. Should self-reference or point to primary URL.

Robots Directives
  Meta robots and X-Robots-Tag. Controls indexing (noindex) and link following (nofollow).

Open Graph
  og:title, og:description, og:image for social sharing previews (Facebook, LinkedIn, etc.)

Heading Structure
  H1-H6 hierarchy. Should have exactly one H1. Proper hierarchy helps accessibility and SEO.

Structured Data
  JSON-LD/Schema.org markup. Enables rich snippets in search results.

SEO SCORE (0-100):
  Weighted score based on presence and quality of all SEO signals.

WHY IT MATTERS:
• 60% of traffic comes from search engines
• Missing meta tags = poor click-through rates
• Broken canonicals cause ranking issues
• Structured data enables rich results"#,

            Section::Aeo => r#"AEO (AI ENGINE OPTIMIZATION)

Analyzes how well your content is optimized for AI agents, LLMs, and AI-powered search.

WHAT SANGO CHECKS:

Structured Data Analysis
  JSON-LD blocks, Schema.org types. AI systems use this to understand content semantically.

llms.txt
  A proposed standard file (/llms.txt) that provides AI-friendly site summaries, similar to robots.txt for crawlers.

ai-plugin.json
  ChatGPT plugin manifest at /.well-known/ai-plugin.json. Enables AI agent integrations.

AI Bot Rules
  robots.txt rules for AI crawlers (GPTBot, Google-Extended, anthropic-ai, etc.)

Content Structure
  Text-to-HTML ratio, semantic HTML usage, content extractability. Clean HTML helps AI parse content.

API Discoverability
  OpenAPI/Swagger docs, GraphQL introspection. Machine-readable API definitions.

AEO READINESS:
• Excellent (80-100): Optimized for AI agents
• Good (60-79): Most signals present
• Basic (40-59): Minimal AI support
• Poor (0-39): Not optimized for AI

WHY IT MATTERS:
• AI search (Perplexity, SearchGPT) is growing
• LLMs power customer service bots
• Structured data helps AI understand context
• llms.txt adoption is increasing"#,

            Section::Content => r#"CONTENT ANALYSIS

Analyzes the response content characteristics including type, size, compression, and caching.

WHAT SANGO CHECKS:

Content-Type
  MIME type from header vs actual content. Mismatches can cause security issues or rendering problems.

Response Size
  Body size in bytes. Large responses slow initial render. Categories: tiny (<1KB), small (1-10KB), medium (10-100KB), large (100KB-1MB), huge (>1MB).

Compression
  Whether gzip/Brotli/deflate is enabled. Uncompressed text wastes bandwidth.

Cache Headers
  Cache-Control directives, ETag, Last-Modified. Proper caching reduces server load and improves performance.

Cache Rating:
  A (Excellent): Long max-age, immutable, validators
  B (Good): Reasonable max-age with validators
  C (Basic): Some caching, room for improvement
  D (Poor): No effective caching
  - (Disabled): Explicitly no-store

Character Encoding
  Charset from header and HTML meta. Inconsistencies cause rendering issues.

Resource Hints
  preload, prefetch, preconnect, dns-prefetch. Optimize resource loading priority.

WHY IT MATTERS:
• Compression reduces bandwidth 60-80%
• Caching eliminates redundant requests
• Proper content-types prevent sniffing attacks
• Resource hints improve perceived performance"#,
        }
    }
}

/// Interactive TUI application state
pub struct App {
    /// The probe results to display
    result: ProbeResult,
    /// Available sections based on probe results
    sections: Vec<Section>,
    /// Currently selected section index
    selected: usize,
    /// List state for the section list
    list_state: ListState,
    /// Whether to show the help panel
    show_help: bool,
    /// Whether the app should exit
    should_exit: bool,
}

impl App {
    /// Create a new app with probe results
    pub fn new(result: ProbeResult) -> Self {
        let mut sections = vec![Section::Overview];

        // Add sections based on available results
        if result.tls.is_some() {
            sections.push(Section::Tls);
        }
        if result.http.is_some() {
            sections.push(Section::Http);
        }
        if result.headers.is_some() {
            sections.push(Section::Headers);
        }
        if result.latency.is_some() {
            sections.push(Section::Latency);
        }
        if result.discovery.is_some() {
            sections.push(Section::Discovery);
        }
        if result.techstack.is_some() {
            sections.push(Section::TechStack);
        }
        if result.seo.is_some() {
            sections.push(Section::Seo);
        }
        if result.aeo.is_some() {
            sections.push(Section::Aeo);
        }
        if result.content.is_some() {
            sections.push(Section::Content);
        }

        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            result,
            sections,
            selected: 0,
            list_state,
            show_help: false,
            should_exit: false,
        }
    }

    /// Get the currently selected section
    fn current_section(&self) -> Section {
        self.sections[self.selected]
    }

    /// Move selection up
    fn previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.list_state.select(Some(self.selected));
        }
    }

    /// Move selection down
    fn next(&mut self) {
        if self.selected < self.sections.len() - 1 {
            self.selected += 1;
            self.list_state.select(Some(self.selected));
        }
    }

    /// Toggle help panel
    fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    /// Handle key events
    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.should_exit = true,
            KeyCode::Up | KeyCode::Char('k') => self.previous(),
            KeyCode::Down | KeyCode::Char('j') => self.next(),
            KeyCode::Char('?') | KeyCode::F(1) => self.toggle_help(),
            KeyCode::Char('h') => self.toggle_help(),
            _ => {}
        }
    }

    /// Build section detail content
    fn section_content(&self, section: Section) -> Vec<Line<'static>> {
        match section {
            Section::Overview => self.overview_content(),
            Section::Tls => self.tls_content(),
            Section::Http => self.http_content(),
            Section::Headers => self.headers_content(),
            Section::Latency => self.latency_content(),
            Section::Discovery => self.discovery_content(),
            Section::TechStack => self.techstack_content(),
            Section::Seo => self.seo_content(),
            Section::Aeo => self.aeo_content(),
            Section::Content => self.content_content(),
        }
    }

    fn overview_content(&self) -> Vec<Line<'static>> {
        let health_style = match self.result.overall_health {
            crate::probe::Health::Healthy => Style::default().fg(Color::Green).bold(),
            crate::probe::Health::Degraded => Style::default().fg(Color::Yellow).bold(),
            crate::probe::Health::Unhealthy => Style::default().fg(Color::Red).bold(),
            crate::probe::Health::Unknown => Style::default().fg(Color::Gray).bold(),
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled("Target: ", Style::default().bold()),
                Span::raw(self.result.target.clone()),
            ]),
            Line::from(vec![
                Span::styled("Time: ", Style::default().bold()),
                Span::raw(self.result.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Health: ", Style::default().bold()),
                Span::styled(format!("{}", self.result.overall_health), health_style),
            ]),
            Line::from(""),
        ];

        // Summary of checks
        lines.push(Line::from(Span::styled("Checks Performed:", Style::default().bold().underlined())));
        lines.push(Line::from(""));

        if self.result.tls.is_some() {
            let tls = self.result.tls.as_ref().unwrap();
            let status = if tls.valid { "✓" } else { "✗" };
            let color = if tls.valid { Color::Green } else { Color::Red };
            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", status), Style::default().fg(color)),
                Span::raw(format!("TLS: {} (expires in {} days)", tls.tls_version, tls.expires_in_days)),
            ]));
        }

        if self.result.http.is_some() {
            let http = self.result.http.as_ref().unwrap();
            lines.push(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(Color::Green)),
                Span::raw(format!("HTTP: {} (status {})", http.http_version, http.status_code)),
            ]));
        }

        if self.result.headers.is_some() {
            let headers = self.result.headers.as_ref().unwrap();
            let issue_count = headers.issues.len();
            let status = if issue_count == 0 { "✓" } else { "!" };
            let color = if issue_count == 0 { Color::Green } else { Color::Yellow };
            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", status), Style::default().fg(color)),
                Span::raw(format!("Security Headers: {} issues", issue_count)),
            ]));
        }

        if self.result.latency.is_some() {
            let latency = self.result.latency.as_ref().unwrap();
            lines.push(Line::from(vec![
                Span::styled("  ✓ ", Style::default().fg(Color::Green)),
                Span::raw(format!("Latency: {}ms total", latency.total.as_millis())),
            ]));
        }

        if self.result.seo.is_some() {
            let seo = self.result.seo.as_ref().unwrap();
            let color = if seo.score >= 80 { Color::Green } else if seo.score >= 60 { Color::Yellow } else { Color::Red };
            lines.push(Line::from(vec![
                Span::styled("  ◉ ", Style::default().fg(color)),
                Span::raw(format!("SEO Score: {}/100", seo.score)),
            ]));
        }

        if self.result.aeo.is_some() {
            let aeo = self.result.aeo.as_ref().unwrap();
            let color = if aeo.score >= 80 { Color::Green } else if aeo.score >= 60 { Color::Yellow } else { Color::Red };
            lines.push(Line::from(vec![
                Span::styled("  ◉ ", Style::default().fg(color)),
                Span::raw(format!("AEO Score: {}/100 ({})", aeo.score, aeo.readiness)),
            ]));
        }

        if !self.result.errors.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Errors:", Style::default().fg(Color::Red).bold())));
            for error in &self.result.errors {
                lines.push(Line::from(vec![
                    Span::styled("  ✗ ", Style::default().fg(Color::Red)),
                    Span::raw(error.clone()),
                ]));
            }
        }

        lines
    }

    fn tls_content(&self) -> Vec<Line<'static>> {
        let Some(ref tls) = self.result.tls else {
            return vec![Line::from("TLS check was skipped")];
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled("Connection: ", Style::default().bold()),
                if tls.valid {
                    Span::styled("Valid", Style::default().fg(Color::Green))
                } else {
                    Span::styled("Invalid", Style::default().fg(Color::Red))
                },
            ]),
            Line::from(vec![
                Span::styled("TLS Version: ", Style::default().bold()),
                Span::raw(tls.tls_version.clone()),
            ]),
            Line::from(vec![
                Span::styled("Cipher Suite: ", Style::default().bold()),
                Span::raw(tls.cipher_suite.clone()),
            ]),
            Line::from(vec![
                Span::styled("ALPN: ", Style::default().bold()),
                Span::raw(tls.alpn_negotiated.clone().unwrap_or_else(|| "none".to_string())),
            ]),
            Line::from(""),
            Line::from(Span::styled("Certificate:", Style::default().bold().underlined())),
            Line::from(vec![
                Span::raw("  Subject: "),
                Span::raw(tls.subject.clone()),
            ]),
            Line::from(vec![
                Span::raw("  Issuer: "),
                Span::raw(tls.issuer.clone()),
            ]),
            Line::from(vec![
                Span::raw("  Chain: "),
                Span::raw(format!("{} certificates", tls.chain_length)),
            ]),
        ];

        let expiry_style = if tls.expires_in_days < 7 {
            Style::default().fg(Color::Red)
        } else if tls.expires_in_days < 30 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Green)
        };
        lines.push(Line::from(vec![
            Span::raw("  Expires: "),
            Span::styled(format!("{} days", tls.expires_in_days), expiry_style),
        ]));

        if !tls.issues.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Issues:", Style::default().bold().underlined())));
            for issue in &tls.issues {
                let severity_style = match issue.severity {
                    crate::checks::tls::Severity::Critical => Style::default().fg(Color::Red).bold(),
                    crate::checks::tls::Severity::High => Style::default().fg(Color::Red),
                    crate::checks::tls::Severity::Medium => Style::default().fg(Color::Yellow),
                    crate::checks::tls::Severity::Low => Style::default().fg(Color::Gray),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("  [{:?}] ", issue.severity), severity_style),
                    Span::raw(issue.message.clone()),
                ]));
            }
        }

        lines
    }

    fn http_content(&self) -> Vec<Line<'static>> {
        let Some(ref http) = self.result.http else {
            return vec![Line::from("HTTP check was skipped")];
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled("HTTP Version: ", Style::default().bold()),
                Span::raw(http.http_version.clone()),
            ]),
            Line::from(vec![
                Span::styled("Status Code: ", Style::default().bold()),
                Span::raw(format!("{}", http.status_code)),
            ]),
            Line::from(vec![
                Span::styled("HTTP/2: ", Style::default().bold()),
                if http.http2_supported {
                    Span::styled("Supported", Style::default().fg(Color::Green))
                } else {
                    Span::styled("Not supported", Style::default().fg(Color::Gray))
                },
            ]),
            Line::from(vec![
                Span::styled("HTTP/3: ", Style::default().bold()),
                if http.http3_advertised {
                    Span::styled("Advertised", Style::default().fg(Color::Green))
                } else {
                    Span::styled("Not advertised", Style::default().fg(Color::Gray))
                },
            ]),
        ];

        if !http.redirect_chain.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Redirect Chain:", Style::default().bold().underlined())));
            for redirect in &http.redirect_chain {
                lines.push(Line::from(format!("  {} → {}", redirect.status, redirect.url)));
            }
        }

        if !http.issues.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Issues:", Style::default().bold().underlined())));
            for issue in &http.issues {
                lines.push(Line::from(format!("  [{:?}] {}", issue.severity, issue.message)));
            }
        }

        lines
    }

    fn headers_content(&self) -> Vec<Line<'static>> {
        let Some(ref headers) = self.result.headers else {
            return vec![Line::from("Headers check was skipped")];
        };

        let mut lines = vec![];

        // HSTS
        lines.push(Line::from(vec![
            Span::styled("HSTS: ", Style::default().bold()),
            match &headers.hsts {
                Some(hsts) => Span::styled(
                    format!("max-age={}{}{}",
                        hsts.max_age,
                        if hsts.include_subdomains { ", includeSubDomains" } else { "" },
                        if hsts.preload { ", preload" } else { "" }
                    ),
                    Style::default().fg(Color::Green)
                ),
                None => Span::styled("Missing", Style::default().fg(Color::Red)),
            },
        ]));

        // CSP
        lines.push(Line::from(vec![
            Span::styled("CSP: ", Style::default().bold()),
            match &headers.csp {
                Some(csp) => {
                    if csp.report_only {
                        Span::styled("Report-Only", Style::default().fg(Color::Yellow))
                    } else {
                        Span::styled("Present", Style::default().fg(Color::Green))
                    }
                }
                None => Span::styled("Missing", Style::default().fg(Color::Red)),
            },
        ]));

        // X-Frame-Options
        lines.push(Line::from(vec![
            Span::styled("X-Frame-Options: ", Style::default().bold()),
            match &headers.x_frame_options {
                Some(v) => Span::styled(v.clone(), Style::default().fg(Color::Green)),
                None => Span::styled("Missing", Style::default().fg(Color::Yellow)),
            },
        ]));

        // X-Content-Type-Options
        lines.push(Line::from(vec![
            Span::styled("X-Content-Type-Options: ", Style::default().bold()),
            match &headers.x_content_type_options {
                Some(v) => Span::styled(v.clone(), Style::default().fg(Color::Green)),
                None => Span::styled("Missing", Style::default().fg(Color::Yellow)),
            },
        ]));

        if !headers.issues.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Issues:", Style::default().bold().underlined())));
            for issue in &headers.issues {
                lines.push(Line::from(format!("  [{:?}] {}", issue.severity, issue.message)));
            }
        }

        lines
    }

    fn latency_content(&self) -> Vec<Line<'static>> {
        let Some(ref latency) = self.result.latency else {
            return vec![Line::from("Latency check was skipped")];
        };

        let format_ms = |ms: u128| -> Span<'static> {
            let style = if ms >= 1000 {
                Style::default().fg(Color::Red)
            } else if ms >= 200 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };
            Span::styled(format!("{}ms", ms), style)
        };

        vec![
            Line::from(vec![
                Span::styled("DNS Lookup:    ", Style::default().bold()),
                format_ms(latency.dns_lookup.as_millis()),
            ]),
            Line::from(vec![
                Span::styled("TCP Connect:   ", Style::default().bold()),
                format_ms(latency.tcp_connect.as_millis()),
            ]),
            Line::from(vec![
                Span::styled("TLS Handshake: ", Style::default().bold()),
                format_ms(latency.tls_handshake.as_millis()),
            ]),
            Line::from(vec![
                Span::styled("TTFB:          ", Style::default().bold()),
                format_ms(latency.time_to_first_byte.as_millis()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Total:         ", Style::default().bold()),
                Span::styled(
                    format!("{}ms", latency.total.as_millis()),
                    Style::default().bold()
                ),
            ]),
        ]
    }

    fn discovery_content(&self) -> Vec<Line<'static>> {
        let Some(ref discovery) = self.result.discovery else {
            return vec![Line::from("Discovery check was skipped")];
        };

        let mut lines = vec![];

        // robots.txt
        match &discovery.robots {
            Some(r) if r.exists => {
                lines.push(Line::from(vec![
                    Span::styled("robots.txt: ", Style::default().bold()),
                    Span::styled("Found", Style::default().fg(Color::Green)),
                ]));
                if !r.disallowed.is_empty() {
                    lines.push(Line::from(format!("  {} disallowed paths", r.disallowed.len())));
                }
                if !r.sitemaps.is_empty() {
                    lines.push(Line::from(format!("  {} sitemaps referenced", r.sitemaps.len())));
                }
            }
            _ => {
                lines.push(Line::from(vec![
                    Span::styled("robots.txt: ", Style::default().bold()),
                    Span::styled("Not found", Style::default().fg(Color::Yellow)),
                ]));
            }
        }

        // Sitemap
        match &discovery.sitemap {
            Some(s) if s.exists => {
                lines.push(Line::from(vec![
                    Span::styled("Sitemap: ", Style::default().bold()),
                    Span::styled(format!("{} entries", s.entry_count), Style::default().fg(Color::Green)),
                ]));
            }
            _ => {
                lines.push(Line::from(vec![
                    Span::styled("Sitemap: ", Style::default().bold()),
                    Span::styled("Not found", Style::default().fg(Color::Yellow)),
                ]));
            }
        }

        // Discovered paths
        if !discovery.discovered_paths.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Discovered Paths:", Style::default().bold().underlined())));
            for path in &discovery.discovered_paths {
                let status_style = if path.status_code == 200 {
                    Style::default().fg(Color::Green)
                } else if path.status_code >= 300 && path.status_code < 400 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Red)
                };
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::raw(path.path.clone()),
                    Span::raw(" ["),
                    Span::styled(format!("{}", path.status_code), status_style),
                    Span::raw("]"),
                ]));
            }
        }

        lines
    }

    fn techstack_content(&self) -> Vec<Line<'static>> {
        let Some(ref tech) = self.result.techstack else {
            return vec![Line::from("Tech stack check was skipped")];
        };

        let mut lines = vec![];

        // Server
        if let Some(ref server) = tech.server {
            lines.push(Line::from(vec![
                Span::styled("Server: ", Style::default().bold()),
                Span::raw(server.name.clone()),
                Span::raw(server.version.as_ref().map(|v| format!(" {}", v)).unwrap_or_default()),
            ]));
        }

        // CDN
        if let Some(ref cdn) = tech.cdn {
            lines.push(Line::from(vec![
                Span::styled("CDN: ", Style::default().bold()),
                Span::styled(cdn.name.clone(), Style::default().fg(Color::Green)),
                Span::raw(cdn.edge_location.as_ref().map(|e| format!(" ({})", e)).unwrap_or_default()),
            ]));
        }

        // Frameworks
        if !tech.frameworks.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Frameworks:", Style::default().bold().underlined())));
            for fw in &tech.frameworks {
                lines.push(Line::from(format!(
                    "  {} {} ({}% confidence)",
                    fw.name,
                    fw.version.as_ref().map(|v| v.as_str()).unwrap_or(""),
                    (fw.confidence * 100.0) as u8
                )));
            }
        }

        // CMS
        if let Some(ref cms) = tech.cms {
            lines.push(Line::from(vec![
                Span::styled("CMS: ", Style::default().bold()),
                Span::raw(cms.name.clone()),
            ]));
        }

        lines
    }

    fn seo_content(&self) -> Vec<Line<'static>> {
        let Some(ref seo) = self.result.seo else {
            return vec![Line::from("SEO check was skipped")];
        };

        let score_style = if seo.score >= 80 {
            Style::default().fg(Color::Green).bold()
        } else if seo.score >= 60 {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::Red).bold()
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled("SEO Score: ", Style::default().bold()),
                Span::styled(format!("{}/100", seo.score), score_style),
            ]),
            Line::from(""),
        ];

        // Title
        if let Some(ref title) = seo.title {
            let status = if title.length_optimal { "OK" } else { "!" };
            lines.push(Line::from(vec![
                Span::styled("Title: ", Style::default().bold()),
                Span::raw(format!("[{}] {} ({} chars)", status, title.content, title.length)),
            ]));
        }

        // Description
        if let Some(ref desc) = seo.description {
            let status = if desc.length_optimal { "OK" } else { "!" };
            lines.push(Line::from(vec![
                Span::styled("Description: ", Style::default().bold()),
                Span::raw(format!("[{}] {} chars", status, desc.length)),
            ]));
        }

        // Open Graph
        let og_status = if seo.open_graph.is_complete { "Complete" } else { "Incomplete" };
        lines.push(Line::from(vec![
            Span::styled("Open Graph: ", Style::default().bold()),
            Span::raw(og_status),
        ]));

        // Headings
        lines.push(Line::from(vec![
            Span::styled("H1 Count: ", Style::default().bold()),
            Span::raw(format!("{}", seo.headings.h1_count)),
        ]));

        if !seo.issues.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Issues:", Style::default().bold().underlined())));
            for issue in &seo.issues {
                lines.push(Line::from(format!("  [{:?}] {}", issue.severity, issue.message)));
            }
        }

        lines
    }

    fn aeo_content(&self) -> Vec<Line<'static>> {
        let Some(ref aeo) = self.result.aeo else {
            return vec![Line::from("AEO check was skipped")];
        };

        let score_style = if aeo.score >= 80 {
            Style::default().fg(Color::Green).bold()
        } else if aeo.score >= 60 {
            Style::default().fg(Color::Yellow).bold()
        } else {
            Style::default().fg(Color::Red).bold()
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled("AEO Score: ", Style::default().bold()),
                Span::styled(format!("{}/100", aeo.score), score_style),
                Span::raw(format!(" ({})", aeo.readiness)),
            ]),
            Line::from(""),
        ];

        // JSON-LD
        if !aeo.structured_data.json_ld_blocks.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("JSON-LD: ", Style::default().bold()),
                Span::styled(
                    format!("{} blocks", aeo.structured_data.json_ld_blocks.len()),
                    Style::default().fg(Color::Green)
                ),
            ]));
            if !aeo.structured_data.schema_types.is_empty() {
                lines.push(Line::from(format!("  Types: {}", aeo.structured_data.schema_types.join(", "))));
            }
        } else {
            lines.push(Line::from(vec![
                Span::styled("JSON-LD: ", Style::default().bold()),
                Span::styled("None", Style::default().fg(Color::Yellow)),
            ]));
        }

        // llms.txt
        match &aeo.ai_endpoints.llms_txt {
            Some(llms) if llms.exists => {
                lines.push(Line::from(vec![
                    Span::styled("llms.txt: ", Style::default().bold()),
                    Span::styled("Found", Style::default().fg(Color::Green)),
                ]));
            }
            _ => {
                lines.push(Line::from(vec![
                    Span::styled("llms.txt: ", Style::default().bold()),
                    Span::styled("Not found", Style::default().fg(Color::Yellow)),
                ]));
            }
        }

        // Content structure
        lines.push(Line::from(vec![
            Span::styled("Semantic Score: ", Style::default().bold()),
            Span::raw(format!("{}%", aeo.content_structure.semantic_score)),
        ]));

        if !aeo.issues.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Issues:", Style::default().bold().underlined())));
            for issue in &aeo.issues {
                lines.push(Line::from(format!("  [{:?}] {}", issue.severity, issue.message)));
            }
        }

        lines
    }

    fn content_content(&self) -> Vec<Line<'static>> {
        let Some(ref content) = self.result.content else {
            return vec![Line::from("Content check was skipped")];
        };

        let mut lines = vec![];

        // Content type
        lines.push(Line::from(vec![
            Span::styled("Content-Type: ", Style::default().bold()),
            Span::raw(content.content_type.mime_type.clone().unwrap_or_else(|| "unknown".to_string())),
        ]));

        // Size
        lines.push(Line::from(vec![
            Span::styled("Size: ", Style::default().bold()),
            Span::raw(format!("{} ({})", content.size.body_size_formatted, content.size.size_category)),
        ]));

        // Compression
        lines.push(Line::from(vec![
            Span::styled("Compression: ", Style::default().bold()),
            if content.compression.is_compressed {
                Span::styled(
                    content.compression.algorithm.clone().unwrap_or_else(|| "yes".to_string()),
                    Style::default().fg(Color::Green)
                )
            } else if content.compression.should_compress {
                Span::styled("Recommended but not enabled", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("Not applicable")
            },
        ]));

        // Cache
        let cache_style = match content.cache.rating {
            crate::checks::content::CacheRating::Excellent => Style::default().fg(Color::Green),
            crate::checks::content::CacheRating::Good => Style::default().fg(Color::Green),
            crate::checks::content::CacheRating::Basic => Style::default().fg(Color::Yellow),
            crate::checks::content::CacheRating::Poor => Style::default().fg(Color::Red),
            crate::checks::content::CacheRating::NotCached => Style::default().fg(Color::Gray),
        };
        lines.push(Line::from(vec![
            Span::styled("Cache Rating: ", Style::default().bold()),
            Span::styled(format!("{:?}", content.cache.rating), cache_style),
        ]));

        if let Some(max_age) = content.cache.effective_max_age {
            lines.push(Line::from(format!("  max-age: {}s", max_age)));
        }

        // Resource hints
        if content.resource_hints.total_count > 0 {
            lines.push(Line::from(vec![
                Span::styled("Resource Hints: ", Style::default().bold()),
                Span::raw(format!("{} total", content.resource_hints.total_count)),
            ]));
        }

        if !content.issues.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Issues:", Style::default().bold().underlined())));
            for issue in &content.issues {
                lines.push(Line::from(format!("  [{:?}] {}", issue.severity, issue.message)));
            }
        }

        lines
    }
}

/// Run the interactive TUI
pub fn run_interactive(result: ProbeResult) -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(result);

    // Main loop
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                app.handle_key(key.code);
            }
        }

        if app.should_exit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Render the UI
fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24),
            Constraint::Min(40),
            if app.show_help { Constraint::Percentage(40) } else { Constraint::Length(0) },
        ])
        .split(f.area());

    // Left panel: Section list
    let sections: Vec<ListItem> = app
        .sections
        .iter()
        .map(|s| {
            ListItem::new(format!(" {} {}", s.icon(), s.name()))
        })
        .collect();

    let section_list = List::new(sections)
        .block(Block::default().borders(Borders::ALL).title(" Sections "))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(section_list, chunks[0], &mut app.list_state);

    // Middle panel: Section details
    let current = app.current_section();
    let content_lines = app.section_content(current);

    let detail_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} {} ", current.icon(), current.name()));

    let detail = Paragraph::new(content_lines)
        .block(detail_block)
        .wrap(Wrap { trim: false });

    f.render_widget(detail, chunks[1]);

    // Right panel: Help (if visible)
    if app.show_help {
        let help_text = current.help_text();
        let help_block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ", current.help_title()))
            .border_style(Style::default().fg(Color::Cyan));

        let help = Paragraph::new(help_text)
            .block(help_block)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(Color::Gray));

        f.render_widget(help, chunks[2]);
    }

    // Footer with keybindings
    let footer_area = Rect {
        x: 0,
        y: f.area().height - 1,
        width: f.area().width,
        height: 1,
    };

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓ ", Style::default().bold()),
        Span::raw("Navigate  "),
        Span::styled(" h/? ", Style::default().bold()),
        Span::raw("Help  "),
        Span::styled(" q ", Style::default().bold()),
        Span::raw("Quit"),
    ]))
    .style(Style::default().bg(Color::DarkGray));

    f.render_widget(footer, footer_area);
}
