use anyhow::Result;
use clap::Parser;
use std::time::Duration;

mod checks;
mod interactive;
mod output;
mod probe;

use probe::ProbeConfig;

/// Sango - Operator-grade edge diagnostics
///
/// A read-only, non-invasive diagnostic CLI that analyzes web endpoints for health,
/// security, performance, and discoverability. Sango makes standard HTTPS requests
/// (like a browser would) and analyzes the responses - it never modifies anything.
#[derive(Parser, Debug)]
#[command(name = "sango")]
#[command(author, version)]
#[command(
    about = "Operator-grade edge diagnostics - analyze TLS, HTTP, security headers, SEO, AEO, and more"
)]
#[command(arg_required_else_help = true)]
#[command(after_long_help = EXTENDED_HELP)]
struct Args {
    /// Target URL or hostname to diagnose
    ///
    /// Sango will establish an HTTPS connection to this target and perform
    /// all enabled diagnostic checks. You can provide:
    ///   - Full URL: https://example.com/path
    ///   - Hostname: example.com (defaults to https:// port 443)
    ///   - With port: example.com:8443
    #[arg(required = true, value_name = "TARGET")]
    target: String,

    /// Output format for results
    ///
    /// Choose how results are displayed:
    ///   - pretty: Colored, human-readable output (default)
    ///   - json: Machine-readable JSON for automation/scripting
    ///   - compact: Single-line summary for dashboards/logs
    #[arg(short, long, default_value = "pretty", value_enum)]
    format: OutputFormat,

    /// Launch interactive TUI mode
    ///
    /// Opens a terminal user interface where you can navigate through
    /// results using arrow keys and get detailed explanations for each
    /// metric. Press 'h' or '?' for contextual help on any section.
    ///
    /// Navigation:
    ///   ↑/↓ or j/k - Move between sections
    ///   h or ?     - Toggle help panel
    ///   q or Esc   - Exit
    #[arg(short, long)]
    interactive: bool,

    /// Run only specific checks (comma-separated)
    ///
    /// Available checks:
    ///   tls, http, headers, latency, discovery,
    ///   techstack, seo, aeo, content, topology, assets
    ///
    /// Examples:
    ///   --only tls,http           Run only TLS and HTTP checks
    ///   --only topology,assets    Run only topology and asset analysis
    ///   --only seo,aeo            Run only discoverability checks
    #[arg(long, value_name = "CHECKS", value_delimiter = ',')]
    only: Option<Vec<String>>,

    /// Skip TLS/SSL certificate checks
    ///
    /// When enabled, skips:
    ///   - Certificate chain validation
    ///   - Expiration date checking
    ///   - TLS version and cipher suite analysis
    ///   - ALPN protocol negotiation
    ///
    /// Use this for endpoints where TLS isn't relevant or when debugging
    /// other issues in isolation.
    #[arg(long)]
    skip_tls: bool,

    /// Skip HTTP protocol checks
    ///
    /// When enabled, skips:
    ///   - HTTP/2 support detection
    ///   - HTTP/3 (QUIC) advertisement checking
    ///   - Status code analysis
    ///   - Redirect chain following
    ///
    /// The main page fetch still occurs for other checks; this only
    /// skips protocol-specific analysis.
    #[arg(long)]
    skip_http: bool,

    /// Skip security header checks
    ///
    /// When enabled, skips analysis of:
    ///   - HSTS (Strict-Transport-Security)
    ///   - CSP (Content-Security-Policy)
    ///   - X-Frame-Options
    ///   - X-Content-Type-Options
    ///   - COOP/COEP (Cross-Origin policies)
    ///   - Referrer-Policy
    #[arg(long)]
    skip_headers: bool,

    /// Skip latency breakdown measurements
    ///
    /// When enabled, skips timing measurements for:
    ///   - DNS resolution time
    ///   - TCP connection time
    ///   - TLS handshake time
    ///   - Time to First Byte (TTFB)
    ///
    /// Useful when you're only interested in content/security analysis
    /// and not performance metrics.
    #[arg(long)]
    skip_latency: bool,

    /// Skip path and sitemap discovery
    ///
    /// When enabled, skips:
    ///   - robots.txt parsing
    ///   - sitemap.xml detection and parsing
    ///   - Common path probing (/api, /health, /.well-known/*)
    ///   - Well-known endpoint discovery
    ///
    /// Discovery makes multiple HTTP requests to standard paths.
    /// Skip this if you want faster scans or minimal requests.
    #[arg(long)]
    skip_discovery: bool,

    /// Skip technology stack detection
    ///
    /// When enabled, skips fingerprinting of:
    ///   - Web server (nginx, Apache, etc.)
    ///   - CDN (Cloudflare, Fastly, etc.)
    ///   - Frameworks (React, Next.js, Rails, etc.)
    ///   - CMS (WordPress, Drupal, etc.)
    ///   - JavaScript libraries and analytics
    ///
    /// Detection is passive (reads headers and HTML patterns).
    #[arg(long)]
    skip_techstack: bool,

    /// Skip SEO (Search Engine Optimization) analysis
    ///
    /// When enabled, skips analysis of:
    ///   - Title and meta description
    ///   - Canonical URLs
    ///   - Open Graph and Twitter Card tags
    ///   - Heading structure (H1-H6)
    ///   - Structured data (JSON-LD)
    ///   - Mobile-friendliness signals
    ///   - hreflang internationalization
    #[arg(long)]
    skip_seo: bool,

    /// Skip AEO (AI Engine Optimization) analysis
    ///
    /// When enabled, skips analysis of:
    ///   - Structured data depth (Schema.org types)
    ///   - llms.txt file detection
    ///   - AI plugin manifest (ai-plugin.json)
    ///   - robots.txt AI bot rules
    ///   - Content extractability scoring
    ///   - API discoverability (OpenAPI, GraphQL)
    #[arg(long)]
    skip_aeo: bool,

    /// Skip content analysis
    ///
    /// When enabled, skips:
    ///   - Content-Type validation and sniffing
    ///   - Response size analysis
    ///   - Compression detection (gzip, Brotli)
    ///   - Cache header analysis
    ///   - Character encoding validation
    ///   - Resource hint detection
    #[arg(long)]
    skip_content: bool,

    /// Skip topology/link spidering analysis
    ///
    /// When enabled, skips:
    ///   - Internal link discovery
    ///   - Site structure mapping
    ///   - Broken link detection
    ///   - Redirect chain analysis
    ///
    /// Topology makes multiple HTTP requests to discovered URLs.
    /// Skip this for faster scans.
    #[arg(long)]
    skip_topology: bool,

    /// Skip asset loading analysis
    ///
    /// When enabled, skips:
    ///   - Asset extraction (JS, CSS, images, fonts)
    ///   - Load time measurement
    ///   - Provenance classification (CDN, third-party)
    ///   - Cache header analysis for assets
    ///
    /// Asset analysis makes HTTP requests to each discovered asset.
    /// Skip this for faster scans.
    #[arg(long)]
    skip_assets: bool,

    /// Maximum URLs to spider for topology check
    ///
    /// Limits the number of internal URLs to probe during topology
    /// analysis. Higher values give more complete site maps but
    /// take longer. Default: 50
    #[arg(long, default_value = "50", value_name = "COUNT")]
    max_urls: usize,

    /// Maximum assets to analyze
    ///
    /// Limits the number of assets (JS, CSS, images, etc.) to
    /// analyze for timing and provenance. Higher values give more
    /// complete analysis but take longer. Default: 50
    #[arg(long, default_value = "50", value_name = "COUNT")]
    max_assets: usize,

    // ─────────────────────────────────────────────────────────────
    // Topology Configuration
    // ─────────────────────────────────────────────────────────────
    /// Include sitemap URLs in topology discovery
    ///
    /// When enabled, fetches sitemap.xml and includes those URLs
    /// in the topology analysis. Disable for faster scans.
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    topology_include_sitemap: bool,

    /// Follow and report external links in topology
    ///
    /// When enabled, counts external links found on the page
    /// (they are not probed, just counted).
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    topology_count_external: bool,

    // ─────────────────────────────────────────────────────────────
    // Assets Configuration
    // ─────────────────────────────────────────────────────────────
    /// Slow asset threshold in milliseconds
    ///
    /// Assets taking longer than this are flagged as slow.
    /// Default: 500ms
    #[arg(long, default_value = "500", value_name = "MS")]
    assets_slow_threshold: u64,

    /// Very slow asset threshold in milliseconds
    ///
    /// Assets taking longer than this are flagged as critical.
    /// Default: 2000ms
    #[arg(long, default_value = "2000", value_name = "MS")]
    assets_very_slow_threshold: u64,

    /// Large JavaScript threshold in KB
    ///
    /// JS files larger than this are flagged.
    /// Default: 100KB
    #[arg(long, default_value = "100", value_name = "KB")]
    assets_large_js_kb: u64,

    /// Large image threshold in KB
    ///
    /// Images larger than this are flagged.
    /// Default: 500KB
    #[arg(long, default_value = "500", value_name = "KB")]
    assets_large_image_kb: u64,

    /// Third-party warning threshold (percentage)
    ///
    /// Warn if more than this percentage of assets are third-party.
    /// Default: 50%
    #[arg(long, default_value = "50", value_name = "PERCENT")]
    assets_third_party_threshold: u64,

    /// Include font assets in analysis
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    assets_include_fonts: bool,

    /// Include media assets (video/audio) in analysis
    #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
    assets_include_media: bool,

    // ─────────────────────────────────────────────────────────────
    // Latency Configuration
    // ─────────────────────────────────────────────────────────────
    /// DNS lookup warning threshold in milliseconds
    #[arg(long, default_value = "100", value_name = "MS")]
    latency_dns_warn: u64,

    /// TCP connect warning threshold in milliseconds
    #[arg(long, default_value = "100", value_name = "MS")]
    latency_tcp_warn: u64,

    /// TLS handshake warning threshold in milliseconds
    #[arg(long, default_value = "200", value_name = "MS")]
    latency_tls_warn: u64,

    /// TTFB warning threshold in milliseconds
    #[arg(long, default_value = "500", value_name = "MS")]
    latency_ttfb_warn: u64,

    /// Connection timeout in seconds
    ///
    /// Maximum time to wait for each HTTP request. Applies to:
    ///   - Initial TLS connection
    ///   - Each discovery probe
    ///   - Main page fetch
    ///
    /// Increase for slow or distant servers. Decrease for faster
    /// failure detection.
    #[arg(short, long, default_value = "10", value_name = "SECONDS")]
    timeout: u64,

    /// Enable verbose debug output
    ///
    /// Shows detailed diagnostic information including:
    ///   - Individual request timing
    ///   - Header parsing details
    ///   - Pattern matching decisions
    ///
    /// Useful for debugging or understanding why a check failed.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    /// Colored, human-readable output with sections and issues
    Pretty,
    /// JSON output for automation, scripting, and CI/CD pipelines
    Json,
    /// Single-line summary for logs, dashboards, and monitoring
    Compact,
}

const EXTENDED_HELP: &str = r#"
WHAT SANGO CHECKS:

  TLS/SSL (--skip-tls to disable)
    Validates the certificate chain against trusted CAs, checks expiration,
    analyzes TLS version (1.2/1.3) and cipher suites, reports ALPN negotiation.
    WHY: Expired certs break trust, weak TLS enables attacks, ALPN indicates HTTP/2.

  HTTP Protocol (--skip-http to disable)
    Detects HTTP version, checks HTTP/2 support, looks for HTTP/3 advertisement,
    follows redirect chains.
    WHY: Modern protocols improve performance 30-50%, redirect chains add latency.

  Security Headers (--skip-headers to disable)
    Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, COOP/COEP.
    WHY: Missing headers enable XSS, clickjacking, and other attacks.

  Latency (--skip-latency to disable)
    Measures DNS lookup, TCP connect, TLS handshake, and Time to First Byte.
    WHY: Identifies which phase is slow - helps target optimization.

  Discovery (--skip-discovery to disable)
    Parses robots.txt, finds sitemaps, probes /api, /health, /.well-known/*.
    WHY: Validates crawler config, finds exposed endpoints, checks standards.

  Tech Stack (--skip-techstack to disable)
    Fingerprints server, CDN, frameworks, CMS from headers and HTML patterns.
    WHY: Identifies outdated/vulnerable software, confirms deployment config.

  SEO (--skip-seo to disable)
    Analyzes title, description, canonical, Open Graph, headings, structured data.
    WHY: Search engines drive 60%+ of traffic; these affect rankings.

  AEO (--skip-aeo to disable)
    Checks JSON-LD depth, llms.txt, ai-plugin.json, AI bot rules, extractability.
    WHY: AI-powered search is growing; structured data helps LLMs understand content.

  Content (--skip-content to disable)
    Validates Content-Type, checks compression, analyzes cache headers.
    WHY: Compression saves 60-80% bandwidth, caching reduces server load.

  Topology (--skip-topology to disable)
    Discovers internal links, builds site structure map, finds broken links.
    WHY: Identifies dead links, redirect chains, and site architecture.

  Assets (--skip-assets to disable)
    Analyzes JS, CSS, images, fonts - measures load time and provenance.
    WHY: Identifies slow/large assets, third-party dependencies, caching issues.

EXAMPLES:
    sango https://example.com              Full diagnostic scan
    sango example.com -f json              JSON output for scripting
    sango example.com -f compact           Single-line for monitoring
    sango example.com -i                   Interactive TUI mode
    sango example.com --skip-discovery     Faster scan, fewer requests
    sango example.com -t 30                30-second timeout for slow sites

    # Run only specific checks
    sango example.com --only tls,http,headers
    sango example.com --only topology,assets
    sango example.com --only seo,aeo

    # Deep topology scan (more URLs)
    sango example.com --only topology --max-urls 200

    # Deep asset analysis with custom thresholds
    sango example.com --only assets --max-assets 200 \
        --assets-slow-threshold 300 --assets-large-js-kb 50

    # Latency-focused scan with strict thresholds
    sango example.com --only latency \
        --latency-dns-warn 50 --latency-ttfb-warn 200

EXIT CODES:
    0 - Healthy or Degraded (low/medium severity issues only)
    1 - Unhealthy (critical or high severity issues found)
    2 - Unknown (probe failed to complete)

INTERACTIVE MODE (-i):
    Opens a terminal UI for exploring results. Navigate with arrow keys,
    press 'h' for contextual help explaining each metric.

MORE INFO:
    https://github.com/raskell-io/sango
"#;

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::DEBUG.into()),
            )
            .init();
    }

    // Handle --only flag: if specified, skip all checks except those listed
    let (
        skip_tls,
        skip_http,
        skip_headers,
        skip_latency,
        skip_discovery,
        skip_techstack,
        skip_seo,
        skip_aeo,
        skip_content,
        skip_topology,
        skip_assets,
    ) = if let Some(ref only_checks) = args.only {
        let checks: std::collections::HashSet<_> =
            only_checks.iter().map(|s| s.to_lowercase()).collect();
        (
            !checks.contains("tls"),
            !checks.contains("http"),
            !checks.contains("headers"),
            !checks.contains("latency"),
            !checks.contains("discovery"),
            !checks.contains("techstack"),
            !checks.contains("seo"),
            !checks.contains("aeo"),
            !checks.contains("content"),
            !checks.contains("topology"),
            !checks.contains("assets"),
        )
    } else {
        // Use explicit skip flags
        (
            args.skip_tls,
            args.skip_http,
            args.skip_headers,
            args.skip_latency,
            args.skip_discovery,
            args.skip_techstack,
            args.skip_seo,
            args.skip_aeo,
            args.skip_content,
            args.skip_topology,
            args.skip_assets,
        )
    };

    // Build probe config
    let config = ProbeConfig {
        skip_tls,
        skip_http,
        skip_headers,
        skip_latency,
        skip_discovery,
        skip_techstack,
        skip_seo,
        skip_aeo,
        skip_content,
        skip_topology,
        skip_assets,
        max_urls: args.max_urls,
        max_assets: args.max_assets,
        timeout: Duration::from_secs(args.timeout),
        // Topology configuration
        topology_include_sitemap: args.topology_include_sitemap,
        topology_count_external: args.topology_count_external,
        // Assets configuration
        assets_slow_threshold_ms: args.assets_slow_threshold,
        assets_very_slow_threshold_ms: args.assets_very_slow_threshold,
        assets_large_js_bytes: args.assets_large_js_kb * 1024,
        assets_large_image_bytes: args.assets_large_image_kb * 1024,
        assets_third_party_threshold: args.assets_third_party_threshold,
        assets_include_fonts: args.assets_include_fonts,
        assets_include_media: args.assets_include_media,
        // Latency configuration
        latency_dns_warn_ms: args.latency_dns_warn,
        latency_tcp_warn_ms: args.latency_tcp_warn,
        latency_tls_warn_ms: args.latency_tls_warn,
        latency_ttfb_warn_ms: args.latency_ttfb_warn,
    };

    // Run probe
    let result = probe::run_probe(&args.target, config).await?;

    // Output results
    if args.interactive {
        // Interactive TUI mode
        interactive::run_interactive(result)?;
        std::process::exit(0);
    } else {
        match args.format {
            OutputFormat::Pretty => {
                output::print_pretty(&result);
            }
            OutputFormat::Json => {
                println!("{}", output::print_json(&result));
            }
            OutputFormat::Compact => {
                println!("{}", output::print_compact(&result));
            }
        }

        // Exit with appropriate code
        match result.overall_health {
            probe::Health::Healthy => std::process::exit(0),
            probe::Health::Degraded => std::process::exit(0),
            probe::Health::Unhealthy => std::process::exit(1),
            probe::Health::Unknown => std::process::exit(2),
        }
    }
}
