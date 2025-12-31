# Sango - Comprehensive Web Endpoint Intelligence

## Purpose

Sango is a read-only diagnostic CLI that provides comprehensive intelligence about web endpoints. Beyond basic edge health checks, Sango answers: "What is this endpoint, how healthy is it, and what should be improved?"

## Vision

Sango aims to be the single command operators and developers run to understand everything about a web endpoint:
- **Infrastructure health** - TLS, protocols, latency
- **Security posture** - Headers, policies, vulnerabilities
- **Content intelligence** - What's served, in what format, from where
- **Technology fingerprinting** - What stack powers this endpoint
- **Discoverability** - SEO/AEO readiness for search and AI agents

## Architecture

```
src/
├── main.rs              # CLI entry point (clap)
├── probe.rs             # Probe orchestration
├── output.rs            # Output formatting (pretty/json/compact)
└── checks/
    ├── mod.rs           # Check module exports
    │
    │  # Phase 1: Edge Health (implemented)
    ├── tls.rs           # TLS chain, expiry, OCSP, ciphers, ALPN
    ├── http.rs          # HTTP/1.1, H2, H3 detection
    ├── headers.rs       # Security headers (HSTS, CSP, COOP/COEP)
    ├── latency.rs       # DNS, TCP, TLS, TTFB breakdown
    │
    │  # Phase 2: Content Intelligence
    ├── discovery.rs     # Subpath and resource discovery
    ├── content.rs       # Content-type detection and analysis
    │
    │  # Phase 3: Technology Detection
    ├── techstack.rs     # Framework, server, CDN fingerprinting
    │
    │  # Phase 4: Discoverability
    ├── seo.rs           # SEO signals (meta, structure, performance)
    └── aeo.rs           # AEO signals (structured data, AI-readiness)
```

## Design Principles

1. **Read-only**: No mutations, no agents, no config access
2. **Safe for production**: All probes are standard HTTP/TLS operations
3. **Opinionated output**: Judgments with actionable recommendations
4. **Operator-focused**: Answers "what should I fix first?"
5. **Composable**: Each check module is independent and skippable
6. **Fast by default**: Parallel execution, smart caching

## Check Categories

### Edge Health (Phase 1 - Complete)
- TLS certificate chain validation
- Protocol support (HTTP/1.1, H2, H3)
- Security headers analysis
- Latency breakdown (DNS, TCP, TLS, TTFB)

### Content Intelligence (Phase 2)
- Subpath discovery (robots.txt, sitemap.xml, common paths)
- Content-type detection per resource
- Response size and compression analysis
- Redirect chain analysis

### Technology Detection (Phase 3)
- Server identification (nginx, Apache, Cloudflare, etc.)
- Framework fingerprinting (Next.js, Rails, Django, etc.)
- CDN detection (Cloudflare, Fastly, Akamai, etc.)
- CMS identification (WordPress, Drupal, etc.)

### Discoverability (Phase 4)
- **SEO**: Meta tags, Open Graph, canonical URLs, mobile-friendliness
- **AEO**: Schema.org markup, AI-friendly structure, llms.txt

## Key Dependencies

### Current
- `rustls` + `x509-parser`: TLS inspection
- `reqwest` + `hyper`: HTTP client
- `hickory-resolver`: DNS resolution
- `clap`: CLI framework
- `colored` + `tabled`: Pretty output

### Planned
- `scraper`: HTML parsing for tech detection
- `regex`: Pattern matching for fingerprinting
- `quick-xml`: Sitemap and structured data parsing

## Implementation Notes

- All checks are async and run concurrently where possible
- Each check module returns a structured result with issues list
- Severity levels: Info, Low, Medium, High, Critical
- Output formats: pretty (default), json, compact
- Exit codes: 0 (healthy/degraded), 1 (unhealthy), 2 (unknown)

## Testing Strategy

- Unit tests for parsing and analysis logic
- Integration tests using wiremock for HTTP mocking
- Snapshot tests for fingerprint databases
- No network tests in CI (use explicit integration test flag)

## CLI Usage

```bash
# Full assessment
sango https://example.com

# Specific checks only
sango https://example.com --only tls,headers
sango https://example.com --only seo,aeo

# Skip expensive checks
sango https://example.com --skip discovery,techstack

# Output formats
sango https://example.com -f json
sango https://example.com -f compact
```
