# Sango Roadmap

From edge diagnostics to comprehensive web endpoint intelligence.

---

## Phase 1: Edge Health (Complete)

Foundation for all subsequent phases. Establishes the probe architecture and output formatting.

### Implemented
- [x] TLS diagnostics (chain, expiry, ciphers, ALPN)
- [x] HTTP protocol detection (HTTP/1.1, H2, H3)
- [x] Security headers analysis (HSTS, CSP, COOP/COEP, etc.)
- [x] Latency breakdown (DNS, TCP, TLS handshake, TTFB)
- [x] Output formats (pretty, JSON, compact)
- [x] CLI with skip flags and timeout configuration

---

## Phase 2: Content Intelligence

Understand what an endpoint serves and how it's structured.

### 2.1 Subpath Discovery
Discover the structure of a web property without invasive crawling.

**Implementation: `src/checks/discovery.rs`**

- [ ] Parse and analyze `robots.txt`
  - Extract allowed/disallowed paths
  - Identify sitemap references
  - Detect crawl-delay directives
- [ ] Parse `sitemap.xml` and sitemap index files
  - Extract URL list with lastmod dates
  - Handle gzipped sitemaps
  - Respect sitemap limits (50k URLs)
- [ ] Probe common paths (configurable)
  - `/api`, `/graphql`, `/health`, `/metrics`
  - `/.well-known/*` endpoints
  - `/favicon.ico`, `/manifest.json`
- [ ] Report discovered structure
  - Path tree visualization
  - Response codes per path
  - Content-type distribution

### 2.2 Content Analysis
Analyze what's actually served at each discovered path.

**Implementation: `src/checks/content.rs`**

- [ ] Content-type detection
  - MIME type from headers
  - Actual content sniffing for mismatches
  - Charset detection
- [ ] Response analysis
  - Size (raw and compressed)
  - Compression ratio and algorithm
  - Cache headers (age, max-age, etag)
- [ ] Redirect chain analysis
  - Hop count and destinations
  - HTTP vs HTTPS redirects
  - Redirect loops detection
- [ ] Resource hints
  - Preload/prefetch directives
  - Resource priorities

### Deliverables
- New CLI flags: `--discover`, `--content-analysis`
- Discovery report section in output
- Content summary table

---

## Phase 3: Technology Detection

Fingerprint the technology stack powering an endpoint.

### 3.1 Server & Infrastructure
**Implementation: `src/checks/techstack.rs`**

- [ ] Server identification
  - Parse `Server` header
  - Fingerprint by behavior (error pages, defaults)
  - Version detection where exposed
- [ ] CDN detection
  - Cloudflare, Fastly, Akamai, CloudFront, Vercel, Netlify
  - Edge location identification
  - Cache status headers
- [ ] Hosting signals
  - IP geolocation (continent/country)
  - ASN identification
  - Cloud provider detection (AWS, GCP, Azure)

### 3.2 Application Stack
- [ ] Framework fingerprinting
  - Next.js, Nuxt, Remix, SvelteKit (SSR frameworks)
  - Rails, Django, Laravel, Express (backend)
  - React, Vue, Angular (SPA indicators)
- [ ] CMS detection
  - WordPress, Drupal, Ghost, Contentful
  - Headless CMS indicators
- [ ] JavaScript library detection
  - Major libraries from script patterns
  - Build tool signatures (Webpack, Vite, esbuild)
- [ ] API technology hints
  - GraphQL introspection (if enabled)
  - REST/OpenAPI indicators
  - gRPC-Web detection

### 3.3 Fingerprint Database
- [ ] Create extensible fingerprint format (YAML/TOML)
- [ ] Header patterns
- [ ] HTML/JS patterns
- [ ] Cookie patterns
- [ ] Error page signatures

### Deliverables
- Tech stack summary section
- Confidence scores per detection
- Version information where available
- `--techstack` flag for isolated runs

---

## Phase 4: Discoverability Assessment

Evaluate how well the endpoint is optimized for search engines and AI agents.

### 4.1 SEO Analysis
**Implementation: `src/checks/seo.rs`**

- [ ] Meta tags audit
  - Title (length, presence, uniqueness hint)
  - Description (length, presence)
  - Canonical URL
  - Robots meta directives
- [ ] Open Graph / Social
  - og:title, og:description, og:image
  - Twitter Card metadata
  - Image dimensions and accessibility
- [ ] Technical SEO
  - Mobile viewport configuration
  - Structured heading hierarchy (H1-H6)
  - Internal linking signals
  - Hreflang for internationalization
- [ ] Performance signals
  - Core Web Vitals hints (from headers/resource loading)
  - Render-blocking resources
  - Image optimization signals

### 4.2 AEO (AI Engine Optimization)
**Implementation: `src/checks/aeo.rs`**

Prepare endpoints for the age of AI agents and LLM-powered search.

- [ ] Structured data analysis
  - JSON-LD presence and validity
  - Schema.org types used
  - Rich snippet eligibility
- [ ] AI-readiness signals
  - `llms.txt` detection and parsing
  - `.well-known/ai-plugin.json` (ChatGPT plugins)
  - Clean, extractable content structure
- [ ] Content accessibility
  - Text-to-markup ratio
  - Semantic HTML usage
  - Accessibility hints (alt text, ARIA)
- [ ] API discoverability
  - OpenAPI/Swagger documentation
  - GraphQL schema exposure
  - Developer documentation links

### Deliverables
- SEO score with breakdown
- AEO readiness rating
- Prioritized recommendations
- `--seo` and `--aeo` flags

---

## Phase 5: Polish & Ecosystem

Make Sango production-ready and integrate with the broader ecosystem.

### 5.1 Output Enhancements
- [ ] HTML report output (`-f html`)
- [ ] Markdown report output (`-f markdown`)
- [ ] Diff mode for before/after comparisons
- [ ] Baseline/threshold configuration

### 5.2 Performance
- [ ] Connection pooling for multi-path probes
- [ ] Parallel check execution tuning
- [ ] Result caching for repeated runs
- [ ] Streaming output for long-running checks

### 5.3 Configuration
- [ ] Config file support (`.sango.toml`)
- [ ] Custom fingerprint rules
- [ ] Ignore patterns for known issues
- [ ] Severity threshold customization

### 5.4 Integration
- [ ] GitHub Actions workflow
- [ ] Pre-commit hook support
- [ ] CI/CD exit code conventions
- [ ] Webhook notifications

---

## Success Metrics

Sango should enable users to answer these questions with a single command:

1. **Is this endpoint healthy?** - TLS valid, protocols modern, headers secure
2. **What does this endpoint serve?** - Content types, structure, paths
3. **What technology powers it?** - Server, framework, CDN, CMS
4. **How discoverable is it?** - SEO score, AEO readiness, structured data
5. **What should I fix first?** - Prioritized, actionable recommendations

---

## Non-Goals

- **Crawling**: Sango probes, it doesn't crawl. Discovery is bounded.
- **Vulnerability scanning**: Security headers yes, CVE detection no.
- **Performance testing**: Latency measurement yes, load testing no.
- **Monitoring**: Point-in-time assessment, not continuous monitoring.
- **Mutation**: Sango never writes, posts, or modifies anything.

---

## Contributing

Each phase is designed to be implemented incrementally. New check modules follow the established pattern:

1. Create `src/checks/{name}.rs`
2. Define result struct with `issues: Vec<Issue>`
3. Implement async check function
4. Add to probe orchestration
5. Add output formatting
6. Add CLI flags
7. Write tests

See existing check modules for reference implementations.
