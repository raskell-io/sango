use anyhow::Result;
use clap::Parser;
use std::time::Duration;

mod checks;
mod output;
mod probe;

use probe::ProbeConfig;

/// Sango - Operator-grade edge diagnostics
///
/// A read-only diagnostic CLI that tells you whether a web edge is sane,
/// observable, and survivable.
#[derive(Parser, Debug)]
#[command(name = "sango")]
#[command(author, version)]
#[command(about = "Operator-grade edge diagnostics", long_about = None)]
#[command(after_help = "EXAMPLES:
    sango https://example.com          Check an HTTPS endpoint
    sango example.com                  Check with default HTTPS port
    sango example.com:8443             Check custom port
    sango https://example.com -f json  Output as JSON
    sango https://example.com -v       Verbose output")]
struct Args {
    /// Target URL or hostname to diagnose
    ///
    /// Can be a full URL (https://example.com), hostname (example.com),
    /// or hostname with port (example.com:8443)
    #[arg(required = true, value_name = "TARGET")]
    target: String,

    /// Output format
    #[arg(short, long, default_value = "pretty", value_enum)]
    format: OutputFormat,

    /// Skip TLS certificate checks
    #[arg(long, help = "Skip TLS certificate and connection checks")]
    skip_tls: bool,

    /// Skip HTTP protocol checks
    #[arg(long, help = "Skip HTTP/2 and HTTP/3 protocol checks")]
    skip_http: bool,

    /// Skip security header checks
    #[arg(long, help = "Skip HSTS, CSP, and other security header checks")]
    skip_headers: bool,

    /// Connection timeout in seconds
    #[arg(short, long, default_value = "10", value_name = "SECONDS")]
    timeout: u64,

    /// Enable verbose output
    #[arg(short, long, help = "Show detailed diagnostic information")]
    verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    /// Colored, human-readable output
    Pretty,
    /// JSON output for automation
    Json,
    /// Single-line summary
    Compact,
}

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

    // Build probe config
    let config = ProbeConfig {
        skip_tls: args.skip_tls,
        skip_http: args.skip_http,
        skip_headers: args.skip_headers,
        timeout: Duration::from_secs(args.timeout),
    };

    // Run probe
    let result = probe::run_probe(&args.target, config).await?;

    // Output results
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
