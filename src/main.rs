use anyhow::Result;
use clap::Parser;

mod checks;
mod output;
mod probe;

#[derive(Parser, Debug)]
#[command(name = "sango")]
#[command(author, version, about = "Operator-grade edge diagnostics", long_about = None)]
struct Args {
    /// Target URL or hostname to diagnose
    #[arg(required = true)]
    target: String,

    /// Output format
    #[arg(short, long, default_value = "pretty")]
    format: OutputFormat,

    /// Skip TLS checks
    #[arg(long, default_value = "false")]
    skip_tls: bool,

    /// Skip HTTP checks
    #[arg(long, default_value = "false")]
    skip_http: bool,

    /// Skip security header checks
    #[arg(long, default_value = "false")]
    skip_headers: bool,

    /// Connection timeout in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,

    /// Verbose output
    #[arg(short, long, default_value = "false")]
    verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
    Compact,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(if args.verbose {
                    tracing::Level::DEBUG.into()
                } else {
                    tracing::Level::INFO.into()
                }),
        )
        .init();

    println!("sango - edge diagnostics");
    println!("Target: {}", args.target);
    println!();
    println!("Coming soon: TLS, HTTP/3, security headers, WAF signals, latency analysis");

    Ok(())
}
