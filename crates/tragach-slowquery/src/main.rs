//! tragach-slowquery — DSQL statement tracing for Firebird via eBPF uprobes.
//! See SPECS.md §5.1.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "tragach-slowquery", version, about = "DSQL statement tracing for Firebird", long_about = None)]
struct Args {
    /// Only emit events whose execute duration exceeds this threshold (e.g. 100ms).
    #[arg(long)]
    threshold: Option<humantime::Duration>,

    /// Emit JSON Lines instead of human-readable output.
    #[arg(long)]
    json: bool,

    /// Firebird install root. Probes attach against
    /// `<prefix>/plugins/libEngine13.so`.
    #[arg(long, default_value = "/opt/firebird-v5")]
    firebird_prefix: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let _args = Args::parse();
    anyhow::bail!(
        "tragach-slowquery: skeleton only — probe attachment lands in the \
         slowquery implementation pass (SPECS.md §5.1)"
    );
}
