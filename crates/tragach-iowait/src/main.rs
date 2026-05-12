//! tragach-iowait — off-CPU profiling of Firebird threads via sched tracepoints.
//! See SPECS.md §5.2.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "tragach-iowait", version, about = "Off-CPU profiling for Firebird", long_about = None)]
struct Args {
    /// Firebird PID. If unset, resolved at startup from the systemd unit
    /// state (firebird.service) or by walking /proc.
    #[arg(long)]
    pid: Option<u32>,

    /// Flush interval — every <duration>, emit a summary of off-CPU buckets.
    #[arg(long, default_value = "10s")]
    interval: humantime::Duration,

    /// Number of representative kernel stacks to print per bucket.
    #[arg(long, default_value_t = 3)]
    top_stacks: u32,

    /// Emit JSON Lines instead of human-readable output.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let _args = Args::parse();
    anyhow::bail!(
        "tragach-iowait: skeleton only — sched_switch/sched_wakeup wiring \
         lands in the iowait implementation pass (SPECS.md §5.2)"
    );
}
