//! tragach-pageio — engine page-I/O correlated with block-device latency.
//! See SPECS.md §5.4.

mod symbols;

use anyhow::{Context, Result, anyhow, bail};
use aya::maps::{Array as AyaArray, MapData, PerCpuArray as AyaPerCpuArray, PerCpuValues};
use aya::programs::{TracePoint, UProbe};
use aya::{Ebpf, include_bytes_aligned};
use chrono::{DateTime, Utc};
use clap::Parser;
use log::{info, warn};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Per-window aggregate counters. Layout must match the BPF-side struct in
/// `crates/tragach-pageio/src/bpf/main.rs` — read by raw bytes from the
/// per-CPU array.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PageIoCounters {
    engine_count: u64,
    engine_total_ns: u64,
    engine_max_ns: u64,
    block_count: u64,
    block_total_bytes: u64,
    block_total_wait_ns: u64,
    block_max_wait_ns: u64,
}
// SAFETY: PageIoCounters is `#[repr(C)]` and contains only `u64` fields — POD.
unsafe impl aya::Pod for PageIoCounters {}

#[derive(Debug, Parser)]
#[command(name = "tragach-pageio", version, about = "Engine-to-block-device page-I/O correlation for Firebird", long_about = None)]
struct Args {
    /// Firebird worker PID. If unset, resolved via `pgrep -x firebird`.
    #[arg(long)]
    pid: Option<u32>,

    /// Flush interval — every <duration>, emit a window summary.
    #[arg(long, default_value = "10s")]
    interval: humantime::Duration,

    /// Firebird install root.
    #[arg(long, default_value = "/opt/firebird-v5")]
    firebird_prefix: PathBuf,

    /// Override the debug-symbols file path (same convention as slowquery).
    #[arg(long)]
    debug_path: Option<PathBuf>,

    /// Emit JSON Lines instead of human-readable output.
    #[arg(long)]
    json: bool,
}

static BPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tragach-pageio"));

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let pid = match args.pid {
        Some(p) => p,
        None => resolve_firebird_pid()?,
    };
    info!("targeting Firebird PID {pid}");

    let libengine = args.firebird_prefix.join("plugins/libEngine13.so");
    let debug_path = args
        .debug_path
        .clone()
        .unwrap_or_else(|| args.firebird_prefix.join("plugins/.debug/libEngine13.so.debug"));
    ensure_paths(&libengine, &debug_path)?;

    let offsets = symbols::resolve(&debug_path)
        .with_context(|| format!("resolving CCH_fetch_page in {}", debug_path.display()))?;
    info!("resolved CCH_fetch_page = 0x{:x}", offsets.cch_fetch_page);

    if let Err(e) = raise_rlimit_memlock() {
        warn!("RLIMIT_MEMLOCK raise failed ({e}) — continuing");
    }

    let mut bpf = Ebpf::load(BPF_OBJECT).context("loading BPF object")?;

    // Set TARGET_TGID before attaching probes so early events don't get past
    // the filter with a zero target.
    {
        let mut target: AyaArray<&mut MapData, u32> = AyaArray::try_from(
            bpf.map_mut("TARGET_TGID").ok_or_else(|| anyhow!("TARGET_TGID missing"))?,
        )?;
        target.set(0, pid, 0)?;
    }

    // CCH_fetch_page uprobe + uretprobe.
    attach_uprobe(&mut bpf, "cch_fetch_page_entry", offsets.cch_fetch_page, &libengine)?;
    attach_uprobe(&mut bpf, "cch_fetch_page_exit", offsets.cch_fetch_page, &libengine)?;

    // block_rq_issue / block_rq_complete tracepoints.
    let issue: &mut TracePoint = bpf
        .program_mut("block_rq_issue")
        .ok_or_else(|| anyhow!("block_rq_issue program missing"))?
        .try_into()?;
    issue.load()?;
    issue.attach("block", "block_rq_issue")?;

    let complete: &mut TracePoint = bpf
        .program_mut("block_rq_complete")
        .ok_or_else(|| anyhow!("block_rq_complete program missing"))?
        .try_into()?;
    complete.load()?;
    complete.attach("block", "block_rq_complete")?;

    info!(
        "attached CCH_fetch_page (uprobe+uretprobe) + block_rq_issue + block_rq_complete; \
         flushing every {}",
        args.interval
    );

    let counters_map = bpf
        .take_map("COUNTERS")
        .ok_or_else(|| anyhow!("COUNTERS map missing"))?;
    let counters: AyaPerCpuArray<MapData, PageIoCounters> = AyaPerCpuArray::try_from(counters_map)?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut tick = tokio::time::interval(args.interval.into());
    tick.tick().await; // skip immediate first tick

    let mut prev_snapshot = PageIoCounters::default();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ntragach-pageio: shutting down");
                return Ok(());
            }
            _ = tick.tick() => {
                let snapshot = snapshot_counters(&counters)?;
                let delta = delta_counters(&prev_snapshot, &snapshot);
                prev_snapshot = snapshot;
                let window_ms = args.interval.as_millis() as u64;
                if args.json {
                    write_json(&mut out, &delta, window_ms, pid)?;
                } else {
                    write_human(&mut out, &delta, window_ms, pid)?;
                }
            }
        }
    }
}

fn resolve_firebird_pid() -> Result<u32> {
    let out = Command::new("pgrep").args(["-x", "firebird"]).output()
        .context("running pgrep -x firebird")?;
    if !out.status.success() {
        bail!("pgrep -x firebird found nothing; pass --pid");
    }
    let text = std::str::from_utf8(&out.stdout).context("pgrep output not UTF-8")?;
    let pid: u32 = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("empty pgrep output"))?
        .parse()
        .context("parsing pgrep PID")?;
    Ok(pid)
}

fn ensure_paths(libengine: &Path, debug: &Path) -> Result<()> {
    if !libengine.exists() {
        bail!(
            "libEngine13.so not found at {} — pass --firebird-prefix",
            libengine.display()
        );
    }
    if !debug.exists() {
        bail!(
            "debug symbols not found at {} — pass --debug-path to relocate, or \
             install a firebird debug package.",
            debug.display()
        );
    }
    Ok(())
}

fn attach_uprobe(bpf: &mut Ebpf, prog_name: &str, offset: u64, target: &Path) -> Result<()> {
    let prog: &mut UProbe = bpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program {prog_name} missing"))?
        .try_into()?;
    prog.load()?;
    prog.attach(None, offset, target, None)
        .with_context(|| format!("attaching {prog_name} at offset 0x{offset:x}"))?;
    info!("attached {prog_name} at offset 0x{offset:x}");
    Ok(())
}

fn raise_rlimit_memlock() -> Result<()> {
    #[repr(C)]
    struct Rl { cur: u64, max: u64 }
    const RLIMIT_MEMLOCK: i32 = 8;
    unsafe extern "C" {
        fn setrlimit(resource: i32, rlim: *const Rl) -> i32;
    }
    let rl = Rl { cur: u64::MAX, max: u64::MAX };
    let rc = unsafe { setrlimit(RLIMIT_MEMLOCK, &rl) };
    if rc != 0 { return Err(anyhow!("setrlimit rc={rc}")); }
    Ok(())
}

/// Sum per-CPU counter slots into a single PageIoCounters. `*_max` fields take
/// the max across CPUs rather than the sum.
fn snapshot_counters(
    counters: &AyaPerCpuArray<MapData, PageIoCounters>,
) -> Result<PageIoCounters> {
    let per_cpu: PerCpuValues<PageIoCounters> = counters
        .get(&0, 0)
        .context("reading COUNTERS per-cpu values")?;
    let mut out = PageIoCounters::default();
    for c in per_cpu.iter() {
        out.engine_count = out.engine_count.wrapping_add(c.engine_count);
        out.engine_total_ns = out.engine_total_ns.wrapping_add(c.engine_total_ns);
        if c.engine_max_ns > out.engine_max_ns {
            out.engine_max_ns = c.engine_max_ns;
        }
        out.block_count = out.block_count.wrapping_add(c.block_count);
        out.block_total_bytes = out.block_total_bytes.wrapping_add(c.block_total_bytes);
        out.block_total_wait_ns = out.block_total_wait_ns.wrapping_add(c.block_total_wait_ns);
        if c.block_max_wait_ns > out.block_max_wait_ns {
            out.block_max_wait_ns = c.block_max_wait_ns;
        }
    }
    Ok(out)
}

/// Per-window delta from cumulative snapshots. Max fields aren't deltaable;
/// we just take the current snapshot's max (best-effort window-local view).
fn delta_counters(prev: &PageIoCounters, now: &PageIoCounters) -> PageIoCounters {
    PageIoCounters {
        engine_count: now.engine_count.wrapping_sub(prev.engine_count),
        engine_total_ns: now.engine_total_ns.wrapping_sub(prev.engine_total_ns),
        engine_max_ns: now.engine_max_ns,
        block_count: now.block_count.wrapping_sub(prev.block_count),
        block_total_bytes: now.block_total_bytes.wrapping_sub(prev.block_total_bytes),
        block_total_wait_ns: now.block_total_wait_ns.wrapping_sub(prev.block_total_wait_ns),
        block_max_wait_ns: now.block_max_wait_ns,
    }
}

fn fmt_dur_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2}s", ns as f64 / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.2}ms", ns as f64 / 1e6)
    } else if ns >= 1_000 {
        format!("{}us", ns / 1_000)
    } else {
        format!("{}ns", ns)
    }
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.2} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.2} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1 << 10 {
        format!("{:.2} kB", b as f64 / (1u64 << 10) as f64)
    } else {
        format!("{} B", b)
    }
}

fn write_human<W: std::io::Write>(
    w: &mut W,
    c: &PageIoCounters,
    window_ms: u64,
    pid: u32,
) -> Result<()> {
    let ts: DateTime<Utc> = chrono::Utc::now();
    writeln!(
        w,
        "=== tragach-pageio  {} window  pid={} ===",
        humantime::format_duration(std::time::Duration::from_millis(window_ms)),
        pid,
    )?;
    if c.engine_count == 0 && c.block_count == 0 {
        writeln!(w, "  (no page-I/O activity in this window)  [{}]", ts.format("%H:%M:%S"))?;
        writeln!(w)?;
        w.flush().ok();
        return Ok(());
    }

    let engine_avg = if c.engine_count > 0 { c.engine_total_ns / c.engine_count } else { 0 };
    let block_avg = if c.block_count > 0 {
        c.block_total_wait_ns / c.block_count.max(1)
    } else {
        0
    };
    writeln!(w, "Engine page reads (cache misses):")?;
    writeln!(w, "  count               : {}", c.engine_count)?;
    writeln!(w, "  total wait          : {}", fmt_dur_ns(c.engine_total_ns))?;
    writeln!(
        w,
        "  avg / max per call  : {} / {}",
        fmt_dur_ns(engine_avg),
        fmt_dur_ns(c.engine_max_ns)
    )?;
    writeln!(w, "Block-device I/O (filtered to Firebird tgid):")?;
    writeln!(w, "  requests            : {}", c.block_count)?;
    writeln!(w, "  total bytes         : {}", fmt_bytes(c.block_total_bytes))?;
    writeln!(w, "  total wait          : {}", fmt_dur_ns(c.block_total_wait_ns))?;
    writeln!(
        w,
        "  avg / max per req   : {} / {}",
        fmt_dur_ns(block_avg),
        fmt_dur_ns(c.block_max_wait_ns)
    )?;
    if c.engine_total_ns > 0 {
        let ratio = c.block_total_wait_ns as f64 / c.engine_total_ns as f64;
        writeln!(
            w,
            "Ratio block/engine    : {:.2}  (1.0 = engine wait dominated by disk; <1.0 = cache/coord overhead)",
            ratio
        )?;
    }
    writeln!(w)?;
    w.flush().ok();
    Ok(())
}

#[derive(Serialize)]
struct JsonWindow {
    ts: String,
    window_ms: u64,
    pid: u32,
    engine: EngineStats,
    block: BlockStats,
}

#[derive(Serialize)]
struct EngineStats {
    count: u64,
    total_ns: u64,
    avg_ns: u64,
    max_ns: u64,
}

#[derive(Serialize)]
struct BlockStats {
    count: u64,
    total_bytes: u64,
    total_wait_ns: u64,
    avg_wait_ns: u64,
    max_wait_ns: u64,
}

fn write_json<W: std::io::Write>(
    w: &mut W,
    c: &PageIoCounters,
    window_ms: u64,
    pid: u32,
) -> Result<()> {
    let ts: DateTime<Utc> = chrono::Utc::now();
    let engine_avg = if c.engine_count > 0 { c.engine_total_ns / c.engine_count } else { 0 };
    let block_avg = if c.block_count > 0 { c.block_total_wait_ns / c.block_count } else { 0 };
    let json = JsonWindow {
        ts: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        window_ms,
        pid,
        engine: EngineStats {
            count: c.engine_count,
            total_ns: c.engine_total_ns,
            avg_ns: engine_avg,
            max_ns: c.engine_max_ns,
        },
        block: BlockStats {
            count: c.block_count,
            total_bytes: c.block_total_bytes,
            total_wait_ns: c.block_total_wait_ns,
            avg_wait_ns: block_avg,
            max_wait_ns: c.block_max_wait_ns,
        },
    };
    serde_json::to_writer(&mut *w, &json)?;
    writeln!(w)?;
    Ok(())
}
