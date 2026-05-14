//! tragach-iowait — off-CPU profiling of Firebird via sched tracepoints.
//! See SPECS.md §5.2 and docs/design-notes.md.

mod classify;
mod kallsyms;

use anyhow::{Context, Result, anyhow, bail};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, StackTraceMap};
use aya::programs::TracePoint;
use aya::{Ebpf, include_bytes_aligned};
use chrono::Utc;
use clap::Parser;
use classify::{Reason, classify};
use kallsyms::Kallsyms;
use log::{info, warn};
use serde::Serialize;
use std::collections::HashMap as StdHashMap;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "tragach-iowait", version, about = "Off-CPU profiling for Firebird", long_about = None)]
struct Args {
    /// Firebird worker PID. If unset, resolved via `pgrep -x firebird`.
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

    /// Suppress idle-worker buckets at flush time. SuperServer worker threads
    /// sleeping in `futex_wait` accumulate `N_workers × window × idle_fraction`
    /// of off-CPU time regardless of workload — without filtering, futex
    /// dominates every iowait window. With this flag set, any (pid, stack_id)
    /// bucket whose total exceeds `--idle-threshold` of the window is dropped
    /// before reason classification. See SPECS.md §5.2.
    #[arg(long)]
    exclude_idle: bool,

    /// Fraction of the window above which a single-thread-single-stack bucket
    /// counts as "idle." Range 0.0-1.0. Default 0.50 — validated against
    /// SuperServer worker-pool behavior: workers accumulate ~63% of the window
    /// in `futex_wait_queue`, the accept thread ~85% in `do_sys_poll`, so 0.50
    /// catches both. Truly busy threads alternate between work and waits and
    /// stay well below 50% in any single bucket. Ignored unless --exclude-idle.
    #[arg(long, default_value_t = 0.50)]
    idle_threshold: f64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct BucketKey {
    pid: u32,
    stack_id: i32,
}
// SAFETY: BucketKey is #[repr(C)] all-POD with no padding; layout matches the BPF map's key type exactly.
unsafe impl aya::Pod for BucketKey {}

static BPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tragach-iowait"));

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let pid = match args.pid {
        Some(p) => p,
        None => resolve_firebird_pid()?,
    };
    info!("targeting Firebird PID {pid}");

    let kallsyms = Kallsyms::load("/proc/kallsyms")
        .context("loading /proc/kallsyms (run as root for symbol addresses)")?;
    info!("loaded {} kernel symbols", kallsyms.len());

    if let Err(e) = raise_rlimit_memlock() {
        warn!("RLIMIT_MEMLOCK raise failed ({e}) — continuing");
    }

    let mut bpf = Ebpf::load(BPF_OBJECT).context("loading BPF object")?;

    {
        let mut target: AyaArray<&mut MapData, u32> = AyaArray::try_from(
            bpf.map_mut("TARGET_TGID").ok_or_else(|| anyhow!("TARGET_TGID missing"))?,
        )?;
        target.set(0, pid, 0)?;
    }

    let sched_switch: &mut TracePoint = bpf
        .program_mut("sched_switch")
        .ok_or_else(|| anyhow!("sched_switch program missing"))?
        .try_into()?;
    sched_switch.load()?;
    sched_switch.attach("sched", "sched_switch")?;

    let sched_wakeup: &mut TracePoint = bpf
        .program_mut("sched_wakeup")
        .ok_or_else(|| anyhow!("sched_wakeup program missing"))?
        .try_into()?;
    sched_wakeup.load()?;
    sched_wakeup.attach("sched", "sched_wakeup")?;

    info!("attached sched_switch + sched_wakeup; flushing every {}", args.interval);

    let buckets_map = bpf
        .take_map("BUCKETS")
        .ok_or_else(|| anyhow!("BUCKETS map missing"))?;
    let stacks_map = bpf
        .take_map("STACKS")
        .ok_or_else(|| anyhow!("STACKS map missing"))?;
    let mut buckets: AyaHashMap<MapData, BucketKey, u64> = AyaHashMap::try_from(buckets_map)?;
    let stacks: StackTraceMap<MapData> = StackTraceMap::try_from(stacks_map)?;

    let mut tick = tokio::time::interval(args.interval.into());
    tick.tick().await; // skip the immediate first tick

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ntragach-iowait: stopping");
                return Ok(());
            }
            _ = tick.tick() => {
                flush_window(
                    &mut buckets,
                    &stacks,
                    &kallsyms,
                    args.interval.into(),
                    pid,
                    args.top_stacks,
                    args.json,
                    args.exclude_idle,
                    args.idle_threshold,
                    &mut out,
                )?;
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
    let pid: u32 = text.split_whitespace().next()
        .ok_or_else(|| anyhow!("empty pgrep output"))?
        .parse()
        .context("parsing pgrep PID")?;
    Ok(pid)
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

#[derive(Default)]
struct ReasonAgg {
    total_ns: u64,
    pids: std::collections::HashSet<u32>,
    /// stack_id → (total_ns, top_frame_name)
    by_stack: StdHashMap<i32, (u64, Vec<String>)>,
}

#[derive(Serialize)]
struct JsonWindow<'a> {
    ts: String,
    window_ms: u64,
    pid: u32,
    /// Number of (pid, stack_id) buckets dropped by --exclude-idle this window.
    /// `0` when --exclude-idle is off.
    excluded_idle_buckets: usize,
    by_reason: StdHashMap<&'a str, JsonReason<'a>>,
}

#[derive(Serialize)]
struct JsonReason<'a> {
    total_ms: u64,
    threads: usize,
    top_stacks: Vec<JsonStack<'a>>,
}

#[derive(Serialize)]
struct JsonStack<'a> {
    ms: u64,
    frames: &'a [String],
}

fn flush_window<W: std::io::Write>(
    buckets: &mut AyaHashMap<MapData, BucketKey, u64>,
    stacks: &StackTraceMap<MapData>,
    kallsyms: &Kallsyms,
    window: Duration,
    pid: u32,
    top_stacks: u32,
    json: bool,
    exclude_idle: bool,
    idle_threshold: f64,
    out: &mut W,
) -> Result<()> {
    // Drain BUCKETS atomically-ish: snapshot keys+values, then delete each key.
    let mut snapshot: Vec<(BucketKey, u64)> = Vec::new();
    for entry in buckets.iter() {
        let (k, v) = entry?;
        snapshot.push((k, v));
    }
    for (k, _) in &snapshot {
        let _ = buckets.remove(k);
    }

    // Idle-bucket filter — drop (pid, stack_id) entries whose ns exceeds
    // idle_threshold × window. See SPECS.md §5.2.
    let mut excluded_idle: usize = 0;
    if exclude_idle {
        let window_ns = window.as_nanos() as f64;
        let threshold_ns = (window_ns * idle_threshold) as u64;
        let before = snapshot.len();
        snapshot.retain(|(_, ns)| *ns < threshold_ns);
        excluded_idle = before - snapshot.len();
    }

    let mut by_reason: StdHashMap<Reason, ReasonAgg> = StdHashMap::new();

    for (key, ns) in &snapshot {
        let frames = if key.stack_id >= 0 {
            match stacks.get(&(key.stack_id as u32), 0) {
                Ok(st) => st.frames().iter().map(|f| kallsyms.lookup(f.ip)).collect::<Vec<_>>(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let reason = classify(&frames);
        let agg = by_reason.entry(reason).or_default();
        agg.total_ns = agg.total_ns.saturating_add(*ns);
        agg.pids.insert(key.pid);
        let stack_entry = agg.by_stack.entry(key.stack_id).or_insert_with(|| (0, frames));
        stack_entry.0 = stack_entry.0.saturating_add(*ns);
    }

    if json {
        let mut by_reason_json: StdHashMap<&str, JsonReason> = StdHashMap::new();
        for (reason, agg) in &by_reason {
            let mut top: Vec<(&i32, &(u64, Vec<String>))> = agg.by_stack.iter().collect();
            top.sort_by_key(|(_, (ns, _))| std::cmp::Reverse(*ns));
            top.truncate(top_stacks as usize);
            by_reason_json.insert(
                reason.label(),
                JsonReason {
                    total_ms: agg.total_ns / 1_000_000,
                    threads: agg.pids.len(),
                    top_stacks: top.iter().map(|(_, (ns, frames))| JsonStack {
                        ms: ns / 1_000_000,
                        frames,
                    }).collect(),
                },
            );
        }
        let win = JsonWindow {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            window_ms: window.as_millis() as u64,
            pid,
            excluded_idle_buckets: excluded_idle,
            by_reason: by_reason_json,
        };
        serde_json::to_writer(&mut *out, &win)?;
        writeln!(out)?;
    } else {
        writeln!(
            out,
            "=== tragach-iowait  {} window  pid={} ===",
            humantime::format_duration(window),
            pid
        )?;
        if exclude_idle {
            writeln!(
                out,
                "  --exclude-idle: dropped {} bucket(s) above {:.0}% of window",
                excluded_idle,
                idle_threshold * 100.0
            )?;
        }
        if by_reason.is_empty() {
            writeln!(out, "  (no off-CPU activity in this window)")?;
        } else {
            writeln!(out, "Off-CPU time by reason:")?;
            let mut reasons: Vec<(&Reason, &ReasonAgg)> = by_reason.iter().collect();
            reasons.sort_by_key(|(_, a)| std::cmp::Reverse(a.total_ns));
            for (reason, agg) in reasons {
                let top_frame = agg
                    .by_stack
                    .values()
                    .max_by_key(|(ns, _)| *ns)
                    .map(|(_, frames)| meaningful_frame(frames).to_string())
                    .unwrap_or_else(|| "?".to_string());
                writeln!(
                    out,
                    "  {:<22}: {:>7}  ({:>3} threads, top: {})",
                    reason.label(),
                    fmt_ms(agg.total_ns),
                    agg.pids.len(),
                    top_frame
                )?;
                if top_stacks > 0 {
                    let mut stacks_v: Vec<(&i32, &(u64, Vec<String>))> =
                        agg.by_stack.iter().collect();
                    stacks_v.sort_by_key(|(_, (ns, _))| std::cmp::Reverse(*ns));
                    for (_, (ns, frames)) in stacks_v.iter().take(top_stacks as usize) {
                        if frames.is_empty() { continue; }
                        let frames_str: Vec<&str> = frames.iter().take(5).map(String::as_str).collect();
                        writeln!(out, "      {:>7}  {}", fmt_ms(*ns), frames_str.join(" → "))?;
                    }
                }
            }
        }
        writeln!(out)?;
    }
    out.flush().ok();
    Ok(())
}

/// Skip the universal `__schedule`/`schedule` leaves and return the first
/// frame that actually describes WHY the task is asleep.
fn meaningful_frame(frames: &[String]) -> &str {
    for f in frames {
        let s = f.as_str();
        if s == "__schedule" || s.starts_with("schedule") && !s.starts_with("schedule_") {
            continue;
        }
        if s == "schedule" {
            continue;
        }
        return s;
    }
    frames.first().map(String::as_str).unwrap_or("?")
}

fn fmt_ms(ns: u64) -> String {
    let ms = ns as f64 / 1_000_000.0;
    if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else if ms >= 1.0 {
        format!("{:.0}ms", ms)
    } else {
        format!("{:.0}us", ns as f64 / 1_000.0)
    }
}
