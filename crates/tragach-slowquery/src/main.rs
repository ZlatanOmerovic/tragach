//! tragach-slowquery — DSQL statement tracing for Firebird via eBPF uprobes.
//! See SPECS.md §5.1 and docs/design-notes.md.

mod symbols;

use anyhow::{Context, Result, anyhow, bail};
use aya::maps::{MapData, RingBuf};
use aya::programs::UProbe;
use aya::{Ebpf, include_bytes_aligned};
use chrono::{DateTime, Utc};
use clap::Parser;
use log::{info, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tragach_common::event::{SQL_MAX, SlowQueryEvent};

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
    /// `<prefix>/plugins/libEngine13.so` with offsets resolved from
    /// `<prefix>/plugins/.debug/libEngine13.so.debug`.
    #[arg(long, default_value = "/opt/firebird-v5")]
    firebird_prefix: PathBuf,
}

static BPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tragach-slowquery"));

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let libengine = args.firebird_prefix.join("plugins/libEngine13.so");
    let debug_path = args
        .firebird_prefix
        .join("plugins/.debug/libEngine13.so.debug");
    ensure_paths(&libengine, &debug_path)?;

    let offsets = symbols::resolve(&debug_path)
        .with_context(|| format!("resolving DSQL symbols in {}", debug_path.display()))?;
    info!(
        "resolved offsets: prepare=0x{:x} execute=0x{:x} execute_immediate=0x{:x}",
        offsets.prepare, offsets.execute, offsets.execute_immediate
    );

    if let Err(e) = raise_rlimit_memlock() {
        warn!("RLIMIT_MEMLOCK raise failed ({e}) — continuing; kernels ≥ 5.11 typically don't need it");
    }

    let mut bpf = Ebpf::load(BPF_OBJECT).context("loading BPF object")?;

    attach_pair(
        &mut bpf,
        "dsql_prepare_entry",
        "dsql_prepare_exit",
        offsets.prepare,
        &libengine,
    )?;
    attach_pair(
        &mut bpf,
        "dsql_execute_entry",
        "dsql_execute_exit",
        offsets.execute,
        &libengine,
    )?;
    attach_pair(
        &mut bpf,
        "dsql_execute_immediate_entry",
        "dsql_execute_immediate_exit",
        offsets.execute_immediate,
        &libengine,
    )?;
    attach_pair(
        &mut bpf,
        "dsql_open_cursor_entry",
        "dsql_open_cursor_exit",
        offsets.open_cursor,
        &libengine,
    )?;
    attach_pair(
        &mut bpf,
        "dsql_fetch_next_entry",
        "dsql_fetch_next_exit",
        offsets.fetch_next,
        &libengine,
    )?;

    let ring: RingBuf<MapData> = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map missing from BPF object"))?
        .try_into()
        .context("EVENTS is not a RingBuf")?;

    info!("attached; streaming events. Ctrl-C to stop.");
    run_event_loop(ring, &args).await
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
            "debug symbols not found at {} — gnu_debuglink target missing; \
             install firebird debug package or unstripped build",
            debug.display()
        );
    }
    Ok(())
}

fn attach_pair(
    bpf: &mut Ebpf,
    entry_prog: &str,
    exit_prog: &str,
    offset: u64,
    target: &Path,
) -> Result<()> {
    let entry: &mut UProbe = bpf
        .program_mut(entry_prog)
        .ok_or_else(|| anyhow!("program {entry_prog} missing"))?
        .try_into()?;
    entry.load()?;
    entry
        .attach(None, offset, target, None)
        .with_context(|| format!("attaching {entry_prog} at offset 0x{offset:x}"))?;

    let exit: &mut UProbe = bpf
        .program_mut(exit_prog)
        .ok_or_else(|| anyhow!("program {exit_prog} missing"))?
        .try_into()?;
    exit.load()?;
    exit.attach(None, offset, target, None)
        .with_context(|| format!("attaching {exit_prog} at offset 0x{offset:x}"))?;

    info!("attached {entry_prog} + {exit_prog} at offset 0x{offset:x}");
    Ok(())
}

fn raise_rlimit_memlock() -> Result<()> {
    // Aya's BTF-backed loader generally doesn't need this on kernels ≥ 5.11,
    // but older or restrictive setups still cgroup-charge BPF memory. Bumping
    // RLIMIT_MEMLOCK to infinity is the safe default.
    let new = libc_rlimit::Rlimit {
        rlim_cur: u64::MAX,
        rlim_max: u64::MAX,
    };
    libc_rlimit::set(&new)
}

mod libc_rlimit {
    use anyhow::{Result, anyhow};

    pub struct Rlimit {
        pub rlim_cur: u64,
        pub rlim_max: u64,
    }

    pub fn set(r: &Rlimit) -> Result<()> {
        // SAFETY: layout of `libc::rlimit` is two u64s on Linux x86_64 ABI.
        #[repr(C)]
        struct Rl {
            cur: u64,
            max: u64,
        }
        let rl = Rl {
            cur: r.rlim_cur,
            max: r.rlim_max,
        };
        const RLIMIT_MEMLOCK: i32 = 8;
        unsafe extern "C" {
            fn setrlimit(resource: i32, rlim: *const Rl) -> i32;
        }
        let rc = unsafe { setrlimit(RLIMIT_MEMLOCK, &rl) };
        if rc != 0 {
            return Err(anyhow!("setrlimit(MEMLOCK) failed (rc={rc})"));
        }
        Ok(())
    }
}

async fn run_event_loop(ring: RingBuf<MapData>, args: &Args) -> Result<()> {
    let threshold_ns: Option<u64> = args.threshold.map(|d| d.as_nanos() as u64);
    let mut id_table: HashMap<u64, u32> = HashMap::new();
    let mut next_id: u32 = 0;
    let mut dropped: u64 = 0;

    let mut async_fd = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)
        .context("registering ring buffer with tokio")?;

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ntragach-slowquery: shutting down (dropped={dropped})");
                return Ok(());
            }
            ready = async_fd.readable_mut() => {
                let mut guard = ready?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    let bytes: &[u8] = &item;
                    match decode_event(bytes) {
                        Ok(ev) => {
                            if let Some(t) = threshold_ns {
                                if ev.execute_ns < t { continue; }
                            }
                            let small_id = match id_table.get(&ev.attachment_id) {
                                Some(id) => *id,
                                None => {
                                    next_id = next_id.wrapping_add(1);
                                    id_table.insert(ev.attachment_id, next_id);
                                    next_id
                                }
                            };
                            if args.json {
                                write_json(&mut stdout, &ev, small_id)?;
                            } else {
                                write_human(&mut stdout, &ev, small_id)?;
                            }
                        }
                        Err(()) => { dropped += 1; }
                    }
                }
                guard.clear_ready();
            }
        }
    }
}

fn decode_event(bytes: &[u8]) -> Result<SlowQueryEvent, ()> {
    if bytes.len() < std::mem::size_of::<SlowQueryEvent>() {
        warn!(
            "short ringbuf record: {} < {}",
            bytes.len(),
            std::mem::size_of::<SlowQueryEvent>()
        );
        return Err(());
    }
    // SlowQueryEvent is #[repr(C)], all-POD, no padding-sensitive fields. The
    // ring buffer aligns records to 8 bytes per the kernel ABI; read_unaligned
    // is defensive but cheap.
    let ev: SlowQueryEvent = unsafe {
        std::ptr::read_unaligned(bytes.as_ptr() as *const SlowQueryEvent)
    };
    Ok(ev)
}

fn sql_str(ev: &SlowQueryEvent) -> std::borrow::Cow<'_, str> {
    let n = (ev.sql_len as usize).min(SQL_MAX);
    let trimmed = &ev.sql[..n];
    // Cut on NUL in case length field is wrong or SQL was shorter than reported.
    let end = trimmed.iter().position(|&b| b == 0).unwrap_or(trimmed.len());
    String::from_utf8_lossy(&trimmed[..end])
}

fn write_human<W: std::io::Write>(w: &mut W, ev: &SlowQueryEvent, att: u32) -> Result<()> {
    let ts: DateTime<Utc> = chrono::Utc::now();
    let sql = sql_str(ev);
    let truncated = if ev.sql_truncated != 0 { "..." } else { "" };
    writeln!(
        w,
        "{}  att={:<4} prepare={:>9}  execute={:>9}  {}{}",
        ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        att,
        fmt_duration(ev.prepare_ns),
        fmt_duration(ev.execute_ns),
        sql,
        truncated,
    )?;
    Ok(())
}

#[derive(Serialize)]
struct JsonEvent<'a> {
    ts: String,
    att: u32,
    att_ptr: String,
    tid: u32,
    prepare_us: u64,
    execute_us: u64,
    sql: &'a str,
    truncated: bool,
}

fn write_json<W: std::io::Write>(w: &mut W, ev: &SlowQueryEvent, att: u32) -> Result<()> {
    let ts: DateTime<Utc> = chrono::Utc::now();
    let sql = sql_str(ev);
    let json = JsonEvent {
        ts: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        att,
        att_ptr: format!("0x{:x}", ev.attachment_id),
        tid: ev.tid,
        prepare_us: ev.prepare_ns / 1_000,
        execute_us: ev.execute_ns / 1_000,
        sql: &sql,
        truncated: ev.sql_truncated != 0,
    };
    serde_json::to_writer(&mut *w, &json)?;
    writeln!(w)?;
    Ok(())
}

fn fmt_duration(ns: u64) -> String {
    let d = Duration::from_nanos(ns);
    if d.as_secs() >= 1 {
        format!("{:.2}s", d.as_secs_f64())
    } else if d.as_millis() >= 1 {
        format!("{:.2}ms", d.as_secs_f64() * 1_000.0)
    } else if d.as_micros() >= 1 {
        format!("{}us", d.as_micros())
    } else {
        format!("{}ns", d.as_nanos())
    }
}
