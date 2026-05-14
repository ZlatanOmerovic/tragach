//! tragach-attach — per-attachment lifecycle tracing for Firebird.
//! See SPECS.md §5.3 and docs/design-notes.md.

mod symbols;

use anyhow::{Context, Result, anyhow, bail};
use aya::maps::{MapData, RingBuf};
use aya::programs::UProbe;
use aya::{Ebpf, include_bytes_aligned};
use chrono::{DateTime, Utc};
use clap::Parser;
use log::{info, warn};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tragach_common::event::{AttachEvent, AttachEventKind};

#[derive(Debug, Parser)]
#[command(name = "tragach-attach", version, about = "Per-attachment lifecycle tracing for Firebird", long_about = None)]
struct Args {
    /// Firebird install root. Probes attach against
    /// `<prefix>/plugins/libEngine13.so` with offsets resolved (by default)
    /// from `<prefix>/plugins/.debug/libEngine13.so.debug`.
    #[arg(long, default_value = "/opt/firebird-v5")]
    firebird_prefix: PathBuf,

    /// Override the debug-symbols file path (same convention as
    /// tragach-slowquery).
    #[arg(long)]
    debug_path: Option<PathBuf>,

    /// Only emit `closed` events for attachments that lived at least this
    /// long. Useful for filtering connection-pool keepalive churn. `opened`
    /// events are always emitted.
    #[arg(long)]
    min_duration: Option<humantime::Duration>,

    /// Emit JSON Lines instead of human-readable output.
    #[arg(long)]
    json: bool,
}

static BPF_OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tragach-attach"));

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let libengine = args.firebird_prefix.join("plugins/libEngine13.so");
    let debug_path = args
        .debug_path
        .clone()
        .unwrap_or_else(|| args.firebird_prefix.join("plugins/.debug/libEngine13.so.debug"));
    ensure_paths(&libengine, &debug_path)?;

    let offsets = symbols::resolve(&debug_path)
        .with_context(|| format!("resolving attach symbols in {}", debug_path.display()))?;
    info!(
        "resolved offsets: Attachment::Attachment=0x{:x} release_attachment=0x{:x}",
        offsets.attachment_ctor, offsets.release_attachment
    );

    if let Err(e) = raise_rlimit_memlock() {
        warn!("RLIMIT_MEMLOCK raise failed ({e}) — continuing");
    }

    let mut bpf = Ebpf::load(BPF_OBJECT).context("loading BPF object")?;

    attach_uprobe(
        &mut bpf,
        "attach_ctor_entry",
        offsets.attachment_ctor,
        &libengine,
    )?;
    attach_uprobe(
        &mut bpf,
        "release_attachment_entry",
        offsets.release_attachment,
        &libengine,
    )?;

    let ring: RingBuf<MapData> = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map missing from BPF object"))?
        .try_into()
        .context("EVENTS is not a RingBuf")?;

    info!("attached; streaming attachment-lifecycle events. Ctrl-C to stop.");
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
            "debug symbols not found at {} — gnu_debuglink target missing. \
             Pass --debug-path <path> to point at a relocated debug file, or \
             install a firebird debug package / unstripped build under the \
             prefix.",
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
    struct Rl {
        cur: u64,
        max: u64,
    }
    const RLIMIT_MEMLOCK: i32 = 8;
    unsafe extern "C" {
        fn setrlimit(resource: i32, rlim: *const Rl) -> i32;
    }
    let rl = Rl { cur: u64::MAX, max: u64::MAX };
    let rc = unsafe { setrlimit(RLIMIT_MEMLOCK, &rl) };
    if rc != 0 {
        return Err(anyhow!("setrlimit rc={rc}"));
    }
    Ok(())
}

async fn run_event_loop(ring: RingBuf<MapData>, args: &Args) -> Result<()> {
    let min_duration_ns: Option<u64> = args.min_duration.map(|d| d.as_nanos() as u64);
    let mut dropped: u64 = 0;

    let mut async_fd = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)
        .context("registering ring buffer with tokio")?;

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\ntragach-attach: shutting down (dropped={dropped})");
                return Ok(());
            }
            ready = async_fd.readable_mut() => {
                let mut guard = ready?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    let bytes: &[u8] = &item;
                    match decode_event(bytes) {
                        Ok(ev) => {
                            // min_duration only applies to closed events; opened lifecycle
                            // boundary should always be visible.
                            if ev.kind == AttachEventKind::Closed as u32 {
                                if let Some(t) = min_duration_ns {
                                    if ev.duration_ns < t { continue; }
                                }
                            }
                            if args.json {
                                write_json(&mut stdout, &ev)?;
                            } else {
                                write_human(&mut stdout, &ev)?;
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

fn decode_event(bytes: &[u8]) -> Result<AttachEvent, ()> {
    if bytes.len() < std::mem::size_of::<AttachEvent>() {
        warn!(
            "short ringbuf record: {} < {}",
            bytes.len(),
            std::mem::size_of::<AttachEvent>()
        );
        return Err(());
    }
    let ev: AttachEvent =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const AttachEvent) };
    Ok(ev)
}

fn write_human<W: std::io::Write>(w: &mut W, ev: &AttachEvent) -> Result<()> {
    let ts: DateTime<Utc> = chrono::Utc::now();
    let kind_str = if ev.kind == AttachEventKind::Opened as u32 {
        "opened"
    } else {
        "closed"
    };
    let duration_str = if ev.kind == AttachEventKind::Opened as u32 {
        "        -".to_string()
    } else {
        format!("{:>9}", fmt_duration(ev.duration_ns))
    };
    writeln!(
        w,
        "{}  att_ptr=0x{:016x}  duration={}  pid={:>6} tid={:>6}  ({})",
        ts.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        ev.attachment_ptr,
        duration_str,
        ev.pid,
        ev.tid,
        kind_str,
    )?;
    Ok(())
}

#[derive(Serialize)]
struct JsonEvent {
    ts: String,
    /// `"opened"` or `"closed"`.
    event: &'static str,
    /// Raw Jrd::Attachment* pointer as hex.
    att_ptr: String,
    /// Total lifetime in µs; `null` on `"opened"`.
    duration_us: Option<u64>,
    pid: u32,
    tid: u32,
}

fn write_json<W: std::io::Write>(w: &mut W, ev: &AttachEvent) -> Result<()> {
    let ts: DateTime<Utc> = chrono::Utc::now();
    let kind = if ev.kind == AttachEventKind::Opened as u32 {
        "opened"
    } else {
        "closed"
    };
    let json = JsonEvent {
        ts: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        event: kind,
        att_ptr: format!("0x{:x}", ev.attachment_ptr),
        duration_us: if ev.kind == AttachEventKind::Opened as u32 {
            None
        } else {
            Some(ev.duration_ns / 1_000)
        },
        pid: ev.pid,
        tid: ev.tid,
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
