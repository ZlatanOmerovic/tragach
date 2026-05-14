//! tragach-pageio BPF program — engine ↔ block-device I/O correlation.
//!
//! Four BPF programs:
//!   - uprobe   `CCH_fetch_page` entry  (Jrd::thread_db*, Jrd::win*, bool)
//!   - uretprobe `CCH_fetch_page` exit
//!   - tracepoint block:block_rq_issue
//!   - tracepoint block:block_rq_complete
//!
//! Maps (all aggregate, no per-event ringbuf in PoC scope):
//!   - TARGET_TGID         : Array<u32>(1)         — set by userspace
//!   - FETCH_IN_PROGRESS   : HashMap<tid, FetchInfo>
//!   - BLOCK_INFLIGHT      : HashMap<BlockKey, u64> — issue_ts per (dev, sector)
//!   - COUNTERS            : PerCpuArray<PageIoCounters>(1) — windowed totals
//!
//! Userspace snapshots COUNTERS each flush interval, sums across CPUs, prints.
//! See SPECS.md §5.4 for the full spec.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user},
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{Array, HashMap, PerCpuArray},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};

/// Per-window aggregate counters. Layout must match userspace's `PageIoCounters`
/// in `tragach-pageio`'s `main.rs` — read by raw bytes from the per-CPU array.
#[repr(C)]
#[derive(Clone, Copy)]
struct PageIoCounters {
    engine_count: u64,
    engine_total_ns: u64,
    engine_max_ns: u64,
    block_count: u64,
    block_total_bytes: u64,
    block_total_wait_ns: u64,
    block_max_wait_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FetchInfo {
    start_ts: u64,
    page_num: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BlockKey {
    dev: u32,
    _pad: u32,
    sector: u64,
}

// Target Firebird process (tgid). Set by userspace before attaching probes.
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

// In-flight CCH_fetch_page calls, keyed by tid.
#[map]
static FETCH_IN_PROGRESS: HashMap<u32, FetchInfo> = HashMap::with_max_entries(8192, 0);

// In-flight block requests, keyed by (dev, sector). Bounded for safety; sustained
// pressure beyond this means we lose some completion matches but counters keep working.
#[map]
static BLOCK_INFLIGHT: HashMap<BlockKey, u64> = HashMap::with_max_entries(16384, 0);

// Cumulative per-CPU counters. Userspace tracks deltas between snapshots.
#[map]
static COUNTERS: PerCpuArray<PageIoCounters> = PerCpuArray::with_max_entries(1, 0);

// ---------- CCH_fetch_page (uprobe + uretprobe) ----------

#[uprobe]
pub fn cch_fetch_page_entry(ctx: ProbeContext) -> u32 {
    let _ = try_cch_entry(&ctx);
    0
}

#[uretprobe]
pub fn cch_fetch_page_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_cch_exit(&ctx);
    0
}

fn try_cch_entry(ctx: &ProbeContext) -> Result<(), i64> {
    // Only track calls from the target Firebird process.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target = TARGET_TGID.get(0).ok_or(-1_i64)?;
    if *target == 0 || *target != tgid {
        return Ok(());
    }

    // Arg 1 (RSI) is `Jrd::win*`. PageNumber sits at win+0 (verified via pahole).
    let win_ptr: u64 = ctx.arg(1).ok_or(-1_i64)?;
    let page_num: u64 = if win_ptr != 0 {
        unsafe { bpf_probe_read_user(win_ptr as *const u64).unwrap_or(0) }
    } else {
        0
    };

    let info = FetchInfo {
        start_ts: unsafe { bpf_ktime_get_ns() },
        page_num,
    };
    let tid = (bpf_get_current_pid_tgid() & 0xffff_ffff) as u32;
    FETCH_IN_PROGRESS.insert(&tid, &info, 0)?;
    Ok(())
}

fn try_cch_exit(_ctx: &RetProbeContext) -> Result<(), i64> {
    let tid = (bpf_get_current_pid_tgid() & 0xffff_ffff) as u32;
    let info_ptr = unsafe { FETCH_IN_PROGRESS.get(&tid) }.ok_or(-1_i64)?;
    let info = unsafe { *(info_ptr as *const FetchInfo) };
    let _ = FETCH_IN_PROGRESS.remove(&tid);

    let now = unsafe { bpf_ktime_get_ns() };
    let duration_ns = now.saturating_sub(info.start_ts);

    let counters_ptr = COUNTERS.get_ptr_mut(0).ok_or(-1_i64)?;
    unsafe {
        (*counters_ptr).engine_count = (*counters_ptr).engine_count.wrapping_add(1);
        (*counters_ptr).engine_total_ns = (*counters_ptr).engine_total_ns.wrapping_add(duration_ns);
        if duration_ns > (*counters_ptr).engine_max_ns {
            (*counters_ptr).engine_max_ns = duration_ns;
        }
    }
    Ok(())
}

// ---------- block_rq_issue / block_rq_complete (tracepoints) ----------

#[tracepoint]
pub fn block_rq_issue(ctx: TracePointContext) -> u32 {
    let _ = try_block_issue(&ctx);
    0
}

#[tracepoint]
pub fn block_rq_complete(ctx: TracePointContext) -> u32 {
    let _ = try_block_complete(&ctx);
    0
}

fn try_block_issue(ctx: &TracePointContext) -> Result<(), i64> {
    // Filter to target tgid. At block_rq_issue the kernel is executing in the
    // context of the requesting task most of the time (direct submission).
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target = TARGET_TGID.get(0).ok_or(-1_i64)?;
    if *target == 0 || *target != tgid {
        return Ok(());
    }

    // Field offsets validated against /sys/kernel/debug/tracing/events/block/block_rq_issue/format
    let dev: u32 = unsafe { ctx.read_at(8) }.map_err(|_| -1_i64)?;
    let sector: u64 = unsafe { ctx.read_at(16) }.map_err(|_| -1_i64)?;
    let bytes: u32 = unsafe { ctx.read_at(28) }.map_err(|_| -1_i64)?;
    let now = unsafe { bpf_ktime_get_ns() };

    let key = BlockKey { dev, _pad: 0, sector };
    let _ = BLOCK_INFLIGHT.insert(&key, &now, 0);

    let counters_ptr = COUNTERS.get_ptr_mut(0).ok_or(-1_i64)?;
    unsafe {
        (*counters_ptr).block_count = (*counters_ptr).block_count.wrapping_add(1);
        (*counters_ptr).block_total_bytes =
            (*counters_ptr).block_total_bytes.wrapping_add(bytes as u64);
    }
    Ok(())
}

fn try_block_complete(ctx: &TracePointContext) -> Result<(), i64> {
    // Don't filter by tgid on complete — completions run in softirq context
    // most of the time, so current is unrelated. Instead, match the (dev,sector)
    // key — if we issued it, it's ours.
    let dev: u32 = unsafe { ctx.read_at(8) }.map_err(|_| -1_i64)?;
    let sector: u64 = unsafe { ctx.read_at(16) }.map_err(|_| -1_i64)?;

    let key = BlockKey { dev, _pad: 0, sector };
    let issue_ts_ptr = unsafe { BLOCK_INFLIGHT.get(&key) }.ok_or(-1_i64)?;
    let issue_ts = unsafe { *(issue_ts_ptr as *const u64) };
    let _ = BLOCK_INFLIGHT.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let wait_ns = now.saturating_sub(issue_ts);

    let counters_ptr = COUNTERS.get_ptr_mut(0).ok_or(-1_i64)?;
    unsafe {
        (*counters_ptr).block_total_wait_ns =
            (*counters_ptr).block_total_wait_ns.wrapping_add(wait_ns);
        if wait_ns > (*counters_ptr).block_max_wait_ns {
            (*counters_ptr).block_max_wait_ns = wait_ns;
        }
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
