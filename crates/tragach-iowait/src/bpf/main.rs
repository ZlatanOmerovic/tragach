//! tragach-iowait BPF program — off-CPU profiling of a single PID.
//!
//! Two tracepoints, no Firebird symbols:
//!
//! ```text
//! sched:sched_switch (prev_pid=offset 24:i32, prev_state=offset 32:i64)
//!   - filter: prev's tgid == TARGET_TGID[0]
//!   - filter: (prev_state as u8) != 0   (task going to sleep, not just preempted)
//!   - capture kernel stack via bpf_get_stackid
//!   - record START[prev_pid] = {ts_ns, stack_id}
//!
//! sched:sched_wakeup (pid=offset 24:i32)
//!   - lookup START[pid]; if present, delta = now - ts_ns
//!   - accumulate BUCKETS[(pid, stack_id)] += delta
//!   - remove START[pid]
//! ```
//!
//! Userspace drains BUCKETS each flush interval, resolves stack_ids via
//! STACKS map → kernel symbols → bucket classification. Field offsets came
//! from `/sys/kernel/debug/tracing/events/sched/{sched_switch,sched_wakeup}/format`.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{Array, HashMap, StackTrace},
    programs::TracePointContext,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct StartInfo {
    ts_ns: u64,
    stack_id: i32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BucketKey {
    pid: u32,
    stack_id: i32,
}

// Set by userspace at startup. Value 0 means "track all PIDs"; we always
// expect userspace to populate this with the Firebird worker PID.
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static START: HashMap<u32, StartInfo> = HashMap::with_max_entries(16384, 0);

#[map]
static BUCKETS: HashMap<BucketKey, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static STACKS: StackTrace = StackTrace::with_max_entries(4096, 0);

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    let _ = try_sched_switch(&ctx);
    0
}

#[tracepoint]
pub fn sched_wakeup(ctx: TracePointContext) -> u32 {
    let _ = try_sched_wakeup(&ctx);
    0
}

fn try_sched_switch(ctx: &TracePointContext) -> Result<(), i64> {
    // Tracepoint field offsets, validated against the kernel format file.
    let prev_pid: i32 = unsafe { ctx.read_at(24) }.map_err(|_| -1_i64)?;
    let prev_state: i64 = unsafe { ctx.read_at(32) }.map_err(|_| -1_i64)?;

    // Task is still runnable (preempted, not sleeping) — skip.
    if (prev_state as u8) == 0 {
        return Ok(());
    }

    // Filter to target process (tgid). At sched_switch the kernel runs in
    // the context of the outgoing task, so current's tgid is prev's tgid.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let target = TARGET_TGID.get(0).ok_or(-1_i64)?;
    if *target == 0 || *target != tgid {
        return Ok(());
    }

    let stack_id = unsafe {
        STACKS.get_stackid(ctx, 0).unwrap_or(-1)
    } as i32;

    let info = StartInfo {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        stack_id,
        _pad: 0,
    };
    let key = prev_pid as u32;
    let _ = START.insert(&key, &info, 0);
    Ok(())
}

fn try_sched_wakeup(ctx: &TracePointContext) -> Result<(), i64> {
    let woken_pid: i32 = unsafe { ctx.read_at(24) }.map_err(|_| -1_i64)?;
    let key = woken_pid as u32;

    let info_ptr = unsafe { START.get(&key) }.ok_or(-1_i64)?;
    let info = unsafe { *(info_ptr as *const StartInfo) };
    let _ = START.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now.saturating_sub(info.ts_ns);

    let bkey = BucketKey {
        pid: key,
        stack_id: info.stack_id,
    };
    let new_total = match unsafe { BUCKETS.get(&bkey) } {
        Some(existing_ptr) => unsafe { *(existing_ptr as *const u64) }.wrapping_add(delta),
        None => delta,
    };
    let _ = BUCKETS.insert(&bkey, &new_total, 0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
