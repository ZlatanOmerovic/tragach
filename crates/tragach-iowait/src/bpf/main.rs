//! tragach-iowait BPF program — sched:sched_switch + sched:sched_wakeup.
//!
//! Skeleton: one no-op tracepoint program. Real wiring lands in the iowait
//! implementation pass per SPECS.md §5.2 — per-thread off-CPU accounting,
//! kernel-stack-keyed buckets, PID filtering.

#![no_std]
#![no_main]

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

#[tracepoint]
pub fn tragach_iowait_skeleton(_ctx: TracePointContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
