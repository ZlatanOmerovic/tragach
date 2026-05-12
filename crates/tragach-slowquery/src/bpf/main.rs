//! tragach-slowquery BPF program — DSQL prepare/execute uprobes.
//!
//! Skeleton: a single no-op uprobe so the crate compiles end-to-end. The real
//! probes attach to `*DSQL_prepare*` and `*DSQL_execute*` substrings against
//! libEngine13.so per SPECS.md §5.1 — exact patterns and ring-buffer wiring
//! land in the implementation pass that reads symbols/v5.0.4-libEngine13.txt
//! for matched targets.

#![no_std]
#![no_main]

use aya_ebpf::macros::uprobe;
use aya_ebpf::programs::ProbeContext;

#[uprobe]
pub fn tragach_slowquery_skeleton(_ctx: ProbeContext) -> u32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
