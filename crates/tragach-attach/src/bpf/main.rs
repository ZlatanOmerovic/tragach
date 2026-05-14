//! tragach-attach BPF program — per-attachment lifecycle tracing.
//!
//! Two uprobes against `libEngine13.so`, both entry-only:
//!
//! ```text
//! Jrd::Attachment::Attachment(MemoryPool*, Database*, JProvider*)
//!   - entry: RDI = this = fresh Attachment*.
//!   - emit Opened event + store {open_ts, pid, tid} in LIVE keyed by RDI.
//!
//! release_attachment(thread_db*, Attachment*, ...)
//!   - entry: RSI = Attachment* being released.
//!   - look up LIVE[RSI]; compute duration = now - open_ts.
//!   - emit Closed event with duration. Remove LIVE entry.
//! ```
//!
//! LRU-bounded LIVE map (1024) — same precedent as slowquery's
//! PREPARED_STATEMENTS. Attachments evicted before release emit no Closed
//! event; attachments whose release fires before tragach attached are
//! silently dropped (no LIVE record to match).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, uprobe},
    maps::{LruHashMap, RingBuf},
    programs::ProbeContext,
};
use tragach_common::event::{AttachEvent, AttachEventKind};

#[repr(C)]
#[derive(Clone, Copy)]
struct LiveAttachment {
    open_ts_ns: u64,
    open_pid: u32,
    open_tid: u32,
}

// Attachment* → LiveAttachment. LRU because we don't (yet) probe abnormal
// destruction paths; bounded memory is the right default.
#[map]
static LIVE: LruHashMap<u64, LiveAttachment> = LruHashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[uprobe]
pub fn attach_ctor_entry(ctx: ProbeContext) -> u32 {
    let _ = try_attach_ctor_entry(&ctx);
    0
}

#[uprobe]
pub fn release_attachment_entry(ctx: ProbeContext) -> u32 {
    let _ = try_release_attachment_entry(&ctx);
    0
}

#[inline(always)]
fn pid_tid() -> (u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = (pid_tgid & 0xffff_ffff) as u32;
    (pid, tid)
}

fn try_attach_ctor_entry(ctx: &ProbeContext) -> Result<(), i64> {
    // Arg 0 (RDI) is `this` — the freshly allocated Attachment*.
    let attachment_ptr: u64 = ctx.arg(0).ok_or(-1_i64)?;
    if attachment_ptr == 0 {
        return Ok(());
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let (pid, tid) = pid_tid();

    let live = LiveAttachment {
        open_ts_ns: now,
        open_pid: pid,
        open_tid: tid,
    };
    LIVE.insert(&attachment_ptr, &live, 0)?;

    // Emit Opened event in place — no scratch map needed (AttachEvent is small).
    if let Some(mut slot) = EVENTS.reserve::<AttachEvent>(0) {
        let slot_ptr = slot.as_mut_ptr();
        unsafe {
            (*slot_ptr).ts_ns = now;
            (*slot_ptr).duration_ns = 0;
            (*slot_ptr).attachment_ptr = attachment_ptr;
            (*slot_ptr).pid = pid;
            (*slot_ptr).tid = tid;
            (*slot_ptr).kind = AttachEventKind::Opened as u32;
            (*slot_ptr)._pad = 0;
        }
        slot.submit(0);
    }
    Ok(())
}

fn try_release_attachment_entry(ctx: &ProbeContext) -> Result<(), i64> {
    // Arg 1 (RSI) is the Attachment* being released. Arg 0 (RDI) is thread_db*.
    let attachment_ptr: u64 = ctx.arg(1).ok_or(-1_i64)?;
    if attachment_ptr == 0 {
        return Ok(());
    }

    let live_ptr = unsafe { LIVE.get(&attachment_ptr) }.ok_or(-1_i64)?;
    // LiveAttachment is 16 bytes — safe to copy.
    let live = unsafe { *(live_ptr as *const LiveAttachment) };
    let _ = LIVE.remove(&attachment_ptr);

    let now = unsafe { bpf_ktime_get_ns() };
    let duration_ns = now.saturating_sub(live.open_ts_ns);
    let (pid, tid) = pid_tid();

    if let Some(mut slot) = EVENTS.reserve::<AttachEvent>(0) {
        let slot_ptr = slot.as_mut_ptr();
        unsafe {
            (*slot_ptr).ts_ns = now;
            (*slot_ptr).duration_ns = duration_ns;
            (*slot_ptr).attachment_ptr = attachment_ptr;
            // Release-side pid/tid (often differs from open-side under a worker pool).
            (*slot_ptr).pid = pid;
            (*slot_ptr).tid = tid;
            (*slot_ptr).kind = AttachEventKind::Closed as u32;
            (*slot_ptr)._pad = 0;
        }
        slot.submit(0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
