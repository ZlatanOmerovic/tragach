//! tragach-slowquery BPF program.
//!
//! Six probes against `libEngine13.so` (SysV AMD64 calling convention):
//!
//! ```text
//! DSQL_prepare(thread_db*, Attachment*=RSI, ..., length=RCX, sql=R8, ...) → DsqlRequest*=RAX
//!   - entry  : capture (tid, ts, RSI, RCX, R8); read SQL text via bpf_probe_read_user_str
//!   - exit   : compute prepare_ns; store {attachment, sql, prepare_ns} in LRU map keyed by RAX
//!
//! DSQL_execute(thread_db*, jrd_tra**, DsqlRequest*=RDX, ...)
//!   - entry  : capture (tid, ts, RDX)
//!   - exit   : execute_ns = now - entry; look up RDX in LRU map; emit ringbuf event
//!
//! DSQL_execute_immediate(thread_db*, Attachment*=RSI, ..., length=RCX, sql=R8, ...)
//!   - entry  : capture (tid, ts, RSI, RCX, R8); read SQL text
//!   - exit   : execute_ns = now - entry; emit ringbuf event with prepare_ns=0
//! ```
//!
//! Map layout, sizing rationale, design choices: see `docs/design-notes.md`.
//!
//! Stack discipline: `WithSql` is 528 bytes; the BPF stack is 512 total. We
//! never copy these structs by value — always work through `*const`/`*mut`
//! pointers and let `ptr::copy_nonoverlapping` route the SQL buffer through
//! either a scratch per-CPU array or directly into a ring-buffer slot.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use core::ptr;
use tragach_common::event::{SQL_MAX, SlowQueryEvent};

// ---------- map value types ----------

#[repr(C)]
#[derive(Clone, Copy)]
struct WithSql {
    ts_ns: u64,
    attachment_ptr: u64,
    sql_len: u32,
    sql_truncated: u32,
    sql: [u8; SQL_MAX],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PreparedStatement {
    attachment_ptr: u64,
    prepare_ns: u64,
    sql_len: u32,
    sql_truncated: u32,
    sql: [u8; SQL_MAX],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecuteEntry {
    ts_ns: u64,
    dsql_request_ptr: u64,
}

/// Cursor we're currently iterating. Stored under the DsqlCursor* pointer so
/// fetchNext exits can look it up. Per design-notes "Cursor SELECT lifecycle".
#[repr(C)]
#[derive(Clone, Copy)]
struct OpenCursor {
    open_ts_ns: u64,
    dsql_request_ptr: u64,
}

// ---------- per-CPU scratch (struct values exceed the 512-byte BPF stack) ----------

#[map]
static WITH_SQL_SCRATCH: PerCpuArray<WithSql> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PREPARED_SCRATCH: PerCpuArray<PreparedStatement> = PerCpuArray::with_max_entries(1, 0);

// ---------- live state ----------

#[map]
static PREPARE_IN_PROGRESS: HashMap<u32, WithSql> = HashMap::with_max_entries(8192, 0);

#[map]
static EXECUTE_IN_PROGRESS: HashMap<u32, ExecuteEntry> = HashMap::with_max_entries(8192, 0);

#[map]
static IMMEDIATE_IN_PROGRESS: HashMap<u32, WithSql> = HashMap::with_max_entries(8192, 0);

// In-flight openCursor/fetchNext, keyed by tid.
#[map]
static OPENCURSOR_IN_PROGRESS: HashMap<u32, OpenCursor> = HashMap::with_max_entries(8192, 0);

#[map]
static FETCH_IN_PROGRESS: HashMap<u32, u64> = HashMap::with_max_entries(8192, 0);

// LRU because we don't probe DSQL_free_statement in v0.1.
#[map]
static PREPARED_STATEMENTS: LruHashMap<u64, PreparedStatement> =
    LruHashMap::with_max_entries(1024, 0);

// DsqlCursor* → OpenCursor. LRU bounds memory if cursors close before EOF.
#[map]
static OPEN_CURSORS: LruHashMap<u64, OpenCursor> = LruHashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// ---------- probe bodies ----------

#[uprobe]
pub fn dsql_prepare_entry(ctx: ProbeContext) -> u32 {
    let _ = try_capture_sql_entry(&ctx, &PREPARE_IN_PROGRESS);
    0
}

#[uretprobe]
pub fn dsql_prepare_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_prepare_exit(&ctx);
    0
}

#[uprobe]
pub fn dsql_execute_entry(ctx: ProbeContext) -> u32 {
    let _ = try_execute_entry(&ctx);
    0
}

#[uretprobe]
pub fn dsql_execute_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_execute_exit(&ctx);
    0
}

#[uprobe]
pub fn dsql_execute_immediate_entry(ctx: ProbeContext) -> u32 {
    let _ = try_capture_sql_entry(&ctx, &IMMEDIATE_IN_PROGRESS);
    0
}

#[uretprobe]
pub fn dsql_execute_immediate_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_immediate_exit(&ctx);
    0
}

#[uprobe]
pub fn dsql_open_cursor_entry(ctx: ProbeContext) -> u32 {
    let _ = try_open_cursor_entry(&ctx);
    0
}

#[uretprobe]
pub fn dsql_open_cursor_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_open_cursor_exit(&ctx);
    0
}

#[uprobe]
pub fn dsql_fetch_next_entry(ctx: ProbeContext) -> u32 {
    let _ = try_fetch_next_entry(&ctx);
    0
}

#[uretprobe]
pub fn dsql_fetch_next_exit(ctx: RetProbeContext) -> u32 {
    let _ = try_fetch_next_exit(&ctx);
    0
}

// ---------- helpers ----------

#[inline(always)]
fn tid() -> u32 {
    (bpf_get_current_pid_tgid() & 0xffff_ffff) as u32
}

/// Common entry for `DSQL_prepare` and `DSQL_execute_immediate`. Both pass
/// `Attachment*` in RSI (arg 1), `length` (ULONG) in RCX (arg 3), `sql` (const
/// TEXT*) in R8 (arg 4).
fn try_capture_sql_entry(
    ctx: &ProbeContext,
    target_map: &HashMap<u32, WithSql>,
) -> Result<(), i64> {
    let attachment_ptr: u64 = ctx.arg(1).ok_or(-1_i64)?;
    let length: u64 = ctx.arg(3).ok_or(-1_i64)?;
    let sql_ptr: u64 = ctx.arg(4).ok_or(-1_i64)?;

    let scratch_ptr = WITH_SQL_SCRATCH.get_ptr_mut(0).ok_or(-1_i64)?;
    unsafe {
        (*scratch_ptr).ts_ns = bpf_ktime_get_ns();
        (*scratch_ptr).attachment_ptr = attachment_ptr;
        (*scratch_ptr).sql_len = length as u32;
        (*scratch_ptr).sql_truncated = 0;
        // Zero the buffer so a previous probe's bytes don't leak past the actual length.
        ptr::write_bytes((*scratch_ptr).sql.as_mut_ptr(), 0, SQL_MAX);

        if sql_ptr != 0 {
            let copied = bpf_probe_read_user_str_bytes(
                sql_ptr as *const u8,
                &mut (*scratch_ptr).sql,
            )
            .unwrap_or(&[]);
            let copied_len = copied.len() as u32;
            // Firebird passes length=0 to mean "strlen the string". Use what we read.
            if length == 0 {
                (*scratch_ptr).sql_len = copied_len;
            }
            if copied_len >= (SQL_MAX as u32 - 1) && length > copied_len as u64 {
                (*scratch_ptr).sql_truncated = 1;
            }
        } else {
            (*scratch_ptr).sql_len = 0;
        }
    }

    let key = tid();
    target_map.insert(&key, unsafe { &*scratch_ptr }, 0)?;
    Ok(())
}

fn try_prepare_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let key = tid();
    let entry_ptr = unsafe { PREPARE_IN_PROGRESS.get(&key) }.ok_or(-1_i64)?;
    let entry_ptr = entry_ptr as *const WithSql;

    let dsql_request_ptr: u64 = ctx.ret().unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };
    let ts = unsafe { (*entry_ptr).ts_ns };
    let prepare_ns = now.saturating_sub(ts);
    let attachment_ptr = unsafe { (*entry_ptr).attachment_ptr };
    let sql_len = unsafe { (*entry_ptr).sql_len };
    let sql_truncated = unsafe { (*entry_ptr).sql_truncated };

    if dsql_request_ptr == 0 {
        let _ = PREPARE_IN_PROGRESS.remove(&key);
        return Ok(());
    }

    let scratch_ptr = PREPARED_SCRATCH.get_ptr_mut(0).ok_or(-1_i64)?;
    unsafe {
        (*scratch_ptr).attachment_ptr = attachment_ptr;
        (*scratch_ptr).prepare_ns = prepare_ns;
        (*scratch_ptr).sql_len = sql_len;
        (*scratch_ptr).sql_truncated = sql_truncated;
        // Copy SQL pointer→pointer to avoid landing 512 bytes on the BPF stack.
        ptr::copy_nonoverlapping(
            (*entry_ptr).sql.as_ptr(),
            (*scratch_ptr).sql.as_mut_ptr(),
            SQL_MAX,
        );
    }
    // After this, entry_ptr is invalidated.
    let _ = PREPARE_IN_PROGRESS.remove(&key);

    PREPARED_STATEMENTS.insert(&dsql_request_ptr, unsafe { &*scratch_ptr }, 0)?;
    Ok(())
}

fn try_execute_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let dsql_request_ptr: u64 = ctx.arg(2).ok_or(-1_i64)?;
    if dsql_request_ptr == 0 {
        return Ok(());
    }
    let entry = ExecuteEntry {
        ts_ns: unsafe { bpf_ktime_get_ns() },
        dsql_request_ptr,
    };
    EXECUTE_IN_PROGRESS.insert(&tid(), &entry, 0)?;
    Ok(())
}

fn try_execute_exit(_ctx: &RetProbeContext) -> Result<(), i64> {
    let key = tid();
    let entry_ptr = unsafe { EXECUTE_IN_PROGRESS.get(&key) }.ok_or(-1_i64)?;
    // ExecuteEntry is 16 bytes — safe to copy.
    let entry_copy = unsafe { *(entry_ptr as *const ExecuteEntry) };
    let _ = EXECUTE_IN_PROGRESS.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let execute_ns = now.saturating_sub(entry_copy.ts_ns);

    let prepared_ptr = unsafe { PREPARED_STATEMENTS.get(&entry_copy.dsql_request_ptr) };
    match prepared_ptr {
        Some(p) => {
            let p = p as *const PreparedStatement;
            let attachment_ptr = unsafe { (*p).attachment_ptr };
            let prepare_ns = unsafe { (*p).prepare_ns };
            let sql_len = unsafe { (*p).sql_len };
            let sql_truncated = unsafe { (*p).sql_truncated };
            let sql_src = unsafe { (*p).sql.as_ptr() };
            emit_event(
                now,
                attachment_ptr,
                prepare_ns,
                execute_ns,
                sql_len,
                sql_truncated,
                Some(sql_src),
            )
        }
        None => emit_event(now, 0, 0, execute_ns, 0, 0, None),
    }
}

fn try_immediate_exit(_ctx: &RetProbeContext) -> Result<(), i64> {
    let key = tid();
    let entry_ptr = unsafe { IMMEDIATE_IN_PROGRESS.get(&key) }.ok_or(-1_i64)?;
    let entry_ptr = entry_ptr as *const WithSql;

    let now = unsafe { bpf_ktime_get_ns() };
    let ts = unsafe { (*entry_ptr).ts_ns };
    let execute_ns = now.saturating_sub(ts);
    let attachment_ptr = unsafe { (*entry_ptr).attachment_ptr };
    let sql_len = unsafe { (*entry_ptr).sql_len };
    let sql_truncated = unsafe { (*entry_ptr).sql_truncated };
    let sql_src = unsafe { (*entry_ptr).sql.as_ptr() };

    let r = emit_event(
        now,
        attachment_ptr,
        0,
        execute_ns,
        sql_len,
        sql_truncated,
        Some(sql_src),
    );
    let _ = IMMEDIATE_IN_PROGRESS.remove(&key);
    r
}

fn try_open_cursor_entry(ctx: &ProbeContext) -> Result<(), i64> {
    // `this` (DsqlRequest*) is arg 0 (RDI) for member functions.
    let dsql_request_ptr: u64 = ctx.arg(0).ok_or(-1_i64)?;
    let entry = OpenCursor {
        open_ts_ns: unsafe { bpf_ktime_get_ns() },
        dsql_request_ptr,
    };
    OPENCURSOR_IN_PROGRESS.insert(&tid(), &entry, 0)?;
    Ok(())
}

fn try_open_cursor_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let key = tid();
    let entry_ptr = unsafe { OPENCURSOR_IN_PROGRESS.get(&key) }.ok_or(-1_i64)?;
    // 16 bytes — safe to copy.
    let entry = unsafe { *(entry_ptr as *const OpenCursor) };
    let _ = OPENCURSOR_IN_PROGRESS.remove(&key);

    let cursor_ptr: u64 = ctx.ret().unwrap_or(0);
    if cursor_ptr == 0 {
        return Ok(());
    }
    OPEN_CURSORS.insert(&cursor_ptr, &entry, 0)?;
    Ok(())
}

fn try_fetch_next_entry(ctx: &ProbeContext) -> Result<(), i64> {
    let cursor_ptr: u64 = ctx.arg(0).ok_or(-1_i64)?;
    if cursor_ptr == 0 {
        return Ok(());
    }
    FETCH_IN_PROGRESS.insert(&tid(), &cursor_ptr, 0)?;
    Ok(())
}

fn try_fetch_next_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let key = tid();
    let cursor_ptr_ref = unsafe { FETCH_IN_PROGRESS.get(&key) }.ok_or(-1_i64)?;
    let cursor_ptr = unsafe { *(cursor_ptr_ref as *const u64) };
    let _ = FETCH_IN_PROGRESS.remove(&key);

    // EOF signaled by return == 1 (DsqlCursor.cpp:115); 0 means a row was fetched.
    let ret: u64 = ctx.ret().unwrap_or(0);
    if ret != 1 {
        return Ok(());
    }

    let oc_ptr = unsafe { OPEN_CURSORS.get(&cursor_ptr) }.ok_or(-1_i64)?;
    let oc = unsafe { *(oc_ptr as *const OpenCursor) };
    let _ = OPEN_CURSORS.remove(&cursor_ptr);

    let now = unsafe { bpf_ktime_get_ns() };
    let execute_ns = now.saturating_sub(oc.open_ts_ns);

    let prepared = unsafe { PREPARED_STATEMENTS.get(&oc.dsql_request_ptr) };
    match prepared {
        Some(p) => {
            let p = p as *const PreparedStatement;
            let attachment_ptr = unsafe { (*p).attachment_ptr };
            let prepare_ns = unsafe { (*p).prepare_ns };
            let sql_len = unsafe { (*p).sql_len };
            let sql_truncated = unsafe { (*p).sql_truncated };
            let sql_src = unsafe { (*p).sql.as_ptr() };
            emit_event(
                now,
                attachment_ptr,
                prepare_ns,
                execute_ns,
                sql_len,
                sql_truncated,
                Some(sql_src),
            )
        }
        // openCursor without a tracked prepare (e.g. LRU-evicted prepared
        // statement) — still emit the cursor event so the user sees something.
        None => emit_event(now, 0, 0, execute_ns, 0, 0, None),
    }
}

/// Emit a SlowQueryEvent via the ring buffer. If `sql_src` is Some, copy
/// SQL_MAX bytes from there to the slot; if None, zero the slot's sql buffer.
/// The ring buffer slot is written in place; nothing lands on the BPF stack.
fn emit_event(
    ts_ns: u64,
    attachment_ptr: u64,
    prepare_ns: u64,
    execute_ns: u64,
    sql_len: u32,
    sql_truncated: u32,
    sql_src: Option<*const u8>,
) -> Result<(), i64> {
    let mut entry = match EVENTS.reserve::<SlowQueryEvent>(0) {
        Some(e) => e,
        None => return Err(-1),
    };
    let slot = entry.as_mut_ptr();
    unsafe {
        (*slot).ts_ns = ts_ns;
        (*slot).prepare_ns = prepare_ns;
        (*slot).execute_ns = execute_ns;
        (*slot).attachment_id = attachment_ptr;
        (*slot).tid = tid();
        (*slot).sql_len = sql_len;
        (*slot).sql_truncated = sql_truncated;
        (*slot)._pad = 0;
        match sql_src {
            Some(src) => {
                ptr::copy_nonoverlapping(src, (*slot).sql.as_mut_ptr(), SQL_MAX);
            }
            None => {
                ptr::write_bytes((*slot).sql.as_mut_ptr(), 0, SQL_MAX);
            }
        }
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
