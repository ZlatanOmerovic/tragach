//! Wire events emitted from BPF to userspace. See SPECS.md §5.

/// Maximum bytes of SQL text inlined per slowquery event. Anything longer is
/// truncated and `sql_truncated` is set to 1.
pub const SQL_MAX: usize = 512;

/// Off-CPU reason bucket. Keep in sync with the BPF-side classification in
/// `tragach-iowait`.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OffCpuReason {
    Other = 0,
    BlockIo = 1,
    Futex = 2,
    SchedDelay = 3,
}

/// One DSQL statement: prepare + execute durations plus the SQL text.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SlowQueryEvent {
    pub ts_ns: u64,
    pub prepare_ns: u64,
    pub execute_ns: u64,
    pub attachment_id: u64,
    pub tid: u32,
    pub sql_len: u32,
    pub sql_truncated: u32,
    pub _pad: u32,
    pub sql: [u8; SQL_MAX],
}

/// One off-CPU sample for a Firebird thread.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoWaitSample {
    pub ts_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub offcpu_ns: u64,
    pub kstack_id: i32,
    pub reason: u32,
}

/// Attachment lifecycle event kind. Keep in sync with userspace decoder.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachEventKind {
    Opened = 0,
    Closed = 1,
}

/// One attachment-lifecycle event (open or close). See SPECS.md §5.3.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AttachEvent {
    /// `bpf_ktime_get_ns()` at the moment the event fired.
    pub ts_ns: u64,
    /// Lifetime in nanoseconds. `0` for `Opened` events (not yet known).
    pub duration_ns: u64,
    /// Raw `Jrd::Attachment*` pointer — stable for the connection's lifetime.
    pub attachment_ptr: u64,
    /// Firebird worker PID handling this end of the lifecycle.
    pub pid: u32,
    /// Linux TID handling this end of the lifecycle.
    pub tid: u32,
    /// `AttachEventKind` discriminant.
    pub kind: u32,
    /// Padding to keep the struct 8-byte aligned.
    pub _pad: u32,
}
