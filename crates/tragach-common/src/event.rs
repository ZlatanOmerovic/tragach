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
