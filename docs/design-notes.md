# tragach design notes

This file records *why* — probe-target choices, divergences from Firebird's Trace API, surprises found during validation. SPECS.md is *what*; this is *why*. Append-only by convention.

## Symbols artifact

`symbols/v5.0.4-libEngine13.txt` is the ground-truth list of probe targets, generated from `/opt/firebird-v5/plugins/.debug/libEngine13.so.debug` via `xtask symbols`.

Important: the stripped `libEngine13.so` exposes only ~495 dynamic symbols, almost all *imports* from libfbclient. The internal engine C++ functions (`DSQL_*`, `JRD_*`, `CCH_*`, `Attachment::*`) live only as local `t` symbols in the `.debug` file. `nm -CD` of the stripped binary is therefore insufficient — `xtask symbols` reads the `.debug` file via gnu_debuglink instead. CLAUDE.md treats the artifact as ground truth; the artifact is wrong if it's missing internals, so the source choice matters.

## DSQL probe targets (slowquery, SPECS §5.1)

From the v5.0.4 symbols artifact, the substring patterns yield three primaries + three `.cold` clones:

| Function | Mangled symbol | Primary offset | Source ref |
|---|---|---|---|
| `DSQL_prepare` | `_Z12DSQL_preparePN3Jrd9thread_dbEPNS_10AttachmentEPNS_7jrd_traEjPKctjPN8Firebird5ArrayIhNS8_12EmptyStorageIhEEEESD_b` | `0x43d6b0` | `~/src/firebird/src/dsql/dsql.cpp:250` |
| `DSQL_execute` | `_Z12DSQL_executePN3Jrd9thread_dbEPPNS_7jrd_traEPNS_11DsqlRequestEPN8Firebird16IMessageMetadataEPKhS9_Ph` | `0x43c830` | `~/src/firebird/src/dsql/dsql.cpp:136` |
| `DSQL_execute_immediate` | `_Z22DSQL_execute_immediatePN3Jrd9thread_dbEPNS_10AttachmentEPPNS_7jrd_traEjPKctPN8Firebird16IMessageMetadataEPKhSB_Phb` | `0x43d920` | `~/src/firebird/src/dsql/dsql.cpp:327` |
| `Jrd::DsqlDmlRequest::openCursor` | `_ZN3Jrd14DsqlDmlRequest10openCursorEPNS_9thread_dbEPPNS_7jrd_traEPN8Firebird16IMessageMetadataEPKhS8_j` | `0x3995b0` | `~/src/firebird/src/dsql/DsqlRequests.cpp:520` |
| `Jrd::DsqlCursor::fetchNext` | `_ZN3Jrd10DsqlCursor9fetchNextEPNS_9thread_dbEPh` | `0x393f60` | `~/src/firebird/src/dsql/DsqlCursor.cpp:106` |

`.cold` clones (suffix `.cold` on the mangled symbol, addresses around `0x9b???` rather than `0x43????`) are GCC-emitted secondary blocks for unlikely paths within the same function — attaching to them would double-count contended paths. Userspace symbol resolution must exclude any name ending in `.cold`.

**Trace API alignment.** All three are wrapped by `TraceDSQLPrepare` / `TraceDSQLExecute` in `~/src/firebird/src/jrd/trace/TraceDSQLHelpers.h`, which call `TraceManager::event_dsql_prepare` / `event_dsql_execute`. Our probe choice IS the Trace API event boundary — stable across point releases by construction (CLAUDE.md: "prefer Trace API hook sites").

**Argument positions (SysV AMD64).** From `~/src/firebird/src/dsql/dsql_proto.h:38-45`:

- `DSQL_prepare(thread_db*, Attachment*, jrd_tra*, ULONG length, const TEXT* string, USHORT dialect, unsigned prepareFlags, Array<UCHAR>*, Array<UCHAR>*, bool isInternalRequest) → DsqlRequest*`
  - At entry: RDI=tdbb, **RSI=Attachment\***, RDX=transaction, **RCX=length**, **R8=string**, R9=dialect; rest spill to stack.
  - At exit: **RAX = DsqlRequest\*** — the correlation key.
- `DSQL_execute(thread_db*, jrd_tra**, DsqlRequest*, IMessageMetadata*, const UCHAR*, IMessageMetadata*, UCHAR*) → void`
  - At entry: RDI=tdbb, RSI=tra_handle, **RDX=DsqlRequest\***, ...
- `DSQL_execute_immediate(thread_db*, Attachment*, jrd_tra**, ULONG length, const TEXT* string, USHORT dialect, ...) → void`
  - At entry: RDI=tdbb, **RSI=Attachment\***, RDX=tra_handle, **RCX=length**, **R8=string**, ...
- `Jrd::DsqlDmlRequest::openCursor(thread_db*, jrd_tra**, IMessageMetadata*, const UCHAR*, unsigned) → DsqlCursor*`
  - At entry: **RDI=this (DsqlRequest\*)** — joins to PREPARED_STATEMENTS map.
  - At exit: **RAX = DsqlCursor\*** — the new join key for fetch lifecycle.
- `Jrd::DsqlCursor::fetchNext(thread_db*, UCHAR* buffer) → int`
  - At entry: **RDI=this (DsqlCursor\*)** — joins to OPEN_CURSORS map.
  - At exit: **RAX = 1 on EOF, 0 on row fetched** (per `DsqlCursor.cpp:115` and `:119`). The EOF return triggers the cursor's event emission.

## Cursor SELECT lifecycle (added in e1ae278)

The Firebird 5 OO API routes multi-row SELECTs through `JStatement::openCursor` → `DsqlRequest::openCursor` (virtual) → `DsqlDmlRequest::openCursor` (concrete impl). Singleton SELECTs and DML still go through `DSQL_execute`.

For cursor-based SELECTs we treat the lifecycle as:

```text
openCursor entry           → start timer keyed by tid (per-thread in-flight)
openCursor exit            → return DsqlCursor* becomes the join key; record {dsql_request_ptr, open_ts}
                             in OPEN_CURSORS keyed by DsqlCursor*
fetchNext entry            → record cursor_ptr keyed by tid (so retprobe knows which cursor)
fetchNext exit, ret==0     → row fetched; keep accumulating
fetchNext exit, ret==1     → EOF; emit event with execute_ns = now − open_ts; remove OPEN_CURSORS entry
```

This matches Firebird's own Trace API semantics (`TraceDSQLExecute::finish(have_cursor=true)` defers the "done" event; `TraceDSQLFetch::fetch(eof=true)` is what actually emits — see `TraceDSQLHelpers.h`). Our `execute_ns` therefore corresponds to `req_fetch_elapsed` in Firebird's accounting.

Known gaps for v0.1:
- Cursors that close before EOF (client cancels mid-fetch) never emit. LRU eviction caps memory cost; FUTURE.md item to add a `DSQL_free_statement` / cursor-close probe.
- We probe `DsqlDmlRequest::openCursor` (concrete) only. The base virtual `DsqlRequest::openCursor` is bypassed by vtable dispatch in the normal call path. Static calls to the base would be missed but are not part of any normal flow.
- Scrollable cursor operations (`fetchAbsolute`, `fetchRelative`, `fetchPrior`, `fetchFirst`, `fetchLast`) are not probed. They are not used by isql's typical sequential iteration. The same approach extends to them in v0.2 if needed.

## Design decisions (slowquery v0.1)

These are choices made for v0.1; flag them in conversation if any need revisiting before SPECS amendment.

1. **Attachment ID display.** The `Attachment*` raw pointer is captured kernel-side and emitted on the wire. Userspace assigns sequential small IDs (`att=1, 2, 3 …`) per-run via a `HashMap<u64, u32>` for human-readable output. Rationale: avoids needing struct offsets for `att_attachment_id` (CLAUDE.md license hygiene); pointer is uniquely stable for the attachment's lifetime; small IDs are nicer to read. JSON output also emits the raw pointer as `att_ptr` for cross-run identity if needed.

2. **Internal Firebird requests (`isInternalRequest=true`).** Included in v0.1. The flag is the 10th argument to `DSQL_prepare` (stack-spilled past R9), which makes kernel-side filtering fiddly. v0.1 emits all events; the user can filter in their pipeline. Trace API skips these by default — we diverge for visibility into internal traffic.

3. **`DSQL_execute_immediate`.** Emits a single event with `prepare_ns=0` and `execute_ns` = total wall-clock of the call. There is no separable prepare phase available to a uprobe at this boundary. `prepare_ns=0` is the implicit signal that this was an immediate execution.

4. **Prepared-statement map.** `LruHashMap<DsqlRequest*, PreparedStatement>` with 1024 entries. We do not probe `DSQL_free_statement` in v0.1, so the map would grow unbounded on a long-running Firebird — LRU eviction keeps the working set bounded and trades coverage at the long tail (very old, rarely re-executed prepared statements) for simplicity. The execute event for an evicted prepared statement reports `prepare_ns=0` (same as an unprobed prepare).

5. **SQL text capture.** Up to `SQL_MAX = 512` bytes at the prepare/immediate entry via `bpf_probe_read_user_str`. Longer text gets `sql_truncated=1`. Captured at entry (the `string` pointer's lifetime past prepare exit is not guaranteed).

6. **BPF stack handling.** Per-CPU array scratch maps for the >512-byte structs (`PrepareEntry`, `ImmediateEntry`) since the BPF stack is 512 bytes total. Maps `PREPARE_SCRATCH` / `IMMEDIATE_SCRATCH` each hold one entry.

## Attaching uprobes by offset, not by name

Aya's `UProbe::attach(fn_name, offset, target, pid)` resolves `fn_name` against `target`'s symbol table. Our `target` is `/opt/firebird-v5/plugins/libEngine13.so`, which is stripped — its dynsym lacks the internal C++ engine symbols. The symbols live in `.debug/libEngine13.so.debug` via gnu_debuglink, and Aya 0.13 does not appear to follow that link. We therefore resolve symbol → offset ourselves (userspace reads the `.debug` file with `object`/`goblin`) and call `attach(None, offset, libEngine13_path, pid)`. The kernel installs the breakpoint at the same offset in the loaded `.so` since `.debug` is the byproduct of `objcopy --only-keep-debug` against the same compilation unit.

## iowait probe targets (SPECS §5.2)

No Firebird symbols. Two kernel tracepoints:

- `sched:sched_switch` — fires when a thread is descheduled. Filter to threads whose `prev_pid` belongs to the Firebird process; record the off-CPU start timestamp keyed by `prev_pid`.
- `sched:sched_wakeup` — fires when a thread becomes runnable. Look up the start timestamp, compute the delta, attribute it to a bucket keyed by the kernel stack captured at `sched_switch` time.

Bucket classification (Other / BlockIo / Futex / SchedDelay) happens at flush time in userspace, by matching kernel-stack symbols against a small known-token set. This keeps the BPF side simple and dependent only on `bpf_get_stackid` + ring-buffer emission.

## License hygiene

No Firebird source, struct layouts, doc-comments, or constants get copied into this repo. References are by `path:line` only. Struct field offsets, if ever needed, are re-derived with `pahole` against the compiled binary.
