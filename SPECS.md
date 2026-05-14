# SPECS.md — tragach 1.0.0-beta

The work order for tragach 1.0.0-beta. CLAUDE.md is the operating manual; this file is the spec. FUTURE.md is everything 1.0.0-beta explicitly defers.

## 1. Project identity

- **Name:** tragach (pronounced TRAH-gach, from Bosnian *tragač* — "tracer / one who follows tracks"). Use the spelling `tragach` consistently in all code, filenames, identifiers, documentation, commits, and user-facing strings. Do not use `tragač` or `tragac`.
- **Tagline:** *eBPF observability for Firebird — see why your queries are slow, not just that they are.*
- **License:** Apache-2.0
- **Relationship to other projects:** tragach is independent. It is not part of, namespaced under, or branded with Plamenix or any Firebird Foundation project. No cross-references unless the human explicitly approves.

## 2. 1.0.0-beta scope

Four CLI binaries:

1. **`tragach-slowquery`** — engine-level statement tracing. Captures DSQL statement prepare + execute timing per attachment, with the SQL text.
2. **`tragach-iowait`** — kernel-level off-CPU profiling of the Firebird process. Shows where Firebird threads spend time blocked (block I/O, futex, scheduler delay) and for how long.
3. **`tragach-attach`** — connection-lifecycle tracing. Per-attachment open and close timestamps and duration, capturing the inner `Jrd::Attachment*` at construction time and joining against `release_attachment`. Added in `v1.0.0-beta.2` (promoted from FUTURE.md).
4. **`tragach-pageio`** — page-I/O correlation. Joins engine-level `CCH_fetch_page` cache-miss events with kernel `block_rq_issue` / `block_rq_complete` tracepoints to surface "engine asked for a page, the block device took X ms to deliver it." Added in `v1.0.0-beta.2` (promoted from FUTURE.md).

These four together demonstrate the project's full value proposition: engine probing (slowquery), kernel off-CPU correlation (iowait), connection lifecycle (attach), and engine↔block-device latency correlation (pageio). Additional planned scripts are in FUTURE.md.

## 3. Target configuration

### Build environment
- Host: Debian 13 trixie VM, kernel 6.12 LTS, BTF present at `/sys/kernel/btf/vmlinux`
- Rust toolchain:
  - **Stable** for userspace (`tragach-*` binaries)
  - **Nightly with `rust-src`** for kernel-side eBPF programs; build with `cargo +nightly build -Z build-std=core --target bpfel-unknown-none`
- Aya: latest stable release pinned in `Cargo.toml` (do not track `main`)
- `bpf-linker`: latest stable from `cargo install`

### Target Firebird
- Version: the v5.0.x tag built and installed in the bootstrap. Pin the exact tag in `Cargo.toml` metadata and in `symbols/`.
- Architecture: SuperServer only. Classic and SuperClassic are out of scope for 1.0.0-beta.
- Binary layout: server is `/opt/firebird-v5/bin/firebird`; engine logic is in `/opt/firebird-v5/plugins/libEngine13.so`. Both have separate `.debug` files via gnu_debuglink.
- Build flags (already done in bootstrap): `-O2 -g`. No re-builds required.

### Runtime requirements
- Linux kernel ≥ 6.1 with BTF enabled
- CAP_BPF + CAP_PERFMON (or root)
- Firebird v5 SuperServer installed at `/opt/firebird-v5` (path configurable via `--firebird-prefix` flag at runtime, defaulting to `/opt/firebird-v5`)

## 4. Repository layout

```
~/tragach/
├── CLAUDE.md
├── SPECS.md
├── FUTURE.md
├── README.md
├── LICENSE                         (Apache-2.0)
├── Cargo.toml                      (workspace)
├── crates/
│   ├── tragach-common/             (shared types, event structs, CLI helpers)
│   ├── tragach-slowquery/
│   │   ├── Cargo.toml
│   │   ├── src/main.rs             (userspace)
│   │   └── src/bpf/main.rs         (kernel-side, separate target)
│   └── tragach-iowait/
│       ├── Cargo.toml
│       ├── src/main.rs
│       └── src/bpf/main.rs
├── symbols/
│   └── <firebird-tag>-libEngine13.txt   (nm -CD output, committed)
├── tests/
│   └── workloads/
│       ├── slowquery-basic.sql     (isql script that exercises slowquery)
│       └── iowait-basic.sql        (isql script that exercises iowait)
├── docs/
│   └── design-notes.md             (probe choices, divergence from Trace API, etc.)
└── xtask/                          (build orchestration: cargo xtask build, test, symbols)
```

## 5. Script specifications

### 5.1 `tragach-slowquery`

**Question answered:** *Which DSQL statements ran, how long did each take, against which attachment, and with what SQL text?*

**Hook points (all in `libEngine13.so`):**

| Function | Role | Probe pair | Substring pattern | Expected count |
|---|---|---|---|---|
| `DSQL_prepare` | Statement preparation timing + SQL text capture | uprobe + uretprobe | `*DSQL_prepare*` | 2 (1 primary + 1 `.cold`) |
| `DSQL_execute` | Non-cursor execute path (DML, singleton SELECT, SET TRANSACTION) | uprobe + uretprobe | `*DSQL_execute*` substring | 2 |
| `DSQL_execute_immediate` | One-shot prepare+execute (also caught by `*DSQL_execute*`) | uprobe + uretprobe | `*DSQL_execute_immediate*` | 2 |
| `Jrd::DsqlDmlRequest::openCursor` | **Cursor-based SELECT execute path** — the Firebird 5 OO API routes multi-row SELECTs through this, not through `DSQL_execute` | uprobe + uretprobe | `*DsqlDmlRequest*openCursor*` | 2 |
| `Jrd::DsqlCursor::fetchNext` | Per-row fetch; return value `1` signals EOF and triggers cursor-event emission | uprobe + uretprobe | `*DsqlCursor*fetchNext*` | 2 |

Total: 10 probe attachments. Well under bpftrace's 1024-program default. All `.cold` clones must be filtered at attach time (suffix `.cold` on the mangled symbol).

**Justification:** all five entry points are wrapped by Firebird's own Trace API helpers (`TraceDSQLPrepare`, `TraceDSQLExecute`, `TraceDSQLFetch` in `src/jrd/trace/TraceDSQLHelpers.h`), making them stable boundaries across Firebird point releases. Their `event_dsql_prepare` / `event_dsql_execute` calls are the canonical event lifecycle.

**Event lifecycle:**

- **DML / singleton SELECT / SET TRANSACTION / execute-immediate** — one event per `DSQL_execute` or `DSQL_execute_immediate` call. `execute_ns` is the wall-clock of that call.
- **Cursor-based SELECT** — one event when `DsqlCursor::fetchNext` returns `1` (EOF). `execute_ns` is total wall-clock from `DsqlDmlRequest::openCursor` entry to that EOF fetch return (matches Firebird's Trace API `req_fetch_elapsed` semantics — total time spent producing the result set). Cursors closed before EOF are lost for 1.0.0-beta; `DSQL_free_statement` probe would close that gap and is deferred to FUTURE.md.

**Capture:**
- Entry timestamp + arguments (attachment pointer, SQL text pointer, length) at `DSQL_prepare` and `DSQL_execute_immediate`.
- `DsqlRequest*` return value at `DSQL_prepare` exit — correlation key joining prepare → execute / openCursor → fetch.
- Exit timestamps at all retprobes; durations computed in BPF; events emitted via ring buffer.

**Output (default):**
```
2026-05-12T14:23:01Z  att=42  prepare=2.1ms   execute=124ms   SELECT * FROM orders WHERE ...
```

**Output (`--json`):**
```
{"ts":"2026-05-12T14:23:01Z","att":42,"prepare_us":2100,"execute_us":124000,"sql":"SELECT * FROM orders WHERE ..."}
```

**Flags (1.0.0-beta):**
- `--threshold <duration>` — only emit if execute exceeds threshold (e.g. `--threshold 100ms`)
- `--json` — JSON Lines output
- `--firebird-prefix <path>` — override default `/opt/firebird-v5`

**Success criterion:** running `tests/workloads/slowquery-basic.sql` produces one event per executed statement, covering both the `DSQL_execute` path (singleton SELECTs, DML, set-transaction) and the `openCursor`+`fetchNext` path (multi-row SELECTs). Durations are positive and reflect *engine-side* time only — `prepare_ns` is wall-clock inside `DSQL_prepare`, `execute_ns` is wall-clock inside `DSQL_execute` / `DSQL_execute_immediate` / from `openCursor` entry to EOF `fetchNext` return. `isql`'s `SET STATS ON` "Elapsed time" additionally includes TCP round-trip and result formatting, so isql elapsed exceeds tragach `prepare_ns + execute_ns` by a roughly per-statement constant on localhost (typically a few hundred µs); they are not directly comparable.

Where precise validation matters, Firebird's Trace API (`fbtracemgr` against `event_dsql_prepare` / `event_dsql_execute`) is the apples-to-apples reference — it probes the same boundaries as tragach. For statements whose engine-side execute time exceeds 10 ms, tragach `execute_ns` should match the Trace API's `req_fetch_elapsed` within 10%; below that threshold relative noise from probe overhead dominates.

### 5.2 `tragach-iowait`

**Question answered:** *When Firebird threads are blocked, where are they blocked and for how long?*

**Hook points (kernel-side, no Firebird symbols needed):**
- `tracepoint:sched:sched_switch` — captures off-CPU start per Firebird thread
- `tracepoint:sched:sched_wakeup` — captures off-CPU end
- Filter to threads belonging to the firebird process (PID resolved at startup from systemd unit state, or from `--pid` flag)
- Per off-CPU period, capture kernel stack to attribute the blocking reason (block I/O wait, futex, sleep, etc.)

**Capture:**
- Per thread, total off-CPU time bucketed by kernel stack
- Periodic flush (default every 10s) emits a summary

**Output (default, every flush interval):**
```
=== tragach-iowait  10s window  pid=4471 ===
Off-CPU time by reason:
  block I/O wait        :  8420ms  (12 threads, top stack: blk_mq_wait...)
  futex wait            :  1240ms  ( 4 threads, top stack: futex_wait_queue...)
  scheduler delay       :   180ms
  other                 :    62ms
```

**Output (`--json`):** one JSON object per flush window with per-bucket totals and representative stacks.

**Flags (1.0.0-beta):**
- `--pid <pid>` — override Firebird PID detection
- `--interval <duration>` — flush interval (default 10s)
- `--json`
- `--top-stacks <n>` — number of representative stacks per bucket (default 3)

**Flags (1.0.0-beta.2, added by promotion from FUTURE.md):**
- `--exclude-idle` — when set, suppresses any `(pid, stack_id)` bucket whose accumulated off-CPU time exceeds `--idle-threshold` of the window before reason classification runs. Defaults off (preserves prior output shape).
- `--idle-threshold <fraction>` — fraction of the window above which a single-thread-single-stack bucket counts as "idle." Default `0.50`. Range `0.0`–`1.0`. Ignored unless `--exclude-idle` is set.

**The idle-thread heuristic.** SuperServer worker threads sleep in `futex_wait_queue` for ~63% of any given window (idle worker pool, 5 threads × ~9.5 s in a 15 s window); the connection-accept thread sleeps in `schedule_hrtimeout_range_clock`→`do_sys_poll` for ~85% of the window. Both are above the 0.50 default and get dropped. A genuinely-busy thread doing real I/O switches between CPU work and brief waits, so no single `(pid, stack_id)` bucket accumulates close to half the window. The `--exclude-idle` filter drops buckets above the threshold; the remainder is the workload signal.

The 0.50 default was calibrated empirically during implementation. An earlier 0.80 caught only the poll thread (85% > 80%) but missed the worker-pool futex buckets (63% < 80%). Lowering to 0.50 catches both classes without misclassifying genuinely-busy threads.

The heuristic doesn't change which events the BPF program emits; it filters at flush time in userspace, on the snapshot of `BUCKETS` taken before classification. JSON output gains an `excluded_idle_buckets` counter alongside `by_reason`.

**Success criterion:** running `tests/workloads/iowait-basic.sql` against a 2 GB database (built with `tests/workloads/build-large-db.sh`) with the page cache flushed shows the `block I/O wait` bucket scaling proportionally with actual disk activity — observed in validation: ~500 ms with no real read (BLOB pages not touched) vs ~1.3 s when the scan reads ~2 GB of BLOB data (`Reads = 252539` per isql's `SET STATS ON`). Both `futex wait` and `scheduler delay` buckets also appear, populated by Firebird's worker-pool threads sleeping on connection accept and inter-thread sync.

**Why "dominates" was the wrong test (without filtering).** In SuperServer, idle worker threads accumulate sleep time as `N_workers × window × idle_fraction`. With 5 workers × 15 s × ~80% idle ≈ 60 s of futex-wait accumulated per 15 s window, the block-I/O bucket cannot dominate by raw aggregate even under heavy read workload (a 2 GB scan only generates ~1.3 s of I/O on NVMe). The `--exclude-idle` flag added in v1.0.0-beta.2 (above) addresses this by dropping idle-worker buckets before classification. With it on, the block-I/O bucket *can* dominate as SPECS originally intended, on the same workload — see the worked example in the README.

### 5.3 `tragach-attach`

**Question answered:** *Which attachments opened against the server, when, and how long did each stay open?*

Added in `v1.0.0-beta.2` (promoted from FUTURE.md in commit hash TBD). PoC scope — DB alias name, login user, and source IP are deferred (notes below).

**Hook points (all in `libEngine13.so`):**

| Function | Role | Probe pair | Substring pattern | Expected count |
|---|---|---|---|---|
| `Jrd::Attachment::Attachment(MemoryPool*, Database*, JProvider*)` | Inner `Attachment` constructor — `this` at entry is the freshly-allocated `Attachment*`, used as the lifecycle correlation key | uprobe entry only | `*Jrd*Attachment*Attachment*MemoryPool*Database*JProvider*` | 1 primary (filter `.cold`) |
| `release_attachment(Jrd::thread_db*, Jrd::Attachment*, ...)` | The static file-scope teardown function in `jrd.cpp`. Argument 2 (RSI) is the `Attachment*` being released — matches the ctor's `this` | uprobe entry only | `*release_attachment*` | 1 primary (filter `.cold`) |

Total: 2 probe attachments. Well under bpftrace's 1024-program default. `.cold` clones must be filtered at attach time, same discipline as slowquery.

**Probe target choice.** The OO-API surface around attachments goes through `JAttachment` (the public wrapper) and `create_attachment` (a static factory in `jrd.cpp`), but these speak `JAttachment*`, not the inner `Jrd::Attachment*` that `release_attachment` takes. Bridging `JAttachment*` → `Attachment*` would require a two-level `pahole`-derived struct offset chain (`JAttachment.att` is a `StableAttachmentPart*`, which in turn holds the `Attachment*`). Probing the inner ctor directly avoids any struct-offset dependency at the cost of dropping the `alias_name` / `DatabaseOptions` metadata that `create_attachment` carries. That metadata returns as a follow-up.

**Justification.** `Jrd::Attachment::Attachment` is the canonical inner-attachment constructor (the only primary entry in the symbols artifact). `release_attachment` is the single static file-scope teardown function called from every disconnect path (`jrd.cpp:3528`, `:8504`, `:8805`) and from `drop_database`. Symmetry on `Attachment*` makes correlation trivial: no struct offsets, no per-version maintenance burden.

**Event lifecycle:**

- At `Attachment::Attachment` entry: capture `RDI` (= `this` = the new `Attachment*`), record `open_ts = bpf_ktime_get_ns()`. Store keyed by `Attachment*` in an LRU map (1024 entries — see slowquery for precedent).
- At `release_attachment` entry: capture `RSI` (= `Attachment*` being released). Look up the open record, compute `duration_ns = now - open_ts`. Emit ringbuf event. Remove from map.
- Attachments evicted from the LRU before release emit no event. Attachments whose `release_attachment` runs before tragach attached are silently dropped (same convention as slowquery's unmatched executes).

**Capture (PoC v1.0.0-beta.2):**
- `Attachment*` (raw pointer, hex) — stable per-attachment identity for the connection's lifetime.
- `open_ts_ns`, `close_ts_ns` (monotonic, from `bpf_ktime_get_ns`).
- `duration_ns` (computed).
- `pid`, `tid` of the Firebird worker handling each end.

**Capture (deferred, FUTURE.md when promoted):**
- `alias_name` (the DB path) — requires probing `create_attachment` entry and reading `Firebird::PathName` via a `pahole` offset.
- Login user / role — requires reading `Attachment`'s auth-related members via `pahole`.
- Source IP/port — kernel-side `tcp_v4_connect` / `inet_csk_accept` tracepoints, joined by `(pid, peer_addr)`.

**Output (default):**
```
2026-05-13T15:01:43.881Z  att_ptr=0x7f8c1d04a000  duration=12.4s   pid=736 tid=740   (closed)
2026-05-13T15:01:43.882Z  att_ptr=0x7f8c1d04b800  duration=    -   pid=736 tid=741   (opened)
```

**Output (`--json`):** one JSON object per event. Schema:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (RFC 3339 ms, UTC) | Observation time |
| `event` | string | `"opened"` or `"closed"` |
| `att_ptr` | string (hex) | Raw `Jrd::Attachment*` |
| `duration_us` | integer or `null` | Total lifetime in µs; `null` on `"opened"` event |
| `pid` | integer | Firebird worker process |
| `tid` | integer | Linux thread handling this end of the lifecycle |

**Flags (v1.0.0-beta.2):**
- `--firebird-prefix <path>` — override default `/opt/firebird-v5` (same convention as slowquery).
- `--debug-path <path>` — override the debug-symbols file location (same as slowquery).
- `--json` — JSON Lines output.
- `--min-duration <duration>` — only emit `"closed"` events for attachments that lived at least this long. Useful for filtering pool-keepalive churn.

**Success criterion:** running a workload that opens N attachments and closes them all produces exactly N `"opened"` events followed by N `"closed"` events with positive `duration_us`. Validated against `forge run steady-oltp` (creates a known number of attachments per scenario) and a simple `isql` connect-disconnect script.

### 5.4 `tragach-pageio`

**Question answered:** *When Firebird reads a page that wasn't in its cache, what's the underlying block-device latency, and how much engine time is spent waiting on it?*

Added in `v1.0.0-beta.2` (promoted from FUTURE.md in commit hash TBD). PoC scope — read path only (`CCH_fetch_page`), aggregated per flush window. Write path (`CCH_flush`, `CCH_mark`) and per-query attribution are deferred.

**Hook points:**

| Function | Role | Probe | Substring pattern | Expected count |
|---|---|---|---|---|
| `CCH_fetch_page(Jrd::thread_db*, Jrd::win*, bool)` (libEngine13.so) | Cache-manager entry that runs **only on a cache miss** — every call is a real disk read about to happen. Entry: tdbb (RDI), `win*` (RSI), read_shadow (RDX). Exit: returns void; duration is the wait the engine perceives | uprobe entry + uretprobe exit | `_Z14CCH_fetch_pagePN3Jrd9thread_dbEPNS_3winEb` | 1 primary (filter `.cold`) |
| `block:block_rq_issue` (kernel tracepoint) | Block layer accepts a request. `dev` u32@8, `sector` u64@16, `bytes` u32@28, `rwbs` char[8]@34. Filter to Firebird tgid | tracepoint | n/a (tracepoint) | n/a |
| `block:block_rq_complete` (kernel tracepoint) | Block device signals completion. Same `dev`/`sector` as issue → joinable by `(dev, sector)` tuple | tracepoint | n/a (tracepoint) | n/a |

Total: 1 uprobe + 1 uretprobe + 2 tracepoints = 4 BPF programs. Well under any limit.

**Why `CCH_fetch_page` and not `CCH_fetch`.** `CCH_fetch` is the higher-level wrapper that first calls `CCH_fetch_lock` and *conditionally* `CCH_fetch_page`. Probing `CCH_fetch` would fire on cache hits too and require parsing the lock-state return to filter — too noisy for a PoC. `CCH_fetch_page` is unambiguously "Firebird is going to disk." `src/jrd/cch.cpp:899` is the entry point; comment at `:933` confirms "we will read a page, and if there is an I/O error we will try..."

**Page number capture.** The `Jrd::win` struct lays `PageNumber win_page` at offset 0 (verified via `pahole`). Reading 8 bytes from `*(WIN*)` at the BPF probe entry gives us the full `PageNumber` value (page space ID + page number, packed). No deep struct chasing required.

**Event flow:**

1. uprobe `CCH_fetch_page` entry: capture `start_ts = bpf_ktime_get_ns()`, read 8 bytes from `*WIN` to get `page_num`, store `{start_ts, page_num}` keyed by tid in `FETCH_IN_PROGRESS` HashMap.
2. tracepoint `block_rq_issue`: filter `bpf_get_current_pid_tgid() >> 32 == TARGET_TGID`. Record `{issue_ts, bytes}` keyed by `(dev, sector)` in `BLOCK_INFLIGHT` HashMap. Increment per-window counters: `block_rq_count`, `block_rq_bytes`.
3. tracepoint `block_rq_complete`: look up `(dev, sector)` in `BLOCK_INFLIGHT`; compute `wait_ns = now - issue_ts`. Add to per-window counter `block_rq_total_wait_ns`. Remove from `BLOCK_INFLIGHT`.
4. uretprobe `CCH_fetch_page` exit: compute `duration_ns = now - start_ts`. Increment per-window `cch_fetch_count`, `cch_fetch_total_ns`. Remove tid from `FETCH_IN_PROGRESS`.

**Output (default, every flush interval — defaults to `10s`, same as iowait):**

```
=== tragach-pageio  10s window  pid=736 ===
Engine page reads (cache misses):
  count                : 1240
  total wait           : 842 ms
  avg / max per call   : 679 µs / 12.4 ms
Block-device I/O (filtered to Firebird tgid):
  requests             : 1187
  total bytes          : 9.7 MB
  total wait           : 783 ms
  avg / max per req    : 659 µs / 11.8 ms
Ratio                  : engine 842 ms / block 783 ms (engine wait ≈ block wait + cache-coordination overhead)
```

**Output (`--json`):** one JSON object per flush window:

| Field | Type | Notes |
|---|---|---|
| `ts` | string | Window emission time |
| `window_ms` | integer | Flush interval |
| `pid` | integer | Target Firebird PID |
| `engine.count` | integer | `CCH_fetch_page` calls in this window |
| `engine.total_ns` | integer | Total engine-perceived I/O wait |
| `engine.avg_ns`, `engine.max_ns` | integer | Distribution stats |
| `block.count` | integer | `block_rq_issue` events filtered to target tgid |
| `block.total_bytes` | integer | Total bytes from `block_rq_issue.bytes` |
| `block.total_wait_ns` | integer | Sum of (`complete.ts` − `issue.ts`) for joined pairs |
| `block.avg_ns`, `block.max_ns` | integer | Distribution stats |

**Flags (v1.0.0-beta.2):**
- `--pid <pid>` — override Firebird PID detection.
- `--interval <duration>` — flush interval (default `10s`).
- `--firebird-prefix <path>` — same convention as the other binaries.
- `--debug-path <path>` — same convention as the other binaries.
- `--json` — JSON Lines output.

**Success criterion:** running `forge run cold-scan` (or any sufficiently-large unindexed-scan workload) after `echo 3 > /proc/sys/vm/drop_caches` produces a window where `engine.count > 0` AND `block.count > 0` AND `block.total_wait_ns` is within 50% of `engine.total_ns` for that same window. The intuition: engine wait should be dominated by actual block wait, with cache-coordination + small overhead accounting for the gap.

**Deferred (FUTURE.md):**
- Write path: `CCH_flush(thread_db*, USHORT, TraNumber)` at `0x1f1330`. Async flushing decouples engine call from disk write — measurement is meaningful only with extra correlation.
- Per-query attribution: joining each `tragach-pageio` event back to the originating `tragach-slowquery` statement. Listed as v0.3 in FUTURE.md.
- Per-page-type breakdown: `WIN.win_page` carries a page-type discriminant; aggregating by type ("data page reads vs index reads vs blob page reads") is a follow-up.

## 6. Symbols artifact

For each Firebird version tracked:

- File: `symbols/<firebird-tag>-libEngine13.txt`
- Content: `nm -CD /opt/firebird-v5/plugins/libEngine13.so | sort` (or whichever invocation correctly resolves gnu_debuglink)
- Committed to git
- Regenerate on every Firebird version bump; diff before changing probe patterns
- An `xtask symbols` command produces it; CI (when added) verifies the committed file matches what the current installed binary produces

The file is ground truth for probe selection. If a probe target is in the source but not in this file, it does not exist in the binary and cannot be used.

## 7. Non-goals (1.0.0-beta)

Each of these is real future work, but explicitly out of 1.0.0-beta:
- Classic or SuperClassic architecture
- Firebird v3, v4, or v6 (v6 not yet stable; v3/v4 are v0.x+ work)
- Daemon mode, long-running background process
- Prometheus / OpenMetrics / StatsD exporter
- Persistent storage, history, time-series
- GUI, TUI, web UI
- Cross-platform (Windows, macOS, FreeBSD)
- Windows ETW or DTrace alternatives
- Upstream patch to Firebird adding USDT probes (separate effort, see FUTURE.md)
- Any of the other planned scripts beyond slowquery/iowait/attach (see FUTURE.md)
- Multi-tenant aggregation across multiple Firebird instances
- Plan visibility, query plan analysis
- SQL parsing or query-pattern fingerprinting

## 8. Success criteria for 1.0.0-beta as a whole

- Both binaries compile clean on the pinned Aya version
- Both binaries pass their per-script success criteria (§5.1, §5.2)
- `symbols/` committed and matches the installed binary
- README covers: what tragach is, install + run, both scripts with example output, known limitations
- Apache-2.0 LICENSE file present
- No Firebird source, struct layouts, or constants copied into the repo (license hygiene rule satisfied)
- Overhead measured: each script's per-event overhead documented in its header comment, total CPU impact on a busy Firebird benchmarked and reported in README

## 9. Open knowns / runtime determinations

These are resolved at execution time by reading authoritative sources, not by guessing:

- Exact Aya minor version to pin — pick the latest stable at project init, commit to `Cargo.toml`
- Exact Firebird v5 tag — already determined by the bootstrap; read it from the installed binary's `--version` output and from the source clone's checked-out tag
- Exact mangled probe patterns — read from `symbols/<tag>-libEngine13.txt`; verify probe counts before committing them to scripts
- Aya API specifics (uprobe attach syntax, ring buffer API) — read from Aya's pinned-version docs and examples, not from memory

## 10. References

- Firebird source (read-only): `~/src/firebird/`, tag pinned in `symbols/` filename
- Firebird Trace API reference: in source under `doc/` and headers under `src/jrd/trace/`
- Aya book: pinned version's documentation
- bpftrace reference manual: for cross-checking probe patterns
