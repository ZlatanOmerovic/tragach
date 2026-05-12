# SPECS.md — tragach v0.1

The work order for tragach v0.1. CLAUDE.md is the operating manual; this file is the spec. FUTURE.md is everything v0.1 explicitly defers.

## 1. Project identity

- **Name:** tragach (pronounced TRAH-gach, from Bosnian *tragač* — "tracer / one who follows tracks"). Use the spelling `tragach` consistently in all code, filenames, identifiers, documentation, commits, and user-facing strings. Do not use `tragač` or `tragac`.
- **Tagline:** *eBPF observability for Firebird — see why your queries are slow, not just that they are.*
- **License:** Apache-2.0
- **Relationship to other projects:** tragach is independent. It is not part of, namespaced under, or branded with Plamenix or any Firebird Foundation project. No cross-references unless the human explicitly approves.

## 2. v0.1 scope

Two CLI binaries:

1. **`tragach-slowquery`** — engine-level statement tracing. Captures DSQL statement prepare + execute timing per attachment, with the SQL text.
2. **`tragach-iowait`** — kernel-level off-CPU profiling of the Firebird process. Shows where Firebird threads spend time blocked (block I/O, futex, scheduler delay) and for how long.

These two are chosen because together they demonstrate the project's full value proposition: engine probing (slowquery) and kernel correlation (iowait). The other planned scripts are in FUTURE.md.

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
- Architecture: SuperServer only. Classic and SuperClassic are out of scope for v0.1.
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
- **Cursor-based SELECT** — one event when `DsqlCursor::fetchNext` returns `1` (EOF). `execute_ns` is total wall-clock from `DsqlDmlRequest::openCursor` entry to that EOF fetch return (matches Firebird's Trace API `req_fetch_elapsed` semantics — total time spent producing the result set). Cursors closed before EOF are lost for v0.1; `DSQL_free_statement` probe would close that gap and is deferred to FUTURE.md.

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

**Flags (v0.1):**
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

**Flags (v0.1):**
- `--pid <pid>` — override Firebird PID detection
- `--interval <duration>` — flush interval (default 10s)
- `--json`
- `--top-stacks <n>` — number of representative stacks per bucket (default 3)

**Success criterion:** running `tests/workloads/iowait-basic.sql` against a 2 GB database (built with `tests/workloads/build-large-db.sh`) with the page cache flushed shows the `block I/O wait` bucket scaling proportionally with actual disk activity — observed in validation: ~500 ms with no real read (BLOB pages not touched) vs ~1.3 s when the scan reads ~2 GB of BLOB data (`Reads = 252539` per isql's `SET STATS ON`). Both `futex wait` and `scheduler delay` buckets also appear, populated by Firebird's worker-pool threads sleeping on connection accept and inter-thread sync.

**Why "dominates" was the wrong test.** In SuperServer, idle worker threads accumulate sleep time as `N_workers × window × idle_fraction`. With 5 workers × 15 s × ~80% idle ≈ 60 s of futex-wait accumulated per 15 s window, the block-I/O bucket cannot dominate by raw aggregate even under heavy read workload (a 2 GB scan only generates ~1.3 s of I/O on NVMe). The tool reports the events correctly; "active-thread filtering" that would surface dominance is a v0.2 feature (FUTURE.md). Contended-UPDATE / futex-wait demonstration remains a manual two-session check.

## 6. Symbols artifact

For each Firebird version tracked:

- File: `symbols/<firebird-tag>-libEngine13.txt`
- Content: `nm -CD /opt/firebird-v5/plugins/libEngine13.so | sort` (or whichever invocation correctly resolves gnu_debuglink)
- Committed to git
- Regenerate on every Firebird version bump; diff before changing probe patterns
- An `xtask symbols` command produces it; CI (when added) verifies the committed file matches what the current installed binary produces

The file is ground truth for probe selection. If a probe target is in the source but not in this file, it does not exist in the binary and cannot be used.

## 7. Non-goals (v0.1)

Each of these is real future work, but explicitly out of v0.1:
- Classic or SuperClassic architecture
- Firebird v3, v4, or v6 (v6 not yet stable; v3/v4 are v0.x+ work)
- Daemon mode, long-running background process
- Prometheus / OpenMetrics / StatsD exporter
- Persistent storage, history, time-series
- GUI, TUI, web UI
- Cross-platform (Windows, macOS, FreeBSD)
- Windows ETW or DTrace alternatives
- Upstream patch to Firebird adding USDT probes (separate effort, see FUTURE.md)
- Any of the other planned scripts (see FUTURE.md)
- Multi-tenant aggregation across multiple Firebird instances
- Plan visibility, query plan analysis
- SQL parsing or query-pattern fingerprinting

## 8. Success criteria for v0.1 as a whole

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
