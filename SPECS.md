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

**Hook points:**
- Probe pattern: substring `*DSQL_prepare*` and `*DSQL_execute*` against `/opt/firebird-v5/plugins/libEngine13.so`
- Expected probe count: ~2 per pattern (verify against `symbols/`)
- Justification: these are the documented entry points for DSQL handling and correspond to Trace API event boundaries (`event_dsql_prepare`, `event_dsql_execute`). Stable across Firebird point releases as a result.

**Capture:**
- Entry timestamp + arguments (attachment pointer, SQL text pointer, length)
- Exit timestamp
- Compute duration; emit event

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

**Success criterion:** running `tests/workloads/slowquery-basic.sql` produces an event line per statement, with durations matching `isql -t` wall-clock within 10%.

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

**Success criterion:** running `tests/workloads/iowait-basic.sql` (which intentionally issues a large table scan + a deliberately contended UPDATE) shows the block-I/O-wait bucket dominating during the scan and the futex-wait bucket appearing during the contention.

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
