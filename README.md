# tragach

[![build](https://github.com/ZlatanOmerovic/tragach/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/ZlatanOmerovic/tragach/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/ZlatanOmerovic/tragach?include_prereleases&sort=semver)](https://github.com/ZlatanOmerovic/tragach/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> *eBPF observability for Firebird — see why your queries are slow, not just that they are.*

Two CLI tools that observe a running Firebird v5 SuperServer:

- **`tragach-slowquery`** — engine-level DSQL statement tracing. Per-attachment prepare + execute timing with the SQL text, captured via uprobes on `libEngine13.so`. Covers cursor-based SELECTs (openCursor + fetchNext lifecycle) as well as the non-cursor DSQL_execute path.
- **`tragach-iowait`** — kernel-level off-CPU profiling of Firebird threads via `sched:sched_switch` / `sched:sched_wakeup`. Bucketed by reason (block I/O / futex / scheduler delay / other) with representative kernel stacks.

See [SPECS.md](SPECS.md) for the v0.1 work order. [FUTURE.md](FUTURE.md) tracks what is deliberately deferred.

## Status

**Version:** `1.0.0-beta` — first public pre-release, [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html). Both probes implemented, validated against live Firebird, overhead measured. CI builds against Ubuntu 22.04 / 24.04 and Debian 12 / 13. Binary tarballs attached to each release.

## Requirements

- Linux kernel ≥ 6.1 with BTF (`/sys/kernel/btf/vmlinux`)
- Firebird v5 SuperServer at `/opt/firebird-v5` (override with `--firebird-prefix`). For slowquery, the install must include debug symbols at `<firebird-prefix>/plugins/.debug/libEngine13.so.debug` — point `--debug-path` somewhere else if your distro installs them apart from the engine (e.g. a `firebird-dbgsym` package that lands them under `/usr/lib/debug/`).
- CAP_BPF + CAP_PERFMON (or root) to attach the BPF programs

## Build

Toolchain:

```bash
rustup toolchain install stable nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

The repo pins all required versions (Aya 0.13.1, bpf-linker 0.10.3) in `Cargo.toml`; the BPF subcrates are built with `nightly + -Z build-std=core --target bpfel-unknown-none` automatically by each userspace crate's `build.rs`.

Build the binaries:

```bash
cargo build --release -p tragach-slowquery
cargo build --release -p tragach-iowait
```

Regenerate the symbols artifact when bumping Firebird:

```bash
cargo xtask symbols
```

## Install

The binaries are self-contained. Copy them somewhere on `PATH`:

```bash
sudo install -m 0755 target/release/tragach-slowquery target/release/tragach-iowait /usr/local/bin/
```

Either run as root or grant `CAP_BPF` + `CAP_PERFMON`:

```bash
sudo setcap cap_bpf,cap_perfmon=eip /usr/local/bin/tragach-slowquery
sudo setcap cap_bpf,cap_perfmon=eip /usr/local/bin/tragach-iowait
```

## Usage

### `tragach-slowquery`

```bash
sudo tragach-slowquery \
    [--threshold 100ms] [--json] \
    [--firebird-prefix /opt/firebird-v5] \
    [--debug-path /usr/lib/debug/.../libEngine13.so.debug]
```

Example output (human-readable) — running the workload in `tests/workloads/slowquery-basic.sql`:

```
2026-05-12T22:24:36.553Z  att=2    prepare=    103us  execute=     20us  SELECT RDB$MAP_USING, RDB$MAP_PLUGIN, RDB$MAP_DB, ... FROM RDB$AUTH_MAPPING
2026-05-12T22:24:36.564Z  att=3    prepare=      0ns  execute=   2.16ms  SET TRANSACTION
2026-05-12T22:24:36.567Z  att=3    prepare=    826us  execute=     41us  SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO = 2
2026-05-12T22:24:36.568Z  att=3    prepare=     63us  execute=     48us  SELECT COUNT(*) FROM EMPLOYEE
2026-05-12T22:24:36.569Z  att=3    prepare=    346us  execute=    178us  SELECT D.DEPARTMENT, COUNT(E.EMP_NO) FROM DEPARTMENT D LEFT JOIN EMPLOYEE E ...
```

`att=N` is a sequential per-run small ID; the JSON output also emits `att_ptr` (the raw Attachment pointer in hex) for cross-run identity. `prepare=0ns` flags a `DSQL_execute_immediate` call (no separable prepare phase) or a prepared statement that was LRU-evicted before this execute.

`--json` emits one JSON object per line. Schema:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (RFC 3339, ms precision, UTC) | Event observation time in userspace |
| `att` | integer or `null` | Sequential per-run small ID; `null` when the attachment was not captured (execute without tracked prepare) |
| `att_ptr` | string (hex, e.g. `"0x7f8c1d04a000"`) or `null` | Raw `Attachment*` pointer; stable for the attachment's lifetime; `null` when unknown |
| `tid` | integer | Linux thread ID that issued the statement (server-side worker) |
| `prepare_us` | integer | `DSQL_prepare` duration in microseconds; `0` for `DSQL_execute_immediate`, LRU-evicted prepares, or untracked prepares |
| `execute_us` | integer | `DSQL_execute` / `DSQL_execute_immediate` / `openCursor`→EOF duration in microseconds |
| `sql` | string or `null` | SQL text up to 512 bytes; `null` when not captured |
| `truncated` | boolean | `true` when the SQL text exceeded 512 bytes and was truncated |

Example:

```json
{"ts":"2026-05-12T22:24:36.567Z","att":3,"att_ptr":"0x7f8c1d04a000","tid":740,"prepare_us":826,"execute_us":41,"sql":"SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO = 2","truncated":false}
{"ts":"2026-05-12T22:24:36.572Z","att":null,"att_ptr":null,"tid":740,"prepare_us":0,"execute_us":67,"sql":null,"truncated":false}
```

The second line shows the "execute without tracked prepare" case — tragach saw the execute but never saw the prepare (probably prepared before tragach attached, or LRU-evicted from the 1024-entry prepared-statement map).

### `tragach-iowait`

```bash
sudo tragach-iowait [--pid N] [--interval 10s] [--top-stacks 3] [--json]
```

By default it resolves the Firebird worker PID via `pgrep -x firebird` (override with `--pid`). Every `--interval`, prints a summary:

```
=== tragach-iowait  3s window  pid=736 ===
Off-CPU time by reason:
  futex wait            :   281ms  (  5 threads, top: futex_wait_queue)
        281ms  __schedule → schedule → futex_wait_queue → __futex_wait → futex_wait
  scheduler delay       :   136ms  (  2 threads, top: schedule_hrtimeout_range_clock)
        133ms  __schedule → schedule → schedule_hrtimeout_range_clock → do_sys_poll → __x64_sys_poll
          3ms  __schedule → schedule → jbd2_log_wait_commit → ext4_sync_file → ext4_buffered_write_iter
  block I/O wait        :    40ms  (  1 threads, top: io_schedule)
         32ms  __schedule → schedule → io_schedule → folio_wait_bit_common → filemap_get_pages
          3ms  __schedule → schedule → io_schedule → folio_wait_bit_common → filemap_fault
```

Bucket classification is by stack-frame substring: block I/O matches `blk_*` / `bio_*` / `submit_bio*` / `io_schedule*` / `wait_on_buffer`; futex matches `futex_*` / `do_futex` / `__futex*`; scheduler delay catches anything rooted at `schedule` that isn't one of the above; everything else falls into `other`.

`--json` emits one JSON object per flush window. Schema:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (RFC 3339, UTC) | Window emission time |
| `window_ms` | integer | Flush interval in milliseconds (mirrors `--interval`) |
| `pid` | integer | Target Firebird PID |
| `by_reason` | object | Keyed by reason label (`"block I/O wait"`, `"futex wait"`, `"scheduler delay"`, `"other"`); empty keys absent |
| `by_reason.<label>.total_ms` | integer | Total off-CPU milliseconds in this bucket this window |
| `by_reason.<label>.threads` | integer | Distinct thread IDs contributing to this bucket |
| `by_reason.<label>.top_stacks` | array | Up to `--top-stacks` entries, sorted by `ms` descending |
| `by_reason.<label>.top_stacks[].ms` | integer | Off-CPU milliseconds attributed to this exact stack |
| `by_reason.<label>.top_stacks[].frames` | array of strings | Kernel frames leaf-first (e.g. `["__schedule","schedule","io_schedule",…]`) |

## Why not just `SET STATS ON` in `isql`?

`isql`'s `SET STATS ON` reports a single "Elapsed time" number per statement — but that number includes the TCP round-trip from `isql` to the Firebird server **and** the time `isql` spends formatting + printing rows back. tragach probes the engine's `DSQL_prepare` / `DSQL_execute` (and the `openCursor` → EOF `fetchNext` cursor lifecycle) directly, so its `prepare_ns` and `execute_ns` are *just* the time spent inside the engine.

Same three queries against the bundled `employee.fdb`, captured back-to-back on the same idle VM (localhost TCP):

| Query | `isql` Elapsed | tragach `prepare` | tragach `execute` | tragach total | client overhead (the gap) |
|---|---:|---:|---:|---:|---:|
| `SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO=2` | 2000 µs | 853 µs | 46 µs | **899 µs** | ~1100 µs |
| `SELECT COUNT(*) FROM EMPLOYEE` | 1000 µs | 71 µs | 49 µs | **120 µs** | ~880 µs |
| `SELECT DEPARTMENT, COUNT(...) FROM DEPARTMENT LEFT JOIN EMPLOYEE GROUP BY DEPARTMENT` | 2000 µs | 421 µs | 216 µs | **637 µs** | ~1363 µs |

For sub-millisecond engine work, isql's number is dominated by client-side overhead — a >50% measurement error if you're trying to diagnose Firebird itself. tragach also separates `prepare_ns` from `execute_ns` (isql lumps them), and observes **every** attachment on the server, not just the one you happen to be typing into.

A few non-obvious benefits beyond accuracy:

- **No client change.** Applications don't need `SET STATS ON`, a Trace API plugin, or a recompile. tragach attaches uprobes from outside the process.
- **Cross-attachment view.** See what every connection is doing concurrently, not just one isql session.
- **Stack-level off-CPU attribution** (via `tragach-iowait`) — `SET STATS ON` can't tell you *why* a query was slow (block I/O? futex? scheduler delay?). tragach can.

The tradeoff is the [overhead below](#overhead) — tragach adds ~31 µs per DSQL statement (~10% wall-clock on a 3 300 stmts/s burst). `SET STATS ON` is essentially free. Use tragach when you need engine-level fidelity or the cross-attachment view; `SET STATS ON` is enough when you just want a one-shot end-to-end number from your isql session.

## Overhead

Measured on Debian 13 trixie (kernel 6.12), Firebird v5.0.4 SuperServer, against the bundled `employee.fdb`. Benchmark: 10 000 singleton SELECT statements via `isql`, mean of 5 runs each.

| | Baseline | Instrumented | Overhead |
|---|---|---|---|
| `tragach-slowquery` (10 000 stmt/3 s burst) | 309 µs/stmt | 340 µs/stmt | +31 µs/stmt (10.0% wall-clock) |
| `tragach-iowait` (same Firebird workload) | 3.11 s total | 3.13 s total | ≈ 0.6% wall-clock |
| `tragach-iowait` (non-Firebird, context-switch-heavy) | 12.38 s | 12.66 s | ≈ 2.3% wall-clock |

Methodology and per-probe breakdowns are in each script's source-file header (`crates/tragach-*/src/bpf/main.rs`). On a typical workload tragach-slowquery costs ~15 µs per uprobe/uretprobe pair (≈ two pairs per `DSQL_prepare` + `DSQL_execute` cycle). tragach-iowait's per-context-switch cost is below the test's ~1 µs jitter floor; the workload-level deltas above are the authoritative envelope.

## On the debug-symbol dependency (and how USDT would obsolete it)

`tragach-slowquery` attaches its probes by resolving offsets from the mangled C++ symbols in Firebird's `.debug/libEngine13.so.debug` file — the shipped `libEngine13.so` is stripped, and Firebird does not currently expose a stable, programmatic instrumentation interface for external tracers. The approach works (this is what `1.0.0-beta` ships), but it carries unavoidable cost: every Firebird release requires re-validating the `symbols/<tag>-libEngine13.txt` artifact, the symbols are not part of Firebird's ABI and can shift on recompile, `.cold` clones must be filtered to avoid double-counting, and we have to know the SysV AMD64 calling convention to read function arguments. A `firebird-dbgsym` package (or any unstripped build) is a hard runtime requirement.

The Linux-native solution to this entire class of problems is [USDT — User Statically Defined Tracing](https://docs.ebpf.io/linux/concepts/usdt/), the platform's successor to DTrace's static probes. A USDT probe is a `NOP` instruction the upstream author places at a deliberately chosen point in the source, with metadata — probe name, provider, *and the location of each argument* — recorded in a dedicated `.note.stapsdt` section of the shipped `.so`. eBPF tools attach by `provider:probe_name` and read arguments via the embedded spec. There is no debug file, no mangled symbol resolution, no calling-convention math, no `.cold` filtering, and no breakage on recompile. PostgreSQL, MySQL, Node, Python, Ruby, the JVM, and OpenSSL all ship USDT probes today.

If Firebird upstream were to add USDT probes at the DSQL event boundaries it already exposes through its Trace API (`event_dsql_prepare`, `event_dsql_execute`, the cursor open/fetch lifecycle), tragach could attach by stable names like `firebird:dsql_prepare__entry`, drop the `.debug` dependency entirely, stop maintaining per-version symbol artifacts, and survive Firebird recompiles automatically. The probes the Trace API already calls into are the natural locations; the only additional cost to Firebird is a handful of `STAP_PROBE` macros and a one-time `<sys/sdt.h>` build dep. Submitting a focused USDT patch upstream is tracked in [FUTURE.md](FUTURE.md) as a v0.5+ item, sequenced deliberately after enough real-world tragach usage to justify a specific probe list rather than a speculative one.

On the tooling side, [Aya](https://aya-rs.dev/) (tragach's userspace loader) does not yet ship a native USDT attach API — libbpf and bpftrace do — so the migration would coordinate either upstream Aya USDT support or a small in-tree `.note.stapsdt` parser feeding the offsets into a raw uprobe attach. Either path is a net simplification over the current symbol-based attachment; both are deferred until Firebird has the probes worth attaching to.

## Known limitations

- Firebird v5 SuperServer only (Classic/SuperClassic, v3/v4/v6 deferred — see FUTURE.md).
- Linux only (eBPF is Linux-only by design).
- `tragach-slowquery` does not probe `DSQL_free_statement`, so the prepared-statement map is LRU-bounded at 1024 entries; an event for an evicted statement reports `prepare_ns=0`. Cursor SELECTs closed before EOF are not emitted (FUTURE.md).
- `tragach-iowait` filters to a single PID. Firebird SuperServer is one process; Classic / SuperClassic (multiple worker processes) are deferred to FUTURE.md.
- Symbol resolution relies on Firebird's `.debug` files (gnu_debuglink target). A `firebird-dbgsym` package or an unstripped build is required.

## Related

- **[tragach-forge](https://github.com/ZlatanOmerovic/tragach-forge)** — adversarial Firebird workload generator. Peer project. Produces reproducible-but-pathological engine workloads (cold scans, contended UPDATEs, bulk imports, recursive queries, …) with seeded determinism and an NDJSON ground-truth recording of every operation it intended. Pair forge with tragach to validate that tragach observes the workloads forge generates — forge ships a `correlate.py` script that joins its recordings against tragach's `--json` output. Forge runs standalone too, as a general Firebird stress harness.

## License

Apache-2.0. See [LICENSE](LICENSE).
