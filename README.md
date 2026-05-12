# tragach

> *eBPF observability for Firebird — see why your queries are slow, not just that they are.*

Two CLI tools that observe a running Firebird v5 SuperServer:

- **`tragach-slowquery`** — engine-level DSQL statement tracing. Per-attachment prepare + execute timing with the SQL text, captured via uprobes on `libEngine13.so`. Covers cursor-based SELECTs (openCursor + fetchNext lifecycle) as well as the non-cursor DSQL_execute path.
- **`tragach-iowait`** — kernel-level off-CPU profiling of Firebird threads via `sched:sched_switch` / `sched:sched_wakeup`. Bucketed by reason (block I/O / futex / scheduler delay / other) with representative kernel stacks.

See [SPECS.md](SPECS.md) for the v0.1 work order. [FUTURE.md](FUTURE.md) tracks what is deliberately deferred.

## Status

v0.1 functionally complete — both probes implemented, validated against live Firebird, overhead measured.

## Requirements

- Linux kernel ≥ 6.1 with BTF (`/sys/kernel/btf/vmlinux`)
- Firebird v5 SuperServer at `/opt/firebird-v5` (override with `--firebird-prefix`); for slowquery the install must include debug symbols (`<prefix>/plugins/.debug/libEngine13.so.debug`)
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
sudo tragach-slowquery [--threshold 100ms] [--json] [--firebird-prefix /opt/firebird-v5]
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

`--json` emits one JSON object per event:

```json
{"ts":"2026-05-12T22:24:36.567Z","att":3,"att_ptr":"0x7f8c1d04a000","tid":740,"prepare_us":826,"execute_us":41,"sql":"SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO = 2","truncated":false}
```

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

`--json` emits one JSON object per flush window with per-bucket totals and the top-N stacks.

## Overhead

Measured on Debian 13 trixie (kernel 6.12), Firebird v5.0.4 SuperServer, against the bundled `employee.fdb`. Benchmark: 10 000 singleton SELECT statements via `isql`, mean of 5 runs each.

| | Baseline | Instrumented | Overhead |
|---|---|---|---|
| `tragach-slowquery` (10 000 stmt/3 s burst) | 309 µs/stmt | 340 µs/stmt | +31 µs/stmt (10.0% wall-clock) |
| `tragach-iowait` (same Firebird workload) | 3.11 s total | 3.13 s total | ≈ 0.6% wall-clock |
| `tragach-iowait` (non-Firebird, context-switch-heavy) | 12.38 s | 12.66 s | ≈ 2.3% wall-clock |

Methodology and per-probe breakdowns are in each script's source-file header (`crates/tragach-*/src/bpf/main.rs`). On a typical workload tragach-slowquery costs ~15 µs per uprobe/uretprobe pair (≈ two pairs per `DSQL_prepare` + `DSQL_execute` cycle). tragach-iowait's per-context-switch cost is below the test's ~1 µs jitter floor; the workload-level deltas above are the authoritative envelope.

## Known limitations

- Firebird v5 SuperServer only (Classic/SuperClassic, v3/v4/v6 deferred — see FUTURE.md).
- Linux only (eBPF is Linux-only by design).
- `tragach-slowquery` does not probe `DSQL_free_statement`, so the prepared-statement map is LRU-bounded at 1024 entries; an event for an evicted statement reports `prepare_ns=0`. Cursor SELECTs closed before EOF are not emitted (FUTURE.md).
- `tragach-iowait` filters to a single PID. Firebird SuperServer is one process; Classic / SuperClassic (multiple worker processes) are deferred to FUTURE.md.
- Symbol resolution relies on Firebird's `.debug` files (gnu_debuglink target). A `firebird-dbgsym` package or an unstripped build is required.

## License

Apache-2.0. See [LICENSE](LICENSE).
