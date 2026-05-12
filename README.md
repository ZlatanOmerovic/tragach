# tragach

> *eBPF observability for Firebird — see why your queries are slow, not just that they are.*

Two CLI tools that observe a running Firebird v5 SuperServer:

- **`tragach-slowquery`** — engine-level DSQL statement tracing.
- **`tragach-iowait`** — kernel-level off-CPU profiling of Firebird threads.

See [SPECS.md](SPECS.md) for the v0.1 work order. See [FUTURE.md](FUTURE.md) for deferred work.

## Status

v0.1 — skeleton landed; probe implementations in progress.

## Requirements

- Linux kernel ≥ 6.1 with BTF (`/sys/kernel/btf/vmlinux`)
- Firebird v5 SuperServer at `/opt/firebird-v5` (override with `--firebird-prefix`)
- CAP_BPF + CAP_PERFMON (or root) to attach the BPF programs

## Build

> TODO: documented once the build pipeline is verified end-to-end on a fresh checkout.

Outline: stable Rust for userspace, nightly + `rust-src` + `bpf-linker` for the BPF side. `cargo xtask build` orchestrates both.

## Install

> TODO

## Usage

> TODO — example output for each script.

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

## License

Apache-2.0. See [LICENSE](LICENSE).
