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

## Known limitations

- Firebird v5 SuperServer only (Classic/SuperClassic, v3/v4/v6 deferred — see FUTURE.md).
- Linux only (eBPF is Linux-only by design).

## License

Apache-2.0. See [LICENSE](LICENSE).
