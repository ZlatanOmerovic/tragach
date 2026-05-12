# tragach design notes

This file records *why* — probe-target choices, divergences from Firebird's Trace API, surprises found during validation. SPECS.md is *what*; this is *why*. Append-only by convention.

## Symbols artifact

`symbols/v5.0.4-libEngine13.txt` is the ground-truth list of probe targets, generated from `/opt/firebird-v5/plugins/.debug/libEngine13.so.debug` via `xtask symbols`.

Important: the stripped `libEngine13.so` exposes only ~495 dynamic symbols, almost all *imports* from libfbclient. The internal engine C++ functions (`DSQL_*`, `JRD_*`, `CCH_*`, `Attachment::*`) live only as local `t` symbols in the `.debug` file. `nm -CD` of the stripped binary is therefore insufficient — `xtask symbols` reads the `.debug` file via gnu_debuglink instead. CLAUDE.md treats the artifact as ground truth; the artifact is wrong if it's missing internals, so the source choice matters.

## DSQL probe targets (slowquery, SPECS §5.1)

From the v5.0.4 symbols artifact, the substring patterns yield:

- `DSQL_prepare` — 2 matches: 1 primary + 1 `[clone .cold]`
- `DSQL_execute` — 4 matches: 2 distinct functions (`DSQL_execute`, `DSQL_execute_immediate`), each with 1 `[clone .cold]`

`.cold` clones are GCC-emitted secondary entry blocks for unlikely paths within the same function. Attaching a uprobe to a `.cold` clone double-counts in pathological cases. The implementation pass must filter the substring match to exclude `[clone .cold]` (and document why in code).

Both primaries are mangled C++ in the source under `~/src/firebird/src/dsql/dsql.cpp` (verify path:line at implementation time). They are the documented entry points for DSQL handling and align with Firebird's Trace API events (`event_dsql_prepare`, `event_dsql_execute`) — stable across point releases as a result.

## iowait probe targets (SPECS §5.2)

No Firebird symbols. Two kernel tracepoints:

- `sched:sched_switch` — fires when a thread is descheduled. Filter to threads whose `prev_pid` belongs to the Firebird process; record the off-CPU start timestamp keyed by `prev_pid`.
- `sched:sched_wakeup` — fires when a thread becomes runnable. Look up the start timestamp, compute the delta, attribute it to a bucket keyed by the kernel stack captured at `sched_switch` time.

Bucket classification (Other / BlockIo / Futex / SchedDelay) happens at flush time in userspace, by matching kernel-stack symbols against a small known-token set. This keeps the BPF side simple and dependent only on `bpf_get_stackid` + ring-buffer emission.

## License hygiene

No Firebird source, struct layouts, doc-comments, or constants get copied into this repo. References are by `path:line` only. Struct field offsets, if ever needed, are re-derived with `pahole` against the compiled binary.
