# FUTURE.md — tragach beyond v0.1

This file documents work that is *deliberately deferred* past v0.1. Items here are out of scope for the current SPECS.md; they enter scope only by being moved into SPECS.md in a dedicated commit.

The purpose of this file is twofold: (1) prevent scope creep in v0.1 by giving every "but wouldn't it be cool to..." a home outside SPECS.md, and (2) preserve design thinking so it isn't lost between versions.

## v0.2 — additional scripts

The other two scripts originally planned alongside `tragach-slowquery` and `tragach-iowait`:

### `tragach-attach`
**Question:** *Connection lifecycle — who connects, from where, how long is each attachment, what does it do?*

**Hook points (planned):**
- Probe patterns against `libEngine13.so`: attachment construction and destruction. Candidate substrings include `*Attachment*C1*` (constructor) and `*Attachment*D1*` (destructor), but `*Attachment*` alone matched 571 probes during bootstrap verification and exceeds bpftrace's 1024-program default — narrowing is required. Read `symbols/` and pick a tight pattern at v0.2 design time.
- Optional: kernel-side `tcp_v4_connect` / `inet_csk_accept` correlation for connection source IP and port.

**Open design questions:**
- How to key events to a specific attachment ID across the connection's lifetime when the attachment struct's layout isn't part of a stable ABI — likely via the attachment pointer captured at construction time.
- Whether to capture authentication events or stay at connection-lifecycle level only.

### `tragach-pageio`
**Question:** *When Firebird reads or writes a database page, what's the underlying block-device latency, and which queries triggered the I/O?*

This is the killer demo: correlating engine-level page operations with kernel-level block-device events. Source-side probe is at the buffer-manager / cache-manager layer in Firebird (`src/jrd/cch.cpp` and adjacent). Kernel side is `block_rq_issue` / `block_rq_complete` tracepoints.

**Open design questions:**
- Engine probe target needs careful selection. `CCH_*` functions in v5 are mangled C++ — read `symbols/` at design time.
- Correlation across engine event and kernel block event uses (PID, request ID) tuple — verify request ID is available at both ends.
- Output format: per-query I/O attribution, or aggregated histogram? Probably both with a flag.

## v0.2 — iowait active-thread filtering

The original SPECS §5.2 success criterion ("block I/O dominates during scans") proved unachievable on SuperServer: idle worker threads sleeping in `futex_wait` and the connection-accept thread sleeping in `poll()` accumulate `N_threads × window × idle_fraction` of off-CPU time regardless of workload, so the absolute aggregate is always futex-dominated even when actual disk activity is heavy. tragach-iowait correctly tracks proportional response (block I/O grew 2.7× under a 2 GB cold scan in validation), but the "dominance" view requires distinguishing "thread sleeping waiting for work" from "thread sleeping waiting for I/O or a lock."

**Plan:** add a v0.2 flag (`--active-threads` or `--exclude-idle`) that suppresses any (pid, stack_id) bucket whose accumulated off-CPU time exceeds some fraction of the window (suggesting the thread spent the whole window in that one wait — a near-certain idle marker). Alternatively / additionally, emit per-thread bucket breakdowns so the scan thread's profile is visible independently of the worker pool's idle profile. Document the heuristic alongside the flag.

## v0.2+ — slowquery parameter values

Currently `tragach-slowquery` captures the SQL template that `DSQL_prepare` receives — for parameterized statements that means the literal `?` placeholders, not the bound values. The values arrive separately at `DSQL_execute` time through two arguments we ignore today: `IMessageMetadata* in_meta` (RCX, arg 3) and `const UCHAR* in_msg` (R8, arg 4). The metadata describes parameter count, types, offsets, and null bitmap; the message is the binary-packed value buffer.

This is intentionally deferred. Reasons:
- `IMessageMetadata` is a Firebird OO virtual interface (`getCount`, `getType`, `getOffset`, `getLength`, `getNullable`, `getScale`, …). BPF programs cannot make virtual calls, so we can't introspect it from kernel-side.
- The struct backing the interface is not part of any stable ABI. Per CLAUDE.md license hygiene we'd have to re-derive field offsets per Firebird version with `pahole`, no copying. Maintenance burden grows per supported version.
- Type-specific decoding (TIMESTAMP, NUMERIC with scale, VARCHAR length-prefix, BLOB IDs that reference separate pages, CHARSET-aware text) is non-trivial and partly requires database-side lookups.

**Plan (sketch, when promoted):**
1. BPF side captures the raw `in_msg` bytes (up to a fixed cap, e.g. 1 KiB) and the `IMessageMetadata*` pointer; ringbuf-emits both alongside the existing event.
2. Userspace maintains a per-`DsqlRequest*` metadata cache populated by reconnecting to Firebird as SYSDBA and calling `isc_dsql_describe_bind` (or the modern OO equivalent) to learn the parameter shape. This avoids any struct-offset assumptions.
3. Userspace decodes the binary buffer using the cached metadata and renders values per type.
4. Output adds a `params` array to the JSON schema and a `params=[…]` suffix to the human display, gated behind a `--with-params` flag (off by default — privacy concern, since values often contain PII / secrets).

**Open question for promotion:** the privacy default. Some shops will want values; others can't have them in logs. v0.x ships off-by-default; v1.x may reverse if reasonable redaction is in place.

## v0.2+ — quality-of-life

- **Single `tragach` binary with subcommands.** `tragach slowquery`, `tragach iowait`, etc. Shared CLI parsing, shared output formatting, shared `--firebird-prefix` resolution. Worth doing once there are ≥3 scripts.
- **`tragach symbols` subcommand.** Regenerate `symbols/` from the currently installed Firebird without going through `xtask`. Convenience wrapper around `nm -CD` with the gnu_debuglink handling baked in.
- **`tragach version` reporting.** Print tragach version, Aya version, target Firebird tag from `symbols/`, kernel version, BTF availability.
- **Multi-attachment correlation in slowquery.** Currently each event is independent; v0.2 could group sequential statements per attachment for "session view."

## v0.3 — multi-architecture and multi-version

- **Firebird Classic and SuperClassic support.** Classic spawns one process per connection — the tool needs per-process attachment logic instead of single-process. Significant refactor; do not merge into v0.x scripts opportunistically, design as v0.3.
- **Firebird v4 support.** Likely different `libEngine*.so` name and possibly different mangled symbols. New `symbols/` artifact, conditional probe selection at runtime. Versioned via a `tragach-target` config block.
- **Firebird v6 support.** Once v6 ships stable. May involve different plugin architecture.

## v0.4 — deployment shapes

- **Daemon mode.** Long-running `tragach-agent` that hosts multiple scripts simultaneously, manages BPF program lifecycle, exposes a control plane (Unix socket or HTTP). At this point, the libbpf-rs / loader story matters more than the script-as-binary story.
- **Prometheus / OpenMetrics exporter.** `tragach-agent --metrics-port 9100` exposes counters and histograms. Standard infra integration. Useful once tragach-agent exists.
- **Structured logging output.** Beyond `--json`, support OpenTelemetry log format for ingestion into Loki, Elasticsearch, Datadog, etc.

## v0.5+ — ecosystem moves

- **Upstream USDT-probe PR to Firebird.** This was the original "should I post the PR?" question. Postponed deliberately because v0.1–v0.4 give us empirical evidence about which probe points are valuable. With months of real usage, the PR becomes "here are the 6 probes I keep needing, here's why these and not others" rather than a speculative patch. RFC on firebird-devel first, then PR with limited scope.
- **Firebird Trace API plugin alternative.** Once tragach has proven its value as an external tool, consider whether a parallel implementation as a Trace API plugin (registered via `firebird.conf`'s `TracePlugin`) would help users who can't run BPF. Different code path, same data model.
- **Integration with Plamenix.** If and only if the human decides this is desirable. tragach stays usable standalone regardless. The integration would likely be: Plamenix shells out to `tragach-*` and visualizes the JSON output. Plamenix-side work, not tragach-side, except for stabilizing the `--json` schema.

## v1.0 — rewrite the keepers in C/libbpf

After v0.x has proven which scripts are durably valuable, the high-value ones get a second life as C/libbpf programs for production distribution. Single-binary, CO-RE, packageable in distros. The Aya versions stay as the canonical reference implementation and as the iteration substrate for new features.

This is *deliberate*, not regrettable. The bpftrace-then-libbpf path is well-trodden in the eBPF community; Aya-then-libbpf is the same pattern with the prototyping language different. Speak about it as "graduating" a script, not "abandoning Rust."

## Explicitly will-not-do

These appear in this file so that if anyone proposes them, the answer is documented:

- **GUI for tragach itself.** tragach is a CLI. Plamenix can visualize tragach's output; tragach itself does not ship UI.
- **Windows or macOS support.** eBPF is Linux-only. Windows users can run tragach in a Linux VM (which is how the project was bootstrapped). No ETW or DTrace ports.
- **Replacing Firebird's Trace API.** The Trace API is the official semantic event stream. tragach complements it by adding the kernel-level layer below. Users who only need SQL event auditing should keep using `fbtracemgr` / FB TraceManager.
- **SQL parsing or query-shape fingerprinting.** Firebird itself can produce statement hashes (or the user can post-process JSON output). tragach does not parse SQL.
- **Becoming a general-purpose database observability tool.** No Postgres support, no MySQL support, no abstraction layer. tragach is for Firebird. If you want general, use other tools.

## How items move from FUTURE.md to SPECS.md

1. Open an issue (or a discussion document) describing the work, its scope, its success criteria.
2. Confirm prerequisites are met — usually that v0.(N-1) has shipped and gathered enough real-use evidence.
3. Move the item's section from FUTURE.md to a new section in SPECS.md, in a dedicated commit. The commit message is "scope: promote X from FUTURE.md to SPECS.md, target vN.M".
4. Implement under the rules in CLAUDE.md.
5. After ship, the item leaves FUTURE.md permanently (no need to record completed work here).
