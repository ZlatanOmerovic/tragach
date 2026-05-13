# tragach

[![build](https://github.com/ZlatanOmerovic/tragach/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/ZlatanOmerovic/tragach/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/ZlatanOmerovic/tragach?include_prereleases&sort=semver)](https://github.com/ZlatanOmerovic/tragach/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> *eBPF tracing for Firebird — see why your queries are slow, not just that they are.*

## Contents

- [What's inside](#whats-inside)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
  - [`tragach-slowquery`](#tragach-slowquery)
  - [`tragach-iowait`](#tragach-iowait)
- [Worked example: tragach + tragach-forge](#worked-example-tragach--tragach-forge)
- [Why not just `SET STATS ON`?](#why-not-just-set-stats-on)
- [Overhead](#overhead)
- [Why we need debug symbols today](#why-we-need-debug-symbols-today)
- [Known limitations](#known-limitations)
- [Related projects](#related-projects)
- [Tech stack](#tech-stack)
- [Credits & license](#credits--license)

## What's inside

Two small command-line tools that watch a running Firebird v5 SuperServer from the outside, without changing anything inside it:

- **`tragach-slowquery`** — engine-level DSQL statement tracing. For every statement, you get the SQL text, the attachment it ran on, and separate timings for prepare and execute. Cursor-based SELECTs are tracked through their whole `openCursor`→`fetchNext`→EOF lifecycle, not just the open.
- **`tragach-iowait`** — kernel-level off-CPU profiling of Firebird's threads. Tells you *where* a thread was blocked (block I/O, futex, scheduler delay) and for how long, with a representative kernel stack per bucket.

Both attach via eBPF — no Firebird recompile, no client-side code change, no fbtrace plugin to configure.

`SPECS.md` is the authoritative work order. `FUTURE.md` is the deferred backlog. `docs/design-notes.md` records the probe choices and the SuperServer findings that shaped the design. If you want a real workload to point tragach at, see [tragach-forge](#related-projects) below — same author, peer project, built for exactly that.

## Requirements

- Linux kernel ≥ 6.1 with BTF (`/sys/kernel/btf/vmlinux` exists)
- Firebird v5 SuperServer at `/opt/firebird-v5` (override with `--firebird-prefix`)
- For `tragach-slowquery` specifically, debug symbols at `<firebird-prefix>/plugins/.debug/libEngine13.so.debug`, or pointed at via `--debug-path` (your distro's `firebird-dbgsym` package usually installs these under `/usr/lib/debug/`)
- `CAP_BPF` + `CAP_PERFMON` to attach the BPF programs (or just run as root)

## Install

### Pre-built binaries

Grab the latest release tarball from the [releases page](https://github.com/ZlatanOmerovic/tragach/releases):

```bash
# Pick the tarball matching your distro (ubuntu-22.04 or ubuntu-24.04)
curl -L -o tragach.tar.gz \
    https://github.com/ZlatanOmerovic/tragach/releases/latest/download/tragach-v1.0.0-beta-ubuntu-24.04-x86_64.tar.gz
tar xzf tragach.tar.gz
sudo install -m 0755 tragach-slowquery tragach-iowait /usr/local/bin/
```

### Build from source

You'll need rustup with both stable and nightly (the BPF side needs `rust-src`), plus `bpf-linker`:

```bash
rustup toolchain install stable nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

git clone https://github.com/ZlatanOmerovic/tragach
cd tragach
cargo build --release -p tragach-slowquery -p tragach-iowait
```

The userspace and BPF crates are built separately by each crate's `build.rs` — you don't need to think about it. Binaries land in `target/release/`.

If you bump Firebird, regenerate the symbols artifact:

```bash
cargo xtask symbols
```

### Capabilities

Either run as root, or grant the two capabilities once:

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

Sample output, watching `isql` against the bundled `employee.fdb`:

```
2026-05-12T22:24:36.553Z  att=2    prepare=    103us  execute=     20us  SELECT RDB$MAP_USING, RDB$MAP_PLUGIN, RDB$MAP_DB, ... FROM RDB$AUTH_MAPPING
2026-05-12T22:24:36.564Z  att=3    prepare=      0ns  execute=   2.16ms  SET TRANSACTION
2026-05-12T22:24:36.567Z  att=3    prepare=    826us  execute=     41us  SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO = 2
2026-05-12T22:24:36.568Z  att=3    prepare=     63us  execute=     48us  SELECT COUNT(*) FROM EMPLOYEE
2026-05-12T22:24:36.569Z  att=3    prepare=    346us  execute=    178us  SELECT D.DEPARTMENT, COUNT(E.EMP_NO) FROM DEPARTMENT D LEFT JOIN EMPLOYEE E ...
```

`att=N` is a small per-run identifier. The JSON form also emits `att_ptr` (the raw `Attachment*` pointer in hex) for cross-run identity. `prepare=0ns` means it was a `DSQL_execute_immediate` call (no separable prepare phase), or that the prepare happened before tragach attached.

`--json` emits one object per line:

| Field | Type | Notes |
|---|---|---|
| `ts` | string (RFC 3339 ms, UTC) | Observation time in userspace |
| `att` | integer or `null` | Per-run small ID; `null` if attachment unknown |
| `att_ptr` | string (hex) or `null` | Raw `Attachment*`; stable for the attachment's life |
| `tid` | integer | Linux thread ID of the Firebird worker |
| `prepare_us` | integer | `DSQL_prepare` duration in µs; `0` for immediate calls |
| `execute_us` | integer | `DSQL_execute` or `openCursor`→EOF duration in µs |
| `sql` | string or `null` | SQL text up to 512 bytes; `null` if not captured |
| `truncated` | boolean | `true` when SQL exceeded 512 bytes |

```json
{"ts":"2026-05-12T22:24:36.567Z","att":3,"att_ptr":"0x7f8c1d04a000","tid":740,"prepare_us":826,"execute_us":41,"sql":"SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO = 2","truncated":false}
```

### `tragach-iowait`

```bash
sudo tragach-iowait [--pid N] [--interval 10s] [--top-stacks 3] [--json]
```

Without `--pid`, it auto-detects via `pgrep -x firebird`. Every `--interval`, it prints a summary:

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

Classification is by stack-frame substring: block I/O matches `blk_*` / `bio_*` / `submit_bio*` / `io_schedule*` / `wait_on_buffer`; futex matches `futex_*` / `do_futex` / `__futex*`; scheduler delay catches anything rooted at `schedule` that isn't one of the above; everything else lands in `other`.

`--json` emits one object per flush window with `by_reason` keyed on the bucket label, each carrying `total_ms`, `threads` (distinct count), and `top_stacks[].{ms, frames}`.

## Worked example: tragach + tragach-forge

Two short scenarios from [tragach-forge](#related-projects) against a populated `forge.fdb` (20 000 INVENTORY rows, 439 CUSTOMER_NOTES, 50 WAREHOUSES, all loaded by `forge load --seed 42`). Both runs lasted one minute. `tragach-slowquery` and `tragach-iowait` were attached the whole time.

### Scenario 1 — `pathological-like`: a single SQL shape, high volume

Forge fires one query shape for sixty seconds: `SELECT CUSTOMER_NOTE_ID FROM CUSTOMER_NOTES WHERE NOTES LIKE '%word%'` — a full scan of every BLOB body, no index. The scenario is single-worker but doesn't rate-limit; it produced **13 783 iterations** at 230 statements/second.

`tragach-slowquery` captured one event per iteration. Distribution:

| | execute_us |
|---|---:|
| min | 1 187 |
| p50 | 1 570 |
| p99 | 2 191 |
| max | 4 760 |
| **total engine time over 60 s wall** | **22.08 s** |

The first event shows the cold-cache cost (`prepare=3 003 us`, `execute=3 899 us`); every subsequent execute reuses the prepared statement (`prepare=11 us`) and runs in roughly 1.5 ms. Without tragach you'd see this as one of many "SELECT against CUSTOMER_NOTES" lines in the Firebird log — with tragach you can see exactly that the engine spent 22 of the 60 wall seconds in this one query shape.

`tragach-iowait` for the same window:

```
--- window 2 (10000ms) ---
  futex wait              45531 ms  (5 threads)
  scheduler delay          9528 ms  (1 thread)
--- window 3 (10000ms) ---
  futex wait              35547 ms  (5 threads)
  scheduler delay          9538 ms  (1 thread)
```

Block I/O wait barely registers (the CUSTOMER_NOTES BLOBs fit in cache after the first read). The dominant numbers are the SuperServer worker-pool baseline — five idle worker threads accumulating futex-wait time, one accept thread accumulating poll-wait — exactly the architectural finding the design notes call out (`docs/design-notes.md` → *SuperServer worker-pool finding*). The signal you care about for this workload is in `tragach-slowquery`'s output, not `tragach-iowait`'s.

### Scenario 2 — `indexed-vs-unindexed`: the "show, don't tell" demo

Forge alternates two queries per iteration on the same table:

```sql
-- A: uses IX_INVENTORY_WH_PROD
SELECT INVENTORY_ID, QUANTITY_ON_HAND FROM INVENTORY
WHERE WAREHOUSE_ID = ? AND PRODUCT_ID = ?

-- B: full scan, DESCRIPTION has no index
SELECT INVENTORY_ID FROM INVENTORY WHERE DESCRIPTION LIKE ?
```

(Firebird 5 SuperServer reliably crashed under this scenario in our environment after 35 iterations — the forge documentation calls these *the signal, not a bug*. The 41 events that made it through tell the story we need:)

| Query shape | n | min | p50 | p99 | max |
|---|---:|---:|---:|---:|---:|
| Indexed lookup (`WHERE WAREHOUSE_ID = ? AND PRODUCT_ID = ?`) | 20 | 24 µs | **43 µs** | 501 µs | 479 µs |
| Unindexed LIKE (`WHERE DESCRIPTION LIKE ?`) | 21 | 5 767 µs | **6 857 µs** | 19 662 µs | 15 351 µs |

**Median unindexed query is 159× slower than median indexed query** on the same table, against the same data, in the same session. In a log file these look identical — *"two SELECTs against INVENTORY"*. tragach surfaces the gap immediately, per statement:

```json
{"ts":"2026-05-13T02:05:10.437Z","att":3,"att_ptr":"0x7f46af51f040","tid":175574,
 "prepare_us":181,"execute_us":44,
 "sql":"SELECT INVENTORY_ID, QUANTITY_ON_HAND FROM INVENTORY WHERE WAREHOUSE_ID = ? AND PRODUCT_ID = ?","truncated":false}

{"ts":"2026-05-13T02:05:10.427Z","att":3,"att_ptr":"0x7f46af51f040","tid":175574,
 "prepare_us":313,"execute_us":15351,
 "sql":"SELECT INVENTORY_ID FROM INVENTORY WHERE DESCRIPTION LIKE ?","truncated":false}
```

Same attachment, same thread, ten milliseconds apart — `execute_us` differs by 350×. That kind of per-statement evidence is what you point at when someone asks *"why is the app slow?"*.

### Reproducing this

```bash
# In the tragach-forge clone:
export FORGE_DB_PASSWORD='...'
.venv/bin/forge init --force
.venv/bin/forge load --seed 42

# In one terminal:
sudo tragach-slowquery --json > /tmp/slowq.ndjson

# In another terminal:
sudo tragach-iowait --interval 10s --json > /tmp/iowait.ndjson

# In a third:
.venv/bin/forge run pathological-like --seed 42 --duration 1m \
    --record /tmp/forge-intent.ndjson

# Then correlate:
python -m forge.correlate /tmp/forge-intent.ndjson /tmp/slowq.ndjson
```

`correlate.py` joins forge's intent stream against tragach's observation stream and reports coverage (% of forge intents tragach saw), per-scenario accuracy (mean / p50 / p99 of `|forge_duration − tragach_duration|`), and false positives (tragach events with no matching forge intent — engine-internal traffic, trigger work, etc.).

## Why not just `SET STATS ON`?

`isql`'s `SET STATS ON` gives you one wall-clock number per statement — but that number includes the TCP round-trip to Firebird *and* the time `isql` spends formatting + printing rows. tragach probes `DSQL_prepare` / `DSQL_execute` / `openCursor`→EOF directly, so its timings are *only* what the engine actually did.

Same three queries against the bundled `employee.fdb`, idle localhost VM:

| Query | `isql` Elapsed | tragach `prepare` | tragach `execute` | tragach total | the gap |
|---|---:|---:|---:|---:|---:|
| `SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO=2` | 2000 µs | 853 µs | 46 µs | **899 µs** | ~1100 µs |
| `SELECT COUNT(*) FROM EMPLOYEE` | 1000 µs | 71 µs | 49 µs | **120 µs** | ~880 µs |
| `SELECT DEPARTMENT, COUNT(...) FROM DEPARTMENT LEFT JOIN EMPLOYEE GROUP BY DEPARTMENT` | 2000 µs | 421 µs | 216 µs | **637 µs** | ~1363 µs |

For sub-millisecond engine work, isql's number is *mostly* client overhead. If you want to diagnose Firebird itself, that's a >50% error.

A few other things tragach gives you that `SET STATS` can't, at any speed:

- **Every attachment, not just yours.** You see what every connection is doing, not just the one you typed `SET STATS ON` into.
- **`prepare_ns` and `execute_ns` separate.** isql lumps them.
- **No client change.** No `SET STATS ON` per script, no Trace API plugin, no application recompile.
- **Stack-level *why* attribution** through `tragach-iowait`. `SET STATS` won't tell you a query waited 800 ms in `io_schedule` because pages weren't cached.

The trade is overhead — tragach adds ~10 % wall-clock per query while attached. `SET STATS` is essentially free. Use tragach when you need engine fidelity or a cross-attachment view; `SET STATS` is fine for "how long did this one statement take from my session?".

## Overhead

Measured on Debian 13 trixie (kernel 6.12), Firebird v5.0.4 SuperServer, against the bundled `employee.fdb`. Benchmark: 10 000 singleton SELECT statements via `isql`, mean of 5 runs each.

| | Baseline | Instrumented | Overhead |
|---|---|---|---|
| `tragach-slowquery` (10 000 stmts/3 s burst) | 309 µs/stmt | 340 µs/stmt | +31 µs/stmt (10.0 % wall-clock) |
| `tragach-iowait` (same Firebird workload) | 3.11 s total | 3.13 s total | ≈ 0.6 % wall-clock |
| `tragach-iowait` (non-Firebird, context-switch-heavy) | 12.38 s | 12.66 s | ≈ 2.3 % wall-clock |

Per-probe breakdown lives in each script's source-file header (`crates/tragach-*/src/bpf/main.rs`). On a typical workload `tragach-slowquery` costs ~15 µs per uprobe/uretprobe pair (roughly two pairs per `DSQL_prepare`+`DSQL_execute` cycle). `tragach-iowait`'s per-context-switch handler cost is below the test's ~1 µs jitter floor; treat the workload-level deltas above as the authoritative envelope.

## Why we need debug symbols today

`tragach-slowquery` resolves probe offsets from the mangled C++ symbols in Firebird's `.debug/libEngine13.so.debug` — the shipped `libEngine13.so` is stripped, and Firebird doesn't currently expose a stable, programmatic interface for external tracers. It works (it's what `1.0.0-beta` ships), but it's not free: every Firebird release means re-validating `symbols/<tag>-libEngine13.txt`, the symbols aren't ABI and can shift on recompile, `.cold` clones need filtering, and we have to know the SysV AMD64 calling convention to read function arguments.

The clean Linux-native answer is [**USDT** (User Statically Defined Tracing)](https://docs.ebpf.io/linux/concepts/usdt/), the platform's successor to DTrace's static probes. A USDT probe is a `NOP` instruction the upstream author places at a deliberately chosen point in source, with metadata — probe name, provider, *and the location of each argument* — recorded in a dedicated `.note.stapsdt` section of the shipped `.so`. eBPF tools attach by `provider:probe_name` and read arguments via the embedded spec. No debug file. No mangled symbol math. No `.cold` filtering. Recompile-stable. PostgreSQL, MySQL, Node, Python, Ruby, the JVM, and OpenSSL all ship USDT probes today.

If Firebird upstream were to add USDT probes at the DSQL event boundaries it already exposes through its Trace API (`event_dsql_prepare`, `event_dsql_execute`, the cursor open/fetch lifecycle), tragach could attach by stable names like `firebird:dsql_prepare__entry`, drop the `.debug` dependency entirely, and stop maintaining per-version symbol artifacts. The probes the Trace API already calls into are the natural locations; the additional cost to Firebird is a handful of `STAP_PROBE` macros and a one-time `<sys/sdt.h>` build dep. Submitting a focused USDT patch upstream is tracked in [FUTURE.md](FUTURE.md) as a v0.5+ item, sequenced deliberately after enough real-world tragach usage to justify a specific probe list rather than a speculative one.

On the tooling side, [Aya](https://aya-rs.dev/) (tragach's userspace loader) doesn't yet ship a native USDT attach API — libbpf and bpftrace do — so the migration would also coordinate either upstream Aya USDT support or a small in-tree `.note.stapsdt` parser. Either path is a net simplification over the current symbol-based attachment; both are deferred until Firebird has the probes worth attaching to.

## Known limitations

- **Firebird v5 SuperServer only.** Classic / SuperClassic and Firebird v3 / v4 / v6 are deferred — see [FUTURE.md](FUTURE.md). v6 isn't shipped stable yet anyway.
- **Linux only.** eBPF is a Linux thing.
- **`tragach-slowquery` doesn't probe `DSQL_free_statement`.** The prepared-statement map is LRU-bounded at 1024 entries; events for evicted statements report `prepare_ns=0` and unknown SQL. Cursors closed before EOF never emit. Both are tracked in FUTURE.md.
- **`tragach-iowait` filters to one PID.** SuperServer is a single process so this works. Classic / SuperClassic (multiple worker processes) are out of scope for `1.0.0-beta`.
- **Debug symbols required.** A `firebird-dbgsym` package or unstripped build is a hard runtime requirement for `tragach-slowquery`. The [Why we need debug symbols today](#why-we-need-debug-symbols-today) section explains what would change that.

## Related projects

### [tragach-forge](https://github.com/ZlatanOmerovic/tragach-forge)

Adversarial Firebird workload generator. Peer project, same author, built specifically to feed tragach interesting work.

Forge gives you:

- **A populated 1M-row INVENTORY** plus 100 warehouses, 10k products, 5k customer notes, with optional mixed-mode dirty baseline that produces dead version chains, GC backlog, and fragmented free space — the conditions where Firebird gets interesting.
- **15 scenarios** covering steady OLTP, hot-row contention, cold full-table scans, indexed-vs-unindexed pairs, long-held transactions, complex multi-table joins, slow aggregates, correlated subqueries, recursive CTEs, window functions, heavy GROUP BY, and SUSPEND-style PSQL streaming. `mixed-chaos` weights them into a production-shaped traffic mix.
- **Seed-deterministic recording.** Every operation forge intends to run is written to NDJSON before it fires, with a ULID intent ID. Two runs at the same `--seed` produce byte-identical intent streams.
- **`correlate.py`** joins forge's intent NDJSON against `tragach-slowquery --json` and reports coverage (% of forge intents tragach saw), accuracy (per-scenario p50/p99 of |forge − tragach| duration), and false positives.

Forge has also helpfully discovered that Firebird 5 SuperServer reliably crashes under its mixed-chaos workload at ≥4 concurrent writers. The forge authors are explicit: *the crashes are the signal*, exactly the kind of engine pathology tragach is built to surface.

You don't have to run forge to use tragach — point tragach at your own workload, or just at idle Firebird if you want to see what production traffic looks like. Forge is the reproducible counterpart for development and validation.

## Tech stack

**Userspace (stable Rust):**

- [Aya 0.13.1](https://aya-rs.dev/) — eBPF loader and program manager
- [aya-log 0.2.1](https://crates.io/crates/aya-log) — log-from-BPF helpers (currently unused but available)
- [Tokio 1.x](https://tokio.rs/) — async runtime for ring-buffer polling and signal handling
- [clap 4](https://crates.io/crates/clap) — CLI parsing
- [serde + serde_json 1.x](https://serde.rs/) — JSON output
- [chrono 0.4](https://crates.io/crates/chrono) — timestamps
- [humantime 2](https://crates.io/crates/humantime) — `--threshold 100ms` style durations
- [object 0.36](https://crates.io/crates/object) — ELF parsing for symbol-offset resolution
- [nix 0.29](https://crates.io/crates/nix) — Unix-y bindings (signals, capabilities checks)

**BPF side (nightly Rust + `-Z build-std=core` + `bpfel-unknown-none`):**

- [aya-ebpf 0.1.1](https://crates.io/crates/aya-ebpf) — kernel-side eBPF macros and map types
- [aya-log-ebpf 0.1.0](https://crates.io/crates/aya-log-ebpf) — log macros for BPF
- [bpf-linker 0.10.3](https://github.com/aya-rs/bpf-linker) — LLVM-based BPF object linker

**Kernel features used:**

- uprobes + uretprobes (for engine-side function entry/exit)
- `sched:sched_switch` / `sched:sched_wakeup` tracepoints (for off-CPU profiling)
- `BPF_MAP_TYPE_RINGBUF` (event stream), `BPF_MAP_TYPE_LRU_HASH` (prepared-statement cache), `BPF_MAP_TYPE_STACK_TRACE` (kernel stacks)
- BTF (`/sys/kernel/btf/vmlinux`) for CO-RE friendliness

**Build & CI:**

- GitHub Actions matrix across Ubuntu 22.04 / 24.04 and Debian 12 / 13 (containers for the Debian legs)
- Tag-triggered release workflow that builds, packages tarballs + SHA-256, attaches to a GitHub release
- Branch protection on `main`: PR required, all 4 CI checks must pass

## Credits & license

Built by **Zlatan Omerović** — [@ZlatanOmerovic](https://github.com/ZlatanOmerovic) · zlomerovic@hotmail.com.

Pair-programmed with [Claude](https://claude.com/claude-code) (Anthropic) as a coding collaborator — including the eBPF probe design, the workspace + CI scaffolding, the Firebird-source archaeology, and most of the prose you're reading right now.

Released under the [Apache License 2.0](LICENSE).
