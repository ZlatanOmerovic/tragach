# CLAUDE.md

You are working on **tragach** — an eBPF observability tool for FirebirdSQL Server, written in Rust with Aya. The project answers *why* a Firebird query was slow, not just *that* it was, by combining engine-level uprobes with kernel-level tracing.

Read **SPECS.md** for the v0.1 work order, target configuration, and exact script designs. Read **FUTURE.md** for deferred work — anything not in SPECS.md is out of scope until SPECS.md is amended in a separate commit.

## Operating principles

- **Scope is locked by SPECS.md.** New probe targets, new scripts, new features: edit SPECS.md first in a separate commit, then implement. If you're tempted to add something "while I'm here," stop and ask.
- **Source-reading is mandatory.** Before proposing any probe, read the relevant Firebird source at `~/src/firebird/` (pinned to the v5 tag in SPECS.md). Source presence is necessary; binary presence (next rule) is the sufficient check.
- **Binary verification is non-negotiable.** Every probe target must exist in `nm -CD` output of the actual installed binary (typically `/opt/firebird-v5/plugins/libEngine13.so`, following gnu_debuglink to the `.debug` file). Source says exists ≠ binary has the symbol. Inlining and LTO are real.
- **The `symbols/` directory is ground truth.** Per Firebird tag, commit `nm -CD` output as a checked-in artifact. Diff on version bumps to detect breakage early.
- **Mangled C++ is the reality.** Firebird v5 symbols are mangled C++ (no `JRD_*` C-style names). bpftrace and Aya match against demangled or mangled forms via substring patterns. Every probe in SPECS.md specifies (a) its substring pattern, (b) its expected probe count from the symbols file, and (c) whether that count is under bpftrace's 1024-program default. Do not ship a probe whose count exceeds the limit without narrowing.
- **Prefer Trace API hook sites where available.** Functions Firebird's own Trace API calls (search source for `TraceManager::event_*`, `TracePlugin` callsites) are stable boundaries. If a probe choice diverges from Trace API sites, comment in the code why.
- **Validate against live Firebird.** Every script must be exercised against the running Firebird instance with a known workload (an `isql` script in `tests/workloads/`). Observed event counts must match expectations from source reading. Divergence → investigate before merging.
- **License hygiene.** No Firebird source code, struct layouts, doc-comments, or constants copied into the tragach repo. Reference by `path:line` only. Struct field offsets, if ever needed, get re-derived with `pahole` on the compiled binary.
- **No daemon, no exporter, no GUI.** v0.1 is two CLI binaries that print to stdout. See FUTURE.md for what's deferred.

## Workflow for adding or modifying a script

1. Identify the user-facing question the script answers (already in SPECS.md, or amend it).
2. Read relevant Firebird source paths to find candidate hook points.
3. Prefer Trace API sites; if not, document the choice in code.
4. Verify candidates exist in `symbols/<firebird-tag>-libEngine13.txt`. Check probe count against the 1024 limit.
5. Implement (`cargo build` against nightly with `-Z build-std=core` for kernel-side; stable for userspace).
6. Run against live Firebird with the workload in `tests/workloads/`.
7. Reconcile observed behavior with source expectations. Document any surprises in the script's header comment.

## Verifier failures

When the BPF verifier rejects a program: read the verifier log line-by-line. Do not pattern-match a "fix" from training data. Most verifier rejections are real bugs (out-of-bounds, unchecked NULL, loop without bound) and silencing them with the wrong fix produces silent-garbage programs.

## What "done" means for a script

A script is done when: (a) it compiles clean on Aya's pinned version, (b) it produces correct output against the test workload, (c) its overhead is measured and documented in the script's header, (d) the SPECS.md success criterion for it is met, and (e) `symbols/` is up to date.

## When in doubt

Re-read SPECS.md. If it doesn't answer, ask the human. Do not guess at probe targets, do not guess at struct offsets, do not guess at Firebird internals.
