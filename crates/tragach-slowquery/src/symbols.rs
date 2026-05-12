//! Resolve mangled DSQL symbol offsets from libEngine13.so's debug file.
//!
//! The shipped `libEngine13.so` is stripped — its dynamic symbol table holds
//! only ~495 imported symbols and none of the internal C++ engine entry
//! points. The full symbol table lives in `.debug/libEngine13.so.debug` via
//! gnu_debuglink. Since `.debug` is the byproduct of `objcopy
//! --only-keep-debug` against the same compilation unit, function addresses
//! match the loaded `.so` byte-for-byte — we read offsets from `.debug` and
//! attach uprobes by offset against the `.so`.
//!
//! Match by the mangled length-prefix to avoid false positives:
//! `_Z12DSQL_prepare…` (12-char function name) cannot collide with
//! `_Z22DSQL_execute_immediate…` (22-char function name). `.cold` clones are
//! filtered to avoid double-counting unlikely-path entry blocks.

use anyhow::{Context, Result, anyhow};
use object::{Object, ObjectSymbol, SymbolKind};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct DsqlOffsets {
    pub prepare: u64,
    pub execute: u64,
    pub execute_immediate: u64,
    pub open_cursor: u64,
    pub fetch_next: u64,
}

pub fn resolve(debug_path: &Path) -> Result<DsqlOffsets> {
    let data = std::fs::read(debug_path)
        .with_context(|| format!("reading {}", debug_path.display()))?;
    let elf = object::File::parse(&*data)
        .with_context(|| format!("parsing ELF {}", debug_path.display()))?;

    let mut prepare: Option<u64> = None;
    let mut execute: Option<u64> = None;
    let mut execute_immediate: Option<u64> = None;
    let mut open_cursor: Option<u64> = None;
    let mut fetch_next: Option<u64> = None;

    for sym in elf.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.ends_with(".cold") {
            continue;
        }
        // Itanium ABI length prefixes disambiguate similar names — e.g.
        // `_Z12DSQL_execute…` (12 chars) vs `_Z22DSQL_execute_immediate…` (22).
        if name.starts_with("_Z12DSQL_prepareP") {
            check_unique("DSQL_prepare", &mut prepare, sym.address())?;
        } else if name.starts_with("_Z22DSQL_execute_immediateP") {
            check_unique("DSQL_execute_immediate", &mut execute_immediate, sym.address())?;
        } else if name.starts_with("_Z12DSQL_executeP") {
            check_unique("DSQL_execute", &mut execute, sym.address())?;
        } else if name.starts_with("_ZN3Jrd14DsqlDmlRequest10openCursorE") {
            check_unique(
                "Jrd::DsqlDmlRequest::openCursor",
                &mut open_cursor,
                sym.address(),
            )?;
        } else if name.starts_with("_ZN3Jrd10DsqlCursor9fetchNextE") {
            check_unique("Jrd::DsqlCursor::fetchNext", &mut fetch_next, sym.address())?;
        }
    }

    Ok(DsqlOffsets {
        prepare: prepare.ok_or_else(|| anyhow!("DSQL_prepare symbol not found"))?,
        execute: execute.ok_or_else(|| anyhow!("DSQL_execute symbol not found"))?,
        execute_immediate: execute_immediate
            .ok_or_else(|| anyhow!("DSQL_execute_immediate symbol not found"))?,
        open_cursor: open_cursor
            .ok_or_else(|| anyhow!("Jrd::DsqlDmlRequest::openCursor symbol not found"))?,
        fetch_next: fetch_next
            .ok_or_else(|| anyhow!("Jrd::DsqlCursor::fetchNext symbol not found"))?,
    })
}

fn check_unique(label: &str, slot: &mut Option<u64>, addr: u64) -> Result<()> {
    if let Some(prev) = *slot {
        if prev != addr {
            return Err(anyhow!(
                "{label}: multiple non-cold matches (0x{prev:x}, 0x{addr:x}) — \
                 symbols artifact has drifted; rerun `xtask symbols` and audit"
            ));
        }
    } else {
        *slot = Some(addr);
    }
    Ok(())
}
