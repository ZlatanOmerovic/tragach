//! Resolve the `CCH_fetch_page` mangled-symbol offset from the `.debug` file.
//!
//! Same approach as slowquery and attach: read the `.debug` ELF, match by
//! Itanium-ABI prefix, filter `.cold` clones, dedupe by address.

use anyhow::{Context, Result, anyhow};
use object::{Object, ObjectSymbol, SymbolKind};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct PageIoOffsets {
    pub cch_fetch_page: u64,
}

pub fn resolve(debug_path: &Path) -> Result<PageIoOffsets> {
    let data = std::fs::read(debug_path)
        .with_context(|| format!("reading {}", debug_path.display()))?;
    let elf = object::File::parse(&*data)
        .with_context(|| format!("parsing ELF {}", debug_path.display()))?;

    let mut cch_fetch_page: Option<u64> = None;

    for sym in elf.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.ends_with(".cold") {
            continue;
        }
        // 14-char function name: CCH_fetch_page. Length prefix disambiguates
        // it from the shorter `CCH_fetch` (9 chars).
        if name.starts_with("_Z14CCH_fetch_pagePN3Jrd9thread_dbE") {
            // Skip the local `Pio::callback` symbol that shares a similar prefix
            // (`_ZZ14CCH_fetch_page...` — note the `_ZZ`, not `_Z`).
            check_unique("CCH_fetch_page", &mut cch_fetch_page, sym.address())?;
        }
    }

    Ok(PageIoOffsets {
        cch_fetch_page: cch_fetch_page
            .ok_or_else(|| anyhow!("CCH_fetch_page symbol not found"))?,
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
