//! Resolve mangled symbol offsets for tragach-attach's two probe targets.
//!
//! Same approach as slowquery: read the `.debug` file, match mangled names by
//! Itanium-ABI prefix, dedupe by address (C1/C2 ctor variants share an offset
//! when there's no virtual base, which is the case here). `.cold` clones are
//! filtered.

use anyhow::{Context, Result, anyhow};
use object::{Object, ObjectSymbol, SymbolKind};
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct AttachOffsets {
    pub attachment_ctor: u64,
    pub release_attachment: u64,
}

pub fn resolve(debug_path: &Path) -> Result<AttachOffsets> {
    let data = std::fs::read(debug_path)
        .with_context(|| format!("reading {}", debug_path.display()))?;
    let elf = object::File::parse(&*data)
        .with_context(|| format!("parsing ELF {}", debug_path.display()))?;

    let mut attachment_ctor: Option<u64> = None;
    let mut release_attachment: Option<u64> = None;

    for sym in elf.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.ends_with(".cold") {
            continue;
        }
        // C1 (complete object ctor) and C2 (base subobject ctor) share the
        // same address here because Jrd::Attachment has no virtual base.
        // check_unique allows that: it only errors on *different* addresses.
        if name.starts_with("_ZN3Jrd10AttachmentC1E")
            || name.starts_with("_ZN3Jrd10AttachmentC2E")
        {
            check_unique(
                "Jrd::Attachment::Attachment",
                &mut attachment_ctor,
                sym.address(),
            )?;
        } else if name.starts_with("_ZL18release_attachment") {
            // `_ZL` = file-local linkage (it's `static` in jrd.cpp).
            check_unique("release_attachment", &mut release_attachment, sym.address())?;
        }
    }

    Ok(AttachOffsets {
        attachment_ctor: attachment_ctor
            .ok_or_else(|| anyhow!("Jrd::Attachment::Attachment symbol not found"))?,
        release_attachment: release_attachment
            .ok_or_else(|| anyhow!("release_attachment symbol not found"))?,
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
