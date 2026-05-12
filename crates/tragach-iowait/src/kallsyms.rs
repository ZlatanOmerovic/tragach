//! Minimal /proc/kallsyms reader for kernel-IP → symbol lookup.
//!
//! /proc/kallsyms returns zero addresses for non-root readers (KPTI / kptr_restrict).
//! tragach-iowait runs as root in normal use, so addresses are real.

use anyhow::{Context, Result};
use std::path::Path;

pub struct Kallsyms {
    /// Sorted by address ascending.
    syms: Vec<(u64, String)>,
}

impl Kallsyms {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading {}", path.as_ref().display()))?;
        let mut syms: Vec<(u64, String)> = Vec::with_capacity(text.lines().count());
        for line in text.lines() {
            // Format: "<hex_addr> <type_char> <name>[\t<module>]"
            let mut parts = line.splitn(3, ' ');
            let addr_s = match parts.next() { Some(s) => s, None => continue };
            let _type = parts.next();
            let name = match parts.next() { Some(s) => s, None => continue };
            let addr = match u64::from_str_radix(addr_s, 16) {
                Ok(a) => a,
                Err(_) => continue,
            };
            if addr == 0 {
                continue;
            }
            // Strip module suffix if present.
            let clean = name.split('\t').next().unwrap_or(name).to_string();
            syms.push((addr, clean));
        }
        syms.sort_by_key(|(a, _)| *a);
        Ok(Self { syms })
    }

    pub fn len(&self) -> usize {
        self.syms.len()
    }

    /// Binary search for the symbol whose address is the largest ≤ ip.
    pub fn lookup(&self, ip: u64) -> String {
        if ip == 0 || self.syms.is_empty() {
            return "?".to_string();
        }
        let idx = self.syms.partition_point(|(a, _)| *a <= ip);
        if idx == 0 {
            return format!("0x{ip:x}");
        }
        self.syms[idx - 1].1.clone()
    }
}
