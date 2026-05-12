//! Build orchestration for tragach. See SPECS.md §4 and §6.
//!
//! Subcommands:
//!   xtask symbols  — regenerate `symbols/<tag>-libEngine13.txt` from the
//!                    installed Firebird, following gnu_debuglink to the
//!                    `.debug` file which holds the internal C++ symbols.
//!   xtask build    — build both userspace binaries and their BPF programs.
//!   xtask test     — run cargo test across the workspace.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask", about = "tragach build orchestration")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Regenerate symbols/<firebird-tag>-libEngine13.txt
    Symbols {
        /// Firebird install root (must contain plugins/libEngine13.so).
        #[arg(long, default_value = "/opt/firebird-v5")]
        firebird_prefix: PathBuf,
        /// Firebird tag — becomes the artifact filename prefix.
        #[arg(long, default_value = "v5.0.4")]
        tag: String,
    },
    /// Build both userspace binaries and their BPF programs.
    Build,
    /// Run cargo test across the workspace.
    Test,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Symbols { firebird_prefix, tag } => regen_symbols(&firebird_prefix, &tag),
        Cmd::Build => Err(anyhow!(
            "xtask build: not yet implemented — wired up alongside aya-build in the build pass"
        )),
        Cmd::Test => Err(anyhow!("xtask test: not yet implemented")),
    }
}

fn regen_symbols(prefix: &Path, tag: &str) -> Result<()> {
    let stripped = prefix.join("plugins/libEngine13.so");
    if !stripped.exists() {
        return Err(anyhow!(
            "libEngine13.so not found at {} — pass --firebird-prefix",
            stripped.display()
        ));
    }
    // The stripped .so exposes ~495 dynamic symbols, mostly imports. The internal
    // engine C++ functions (DSQL_*, JRD_*, CCH_*, Attachment::*) live as local
    // `t` symbols in the .debug file only. Prefer that when present.
    let debug = prefix.join("plugins/.debug/libEngine13.so.debug");
    let source = if debug.exists() { debug } else { stripped };

    let nm = Command::new("nm")
        .args(["-C", "--defined-only"])
        .arg(&source)
        .output()
        .with_context(|| format!("running nm against {}", source.display()))?;
    if !nm.status.success() {
        return Err(anyhow!(
            "nm failed (status={:?}): {}",
            nm.status.code(),
            String::from_utf8_lossy(&nm.stderr)
        ));
    }

    let mut lines: Vec<&[u8]> = nm.stdout.split(|b| *b == b'\n').filter(|l| !l.is_empty()).collect();
    lines.sort();
    let mut out = lines.join(&b'\n');
    out.push(b'\n');

    let out_dir = repo_root().join("symbols");
    std::fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(format!("{tag}-libEngine13.txt"));
    std::fs::write(&out_path, &out)
        .with_context(|| format!("writing {}", out_path.display()))?;
    eprintln!("wrote {} ({} symbols)", out_path.display(), lines.len());
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate has a parent directory")
        .to_path_buf()
}
