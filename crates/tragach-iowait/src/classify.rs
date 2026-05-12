//! Classify a kernel stack into one of four reason buckets by string match.
//!
//! Order matters: BlockIo and Futex are specific; SchedDelay is the catch-all
//! for any stack rooted in schedule/__schedule; Other is the last resort.

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Reason {
    BlockIo,
    Futex,
    SchedDelay,
    Other,
}

impl Reason {
    pub fn label(&self) -> &'static str {
        match self {
            Reason::BlockIo => "block I/O wait",
            Reason::Futex => "futex wait",
            Reason::SchedDelay => "scheduler delay",
            Reason::Other => "other",
        }
    }
}

pub fn classify(frames: &[String]) -> Reason {
    // Scan from leaf to root; the most recent (leaf) frame is most informative.
    for f in frames {
        if is_block_io(f) {
            return Reason::BlockIo;
        }
        if is_futex(f) {
            return Reason::Futex;
        }
    }
    // Pure schedule call with no I/O or futex below it.
    for f in frames {
        if f.starts_with("schedule") || f == "__schedule" {
            return Reason::SchedDelay;
        }
    }
    Reason::Other
}

fn is_block_io(name: &str) -> bool {
    name.starts_with("blk_")
        || name.starts_with("bio_")
        || name.starts_with("submit_bio")
        || name.starts_with("io_schedule")
        || name.starts_with("__io_schedule")
        || name.starts_with("wait_on_buffer")
}

fn is_futex(name: &str) -> bool {
    name.starts_with("futex_")
        || name.starts_with("do_futex")
        || name.starts_with("__futex")
}
