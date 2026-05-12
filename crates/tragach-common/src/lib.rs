//! Shared types for tragach userspace and BPF programs.
//!
//! Wire structs must stay `#[repr(C)]` so they pass unchanged between the
//! kernel and userspace through Aya ring buffers. Field shapes are owned by
//! SPECS.md §5; bump the spec, not just this file, when changing them.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod event;
