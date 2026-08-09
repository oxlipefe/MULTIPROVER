//! `repo-b-common` — núcleo estable de tipos del protocolo, `no_std` + `alloc`.
//!
//! Los tipos deben ser **idénticos** a los de `zeth` (Repo A) para que el
//! diferencial bit-a-bit vs `revm` no mienta. Hoy se vendorean mínimos; en
//! Fase 5 se reconcilian con `zeth-common` (path-dep o vendoreo sincronizado).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod access_list;
pub mod account;
pub mod authorization;
pub mod primitives;
pub mod receipt;
pub mod transaction;
