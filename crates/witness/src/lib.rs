//! `repo-b-witness` — el recorder que **envuelve `State`** para producir un
//! `ExecutionWitness` (statelessness.1).
//!
//! **Fase 3 (PENDIENTE).** El motor NO sabe que está siendo grabado: el witness
//! sale de envolver el seam `State` con interior mutability. El guest ejecuta
//! contra el witness (pre-images parciales), no contra la DB; root == full.
#![no_std]
#![forbid(unsafe_code)]

pub use repo_b_evm::ExecutionWitness;
