//! Seam `Host` (ADR-0002) — **solo el subset storage** de este slice
//! (SLOAD/SSTORE/TLOAD/TSTORE + refund). El resto del trait del ADR (env,
//! account access, code, log, selfdestruct) entra en sus propios slices,
//! just-in-time — no se agrega acá especulativamente (YAGNI).
//!
//! El intérprete llama a `&mut dyn Host` para todo lo que toca el mundo; NO
//! trackea cold/warm por su cuenta (eso lo decide quien implemente `Host` —
//! el mock en 002, el journal en 004).

use repo_b_common::primitives::{Address, U256};

/// Envuelve un valor con el flag de acceso frío (EIP-2929): el intérprete
/// cobra el gas correcto (cold vs warm) sin saber CÓMO se trackea.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLoad<T> {
    pub data: T,
    pub is_cold: bool,
}

/// Lo que el gas de SSTORE necesita (EIP-2200): el valor del slot antes de la
/// tx (`original`), el valor actual dentro de la tx (`current`) y el que se
/// está escribiendo (`new`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SStoreResult {
    pub original: U256,
    pub current: U256,
    pub new: U256,
}

/// Subset storage del seam `Host`. Vive en `interpreter` (no en `evm`) para
/// no invertir la dirección de dependencias (ADR-0002 §1): usa solo tipos de
/// `common`.
pub trait Host {
    fn sload(&mut self, addr: Address, key: U256) -> StateLoad<U256>;
    fn sstore(&mut self, addr: Address, key: U256, value: U256) -> StateLoad<SStoreResult>;
    /// EIP-1153 — transient storage: sin cold/warm, no journaled más allá de
    /// la tx (el fin-de-tx lo maneja quien implemente `Host`).
    fn tload(&mut self, addr: Address, key: U256) -> U256;
    fn tstore(&mut self, addr: Address, key: U256, value: U256);
    /// Acumulador de refund (EIP-3529); el tope al liquidar la tx es
    /// responsabilidad de quien implemente `Host`, no del intérprete.
    fn refund(&mut self, delta: i64);
}
