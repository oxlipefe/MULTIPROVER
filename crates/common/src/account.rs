//! Diff de estado producido por el EVM (NO muta estado; produce datos).
//! `AccountUpdate` es la unidad del `StateChanges`.
//! Mínimo vendoreado; reconciliar con zeth en Fase 5.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::primitives::{Address, B256, Bytes, U256};

/// Estado básico de una cuenta tal como lo lee el EVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
}

/// Cambio aplicado a una cuenta tras ejecutar una tx/bloque.
/// El orden de `storage` es determinista (`BTreeMap`, no `HashMap`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountUpdate {
    pub address: Address,
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    pub code: Option<Bytes>,
    /// Slots de storage modificados (key -> value). Determinista.
    pub storage: BTreeMap<U256, U256>,
    /// La cuenta fue destruida (SELFDESTRUCT / drain EIP-161).
    pub destroyed: bool,
}

pub type StateChanges = Vec<AccountUpdate>;
