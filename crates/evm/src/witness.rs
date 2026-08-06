//! `ExecutionWitness` — el tipo que produce **envolver `State`** con un recorder
//! (statelessness; ARCHITECTURE §5.1). El recorder/lógica vive en el crate
//! `repo-b-witness` (Fase 3); acá solo el tipo que referencia `ExecutionOutcome`.
//!
//! Mínimo vendoreado; el formato final se alinea a `ExecutionWitness` de zeth
//! (ADR 0005 de zeth) en Fase 3.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes, U256};

/// Pre-images parciales contra los que el guest ejecuta (sin DB completa).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionWitness {
    /// Cuentas accedidas: balance/nonce/code_hash.
    pub accounts: BTreeMap<Address, WitnessAccountInfo>,
    /// Slots de storage leídos (addr -> key -> value). Determinista.
    pub storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    /// Bytecode por code_hash.
    pub code: BTreeMap<B256, Bytes>,
    /// Block hashes accedidos (BLOCKHASH).
    pub block_hashes: BTreeMap<u64, B256>,
    /// Nodos de trie / pre-images, si aplica.
    pub nodes: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessAccountInfo {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
}
