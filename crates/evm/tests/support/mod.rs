//! `State` en memoria para los tests de integración de `repo-b-evm`.
//!
//! Determinista (`BTreeMap`, nunca `HashMap`) y **fail-closed**: el código se
//! sirve por hash y un hash desconocido es `StateError`, no bytes vacíos —
//! aproximar acá escondería divergencias de consenso en los tests.
//!
//! `dead_code` allowed: cada binario de test (`journal`, `contracts`, `calls`)
//! compila este módulo entero pero usa solo su parte del builder.
#![allow(dead_code)]

use std::collections::BTreeMap;

use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
use repo_b_evm::error::StateError;
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, BlockEnv, CodeMetadata, Spec};

pub const SENDER: Address = Address::new([0xAA; 20]);
pub const CONTRACT: Address = Address::new([0xBB; 20]);
pub const COINBASE: Address = Address::new([0xCC; 20]);
pub const BASE_FEE: u64 = 10;

#[derive(Debug, Clone, Default)]
pub struct MemState {
    accounts: BTreeMap<Address, AccountInfo>,
    storage: BTreeMap<(Address, U256), U256>,
    code: BTreeMap<B256, Bytes>,
    block_hashes: BTreeMap<u64, B256>,
    /// Direcciones cuya lectura de storage falla (test de fail-closed).
    failing: Option<Address>,
}

impl MemState {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_eoa(mut self, addr: Address, balance: u64, nonce: u64) -> Self {
        self.accounts.insert(
            addr,
            AccountInfo {
                balance: U256::from(balance),
                nonce,
                code_hash: KECCAK256_EMPTY,
            },
        );
        self
    }

    #[must_use]
    pub fn with_contract(mut self, addr: Address, code: &[u8], balance: u64) -> Self {
        let bytes = Bytes::copy_from_slice(code);
        let code_hash = keccak256(&bytes);
        self.code.insert(code_hash, bytes);
        self.accounts.insert(
            addr,
            AccountInfo {
                balance: U256::from(balance),
                nonce: 1,
                code_hash,
            },
        );
        self
    }

    /// Rompe el vínculo hash→bytecode de una cuenta: el `State` conoce el
    /// `code_hash` pero no puede servir los bytes (witness incompleto).
    #[must_use]
    pub fn with_unknown_code(mut self, addr: Address) -> Self {
        if let Some(account) = self.accounts.get(&addr) {
            self.code.remove(&account.code_hash);
        }
        self
    }

    #[must_use]
    pub fn with_slot(mut self, addr: Address, key: u64, value: u64) -> Self {
        self.storage
            .insert((addr, U256::from(key)), U256::from(value));
        self
    }

    #[must_use]
    pub fn failing_on(mut self, addr: Address) -> Self {
        self.failing = Some(addr);
        self
    }

    #[must_use]
    pub fn with_block_hash(mut self, number: u64, hash: B256) -> Self {
        self.block_hashes.insert(number, hash);
        self
    }
}

impl State for MemState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        Ok(self.accounts.get(&addr).cloned())
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        if self.failing == Some(addr) {
            return Err(StateError::Database("slot indisponible (test)".into()));
        }
        Ok(self
            .storage
            .get(&(addr, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        if code_hash == KECCAK256_EMPTY {
            return Ok(Bytes::new());
        }
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| StateError::Database(format!("código desconocido: {code_hash}")))
    }

    fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
        Ok(CodeMetadata::Regular)
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        self.block_hashes.get(&number).copied().ok_or_else(|| {
            StateError::Database(format!("hash desconocido para el bloque {number}"))
        })
    }
}

pub fn env(spec: Spec) -> BlockEnv {
    BlockEnv {
        spec,
        chain_id: 1,
        number: 1,
        coinbase: COINBASE,
        timestamp: 1000,
        gas_limit: 30_000_000,
        base_fee: BASE_FEE,
        prevrandao: B256::ZERO,
        blob_excess_gas: Some(0),
        blob_base_fee: Some(1),
        blob_base_fee_update_fraction: None,
    }
}
