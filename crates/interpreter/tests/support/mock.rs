//! `MockHost`: host de test con storage en `BTreeMap` (determinista, sin
//! `HashMap`). Incluido solo por los tests que ejercitan el seam `Host` de
//! verdad (`#[path = "support/mock.rs"] mod mock;`), separado de
//! `support/mod.rs` para que `NoopHost`-only tests no lo compilen como
//! dead-code. Ver `support/mod.rs`.
//!
//! `dead_code` allowed: `storage.rs` ejercita el subset de storage
//! (`with_slot`/`with_warm`/`refunds`) y `logs_env.rs` el de entorno/log
//! (`with_env`/`with_tx`/`with_self_balance`/`with_block_hash`/`logs`) — cada
//! binario de test usa solo su parte del builder (mismo patrón que
//! `crates/evm/tests/support/mod.rs`).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use repo_b_common::primitives::{Address, B256, U256};
use repo_b_common::receipt::Log;
use repo_b_interpreter::host::{BlockEnv, TxEnv};
use repo_b_interpreter::{Host, SStoreResult, StateLoad};

#[derive(Debug, Clone, Copy)]
struct SlotState {
    original: U256,
    current: U256,
}

/// Cold/warm es controlable explícitamente (`with_warm`) y también se
/// actualiza por acceso (semántica EIP-2929: el primer acceso a un slot
/// dentro de un mismo `run` lo deja warm para el siguiente). Graba cada
/// llamada a `refund` para que el test la audite.
#[derive(Debug, Default)]
pub struct MockHost {
    slots: BTreeMap<(Address, U256), SlotState>,
    warm: BTreeSet<(Address, U256)>,
    transient: BTreeMap<(Address, U256), U256>,
    refunds: Vec<i64>,
    env: BlockEnv,
    tx: TxEnv,
    self_balance: U256,
    block_hashes: BTreeMap<u64, B256>,
    logs: Vec<Log>,
}

impl MockHost {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_env(mut self, env: BlockEnv) -> Self {
        self.env = env;
        self
    }

    #[must_use]
    pub fn with_tx(mut self, tx: TxEnv) -> Self {
        self.tx = tx;
        self
    }

    #[must_use]
    pub fn with_self_balance(mut self, balance: U256) -> Self {
        self.self_balance = balance;
        self
    }

    #[must_use]
    pub fn with_block_hash(mut self, number: u64, hash: B256) -> Self {
        self.block_hashes.insert(number, hash);
        self
    }

    pub fn logs(&self) -> &[Log] {
        &self.logs
    }

    /// Preconfigura un slot: `original` = valor antes de la tx, `current` =
    /// valor ya escrito en esta tx (antes del SSTORE que ejecute el test).
    /// Para el caso "no tocado todavía" `original == current`.
    pub fn with_slot(mut self, addr: Address, key: U256, original: U256, current: U256) -> Self {
        self.slots
            .insert((addr, key), SlotState { original, current });
        self
    }

    /// Marca `(addr, key)` como ya-accedido (warm) antes de correr el
    /// programa, para aislar el costo warm sin necesitar un segundo SLOAD.
    pub fn with_warm(mut self, addr: Address, key: U256) -> Self {
        self.warm.insert((addr, key));
        self
    }

    pub fn refunds(&self) -> &[i64] {
        &self.refunds
    }

    pub fn transient(&self, addr: Address, key: U256) -> U256 {
        self.transient
            .get(&(addr, key))
            .copied()
            .unwrap_or(U256::ZERO)
    }
}

impl Host for MockHost {
    fn sload(&mut self, addr: Address, key: U256) -> StateLoad<U256> {
        let is_cold = self.warm.insert((addr, key));
        let value = self
            .slots
            .get(&(addr, key))
            .map(|slot| slot.current)
            .unwrap_or(U256::ZERO);
        StateLoad {
            data: value,
            is_cold,
        }
    }

    fn sstore(&mut self, addr: Address, key: U256, value: U256) -> StateLoad<SStoreResult> {
        let is_cold = self.warm.insert((addr, key));
        let slot = self.slots.entry((addr, key)).or_insert(SlotState {
            original: U256::ZERO,
            current: U256::ZERO,
        });
        let original = slot.original;
        let current = slot.current;
        slot.current = value;
        StateLoad {
            data: SStoreResult {
                original,
                current,
                new: value,
            },
            is_cold,
        }
    }

    fn tload(&mut self, addr: Address, key: U256) -> U256 {
        self.transient(addr, key)
    }

    fn tstore(&mut self, addr: Address, key: U256, value: U256) {
        self.transient.insert((addr, key), value);
    }

    fn refund(&mut self, delta: i64) {
        self.refunds.push(delta);
    }

    fn env(&self) -> &BlockEnv {
        &self.env
    }

    fn tx(&self) -> &TxEnv {
        &self.tx
    }

    fn self_balance(&mut self) -> U256 {
        self.self_balance
    }

    fn block_hash(&mut self, number: u64) -> B256 {
        self.block_hashes.get(&number).copied().unwrap_or(B256::ZERO)
    }

    fn log(&mut self, log: Log) {
        self.logs.push(log);
    }
}
