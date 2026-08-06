//! Seam `Host` (ADR-0002). Slice 2.2 agregó el subset storage (SLOAD/SSTORE/
//! TLOAD/TSTORE + refund); slice 2.3 (este) agrega entorno (`env`/`tx`),
//! `self_balance`, `block_hash` y `log`. Account access/code/selfdestruct
//! quedan para sus propios slices, just-in-time — no se agregan acá
//! especulativamente (YAGNI).
//!
//! El intérprete llama a `&mut dyn Host` para todo lo que toca el mundo; NO
//! trackea cold/warm por su cuenta (eso lo decide quien implemente `Host` —
//! el mock en 002, el journal en 004).

use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, U256};
use repo_b_common::receipt::Log;

/// Envuelve un valor con el flag de acceso frío (EIP-2929): el intérprete
/// cobra el gas correcto (cold vs warm) sin saber CÓMO se trackea.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLoad<T> {
    pub data: T,
    pub is_cold: bool,
}

/// Proyección MÍNIMA del `BlockEnv` del seam (vendoreado en `evm`; ADR-0002
/// prohíbe tocarlo) con solo los campos que los opcodes de entorno de este
/// slice necesitan. Vive en `interpreter::host` — no en `evm` — por la misma
/// razón que `TxEnv`: el intérprete solo depende de `common` (ADR-0002 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockEnv {
    pub chain_id: u64,
    pub number: u64,
    pub coinbase: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub prevrandao: B256,
    /// EIP-7516 (BLOBBASEFEE) / EIP-4844 `fake_exponential`: ya calculado por
    /// quien arma el frame (`evm`); el intérprete solo lo apila.
    pub blob_base_fee: u64,
}

/// Datos de la tx que ORIGIN/GASPRICE/BLOBHASH necesitan. Vive en
/// `interpreter::host` (NO en el seam `Transaction` vendeado): en el slice
/// single-frame, `origin` = sender de la tx y `gas_price` = el effective ya
/// calculado por `OwnVm` (EIP-1559). `blob_hashes` vacío hasta el tipo de tx
/// 4844 (slice 2.7).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxEnv {
    pub origin: Address,
    pub gas_price: u128,
    pub blob_hashes: Vec<B256>,
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

    /// Entorno del bloque (NUMBER/TIMESTAMP/COINBASE/GASLIMIT/CHAINID/
    /// BASEFEE/PREVRANDAO/BLOBBASEFEE).
    fn env(&self) -> &BlockEnv;
    /// Datos de la tx (ORIGIN/GASPRICE/BLOBHASH).
    fn tx(&self) -> &TxEnv;
    /// Balance de la cuenta en ejecución (SELFBALANCE, EIP-1884): YA refleja
    /// el value entrante de esta call y, si la cuenta es también el sender,
    /// el gas prepagado — nunca el balance "congelado" que serviría un
    /// `State::account` leído a mitad de tx.
    fn self_balance(&mut self) -> U256;
    /// `BLOCKHASH`: hash de un bloque ancestro. El chequeo de ventana
    /// (`[number-256, number-1]`) lo hace el intérprete ANTES de llamar acá;
    /// un `number` fuera de ventana ni siquiera llega a este método.
    fn block_hash(&mut self, number: u64) -> B256;
    /// Emite un log (LOG0..LOG4); journaled y revertido igual que storage.
    fn log(&mut self, log: Log);
}
