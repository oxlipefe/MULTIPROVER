//! Transacción (mínimo vendoreado; reconciliar con zeth en Fase 5).
//!
//! En zeth `Transaction` es un enum con variantes Legacy/2930/1559/4844/7702.
//! Acá se mantiene una struct plana mínima con los campos que el slice de
//! Fase 1 necesita (ficha 02 §decisión 4); el layout final por variante se
//! reconcilia contra el `Transaction` de zeth en Fase 5. El sender se
//! pre-recupera FUERA del EVM (contrato del seam `Vm`).

use crate::primitives::{Address, Bytes, U256};

/// Tipo EIP-2718 de la transacción.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxType {
    Legacy = 0,
    Eip2930 = 1,
    Eip1559 = 2,
    Eip4844 = 3,
    Eip7702 = 4,
}

/// Transacción mínima del slice de Fase 1.
///
/// Precios de gas en `u128` (alineado a revm). Una tx legacy usa `gas_price`;
/// una 1559 usa `max_fee_per_gas`/`max_priority_fee_per_gas`. El validador
/// del EVM rechaza combinaciones inconsistentes (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub tx_type: TxType,
    /// Sender **pre-recuperado fuera del EVM** (el VM no llama a
    /// `recover_signer`; contrato del seam). En zeth el sender sale de la
    /// firma; el placeholder lo carga directo hasta reconciliar en Fase 5.
    pub sender: Address,
    pub nonce: u64,
    /// `None` = CREATE (no soportado en el slice de Fase 1; fail-closed).
    pub to: Option<Address>,
    pub value: U256,
    pub input: Bytes,
    pub gas_limit: u64,
    /// Solo legacy/2930.
    pub gas_price: Option<u128>,
    /// Solo 1559+.
    pub max_fee_per_gas: Option<u128>,
    /// Solo 1559+.
    pub max_priority_fee_per_gas: Option<u128>,
}
