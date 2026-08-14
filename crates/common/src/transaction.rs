//! Transacción (mínimo vendoreado; reconciliar con zeth en Fase 5).
//!
//! En zeth `Transaction` es un enum con variantes Legacy/2930/1559/4844/7702.
//! Acá se mantiene una struct plana mínima con los campos que el slice de
//! Fase 1 necesita; el layout final por variante se
//! reconcilia contra el `Transaction` de zeth en Fase 5. El sender se
//! pre-recupera FUERA del EVM (contrato del seam `Vm`).

use alloc::vec::Vec;

use crate::access_list::AccessList;
use crate::authorization::AuthorizationList;
use crate::primitives::{Address, B256, Bytes, U256};

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
    /// EIP-2930. Legacy/1559 sin lista propia quedan con
    /// `Vec::new()` por invariante de construcción: una legacy tx con AL no
    /// vacía no es un estado que la EVM real produzca (EIP-2718 la tipa a
    /// nivel de encoding, fuera del scope — acá no hay decoder RLP).
    pub access_list: AccessList,
    /// EIP-4844. `None` en una tx `Eip4844` es tx malformada
    /// (mismo tratamiento que `gas_price`/`max_fee_per_gas` ausente en las
    /// otras variantes). El resto de variantes queda con `None` por el mismo
    /// invariante de construcción que `access_list` (EIP-2718 tipa el campo a
    /// nivel de encoding, fuera del scope — acá no hay decoder RLP).
    pub max_fee_per_blob_gas: Option<u128>,
    /// EIP-4844. Vacío en toda variante que no sea `Eip4844`, por
    /// el mismo invariante de construcción que `access_list`.
    pub blob_versioned_hashes: Vec<B256>,
    /// EIP-7702. Vacío en toda variante que no sea `Eip7702` por
    /// el mismo invariante de construcción que `access_list`; **vacío en una
    /// tx `Eip7702` invalida la tx entera** (la EIP exige al menos 1 tupla —
    /// verificado contra revm: `InvalidTransaction::EmptyAuthorizationList`).
    pub authorization_list: AuthorizationList,
}
