//! EIP-4895 — withdrawals del beacon chain hacia la capa de ejecución.
//!
//! Una withdrawal no es una transacción: no se firma, no gasta gas y no ejecuta
//! EVM. Es un crédito de balance que el protocolo aplica al CERRAR el bloque.
//! Por eso vive en `common` como dato del protocolo y la aplica el motor
//! (`finish_block`), mientras que su `withdrawalsRoot` —que es un trie— lo
//! computa el cliente.

use alloy_rlp::RlpEncodable;

use crate::primitives::{Address, U256};

/// Wei por Gwei. El `amount` de una withdrawal viene en **Gwei**, no en Wei:
/// acreditarlo sin convertir subestima el crédito por un factor de mil
/// millones, y el root MPT lo delata.
pub const GWEI_TO_WEI: u64 = 1_000_000_000;

/// Una withdrawal del consensus layer. `RlpEncodable` codifica
/// `[index, validatorIndex, address, amount]` (EIP-4895), el orden que pide
/// `withdrawalsRoot`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: Address,
    /// **En Gwei.** Ver `amount_wei`.
    pub amount: u64,
}

impl Withdrawal {
    /// El crédito en Wei. No puede desbordar `U256` (`u64::MAX · 10⁹ < 2¹²⁸`),
    /// pero se escribe `saturating_mul` igual: en este repo la aritmética es
    /// explícita, y "no puede desbordar" es un argumento, no una garantía del
    /// tipo.
    #[must_use]
    pub fn amount_wei(&self) -> U256 {
        U256::from(self.amount).saturating_mul(U256::from(GWEI_TO_WEI))
    }
}
