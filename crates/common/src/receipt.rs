//! Logs/receipts (mínimo vendoreado; reconciliar con zeth en Fase 5).

use alloc::vec::Vec;

use crate::primitives::{Address, B256, Bytes};

/// Log emitido por LOG0..LOG4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}
