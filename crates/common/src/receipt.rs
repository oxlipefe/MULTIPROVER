//! Logs/receipts (mínimo vendoreado; reconciliar con zeth en Fase 5).

use alloc::vec::Vec;

use alloy_rlp::RlpEncodable;

use crate::primitives::{Address, B256, Bytes};

/// Log emitido por LOG0..LOG4. `RlpEncodable` codifica `[address, topics,
/// data]` (Yellow Paper), el orden que pide `logs-hash = keccak(rlp(logs))`.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}
