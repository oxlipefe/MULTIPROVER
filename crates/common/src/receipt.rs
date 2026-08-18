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

/// Lo que el motor sabe de una tx ejecutada dentro de un bloque.
///
/// **Mínimo deliberado.** El bloom de 2048 bits NO vive acá: es derivable de
/// `logs`, y derivarlo —como armar el `receiptTrie` o el RLP del bloque— es
/// encoding, no transición de estado. Ese trabajo es del cliente (en
/// producción, zeth; acá, el harness de conformance), y meterlo en el motor
/// arrastraría maquinaria de encoding al guest `no_std` para nada.
///
/// Tampoco lleva el tipo de tx: quien encodea el receipt ya conoce el envelope
/// de la tx que lo produjo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// El `status` post-Byzantium: `1` si la tx terminó en éxito, `0` si
    /// revirtió o halteó. Un rechazo de consenso no produce receipt (la tx no
    /// entra al bloque).
    pub success: bool,
    /// Gas acumulado del BLOQUE hasta esta tx inclusive, no el de la tx sola.
    pub cumulative_gas_used: u64,
    /// Los logs de esta tx. Vacíos en revert/halt (se descartan con el frame).
    pub logs: Vec<Log>,
}
