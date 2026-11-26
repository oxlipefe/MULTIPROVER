//! Lo que se COMPUTA de un bloque para contrastarlo contra su header: los tres
//! tries indexados por posición, el RLP de los receipts y el bloom.
//!
//! Regla: **nada de esto se compara contra sí mismo**. Cada valor que se
//! computa acá tiene su campo en el header y ahí se contrasta; tomar el trie
//! del header en vez de computarlo convertiría el chequeo en una tautología.

use alloc::vec::Vec;

use alloy_primitives::{B256, Bloom, BloomInput};
use alloy_rlp::{Encodable, Header};
use alloy_trie::root::ordered_trie_root_with_encoder;
use repo_b_common::receipt::{Log, Receipt};
use repo_b_common::transaction::TxType;
use repo_b_common::withdrawal::Withdrawal;

use crate::error::BlockError;

/// Root de un trie indexado por posición (`transactionsRoot`, `receiptsRoot`,
/// `withdrawalsRoot`): la clave es `rlp(i)` y el valor, los bytes ya listos.
fn ordered_root<T: AsRef<[u8]>>(values: &[T]) -> B256 {
    ordered_trie_root_with_encoder(values, |value, out| out.extend_from_slice(value.as_ref()))
}

/// `transactionsRoot`: el trie de las txs en su **encoding de consenso**
/// (EIP-2718). Cada elemento es el envelope ya armado: una tx tipada entra al
/// trie como la cadena `type ‖ rlp(payload)`, no como una lista RLP anidada.
/// El encoder del envelope NO vive acá: es el mismo que arma el payload que se
/// firma, para que no haya dos implementaciones del mismo encoding.
#[must_use]
pub fn transactions_root<T: AsRef<[u8]>>(encoded_transactions: &[T]) -> B256 {
    ordered_root(encoded_transactions)
}

/// `receiptsRoot`. Cada receipt va con el envelope EIP-2718 de la tx que lo
/// produjo, así que hacen falta los tipos de las txs, uno por receipt.
pub fn receipts_root(tx_types: &[TxType], receipts: &[Receipt]) -> Result<B256, BlockError> {
    if tx_types.len() != receipts.len() {
        return Err(BlockError::ReceiptCount {
            transactions: tx_types.len(),
            receipts: receipts.len(),
        });
    }
    let encoded = tx_types
        .iter()
        .zip(receipts)
        .map(|(tx_type, receipt)| encode_receipt_2718(*tx_type, receipt))
        .collect::<Vec<_>>();
    Ok(ordered_root(&encoded))
}

/// `withdrawalsRoot` (EIP-4895). Cada withdrawal es
/// `rlp([index, validatorIndex, address, amount])`, con `amount` en Gwei — el
/// valor tal cual viene: la conversión a Wei es del crédito de balance, no del
/// encoding.
#[must_use]
pub fn withdrawals_root(withdrawals: &[Withdrawal]) -> B256 {
    let encoded = withdrawals
        .iter()
        .map(|withdrawal| {
            let mut out = Vec::new();
            withdrawal.encode(&mut out);
            out
        })
        .collect::<Vec<_>>();
    ordered_root(&encoded)
}

/// El bloom de 2048 bits de un conjunto de logs: por cada log entran la
/// dirección y CADA topic.
pub fn logs_bloom<'a>(logs: impl IntoIterator<Item = &'a Log>) -> Bloom {
    let mut bloom = Bloom::ZERO;
    for log in logs {
        bloom.accrue(BloomInput::Raw(log.address.as_slice()));
        for topic in &log.topics {
            bloom.accrue(BloomInput::Raw(topic.as_slice()));
        }
    }
    bloom
}

/// El bloom del bloque: el de todos los logs de todos sus receipts, que es la
/// definición del campo `logsBloom` del header.
#[must_use]
pub fn block_logs_bloom(receipts: &[Receipt]) -> Bloom {
    logs_bloom(receipts.iter().flat_map(|receipt| receipt.logs.iter()))
}

/// Receipt post-Byzantium: `rlp([status, cumulativeGasUsed, bloom, logs])`,
/// con el byte de tipo adelante si la tx era tipada.
fn encode_receipt_2718(tx_type: TxType, receipt: &Receipt) -> Vec<u8> {
    let bloom = logs_bloom(&receipt.logs);
    let status: u8 = u8::from(receipt.success);
    let payload_length = [
        status.length(),
        receipt.cumulative_gas_used.length(),
        bloom.length(),
        list_length(&receipt.logs),
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add);

    let mut out = Vec::new();
    push_type_byte(tx_type, &mut out);
    Header {
        list: true,
        payload_length,
    }
    .encode(&mut out);
    status.encode(&mut out);
    receipt.cumulative_gas_used.encode(&mut out);
    bloom.encode(&mut out);
    alloy_rlp::encode_list::<Log, Log>(&receipt.logs, &mut out);
    out
}

/// EIP-2718: el receipt de una tx tipada se prefija con su byte de tipo; el de
/// una legacy, no.
fn push_type_byte(tx_type: TxType, out: &mut Vec<u8>) {
    match tx_type {
        TxType::Legacy => {}
        TxType::Eip2930 => out.push(0x01),
        TxType::Eip1559 => out.push(0x02),
        TxType::Eip4844 => out.push(0x03),
        TxType::Eip7702 => out.push(0x04),
    }
}

/// Longitud total (header incluido) de una lista RLP de elementos encodables.
/// `alloy_rlp` no implementa `Encodable` para slices, así que la lista se arma
/// a mano.
fn list_length<T: Encodable>(items: &[T]) -> usize {
    let payload_length = items
        .iter()
        .map(Encodable::length)
        .fold(0usize, usize::saturating_add);
    Header {
        list: true,
        payload_length,
    }
    .length_with_payload()
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use repo_b_common::primitives::{Address, EMPTY_ROOT_HASH};

    use super::*;

    /// Un trie sin elementos es el root vacío — la misma constante con la que
    /// el header declara "este bloque no trae txs / receipts / withdrawals".
    #[test]
    fn an_empty_ordered_trie_is_the_empty_root() {
        assert_eq!(transactions_root::<Vec<u8>>(&[]), EMPTY_ROOT_HASH);
        assert_eq!(withdrawals_root(&[]), EMPTY_ROOT_HASH);
        assert_eq!(receipts_root(&[], &[]), Ok(EMPTY_ROOT_HASH));
    }

    /// Un conjunto vacío de logs es el bloom en cero, y un log lo mueve.
    #[test]
    fn the_bloom_of_no_logs_is_zero_and_a_log_moves_it() {
        assert_eq!(logs_bloom(core::iter::empty()), Bloom::ZERO);
        let log = Log {
            address: Address::new([0x11; 20]),
            topics: vec![B256::new([0x22; 32])],
            data: Default::default(),
        };
        assert_ne!(logs_bloom([&log]), Bloom::ZERO);
    }

    /// Un receipt por tx, o error: un receipt de menos no es un trie más corto.
    #[test]
    fn a_missing_receipt_is_an_error_not_a_shorter_trie() {
        let receipt = Receipt {
            success: true,
            cumulative_gas_used: 21_000,
            logs: Vec::new(),
        };
        assert_eq!(
            receipts_root(&[TxType::Legacy, TxType::Eip1559], &[receipt]),
            Err(BlockError::ReceiptCount {
                transactions: 2,
                receipts: 1
            })
        );
    }

    /// El byte de tipo entra al receipt: el mismo receipt bajo una legacy y
    /// bajo una tipada da otro root.
    #[test]
    fn the_type_byte_moves_the_receipts_root() {
        let receipt = Receipt {
            success: true,
            cumulative_gas_used: 21_000,
            logs: Vec::new(),
        };
        let legacy = receipts_root(&[TxType::Legacy], core::slice::from_ref(&receipt));
        let typed = receipts_root(&[TxType::Eip1559], core::slice::from_ref(&receipt));
        assert_ne!(legacy, typed);
    }
}
