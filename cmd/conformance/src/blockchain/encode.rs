//! Lo que el harness COMPUTA de un bloque: el RLP de las txs, el de los
//! receipts, el bloom y los tres tries.
//!
//! Todo esto es **encoding y verificación, no transición de estado**, así que
//! vive acá y no en el motor: meterlo en `crates/evm` arrastraría MPT y RLP al
//! `no_std` del guest y crearía una segunda implementación que puede discrepar
//! de la del cliente stateless.
//!
//! El riesgo del corte es un harness que se autovalida, y se acota con una
//! regla: **nada de esto se compara contra sí mismo**. Cada valor que
//! se computa acá tiene su campo en el header del fixture y ahí se contrasta.
//! Tomar el trie del fixture en vez de computarlo convertiría el chequeo en una
//! tautología.

use alloy_primitives::{Bloom, BloomInput};
use alloy_rlp::{Encodable, Header};
use alloy_trie::root::ordered_trie_root_with_encoder;
use repo_b_common::primitives::B256;
use repo_b_common::receipt::{Log, Receipt};
use repo_b_common::transaction::TxType;
use repo_b_common::withdrawal::Withdrawal;

use super::fixture::FixtureTx;

/// Root de un trie indexado por posición (`transactionsTrie`, `receiptTrie`,
/// `withdrawalsRoot`): la clave es `rlp(i)` y el valor, los bytes ya listos.
fn ordered_root(values: &[Vec<u8>]) -> B256 {
    ordered_trie_root_with_encoder(values, |value, out| out.extend_from_slice(value))
}

/// `transactionsTrie`: el trie de las txs en su **encoding de consenso**
/// (EIP-2718). Una tx tipada entra al trie como la cadena de bytes
/// `type ‖ rlp(payload)`, no como una lista RLP anidada.
/// **El encoder es el del guest, no uno de acá.** Vivía duplicado: uno armaba
/// el envelope para el trie y el otro tendría que armar el payload que se firma,
/// y dos implementaciones del mismo encoding pueden discrepar justo en el campo
/// que el trie no mira. Ahora es uno solo (`repo_b_guest::signature`), y este
/// contraste —el `transactionsTrie` de cada bloque contra su header— es lo que
/// lo gatea.
pub fn transactions_root(txs: &[FixtureTx]) -> Result<B256, String> {
    let encoded = txs
        .iter()
        .map(|tx| {
            super::fixture::signed_transaction(tx)?
                .encode_2718()
                .map_err(|e| format!("la tx no es representable como envelope: {}", e.0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ordered_root(&encoded))
}

/// `receiptTrie`. Mismo envelope EIP-2718 que la tx que lo produjo.
pub fn receipts_root(txs: &[FixtureTx], receipts: &[Receipt]) -> Result<B256, String> {
    if txs.len() != receipts.len() {
        return Err(format!(
            "{} txs y {} receipts: el motor no devolvió un receipt por tx",
            txs.len(),
            receipts.len()
        ));
    }
    let encoded = txs
        .iter()
        .zip(receipts)
        .map(|(tx, receipt)| encode_receipt_2718(tx.tx_type, receipt))
        .collect::<Vec<_>>();
    Ok(ordered_root(&encoded))
}

/// `withdrawalsRoot` (EIP-4895). Cada withdrawal es
/// `rlp([index, validatorIndex, address, amount])`, con `amount` en Gwei — el
/// valor tal cual viene, sin convertir: la conversión a Wei es del crédito de
/// balance, no del encoding.
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

/// Receipt post-Byzantium: `rlp([status, cumulativeGasUsed, bloom, logs])`,
/// con el byte de tipo adelante si la tx era tipada.
fn encode_receipt_2718(tx_type: TxType, receipt: &Receipt) -> Vec<u8> {
    let bloom = logs_bloom(&receipt.logs);
    let status: u8 = u8::from(receipt.success);
    let payload_length = status.length()
        + receipt.cumulative_gas_used.length()
        + bloom.length()
        + list_length(&receipt.logs);

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
    encode_list(&receipt.logs, &mut out);
    out
}

/// EIP-2718: la tx tipada se prefija con su byte de tipo; la legacy, no. Lo
/// usa el **receipt**, cuyo envelope es el de la tx que lo produjo.
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
/// a mano — el mismo motivo por el que el logs-hash usa `encode_list`.
fn list_length<T: Encodable>(items: &[T]) -> usize {
    let payload_length: usize = items.iter().map(Encodable::length).sum();
    Header {
        list: true,
        payload_length,
    }
    .length_with_payload()
}

fn encode_list<T: Encodable>(items: &[T], out: &mut Vec<u8>) {
    alloy_rlp::encode_list::<T, T>(items, out);
}

/// Reexport interno: el driver arma el bloom del bloque acumulando el de cada
/// receipt, que es la definición del campo `bloom` del header.
pub fn block_bloom(receipts: &[Receipt]) -> Bloom {
    logs_bloom(receipts.iter().flat_map(|receipt| receipt.logs.iter()))
}

#[cfg(test)]
mod tests {
    use repo_b_common::primitives::Address;

    use super::*;

    /// Un trie sin elementos es el root vacío — la misma constante con la que
    /// el header declara "este bloque no trae txs / receipts / withdrawals".
    #[test]
    fn an_empty_ordered_trie_is_the_empty_root() {
        assert_eq!(
            ordered_root(&[]),
            repo_b_common::primitives::EMPTY_ROOT_HASH
        );
        assert_eq!(
            withdrawals_root(&[]),
            repo_b_common::primitives::EMPTY_ROOT_HASH
        );
    }

    /// El bloom de un log tiene exactamente 3 bits por ítem (dirección + cada
    /// topic), y un conjunto vacío de logs es el bloom en cero — que es lo que
    /// el header declara para un bloque sin logs.
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
}
