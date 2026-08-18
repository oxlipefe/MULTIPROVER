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
use alloy_rlp::{EMPTY_STRING_CODE, Encodable, Header};
use alloy_trie::root::ordered_trie_root_with_encoder;
use repo_b_common::access_list::AccessList;
use repo_b_common::primitives::{Address, B256};
use repo_b_common::receipt::{Log, Receipt};
use repo_b_common::transaction::TxType;
use repo_b_common::withdrawal::Withdrawal;

use super::fixture::{FixtureAuthorization, FixtureTx};

/// Root de un trie indexado por posición (`transactionsTrie`, `receiptTrie`,
/// `withdrawalsRoot`): la clave es `rlp(i)` y el valor, los bytes ya listos.
fn ordered_root(values: &[Vec<u8>]) -> B256 {
    ordered_trie_root_with_encoder(values, |value, out| out.extend_from_slice(value))
}

/// `transactionsTrie`: el trie de las txs en su **encoding de consenso**
/// (EIP-2718). Una tx tipada entra al trie como la cadena de bytes
/// `type ‖ rlp(payload)`, no como una lista RLP anidada.
pub fn transactions_root(txs: &[FixtureTx]) -> Result<B256, String> {
    let encoded = txs
        .iter()
        .map(encode_tx_2718)
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

/// El encoding de consenso de una tx (EIP-2718).
fn encode_tx_2718(tx: &FixtureTx) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    push_type_byte(tx.tx_type, &mut out);
    match tx.tx_type {
        TxType::Legacy => encode_legacy(tx, &mut out),
        TxType::Eip2930 => encode_eip2930(tx, &mut out)?,
        TxType::Eip1559 => encode_eip1559(tx, &mut out)?,
        TxType::Eip4844 => encode_eip4844(tx, &mut out)?,
        TxType::Eip7702 => encode_eip7702(tx, &mut out)?,
    }
    Ok(out)
}

/// EIP-2718: la tx tipada se prefija con su byte de tipo; la legacy, no.
fn push_type_byte(tx_type: TxType, out: &mut Vec<u8>) {
    match tx_type {
        TxType::Legacy => {}
        TxType::Eip2930 => out.push(0x01),
        TxType::Eip1559 => out.push(0x02),
        TxType::Eip4844 => out.push(0x03),
        TxType::Eip7702 => out.push(0x04),
    }
}

/// `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`.
fn encode_legacy(tx: &FixtureTx, out: &mut Vec<u8>) {
    // Una tx legacy sin `gasPrice` es un fixture malformado; cero es el valor
    // que el protocolo le daría a un campo ausente en RLP y no cambia nada que
    // este slice mida (el motor la rechaza aparte).
    let gas_price = tx.gas_price.unwrap_or_default();
    let payload_length = tx.nonce.length()
        + gas_price.length()
        + tx.gas_limit.length()
        + to_length(tx.to)
        + tx.value.length()
        + tx.data.length()
        + tx.v.length()
        + tx.r.length()
        + tx.s.length();
    Header {
        list: true,
        payload_length,
    }
    .encode(out);
    tx.nonce.encode(out);
    gas_price.encode(out);
    tx.gas_limit.encode(out);
    encode_to(tx.to, out);
    tx.value.encode(out);
    tx.data.encode(out);
    tx.v.encode(out);
    tx.r.encode(out);
    tx.s.encode(out);
}

/// `0x01 ‖ rlp([chainId, nonce, gasPrice, gasLimit, to, value, data,
/// accessList, yParity, r, s])`.
fn encode_eip2930(tx: &FixtureTx, out: &mut Vec<u8>) -> Result<(), String> {
    let chain_id = tx.chain_id.ok_or("tx tipo 1 sin chainId")?;
    let gas_price = tx.gas_price.ok_or("tx tipo 1 sin gasPrice")?;
    let payload_length = chain_id.length()
        + tx.nonce.length()
        + gas_price.length()
        + tx.gas_limit.length()
        + to_length(tx.to)
        + tx.value.length()
        + tx.data.length()
        + access_list_length(&tx.access_list)
        + tx.v.length()
        + tx.r.length()
        + tx.s.length();
    Header {
        list: true,
        payload_length,
    }
    .encode(out);
    chain_id.encode(out);
    tx.nonce.encode(out);
    gas_price.encode(out);
    tx.gas_limit.encode(out);
    encode_to(tx.to, out);
    tx.value.encode(out);
    tx.data.encode(out);
    encode_access_list(&tx.access_list, out);
    tx.v.encode(out);
    tx.r.encode(out);
    tx.s.encode(out);
    Ok(())
}

/// `0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
/// to, value, data, accessList, yParity, r, s])`.
fn encode_eip1559(tx: &FixtureTx, out: &mut Vec<u8>) -> Result<(), String> {
    let chain_id = tx.chain_id.ok_or("tx tipo 2 sin chainId")?;
    let max_fee = tx.max_fee_per_gas.ok_or("tx tipo 2 sin maxFeePerGas")?;
    let max_priority = tx
        .max_priority_fee_per_gas
        .ok_or("tx tipo 2 sin maxPriorityFeePerGas")?;
    let payload_length = chain_id.length()
        + tx.nonce.length()
        + max_priority.length()
        + max_fee.length()
        + tx.gas_limit.length()
        + to_length(tx.to)
        + tx.value.length()
        + tx.data.length()
        + access_list_length(&tx.access_list)
        + tx.v.length()
        + tx.r.length()
        + tx.s.length();
    Header {
        list: true,
        payload_length,
    }
    .encode(out);
    chain_id.encode(out);
    tx.nonce.encode(out);
    max_priority.encode(out);
    max_fee.encode(out);
    tx.gas_limit.encode(out);
    encode_to(tx.to, out);
    tx.value.encode(out);
    tx.data.encode(out);
    encode_access_list(&tx.access_list, out);
    tx.v.encode(out);
    tx.r.encode(out);
    tx.s.encode(out);
    Ok(())
}

/// `0x03 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
/// to, value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, yParity,
/// r, s])`.
///
/// **`to` NO es opcional en el tipo 3**: EIP-4844 lo declara `Address` a secas
/// y por eso una tx de blob de creación ni siquiera es RLP-representable — el
/// fixture que la intenta publica el bloque solo como `rlp` crudo (ver
/// `driver::undecodable_block`). Se usa igual el mismo `encode_to` que el resto:
/// el caso `None` no llega acá, y si llegara, codificarlo como cadena vacía
/// daría un trie que no cierra, que es exactamente la señal que se quiere.
fn encode_eip4844(tx: &FixtureTx, out: &mut Vec<u8>) -> Result<(), String> {
    let chain_id = tx.chain_id.ok_or("tx tipo 3 sin chainId")?;
    let max_fee = tx.max_fee_per_gas.ok_or("tx tipo 3 sin maxFeePerGas")?;
    let max_priority = tx
        .max_priority_fee_per_gas
        .ok_or("tx tipo 3 sin maxPriorityFeePerGas")?;
    let max_fee_per_blob_gas = tx
        .max_fee_per_blob_gas
        .ok_or("tx tipo 3 sin maxFeePerBlobGas")?;
    let payload_length = chain_id.length()
        + tx.nonce.length()
        + max_priority.length()
        + max_fee.length()
        + tx.gas_limit.length()
        + to_length(tx.to)
        + tx.value.length()
        + tx.data.length()
        + access_list_length(&tx.access_list)
        + max_fee_per_blob_gas.length()
        + list_length(&tx.blob_versioned_hashes)
        + tx.v.length()
        + tx.r.length()
        + tx.s.length();
    Header {
        list: true,
        payload_length,
    }
    .encode(out);
    chain_id.encode(out);
    tx.nonce.encode(out);
    max_priority.encode(out);
    max_fee.encode(out);
    tx.gas_limit.encode(out);
    encode_to(tx.to, out);
    tx.value.encode(out);
    tx.data.encode(out);
    encode_access_list(&tx.access_list, out);
    max_fee_per_blob_gas.encode(out);
    encode_list(&tx.blob_versioned_hashes, out);
    tx.v.encode(out);
    tx.r.encode(out);
    tx.s.encode(out);
    Ok(())
}

/// `0x04 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
/// to, value, data, accessList, authorizationList, yParity, r, s])`.
///
/// La `authorizationList` es `[[chainId, address, nonce, yParity, r, s]…]`, y
/// se encodea desde `FixtureTx::authorization_tuples` y **no** desde la
/// `AuthorizationList` que consume el motor: esa última no lleva la firma
/// (`authority` ya viene recuperado, seam de 2.7c), y la firma es justo lo que
/// el trie necesita. Es la misma separación que ya existe entre `Transaction`
/// y el `v`/`r`/`s` de la tx.
///
/// **`to` NO es opcional en el tipo 4**, igual que en el 3: una tx de creación
/// tipo 4 no es RLP-representable. El motor la rechaza aparte (2.9b-3e).
fn encode_eip7702(tx: &FixtureTx, out: &mut Vec<u8>) -> Result<(), String> {
    let chain_id = tx.chain_id.ok_or("tx tipo 4 sin chainId")?;
    let max_fee = tx.max_fee_per_gas.ok_or("tx tipo 4 sin maxFeePerGas")?;
    let max_priority = tx
        .max_priority_fee_per_gas
        .ok_or("tx tipo 4 sin maxPriorityFeePerGas")?;
    let payload_length = chain_id.length()
        + tx.nonce.length()
        + max_priority.length()
        + max_fee.length()
        + tx.gas_limit.length()
        + to_length(tx.to)
        + tx.value.length()
        + tx.data.length()
        + access_list_length(&tx.access_list)
        + authorization_list_length(&tx.authorization_tuples)
        + tx.v.length()
        + tx.r.length()
        + tx.s.length();
    Header {
        list: true,
        payload_length,
    }
    .encode(out);
    chain_id.encode(out);
    tx.nonce.encode(out);
    max_priority.encode(out);
    max_fee.encode(out);
    tx.gas_limit.encode(out);
    encode_to(tx.to, out);
    tx.value.encode(out);
    tx.data.encode(out);
    encode_access_list(&tx.access_list, out);
    encode_authorization_list(&tx.authorization_tuples, out);
    tx.v.encode(out);
    tx.r.encode(out);
    tx.s.encode(out);
    Ok(())
}

fn authorization_item_length(item: &FixtureAuthorization) -> usize {
    Header {
        list: true,
        payload_length: item.chain_id.length()
            + item.address.length()
            + item.nonce.length()
            + item.y_parity.length()
            + item.r.length()
            + item.s.length(),
    }
    .length_with_payload()
}

fn authorization_list_length(list: &[FixtureAuthorization]) -> usize {
    Header {
        list: true,
        payload_length: list.iter().map(authorization_item_length).sum(),
    }
    .length_with_payload()
}

fn encode_authorization_list(list: &[FixtureAuthorization], out: &mut Vec<u8>) {
    Header {
        list: true,
        payload_length: list.iter().map(authorization_item_length).sum(),
    }
    .encode(out);
    for item in list {
        Header {
            list: true,
            payload_length: item.chain_id.length()
                + item.address.length()
                + item.nonce.length()
                + item.y_parity.length()
                + item.r.length()
                + item.s.length(),
        }
        .encode(out);
        item.chain_id.encode(out);
        item.address.encode(out);
        item.nonce.encode(out);
        item.y_parity.encode(out);
        item.r.encode(out);
        item.s.encode(out);
    }
}

/// `to` ausente (una tx de creación) se codifica como la **cadena vacía**, no
/// como cero: `0x80` y no `0x00`.
fn encode_to(to: Option<Address>, out: &mut Vec<u8>) {
    match to {
        Some(address) => address.encode(out),
        None => out.push(EMPTY_STRING_CODE),
    }
}

fn to_length(to: Option<Address>) -> usize {
    to.map_or(1, |address| address.length())
}

/// La access list es `[[address, [key…]]…]`.
fn encode_access_list(access_list: &AccessList, out: &mut Vec<u8>) {
    Header {
        list: true,
        payload_length: access_list.iter().map(access_list_item_length).sum(),
    }
    .encode(out);
    for item in access_list {
        Header {
            list: true,
            payload_length: item.address.length() + list_length(&item.storage_keys),
        }
        .encode(out);
        item.address.encode(out);
        encode_list(&item.storage_keys, out);
    }
}

fn access_list_length(access_list: &AccessList) -> usize {
    let payload_length: usize = access_list.iter().map(access_list_item_length).sum();
    Header {
        list: true,
        payload_length,
    }
    .length_with_payload()
}

fn access_list_item_length(item: &repo_b_common::access_list::AccessListItem) -> usize {
    Header {
        list: true,
        payload_length: item.address.length() + list_length(&item.storage_keys),
    }
    .length_with_payload()
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

/// El scalar cero de RLP: sirve de recordatorio de que `U256::ZERO` codifica
/// como `0x80` y no como `0x00`. Lo usa el test de humo de abajo.
#[cfg(test)]
const RLP_EMPTY_STRING: u8 = EMPTY_STRING_CODE;

#[cfg(test)]
mod tests {
    use repo_b_common::primitives::U256;

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

    /// `to = None` (tx de creación) es la cadena VACÍA, no el cero. Confundirlos
    /// da un `transactionsTrie` distinto con el mismo largo, que es la clase de
    /// bug que no se ve mirando el hex.
    #[test]
    fn a_create_transaction_encodes_to_as_the_empty_string() {
        let mut out = Vec::new();
        encode_to(None, &mut out);
        assert_eq!(out, vec![RLP_EMPTY_STRING]);
        assert_eq!(to_length(None), 1);

        let mut zero = Vec::new();
        U256::ZERO.encode(&mut zero);
        assert_eq!(zero, vec![RLP_EMPTY_STRING], "el cero también es 0x80…");
        let mut out = Vec::new();
        encode_to(Some(Address::ZERO), &mut out);
        assert_ne!(out, zero, "…pero la dirección cero NO es la cadena vacía");
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
