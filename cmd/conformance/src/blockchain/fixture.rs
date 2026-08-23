//! Parsing del formato `blockchain_test` de EEST.
//!
//! Módulo propio y no un anexo de `fixture.rs`: un `blockchain_test` no es un
//! `state_test` con más campos. Trae genesis, una cadena de bloques con su
//! header completo, withdrawals y txs YA decodificadas con su firma — que hace
//! falta para re-encodearlas y armar el `transactionsTrie`. Los helpers de hex
//! sí se comparten: parsear un `0x…` es lo mismo en los dos formatos.
//!
//! Input hostil hasta validarse: cada campo con error explícito, sin defaults
//! silenciosos donde el default cambiaría el resultado.

use std::collections::BTreeMap;

use alloy_primitives::{B64, Bloom};
use repo_b_common::access_list::AccessList;
use repo_b_common::authorization::AuthorizationList;
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::withdrawal::Withdrawal;
use repo_b_guest::signature::{Signature, SignedTransaction};
use serde_json::Value;

use crate::fixture::{
    FixtureAccount, field, hex_address, hex_array, hex_b256, hex_bytes, hex_gas_price, hex_u64,
    hex_u128, hex_u256, parse_access_list_entry, parse_accounts, parse_authorization,
};

/// Un `blockchain_test` completo (una entrada del `.json`).
#[derive(Debug, Clone)]
pub struct BlockchainTest {
    pub name: String,
    /// El CAMPO `network`, que es el fork del caso. Nunca el path: un fixture
    /// bajo `shanghai/` puede estar parametrizado a Cancun (lección de 2.9a).
    pub network: String,
    pub chain_id: u64,
    pub pre: BTreeMap<Address, FixtureAccount>,
    pub genesis: BlockHeader,
    pub blocks: Vec<TestBlock>,
    /// El head que la cadena TIENE que tener al final. Es la aserción de que
    /// un bloque rechazado no la hace avanzar: en un caso de un solo bloque
    /// inválido vale el hash del genesis. No es un adorno del fixture.
    pub last_block_hash: B256,
    /// `postState` inline, si el fixture lo trae: enriquece el diagnóstico. El
    /// juez sigue siendo el `stateRoot` del header.
    pub post_state: Option<BTreeMap<Address, FixtureAccount>>,
}

#[derive(Debug, Clone)]
pub struct TestBlock {
    /// `expectException` a nivel BLOQUE: el fixture declara que el bloque es
    /// inválido y el cliente DEBE rechazarlo. Un bloque así publica su cuerpo
    /// —header, txs, withdrawals— bajo `rlp_decoded` en vez de al tope.
    pub expect_exception: Option<String>,
    pub header: Option<BlockHeader>,
    pub transactions: Vec<FixtureTx>,
    /// `None` = el fixture no trae el campo (pre-Shanghai). Distinto de
    /// `Some(vec![])`, que es un bloque Shanghai sin withdrawals — y que SÍ
    /// tiene `withdrawalsRoot` en el header.
    pub withdrawals: Option<Vec<Withdrawal>>,
}

/// Lo que el header declara y contra lo que el harness contrasta lo que
/// computa. Trae **todos** los campos del header, porque el harness computa
/// `keccak(rlp(header))` y para eso ninguno es opcional-por-desinterés: los que
/// faltan mueven el hash.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// El hash del bloque **tal como lo publica el fixture**, y su único uso es
    /// ser el oráculo contra el que se contrasta el computado
    /// (`block_hash::block_hash`). Ningún otro camino lo lee: alimentar
    /// `BLOCKHASH` o mover el head con este valor volvería tautológico el
    /// chequeo.
    pub hash: B256,
    pub parent_hash: B256,
    /// `ommersHash` del Yellow Paper. Post-Merge es siempre el root de la lista
    /// vacía, pero es un campo del RLP y omitirlo cambia el hash.
    pub uncle_hash: B256,
    pub number: u64,
    pub coinbase: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    /// Post-Merge es siempre cero, y aun así entra al RLP: es `U256` y no `u64`
    /// porque el campo es un escalar de 256 bits y un header pre-Merge del
    /// corpus lo desbordaría.
    pub difficulty: U256,
    pub extra_data: Bytes,
    /// El `nonce` de PoW: 8 bytes, no un escalar. Post-Merge es cero, pero
    /// codificarlo como escalar daría `0x80` en vez de los ocho bytes.
    pub nonce: B64,
    pub base_fee: Option<u64>,
    /// Post-Merge es el `prevrandao` de DIFFICULTY.
    pub mix_hash: B256,
    pub state_root: B256,
    pub transactions_trie: B256,
    pub receipt_trie: B256,
    pub bloom: Bloom,
    pub withdrawals_root: Option<B256>,
    /// EIP-4844. `None` = el fixture no trae el campo (pre-Cancun). En Cancun+
    /// es obligatorio, y esa regla la aplica `header::check_blob_gas`.
    pub excess_blob_gas: Option<u64>,
    /// EIP-4844: `GAS_PER_BLOB ×` los blobs del bloque. Es el sumando que el
    /// hijo necesita del padre para su propio `excessBlobGas`.
    pub blob_gas_used: Option<u64>,
    /// EIP-4788: la raíz del bloque de beacon padre, calldata de la system
    /// call del arranque del bloque.
    pub parent_beacon_block_root: Option<B256>,
    /// EIP-7685: el commitment SHA-256 de los requests del bloque. `None` =
    /// el fixture no trae el campo (pre-Prague). En Prague+ es obligatorio.
    pub requests_hash: Option<B256>,
}

/// Una tx del bloque, ya decodificada. A diferencia de un `state_test`, el tipo
/// viene EXPLÍCITO (`type`) en vez de inferirse de qué campos están presentes.
#[derive(Debug, Clone)]
pub struct FixtureTx {
    pub tx_type: TxType,
    pub chain_id: Option<U256>,
    pub nonce: u64,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub access_list: AccessList,
    pub max_fee_per_blob_gas: Option<u128>,
    pub blob_versioned_hashes: Vec<B256>,
    pub authorization_list: AuthorizationList,
    /// Las MISMAS tuplas, pero con su firma. Existen aparte de
    /// `authorization_list` por la misma razón que `v`/`r`/`s` existen aparte
    /// de `Transaction`: el motor recibe el `authority` ya recuperado y nunca
    /// ve la firma, pero el envelope RLP del tipo 4 la lleva.
    pub authorization_tuples: Vec<FixtureAuthorization>,
    /// El sender que el fixture DECLARA. **Ya no es de donde sale el sender
    /// que se ejecuta**: desde 4.1c el guest lo deriva de la firma y esto pasa
    /// a ser el **oráculo independiente** contra el que se contrasta.
    pub sender: Address,
    /// Firma. La consume el `transactionsTrie` **y** la recuperación del
    /// sender: son el mismo envelope.
    pub v: U256,
    pub r: U256,
    pub s: U256,
}

/// Una tupla de autorización tal cual la publica el fixture — **solo para
/// encoding**. La versión que consume el motor es `Authorization`.
#[derive(Debug, Clone)]
pub struct FixtureAuthorization {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: u64,
    pub y_parity: U256,
    pub r: U256,
    pub s: U256,
}

/// Parsea todos los `blockchain_test` de un archivo.
pub fn parse_file(raw: &str) -> Result<Vec<BlockchainTest>, String> {
    let root: Value = serde_json::from_str(raw).map_err(|e| format!("JSON inválido: {e}"))?;
    let map = root.as_object().ok_or("el fixture no es un objeto JSON")?;
    let mut tests = Vec::new();
    for (name, body) in map {
        tests.push(parse_test(name, body).map_err(|e| format!("{name}: {e}"))?);
    }
    Ok(tests)
}

fn parse_test(name: &str, body: &Value) -> Result<BlockchainTest, String> {
    let network = field(body, "network")?
        .as_str()
        .ok_or("network no es un string")?
        .to_owned();
    let chain_id = body
        .get("config")
        .and_then(|c| c.get("chainid"))
        .map(hex_u64)
        .transpose()?
        .unwrap_or(1);
    let genesis = parse_header(field(body, "genesisBlockHeader")?)?;
    let pre = parse_accounts(field(body, "pre")?)?;
    let blocks = field(body, "blocks")?
        .as_array()
        .ok_or("blocks no es un array")?
        .iter()
        .map(parse_block)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BlockchainTest {
        name: name.to_owned(),
        network,
        chain_id,
        pre,
        genesis,
        blocks,
        // Obligatorio: es la aserción de dónde quedó el head. Un default
        // silencioso acá convertiría "la cadena no avanzó" en un chequeo que
        // no se hace.
        last_block_hash: hex_b256(field(body, "lastblockhash")?)?,
        post_state: body.get("postState").map(parse_accounts).transpose()?,
    })
}

fn parse_block(value: &Value) -> Result<TestBlock, String> {
    let expect_exception = value
        .get("expectException")
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or("expectException no es un string")
        })
        .transpose()?;
    // Un bloque inválido publica el cuerpo bajo `rlp_decoded`, y ahí adentro
    // el header viene COMPLETO — con la misma forma que el de un bloque
    // válido. Por eso este slice no necesita un decoder de RLP de bloque: el
    // fixture ya trae los dos formatos del mismo dato.
    let body = value.get("rlp_decoded").unwrap_or(value);
    let header = body.get("blockHeader").map(parse_header).transpose()?;
    let transactions = match body.get("transactions") {
        None | Some(Value::Null) => Vec::new(),
        Some(list) => hex_array(list, parse_transaction)?,
    };
    let withdrawals = match body.get("withdrawals") {
        None | Some(Value::Null) => None,
        Some(list) => Some(hex_array(list, parse_withdrawal)?),
    };
    Ok(TestBlock {
        expect_exception,
        header,
        transactions,
        withdrawals,
    })
}

fn parse_header(value: &Value) -> Result<BlockHeader, String> {
    Ok(BlockHeader {
        hash: hex_b256(field(value, "hash")?)?,
        parent_hash: hex_b256(field(value, "parentHash")?)?,
        uncle_hash: hex_b256(field(value, "uncleHash")?)?,
        number: hex_u64(field(value, "number")?)?,
        coinbase: hex_address(field(value, "coinbase")?)?,
        timestamp: hex_u64(field(value, "timestamp")?)?,
        gas_limit: hex_u64(field(value, "gasLimit")?)?,
        gas_used: hex_u64(field(value, "gasUsed")?)?,
        // Obligatorios los tres, y no `Option`: están en los cuatro forks en
        // scope (medido) y un default silencioso acá daría un hash equivocado
        // en vez de decir que el fixture no se entendió.
        difficulty: hex_u256(field(value, "difficulty")?)?,
        extra_data: hex_bytes(field(value, "extraData")?)?,
        nonce: hex_b64(field(value, "nonce")?)?,
        base_fee: value.get("baseFeePerGas").map(hex_u64).transpose()?,
        mix_hash: hex_b256(field(value, "mixHash")?)?,
        state_root: hex_b256(field(value, "stateRoot")?)?,
        transactions_trie: hex_b256(field(value, "transactionsTrie")?)?,
        receipt_trie: hex_b256(field(value, "receiptTrie")?)?,
        bloom: parse_bloom(field(value, "bloom")?)?,
        withdrawals_root: value.get("withdrawalsRoot").map(hex_b256).transpose()?,
        excess_blob_gas: value.get("excessBlobGas").map(hex_u64).transpose()?,
        blob_gas_used: value.get("blobGasUsed").map(hex_u64).transpose()?,
        parent_beacon_block_root: value
            .get("parentBeaconBlockRoot")
            .map(hex_b256)
            .transpose()?,
        requests_hash: value.get("requestsHash").map(hex_b256).transpose()?,
    })
}

/// La tupla cruda, para el envelope RLP. `yParity` es el nombre canónico de
/// EIP-7702 y `v` el alias que el fixture publica al lado: se acepta
/// cualquiera de los dos, y ninguno se inventa si faltan los dos.
fn parse_authorization_tuple(value: &Value) -> Result<FixtureAuthorization, String> {
    let y_parity = value
        .get("yParity")
        .or_else(|| value.get("v"))
        .ok_or("tupla de autorización sin yParity ni v")?;
    Ok(FixtureAuthorization {
        chain_id: hex_u256(field(value, "chainId")?)?,
        address: hex_address(field(value, "address")?)?,
        nonce: hex_u64(field(value, "nonce")?)?,
        y_parity: hex_u256(y_parity)?,
        r: hex_u256(field(value, "r")?)?,
        s: hex_u256(field(value, "s")?)?,
    })
}

/// El `nonce` de PoW del header: **exactamente** 8 bytes. Un largo distinto es
/// un fixture que no entendimos, no un escalar que se pueda left-padear: el RLP
/// lo lleva como cadena de bytes y el padding cambiaría el hash en silencio.
fn hex_b64(value: &Value) -> Result<B64, String> {
    let bytes = hex_bytes(value)?;
    let raw: [u8; 8] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| format!("nonce con longitud {} (se esperaban 8)", bytes.len()))?;
    Ok(B64::new(raw))
}

fn parse_bloom(value: &Value) -> Result<Bloom, String> {
    let bytes = hex_bytes(value)?;
    let raw: [u8; 256] = bytes
        .as_ref()
        .try_into()
        .map_err(|_| format!("bloom con longitud {} (se esperaban 256)", bytes.len()))?;
    Ok(Bloom::new(raw))
}

fn parse_withdrawal(value: &Value) -> Result<Withdrawal, String> {
    Ok(Withdrawal {
        index: hex_u64(field(value, "index")?)?,
        validator_index: hex_u64(field(value, "validatorIndex")?)?,
        address: hex_address(field(value, "address")?)?,
        amount: hex_u64(field(value, "amount")?)?,
    })
}

/// EIP-2718: el byte de tipo. Un tipo que este motor no conoce es un fixture
/// que no entendimos, no una tx legacy — fail-closed.
fn parse_tx_type(value: &Value) -> Result<TxType, String> {
    match hex_u64(value)? {
        0 => Ok(TxType::Legacy),
        1 => Ok(TxType::Eip2930),
        2 => Ok(TxType::Eip1559),
        3 => Ok(TxType::Eip4844),
        4 => Ok(TxType::Eip7702),
        other => Err(format!("tipo de tx desconocido: {other}")),
    }
}

fn parse_transaction(value: &Value) -> Result<FixtureTx, String> {
    let tx_type = match value.get("type") {
        // Sin `type` explícito el fixture es pre-EIP-2718: legacy.
        None | Some(Value::Null) => TxType::Legacy,
        Some(raw) => parse_tx_type(raw)?,
    };
    let access_list = match value.get("accessList") {
        None | Some(Value::Null) => AccessList::new(),
        Some(list) => parse_access_list_entry(list)?,
    };
    let (authorization_list, authorization_tuples) = match value.get("authorizationList") {
        None | Some(Value::Null) => (AuthorizationList::new(), Vec::new()),
        Some(list) => (
            hex_array(list, parse_authorization)?,
            hex_array(list, parse_authorization_tuple)?,
        ),
    };
    Ok(FixtureTx {
        tx_type,
        chain_id: value.get("chainId").map(hex_u256).transpose()?,
        nonce: hex_u64(field(value, "nonce")?)?,
        gas_price: value.get("gasPrice").map(hex_gas_price).transpose()?,
        max_fee_per_gas: value.get("maxFeePerGas").map(hex_gas_price).transpose()?,
        max_priority_fee_per_gas: value
            .get("maxPriorityFeePerGas")
            .map(hex_gas_price)
            .transpose()?,
        gas_limit: hex_u64(field(value, "gasLimit")?)?,
        // Una tx de creación OMITE `to` (no lo trae vacío, como sí hace el
        // formato `state_test`).
        to: match value.get("to") {
            None | Some(Value::Null) => None,
            Some(raw) if raw.as_str() == Some("") => None,
            Some(raw) => Some(hex_address(raw)?),
        },
        value: hex_u256(field(value, "value")?)?,
        data: hex_bytes(field(value, "data")?)?,
        access_list,
        max_fee_per_blob_gas: value.get("maxFeePerBlobGas").map(hex_u128).transpose()?,
        blob_versioned_hashes: match value.get("blobVersionedHashes") {
            None | Some(Value::Null) => Vec::new(),
            Some(list) => hex_array(list, hex_b256)?,
        },
        authorization_list,
        authorization_tuples,
        // `sender` sigue siendo OBLIGATORIO, pero por otra razón que antes: es
        // el oráculo contra el que se contrasta lo que la firma produce. Un
        // fixture sin él no puede juzgar la derivación, así que se rechaza en
        // vez de dejar la aserción sin contraparte.
        sender: hex_address(field(value, "sender")?)?,
        v: hex_u256(field(value, "v")?)?,
        r: hex_u256(field(value, "r")?)?,
        s: hex_u256(field(value, "s")?)?,
    })
}

/// **De la tx del fixture al envelope firmado que consume el guest.**
///
/// Es el único punto donde el harness arma un `SignedTransaction`, y el
/// `sender` declarado **no entra**: `SignedTransaction::new` lo descartaría
/// igual, pero ni siquiera se le pasa. Quién firmó sale de la firma.
///
/// # Errors
/// Si la tx no es representable como envelope (una tipada sin `chainId`, o un
/// `chainId` que no entra en 64 bits) o si el fixture trae distinta cantidad de
/// tuplas que de firmas de tupla.
pub fn signed_transaction(tx: &FixtureTx) -> Result<SignedTransaction, String> {
    if tx.authorization_list.len() != tx.authorization_tuples.len() {
        return Err(format!(
            "{} tuplas de autorización y {} firmas: el fixture no las parea",
            tx.authorization_list.len(),
            tx.authorization_tuples.len()
        ));
    }
    let chain_id = match tx.tx_type {
        // En una legacy el `chainId` viaja adentro del `v` (EIP-155) o no
        // viaja: el campo del fixture es informativo y NO entra al envelope.
        TxType::Legacy => None,
        _ => {
            let raw = tx.chain_id.ok_or("tx tipada sin chainId")?;
            Some(
                u64::try_from(raw)
                    .map_err(|_| "el chainId de la tx no entra en 64 bits".to_owned())?,
            )
        }
    };
    // **Las tuplas del envelope salen de lo que el fixture PUBLICÓ**, no de la
    // lista que el harness ya interpretó: el envelope es el dato del bloque, y
    // pasarlo por nuestra interpretación sería volver a meter una decisión
    // nuestra adentro de lo que la prueba afirma.
    let authorization_list = tx
        .authorization_tuples
        .iter()
        .map(|a| repo_b_common::authorization::Authorization {
            chain_id: a.chain_id,
            address: a.address,
            nonce: a.nonce,
            authority: None,
        })
        .collect();
    let payload = Transaction {
        tx_type: tx.tx_type,
        sender: Address::ZERO,
        nonce: tx.nonce,
        to: tx.to,
        value: tx.value,
        input: tx.data.clone(),
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        access_list: tx.access_list.clone(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
        blob_versioned_hashes: tx.blob_versioned_hashes.clone(),
        authorization_list,
    };
    let firmas = tx
        .authorization_tuples
        .iter()
        .map(|a| Signature {
            v: a.y_parity,
            r: a.r,
            s: a.s,
        })
        .collect();
    Ok(SignedTransaction::new(
        payload,
        chain_id,
        Signature {
            v: tx.v,
            r: tx.r,
            s: tx.s,
        },
        firmas,
    ))
}
