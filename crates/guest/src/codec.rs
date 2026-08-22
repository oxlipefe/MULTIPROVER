//! El input del guest, en bytes.
//!
//! Hasta acá el punto de entrada recibía el bloque **tipado**, que sirve para
//! probar que el camino de ejecución está adentro del ELF pero no para
//! alimentarlo de verdad: adentro de una zkVM lo único que entra es un buffer.
//!
//! **Este es el primer decoder de input externo del repo.** Todo lo demás que
//! decodifica RLP acá adentro son nodos de trie y headers, que vienen
//! verificados por su propio hash; esto no. Cada byte de acá es hostil hasta que
//! se prueba lo contrario, y por eso todo camino de error termina en un rechazo
//! y nunca en un `GuestInput` a medio llenar.
//!
//! **Por qué el formato es propio y no el envelope canónico.** Un guest de
//! producción recibe el bloque con **firmas**, porque verifica el
//! `transactionsTrie` y recupera los senders adentro. Acá no pasa ninguna de las
//! dos: el trie de txs lo computa el host, y la recuperación ECDSA está fuera
//! del EVM — `Transaction` **no tiene** `v`/`r`/`s`. Sin firma no hay envelope
//! que reconstruir. El día que ECDSA entre al guest, el input pasa a ser el
//! envelope canónico y esto se reemplaza; es deuda con nombre, no un descuido.
//!
//! **`Option` en RLP no es "campo que puede faltar".** RLP es posicional: un
//! hueco no es representable. Un opcional viaja como **lista de cero o un
//! elemento**, que es explícito y no se puede confundir con el valor cero — y
//! confundirlos cambiaría el gas (`blob_base_fee` ausente no es
//! `blob_base_fee = 0`).

use alloc::vec::Vec;

use alloy_rlp::{Decodable, Encodable, Header};
use repo_b_common::access_list::{AccessList, AccessListItem};
use repo_b_common::authorization::{Authorization, AuthorizationList};
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;

use crate::GuestInput;

/// Por qué un input no se pudo leer. **Un solo camino de salida**: el guest no
/// tiene a quién reportarle un error parcial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub &'static str);

impl From<alloy_rlp::Error> for CodecError {
    fn from(_: alloy_rlp::Error) -> Self {
        Self("RLP malformado")
    }
}

type R<T> = Result<T, CodecError>;

/// El input decodificado, **dueño de sus datos**.
///
/// `GuestInput` presta; esto posee. Se separan porque el punto de entrada tipado
/// (el que 3.4a dejó) no tiene por qué cambiar de forma solo porque ahora hay un
/// decoder.
#[derive(Debug, Clone)]
pub struct OwnedInput {
    pub witness: ExecutionWitness,
    pub pre_state_root: B256,
    /// El ancla de la cadena de headers. Ver `GuestInput::parent_hash`.
    pub parent_hash: B256,
    pub env: BlockEnv,
    pub txs: Vec<Transaction>,
    pub withdrawals: Vec<Withdrawal>,
    /// Las del **arranque** del bloque.
    pub opening_system_calls: Vec<(Address, Bytes)>,
    /// Las del **cierre**. Lista propia y no un flag: ver
    /// `GuestInput::closing_system_calls`. Que sean dos campos en el formato es
    /// lo que hace que un input hostil no pueda pedir que una llamada de cierre
    /// corra al arrancar.
    pub closing_system_calls: Vec<(Address, Bytes)>,
}

impl OwnedInput {
    #[must_use]
    pub fn as_input(&self) -> GuestInput<'_> {
        GuestInput {
            witness: &self.witness,
            pre_state_root: self.pre_state_root,
            parent_hash: self.parent_hash,
            env: self.env.clone(),
            txs: &self.txs,
            withdrawals: self.withdrawals.clone(),
            opening_system_calls: &self.opening_system_calls,
            closing_system_calls: &self.closing_system_calls,
        }
    }
}

// ---------------------------------------------------------------------------
// Primitivas: listas y opcionales.
// ---------------------------------------------------------------------------

/// Abre una lista RLP y devuelve el cuerpo, dejando el cursor después de ella.
///
/// **Acotado por el largo declarado y no por lo que quede en el buffer**: sin
/// esto, una lista que dice medir más de lo que hay se comería el resto del
/// input en vez de ser rechazada.
fn open_list<'a>(buf: &mut &'a [u8]) -> R<&'a [u8]> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(CodecError("se esperaba una lista RLP"));
    }
    if header.payload_length > buf.len() {
        return Err(CodecError("una lista declara más bytes de los que hay"));
    }
    let (body, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    Ok(body)
}

/// Un opcional: lista vacía = `None`, lista de un elemento = `Some`.
fn decode_opt<T: Decodable>(buf: &mut &[u8]) -> R<Option<T>> {
    let mut body = open_list(buf)?;
    if body.is_empty() {
        return Ok(None);
    }
    let value = T::decode(&mut body)?;
    if !body.is_empty() {
        return Err(CodecError("un opcional trae más de un elemento"));
    }
    Ok(Some(value))
}

fn encode_opt<T: Encodable>(value: Option<&T>, out: &mut Vec<u8>) {
    match value {
        Some(v) => {
            let mut inner = Vec::new();
            v.encode(&mut inner);
            list_of(&inner, out);
        }
        None => list_of(&[], out),
    }
}

/// Envuelve `payload` en una cabecera de lista.
fn list_of(payload: &[u8], out: &mut Vec<u8>) {
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(out);
    out.extend_from_slice(payload);
}

/// Decodifica ítems hasta agotar el cuerpo. Que el cuerpo esté acotado por
/// `open_list` es lo que hace que esto termine.
fn decode_all<T, F: Fn(&mut &[u8]) -> R<T>>(body: &mut &[u8], f: F) -> R<Vec<T>> {
    let mut out = Vec::new();
    while !body.is_empty() {
        out.push(f(body)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// El input completo.
// ---------------------------------------------------------------------------

/// Serializa el input. Vive acá y no en el host **a propósito**: que las dos
/// mitades estén una al lado de la otra no las vuelve una sola implementación
/// —el decoder tiene que poder correr sin el encoder— pero sí hace que un
/// cambio de formato que toque una y no la otra sea visible al leer.
#[must_use]
pub fn encode(input: &OwnedInput) -> Vec<u8> {
    let mut body = Vec::new();

    let mut w = Vec::new();
    for lista in [
        &input.witness.state,
        &input.witness.codes,
        &input.witness.keys,
        &input.witness.headers,
    ] {
        let mut inner = Vec::new();
        for item in lista {
            item.encode(&mut inner);
        }
        list_of(&inner, &mut w);
    }
    list_of(&w, &mut body);

    input.pre_state_root.encode(&mut body);
    input.parent_hash.encode(&mut body);
    encode_env(&input.env, &mut body);

    let mut txs = Vec::new();
    for tx in &input.txs {
        encode_tx(tx, &mut txs);
    }
    list_of(&txs, &mut body);

    let mut ws = Vec::new();
    for withdrawal in &input.withdrawals {
        withdrawal.encode(&mut ws);
    }
    list_of(&ws, &mut body);

    encode_system_calls(&input.opening_system_calls, &mut body);
    encode_system_calls(&input.closing_system_calls, &mut body);

    let mut out = Vec::new();
    list_of(&body, &mut out);
    out
}

/// # Errors
/// `CodecError` ante cualquier byte que no encaje. **Nunca** devuelve un input
/// a medio armar: un input que no decodifica es un rechazo.
pub fn decode(raw: &[u8]) -> R<OwnedInput> {
    let mut cursor = raw;
    let mut body = open_list(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(CodecError("hay bytes después del input"));
    }

    let mut w = open_list(&mut body)?;
    let mut lista = || -> R<Vec<Bytes>> {
        let mut items = open_list(&mut w)?;
        decode_all(&mut items, |b| Ok(Bytes::decode(b)?))
    };
    let witness = ExecutionWitness {
        state: lista()?,
        codes: lista()?,
        keys: lista()?,
        headers: lista()?,
    };
    if !w.is_empty() {
        return Err(CodecError("el witness trae más de cuatro listas"));
    }

    let pre_state_root = B256::decode(&mut body)?;
    let parent_hash = B256::decode(&mut body)?;
    let env = decode_env(&mut body)?;

    let mut txs_body = open_list(&mut body)?;
    let txs = decode_all(&mut txs_body, decode_tx)?;

    let mut ws_body = open_list(&mut body)?;
    let withdrawals = decode_all(&mut ws_body, decode_withdrawal)?;

    // **Dos listas y no una.** El orden posicional es lo que separa arranque de
    // cierre: no hay byte que un input hostil pueda voltear para mover una
    // llamada de un momento del lifecycle al otro.
    let opening_system_calls = decode_system_calls(&mut body)?;
    let closing_system_calls = decode_system_calls(&mut body)?;

    if !body.is_empty() {
        return Err(CodecError("el input trae campos de más"));
    }
    Ok(OwnedInput {
        witness,
        pre_state_root,
        parent_hash,
        env,
        txs,
        withdrawals,
        opening_system_calls,
        closing_system_calls,
    })
}

/// Una lista de system calls. La misma forma para las dos, porque lo que las
/// distingue es **la posición en el input**, no su contenido.
fn encode_system_calls(calls: &[(Address, Bytes)], out: &mut Vec<u8>) {
    let mut sc = Vec::new();
    for (to, data) in calls {
        let mut inner = Vec::new();
        to.encode(&mut inner);
        data.encode(&mut inner);
        list_of(&inner, &mut sc);
    }
    list_of(&sc, out);
}

fn decode_system_calls(body: &mut &[u8]) -> R<Vec<(Address, Bytes)>> {
    let mut sc_body = open_list(body)?;
    decode_all(&mut sc_body, |b| {
        let mut item = open_list(b)?;
        let to = Address::decode(&mut item)?;
        let data = Bytes::decode(&mut item)?;
        if !item.is_empty() {
            return Err(CodecError("una system call trae campos de más"));
        }
        Ok((to, data))
    })
}

// ---------------------------------------------------------------------------
// Piezas.
// ---------------------------------------------------------------------------

fn encode_env(env: &BlockEnv, out: &mut Vec<u8>) {
    let mut inner = Vec::new();
    spec_byte(env.spec).encode(&mut inner);
    env.chain_id.encode(&mut inner);
    env.number.encode(&mut inner);
    env.coinbase.encode(&mut inner);
    env.timestamp.encode(&mut inner);
    env.gas_limit.encode(&mut inner);
    env.base_fee.encode(&mut inner);
    env.prevrandao.encode(&mut inner);
    encode_opt(env.blob_excess_gas.as_ref(), &mut inner);
    encode_opt(env.blob_base_fee.as_ref(), &mut inner);
    encode_opt(env.blob_base_fee_update_fraction.as_ref(), &mut inner);
    list_of(&inner, out);
}

fn decode_env(buf: &mut &[u8]) -> R<BlockEnv> {
    let mut b = open_list(buf)?;
    let env = BlockEnv {
        spec: spec_of(u8::decode(&mut b)?)?,
        chain_id: u64::decode(&mut b)?,
        number: u64::decode(&mut b)?,
        coinbase: Address::decode(&mut b)?,
        timestamp: u64::decode(&mut b)?,
        gas_limit: u64::decode(&mut b)?,
        base_fee: u64::decode(&mut b)?,
        prevrandao: B256::decode(&mut b)?,
        blob_excess_gas: decode_opt(&mut b)?,
        blob_base_fee: decode_opt(&mut b)?,
        blob_base_fee_update_fraction: decode_opt(&mut b)?,
    };
    if !b.is_empty() {
        return Err(CodecError("el env trae campos de más"));
    }
    Ok(env)
}

/// El fork viaja como un byte. **Explícito y no `as`**: si mañana entra un fork
/// nuevo, esto no compila hasta que alguien decida su número.
const fn spec_byte(spec: Spec) -> u8 {
    match spec {
        Spec::Paris => 0,
        Spec::Shanghai => 1,
        Spec::Cancun => 2,
        Spec::Prague => 3,
    }
}

fn spec_of(byte: u8) -> R<Spec> {
    match byte {
        0 => Ok(Spec::Paris),
        1 => Ok(Spec::Shanghai),
        2 => Ok(Spec::Cancun),
        3 => Ok(Spec::Prague),
        _ => Err(CodecError("fork desconocido")),
    }
}

const fn tx_type_byte(t: TxType) -> u8 {
    match t {
        TxType::Legacy => 0,
        TxType::Eip2930 => 1,
        TxType::Eip1559 => 2,
        TxType::Eip4844 => 3,
        TxType::Eip7702 => 4,
    }
}

fn tx_type_of(byte: u8) -> R<TxType> {
    match byte {
        0 => Ok(TxType::Legacy),
        1 => Ok(TxType::Eip2930),
        2 => Ok(TxType::Eip1559),
        3 => Ok(TxType::Eip4844),
        4 => Ok(TxType::Eip7702),
        _ => Err(CodecError("tipo de tx desconocido")),
    }
}

fn encode_tx(tx: &Transaction, out: &mut Vec<u8>) {
    let mut i = Vec::new();
    tx_type_byte(tx.tx_type).encode(&mut i);
    tx.sender.encode(&mut i);
    tx.nonce.encode(&mut i);
    encode_opt(tx.to.as_ref(), &mut i);
    tx.value.encode(&mut i);
    tx.input.encode(&mut i);
    tx.gas_limit.encode(&mut i);
    encode_opt(tx.gas_price.as_ref(), &mut i);
    encode_opt(tx.max_fee_per_gas.as_ref(), &mut i);
    encode_opt(tx.max_priority_fee_per_gas.as_ref(), &mut i);

    let mut al = Vec::new();
    for item in &tx.access_list {
        let mut e = Vec::new();
        item.address.encode(&mut e);
        let mut keys = Vec::new();
        for key in &item.storage_keys {
            key.encode(&mut keys);
        }
        list_of(&keys, &mut e);
        list_of(&e, &mut al);
    }
    list_of(&al, &mut i);

    encode_opt(tx.max_fee_per_blob_gas.as_ref(), &mut i);
    let mut blobs = Vec::new();
    for hash in &tx.blob_versioned_hashes {
        hash.encode(&mut blobs);
    }
    list_of(&blobs, &mut i);

    let mut auths = Vec::new();
    for a in &tx.authorization_list {
        let mut e = Vec::new();
        a.chain_id.encode(&mut e);
        a.address.encode(&mut e);
        a.nonce.encode(&mut e);
        encode_opt(a.authority.as_ref(), &mut e);
        list_of(&e, &mut auths);
    }
    list_of(&auths, &mut i);

    list_of(&i, out);
}

fn decode_tx(buf: &mut &[u8]) -> R<Transaction> {
    let mut b = open_list(buf)?;
    let tx_type = tx_type_of(u8::decode(&mut b)?)?;
    let sender = Address::decode(&mut b)?;
    let nonce = u64::decode(&mut b)?;
    let to = decode_opt(&mut b)?;
    let value = U256::decode(&mut b)?;
    let input = Bytes::decode(&mut b)?;
    let gas_limit = u64::decode(&mut b)?;
    let gas_price = decode_opt(&mut b)?;
    let max_fee_per_gas = decode_opt(&mut b)?;
    let max_priority_fee_per_gas = decode_opt(&mut b)?;

    let mut al_body = open_list(&mut b)?;
    let access_list: AccessList = decode_all(&mut al_body, |x| {
        let mut item = open_list(x)?;
        let address = Address::decode(&mut item)?;
        let mut keys_body = open_list(&mut item)?;
        let storage_keys = decode_all(&mut keys_body, |k| Ok(B256::decode(k)?))?;
        if !item.is_empty() {
            return Err(CodecError("un ítem de access list trae campos de más"));
        }
        Ok(AccessListItem {
            address,
            storage_keys,
        })
    })?;

    let max_fee_per_blob_gas = decode_opt(&mut b)?;
    let mut blobs_body = open_list(&mut b)?;
    let blob_versioned_hashes = decode_all(&mut blobs_body, |h| Ok(B256::decode(h)?))?;

    let mut auths_body = open_list(&mut b)?;
    let authorization_list: AuthorizationList = decode_all(&mut auths_body, |x| {
        let mut item = open_list(x)?;
        let a = Authorization {
            chain_id: U256::decode(&mut item)?,
            address: Address::decode(&mut item)?,
            nonce: u64::decode(&mut item)?,
            authority: decode_opt(&mut item)?,
        };
        if !item.is_empty() {
            return Err(CodecError("una autorización trae campos de más"));
        }
        Ok(a)
    })?;

    if !b.is_empty() {
        return Err(CodecError("una tx trae campos de más"));
    }
    Ok(Transaction {
        tx_type,
        sender,
        nonce,
        to,
        value,
        input,
        gas_limit,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        access_list,
        max_fee_per_blob_gas,
        blob_versioned_hashes,
        authorization_list,
    })
}

fn decode_withdrawal(buf: &mut &[u8]) -> R<Withdrawal> {
    let mut b = open_list(buf)?;
    let w = Withdrawal {
        index: u64::decode(&mut b)?,
        validator_index: u64::decode(&mut b)?,
        address: Address::decode(&mut b)?,
        amount: u64::decode(&mut b)?,
    };
    if !b.is_empty() {
        return Err(CodecError("una withdrawal trae campos de más"));
    }
    Ok(w)
}
