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
//! **Las transacciones viajan en su envelope canónico EIP-2718**, el mismo que
//! el `transactionsTrie` commitea — no en un formato nuestro. Es lo que hace que
//! el bloque que el guest ejecuta sea *el* bloque y no una descripción nuestra
//! de él: el **sender no viaja**, se deriva de la firma (`signature.rs`), así
//! que un input hostil no tiene dónde escribir quién firmó. El envelope se lee
//! con `signature::decode_2718`, que es el segundo decoder de input externo del
//! repo y por eso tiene sus propios tests adversariales.
//!
//! **`Option` en RLP no es "campo que puede faltar".** RLP es posicional: un
//! hueco no es representable. Un opcional viaja como **lista de cero o un
//! elemento**, que es explícito y no se puede confundir con el valor cero — y
//! confundirlos cambiaría el gas (`blob_base_fee` ausente no es
//! `blob_base_fee = 0`).

use alloc::vec::Vec;

use alloy_rlp::{Decodable, Encodable, Header};
use repo_b_common::primitives::{Address, B256, Bytes};
use repo_b_common::spec::Spec;
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;

use crate::GuestInput;
use crate::signature::SignedTransaction;

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
    /// **Con su firma y sin su sender.** Ver el doc del módulo.
    pub txs: Vec<SignedTransaction>,
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
/// # Errors
/// Si alguna tx no es representable como envelope de consenso (una tipada sin
/// `chainId`, un campo de gas ausente). **Es un rechazo y no un envelope a
/// medio armar**: lo que no se puede encodear tampoco se puede commitear a un
/// trie, así que no hay bloque que probar.
pub fn encode(input: &OwnedInput) -> R<Vec<u8>> {
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
        // El envelope canónico entra como una cadena de bytes: el input del
        // guest **transporta** el commitment del bloque, no lo re-describe.
        let envelope = tx.encode_2718().map_err(|e| CodecError(e.0))?;
        Bytes::from(envelope).encode(&mut txs);
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
    Ok(out)
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

/// Una tx del input: su **envelope canónico** como cadena de bytes.
///
/// El decoder del envelope vive en `signature.rs` y no acá porque es el mismo
/// que produce el hash de firma: separarlos permitiría que el guest leyera un
/// envelope y firmara otro.
fn decode_tx(buf: &mut &[u8]) -> R<SignedTransaction> {
    let raw = Bytes::decode(buf)?;
    crate::signature::decode_2718(&raw).map_err(|e| CodecError(e.0))
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
