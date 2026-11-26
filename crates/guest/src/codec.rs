//! El input del guest, en bytes.
//!
//! Adentro de una zkVM lo único que entra es un buffer. **Este es un decoder de
//! input externo**: cada byte es hostil hasta que se prueba lo contrario, y por
//! eso todo camino de error termina en un rechazo y nunca en un input a medio
//! llenar.
//!
//! # Dos formatos, uno por clase de afirmación
//!
//! - [`BlockInput`] — **un bloque**, que es lo que prueba `Mode::Full`. Lleva
//!   el bloque **tal como viaja** (`rlp([header, txs, ommers, withdrawals])`),
//!   el fork, el `chain_id` y el witness. Todo lo demás se **deriva**: el `env`
//!   sale del header, el `pre_state_root` del padre, las system calls de las
//!   constantes del fork y de campos del header. No hay byte del input donde
//!   escribir una dirección de system call, un `env` o un root de arranque.
//! - [`TxInput`] — **txs sueltas sobre un pre-state declarado**, el formato de
//!   un `state_test` de la EF. Es de `Mode::StateTest`, que no afirma nada
//!   sobre un bloque.
//!
//! Los dos llevan su versión adelante: un input de otra versión es un rechazo,
//! no un input que se interpreta con el formato equivocado.
//!
//! **Las transacciones viajan en su envelope canónico EIP-2718**, el mismo que
//! el `transactionsTrie` commitea. El **sender no viaja**: se deriva de la
//! firma (`signature.rs`).
//!
//! **El witness viaja sin `keys`.** Las preimágenes de claves hasheadas no las
//! consulta nadie adentro del guest —el trie se camina por `keccak(clave)`, que
//! el guest computa— y un byte que nadie consulta es un byte que un prover
//! puede cambiar sin cambiar la prueba.
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
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;

use crate::journal::{fork_from_id, fork_id};
use crate::signature::SignedTransaction;

/// La versión de los dos formatos de input.
pub const INPUT_VERSION: u8 = 2;

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

/// El input de un bloque. Ver el doc del módulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInput {
    /// Las reglas con las que se valida y ejecuta el bloque. El header no las
    /// compromete; el guest exige que el header tenga los campos de este fork
    /// y el fork viaja en el journal.
    pub fork: Spec,
    /// La cadena. Tampoco la compromete el header; viaja en el journal.
    pub chain_id: u64,
    /// El bloque **tal como viaja**: `rlp([header, txs, ommers, withdrawals])`.
    /// Es el objeto que mide EIP-7934.
    pub block: Bytes,
    /// Nodos de trie, códigos y la cadena de headers, **del padre hacia
    /// atrás**: `headers[0]` es el padre, y es obligatorio. `keys` va vacío y
    /// no viaja.
    pub witness: ExecutionWitness,
}

/// El input de `Mode::StateTest`. Ver el doc del módulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    /// Nodos de trie y códigos. Sin headers (un `state_test` no tiene cadena) y
    /// sin `keys`.
    pub witness: ExecutionWitness,
    /// **Declarado, no anclado**: es lo que hace que este modo no afirme nada
    /// sobre un bloque.
    pub pre_state_root: B256,
    pub env: BlockEnv,
    /// **Con su firma y sin su sender.**
    pub txs: Vec<SignedTransaction>,
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
    let (body, rest) = buf
        .split_at_checked(header.payload_length)
        .ok_or(CodecError("una lista declara más bytes de los que hay"))?;
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

/// Una lista de cadenas de bytes.
fn encode_bytes_list(items: &[Bytes], out: &mut Vec<u8>) {
    let mut inner = Vec::new();
    for item in items {
        item.encode(&mut inner);
    }
    list_of(&inner, out);
}

fn decode_bytes_list(buf: &mut &[u8]) -> R<Vec<Bytes>> {
    let mut items = open_list(buf)?;
    decode_all(&mut items, |b| Ok(Bytes::decode(b)?))
}

/// La versión, primera en el cuerpo: lo que viene detrás se lee según ella.
fn expect_version(buf: &mut &[u8]) -> R<()> {
    if u8::decode(buf)? != INPUT_VERSION {
        return Err(CodecError("versión de input desconocida"));
    }
    Ok(())
}

/// Abre el input entero: una lista que ocupa todo el buffer.
fn open_input(raw: &[u8]) -> R<&[u8]> {
    let mut cursor = raw;
    let body = open_list(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(CodecError("hay bytes después del input"));
    }
    Ok(body)
}

// ---------------------------------------------------------------------------
// El input de un bloque.
// ---------------------------------------------------------------------------

/// `rlp([version, fork, chain_id, block, [state, codes, headers]])`.
///
/// Vive acá y no en el host **a propósito**: que las dos mitades estén una al
/// lado de la otra no las vuelve una sola implementación —el decoder tiene que
/// poder correr sin el encoder— pero sí hace que un cambio de formato que toque
/// una y no la otra sea visible al leer.
#[must_use]
pub fn encode_block_input(input: &BlockInput) -> Vec<u8> {
    let mut body = Vec::new();
    INPUT_VERSION.encode(&mut body);
    fork_id(input.fork).encode(&mut body);
    input.chain_id.encode(&mut body);
    input.block.encode(&mut body);
    let mut w = Vec::new();
    encode_bytes_list(&input.witness.state, &mut w);
    encode_bytes_list(&input.witness.codes, &mut w);
    encode_bytes_list(&input.witness.headers, &mut w);
    list_of(&w, &mut body);
    let mut out = Vec::new();
    list_of(&body, &mut out);
    out
}

/// # Errors
/// `CodecError` ante cualquier byte que no encaje. **Nunca** devuelve un input
/// a medio armar. El bloque viaja como bytes y se decodifica después, contra
/// el header: este decoder solo corta el sobre.
pub fn decode_block_input(raw: &[u8]) -> R<BlockInput> {
    let mut body = open_input(raw)?;
    expect_version(&mut body)?;
    let fork = fork_from_id(u8::decode(&mut body)?).ok_or(CodecError("fork desconocido"))?;
    let chain_id = u64::decode(&mut body)?;
    let block = Bytes::decode(&mut body)?;
    let mut w = open_list(&mut body)?;
    let witness = ExecutionWitness {
        state: decode_bytes_list(&mut w)?,
        codes: decode_bytes_list(&mut w)?,
        keys: Vec::new(),
        headers: decode_bytes_list(&mut w)?,
    };
    if !w.is_empty() {
        return Err(CodecError("el witness trae más de tres listas"));
    }
    if !body.is_empty() {
        return Err(CodecError("el input trae campos de más"));
    }
    Ok(BlockInput {
        fork,
        chain_id,
        block,
        witness,
    })
}

// ---------------------------------------------------------------------------
// El input de txs sueltas.
// ---------------------------------------------------------------------------

/// `rlp([version, [state, codes], pre_state_root, env, txs])`.
///
/// # Errors
/// Si alguna tx no es representable como envelope de consenso (una tipada sin
/// `chainId`). **Es un rechazo y no un envelope a medio armar.**
pub fn encode_tx_input(input: &TxInput) -> R<Vec<u8>> {
    let mut body = Vec::new();
    INPUT_VERSION.encode(&mut body);
    let mut w = Vec::new();
    encode_bytes_list(&input.witness.state, &mut w);
    encode_bytes_list(&input.witness.codes, &mut w);
    list_of(&w, &mut body);
    input.pre_state_root.encode(&mut body);
    encode_env(&input.env, &mut body);
    let mut txs = Vec::new();
    for tx in &input.txs {
        let envelope = tx.encode_2718().map_err(|e| CodecError(e.0))?;
        Bytes::from(envelope).encode(&mut txs);
    }
    list_of(&txs, &mut body);
    let mut out = Vec::new();
    list_of(&body, &mut out);
    Ok(out)
}

/// # Errors
/// `CodecError` ante cualquier byte que no encaje.
pub fn decode_tx_input(raw: &[u8]) -> R<TxInput> {
    let mut body = open_input(raw)?;
    expect_version(&mut body)?;
    let mut w = open_list(&mut body)?;
    let witness = ExecutionWitness {
        state: decode_bytes_list(&mut w)?,
        codes: decode_bytes_list(&mut w)?,
        keys: Vec::new(),
        headers: Vec::new(),
    };
    if !w.is_empty() {
        return Err(CodecError("el witness trae más de dos listas"));
    }
    let pre_state_root = B256::decode(&mut body)?;
    let env = decode_env(&mut body)?;
    let mut txs_body = open_list(&mut body)?;
    let txs = decode_all(&mut txs_body, decode_tx)?;
    if !body.is_empty() {
        return Err(CodecError("el input trae campos de más"));
    }
    Ok(TxInput {
        witness,
        pre_state_root,
        env,
        txs,
    })
}

// ---------------------------------------------------------------------------
// Piezas.
// ---------------------------------------------------------------------------

fn encode_env(env: &BlockEnv, out: &mut Vec<u8>) {
    let mut inner = Vec::new();
    fork_id(env.spec).encode(&mut inner);
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
        spec: fork_from_id(u8::decode(&mut b)?).ok_or(CodecError("fork desconocido"))?,
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

/// Una tx del input: su **envelope canónico** como cadena de bytes.
///
/// El decoder del envelope vive en `signature.rs` y no acá porque es el mismo
/// que produce el hash de firma: separarlos permitiría que el guest leyera un
/// envelope y firmara otro.
fn decode_tx(buf: &mut &[u8]) -> R<SignedTransaction> {
    let raw = Bytes::decode(buf)?;
    crate::signature::decode_2718(&raw).map_err(|e| CodecError(e.0))
}
