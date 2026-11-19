//! **Importador de un bloque real**: el bloque y su `debug_executionWitness`,
//! como archivos, al input que consume el guest.
//!
//! Es una herramienta de host. No abre conexiones: bajar los dos archivos de un
//! nodo es un `curl` aparte, y lo que entra acá es lo que quedó en disco.
//!
//! # Entrada
//!
//! - **El bloque**: el `result` de `debug_getRawBlock`, un string JSON
//!   `"0x…"` con `rlp([header, txs, ommers, withdrawals])`.
//! - **El witness**: el `result` de `debug_executionWitness`, un objeto JSON
//!   con cuatro listas de strings `"0x…"`: `state`, `codes`, `keys`,
//!   `headers`, con los headers en RLP. **Depende del formato real**: es la
//!   forma que se asume para reth y ethrex; otra forma es un rechazo.
//!
//! Cada archivo puede ser también la respuesta JSON-RPC entera
//! (`{"jsonrpc", "id", "result"}`): se toma su `result`, y una respuesta con
//! `error` es un rechazo.
//!
//! # Qué se decide acá y qué no
//!
//! **Ni el fork ni la cadena los declara quien importa**: salen de lo que el
//! consumidor espera del header (`expected_of`; en mainnet,
//! [`ExpectedBlock::mainnet`], que resuelve el fork por timestamp). Un bloque
//! fuera de ese calendario no se importa.
//!
//! **Todo el archivo es hostil.** Lo que se puede validar sin ejecutar se valida
//! acá con su propio error (forma del JSON, hex, la cadena de headers, el nodo
//! raíz del estado previo). Lo que solo se sabe ejecutando —un nodo que no
//! hashea a lo que su padre referencia, un código que falta, un bloque
//! inválido— lo decide el guest mismo: el importador corre el input por
//! [`run_block_input`] antes de entregarlo, y su journal tiene que pasar la
//! política del consumidor. Un input que el guest rechazaría no sale de acá.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use repo_b_common::primitives::{B256, Bytes, keccak256};
use repo_b_common::witness::ExecutionWitness;
use repo_b_guest::codec::{BlockInput, decode_block_input, encode_block_input};
use repo_b_guest::journal::{Journal, Mode};
use repo_b_guest::{BlockError, GuestError, Header, run_block_input};
use repo_b_prover::{ExpectedBlock, Refusal, require_full_block};
use serde_json::Value;

/// Tope de cada archivo: acota lo que un archivo hostil puede hacer leer. El
/// peso de un witness real de mainnet no está medido todavía; el tope se elige
/// holgado y se revisa con el primero.
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Las cuatro listas del witness, en el orden en que se reportan.
const WITNESS_FIELDS: [&str; 4] = ["state", "codes", "keys", "headers"];

/// Por qué un par de archivos no es un input. Una variante por clase de input
/// hostil, para que un test pueda fijar cuál cayó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// No se pudo leer el archivo o pasa el tope.
    File { file: String, detail: String },
    /// No es JSON, no tiene la forma esperada, o es una respuesta de error.
    Json { file: &'static str, detail: String },
    /// Un string que tenía que ser `0x` + hex par no lo es.
    Hex { field: String, detail: String },
    /// El bloque no decodifica.
    Block(BlockError),
    /// El calendario del consumidor no asigna fork a este bloque (anterior al
    /// Merge, o posterior al horizonte revisado de la tabla).
    OutsideSchedule { number: u64, timestamp: u64 },
    /// Un header del witness no decodifica.
    Header { index: usize, error: BlockError },
    /// Ningún header del witness hashea al `parent_hash` del bloque.
    MissingParent(B256),
    /// Un header que no está en la cadena que baja desde el padre: suelto,
    /// repetido o del otro lado de un hueco.
    Unchained { index: usize, hash: B256 },
    /// El nodo raíz del estado previo (`stateRoot` del padre) no viene.
    MissingStateRoot(B256),
    /// El input no sobrevive su propio codec. Es un bug, no un input hostil.
    Codec(&'static str),
    /// El guest rechaza el input: lo que solo se sabe ejecutando.
    Rejected(GuestError),
    /// El guest lo acepta y el journal no es la prueba del bloque esperado.
    Policy(Refusal),
}

impl core::fmt::Display for ImportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Lo que sale: el input, sus bytes y el journal que el guest publicó al
/// correrlo en el host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub input: BlockInput,
    pub bytes: Vec<u8>,
    pub journal: Journal,
    pub expected: ExpectedBlock,
}

/// Lee un archivo con tope. Pasarse del tope es un error, no un truncado.
pub fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, ImportError> {
    let file_error = |detail: String| ImportError::File {
        file: path.display().to_string(),
        detail,
    };
    let file = std::fs::File::open(path).map_err(|e| file_error(e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| file_error(e.to_string()))?;
    if !u64::try_from(bytes.len()).is_ok_and(|len| len <= cap) {
        return Err(file_error(format!("pasa el tope de {cap} bytes")));
    }
    Ok(bytes)
}

/// El par de archivos, al input del guest. Ver el doc del módulo.
///
/// `expected_of` es lo que el consumidor sabe del bloque por su header; `None`
/// es "este bloque no está en mi calendario".
///
/// # Errors
/// La primera clase de input hostil que aparece, tipada.
pub fn import(
    block_file: &[u8],
    witness_file: &[u8],
    expected_of: impl Fn(&Header) -> Option<ExpectedBlock>,
) -> Result<Imported, ImportError> {
    let block = hex_bytes(&rpc_result(block_file, "bloque")?, "bloque")?;
    let header = repo_b_guest::block::decode_block(&block)
        .map_err(ImportError::Block)?
        .header;
    let expected = expected_of(&header).ok_or(ImportError::OutsideSchedule {
        number: header.number,
        timestamp: header.timestamp,
    })?;
    let rpc = parse_witness(rpc_result(witness_file, "witness")?)?;
    let headers = chain_from_parent(&rpc.headers, header.parent_hash)?;
    require_state_root(&headers, &rpc.state)?;

    let input = BlockInput {
        fork: expected.fork,
        chain_id: expected.chain_id,
        block: block.into(),
        // `keys` no viaja: el guest camina el trie por `keccak(clave)` y no
        // consulta preimágenes.
        witness: ExecutionWitness {
            state: rpc.state,
            codes: rpc.codes,
            keys: Vec::new(),
            headers,
        },
    };
    let bytes = encode_block_input(&input);
    if decode_block_input(&bytes).as_ref() != Ok(&input) {
        return Err(ImportError::Codec("el input no sobrevive su codec"));
    }
    let journal = run_block_input(Mode::Full, &input).map_err(ImportError::Rejected)?;
    require_full_block(&journal.encode(), &expected).map_err(ImportError::Policy)?;
    Ok(Imported {
        input,
        bytes,
        journal,
        expected,
    })
}

/// El `result` de una respuesta JSON-RPC, o el archivo entero si no lo es.
fn rpc_result(raw: &[u8], file: &'static str) -> Result<Value, ImportError> {
    let json = |detail: String| ImportError::Json { file, detail };
    let value: Value = serde_json::from_slice(raw).map_err(|e| json(e.to_string()))?;
    let Some(object) = value.as_object().filter(|o| o.contains_key("jsonrpc")) else {
        return Ok(value);
    };
    if let Some(error) = object.get("error") {
        return Err(json(format!("la respuesta es un error: {error}")));
    }
    object
        .get("result")
        .filter(|r| !r.is_null())
        .cloned()
        .ok_or_else(|| json("la respuesta no trae `result`".to_owned()))
}

/// `"0x…"` con un número par de dígitos hex. Sin el prefijo es un rechazo: el
/// RPC siempre lo pone, y aceptar las dos formas es aceptar un archivo que no
/// salió de un RPC.
fn hex_bytes(value: &Value, field: &str) -> Result<Vec<u8>, ImportError> {
    let hex = |detail: &str| ImportError::Hex {
        field: field.to_owned(),
        detail: detail.to_owned(),
    };
    let text = value.as_str().ok_or_else(|| hex("no es un string"))?;
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| hex("no empieza con 0x"))?;
    alloy_primitives::hex::decode(digits).map_err(|e| hex(&e.to_string()))
}

/// Las cuatro listas, tal como vinieron.
struct RpcWitness {
    state: Vec<Bytes>,
    codes: Vec<Bytes>,
    headers: Vec<Bytes>,
}

/// **Depende del formato real:** se asume un objeto con exactamente
/// `state`, `codes`, `keys` y `headers`, cada uno una lista de `"0x…"`, y los
/// headers en RLP. Un campo de más o de menos es un rechazo: un campo nuevo
/// puede cargar semántica que este importador no conoce.
fn parse_witness(value: Value) -> Result<RpcWitness, ImportError> {
    let json = |detail: String| ImportError::Json {
        file: "witness",
        detail,
    };
    let Value::Object(mut object) = value else {
        return Err(json("no es un objeto".to_owned()));
    };
    if let Some(extra) = object
        .keys()
        .find(|k| !WITNESS_FIELDS.contains(&k.as_str()))
    {
        return Err(json(format!("campo desconocido `{extra}`")));
    }
    let mut lists = Vec::with_capacity(WITNESS_FIELDS.len());
    for name in WITNESS_FIELDS {
        let Some(Value::Array(items)) = object.remove(name) else {
            return Err(json(format!("`{name}` falta o no es una lista")));
        };
        let mut list = Vec::with_capacity(items.len());
        for (i, item) in items.into_iter().enumerate() {
            list.push(Bytes::from(hex_bytes(&item, &format!("{name}[{i}]"))?));
        }
        lists.push(list);
    }
    let [state, codes, _keys, headers]: [Vec<Bytes>; 4] = lists
        .try_into()
        .map_err(|_| json("el witness no tiene cuatro listas".to_owned()))?;
    Ok(RpcWitness {
        state,
        codes,
        headers,
    })
}

/// Los headers del witness, **del padre hacia atrás**, que es el orden que
/// consume el guest.
///
/// **No depende del orden en que vengan**: se encadenan por hash desde el
/// `parent_hash` del bloque. Lo que no queda en esa cadena es un rechazo —un
/// header suelto, uno repetido o lo que queda del otro lado de un hueco—, y un
/// witness sin el padre también.
fn chain_from_parent(raw: &[Bytes], parent_hash: B256) -> Result<Vec<Bytes>, ImportError> {
    let mut by_hash: BTreeMap<B256, (usize, B256, &Bytes)> = BTreeMap::new();
    for (index, bytes) in raw.iter().enumerate() {
        let header =
            Header::decode_exact(bytes).map_err(|error| ImportError::Header { index, error })?;
        let hash = keccak256(bytes.as_ref());
        if by_hash
            .insert(hash, (index, header.parent_hash, bytes))
            .is_some()
        {
            return Err(ImportError::Unchained { index, hash });
        }
    }
    let mut chain = Vec::with_capacity(raw.len());
    let mut wanted = parent_hash;
    while let Some((_, grandparent, bytes)) = by_hash.remove(&wanted) {
        chain.push(bytes.clone());
        wanted = grandparent;
    }
    if chain.is_empty() {
        return Err(ImportError::MissingParent(parent_hash));
    }
    // El primero en el archivo, para que el error no dependa del orden de
    // los hashes.
    if let Some((hash, (index, _, _))) = by_hash.iter().min_by_key(|(_, (index, _, _))| *index) {
        return Err(ImportError::Unchained {
            index: *index,
            hash: *hash,
        });
    }
    Ok(chain)
}

/// **Depende del formato real:** se asume que el witness trae siempre el nodo
/// raíz del estado previo. Todo bloque post-Cancun lo necesita (la system call
/// de EIP-4788 escribe estado), así que su ausencia es un witness incompleto,
/// no uno mínimo.
fn require_state_root(headers: &[Bytes], state: &[Bytes]) -> Result<(), ImportError> {
    let parent = headers
        .first()
        .ok_or(ImportError::MissingParent(B256::ZERO))
        .and_then(|raw| {
            Header::decode_exact(raw).map_err(|error| ImportError::Header { index: 0, error })
        })?;
    let root = parent.state_root;
    if state.iter().any(|node| keccak256(node.as_ref()) == root) {
        return Ok(());
    }
    Err(ImportError::MissingStateRoot(root))
}

/// `--import-block <bloque.json> <witness.json> <salida.bin>`: un bloque de
/// **mainnet**. El fork y la cadena los fija [`ExpectedBlock::mainnet`].
pub fn run_cli(args: &[String]) -> Result<Imported, String> {
    let [block_path, witness_path, out_path] = args else {
        return Err("uso: --import-block <bloque.json> <witness.json> <salida.bin>".to_owned());
    };
    let block = read_capped(Path::new(block_path), MAX_FILE_BYTES).map_err(|e| e.to_string())?;
    let witness =
        read_capped(Path::new(witness_path), MAX_FILE_BYTES).map_err(|e| e.to_string())?;
    let imported = import(&block, &witness, ExpectedBlock::mainnet).map_err(|e| e.to_string())?;
    std::fs::write(out_path, &imported.bytes).map_err(|e| format!("{out_path}: {e}"))?;
    Ok(imported)
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
