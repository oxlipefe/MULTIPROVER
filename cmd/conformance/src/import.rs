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
//! - **El hash del bloque**, dado por quien importa y no por los archivos.
//!
//! Cada archivo puede ser también la respuesta JSON-RPC entera, con
//! exactamente `jsonrpc` (`"2.0"`), `id` y un `result` no nulo: se toma su
//! `result`. Una respuesta con `error`, o con otra clave, es un rechazo.
//!
//! # Qué garantiza
//!
//! **La identidad del bloque la nombra el operador**: el header recalculado
//! (`keccak(rlp(header))`) tiene que ser el hash pedido. Sin ese ancla, una
//! cadena y un estado fabricados pero coherentes entre sí pasarían por el
//! bloque que dicen ser. Con ella, lo que se importa es el bloque que el
//! operador nombró, y el estado previo es el que ese hash compromete: el
//! header fija `parent_hash`, el padre (que tiene que hashear a eso) fija el
//! `stateRoot`, y cada nodo del witness tiene que hashear a lo que lo
//! referencia. **No garantiza** que el hash nombrado sea canónico en mainnet:
//! eso es lo que el operador afirma al darlo.
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
//!
//! **La salida es todo o nada**: el destino se borra al empezar y el input se
//! escribe a un temporal del mismo directorio que se renombra al final. Un
//! rechazo no deja archivo, ni el de una corrida anterior.

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

/// Tope de cada archivo. Acota la memoria, no solo la lectura: el JSON se
/// guarda como árbol (los strings hex) y además decodificado (la mitad), así
/// que el pico ronda dos a tres veces el archivo.
///
/// **Es una estimación, no una medición**: el peso de un witness real de
/// mainnet no se midió todavía. La cuenta: en hex cada byte pesa dos, y un
/// bloque de 60 M de gas con la actividad de los de hoy toca del orden de
/// decenas de miles de nodos y unos cientos de contratos, lo que da unos pocos
/// MB de witness; 64 MiB deja un orden de magnitud de holgura. El peor caso
/// adversarial no entra y no tiene por qué: un `EXTCODESIZE` frío cuesta 2 600
/// de gas y obliga a traer hasta 24 576 bytes de código, ~9,5 bytes por gas, así
/// que 60 M de gas pueden pedir ~570 MB de código. Ese bloque se rechaza acá
/// (fail-closed); el tope se revisa con el primer witness real.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Las claves de una respuesta JSON-RPC exitosa: ninguna más.
const RPC_FIELDS: [&str; 3] = ["jsonrpc", "id", "result"];

/// La bandera del hash que nombra el operador.
const EXPECT_FLAG: &str = "--expect-block-hash";

const USAGE: &str = "uso: --import-block <bloque.json> <witness.json> <salida.bin> \
                     --expect-block-hash 0x<32 bytes>";

/// Las cuatro listas del witness, en el orden en que se reportan.
const WITNESS_FIELDS: [&str; 4] = ["state", "codes", "keys", "headers"];

/// Por qué un par de archivos no es un input. Una variante por clase de input
/// hostil, para que un test pueda fijar cuál cayó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// Los argumentos del binario no tienen la forma de uso.
    Usage(&'static str),
    /// El header recalculado no es el bloque que nombró el operador.
    NotTheNamedBlock { named: B256, computed: B256 },
    /// No se pudo leer o escribir el archivo, o pasa el tope.
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
/// `named` es el hash que el operador dice que tiene el bloque: se compara
/// contra el recalculado antes que nada. `expected_of` es lo que el consumidor
/// sabe del bloque por su header; `None` es "este bloque no está en mi
/// calendario".
///
/// # Errors
/// La primera clase de input hostil que aparece, tipada.
pub fn import(
    block_file: &[u8],
    witness_file: &[u8],
    named: B256,
    expected_of: impl Fn(&Header) -> Option<ExpectedBlock>,
) -> Result<Imported, ImportError> {
    let block = hex_bytes(&rpc_result(block_file, "bloque")?, "bloque")?;
    let header = repo_b_guest::block::decode_block(&block)
        .map_err(ImportError::Block)?
        .header;
    let computed = header.hash();
    if computed != named {
        return Err(ImportError::NotTheNamedBlock { named, computed });
    }
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
///
/// Con `jsonrpc` presente la respuesta es estricta: `jsonrpc` igual a `"2.0"`,
/// `id`, un `result` no nulo, y ninguna otra clave. Una clave de más puede ser
/// un `error` mezclado con un `result`, y elegir uno sería adivinar.
fn rpc_result(raw: &[u8], file: &'static str) -> Result<Value, ImportError> {
    let json = |detail: String| ImportError::Json { file, detail };
    let value: Value = serde_json::from_slice(raw).map_err(|e| json(e.to_string()))?;
    let mut object = match value {
        Value::Object(object) if object.contains_key("jsonrpc") => object,
        other => return Ok(other),
    };
    if let Some(error) = object.get("error") {
        return Err(json(format!("la respuesta es un error: {error}")));
    }
    if let Some(extra) = object.keys().find(|k| !RPC_FIELDS.contains(&k.as_str())) {
        return Err(json(format!("clave desconocida `{extra}` en la respuesta")));
    }
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(json("`jsonrpc` no es \"2.0\"".to_owned()));
    }
    if !object.contains_key("id") {
        return Err(json("la respuesta no trae `id`".to_owned()));
    }
    match object.remove("result") {
        Some(result) if !result.is_null() => Ok(result),
        _ => Err(json("la respuesta no trae `result`".to_owned())),
    }
}

/// El hash que nombra el operador: `0x` y 64 dígitos hex, con el mismo
/// criterio que los archivos.
pub fn parse_block_hash(text: &str) -> Result<B256, ImportError> {
    let bytes = hex_bytes(&Value::String(text.to_owned()), EXPECT_FLAG)?;
    B256::try_from(bytes.as_slice()).map_err(|_| ImportError::Hex {
        field: EXPECT_FLAG.to_owned(),
        detail: format!("tiene {} bytes y no 32", bytes.len()),
    })
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

/// `--import-block <bloque.json> <witness.json> <salida.bin>
/// --expect-block-hash 0x…`: un bloque de **mainnet**, el que nombra el hash.
/// El fork y la cadena los fija [`ExpectedBlock::mainnet`].
///
/// El destino se borra antes de validar nada: un fallo, aun de uso, no deja
/// el archivo de una corrida anterior.
///
/// # Errors
/// Uso, lectura, importación o escritura, tipados.
pub fn run_cli(args: &[String]) -> Result<Imported, ImportError> {
    let [block_path, witness_path, out_path, rest @ ..] = args else {
        return Err(ImportError::Usage(USAGE));
    };
    let out = Path::new(out_path);
    remove_if_present(out)?;
    let [flag, hash] = rest else {
        return Err(ImportError::Usage(USAGE));
    };
    if flag != EXPECT_FLAG {
        return Err(ImportError::Usage(USAGE));
    }
    let named = parse_block_hash(hash)?;
    let block = read_capped(Path::new(block_path), MAX_FILE_BYTES)?;
    let witness = read_capped(Path::new(witness_path), MAX_FILE_BYTES)?;
    let imported = import(&block, &witness, named, ExpectedBlock::mainnet)?;
    write_atomic(out, &imported.bytes)?;
    Ok(imported)
}

fn io_error(path: &Path, error: &std::io::Error) -> ImportError {
    ImportError::File {
        file: path.display().to_string(),
        detail: error.to_string(),
    }
}

fn remove_if_present(path: &Path) -> Result<(), ImportError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io_error(path, &e)),
        _ => Ok(()),
    }
}

/// Escribe a un temporal en el mismo directorio y lo renombra: el destino
/// aparece entero o no aparece. Ante error, el temporal se borra.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ImportError> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".partial-{}", std::process::id()));
    let partial = path.with_file_name(name);
    let written = std::fs::File::create(&partial).and_then(|mut file| {
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        std::fs::rename(&partial, path)
    });
    written.map_err(|e| {
        // Si el borrado también falla no hay a quién avisar mejor: el error
        // que se devuelve es el de la escritura.
        let _ = std::fs::remove_file(&partial);
        io_error(path, &e)
    })
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
