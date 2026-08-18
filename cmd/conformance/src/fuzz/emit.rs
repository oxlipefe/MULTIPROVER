//! El **trinquete**: una divergencia minimizada se serializa al MISMO formato
//! de `fixtures/diff/` y entra al set para siempre.
//!
//! El corpus es el activo: cada bug encontrado una vez
//! pasa a ser defensa permanente. Pero un trinquete solo vale si el fixture que
//! escribe **sirve**:
//!
//! > Un fixture emitido que no parsea, o que al re-correrse no diverge, es un
//! > trinquete mentiroso.
//!
//! Las dos mitades de esa frase se testean por separado, y a propósito: que
//! parsee no necesita al oráculo y se verifica acá; que re-diverja sí lo
//! necesita y lo verifica la campaña (`fuzz::campaign`), que es la única que
//! puede.
//!
//! `post.hash` y `post.logs` van en cero — el juez del diferencial es revm
//! in-process, no el fixture. Calcularlos con nuestro propio motor sería
//! testear el código contra sí mismo (`fixtures/diff/README.md`).

use std::path::{Path, PathBuf};

use repo_b_common::primitives::{Address, U256};
use serde_json::{Map, Value, json};

use crate::fuzz::generate::{FuzzCase, fork_name};

/// Serializa el caso al JSON de `fixtures/diff/`.
pub fn to_fixture_json(case: &FuzzCase, name: &str, comment: &str) -> Value {
    let mut pre = Map::new();
    let test = case.to_state_test();
    for (address, account) in &test.pre {
        let mut storage = Map::new();
        for (key, value) in &account.storage {
            storage.insert(hex_u256(*key), json!(hex_u256(*value)));
        }
        pre.insert(
            hex_address(*address),
            json!({
                "nonce": hex_u64(account.nonce),
                "balance": hex_u256(account.balance),
                "code": format!("0x{}", hex(&account.code)),
                "storage": Value::Object(storage),
            }),
        );
    }

    let mut block_hashes = Map::new();
    for (number, hash) in &test.env.block_hashes {
        block_hashes.insert(
            hex_u64(*number),
            json!(format!("0x{}", hex(hash.as_slice()))),
        );
    }

    let body = json!({
        "_comment": comment,
        "env": {
            "currentCoinbase": hex_address(test.env.coinbase),
            "currentNumber": hex_u64(test.env.number),
            "currentTimestamp": hex_u64(test.env.timestamp),
            "currentGasLimit": hex_u64(test.env.gas_limit),
            "currentBaseFee": hex_u64(test.env.base_fee.unwrap_or_default()),
            "currentRandom": format!("0x{}", hex(test.env.prevrandao.unwrap_or_default().as_slice())),
            "currentExcessBlobGas": hex_u64(test.env.excess_blob_gas.unwrap_or_default()),
            // Extensión propia de `fixtures/diff/`, no campo EF: sin ella el
            // fixture emitido le daría a los dos motores información
            // DISTINTA sobre los ancestros y "el minimizado no reproduce"
            // sería culpa del emisor.
            "blockHashes": Value::Object(block_hashes),
        },
        "config": { "chainid": hex_u64(test.chain_id) },
        "pre": Value::Object(pre),
        "transaction": {
            "sender": hex_address(test.tx.sender),
            // `to: ""` es el convenio del formato EF para una tx de creación.
            "to": test.tx.to.map_or_else(String::new, hex_address),
            "nonce": hex_u64(test.tx.nonce),
            "gasPrice": hex_u128(test.tx.gas_price.unwrap_or_default()),
            "data": [format!("0x{}", hex(&case.calldata))],
            "gasLimit": [hex_u64(case.gas_limit)],
            "value": [hex_u256(case.value)],
        },
        "post": {
            fork_name(case.spec): [{
                "indexes": { "data": 0, "gas": 0, "value": 0 },
                "hash": ZERO_HASH,
                "logs": ZERO_HASH,
            }],
        },
    });

    let mut root = Map::new();
    root.insert(name.to_owned(), body);
    Value::Object(root)
}

const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// Escribe el fixture a `dir/<name>.json`. Devuelve el path escrito.
pub fn write_fixture(
    dir: &Path,
    name: &str,
    case: &FuzzCase,
    comment: &str,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("no se pudo crear {}: {e}", dir.display()))?;
    let path = dir.join(format!("{name}.json"));
    let json = to_fixture_json(case, name, comment);
    let text = serde_json::to_string_pretty(&json)
        .map_err(|e| format!("no se pudo serializar el fixture: {e}"))?;
    std::fs::write(&path, format!("{text}\n"))
        .map_err(|e| format!("no se pudo escribir {}: {e}", path.display()))?;
    Ok(path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_address(address: Address) -> String {
    format!("0x{}", hex(address.as_slice()))
}

// Los escalares se emiten con el ancho que tengan (`0x0`, `0xa`, `0x1c9c380`):
// el parser los lee con `from_str_radix`, que no exige ancho par ni padding.
// Emitir un ancho fijo obligaría a elegir uno, y elegirlo mal es un fixture
// que no parsea.
fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn hex_u128(value: u128) -> String {
    format!("0x{value:x}")
}

fn hex_u256(value: U256) -> String {
    format!("0x{value:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::parse_file;
    use crate::fuzz::generate::generate_case;

    /// La mitad del trinquete que no necesita oráculo: lo emitido **parsea**, y
    /// parsea al MISMO caso. Un emisor que escribe algo que el runner no lee
    /// es un corpus que no existe.
    #[test]
    fn an_emitted_fixture_parses_back_into_the_same_case() {
        for index in 0..24 {
            let case = generate_case(0xFACE, index);
            let json = to_fixture_json(&case, "regresion", "caso de prueba");
            let text = match serde_json::to_string(&json) {
                Ok(text) => text,
                Err(e) => panic!("no serializa: {e}"),
            };
            let parsed = match parse_file(&text) {
                Ok(tests) => tests,
                Err(e) => panic!("el fixture emitido no parsea: {e}"),
            };
            let Some(test) = parsed.first() else {
                panic!("el fixture emitido no trae ningún test");
            };
            let original = case.to_state_test();
            assert_eq!(test.pre, original.pre);
            assert_eq!(test.chain_id, original.chain_id);
            assert_eq!(test.env.base_fee, original.env.base_fee);
            assert_eq!(test.env.prevrandao, original.env.prevrandao);
            assert_eq!(test.env.block_hashes, original.env.block_hashes);
            assert_eq!(test.posts.len(), 1);
            let Some(post) = test.posts.first() else {
                panic!("sin post");
            };
            assert_eq!(post.fork, case.post_case().fork);
            // Lo que de verdad importa: la tx que sale del fixture es la misma
            // tx que el generador tenía en memoria.
            let from_fixture = test.transaction_for(post);
            let from_memory = original.transaction_for(&case.post_case());
            assert_eq!(from_fixture, from_memory);
        }
    }

    /// Una tx de creación se serializa con `to: ""` — el convenio del formato,
    /// no `null` ni la dirección cero (que sería una cuenta real).
    #[test]
    fn a_creation_tx_serializes_with_an_empty_to() {
        let mut case = generate_case(1, 1);
        case.to = None;
        let json = to_fixture_json(&case, "creacion", "");
        let to = json
            .get("creacion")
            .and_then(|body| body.get("transaction"))
            .and_then(|tx| tx.get("to"))
            .and_then(Value::as_str);
        assert_eq!(to, Some(""));
        let text = serde_json::to_string(&json).unwrap_or_default();
        let parsed = parse_file(&text).unwrap_or_default();
        assert_eq!(parsed.first().map(|t| t.tx.to), Some(None));
    }

    /// El juez es revm, no el fixture: los hashes esperados van en cero y eso
    /// es una decisión, no un olvido.
    #[test]
    fn the_expected_hashes_are_zero_because_the_judge_is_revm() {
        let json = to_fixture_json(&generate_case(2, 2), "caso", "");
        let hash = json
            .get("caso")
            .and_then(|body| body.get("post"))
            .and_then(|post| post.as_object())
            .and_then(|forks| forks.values().next())
            .and_then(Value::as_array)
            .and_then(|cases| cases.first())
            .and_then(|case| case.get("hash"))
            .and_then(Value::as_str);
        assert_eq!(hash, Some(ZERO_HASH));
    }

    /// El fixture llega al disco y vuelve. Es el camino real del trinquete.
    #[test]
    fn a_written_fixture_round_trips_through_the_filesystem() {
        let dir = std::env::temp_dir().join(format!("repo-b-fuzz-emit-{}", std::process::id()));
        let case = generate_case(3, 3);
        let path = match write_fixture(&dir, "regresion", &case, "comentario") {
            Ok(path) => path,
            Err(e) => panic!("no se pudo escribir: {e}"),
        };
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(parse_file(&text).is_ok(), "no parsea desde disco");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
