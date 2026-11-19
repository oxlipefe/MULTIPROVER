//! Escribe bloques del corpus **en la forma en que los entrega un nodo**: el
//! bloque como `debug_getRawBlock` y el witness como `debug_executionWitness`.
//!
//! Es el otro lado del importador: con estos pares se prueba
//! ida y vuelta —archivos ⇒ input ⇒ guest— sin un nodo real. El journal que se
//! escribe al lado lo computó el driver **con el estado completo**, no por el
//! camino que recorre el importador.
//!
//! **No-op salvo que `REPO_B_RPC_EXPORT_DIR` esté puesto**, que es el default
//! de toda corrida del gate:
//!
//! ```sh
//! REPO_B_RPC_EXPORT_DIR=cmd/conformance/fixtures/import \
//!   cargo run --release -p conformance -- --witness-blocks
//! ```
//!
//! Los casos se eligen por etiqueta (ver [`CASES`]); una etiqueta que el corpus
//! ya no trae hace fallar la corrida en vez de exportar otro bloque.

use std::path::PathBuf;
use std::sync::Mutex;

use repo_b_common::primitives::Bytes;
use repo_b_common::witness::ExecutionWitness;
use repo_b_guest::journal::Journal;
use serde_json::Value;

/// Los casos exportados: un directorio por clase de bloque, todos de Osaka.
pub const CASES: [(&str, &str); 6] = [
    (
        "transfer",
        "tests/shanghai/eip4895_withdrawals/test_withdrawals.py::TestUseValueInTx::test_use_value_in_tx[fork_Osaka-blockchain_test-tx_after_withdrawals_block] #2",
    ),
    (
        "create",
        "tests/shanghai/eip4895_withdrawals/test_withdrawals.py::test_newly_created_contract[fork_Osaka-blockchain_test-with_tx_value] #1",
    ),
    (
        "blobs",
        "tests/cancun/eip4844_blobs/test_blob_txs.py::test_valid_blob_tx_combinations[fork_Osaka-blobs_per_tx_(1,1)-blockchain_test-block_base_fee_per_gas_7] #1",
    ),
    (
        "withdrawals",
        "tests/shanghai/eip4895_withdrawals/test_withdrawals.py::test_many_withdrawals[fork_Osaka-blockchain_test] #1",
    ),
    (
        "requests",
        "tests/prague/eip7685_general_purpose_el_requests/test_multi_type_requests.py::test_valid_multi_type_requests[fork_Osaka-consolidation+deposit+withdrawal_from_same_tx-blockchain_test] #1",
    ),
    (
        "blockhash",
        "tests/frontier/scenarios/test_scenarios.py::test_scenarios[fork_Osaka-blockchain_test-test_program_program_BLOCKHASH-debug] #5",
    ),
];

/// Los archivos de cada caso.
pub const BLOCK_FILE: &str = "block.json";
pub const WITNESS_FILE: &str = "witness.json";
pub const JOURNAL_FILE: &str = "journal.txt";

fn export_dir() -> Option<PathBuf> {
    std::env::var_os("REPO_B_RPC_EXPORT_DIR").map(PathBuf::from)
}

static WRITTEN: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

/// Escribe el caso si el modo está prendido y la etiqueta es una de [`CASES`].
/// Un error de escritura deja el caso sin marcar, y [`report`] lo dice.
pub fn offer(label: &str, block: &[u8], witness: &ExecutionWitness, journal: &Journal) {
    let Some(root) = export_dir() else { return };
    let Some((name, _)) = CASES.iter().find(|(_, wanted)| *wanted == label) else {
        return;
    };
    let dir = root.join(name);
    let journal_text = super::dump::journal_lines(journal);
    let written = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::write(dir.join(BLOCK_FILE), block_to_rpc_json(block)))
        .and_then(|()| std::fs::write(dir.join(WITNESS_FILE), witness_to_rpc_json(witness)))
        .and_then(|()| {
            std::fs::write(
                dir.join(JOURNAL_FILE),
                format!("case {label}\n{journal_text}"),
            )
        });
    match written {
        Ok(()) => {
            eprintln!(
                "[rpc-export] {name}: {} headers, {} nodos, {} códigos",
                witness.headers.len(),
                witness.state.len(),
                witness.codes.len()
            );
            if let Ok(mut done) = WRITTEN.lock() {
                done.push(name);
            }
        }
        Err(e) => eprintln!("[rpc-export] no se pudo escribir {}: {e}", dir.display()),
    }
}

/// Al final de la corrida: si el modo está prendido, ¿se escribieron todos?
#[must_use]
pub fn report() -> bool {
    if export_dir().is_none() {
        return true;
    }
    let done = WRITTEN.lock().map(|d| d.clone()).unwrap_or_default();
    let missing: Vec<&str> = CASES
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !done.contains(name))
        .collect();
    if missing.is_empty() {
        return true;
    }
    eprintln!("[rpc-export] FAIL: no se exportaron {missing:?}");
    false
}

/// El witness en la forma del RPC: el objeto de cuatro listas, con los
/// headers **del más viejo al padre**. Es el inverso del importador.
///
/// **Depende del formato real:** el orden "del más viejo al padre" es el que
/// se asume para reth; el importador no depende de él, pero estos archivos
/// lo imitan para que el camino que reordena se ejercite.
#[must_use]
pub fn witness_to_rpc_json(witness: &ExecutionWitness) -> String {
    let list = |items: &mut dyn Iterator<Item = &Bytes>| -> Value {
        Value::Array(items.map(|b| Value::String(b.to_string())).collect())
    };
    let mut object = serde_json::Map::new();
    object.insert("state".to_owned(), list(&mut witness.state.iter()));
    object.insert("codes".to_owned(), list(&mut witness.codes.iter()));
    object.insert("keys".to_owned(), list(&mut witness.keys.iter()));
    object.insert(
        "headers".to_owned(),
        list(&mut witness.headers.iter().rev()),
    );
    Value::Object(object).to_string()
}

/// El bloque en la forma del RPC: un string JSON `"0x…"`.
#[must_use]
pub fn block_to_rpc_json(block: &[u8]) -> String {
    Value::String(Bytes::copy_from_slice(block).to_string()).to_string()
}
