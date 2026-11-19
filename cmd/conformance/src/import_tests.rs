//! El importador, contra bloques del corpus escritos en la forma del RPC
//! (`fixtures/import`, ver `blockchain::rpc_export`) y contra cada clase de
//! input hostil.
//!
//! Los bloques son de EEST, con su `chain_id` y su fork fijo: el calendario de
//! mainnet no los reconoce. Por eso el núcleo recibe lo esperado como
//! parámetro, y estos tests le pasan lo que dice el journal congelado; el
//! binario fija [`ExpectedBlock::mainnet`], que se prueba aparte sobre los
//! bordes de su calendario.

use super::*;
use crate::blockchain::rpc_export::{BLOCK_FILE, CASES, JOURNAL_FILE, WITNESS_FILE};
use repo_b_common::chainspec::{MAINNET_PARIS_BLOCK, MAINNET_SCHEDULE_REVIEWED_UNTIL};
use repo_b_common::spec::Spec;
use repo_b_guest::block::{decode_block, encode_block};
use repo_b_guest::journal::fork_from_id;

struct Case {
    block: Vec<u8>,
    witness: Vec<u8>,
    journal: Journal,
}

fn dir(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/import")
        .join(name)
}

fn read(name: &str, file: &str) -> Vec<u8> {
    match std::fs::read(dir(name).join(file)) {
        Ok(bytes) => bytes,
        Err(e) => panic!("{name}/{file}: {e}"),
    }
}

/// El journal que el driver computó con el estado completo.
fn frozen_journal(name: &str) -> Journal {
    let text = String::from_utf8_lossy(&read(name, JOURNAL_FILE)).into_owned();
    let value = |field: &str| -> String {
        let prefix = format!("{field} ");
        match text
            .lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .and_then(|r| r.split_whitespace().next())
        {
            Some(v) => v.to_owned(),
            None => panic!("{name}: el journal no declara `{field}`"),
        }
    };
    let hash = |field: &str| -> B256 {
        match value(field).parse() {
            Ok(h) => h,
            Err(e) => panic!("{name}: `{field}`: {e}"),
        }
    };
    let (Ok(chain_id), Ok(fork)) = (value("chain_id").parse(), value("fork").parse::<u8>()) else {
        panic!("{name}: chain_id y fork tienen que ser números");
    };
    Journal {
        mode: Mode::Full,
        chain_id,
        fork: fork_from_id(fork),
        block_hash: hash("block_hash"),
        parent_hash: hash("parent_hash"),
        pre_state_root: hash("pre_state_root"),
        post_state_root: hash("post_state_root"),
        output_digest: hash("output_digest"),
    }
}

fn case(name: &str) -> Case {
    Case {
        block: read(name, BLOCK_FILE),
        witness: read(name, WITNESS_FILE),
        journal: frozen_journal(name),
    }
}

/// Lo que un consumidor de la red de EEST espera: la cadena y el fork del
/// journal congelado, el hash y el padre del header.
fn eest(journal: &Journal) -> impl Fn(&Header) -> Option<ExpectedBlock> {
    let (chain_id, fork) = (journal.chain_id, journal.fork);
    move |header: &Header| {
        Some(ExpectedBlock {
            chain_id,
            fork: fork?,
            block_hash: header.hash(),
            parent_hash: Some(header.parent_hash),
        })
    }
}

fn import_case(c: &Case, witness: &[u8]) -> Result<Imported, ImportError> {
    import(&c.block, witness, eest(&c.journal))
}

/// El witness del caso como JSON, para alterarlo.
fn witness_json(c: &Case) -> Value {
    match serde_json::from_slice(&c.witness) {
        Ok(v) => v,
        Err(e) => panic!("el witness exportado tiene que ser JSON: {e}"),
    }
}

fn list(value: &mut Value, field: &str) -> Vec<Value> {
    match value.get_mut(field).map(Value::take) {
        Some(Value::Array(items)) => items,
        other => panic!("`{field}` tiene que ser una lista: {other:?}"),
    }
}

fn with_list(mut value: Value, field: &str, f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut items = list(&mut value, field);
    f(&mut items);
    value[field] = Value::Array(items);
    value.to_string().into_bytes()
}

fn bytes_of(item: &Value) -> Vec<u8> {
    match hex_bytes(item, "test") {
        Ok(b) => b,
        Err(e) => panic!("{e}"),
    }
}

fn hex_value(bytes: &[u8]) -> Value {
    Value::String(Bytes::copy_from_slice(bytes).to_string())
}

/// El texto de un rechazo del guest por un dato que el witness no trae.
#[track_caller]
fn missing(result: Result<Imported, ImportError>) -> String {
    match rejected(result) {
        ImportError::Rejected(GuestError::Vm { message, .. })
            if message.contains("el witness no alcanza") =>
        {
            message
        }
        other => panic!("se esperaba un rechazo del guest por falta de datos: {other:?}"),
    }
}

#[track_caller]
fn rejected(result: Result<Imported, ImportError>) -> ImportError {
    match result {
        Err(e) => e,
        Ok(imported) => panic!("se esperaba un rechazo y salió {:?}", imported.journal),
    }
}

/// **Ida y vuelta**: cada par de archivos importa a un input cuyo journal es
/// el que el driver computó con el estado completo. Y cada caso es de la
/// clase que su nombre promete.
#[test]
fn every_exported_case_imports_to_the_driver_journal() {
    for (name, label) in CASES {
        let c = case(name);
        let imported = match import_case(&c, &c.witness) {
            Ok(i) => i,
            Err(e) => panic!("{name}: {e}"),
        };
        assert_eq!(imported.journal, c.journal, "{name} ({label})");
        assert_eq!(imported.input.fork, Spec::Osaka, "{name}");
        assert!(
            imported.input.witness.keys.is_empty(),
            "{name}: keys no viaja"
        );
        let Ok(block) = decode_block(&imported.input.block) else {
            panic!("{name}: el bloque importado decodifica");
        };
        let txs = block.transactions.len();
        let withdrawals = block.withdrawals.as_ref().map_or(0, Vec::len);
        let blob_gas = block.header.blob_gas_used.unwrap_or(0);
        match name {
            "transfer" => assert!(txs > 0 && withdrawals == 0, "{name}"),
            "create" | "requests" => assert!(txs > 0, "{name}"),
            "blobs" => assert!(blob_gas > 0, "{name}"),
            "withdrawals" => assert!(withdrawals > 1, "{name}"),
            "blockhash" => assert!(imported.input.witness.headers.len() > 2, "{name}"),
            _ => panic!("caso sin clase: {name}"),
        }
    }
}

/// La creación lleva una tx sin destino (en RLP, el `to` vacío `0x80`), y el
/// de requests produce requests: el `requestsHash` no es el de la lista vacía.
#[test]
fn the_create_and_requests_cases_exercise_their_class() {
    let create = case("create");
    let Ok(imported) = import_case(&create, &create.witness) else {
        panic!("create importa");
    };
    let Ok(block) = decode_block(&imported.input.block) else {
        panic!("create decodifica");
    };
    let Some(tx) = block.transactions.first() else {
        panic!("create trae una tx");
    };
    let Ok(signed) = repo_b_guest::signature::decode_2718(tx) else {
        panic!("la tx decodifica");
    };
    let Ok(tx) = signed.recover(create.journal.chain_id) else {
        panic!("la firma recupera un sender");
    };
    assert!(tx.to.is_none(), "la tx de `create` crea un contrato");

    let requests = case("requests");
    let Ok(imported) = import_case(&requests, &requests.witness) else {
        panic!("requests importa");
    };
    let Ok(block) = decode_block(&imported.input.block) else {
        panic!("requests decodifica");
    };
    let Some(hash) = block.header.requests_hash else {
        panic!("un header de Osaka trae requestsHash");
    };
    assert_ne!(
        hash,
        repo_b_guest::block::requests::requests_hash(&[]),
        "requestsHash de un bloque sin requests"
    );
}

/// **El orden de los headers no importa**: del más viejo al padre (como lo
/// exporta el RPC), del padre hacia atrás, o rotados, el input es el mismo.
#[test]
fn headers_in_any_order_give_the_same_input() {
    let c = case("blockhash");
    let Ok(reference) = import_case(&c, &c.witness) else {
        panic!("el caso importa");
    };
    let reversed = with_list(witness_json(&c), "headers", |h| h.reverse());
    let rotated = with_list(witness_json(&c), "headers", |h| h.rotate_left(2));
    for witness in [reversed, rotated] {
        let Ok(imported) = import_case(&c, &witness) else {
            panic!("otro orden importa igual");
        };
        assert_eq!(imported.input, reference.input);
    }
}

/// La respuesta JSON-RPC entera es lo mismo que su `result`.
#[test]
fn a_full_rpc_response_is_its_result() {
    let c = case("transfer");
    let wrap = |raw: &[u8]| -> Vec<u8> {
        let Ok(result) = serde_json::from_slice::<Value>(raw) else {
            panic!("JSON");
        };
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result})
            .to_string()
            .into_bytes()
    };
    let Ok(plain) = import_case(&c, &c.witness) else {
        panic!("importa");
    };
    let Ok(wrapped) = import(&wrap(&c.block), &wrap(&c.witness), eest(&c.journal)) else {
        panic!("la respuesta entera importa");
    };
    assert_eq!(wrapped.bytes, plain.bytes);
}

#[test]
fn malformed_json_is_a_json_error() {
    let c = case("transfer");
    let cut = c.witness.get(..c.witness.len() / 2).unwrap_or_default();
    assert!(matches!(
        rejected(import_case(&c, cut)),
        ImportError::Json {
            file: "witness",
            ..
        }
    ));
    let block_cut = c.block.get(..c.block.len() / 2).unwrap_or_default();
    assert!(matches!(
        rejected(import(block_cut, &c.witness, eest(&c.journal))),
        ImportError::Json { file: "bloque", .. }
    ));
    let error = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"no"}}"#;
    assert!(matches!(
        rejected(import_case(&c, error)),
        ImportError::Json {
            file: "witness",
            ..
        }
    ));
}

#[test]
fn a_witness_with_a_field_more_or_less_is_a_json_error() {
    let c = case("transfer");
    let mut extra = witness_json(&c);
    extra["proofs"] = Value::Array(Vec::new());
    let mut missing = witness_json(&c);
    if let Some(object) = missing.as_object_mut() {
        object.remove("keys");
    }
    for witness in [extra, missing, Value::Array(Vec::new())] {
        assert!(matches!(
            rejected(import_case(&c, witness.to_string().as_bytes())),
            ImportError::Json {
                file: "witness",
                ..
            }
        ));
    }
}

#[test]
fn invalid_hex_is_a_hex_error() {
    let c = case("transfer");
    for bad in ["c0", "0xc", "0xzz", "0X00"] {
        let witness = with_list(witness_json(&c), "codes", |codes| {
            codes.push(Value::String(bad.to_owned()));
        });
        assert!(
            matches!(
                rejected(import_case(&c, &witness)),
                ImportError::Hex { ref field, .. } if field.starts_with("codes[")
            ),
            "{bad}"
        );
    }
    let number = br#"17"#;
    assert!(matches!(
        rejected(import(number, &c.witness, eest(&c.journal))),
        ImportError::Hex { .. }
    ));
}

#[test]
fn a_block_that_does_not_decode_is_a_block_error() {
    let c = case("transfer");
    let block = bytes_of(&serde_json::from_slice(&c.block).unwrap_or_default());
    let cut = hex_value(
        block
            .get(..block.len().saturating_sub(1))
            .unwrap_or_default(),
    );
    for raw in [hex_value(&[0x00]), cut] {
        assert!(matches!(
            rejected(import(
                raw.to_string().as_bytes(),
                &c.witness,
                eest(&c.journal)
            )),
            ImportError::Block(_)
        ));
    }
}

/// El block del caso con el header cambiado, como string JSON.
fn block_with(c: &Case, f: impl FnOnce(&mut Header)) -> Vec<u8> {
    let raw = bytes_of(&serde_json::from_slice(&c.block).unwrap_or_default());
    let Ok(block) = decode_block(&raw) else {
        panic!("decodifica");
    };
    let mut header = block.header.clone();
    f(&mut header);
    let rebuilt = encode_block(&header, &block.transactions, block.withdrawals.as_deref());
    hex_value(&rebuilt).to_string().into_bytes()
}

/// **El binario fija mainnet**: un bloque de EEST (número 1) no está en su
/// calendario, y uno de mainnet un segundo después del horizonte revisado
/// tampoco. En el horizonte mismo el calendario sí le da fork, y el rechazo
/// es otro.
#[test]
fn mainnet_refuses_what_its_schedule_does_not_cover() {
    let c = case("transfer");
    assert!(matches!(
        rejected(import(&c.block, &c.witness, ExpectedBlock::mainnet)),
        ImportError::OutsideSchedule { number: 2, .. }
    ));
    let past = block_with(&c, |h| {
        h.number = MAINNET_PARIS_BLOCK;
        h.timestamp = MAINNET_SCHEDULE_REVIEWED_UNTIL.saturating_add(1);
    });
    assert_eq!(
        rejected(import(&past, &c.witness, ExpectedBlock::mainnet)),
        ImportError::OutsideSchedule {
            number: MAINNET_PARIS_BLOCK,
            timestamp: MAINNET_SCHEDULE_REVIEWED_UNTIL.saturating_add(1),
        }
    );
    let at = block_with(&c, |h| {
        h.number = MAINNET_PARIS_BLOCK;
        h.timestamp = MAINNET_SCHEDULE_REVIEWED_UNTIL;
    });
    assert!(!matches!(
        rejected(import(&at, &c.witness, ExpectedBlock::mainnet)),
        ImportError::OutsideSchedule { .. }
    ));
}

#[test]
fn a_witness_without_the_parent_is_missing_parent() {
    let c = case("blockhash");
    let parent = c.journal.parent_hash;
    let none = with_list(witness_json(&c), "headers", Vec::clear);
    assert_eq!(
        rejected(import_case(&c, &none)),
        ImportError::MissingParent(parent)
    );
    // Del más viejo al padre: sin el último, la cadena no arranca.
    let ancestors_only = with_list(witness_json(&c), "headers", |h| {
        h.pop();
    });
    assert_eq!(
        rejected(import_case(&c, &ancestors_only)),
        ImportError::MissingParent(parent)
    );
}

#[test]
fn a_header_off_the_chain_is_unchained() {
    let c = case("blockhash");
    let headers = list(&mut witness_json(&c), "headers");
    let count = headers.len();
    // Un hueco: sin el abuelo, lo que queda más atrás no encadena.
    let gap = with_list(witness_json(&c), "headers", |h| {
        h.remove(count.saturating_sub(2));
    });
    assert!(matches!(
        rejected(import_case(&c, &gap)),
        ImportError::Unchained { index: 0, .. }
    ));
    // Repetido.
    let duplicate = with_list(witness_json(&c), "headers", |h| {
        if let Some(first) = h.first().cloned() {
            h.push(first);
        }
    });
    assert!(matches!(
        rejected(import_case(&c, &duplicate)),
        ImportError::Unchained { index, .. } if index == count
    ));
    // Suelto: el header del propio bloque no es un ancestro.
    let raw = bytes_of(&serde_json::from_slice(&c.block).unwrap_or_default());
    let Ok(block) = decode_block(&raw) else {
        panic!("decodifica");
    };
    let own = hex_value(&block.header.rlp());
    let loose = with_list(witness_json(&c), "headers", |h| h.insert(0, own));
    assert_eq!(
        rejected(import_case(&c, &loose)),
        ImportError::Unchained {
            index: 0,
            hash: c.journal.block_hash
        }
    );
}

#[test]
fn a_header_that_does_not_decode_is_a_header_error() {
    let c = case("transfer");
    let witness = with_list(witness_json(&c), "headers", |h| {
        h.push(hex_value(&[0xc0]));
    });
    assert!(matches!(
        rejected(import_case(&c, &witness)),
        ImportError::Header { index: 1, .. }
    ));
}

/// El índice del nodo raíz del estado previo en `state`.
fn root_index(c: &Case) -> usize {
    let nodes = list(&mut witness_json(c), "state");
    match nodes
        .iter()
        .position(|n| keccak256(bytes_of(n)) == c.journal.pre_state_root)
    {
        Some(i) => i,
        None => panic!("el caso trae el nodo raíz"),
    }
}

#[test]
fn a_witness_without_the_pre_state_root_node_is_missing_state_root() {
    let c = case("transfer");
    let root = root_index(&c);
    let witness = with_list(witness_json(&c), "state", |s| {
        s.remove(root);
    });
    assert_eq!(
        rejected(import_case(&c, &witness)),
        ImportError::MissingStateRoot(c.journal.pre_state_root)
    );
}

/// **Un nodo que no hashea a lo que su padre referencia**: cambiado un byte,
/// su hash es otro y el padre apunta a un nodo que no está. Lo decide el guest.
#[test]
fn a_tampered_trie_node_is_rejected_by_the_guest() {
    let c = case("withdrawals");
    let root = root_index(&c);
    let nodes = list(&mut witness_json(&c), "state");
    let mut checked = 0usize;
    for (i, node) in nodes.iter().enumerate() {
        if i == root {
            continue;
        }
        let mut bytes = bytes_of(node);
        if let Some(last) = bytes.last_mut() {
            *last ^= 0x01;
        }
        let witness = with_list(witness_json(&c), "state", |s| {
            if let Some(slot) = s.get_mut(i) {
                *slot = hex_value(&bytes);
            }
        });
        // El guest pide el nodo por el hash que el padre referencia: el del
        // original, que ya no está.
        let wanted = format!("falta nodo {} del trie", keccak256(bytes_of(node)));
        assert!(
            missing(import_case(&c, &witness)).contains(&wanted),
            "nodo {i}"
        );
        checked = checked.saturating_add(1);
        if checked == 8 {
            break;
        }
    }
    assert_eq!(checked, 8, "el caso tiene nodos para alterar");
}

/// **Un código cuyo hash no aparece**: sin los códigos, o con uno alterado, la
/// cuenta referencia un `code_hash` que el witness no trae.
#[test]
fn a_missing_or_tampered_code_is_rejected_by_the_guest() {
    let c = case("requests");
    let none = with_list(witness_json(&c), "codes", Vec::clear);
    let tampered = with_list(witness_json(&c), "codes", |codes| {
        for code in codes.iter_mut() {
            let mut bytes = bytes_of(code);
            bytes.push(0x00);
            *code = hex_value(&bytes);
        }
    });
    for witness in [none, tampered] {
        assert!(missing(import_case(&c, &witness)).contains("falta el bytecode"));
    }
}

/// La cadena trae el padre pero no los ancestros que `BLOCKHASH` pide: el
/// input arma, y el guest no puede servir el hash.
#[test]
fn a_chain_short_of_what_blockhash_asks_is_rejected_by_the_guest() {
    let c = case("blockhash");
    let parent_only = with_list(witness_json(&c), "headers", |h| {
        let parent = h.pop();
        h.clear();
        h.extend(parent);
    });
    assert!(missing(import_case(&c, &parent_only)).contains("falta la cadena de headers"));
}

#[test]
fn a_file_over_the_cap_is_a_file_error() {
    let path = dir("transfer").join(BLOCK_FILE);
    let len = read("transfer", BLOCK_FILE).len() as u64;
    assert!(read_capped(&path, len).is_ok());
    assert!(matches!(
        read_capped(&path, len.saturating_sub(1)),
        Err(ImportError::File { .. })
    ));
}

/// El binario: tres argumentos, y mainnet fijo.
#[test]
fn the_cli_takes_three_paths_and_fixes_mainnet() {
    assert!(run_cli(&[]).is_err());
    let path = |f: &str| dir("transfer").join(f).display().to_string();
    let out = std::env::temp_dir().join("repo-b-import-cli-test.bin");
    let args = [
        path(BLOCK_FILE),
        path(WITNESS_FILE),
        out.display().to_string(),
    ];
    let Err(e) = run_cli(&args) else {
        panic!("un bloque de EEST no es de mainnet");
    };
    assert!(e.contains("OutsideSchedule"), "{e}");
}
