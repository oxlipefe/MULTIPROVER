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
    import(&c.block, witness, c.journal.block_hash, eest(&c.journal))
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

/// El prefijo con que el guest reporta un dato que el witness no trae.
const MISSING: &str = "internal error: state access error: database error: el witness no alcanza: ";

fn missing(what: &str, tx: Option<usize>) -> ImportError {
    ImportError::Rejected(GuestError::Vm {
        message: format!("{MISSING}{what}"),
        tx,
    })
}

#[track_caller]
fn rejected(result: Result<Imported, ImportError>) -> ImportError {
    match result {
        Err(e) => e,
        Ok(imported) => panic!("se esperaba un rechazo y salió {:?}", imported.journal),
    }
}

/// El error que `serde_json` da para estos bytes: el oráculo del texto.
fn serde_error(raw: &[u8]) -> String {
    match serde_json::from_slice::<Value>(raw) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("se esperaba JSON roto"),
    }
}

fn hex_error(field: &str, detail: &str) -> ImportError {
    ImportError::Hex {
        field: field.to_owned(),
        detail: detail.to_owned(),
    }
}

fn json_error(file: &'static str, detail: &str) -> ImportError {
    ImportError::Json {
        file,
        detail: detail.to_owned(),
    }
}

/// El header del bloque del caso.
fn header_of(c: &Case) -> Header {
    let raw = bytes_of(&serde_json::from_slice(&c.block).unwrap_or_default());
    match decode_block(&raw) {
        Ok(block) => block.header.clone(),
        Err(e) => panic!("el bloque del caso decodifica: {e:?}"),
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
    let named = c.journal.block_hash;
    let Ok(wrapped) = import(&wrap(&c.block), &wrap(&c.witness), named, eest(&c.journal)) else {
        panic!("la respuesta entera importa");
    };
    assert_eq!(wrapped.bytes, plain.bytes);
}

/// **El ancla**: el hash que nombra el operador manda. Otro hash es un rechazo
/// antes de mirar el calendario o el witness, con los dos hashes en el error.
#[test]
fn a_block_other_than_the_named_one_is_refused() {
    let c = case("transfer");
    let named = B256::repeat_byte(0x11);
    let wanted = ImportError::NotTheNamedBlock {
        named,
        computed: c.journal.block_hash,
    };
    let eest_net = import(&c.block, &c.witness, named, eest(&c.journal));
    assert_eq!(rejected(eest_net), wanted);
    // Antes que el calendario: con mainnet el rechazo sigue siendo el del ancla.
    let mainnet = import(&c.block, &c.witness, named, ExpectedBlock::mainnet);
    assert_eq!(rejected(mainnet), wanted);
    // Antes que el witness: uno vacío no llega a leerse.
    assert_eq!(
        rejected(import(&c.block, b"", named, eest(&c.journal))),
        wanted
    );
}

#[test]
fn the_named_hash_is_strict_hex_of_32_bytes() {
    let field = "--expect-block-hash";
    let digits = "ab".repeat(32);
    let Ok(parsed) = parse_block_hash(&format!("0x{digits}")) else {
        panic!("un hash bien formado parsea");
    };
    assert_eq!(parsed, B256::repeat_byte(0xab));
    let cases = [
        (digits.clone(), "no empieza con 0x"),
        (format!("0X{digits}"), "no empieza con 0x"),
        (format!("0x{digits}0"), "odd number of digits"),
        (
            format!("0xzz{}", "ab".repeat(31)),
            "invalid character 'z' at position 0",
        ),
        ("0x".to_owned(), "tiene 0 bytes y no 32"),
        (format!("0x{}", "ab".repeat(31)), "tiene 31 bytes y no 32"),
        (format!("0x{digits}ab"), "tiene 33 bytes y no 32"),
    ];
    for (text, detail) in cases {
        assert_eq!(
            parse_block_hash(&text),
            Err(hex_error(field, detail)),
            "{text}"
        );
    }
}

/// Un directorio propio de este test y este proceso, vacío.
fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("repo-b-import-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    if let Err(e) = std::fs::create_dir_all(&path) {
        panic!("{}: {e}", path.display());
    }
    path
}

fn entries(dir: &std::path::Path) -> Vec<String> {
    let Ok(read) = std::fs::read_dir(dir) else {
        panic!("{} se lee", dir.display());
    };
    let mut names: Vec<String> = read
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// **El binario**: tres rutas y el hash nombrado, obligatorio; mainnet fijo.
/// Ningún rechazo deja archivo, ni siquiera el de una corrida anterior.
#[test]
fn the_cli_requires_the_named_hash_and_leaves_nothing_on_failure() {
    let tmp = scratch("cli");
    let out = tmp.join("salida.bin");
    let path = |f: &str| dir("transfer").join(f).display().to_string();
    let c = case("transfer");
    let run = |tail: &[&str]| {
        // Un destino de una corrida anterior, que el fallo tiene que borrar.
        if let Err(e) = std::fs::write(&out, b"viejo") {
            panic!("{e}");
        }
        let mut args = vec![
            path(BLOCK_FILE),
            path(WITNESS_FILE),
            out.display().to_string(),
        ];
        args.extend(tail.iter().map(|s| (*s).to_owned()));
        let result = run_cli(&args);
        assert_eq!(entries(&tmp), Vec::<String>::new(), "{tail:?}");
        result.err()
    };
    let usage = Some(ImportError::Usage(USAGE));
    let good = c.journal.block_hash.to_string();
    let other = B256::repeat_byte(0x22).to_string();
    assert_eq!(run(&[]), usage);
    assert_eq!(run(&["--expect-block-hash"]), usage);
    assert_eq!(run(&["--expected-block-hash", &good]), usage);
    assert_eq!(run(&["--expect-block-hash", &good, "x"]), usage);
    assert_eq!(
        run(&["--expect-block-hash", "0x12"]),
        Some(hex_error("--expect-block-hash", "tiene 1 bytes y no 32"))
    );
    assert_eq!(
        run(&["--expect-block-hash", &other]),
        Some(ImportError::NotTheNamedBlock {
            named: B256::repeat_byte(0x22),
            computed: c.journal.block_hash,
        })
    );
    // El hash correcto de un bloque de EEST: el calendario de mainnet no lo
    // reconoce (número 2, timestamp de EEST).
    let header = header_of(&c);
    assert_eq!(
        run(&["--expect-block-hash", &good]),
        Some(ImportError::OutsideSchedule {
            number: header.number,
            timestamp: header.timestamp,
        })
    );
    assert_eq!(run_cli(&[]), Err(ImportError::Usage(USAGE)));
    let _ = std::fs::remove_dir_all(&tmp);
}

/// La escritura es todo o nada: aparece el destino entero y ningún temporal;
/// si no se puede escribir, no queda nada.
#[test]
fn the_output_is_written_whole_or_not_at_all() {
    let tmp = scratch("atomic");
    let out = tmp.join("salida.bin");
    assert_eq!(write_atomic(&out, b"uno"), Ok(()));
    assert_eq!(write_atomic(&out, b"dos"), Ok(()));
    assert_eq!(std::fs::read(&out).ok(), Some(b"dos".to_vec()));
    assert_eq!(entries(&tmp), vec!["salida.bin".to_owned()]);
    // El destino es un directorio: el rename falla y el temporal se limpia.
    let blocked = tmp.join("ocupado");
    if let Err(e) = std::fs::create_dir(blocked.join("")) {
        panic!("{e}");
    }
    if let Err(e) = std::fs::write(blocked.join("dentro"), b"x") {
        panic!("{e}");
    }
    assert!(matches!(
        write_atomic(&blocked, b"tres"),
        Err(ImportError::File { ref file, .. }) if *file == blocked.display().to_string()
    ));
    assert_eq!(
        entries(&tmp),
        vec!["ocupado".to_owned(), "salida.bin".to_owned()]
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// **El envelope JSON-RPC es estricto**: con `jsonrpc` presente, solo
/// `jsonrpc`, `id` y un `result` no nulo.
#[test]
fn a_loose_rpc_envelope_is_a_json_error() {
    let c = case("transfer");
    let Ok(result) = serde_json::from_slice::<Value>(&c.witness) else {
        panic!("JSON");
    };
    let error = serde_json::json!({"code": -32000, "message": "no"});
    let cases = [
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": error}),
            format!("la respuesta es un error: {error}"),
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result, "error": error}),
            format!("la respuesta es un error: {error}"),
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": null}),
            "la respuesta no trae `result`".to_owned(),
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1}),
            "la respuesta no trae `result`".to_owned(),
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result, "extra": 0}),
            "clave desconocida `extra` en la respuesta".to_owned(),
        ),
        (
            serde_json::json!({"jsonrpc": "1.0", "id": 1, "result": result}),
            "`jsonrpc` no es \"2.0\"".to_owned(),
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "result": result}),
            "la respuesta no trae `id`".to_owned(),
        ),
    ];
    for (response, detail) in cases {
        let raw = response.to_string().into_bytes();
        assert_eq!(
            rejected(import_case(&c, &raw)),
            json_error("witness", &detail),
            "{response}"
        );
    }
}

#[test]
fn malformed_json_is_a_json_error() {
    let c = case("transfer");
    let cut = c.witness.get(..c.witness.len() / 2).unwrap_or_default();
    assert_eq!(
        rejected(import_case(&c, cut)),
        json_error("witness", &serde_error(cut))
    );
    let block_cut = c.block.get(..c.block.len() / 2).unwrap_or_default();
    assert_eq!(
        rejected(import(block_cut, &c.witness, B256::ZERO, eest(&c.journal))),
        json_error("bloque", &serde_error(block_cut))
    );
}

#[test]
fn a_witness_with_a_field_more_or_less_is_a_json_error() {
    let c = case("transfer");
    let mut extra = witness_json(&c);
    extra["proofs"] = Value::Array(Vec::new());
    let mut missing_keys = witness_json(&c);
    if let Some(object) = missing_keys.as_object_mut() {
        object.remove("keys");
    }
    let cases = [
        (extra, "campo desconocido `proofs`"),
        (missing_keys, "`keys` falta o no es una lista"),
        (Value::Array(Vec::new()), "no es un objeto"),
    ];
    for (witness, detail) in cases {
        assert_eq!(
            rejected(import_case(&c, witness.to_string().as_bytes())),
            json_error("witness", detail)
        );
    }
}

/// Hex inválido o impar en cada lista y en el archivo del bloque.
#[test]
fn invalid_hex_is_a_hex_error() {
    let c = case("transfer");
    let bad = [
        ("c0", "no empieza con 0x"),
        ("0X00", "no empieza con 0x"),
        ("0xc", "odd number of digits"),
        ("0xzz", "invalid character 'z' at position 0"),
    ];
    for field in ["state", "codes", "keys", "headers"] {
        for (text, detail) in bad {
            let mut at = 0usize;
            let witness = with_list(witness_json(&c), field, |items| {
                at = items.len();
                items.push(Value::String(text.to_owned()));
            });
            assert_eq!(
                rejected(import_case(&c, &witness)),
                hex_error(&format!("{field}[{at}]"), detail),
                "{field} {text}"
            );
        }
    }
    for (text, detail) in bad {
        let block = Value::String(text.to_owned()).to_string().into_bytes();
        assert_eq!(
            rejected(import(&block, &c.witness, B256::ZERO, eest(&c.journal))),
            hex_error("bloque", detail),
            "bloque {text}"
        );
    }
    assert_eq!(
        rejected(import(b"17", &c.witness, B256::ZERO, eest(&c.journal))),
        hex_error("bloque", "no es un string")
    );
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
    let cases = [
        (
            hex_value(&[0x00]),
            BlockError::BodyShape {
                reason: "el bloque no es una lista",
            },
        ),
        (cut, BlockError::BlockRlp(alloy_rlp::Error::InputTooShort)),
    ];
    for (raw, error) in cases {
        let file = raw.to_string().into_bytes();
        assert_eq!(
            rejected(import(&file, &c.witness, B256::ZERO, eest(&c.journal))),
            ImportError::Block(error)
        );
    }
}

/// El block del caso con el header cambiado, como string JSON, y el hash del
/// header nuevo.
fn block_with(c: &Case, f: impl FnOnce(&mut Header)) -> (Vec<u8>, B256) {
    let raw = bytes_of(&serde_json::from_slice(&c.block).unwrap_or_default());
    let Ok(block) = decode_block(&raw) else {
        panic!("decodifica");
    };
    let mut header = block.header.clone();
    f(&mut header);
    let rebuilt = encode_block(&header, &block.transactions, block.withdrawals.as_deref());
    (hex_value(&rebuilt).to_string().into_bytes(), header.hash())
}

/// **El binario fija mainnet**: un bloque de EEST (número 2) no está en su
/// calendario, y uno de mainnet un segundo después del horizonte revisado
/// tampoco. En el horizonte mismo el calendario sí le da fork, y el rechazo
/// es otro.
#[test]
fn mainnet_refuses_what_its_schedule_does_not_cover() {
    let c = case("transfer");
    let header = header_of(&c);
    assert_eq!(
        rejected(import(
            &c.block,
            &c.witness,
            c.journal.block_hash,
            ExpectedBlock::mainnet
        )),
        ImportError::OutsideSchedule {
            number: 2,
            timestamp: header.timestamp,
        }
    );
    let (past, past_hash) = block_with(&c, |h| {
        h.number = MAINNET_PARIS_BLOCK;
        h.timestamp = MAINNET_SCHEDULE_REVIEWED_UNTIL.saturating_add(1);
    });
    assert_eq!(
        rejected(import(&past, &c.witness, past_hash, ExpectedBlock::mainnet)),
        ImportError::OutsideSchedule {
            number: MAINNET_PARIS_BLOCK,
            timestamp: MAINNET_SCHEDULE_REVIEWED_UNTIL.saturating_add(1),
        }
    );
    let (at, at_hash) = block_with(&c, |h| {
        h.number = MAINNET_PARIS_BLOCK;
        h.timestamp = MAINNET_SCHEDULE_REVIEWED_UNTIL;
    });
    assert!(!matches!(
        rejected(import(&at, &c.witness, at_hash, ExpectedBlock::mainnet)),
        ImportError::OutsideSchedule { .. }
    ));
}

/// **Un bloque inválido pero coherente**: el header declara un gas que la
/// ejecución no reproduce. Encadena, el witness alcanza, el hash nombrado es
/// el suyo; lo rechaza el guest al ejecutar.
#[test]
fn a_self_consistent_invalid_block_is_rejected_by_execution() {
    let c = case("transfer");
    let gas = header_of(&c).gas_used;
    let (block, named) = block_with(&c, |h| h.gas_used = gas.saturating_add(1));
    assert_eq!(
        rejected(import(&block, &c.witness, named, eest(&c.journal))),
        ImportError::Rejected(GuestError::Block(BlockError::GasUsed {
            declared: gas.saturating_add(1),
            computed: gas,
        }))
    );
}

/// **El guest acepta y la política no**: el consumidor espera otro padre del
/// que el bloque publica.
#[test]
fn a_journal_the_consumer_does_not_expect_is_a_policy_error() {
    let c = case("transfer");
    let other_parent = B256::repeat_byte(0x33);
    let expected_of = |header: &Header| {
        let mut expected = eest(&c.journal)(header)?;
        expected.parent_hash = Some(other_parent);
        Some(expected)
    };
    assert_eq!(
        rejected(import(
            &c.block,
            &c.witness,
            c.journal.block_hash,
            expected_of
        )),
        ImportError::Policy(Refusal::ParentHash {
            expected: other_parent,
            published: c.journal.parent_hash,
        })
    );
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

/// El hash de un header del witness, por su posición en el archivo.
fn header_hash(headers: &[Value], index: usize) -> B256 {
    match headers.get(index) {
        Some(h) => keccak256(bytes_of(h)),
        None => panic!("no hay header {index}"),
    }
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
    assert_eq!(
        rejected(import_case(&c, &gap)),
        ImportError::Unchained {
            index: 0,
            hash: header_hash(&headers, 0),
        }
    );
    // Repetido: el segundo con el mismo hash es el que sobra.
    let duplicate = with_list(witness_json(&c), "headers", |h| {
        if let Some(first) = h.first().cloned() {
            h.push(first);
        }
    });
    assert_eq!(
        rejected(import_case(&c, &duplicate)),
        ImportError::Unchained {
            index: count,
            hash: header_hash(&headers, 0),
        }
    );
    // Suelto: el header del propio bloque no es un ancestro.
    let own = hex_value(&header_of(&c).rlp());
    let loose = with_list(witness_json(&c), "headers", |h| h.insert(0, own));
    assert_eq!(
        rejected(import_case(&c, &loose)),
        ImportError::Unchained {
            index: 0,
            hash: c.journal.block_hash
        }
    );
}

/// **Un intento de ciclo**: un header que se declara hijo del padre del
/// bloque. Un ciclo verdadero de `parent_hash` exigiría una colisión de
/// keccak; lo que un archivo hostil sí puede es apuntar hacia adelante, y eso
/// queda fuera de la cadena que baja desde el padre.
#[test]
fn a_header_pointing_forward_is_unchained() {
    let c = case("blockhash");
    let mut child = header_of(&c);
    child.number = child.number.saturating_add(7);
    let child_rlp = child.rlp();
    let witness = with_list(witness_json(&c), "headers", |h| {
        h.push(hex_value(&child_rlp));
    });
    let count = list(&mut witness_json(&c), "headers").len();
    assert_eq!(
        rejected(import_case(&c, &witness)),
        ImportError::Unchained {
            index: count,
            hash: keccak256(&child_rlp),
        }
    );
}

#[test]
fn a_header_that_does_not_decode_is_a_header_error() {
    let c = case("transfer");
    let witness = with_list(witness_json(&c), "headers", |h| {
        h.push(hex_value(&[0xc0]));
    });
    assert_eq!(
        rejected(import_case(&c, &witness)),
        ImportError::Header {
            index: 1,
            error: BlockError::HeaderRlp(alloy_rlp::Error::InputTooShort),
        }
    );
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

/// El witness con el nodo `i` alterado en su último byte.
fn with_tampered_node(c: &Case, i: usize) -> Vec<u8> {
    with_list(witness_json(c), "state", |s| {
        if let Some(slot) = s.get_mut(i) {
            let mut bytes = bytes_of(slot);
            if let Some(last) = bytes.last_mut() {
                *last ^= 0x01;
            }
            *slot = hex_value(&bytes);
        }
    })
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
        // El guest pide el nodo por el hash que el padre referencia: el del
        // original, que ya no está. La tx que lo pide depende del nodo.
        let wanted = format!("{MISSING}falta nodo {} del trie", keccak256(bytes_of(node)));
        match rejected(import_case(&c, &with_tampered_node(&c, i))) {
            ImportError::Rejected(GuestError::Vm { message, .. }) => {
                assert_eq!(message, wanted, "nodo {i}");
            }
            other => panic!("nodo {i}: {other:?}"),
        }
        checked = checked.saturating_add(1);
        if checked == 8 {
            break;
        }
    }
    assert_eq!(checked, 8, "el caso tiene nodos para alterar");
}

/// **Un nodo interior alterado**: ni la raíz ni una hoja, sino un branch que
/// referencia por hash a dos o más nodos del witness. Su padre lo pide por el
/// hash original.
#[test]
fn a_tampered_interior_node_is_rejected_by_the_guest() {
    let c = case("withdrawals");
    let root = root_index(&c);
    let nodes: Vec<Vec<u8>> = list(&mut witness_json(&c), "state")
        .iter()
        .map(bytes_of)
        .collect();
    let hashes: Vec<B256> = nodes.iter().map(keccak256).collect();
    let references = |node: &[u8]| {
        hashes
            .iter()
            .filter(|h| node.windows(32).any(|w| w == h.as_slice()))
            .count()
    };
    let interior = nodes
        .iter()
        .enumerate()
        .position(|(i, n)| i != root && references(n) >= 2);
    let Some(i) = interior else {
        panic!("el caso trae un branch interior");
    };
    let Some(hash) = hashes.get(i) else {
        panic!("hash {i}");
    };
    assert_eq!(
        rejected(import_case(&c, &with_tampered_node(&c, i))),
        missing(&format!("falta nodo {hash} del trie"), None)
    );
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
    let wanted = missing(
        "falta el bytecode 0xf57acd40259872606d76197ef052f3d35588dadf919ee1f0e3cb9b62d3f4b02c",
        None,
    );
    for witness in [none, tampered] {
        assert_eq!(rejected(import_case(&c, &witness)), wanted);
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
    assert_eq!(
        rejected(import_case(&c, &parent_only)),
        missing("falta la cadena de headers hasta el bloque 0", Some(0))
    );
}

#[test]
fn a_file_over_the_cap_is_a_file_error() {
    let path = dir("transfer").join(BLOCK_FILE);
    let len = read("transfer", BLOCK_FILE).len() as u64;
    assert!(read_capped(&path, len).is_ok());
    assert_eq!(
        read_capped(&path, len.saturating_sub(1)),
        Err(ImportError::File {
            file: path.display().to_string(),
            detail: format!("pasa el tope de {} bytes", len.saturating_sub(1)),
        })
    );
}

#[path = "import_mainnet_tests.rs"]
mod mainnet;
