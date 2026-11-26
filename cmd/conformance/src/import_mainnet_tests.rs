//! Un bloque REAL de mainnet (`fixtures/mainnet/26235156`), por el binario tal
//! como lo usa un operador: el hash de ancla y el calendario de mainnet, sin
//! nada del corpus de EEST. La referencia es lo que un nodo público dice del
//! bloque, no lo que el importador computa.

use super::*;

/// Lo que un nodo de mainnet publica para el bloque 26 235 156.
const BLOCK_HASH: &str = "0xa9533744986888244d786721fc0506984585de242dc3d4e0db6d8337abe75bc4";
const PARENT_HASH: &str = "0x14cd2ccb955333f34102373483c30ad5e8f25162c998feb2eb3c7cad57ba129f";
const STATE_ROOT: &str = "0xe471049224c65cef0fc04f14a0e02fcb784b13a8bf36a320984ac99e7339a3f9";
const GAS_USED: u64 = 5_443_474;
const TXS: usize = 91;

fn hash(text: &str) -> B256 {
    match text.parse() {
        Ok(h) => h,
        Err(e) => panic!("{text}: {e}"),
    }
}

fn file(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/mainnet/26235156")
        .join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

fn import_mainnet(witness: &[u8], named: B256) -> Result<Imported, ImportError> {
    import(&file("block.json"), witness, named, ExpectedBlock::mainnet)
}

#[test]
fn the_real_block_imports_to_the_state_root_mainnet_published() {
    let imported = match import_mainnet(&file("witness.json"), hash(BLOCK_HASH)) {
        Ok(i) => i,
        Err(e) => panic!("el bloque real tiene que importar: {e}"),
    };
    assert_eq!(imported.input.fork, Spec::Bpo2);
    assert_eq!(imported.input.chain_id, 1);
    let j = &imported.journal;
    assert_eq!(j.post_state_root, hash(STATE_ROOT));
    assert_eq!(j.block_hash, hash(BLOCK_HASH));
    assert_eq!(j.parent_hash, hash(PARENT_HASH));
    assert_eq!(j.fork, Some(Spec::Bpo2));
    let block = match decode_block(&imported.input.block) {
        Ok(b) => b,
        Err(e) => panic!("{e:?}"),
    };
    assert_eq!(block.transactions.len(), TXS);
    assert_eq!(block.header.gas_used, GAS_USED);
}

/// Un hash real de mainnet, el del padre: los archivos no son ESE bloque.
#[test]
fn the_real_block_under_another_blocks_hash_is_refused() {
    assert_eq!(
        import_mainnet(&file("witness.json"), hash(PARENT_HASH)),
        Err(ImportError::NotTheNamedBlock {
            named: hash(PARENT_HASH),
            computed: hash(BLOCK_HASH),
        })
    );
}

/// Un byte de un nodo de `state` cambiado: el nodo hashea a otra cosa y el
/// guest no encuentra el que el padre referencia.
#[test]
fn a_tampered_state_node_of_the_real_block_is_rejected_by_the_guest() {
    let mut witness: Value = match serde_json::from_slice(&file("witness.json")) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let mut nodes = list(&mut witness, "state");
    let index = TAMPERED_NODE;
    let original = bytes_of(&nodes[index]);
    let mut altered = original.clone();
    if let Some(last) = altered.last_mut() {
        *last ^= 0x01;
    }
    nodes[index] = hex_value(&altered);
    witness["state"] = Value::Array(nodes);
    match import_mainnet(witness.to_string().as_bytes(), hash(BLOCK_HASH)) {
        Err(ImportError::Rejected(GuestError::Vm { message, .. })) => assert_eq!(
            message,
            format!("{MISSING}falta nodo {} del trie", keccak256(&original))
        ),
        other => panic!("se esperaba el rechazo del guest y salió {other:?}"),
    }
}

/// Un nodo que el bloque recorre (no la raíz, que se rechaza antes de ejecutar).
const TAMPERED_NODE: usize = 1;
