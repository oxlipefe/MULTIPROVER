//! Un verificador que no verifica pasa todos los tests felices.
//!
//! La única forma de probar que el `WitnessState` **verifica** es darle un
//! witness roto y exigir que falle: un byte cambiado, un nodo faltante, un
//! bytecode que no corresponde a su hash. Y la contracara, igual de
//! importante: una cuenta que de verdad no existe tiene que resolverse como
//! **ausencia probada**, no como error — si no, un witness bien podado sería
//! indistinguible de uno incompleto.

use alloy_rlp::Encodable;
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{EMPTY_ROOT_HASH, HashBuilder, Nibbles, TrieAccount};
use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::state::State;
use repo_b_witness::WitnessState;

const PRESENTE: Address = Address::new([0xAA; 20]);
const OTRA: Address = Address::new([0xBB; 20]);
const AUSENTE: Address = Address::new([0xCC; 20]);

fn cuenta(nonce: u64, balance: u64, code_hash: B256) -> Vec<u8> {
    let mut out = Vec::new();
    TrieAccount {
        nonce,
        balance: U256::from(balance),
        storage_root: EMPTY_ROOT_HASH,
        code_hash,
    }
    .encode(&mut out);
    out
}

/// Trie con dos cuentas; el witness retiene los caminos de las tres
/// direcciones de interés (la ausente incluida: su camino es su prueba).
fn witness_de_prueba(code: &[u8]) -> (ExecutionWitness, B256) {
    let code_hash = keccak256(code);
    let mut hojas = vec![
        (
            Nibbles::unpack(keccak256(PRESENTE)),
            cuenta(7, 1000, code_hash),
        ),
        (
            Nibbles::unpack(keccak256(OTRA)),
            cuenta(1, 5, KECCAK256_EMPTY),
        ),
    ];
    hojas.sort_by(|a, b| a.0.cmp(&b.0));

    let targets = vec![
        Nibbles::unpack(keccak256(PRESENTE)),
        Nibbles::unpack(keccak256(OTRA)),
        Nibbles::unpack(keccak256(AUSENTE)),
    ];
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
    for (key, value) in &hojas {
        builder.add_leaf(*key, value);
    }
    let root = builder.root();
    let state: Vec<Bytes> = builder
        .take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| node)
        .collect();
    (
        ExecutionWitness {
            state,
            codes: vec![Bytes::copy_from_slice(code)],
            keys: Vec::new(),
            headers: Vec::new(),
        },
        root,
    )
}

const CODE: &[u8] = &[0x60, 0x01, 0x60, 0x02, 0x01, 0x00];

/// Los tests del repo no usan `expect`: el lint del workspace lo trata como
/// error.
#[track_caller]
fn debe_leer<T, E: std::fmt::Debug>(result: Result<T, E>, que: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{que} tenía que leerse, falló con: {err:?}"),
    }
}

#[track_caller]
fn debe_existir<T>(value: Option<T>, que: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{que} tenía que existir"),
    }
}

#[track_caller]
fn debe_fallar<T: std::fmt::Debug, E>(result: Result<T, E>, que: &str) {
    if let Ok(value) = result {
        panic!("{que} tenía que fallar y dio: {value:?}");
    }
}

/// El camino feliz, para que las mutaciones de abajo signifiquen algo.
#[test]
fn a_witness_that_is_intact_serves_the_account_and_its_code() {
    let (witness, root) = witness_de_prueba(CODE);
    let state = WitnessState::new(&witness, root);

    let info = debe_existir(
        debe_leer(state.account(PRESENTE), "la cuenta del witness"),
        "la cuenta del witness",
    );
    assert_eq!(info.nonce, 7);
    assert_eq!(info.balance, U256::from(1000));
    assert_eq!(
        debe_leer(state.code(info.code_hash), "el código del witness"),
        Bytes::copy_from_slice(CODE)
    );
}

/// **Ausencia probada**: la cuenta no existe y el witness lo demuestra. Tiene
/// que ser `Ok(None)`, no un error — un witness podado es legítimo.
#[test]
fn an_account_that_does_not_exist_resolves_as_proven_absent() {
    let (witness, root) = witness_de_prueba(CODE);
    let state = WitnessState::new(&witness, root);
    assert_eq!(
        debe_leer(state.account(AUSENTE), "el camino de la ausente"),
        None
    );
}

/// **Un byte cambiado en un nodo lo saca de su propio hash**: el padre lo
/// declara bajo otro, y deja de encontrarse. Esto es lo que hace que un witness
/// no se pueda falsificar.
#[test]
fn a_single_flipped_byte_makes_the_witness_unusable() {
    let (mut witness, root) = witness_de_prueba(CODE);
    let ultimo = witness.state.len() - 1;
    let mut roto = witness.state[ultimo].to_vec();
    let fin = roto.len() - 1;
    roto[fin] ^= 0x01;
    witness.state[ultimo] = Bytes::from(roto);

    let state = WitnessState::new(&witness, root);
    let leidas = [state.account(PRESENTE), state.account(OTRA)];
    assert!(
        leidas.iter().any(Result::is_err),
        "con un nodo corrompido, alguna lectura tiene que fallar: {leidas:?}"
    );
}

/// **Nodo faltante ≠ cuenta ausente.** Es la distinción que separa un witness
/// podado de uno incompleto, y confundirlas produce el root equivocado sin que
/// nadie lo note.
#[test]
fn a_missing_node_is_an_error_and_never_an_absent_account() {
    let (mut witness, root) = witness_de_prueba(CODE);
    witness.state.clear();
    let state = WitnessState::new(&witness, root);
    debe_fallar(state.account(PRESENTE), "una cuenta sin sus nodos");
    debe_fallar(
        state.account(AUSENTE),
        "una ausencia sin su prueba de exclusión",
    );
}

/// El bytecode es su propia prueba: bajo un hash que no le corresponde, no está.
#[test]
fn a_bytecode_that_does_not_hash_to_its_key_is_not_served() {
    let (witness, root) = witness_de_prueba(CODE);
    let state = WitnessState::new(&witness, root);
    debe_fallar(
        state.code(keccak256([0xFFu8; 3])),
        "un bytecode que nadie mandó",
    );
    // Y el vacío no necesita witness: `keccak("")` es su definición.
    assert_eq!(
        debe_leer(state.code(KECCAK256_EMPTY), "el código vacío"),
        Bytes::new()
    );
}

/// Verificar contra otro root no puede "funcionar igual".
#[test]
fn the_pre_state_root_is_actually_on_the_path_of_every_read() {
    let (witness, _) = witness_de_prueba(CODE);
    let state = WitnessState::new(&witness, B256::with_last_byte(0x99));
    debe_fallar(
        state.account(PRESENTE),
        "una lectura con el root equivocado",
    );
}
