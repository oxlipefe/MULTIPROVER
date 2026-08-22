//! El lifecycle del bloque **adentro del guest**, en lo que el corpus no puede
//! juzgar.
//!
//! El eje de bloques le da a `run_block` 46 052 bloques reales, y eso cubre el
//! camino feliz mejor que cualquier test escrito a mano. Lo que NO puede cubrir
//! es lo que un fixture de EEST no contiene: un fixture describe qué hace un
//! cliente **correcto**, así que un predeploy que revierte solo aparece con su
//! bloque ya marcado inválido, y el orden de dos pasos cuyo estado es disjunto
//! es inobservable por construcción.
//!
//! Acá se prueban esas tres cosas con un pre-state armado a mano:
//!
//! 1. que los outputs de las llamadas de **cierre** se capturan, en orden y con
//!    su contenido — que es lo que las hace el dato y no un efecto colateral;
//! 2. que una de cierre que **no termina en éxito invalida el bloque**, y que la
//!    misma llamada en el **arranque** no lo hace;
//! 3. que las de cierre corren **después** del settle de withdrawals, medido
//!    por un predeploy que devuelve su propio balance.
//!
//! **El pre-state es un trie de una sola hoja**, y eso alcanza: caminar hacia
//! cualquier otra clave termina en esa misma hoja con la clave equivocada, que
//! es **ausencia probada**. O sea que toda cuenta que no sea el predeploy está
//! probada inexistente, sin un solo nodo más.

use alloy_trie::nodes::LeafNode;
use alloy_trie::{Nibbles, TrieAccount};
use repo_b_common::primitives::{Address, B256, Bytes, EMPTY_ROOT_HASH, U256, keccak256};
use repo_b_common::spec::Spec;
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;
use repo_b_guest::{GuestError, GuestInput, run_block};

/// La dirección del predeploy de los tests. Cualquiera sirve: lo que la hace
/// una system call es el momento en el que el input la pide, no su valor.
const PREDEPLOY: Address = Address::repeat_byte(0x77);

/// Devuelve la calldata tal cual. Con dos llamadas de cierre que traen calldata
/// distinta, el orden de los outputs deja de ser una afirmación y pasa a ser
/// una aserción.
///
/// `CALLDATASIZE PUSH0 PUSH0 CALLDATACOPY CALLDATASIZE PUSH0 RETURN`
const ECO: &[u8] = &[0x36, 0x5f, 0x5f, 0x37, 0x36, 0x5f, 0xf3];

/// Revierte siempre: `PUSH0 PUSH0 REVERT`.
const REVIERTE: &[u8] = &[0x5f, 0x5f, 0xfd];

/// Devuelve su propio balance: `SELFBALANCE PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN`.
const BALANCE: &[u8] = &[0x47, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];

struct Mundo {
    witness: ExecutionWitness,
    root: B256,
}

/// Un pre-state de **una sola cuenta**, con código.
///
/// El nodo se arma con la misma implementación de MPT que el witness usa para
/// verificarlo: un formato que solo entendiera este lado daría un test que pasa
/// contra sí mismo.
fn mundo_con(code: &[u8]) -> Mundo {
    let cuenta = TrieAccount {
        nonce: 1,
        balance: U256::ZERO,
        storage_root: EMPTY_ROOT_HASH,
        code_hash: keccak256(code),
    };
    let hoja = LeafNode {
        key: Nibbles::unpack(keccak256(PREDEPLOY)),
        value: alloy_rlp::encode(cuenta),
    };
    let nodo = alloy_rlp::encode(&hoja);
    let root = keccak256(&nodo);
    Mundo {
        witness: ExecutionWitness {
            state: vec![Bytes::from(nodo)],
            codes: vec![Bytes::copy_from_slice(code)],
            keys: vec![],
            headers: vec![],
        },
        root,
    }
}

fn env() -> BlockEnv {
    BlockEnv {
        spec: Spec::Prague,
        chain_id: 1,
        number: 1,
        coinbase: Address::repeat_byte(0xcc),
        timestamp: 1_700_000_000,
        gas_limit: 30_000_000,
        base_fee: 0,
        prevrandao: B256::ZERO,
        blob_excess_gas: Some(0),
        blob_base_fee: None,
        blob_base_fee_update_fraction: None,
    }
}

fn input<'a>(
    mundo: &'a Mundo,
    withdrawals: Vec<Withdrawal>,
    opening: &'a [(Address, Bytes)],
    closing: &'a [(Address, Bytes)],
) -> GuestInput<'a> {
    GuestInput {
        witness: &mundo.witness,
        pre_state_root: mundo.root,
        parent_hash: B256::ZERO,
        env: env(),
        txs: &[],
        withdrawals,
        opening_system_calls: opening,
        closing_system_calls: closing,
    }
}

/// **El output de una system call de cierre es el dato**, y viene en orden.
///
/// Los requests de EIP-7685 de los tipos 1 y 2 son literalmente estos bytes. Un
/// `run_block` que corriera las llamadas y tirara el resultado produciría el
/// estado correcto y un bloque sin identidad.
#[test]
fn the_closing_system_call_outputs_are_captured_in_order() {
    let mundo = mundo_con(ECO);
    let closing = [
        (PREDEPLOY, Bytes::from_static(b"primero")),
        (PREDEPLOY, Bytes::from_static(b"segundo")),
    ];
    let Ok(salida) = run_block(&input(&mundo, Vec::new(), &[], &closing)) else {
        panic!("el bloque tiene que ejecutar");
    };
    assert_eq!(
        salida.closing_outputs,
        vec![
            Bytes::from_static(b"primero"),
            Bytes::from_static(b"segundo")
        ],
        "los outputs tienen que salir en el orden en el que se pidieron"
    );
}

/// Sin llamadas de cierre no hay outputs. Es la recíproca del test de arriba:
/// sin ella, "los outputs coinciden" podría ser cierto por vacuidad.
#[test]
fn a_block_without_closing_calls_produces_no_outputs() {
    let mundo = mundo_con(ECO);
    let Ok(salida) = run_block(&input(&mundo, Vec::new(), &[], &[])) else {
        panic!("el bloque tiene que ejecutar");
    };
    assert!(salida.closing_outputs.is_empty());
}

/// **Las de cierre son *checked*:** un revert del predeploy invalida el bloque.
///
/// Es la dirección que importa para soundness — si el guest la tratara como una
/// de arranque, la prueba diría que un bloque inválido es válido.
#[test]
fn a_closing_system_call_that_reverts_invalidates_the_block() {
    let mundo = mundo_con(REVIERTE);
    let closing = [(PREDEPLOY, Bytes::new())];
    match run_block(&input(&mundo, Vec::new(), &[], &closing)) {
        Err(GuestError::ClosingSystemCall(_)) => {}
        otro => panic!("una llamada de cierre que revierte tiene que rechazar: {otro:?}"),
    }
}

/// **Y la MISMA llamada en el arranque no invalida nada.**
///
/// La asimetría la fija el texto de cada EIP: 4788/2935 se corren *unchecked* y
/// 7002/7251 *checked*. Sin este test, la de arriba no probaría que hay una
/// asimetría — probaría que el motor rechaza los reverts en general.
#[test]
fn the_same_call_at_the_opening_does_not_invalidate_the_block() {
    let mundo = mundo_con(REVIERTE);
    let opening = [(PREDEPLOY, Bytes::new())];
    let Ok(salida) = run_block(&input(&mundo, Vec::new(), &opening, &[])) else {
        panic!("una llamada de arranque que revierte NO invalida el bloque");
    };
    assert!(salida.closing_outputs.is_empty());
}

/// **Las de cierre corren DESPUÉS del settle de withdrawals.**
///
/// El corpus no puede juzgar este orden: el estado que tocan las withdrawals y
/// el que tocan las system calls es disjunto en todo fixture del set, así que se
/// pinea acá — el predeploy devuelve su propio balance y la withdrawal va
/// dirigida a él. Correr las de cierre antes del settle daría cero.
#[test]
fn the_closing_calls_see_the_state_the_withdrawals_left() {
    let mundo = mundo_con(BALANCE);
    let withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: PREDEPLOY,
        // En Gwei: el motor acredita `amount * 1e9` en Wei.
        amount: 7,
    }];
    let closing = [(PREDEPLOY, Bytes::new())];
    let Ok(salida) = run_block(&input(&mundo, withdrawals, &[], &closing)) else {
        panic!("el bloque tiene que ejecutar");
    };
    let esperado = U256::from(7u64) * U256::from(1_000_000_000u64);
    assert_eq!(
        salida.closing_outputs,
        vec![Bytes::from(esperado.to_be_bytes::<32>().to_vec())],
        "la llamada de cierre no vio el balance que la withdrawal acreditó"
    );
}

/// **Un header que no encadena desde el `parent_hash` es un rechazo.**
///
/// El ancla es lo único que hace verificable la cadena: sin ella los headers
/// del witness serían un dato que el propio witness afirma sobre sí mismo, y
/// servir un `BLOCKHASH` desde ahí es exactamente la forma en la que un guest
/// miente.
#[test]
fn a_header_chain_that_does_not_chain_from_the_anchor_is_refused() {
    let mut mundo = mundo_con(ECO);
    mundo.witness.headers = vec![Bytes::from_static(&[0xc1, 0x80])];
    match run_block(&input(&mundo, Vec::new(), &[], &[])) {
        Err(GuestError::Chain(_)) => {}
        otro => panic!("una cadena que no encadena tiene que rechazar: {otro:?}"),
    }
}
