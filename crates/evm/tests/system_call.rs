//! EIP-4788 — el system call, por el seam `Vm`.
//!
//! Lo que se prueba acá es, casi todo, **lo que el corpus de Cancun no puede
//! medir**: la rama "el contrato no existe" (su único fixture es de un fork de
//! transición, fuera de scope), que `SYSTEM_ADDRESS` no quede en el trie, y que
//! un system call fallido se reporte como tal en vez de pasar por éxito
//! (`SYSTEM_CONTRACT_CALL_FAILED` solo aparece en fixtures de Prague).

mod support;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::{SYSTEM_ADDRESS, Spec};
use repo_b_evm::vm::Vm;
use repo_b_evm::{BEACON_ROOTS_ADDRESS, OwnVm};
use support::{MemState, env};

/// El bytecode REAL del contrato de beacon roots, tal cual viene en el `pre` de
/// los 17 685 fixtures de Cancun.
///
/// Arranca `CALLER PUSH20 0xff..fe EQ PUSH1 0x4d JUMPI`: **discrimina al
/// `SYSTEM_ADDRESS`**. Con el caller de sistema salta al camino de escritura:
///
/// ```text
/// timestamp % 8191          ← timestamp
/// timestamp % 8191 + 8191   ← calldata[0..32]  (el beacon root)
/// ```
const BEACON_ROOTS_CODE: &[u8] = &[
    0x33, 0x73, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x14, 0x60, 0x4d, 0x57, 0x60, 0x20, 0x36, 0x14, 0x60, 0x24,
    0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x5f, 0x35, 0x80, 0x15, 0x60, 0x49, 0x57, 0x62, 0x00, 0x1f, 0xff,
    0x81, 0x06, 0x90, 0x81, 0x54, 0x14, 0x60, 0x3c, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x62, 0x00, 0x1f,
    0xff, 0x01, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3, 0x5b, 0x5f, 0x5f, 0xfd, 0x5b, 0x62, 0x00,
    0x1f, 0xff, 0x42, 0x06, 0x42, 0x81, 0x55, 0x5f, 0x35, 0x90, 0x62, 0x00, 0x1f, 0xff, 0x01, 0x55,
    0x00,
];

/// `HISTORY_BUFFER_LENGTH` de EIP-4788.
const RING: u64 = 8191;

fn beacon_root() -> Bytes {
    Bytes::from(vec![0x7Bu8; 32])
}

#[track_caller]
fn slot_of(changes: &repo_b_evm::StateChanges, addr: Address, key: U256) -> Option<U256> {
    changes
        .iter()
        .find(|update| update.address == addr)
        .and_then(|update| update.storage.get(&key).copied())
}

/// El camino canónico: el contrato existe, el caller es el sistema y las dos
/// escrituras del ring buffer entran al diff. Es lo que mueve el `stateRoot` de
/// **todos** los bloques de Cancun.
#[test]
fn the_beacon_roots_contract_writes_its_ring_buffer_as_the_system_caller() {
    let state = MemState::new().with_contract(BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE, 0);
    let block = env(Spec::Cancun);
    let mut vm = OwnVm::new();

    let outcome = vm
        .execute_system_call(BEACON_ROOTS_ADDRESS, beacon_root(), &block, &state)
        .unwrap_or_else(|e| panic!("la system call debía correr, falló con: {e}"));

    assert!(
        outcome.result.is_success(),
        "esperado Success, obtenido {:?}",
        outcome.result
    );
    let index = U256::from(block.timestamp % RING);
    assert_eq!(
        slot_of(&outcome.state_changes, BEACON_ROOTS_ADDRESS, index),
        Some(U256::from(block.timestamp)),
        "el slot del timestamp"
    );
    assert_eq!(
        slot_of(
            &outcome.state_changes,
            BEACON_ROOTS_ADDRESS,
            index + U256::from(RING)
        ),
        Some(U256::from_be_slice(&beacon_root())),
        "el slot de la raíz"
    );
}

/// **`SYSTEM_ADDRESS` no se toca.** El nonce no se bumpea, no se le cobra nada
/// y no aparece en el diff: si apareciera, sería una cuenta vacía de más en el
/// trie y el `stateRoot` divergiría en todos los bloques post-Cancun.
///
/// El corpus lo caza igual (una mutación que bumpee el nonce rompe Cancun
/// entero), pero acá queda dicho como REGLA y no como número.
#[test]
fn a_system_call_never_touches_the_system_address_nor_the_coinbase() {
    let state = MemState::new().with_contract(BEACON_ROOTS_ADDRESS, BEACON_ROOTS_CODE, 0);
    let block = env(Spec::Cancun);
    let mut vm = OwnVm::new();

    let outcome = vm
        .execute_system_call(BEACON_ROOTS_ADDRESS, beacon_root(), &block, &state)
        .unwrap_or_else(|e| panic!("la system call debía correr, falló con: {e}"));

    for update in &outcome.state_changes {
        assert_ne!(
            update.address, SYSTEM_ADDRESS,
            "el system call emitió un update de SYSTEM_ADDRESS: {update:?}"
        );
        assert_ne!(
            update.address,
            support::COINBASE,
            "el system call le pagó al coinbase: {update:?}"
        );
        assert_eq!(
            update.balance, None,
            "un system call no mueve balances: {update:?}"
        );
        assert_eq!(
            update.nonce, None,
            "un system call no mueve nonces: {update:?}"
        );
    }
}

/// La rama que el trait fija y que **el corpus de Cancun no ejercita**: sin
/// código en el destino, el system call es un no-op exitoso — nunca un error.
#[test]
fn a_system_call_to_an_account_without_code_is_a_successful_noop() {
    // El contrato de beacon roots NO está en el estado.
    let state = MemState::new().with_eoa(BEACON_ROOTS_ADDRESS, 0, 0);
    let mut vm = OwnVm::new();

    let outcome = vm
        .execute_system_call(
            BEACON_ROOTS_ADDRESS,
            beacon_root(),
            &env(Spec::Cancun),
            &state,
        )
        .unwrap_or_else(|e| panic!("un contrato inexistente es no-op, no error: {e}"));

    assert!(matches!(
        outcome.result,
        ExecutionResult::Success { gas_used: 0, .. }
    ));
    assert!(
        outcome.state_changes.is_empty(),
        "un no-op no cambia el estado: {:?}",
        outcome.state_changes
    );
}

/// Un system call que falla se reporta **como fallo**, con el estado sin tocar.
/// Quién decide qué hacer con eso es el cliente (para EIP-4788 el texto del EIP
/// dice que el bloque es inválido); lo que el motor no puede hacer es
/// devolverlo como éxito.
#[test]
fn a_reverting_system_call_reports_the_failure_and_leaves_no_diff() {
    // PUSH1 0x00 PUSH1 0x00 REVERT.
    const ALWAYS_REVERTS: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];
    let state = MemState::new().with_contract(BEACON_ROOTS_ADDRESS, ALWAYS_REVERTS, 0);
    let mut vm = OwnVm::new();

    let outcome = vm
        .execute_system_call(
            BEACON_ROOTS_ADDRESS,
            beacon_root(),
            &env(Spec::Cancun),
            &state,
        )
        .unwrap_or_else(|e| panic!("un revert es un resultado, no un error del motor: {e}"));

    assert!(matches!(outcome.result, ExecutionResult::Revert { .. }));
    assert!(
        outcome.state_changes.is_empty(),
        "un system call revertido no deja diff: {:?}",
        outcome.state_changes
    );
}

/// Un system call **fuera de un bloque abierto** no se puede colar por la
/// variante de bloque: el contexto no existe y el motor lo dice, no lo inventa.
#[test]
fn the_in_block_variant_needs_an_open_block() {
    let mut vm = OwnVm::new();
    assert!(
        vm.system_call_in_block(BEACON_ROOTS_ADDRESS, beacon_root())
            .is_err()
    );
}
