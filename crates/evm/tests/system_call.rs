//! EIP-4788 — el system call, por el seam `Vm`.
//!
//! Lo que se prueba acá es, casi todo, **lo que el corpus de Cancun no puede
//! medir en un fork puro**: la rama "el contrato no existe" (su fixture es de
//! la red de transición a Cancun), que `SYSTEM_ADDRESS` no quede en el trie, y
//! que un system call fallido se reporte como tal en vez de pasar por éxito
//! (`SYSTEM_CONTRACT_CALL_FAILED` solo aparece en fixtures de Prague).

mod support;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::{SYSTEM_ADDRESS, Spec};
use repo_b_evm::vm::Vm;
use repo_b_evm::{
    BEACON_ROOTS_ADDRESS, CONSOLIDATION_REQUESTS_ADDRESS, ExecutionOutcome,
    HISTORY_STORAGE_ADDRESS, InternalError, OwnVm, VmError, WITHDRAWAL_REQUESTS_ADDRESS,
};
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

/// Los cuatro contratos de sistema que el protocolo dispara.
const SYSTEM_CONTRACTS: [Address; 4] = [
    BEACON_ROOTS_ADDRESS,
    HISTORY_STORAGE_ADDRESS,
    WITHDRAWAL_REQUESTS_ADDRESS,
    CONSOLIDATION_REQUESTS_ADDRESS,
];

#[track_caller]
fn assert_state_access_error(result: Result<ExecutionOutcome, VmError>, what: &str) {
    match result {
        Err(VmError::Internal(InternalError::StateAccess(_))) => {}
        otro => panic!("{what}: esperado un error de acceso al estado, obtenido {otro:?}"),
    }
}

/// **Una lectura fallida NO es "el contrato no existe".** Si el `State` conoce
/// el `code_hash` del contrato de sistema pero no puede servir los bytes (un
/// witness al que le falta o le corrompieron el bytecode), la system call
/// tiene que fallar cerrada. Tratarla como el no-op de una cuenta sin código
/// sería saltear la escritura del ring buffer, o los requests, con éxito.
#[test]
fn a_system_call_whose_code_cannot_be_read_fails_closed() {
    for target in SYSTEM_CONTRACTS {
        let state = MemState::new()
            .with_contract(target, BEACON_ROOTS_CODE, 0)
            .with_unknown_code(target);
        let mut vm = OwnVm::new();
        assert_state_access_error(
            vm.execute_system_call(target, beacon_root(), &env(Spec::Prague), &state),
            &format!("código ilegible en {target}"),
        );
    }
}

/// Lo mismo cuando lo que falla es el nodo de la CUENTA: el `code_hash` no se
/// puede leer, y aproximarlo por el de una cuenta vacía es la misma salida
/// silenciosa por otra puerta.
#[test]
fn a_system_call_whose_account_cannot_be_read_fails_closed() {
    for target in SYSTEM_CONTRACTS {
        let state = MemState::new()
            .with_contract(target, BEACON_ROOTS_CODE, 0)
            .failing_account_on(target);
        let mut vm = OwnVm::new();
        assert_state_access_error(
            vm.execute_system_call(target, beacon_root(), &env(Spec::Prague), &state),
            &format!("cuenta ilegible en {target}"),
        );
    }
}

/// Y por la variante de bloque, que es la que corre el cliente: el error sube
/// por `system_call_in_block`, no se convierte en un éxito vacío.
#[test]
fn an_in_block_system_call_with_unreadable_code_fails_closed() {
    for target in SYSTEM_CONTRACTS {
        let state = MemState::new()
            .with_contract(target, BEACON_ROOTS_CODE, 0)
            .with_unknown_code(target);
        let mut vm = OwnVm::new();
        vm.begin_block(&env(Spec::Prague), &state)
            .unwrap_or_else(|e| panic!("begin_block falló: {e}"));
        assert_state_access_error(
            vm.system_call_in_block(target, beacon_root()),
            &format!("código ilegible en {target}, dentro del bloque"),
        );
    }
}

// ------------------------------------------------- `has_code_in_block`
//
// La pregunta que la política de system calls *checked* le hace al motor antes
// de correrlas: el seam devuelve un éxito no-op para una cuenta sin código, así
// que el resultado de la llamada no la contesta.

/// Una fábrica que hace `CREATE` de un contrato cuyo runtime es un byte.
///
/// Initcode `PUSH1 1 PUSH1 0 RETURN` (`60 01 60 00 f3`), guardado alineado a la
/// derecha en la palabra 0 de memoria (offset 27, 5 bytes):
/// `PUSH5 <initcode> PUSH1 0 MSTORE PUSH1 5 PUSH1 27 PUSH1 0 CREATE STOP`.
const FACTORY_CODE: &[u8] = &[
    0x64, 0x60, 0x01, 0x60, 0x00, 0xf3, 0x60, 0x00, 0x52, 0x60, 0x05, 0x60, 0x1b, 0x60, 0x00, 0xf0,
    0x00,
];

fn open_block(state: &MemState) -> OwnVm {
    let mut vm = OwnVm::new();
    let opened = vm.begin_block(&env(Spec::Prague), state);
    assert!(opened.is_ok(), "begin_block: {opened:?}");
    vm
}

#[test]
fn has_code_in_block_distinguishes_code_from_absent_and_codeless_accounts() {
    let contract = Address::repeat_byte(0xc0);
    let eoa = Address::repeat_byte(0xe0);
    let absent = Address::repeat_byte(0xab);
    let state = MemState::new()
        .with_contract(contract, &[0x00], 0)
        .with_eoa(eoa, 1, 0);
    let vm = open_block(&state);
    assert!(matches!(vm.has_code_in_block(contract), Ok(true)));
    assert!(matches!(vm.has_code_in_block(eoa), Ok(false)));
    assert!(matches!(vm.has_code_in_block(absent), Ok(false)));
}

/// Lee el estado DEL BLOQUE, no el de arranque: un contrato que el bloque ya
/// desplegó cuenta (`execution-specs` lee el código con un `TransactionState`
/// sobre el estado del bloque, justamente para ver ese caso).
#[test]
fn has_code_in_block_sees_a_contract_deployed_earlier_in_the_block() {
    let factory = Address::repeat_byte(0xfa);
    let state = MemState::new().with_contract(factory, FACTORY_CODE, 0);
    // `with_contract` arranca la cuenta con nonce 1.
    let created = factory.create(1);
    let mut vm = open_block(&state);
    assert!(matches!(vm.has_code_in_block(created), Ok(false)));
    let outcome = vm.system_call_in_block(factory, Bytes::new());
    assert!(
        matches!(&outcome, Ok(o) if o.result.is_success()),
        "{outcome:?}"
    );
    assert!(
        matches!(vm.has_code_in_block(created), Ok(true)),
        "{:?}",
        vm.has_code_in_block(created)
    );
}

/// Fail-closed: un estado que no puede contestar no es "sin código".
#[test]
fn has_code_in_block_fails_closed_when_the_state_cannot_answer() {
    let unreadable = Address::repeat_byte(0x0a);
    let unknown_code = Address::repeat_byte(0x0c);
    let state = MemState::new()
        .with_contract(unknown_code, &[0x00], 0)
        .with_unknown_code(unknown_code)
        .failing_account_on(unreadable);
    let vm = open_block(&state);
    for address in [unreadable, unknown_code] {
        assert!(
            matches!(
                vm.has_code_in_block(address),
                Err(VmError::Internal(InternalError::StateAccess(_)))
            ),
            "{address}"
        );
    }
    assert!(OwnVm::new().has_code_in_block(unreadable).is_err());
}

// ------------------------------------------- delegación 7702 del destino
//
// `execution-specs` (`process_message_call`): si el código CRUDO del destino
// es un designador, se ejecuta el código del delegado (UN nivel), con las
// precompiles deshabilitadas y el delegado agregado al accessed set. El
// destino no se calienta: el mensaje de sistema arranca con el set vacío.

/// Un destino cualquiera con un designador hacia `delegate`.
const TARGET: Address = Address::repeat_byte(0x7a);

fn delegated_to(delegate: Address) -> MemState {
    MemState::new().with_contract(
        TARGET,
        &repo_b_common::authorization::delegation_designator(delegate),
        0,
    )
}

fn system_call_on(state: &MemState) -> repo_b_evm::ExecutionOutcome {
    OwnVm::new()
        .execute_system_call(TARGET, Bytes::new(), &env(Spec::Prague), state)
        .unwrap_or_else(|e| panic!("la system call debía correr: {e}"))
}

/// `PUSH1 1 PUSH0 SSTORE STOP`: escribe el slot 0 del contexto en el que corre.
const WRITES_SLOT_0: &[u8] = &[0x60, 0x01, 0x5f, 0x55, 0x00];

/// El código del delegado corre, y en el contexto del DESTINO (`ADDRESS` es el
/// destino): el slot escrito es del destino, no del delegado.
#[test]
fn a_delegated_system_contract_runs_the_delegate_code_in_its_own_context() {
    let delegate = Address::repeat_byte(0xde);
    let state = delegated_to(delegate).with_contract(delegate, WRITES_SLOT_0, 0);
    let outcome = system_call_on(&state);
    assert!(outcome.result.is_success(), "{:?}", outcome.result);
    assert_eq!(
        slot_of(&outcome.state_changes, TARGET, U256::ZERO),
        Some(U256::from(1u8))
    );
    assert_eq!(slot_of(&outcome.state_changes, delegate, U256::ZERO), None);
}

#[test]
fn a_delegate_that_reverts_makes_the_system_call_revert() {
    let delegate = Address::repeat_byte(0xde);
    let state = delegated_to(delegate).with_contract(delegate, &[0x5f, 0x5f, 0xfd], 0);
    let outcome = system_call_on(&state);
    assert!(
        matches!(outcome.result, ExecutionResult::Revert { .. }),
        "{:?}",
        outcome.result
    );
}

/// Delegar a una precompile: las precompiles están deshabilitadas en ese
/// camino, así que se ejecuta el código de la cuenta de la precompile (vacío):
/// éxito sin efecto, sin correr la precompile.
#[test]
fn a_delegate_that_is_a_precompile_runs_empty_code() {
    let identity = Address::with_last_byte(0x04);
    let outcome = system_call_on(&delegated_to(identity));
    assert!(
        matches!(
            &outcome.result,
            ExecutionResult::Success { gas_used: 0, output, .. } if output.is_empty()
        ),
        "{:?}",
        outcome.result
    );
}

#[test]
fn a_delegate_without_code_is_a_successful_no_op() {
    let outcome = system_call_on(&delegated_to(Address::repeat_byte(0xab)));
    assert!(
        matches!(outcome.result, ExecutionResult::Success { gas_used: 0, .. }),
        "{:?}",
        outcome.result
    );
}

/// UN solo nivel: si el delegado también es un designador, sus 23 bytes se
/// ejecutan crudos y `0xEF` no es un opcode ⇒ halt.
#[test]
fn a_chain_of_designators_resolves_one_level_and_halts() {
    let first = Address::repeat_byte(0xd1);
    let second = Address::repeat_byte(0xd2);
    let state = delegated_to(first)
        .with_contract(
            first,
            &repo_b_common::authorization::delegation_designator(second),
            0,
        )
        .with_contract(second, WRITES_SLOT_0, 0);
    let outcome = system_call_on(&state);
    assert!(
        matches!(outcome.result, ExecutionResult::Halt { .. }),
        "{:?}",
        outcome.result
    );
}

/// La temperatura: el delegado queda CALIENTE y el destino FRÍO. El código del
/// delegado hace `BALANCE(delegado)` y `BALANCE(destino)`; con los costos de
/// EIP-2929 (100 caliente, 2600 frío), `PUSH20` 3 y `POP` 2 el gas es
/// 3 + 100 + 2 + 3 + 2600 + 2 = 2 710.
#[test]
fn the_delegate_is_warm_and_the_target_is_cold() {
    let delegate = Address::repeat_byte(0xde);
    let mut code = vec![0x73];
    code.extend_from_slice(delegate.as_slice());
    code.extend_from_slice(&[0x31, 0x50, 0x73]);
    code.extend_from_slice(TARGET.as_slice());
    code.extend_from_slice(&[0x31, 0x50, 0x00]);
    let state = delegated_to(delegate).with_contract(delegate, &code, 0);
    let outcome = system_call_on(&state);
    assert!(
        matches!(
            outcome.result,
            ExecutionResult::Success {
                gas_used: 2_710,
                ..
            }
        ),
        "{:?}",
        outcome.result
    );
}
