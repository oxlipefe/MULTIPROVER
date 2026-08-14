//! Ejecución de contratos single-frame por `OwnVm`.
//!
//! Los números de gas se calculan **a mano desde las EIPs** en cada test
//! (2929 cold/warm, 2200 base de SSTORE, 3529 refunds y tope): derivarlos del
//! código sería testear el código contra sí mismo. El oráculo real —revm— es
//! el set diferencial `fixtures/diff/storage`.

mod support;

use std::collections::BTreeMap;

use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{Address, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::error::{HaltReason, VmError};
use repo_b_evm::result::{ExecutionOutcome, ExecutionResult, StateChanges};
use repo_b_evm::types::Spec;
use repo_b_evm::{OwnVm, Vm};

use support::{BASE_FEE, COINBASE, CONTRACT, MemState, SENDER, env};

const GAS_LIMIT: u64 = 1_000_000;
const SENDER_BALANCE: u64 = 100_000_000;

fn tx_to_contract(input: &[u8], value: u64) -> Transaction {
    Transaction {
        tx_type: TxType::Legacy,
        sender: SENDER,
        nonce: 0,
        to: Some(CONTRACT),
        value: U256::from(value),
        input: Bytes::copy_from_slice(input),
        gas_limit: GAS_LIMIT,
        gas_price: Some(u128::from(BASE_FEE)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    }
}

fn base_state(code: &[u8]) -> MemState {
    MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, code, 0)
}

#[track_caller]
fn must_execute(result: Result<ExecutionOutcome, VmError>) -> ExecutionOutcome {
    match result {
        Ok(outcome) => outcome,
        Err(err) => panic!("debia ejecutar, fallo con: {err}"),
    }
}

#[track_caller]
fn must_fail(result: Result<ExecutionOutcome, VmError>) -> VmError {
    match result {
        Ok(outcome) => panic!("debia fallar, ejecuto: {:?}", outcome.result),
        Err(err) => err,
    }
}

fn update_for(changes: &StateChanges, addr: Address) -> Option<&AccountUpdate> {
    changes.iter().find(|update| update.address == addr)
}

fn storage_of(changes: &StateChanges, addr: Address) -> BTreeMap<U256, U256> {
    update_for(changes, addr).map_or_else(BTreeMap::new, |update| update.storage.clone())
}

/// Corre la tx sin value ni calldata contra el contrato del `state`.
#[track_caller]
fn run(state: &MemState, spec: Spec) -> ExecutionOutcome {
    must_execute(OwnVm::new().execute_tx(&tx_to_contract(&[], 0), &env(spec), state))
}

// ------------------------------------------------------------------ SSTORE feliz

#[test]
fn sstore_writes_the_slot_and_charges_cold_set_gas() {
    // PUSH1 0x01 PUSH1 0x00 SSTORE STOP
    let code = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    // 21000 intrínseco + 3 + 3 (PUSHes) + 2100 (cold, EIP-2929) + 20000
    // (SSTORE_SET, EIP-2200) + 0 (STOP) = 43106.
    match &outcome.result {
        ExecutionResult::Success {
            gas_used,
            gas_refunded,
            output,
            logs,
        } => {
            assert_eq!(*gas_used, 43_106);
            assert_eq!(*gas_refunded, 0);
            assert!(output.is_empty());
            assert!(logs.is_empty());
        }
        other => panic!("esperaba Success, obtuve {other:?}"),
    }
    assert_eq!(
        storage_of(&outcome.state_changes, CONTRACT).get(&U256::ZERO),
        Some(&U256::from(1u64))
    );
    assert_eq!(
        update_for(&outcome.state_changes, SENDER).and_then(|u| u.nonce),
        Some(1)
    );
}

#[test]
fn warm_sload_after_sstore_costs_the_warm_price() {
    // PUSH1 0x01 PUSH1 0x00 SSTORE PUSH1 0x00 SLOAD POP STOP
    let code = [0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54, 0x50, 0x00];
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    // 43106 (caso anterior) + 3 (PUSH1) + 100 (SLOAD warm) + 2 (POP) = 43211.
    assert_eq!(outcome.result.gas_used(), 43_211);
}

#[test]
fn cold_sload_of_a_preexisting_slot_reads_the_state() {
    // PUSH1 0x07 SLOAD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
    let code = [
        0x60, 0x07, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3,
    ];
    let state = base_state(&code).with_slot(CONTRACT, 7, 0x2A);

    let outcome = run(&state, Spec::Prague);

    let ExecutionResult::Success { output, .. } = &outcome.result else {
        panic!("esperaba Success, obtuve {:?}", outcome.result)
    };
    assert_eq!(output.len(), 32);
    assert_eq!(U256::from_be_slice(output), U256::from(0x2Au64));
    // 21000 + 3 (PUSH1) + 2100 (SLOAD cold) + 3 (PUSH1) + 3 + 3 (MSTORE +
    // 1 palabra de expansión) + 3 + 3 (PUSHes) + 0 (RETURN) = 23118.
    assert_eq!(outcome.result.gas_used(), 23_118);
    // Una lectura pura no produce diff de storage.
    assert!(storage_of(&outcome.state_changes, CONTRACT).is_empty());
}

// ------------------------------------------------------------------ revert / halt

#[test]
fn revert_discards_the_storage_but_charges_the_consumed_gas() {
    // PUSH1 0x01 PUSH1 0x00 SSTORE PUSH1 0x00 PUSH1 0x00 REVERT
    let code = [0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xFD];
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    // 43106 + 3 + 3 (PUSHes del REVERT) + 0 (REVERT) = 43112. REVERT devuelve
    // el gas restante: NO consume el límite entero.
    match &outcome.result {
        ExecutionResult::Revert {
            gas_used, output, ..
        } => {
            assert_eq!(*gas_used, 43_112);
            assert!(output.is_empty());
        }
        other => panic!("esperaba Revert, obtuve {other:?}"),
    }
    assert!(storage_of(&outcome.state_changes, CONTRACT).is_empty());
    // El nonce igual sube y el fee igual se cobra.
    assert_eq!(
        update_for(&outcome.state_changes, SENDER).and_then(|u| u.nonce),
        Some(1)
    );
    let expected_balance =
        U256::from(SENDER_BALANCE) - U256::from(43_112u64) * U256::from(BASE_FEE);
    assert_eq!(
        update_for(&outcome.state_changes, SENDER).and_then(|u| u.balance),
        Some(expected_balance)
    );
}

#[test]
fn halt_consumes_the_whole_gas_limit_and_discards_the_storage() {
    // PUSH1 0x01 PUSH1 0x00 SSTORE INVALID (0xFE, EIP-141)
    let code = [0x60, 0x01, 0x60, 0x00, 0x55, 0xFE];
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    match &outcome.result {
        ExecutionResult::Halt {
            reason, gas_used, ..
        } => {
            assert_eq!(*reason, HaltReason::InvalidFEOpcode);
            assert_eq!(*gas_used, GAS_LIMIT);
        }
        other => panic!("esperaba Halt, obtuve {other:?}"),
    }
    assert!(storage_of(&outcome.state_changes, CONTRACT).is_empty());
}

/// Una call a un precompile IMPLEMENTADO (`0x01..=
/// 0x04`) ya no es fail-closed — corre de verdad. Antes de este slice,
/// tratarla como cuenta vacía habría dado "success sin output" —
/// divergencia silenciosa vs revm; ahora el output es el REAL del
/// precompile.
#[test]
fn call_to_an_implemented_precompile_runs_it_end_to_end() {
    // IDENTITY (0x04) ya no es fail-closed. PUSH1 0 x4
    // (ventanas) PUSH1 0 (value) PUSH1 0x04 (identity) PUSH2 gas CALL — sin
    // calldata en la tx, el input del CALL es la ventana [0,0) (vacía), así
    // que IDENTITY devuelve output vacío y status éxito (slot no leído acá,
    // solo se ejercita que la tx entera termina en Success y no en un
    // `VmError::Internal` como antes de este slice).
    let code = [
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x04, 0x61, 0xFF, 0xFF,
        0xF1,
    ];
    let state = base_state(&code);

    let outcome =
        must_execute(OwnVm::new().execute_tx(&tx_to_contract(&[], 0), &env(Spec::Prague), &state));

    match outcome.result {
        ExecutionResult::Success { .. } => {}
        other => panic!("esperaba Success, obtuve {other:?}"),
    }
}

/// Con `0x01..=0x11` COMPLETO, ya no queda
/// ninguna dirección "reservada pero sin implementar" contra la cual
/// testear fail-closed — este test reemplaza esa garantía (perdida al
/// implementarse 0x0B/BLS12-381) por la que sigue siendo real: una
/// dirección FUERA del rango reservado (`0x12`) es una cuenta vacía
/// normal, la tx termina en Success (no un `VmError::Internal`).
#[test]
fn call_just_past_the_reserved_precompile_range_is_a_plain_empty_account() {
    // Mismo bytecode que arriba, pero apuntando a 0x12 (el primer byte que
    // ya no es precompile, `LAST_PRECOMPILE + 1`).
    let code = [
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x12, 0x61, 0xFF, 0xFF,
        0xF1,
    ];
    let state = base_state(&code);

    let outcome =
        must_execute(OwnVm::new().execute_tx(&tx_to_contract(&[], 0), &env(Spec::Prague), &state));

    match outcome.result {
        ExecutionResult::Success { .. } => {}
        other => panic!("esperaba Success, obtuve {other:?}"),
    }
}

/// El opcode designado inválido sigue siendo el canario de que el dispatch NO
/// se volvió permisivo al agregar los 4 opcodes de call.
#[test]
fn unassigned_opcodes_are_still_fail_closed() {
    // 0xF6 no está asignado en Prague.
    let state = base_state(&[0xF6]);

    let outcome = run(&state, Spec::Prague);

    match &outcome.result {
        ExecutionResult::Halt { reason, .. } => assert_eq!(*reason, HaltReason::OpcodeNotFound),
        other => panic!("esperaba Halt, obtuve {other:?}"),
    }
}

// --------------------------------------------------------------------- refunds

#[test]
fn clearing_a_slot_credits_the_refund_uncapped() {
    // PUSH1 0x00 PUSH1 0x00 SSTORE STOP — limpia el slot 0 (original = 1).
    let code = [0x60, 0x00, 0x60, 0x00, 0x55, 0x00];
    let state = base_state(&code).with_slot(CONTRACT, 0, 1);

    let outcome = run(&state, Spec::Prague);

    // Gasto: 21000 + 3 + 3 + 2100 (cold) + 2900 (SSTORE_RESET) = 26006.
    // Refund EIP-3529: +4800; tope = 26006/5 = 5201 ⇒ manda el contador.
    match &outcome.result {
        ExecutionResult::Success {
            gas_used,
            gas_refunded,
            ..
        } => {
            assert_eq!(*gas_refunded, 4_800);
            assert_eq!(*gas_used, 26_006 - 4_800);
        }
        other => panic!("esperaba Success, obtuve {other:?}"),
    }
    // El slot limpiado aparece en el diff con valor 0.
    assert_eq!(
        storage_of(&outcome.state_changes, CONTRACT).get(&U256::ZERO),
        Some(&U256::ZERO)
    );
}

#[test]
fn refund_is_capped_at_a_fifth_of_the_gas_used_eip3529() {
    // Limpia 4 slots: PUSH1 0x00 PUSH1 k SSTORE, k = 0..3.
    let mut code = Vec::new();
    for slot in 0u8..4 {
        code.extend_from_slice(&[0x60, 0x00, 0x60, slot, 0x55]);
    }
    code.push(0x00);
    let state = (0u64..4).fold(base_state(&code), |acc, slot| {
        acc.with_slot(CONTRACT, slot, 1)
    });

    let outcome = run(&state, Spec::Prague);

    // Gasto: 21000 + 4 · (3 + 3 + 2100 + 2900) = 21000 + 20024 = 41024.
    // Refund crudo: 4 · 4800 = 19200; tope = 41024/5 = 8204 ⇒ MANDA el tope.
    match &outcome.result {
        ExecutionResult::Success {
            gas_used,
            gas_refunded,
            ..
        } => {
            assert_eq!(*gas_refunded, 8_204);
            assert_eq!(*gas_used, 41_024 - 8_204);
        }
        other => panic!("esperaba Success, obtuve {other:?}"),
    }
}

#[test]
fn a_reverted_tx_refunds_nothing() {
    // Limpia el slot y revierte: el contador de refund se revierte con todo.
    let code = [0x60, 0x00, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xFD];
    let state = base_state(&code).with_slot(CONTRACT, 0, 1);

    let outcome = run(&state, Spec::Prague);

    match &outcome.result {
        ExecutionResult::Revert { gas_used, .. } => assert_eq!(*gas_used, 26_012),
        other => panic!("esperaba Revert, obtuve {other:?}"),
    }
    assert!(storage_of(&outcome.state_changes, CONTRACT).is_empty());
}

// ------------------------------------------------------------ transient (EIP-1153)

#[test]
fn tstore_never_reaches_the_state_diff() {
    // PUSH1 0x01 PUSH1 0x00 TSTORE PUSH1 0x00 TLOAD POP STOP
    let code = [0x60, 0x01, 0x60, 0x00, 0x5D, 0x60, 0x00, 0x5C, 0x50, 0x00];
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    // 21000 + 3 + 3 + 100 (TSTORE) + 3 + 100 (TLOAD) + 2 (POP) = 21211.
    assert_eq!(outcome.result.gas_used(), 21_211);
    assert!(storage_of(&outcome.state_changes, CONTRACT).is_empty());
}

// -------------------------------------------------------------- valor y calldata

#[test]
fn value_moves_on_success_and_stays_put_on_revert() {
    let ok_code = [0x00];
    let state = base_state(&ok_code);
    let outcome = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&[], 500),
        &env(Spec::Prague),
        &state,
    ));
    assert_eq!(
        update_for(&outcome.state_changes, CONTRACT).and_then(|u| u.balance),
        Some(U256::from(500u64))
    );

    // PUSH1 0x00 PUSH1 0x00 REVERT
    let revert_code = [0x60, 0x00, 0x60, 0x00, 0xFD];
    let state = base_state(&revert_code);
    let outcome = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&[], 500),
        &env(Spec::Prague),
        &state,
    ));
    // El value volvió: el balance del contrato es idéntico al del `State`, y
    // el diff SOLO lista lo que cambió — no hay update (EIP-161: tampoco se
    // crea una cuenta vacía por haberla tocado).
    assert_eq!(
        update_for(&outcome.state_changes, CONTRACT).and_then(|u| u.balance),
        None
    );
}

#[test]
fn calldata_reaches_the_contract() {
    // PUSH1 0x00 CALLDATALOAD PUSH1 0x00 SSTORE STOP
    let code = [0x60, 0x00, 0x35, 0x60, 0x00, 0x55, 0x00];
    let state = base_state(&code);
    let mut input = [0u8; 32];
    if let Some(last) = input.last_mut() {
        *last = 0x2A;
    }

    let outcome = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&input, 0),
        &env(Spec::Cancun),
        &state,
    ));

    assert_eq!(
        storage_of(&outcome.state_changes, CONTRACT).get(&U256::ZERO),
        Some(&U256::from(0x2Au64))
    );
    // Intrínseco: 21000 + 31·4 (ceros) + 1·16 (no-cero) = 21140.
    // Ejecución: 3 + 3 (CALLDATALOAD) + 3 + 2100 + 20000 = 22109.
    assert_eq!(outcome.result.gas_used(), 43_249);
}

#[test]
fn the_coinbase_gets_the_tip_over_the_net_gas() {
    let code = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let state = base_state(&code);
    let tx = Transaction {
        tx_type: TxType::Eip1559,
        gas_price: None,
        max_fee_per_gas: Some(20),
        max_priority_fee_per_gas: Some(3),
        ..tx_to_contract(&[], 0)
    };

    let outcome = must_execute(OwnVm::new().execute_tx(&tx, &env(Spec::Prague), &state));

    // effective = min(20, 10 + 3) = 13; tip = 3; gas neto = 43106.
    assert_eq!(
        update_for(&outcome.state_changes, COINBASE).and_then(|u| u.balance),
        Some(U256::from(43_106u64 * 3))
    );
}

// ---------------------------------------------------------- account access

/// Devuelve el output de una ejecución `Success`, o revienta el test.
#[track_caller]
fn success_output(outcome: &ExecutionOutcome) -> Bytes {
    match &outcome.result {
        ExecutionResult::Success { output, .. } => output.clone(),
        other => panic!("esperaba Success, obtuve {other:?}"),
    }
}

#[test]
fn balance_of_the_sender_reflects_the_fee_and_value_debit_within_the_frame() {
    // PUSH20 <sender> BALANCE PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — el
    // valor NO puede salir del `State` congelado (el sender ahí sigue con su
    // balance de pre-tx); tiene que salir del overlay del journal.
    let mut code = vec![0x73];
    code.extend_from_slice(SENDER.as_slice());
    code.extend([0x31, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]);
    let state = base_state(&code);
    let value = 1_000u64;

    let outcome = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&[], value),
        &env(Spec::Prague),
        &state,
    ));

    // sender_balance - gas_limit·gas_price - value = 100_000_000 - 10_000_000 - 1000.
    let gas_prepaid = U256::from(GAS_LIMIT) * U256::from(BASE_FEE);
    let expected = U256::from(SENDER_BALANCE) - gas_prepaid - U256::from(value);
    assert_eq!(U256::from_be_slice(&success_output(&outcome)), expected);
}

#[test]
fn balance_of_to_is_pre_warmed_and_costs_the_warm_price_on_first_access() {
    // BALANCE(address()) — `to` ya viene warm por el pre-warming de tx
    // (EIP-2929 §tx): el PRIMER acceso desde el código cobra 100, no 2600.
    // ADDRESS PUSH20 <contract, para comparar el resultado> ... más simple:
    // BALANCE(ADDRESS) directo.
    let code = [
        0x30, // ADDRESS
        0x31, // BALANCE
        0x60, 0x00, 0x52, // PUSH1 0 MSTORE
        0x60, 0x20, 0x60, 0x00, 0xF3, // PUSH1 0x20 PUSH1 0 RETURN
    ];
    let state = base_state(&code);
    let value = 250u64;

    let outcome = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&[], value),
        &env(Spec::Prague),
        &state,
    ));

    assert_eq!(
        U256::from_be_slice(&success_output(&outcome)),
        U256::from(value)
    );
    // Intrínseco 21000 + ADDRESS(2) + BALANCE warm(100) + PUSH1(3) +
    // MSTORE(3 base + 3 expansión w=1) + PUSH1(3) + PUSH1(3) + RETURN(0) = 21117.
    assert_eq!(outcome.result.gas_used(), 21_117);
}

#[test]
fn extcodehash_of_the_sender_eoa_is_keccak_empty_not_zero() {
    // El sender tiene balance (paga fees) y no código: EOA no-vacía ⇒
    // KECCAK256_EMPTY, NUNCA 0 (ese es el caso de una cuenta vacía/inexistente).
    let mut code = vec![0x73];
    code.extend_from_slice(SENDER.as_slice());
    code.extend([0x3F, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]);
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    assert_eq!(
        U256::from_be_slice(&success_output(&outcome)),
        U256::from_be_slice(KECCAK256_EMPTY.as_slice())
    );
}

#[test]
fn extcodehash_of_a_nonexistent_account_is_zero() {
    let external = Address::new([0xEE; 20]);
    let mut code = vec![0x73];
    code.extend_from_slice(external.as_slice());
    code.extend([0x3F, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]);
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    assert_eq!(U256::from_be_slice(&success_output(&outcome)), U256::ZERO);
}

#[test]
fn extcodesize_of_the_contract_itself_returns_its_own_code_length() {
    let mut code = vec![0x30]; // ADDRESS
    code.extend([0x3B]); // EXTCODESIZE
    code.extend([0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3]);
    let full_len = code.len();
    let state = base_state(&code);

    let outcome = run(&state, Spec::Prague);

    assert_eq!(
        U256::from_be_slice(&success_output(&outcome)),
        U256::from(full_len as u64)
    );
}

// ------------------------------------------------------------------- fail-closed

#[test]
fn a_state_read_failure_is_an_internal_error_not_a_zero() {
    // PUSH1 0x00 SLOAD POP STOP contra un State que falla al leer storage.
    let code = [0x60, 0x00, 0x54, 0x50, 0x00];
    let state = base_state(&code).failing_on(CONTRACT);

    let err =
        must_fail(OwnVm::new().execute_tx(&tx_to_contract(&[], 0), &env(Spec::Prague), &state));

    assert!(matches!(err, VmError::Internal(_)));
}

#[test]
fn unresolvable_code_is_fail_closed() {
    let code = [0x00];
    // El contrato declara un code_hash cuyo bytecode el State no conoce.
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &code, 0)
        .with_unknown_code(CONTRACT);

    let err =
        must_fail(OwnVm::new().execute_tx(&tx_to_contract(&[], 0), &env(Spec::Prague), &state));

    assert!(matches!(err, VmError::Internal(_)));
}

#[test]
fn the_eip7623_calldata_floor_clamps_the_real_gas_charged_under_prague() {
    // Calldata grande + ejecución trivial: bajo Prague el floor de EIP-7623
    // (21000 + 10·tokens, tokens = 100 ceros = 100) MUERDE el gas realmente
    // consumido. Cierre completo del EIP: la tx NO se rechaza,
    // el gas COBRADO se clampea a `max(gas_cobrado, floor_gas)` — y eso tiene
    // que reflejarse en el balance real del sender, no solo en `gas_used`
    // (el punto de mayor riesgo del slice: un fixture que solo mirara
    // `gas_used` podría pasar en verde con el clamp aplicado solo al
    // reporte).
    let code = [0x00];
    let state = base_state(&code);
    let input = [0u8; 100];

    // Intrínseco: 21000 + 100·4 = 21400; ejecución: 0 (STOP); floor:
    // 21000 + 100·10 = 22000 > 21400 ⇒ muerde.
    let prague = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&input, 0),
        &env(Spec::Prague),
        &state,
    ));
    assert!(matches!(
        prague.result,
        ExecutionResult::Success {
            gas_used: 22_000,
            gas_refunded: 0,
            ..
        }
    ));
    // El balance real del sender paga el floor (22000), no el gas
    // efectivamente consumido (21400). gas_price == BASE_FEE ⇒ tip 0.
    let sender =
        update_for(&prague.state_changes, SENDER).unwrap_or_else(|| panic!("update del sender"));
    assert_eq!(
        sender.balance,
        Some(U256::from(SENDER_BALANCE - 22_000 * BASE_FEE))
    );
    // Tip 0: el coinbase no se toca (EIP-161).
    assert!(update_for(&prague.state_changes, COINBASE).is_none());

    // En Cancun el floor no existe: la misma tx ejecuta normal, cobrando
    // exactamente el intrínseco (21400), sin clamp.
    let cancun = must_execute(OwnVm::new().execute_tx(
        &tx_to_contract(&input, 0),
        &env(Spec::Cancun),
        &state,
    ));
    assert_eq!(cancun.result.gas_used(), 21_400);
    let sender_cancun = update_for(&cancun.state_changes, SENDER)
        .unwrap_or_else(|| panic!("update del sender (cancun)"));
    assert_eq!(
        sender_cancun.balance,
        Some(U256::from(SENDER_BALANCE - 21_400 * BASE_FEE))
    );
}

#[test]
fn the_eip7623_calldata_floor_does_not_clamp_when_it_does_not_bite() {
    // Ejecución con trabajo real (SSTORE) que ya cuesta más que el floor:
    // el clamp es un no-op, el gas cobrado es el de siempre.
    let code = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00]; // PUSH1 1 PUSH1 0 SSTORE STOP
    let state = base_state(&code);

    // Sin calldata: floor = 21000 (tokens = 0) — nunca puede morder acá.
    let outcome =
        must_execute(OwnVm::new().execute_tx(&tx_to_contract(&[], 0), &env(Spec::Prague), &state));
    // Mismo código que `the_coinbase_gets_the_tip_over_the_net_gas`: 21000
    // intrínseco + 2·PUSH1(3) + SSTORE cold-set (2100 cold + 20000 set) = 43106.
    assert_eq!(outcome.result.gas_used(), 43_106);
}

#[test]
fn a_gas_limit_exactly_at_the_floor_boundary_is_valid_both_sides() {
    // Edge del chequeo de validación: calldata
    // mayormente-cero cuyo floor (22000) excede el intrínseco (21400).
    // `gas_limit == floor_gas` exactamente: válido, el floor no rechaza.
    let code = [0x00];
    let state = base_state(&code);
    let input = [0u8; 100];
    let mut at_boundary = tx_to_contract(&input, 0);
    at_boundary.gas_limit = 22_000;

    let outcome = must_execute(OwnVm::new().execute_tx(&at_boundary, &env(Spec::Prague), &state));
    assert_eq!(outcome.result.gas_used(), 22_000);

    // Un gas de menos (`gas_limit == floor_gas - 1`): la tx entera es
    // inválida — el mismo chequeo de consenso que ya cubre el intrínseco
    // (verificado contra revm: `validate_initial_tx_gas` rechaza tanto por
    // debajo de `initial_total_gas` como por debajo de `floor_gas`; acá se
    // colapsan en un solo `max()`, ver `own_vm::execute_tx`).
    let mut below_boundary = tx_to_contract(&input, 0);
    below_boundary.gas_limit = 21_999;
    let err = must_fail(OwnVm::new().execute_tx(&below_boundary, &env(Spec::Prague), &state));
    assert!(matches!(
        err,
        VmError::Consensus(repo_b_evm::error::ConsensusError::IntrinsicGasTooLow {
            required: 22_000,
            available: 21_999,
        })
    ));
}
