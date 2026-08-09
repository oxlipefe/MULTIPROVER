//! Calls anidadas end-to-end por `OwnVm` (slice 2.5, task 007).
//!
//! El oráculo de los NÚMEROS es `fixtures/diff/calls` vs revm. Lo que se
//! verifica acá es la **intención**: que el sub-árbol revertido realmente
//! desaparece, que DELEGATECALL escribe el storage del caller, que un halt
//! profundo burbujea como status 0 y que una call sin fondos no es un halt.
//! Sin estos asserts, un fixture podría estar pasando por no ejercitar nada.

mod support;

use std::collections::BTreeMap;

use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::error::VmError;
use repo_b_evm::result::{ExecutionOutcome, ExecutionResult, StateChanges};
use repo_b_evm::types::Spec;
use repo_b_evm::{OwnVm, Vm};

use support::{BASE_FEE, CONTRACT, MemState, SENDER, env};

const CALLEE: Address = Address::new([0xDD; 20]);
const DEEP: Address = Address::new([0xEE; 20]);
const DEAD: Address = Address::new([0x11; 20]);

const GAS_LIMIT: u64 = 1_000_000;
const SENDER_BALANCE: u64 = 100_000_000;

// Opcodes usados por los programas de este archivo.
const STOP: u8 = 0x00;
const ADD: u8 = 0x01;
const ADDRESS: u8 = 0x30;
const CALLER: u8 = 0x33;
const CALLVALUE: u8 = 0x34;
const POP: u8 = 0x50;
const SSTORE: u8 = 0x55;
const PUSH1: u8 = 0x60;
const PUSH3: u8 = 0x62;
const PUSH20: u8 = 0x73;
const CALL: u8 = 0xF1;
const DELEGATECALL: u8 = 0xF4;
const STATICCALL: u8 = 0xFA;
const REVERT: u8 = 0xFD;
const INVALID: u8 = 0xFE;

/// Todo el gas que haya (el 63/64 lo recorta).
const ALL_GAS: [u8; 3] = [0xFF, 0xFF, 0xFF];
/// 60000: suficiente para que el sub-árbol trabaje, acotado para que al caller
/// le quede gas después de un halt del hijo (que quema TODO lo reenviado).
const BOUNDED_GAS: [u8; 3] = [0x00, 0xEA, 0x60];

fn push1(code: &mut Vec<u8>, value: u8) {
    code.extend([PUSH1, value]);
}

/// CALL(gas, addr, value, 0, 0, 0, 0) — µ_s[0] = gas, así que se apila al revés.
fn call(target: Address, value: u8) -> Vec<u8> {
    call_with_gas(target, value, ALL_GAS)
}

fn call_with_gas(target: Address, value: u8, gas: [u8; 3]) -> Vec<u8> {
    let mut code = Vec::new();
    for _ in 0..4 {
        push1(&mut code, 0x00);
    }
    push1(&mut code, value);
    code.push(PUSH20);
    code.extend_from_slice(target.as_slice());
    code.push(PUSH3);
    code.extend(gas);
    code.push(CALL);
    code
}

/// DELEGATECALL/STATICCALL(gas, addr, 0, 0, 0, 0): sin argumento `value`.
fn two_arg_call(op: u8, target: Address) -> Vec<u8> {
    two_arg_call_with_gas(op, target, ALL_GAS)
}

fn two_arg_call_with_gas(op: u8, target: Address, gas: [u8; 3]) -> Vec<u8> {
    let mut code = Vec::new();
    for _ in 0..4 {
        push1(&mut code, 0x00);
    }
    code.push(PUSH20);
    code.extend_from_slice(target.as_slice());
    code.push(PUSH3);
    code.extend(gas);
    code.push(op);
    code
}

/// Guarda `status + 1` en `slot`: nunca cero, así el slot SIEMPRE aparece en
/// el diff (un 0 no existe en el trie y no distinguiría "falló" de "ni corrió").
fn store_status(slot: u8) -> Vec<u8> {
    vec![PUSH1, 0x01, ADD, PUSH1, slot, SSTORE]
}

/// `SSTORE(slot, value)` con constantes (µ_s[0] = key).
fn store_const(slot: u8, value: u8) -> Vec<u8> {
    vec![PUSH1, value, PUSH1, slot, SSTORE]
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn tx(value: u64) -> Transaction {
    Transaction {
        tx_type: TxType::Legacy,
        sender: SENDER,
        nonce: 0,
        to: Some(CONTRACT),
        value: U256::from(value),
        input: Bytes::new(),
        gas_limit: GAS_LIMIT,
        gas_price: Some(u128::from(BASE_FEE)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
    }
}

#[track_caller]
fn must_execute(result: Result<ExecutionOutcome, VmError>) -> ExecutionOutcome {
    match result {
        Ok(outcome) => outcome,
        Err(err) => panic!("debia ejecutar, fallo con: {err}"),
    }
}

fn update_for(changes: &StateChanges, addr: Address) -> Option<&AccountUpdate> {
    changes.iter().find(|update| update.address == addr)
}

fn storage_of(changes: &StateChanges, addr: Address) -> BTreeMap<U256, U256> {
    update_for(changes, addr).map_or_else(BTreeMap::new, |update| update.storage.clone())
}

#[track_caller]
fn slot(changes: &StateChanges, addr: Address, key: u64) -> Option<U256> {
    storage_of(changes, addr).get(&U256::from(key)).copied()
}

#[track_caller]
fn run(state: &MemState, value: u64) -> ExecutionOutcome {
    must_execute(OwnVm::new().execute_tx(&tx(value), &env(Spec::Prague), state))
}

// --------------------------------------------------------------- revert anidado

/// MAIN → MIDDLE → DEEP, con MIDDLE revirtiendo después de que DEEP escribió.
///
/// MAIN reenvía gas ACOTADO: si mandara el 63/64, un halt de MIDDLE le dejaría
/// 1/64 y MAIN no podría ni registrar el status — el test dejaría de probar
/// que el caller sobrevive al halt del hijo.
fn nested_state(middle_tail: &[u8]) -> MemState {
    let main = concat(&[&call_with_gas(CALLEE, 0, BOUNDED_GAS), &store_status(0)]);
    let middle = concat(&[&store_const(2, 0x63), &call(DEEP, 0), &[POP], middle_tail]);
    let deep = concat(&[&store_const(3, 0x2A), &[STOP]]);
    MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 0)
        .with_contract(CALLEE, &middle, 0)
        .with_contract(DEEP, &deep, 0)
}

#[test]
fn a_reverted_middle_frame_erases_its_whole_subtree() {
    let state = nested_state(&[PUSH1, 0x00, PUSH1, 0x00, REVERT]);

    let outcome = run(&state, 0);

    // El abuelo ve status 0 (slot 0 = 0 + 1) y sigue vivo…
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(1u64))
    );
    // …pero NI el slot de MIDDLE ni el del NIETO sobreviven.
    assert!(storage_of(&outcome.state_changes, CALLEE).is_empty());
    assert!(storage_of(&outcome.state_changes, DEEP).is_empty());
    assert!(outcome.result.is_success(), "la tx en sí no revirtió");
}

#[test]
fn a_halted_middle_frame_also_erases_its_whole_subtree() {
    let state = nested_state(&[INVALID]);

    let outcome = run(&state, 0);

    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(1u64))
    );
    assert!(storage_of(&outcome.state_changes, CALLEE).is_empty());
    assert!(storage_of(&outcome.state_changes, DEEP).is_empty());
}

#[test]
fn a_successful_subtree_commits_every_level() {
    // El control: sin este caso, "no veo nada" podría ser un bug de commit.
    let state = nested_state(&[STOP]);

    let outcome = run(&state, 0);

    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(2u64))
    );
    assert_eq!(
        slot(&outcome.state_changes, CALLEE, 2),
        Some(U256::from(0x63u64))
    );
    assert_eq!(
        slot(&outcome.state_changes, DEEP, 3),
        Some(U256::from(0x2Au64))
    );
}

// ------------------------------------------------------------------ contexto

/// Código que graba CALLER/CALLVALUE/ADDRESS en los slots 1/2/3.
fn context_probe() -> Vec<u8> {
    concat(&[
        &[CALLER, PUSH1, 0x01, SSTORE],
        &[CALLVALUE, PUSH1, 0x02, SSTORE],
        &[ADDRESS, PUSH1, 0x03, SSTORE],
        &[STOP],
    ])
}

fn word_of(addr: Address) -> U256 {
    U256::from_be_slice(addr.as_slice())
}

#[test]
fn delegatecall_writes_the_callers_storage_with_the_inherited_context() {
    let main = concat(&[&two_arg_call(DELEGATECALL, CALLEE), &store_status(0)]);
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 0)
        .with_contract(CALLEE, &context_probe(), 0);

    let outcome = run(&state, 0x7B);

    // Los tres SSTORE caen en MAIN, no en el target.
    assert!(storage_of(&outcome.state_changes, CALLEE).is_empty());
    // CALLER heredado = el sender de la tx (NO el contrato que delega).
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 1),
        Some(word_of(SENDER))
    );
    // CALLVALUE heredado = el value de la tx, aunque DELEGATECALL no mueva nada.
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 2),
        Some(U256::from(0x7Bu64))
    );
    // ADDRESS sigue siendo el del caller.
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 3),
        Some(word_of(CONTRACT))
    );
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(2u64))
    );
}

#[test]
fn a_plain_call_writes_the_targets_storage_with_the_caller_as_caller() {
    // El contraste con DELEGATECALL: mismo probe, contexto distinto.
    let main = concat(&[&call(CALLEE, 0), &store_status(0)]);
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 0)
        .with_contract(CALLEE, &context_probe(), 0);

    let outcome = run(&state, 0x7B);

    assert_eq!(
        slot(&outcome.state_changes, CALLEE, 1),
        Some(word_of(CONTRACT))
    );
    // El value del opcode es 0: el de la tx NO se hereda en un CALL.
    assert_eq!(slot(&outcome.state_changes, CALLEE, 2), None);
    assert_eq!(
        slot(&outcome.state_changes, CALLEE, 3),
        Some(word_of(CALLEE))
    );
}

// ---------------------------------------------------------------- staticcall

#[test]
fn a_static_context_propagates_two_frames_deep_and_the_sstore_halts() {
    let main = concat(&[
        &two_arg_call_with_gas(STATICCALL, CALLEE, BOUNDED_GAS),
        &store_status(0),
    ]);
    // MIDDLE hace un CALL NORMAL: `is_static` igual se hereda (EIP-214).
    let middle = concat(&[&call(DEEP, 0), &store_status(6), &[STOP]]);
    let deep = concat(&[&store_const(5, 0x2A), &[STOP]]);
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 0)
        .with_contract(CALLEE, &middle, 0)
        .with_contract(DEEP, &deep, 0);

    let outcome = run(&state, 0);

    // DEEP haltea al escribir; MIDDLE haltea al guardar su status (también
    // escritura); MAIN ve status 0 y ninguna escritura sobrevive.
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(1u64))
    );
    assert!(storage_of(&outcome.state_changes, CALLEE).is_empty());
    assert!(storage_of(&outcome.state_changes, DEEP).is_empty());
}

// -------------------------------------------------------------------- value

#[test]
fn a_call_with_value_to_a_dead_account_creates_it_with_the_balance() {
    let main = concat(&[&call(DEAD, 0x64), &store_status(0)]);
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 1000);

    let outcome = run(&state, 0);

    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(2u64))
    );
    assert_eq!(
        update_for(&outcome.state_changes, DEAD).and_then(|u| u.balance),
        Some(U256::from(0x64u64))
    );
    assert_eq!(
        update_for(&outcome.state_changes, CONTRACT).and_then(|u| u.balance),
        Some(U256::from(1000u64 - 0x64))
    );
}

#[test]
fn a_call_without_funds_pushes_zero_and_the_caller_keeps_running() {
    // La regla que más se equivoca: sin fondos NO es halt.
    let main = concat(&[&call(CALLEE, 0x64), &store_status(0), &store_const(1, 0x2A)]);
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 10)
        .with_contract(CALLEE, &[STOP], 0);

    let outcome = run(&state, 0);

    assert!(matches!(outcome.result, ExecutionResult::Success { .. }));
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(1u64))
    );
    // El frame siguió vivo después del push 0.
    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 1),
        Some(U256::from(0x2Au64))
    );
    // Ningún balance se movió.
    assert_eq!(update_for(&outcome.state_changes, CALLEE), None);
}

#[test]
fn a_call_to_an_account_without_code_succeeds_without_running_anything() {
    let main = concat(&[&call(DEAD, 0), &store_status(0)]);
    let state = MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &main, 0);

    let outcome = run(&state, 0);

    assert_eq!(
        slot(&outcome.state_changes, CONTRACT, 0),
        Some(U256::from(2u64))
    );
    // EIP-161: un touch de value cero NO crea la cuenta.
    assert_eq!(update_for(&outcome.state_changes, DEAD), None);
}
