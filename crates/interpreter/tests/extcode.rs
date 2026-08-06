//! Tests de BALANCE/EXTCODESIZE/EXTCODECOPY/EXTCODEHASH (slice 2.4, ADR-0002
//! §1: seam `Host`) contra `MockHost`. Los números de gas salen de EIP-2929
//! (2600 cold / 100 warm, distinto del 2100/100 de storage) calculados a
//! mano — no del código bajo test (weakening-the-test vetado).
//!
//! Convención de stack (Yellow Paper, igual que `tests/programs.rs`/
//! `tests/storage.rs`): para EXTCODECOPY(address, destOffset, offset, length)
//! el TOPE (µ_s[0]) es `address`, por eso se apila último.

use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
use repo_b_interpreter::gas::cost;
use repo_b_interpreter::opcode::{
    BALANCE, EXTCODECOPY, EXTCODEHASH, EXTCODESIZE, MSTORE, PUSH1, RETURN,
};
use repo_b_interpreter::{Halt, Host, Interpreter, InterpreterOutcome};

#[path = "support/mock.rs"]
mod mock;
use mock::MockHost;

const GAS: u64 = 1_000_000;
const EXTERNAL: Address = Address::new([0xEE; 20]);

/// PUSH20 (0x73): empuja una dirección completa (20 bytes).
const PUSH20: u8 = PUSH1 + 19;

fn push_address(code: &mut Vec<u8>, addr: Address) {
    code.push(PUSH20);
    code.extend_from_slice(addr.as_slice());
}

fn run_program(code: &[u8], host: &mut dyn Host) -> InterpreterOutcome {
    Interpreter::for_code(Bytes::copy_from_slice(code), GAS).run(host)
}

/// Epílogo: guarda el tope del stack en memoria[0..32] y lo retorna.
fn return_top_epilogue(code: &mut Vec<u8>) {
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, RETURN]);
}

fn returned_word(outcome: &InterpreterOutcome) -> U256 {
    match outcome {
        InterpreterOutcome::Success { output, .. } => U256::from_be_slice(output),
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

fn gas_used(outcome: &InterpreterOutcome) -> u64 {
    outcome.gas_used()
}

// --------------------------------------------------------------------- BALANCE

#[test]
fn balance_cold_access_costs_2600_and_pushes_the_balance() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(BALANCE);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_account(EXTERNAL, U256::from(777u64), KECCAK256_EMPTY, false);

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::from(777u64));
    // PUSH20=3, BALANCE=2600, epílogo (PUSH1 MSTORE PUSH1 PUSH1 RETURN)=3+6+3+3+0.
    assert_eq!(gas_used(&outcome), 3 + cost::COLD_ACCOUNT_ACCESS + 3 + 6 + 3 + 3);
}

#[test]
fn balance_warm_access_costs_100() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(BALANCE);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new()
        .with_account(EXTERNAL, U256::from(1u64), KECCAK256_EMPTY, false)
        .with_warm_address(EXTERNAL);

    let outcome = run_program(&code, &mut host);

    assert_eq!(gas_used(&outcome), 3 + cost::WARM_ACCOUNT_ACCESS + 3 + 6 + 3 + 3);
}

#[test]
fn balance_cold_then_warm_in_the_same_run() {
    // Dos BALANCE seguidos sobre la misma dirección: el primero cobra cold
    // (2600), el segundo warm (100) — mismo patrón que `sload_cold_then_warm`.
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(BALANCE);
    code.push(0x50); // POP
    push_address(&mut code, EXTERNAL);
    code.push(BALANCE);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_account(EXTERNAL, U256::from(1u64), KECCAK256_EMPTY, false);

    let outcome = run_program(&code, &mut host);

    // PUSH20=3, BALANCE cold=2600, POP=2, PUSH20=3, BALANCE warm=100, epílogo=15.
    assert_eq!(
        gas_used(&outcome),
        3 + cost::COLD_ACCOUNT_ACCESS + 2 + 3 + cost::WARM_ACCOUNT_ACCESS + 15
    );
}

#[test]
fn balance_of_an_unconfigured_address_is_zero() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(BALANCE);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn balance_on_empty_stack_underflows() {
    let outcome = run_program(&[BALANCE], &mut MockHost::new());
    assert!(matches!(outcome, InterpreterOutcome::Halt {
        reason: Halt::StackUnderflow,
        ..
    }));
}

#[test]
fn balance_out_of_gas_on_cold_cost_halts() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(BALANCE);
    let mut host = MockHost::new().with_account(EXTERNAL, U256::from(1u64), KECCAK256_EMPTY, false);

    // Alcanza para el PUSH20 (3) pero no para el cold access (2600).
    let outcome = Interpreter::for_code(Bytes::copy_from_slice(&code), 3 + 2000).run(&mut host);

    assert!(matches!(outcome, InterpreterOutcome::Halt {
        reason: Halt::OutOfGas,
        ..
    }));
}

// ---------------------------------------------------------------- EXTCODESIZE

#[test]
fn extcodesize_of_a_contract_returns_its_code_length() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODESIZE);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_code(EXTERNAL, Bytes::from_static(&[0x60, 0x00, 0x60, 0x00]));

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::from(4u64));
    assert_eq!(gas_used(&outcome), 3 + cost::COLD_ACCOUNT_ACCESS + 3 + 6 + 3 + 3);
}

#[test]
fn extcodesize_of_an_account_without_code_is_zero() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODESIZE);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn extcodesize_on_empty_stack_underflows() {
    let outcome = run_program(&[EXTCODESIZE], &mut MockHost::new());
    assert!(matches!(outcome, InterpreterOutcome::Halt {
        reason: Halt::StackUnderflow,
        ..
    }));
}

// ---------------------------------------------------------------- EXTCODECOPY

#[test]
fn extcodecopy_copies_code_into_memory() {
    // EXTCODECOPY(EXTERNAL, dest=0, offset=0, len=4).
    let mut code = vec![PUSH1, 0x04, PUSH1, 0x00, PUSH1, 0x00];
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODECOPY);
    code.extend([PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    let target_code = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut host = MockHost::new().with_code(EXTERNAL, Bytes::copy_from_slice(&target_code));

    let outcome = run_program(&code, &mut host);

    let mut expected = [0u8; 32];
    expected[..4].copy_from_slice(&target_code);
    assert_eq!(returned_word(&outcome), U256::from_be_slice(&expected));
}

#[test]
fn extcodecopy_zero_pads_beyond_the_end_of_the_code() {
    // El código tiene 2 bytes; se pide copiar 4 desde offset 0: los últimos 2
    // salen en cero (zero-padded, EIP-211).
    let mut code = vec![PUSH1, 0x04, PUSH1, 0x00, PUSH1, 0x00];
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODECOPY);
    code.extend([PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    let mut host = MockHost::new().with_code(EXTERNAL, Bytes::from_static(&[0xAA, 0xBB]));

    let outcome = run_program(&code, &mut host);

    let mut expected = [0u8; 32];
    expected[0] = 0xAA;
    expected[1] = 0xBB;
    assert_eq!(returned_word(&outcome), U256::from_be_slice(&expected));
}

#[test]
fn extcodecopy_with_offset_past_the_end_is_all_zero() {
    let mut code = vec![PUSH1, 0x04, PUSH1, 0x0A, PUSH1, 0x00];
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODECOPY);
    code.extend([PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    let mut host = MockHost::new().with_code(EXTERNAL, Bytes::from_static(&[0xAA, 0xBB]));

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn extcodecopy_with_zero_length_only_charges_the_access_cost() {
    // len=0: no toca memoria ni cobra expansión/copy — solo el access cost
    // (mismo patrón que CALLDATACOPY/CODECOPY con len 0).
    let mut code = vec![PUSH1, 0x00, PUSH1, 0x00, PUSH1, 0x00];
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODECOPY);
    let mut host = MockHost::new().with_code(EXTERNAL, Bytes::from_static(&[0xAA, 0xBB]));

    let outcome = run_program(&code, &mut host);

    assert!(outcome.is_success(), "esperaba Success, hubo {outcome:?}");
    // 3 PUSH1 (len, offset, dest) = 9, PUSH20 = 3, access cost cold = 2600.
    assert_eq!(gas_used(&outcome), 9 + 3 + cost::COLD_ACCOUNT_ACCESS);
}

#[test]
fn extcodecopy_with_too_few_stack_items_underflows() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODECOPY);
    let outcome = run_program(&code, &mut MockHost::new());
    assert!(matches!(outcome, InterpreterOutcome::Halt {
        reason: Halt::StackUnderflow,
        ..
    }));
}

// ---------------------------------------------------------------- EXTCODEHASH

#[test]
fn extcodehash_of_a_nonexistent_account_is_zero() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODEHASH);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn extcodehash_of_an_empty_eip161_account_is_zero_not_keccak_of_empty() {
    // El footgun clásico: una cuenta vacía (is_empty) pushea 0, NUNCA
    // `keccak("")` — aunque su `code_hash` guardado sea `KECCAK256_EMPTY`.
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODEHASH);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_account(EXTERNAL, U256::ZERO, KECCAK256_EMPTY, true);

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn extcodehash_of_an_existing_eoa_with_balance_is_keccak_empty() {
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODEHASH);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_account(EXTERNAL, U256::from(1u64), KECCAK256_EMPTY, false);

    let outcome = run_program(&code, &mut host);

    assert_eq!(
        returned_word(&outcome),
        U256::from_be_slice(KECCAK256_EMPTY.as_slice())
    );
}

#[test]
fn extcodehash_of_a_contract_is_its_code_hash() {
    let contract_code = [0x60u8, 0x00, 0x60, 0x00];
    let hash: B256 = keccak256(contract_code);
    let mut code = Vec::new();
    push_address(&mut code, EXTERNAL);
    code.push(EXTCODEHASH);
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_account(EXTERNAL, U256::from(1u64), hash, false);

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::from_be_slice(hash.as_slice()));
    assert_eq!(gas_used(&outcome), 3 + cost::COLD_ACCOUNT_ACCESS + 3 + 6 + 3 + 3);
}

#[test]
fn extcodehash_on_empty_stack_underflows() {
    let outcome = run_program(&[EXTCODEHASH], &mut MockHost::new());
    assert!(matches!(outcome, InterpreterOutcome::Halt {
        reason: Halt::StackUnderflow,
        ..
    }));
}
