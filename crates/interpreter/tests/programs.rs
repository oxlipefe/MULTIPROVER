//! Tests de programas: bytecode completo a través de `Interpreter::run`.
//! Cubren la trichotomy, el conteo de gas exacto, el wrapping de protocolo y
//! los paths adversariales (gate de Fase 1: stack effects, gas, edge cases).
//!
//! Convención de stack (Yellow Paper): el operando µ_s[0] es el TOPE. Por eso
//! los programas apilan en orden inverso: p.ej. para MSTORE(offset, value) se
//! apila `value` primero y `offset` último.

use repo_b_common::primitives::{Address, Bytes, U256, keccak256};
use repo_b_common::spec::Spec;
use repo_b_interpreter::opcode::{
    ADD, ADDRESS, CALLDATACOPY, CALLDATALOAD, CALLDATASIZE, CALLER, CALLVALUE, CODECOPY, CODESIZE,
    GAS as OP_GAS, INVALID, JUMP, JUMPDEST, JUMPI, KECCAK256, MLOAD, MSIZE, MSTORE, MUL, PC, PUSH0,
    PUSH1, PUSH32, RETURN, REVERT, STOP, SUB,
};
use repo_b_interpreter::{CallContext, Halt, Interpreter, InterpreterOutcome};

mod support;
use support::{NoopHost, run_frame};

const DUP2: u8 = 0x81;
const SWAP1: u8 = 0x90;
const GAS: u64 = 100_000;

fn run(code: &[u8]) -> InterpreterOutcome {
    run_with_gas(code, GAS)
}

fn run_with_gas(code: &[u8], gas_limit: u64) -> InterpreterOutcome {
    run_frame(
        Interpreter::for_code(Bytes::copy_from_slice(code), gas_limit, Spec::Prague),
        &mut NoopHost,
    )
}

fn run_with_context(context: CallContext, gas_limit: u64) -> InterpreterOutcome {
    run_frame(
        Interpreter::new(context, gas_limit, Spec::Prague),
        &mut NoopHost,
    )
}

/// Contexto con `bytecode = code` (analizado por el intérprete) y el resto en
/// cero salvo lo que el test sobreescriba con `..`.
fn context_for(code: &[u8]) -> CallContext {
    CallContext::for_code(Bytes::copy_from_slice(code))
}

/// Epílogo que guarda el tope del stack en memoria[0..32] y lo retorna:
/// PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN.
fn return_top_epilogue(code: &mut Vec<u8>) {
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, RETURN]);
}

fn returned_word(outcome: &InterpreterOutcome) -> U256 {
    match outcome {
        InterpreterOutcome::Success { output, .. } => U256::from_be_slice(output),
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

// ---------------------------------------------------------------- trichotomy

#[test]
fn empty_code_is_implicit_stop_with_zero_gas() {
    assert_eq!(
        run(&[]),
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 0
        }
    );
}

#[test]
fn falling_off_the_end_is_implicit_stop() {
    // PUSH1 1 y el código termina: no es error, es STOP implícito.
    assert_eq!(
        run(&[PUSH1, 0x01]),
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 3
        }
    );
}

#[test]
fn revert_returns_output_and_remaining_gas() {
    let mut value = [0u8; 32];
    value[31] = 0xAB;
    let mut code = vec![PUSH32];
    code.extend(value);
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, REVERT]);
    match run(&code) {
        InterpreterOutcome::Revert { output, gas_used } => {
            assert_eq!(output.as_ref(), &value);
            // PUSH32(3) + PUSH1(3) + MSTORE(3) + expansión 1 palabra(3)
            // + PUSH1(3)·2 + REVERT(0) = 18. REVERT devuelve el resto.
            assert_eq!(gas_used, 18);
        }
        other => panic!("se esperaba Revert, hubo {other:?}"),
    }
}

#[test]
fn halt_consumes_all_gas() {
    // Halt debe reportar gas_used == limit, no el gasto parcial.
    assert_eq!(
        run(&[PUSH1, 0x03, JUMP, STOP]),
        InterpreterOutcome::Halt {
            reason: Halt::InvalidJump,
            gas_used: GAS
        }
    );
}

// ------------------------------------------------------- aritmética/wrapping

#[test]
fn add_computes_sum_and_charges_exact_gas() {
    let mut code = vec![PUSH1, 0x02, PUSH1, 0x03, ADD];
    return_top_epilogue(&mut code);
    let outcome = run(&code);
    assert_eq!(returned_word(&outcome), U256::from(5u64));
    // PUSH1(3)·2 + ADD(3) + epílogo: PUSH1(3) + MSTORE(3+3 mem) + PUSH1(3)·2
    // + RETURN(0) = 24.
    assert_eq!(outcome.gas_used(), 24);
}

#[test]
fn add_wraps_at_u256_max() {
    // (2^256 - 1) + 1 = 0: wrapping de protocolo, no panic.
    let mut code = vec![PUSH32];
    code.extend([0xFF; 32]);
    code.extend([PUSH1, 0x01, ADD]);
    return_top_epilogue(&mut code);
    assert_eq!(returned_word(&run(&code)), U256::ZERO);
}

#[test]
fn sub_wraps_below_zero() {
    // SUB opera tope − segundo: 0 − 1 = 2^256 − 1.
    let mut code = vec![PUSH1, 0x01, PUSH1, 0x00, SUB];
    return_top_epilogue(&mut code);
    assert_eq!(returned_word(&run(&code)), U256::MAX);
}

#[test]
fn mul_wraps_on_overflow() {
    // 2^255 · 2 = 0 mod 2^256.
    let mut code = vec![PUSH32];
    let mut half = [0u8; 32];
    half[0] = 0x80;
    code.extend(half);
    code.extend([PUSH1, 0x02, MUL]);
    return_top_epilogue(&mut code);
    assert_eq!(returned_word(&run(&code)), U256::ZERO);
}

#[test]
fn arithmetic_on_empty_stack_underflows() {
    assert_eq!(
        run(&[ADD]),
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS
        }
    );
}

// ------------------------------------------------------------- push/dup/swap

#[test]
fn push0_pushes_zero_and_costs_base_gas() {
    let mut code = vec![PUSH0];
    return_top_epilogue(&mut code);
    let outcome = run(&code);
    assert_eq!(returned_word(&outcome), U256::ZERO);
    // PUSH0(2) + PUSH1(3) + MSTORE(3+3 mem) + PUSH1(3)·2 + RETURN(0) = 17.
    assert_eq!(outcome.gas_used(), 17);
}

#[test]
fn push_truncated_by_end_of_code_charges_gas_and_stops() {
    // PUSH2 (0x61) con un solo inmediato y EOF: cobra sus 3 de gas, apila el
    // valor zero-padded (unit test en interpreter.rs) y cae en STOP implícito.
    let outcome = run(&[0x61, 0x12]);
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 3
        }
    );
}

#[test]
fn dup2_duplicates_second_from_top() {
    // [1, 2] → DUP2 → [1, 2, 1]: el tope pasa a ser 1.
    let mut code = vec![PUSH1, 0x01, PUSH1, 0x02, DUP2];
    return_top_epilogue(&mut code);
    assert_eq!(returned_word(&run(&code)), U256::from(1u64));
}

#[test]
fn swap1_exchanges_top_two() {
    // [1, 2] → SWAP1 → [2, 1]: el tope pasa a ser 1 (sin swap sería 2).
    let mut code = vec![PUSH1, 0x01, PUSH1, 0x02, SWAP1];
    return_top_epilogue(&mut code);
    assert_eq!(returned_word(&run(&code)), U256::from(1u64));
}

#[test]
fn stack_overflow_halts_consuming_all_gas() {
    // 1025 PUSH0: el push número 1025 desborda el stack de 1024.
    let code = vec![PUSH0; 1025];
    assert_eq!(
        run(&code),
        InterpreterOutcome::Halt {
            reason: Halt::StackOverflow,
            gas_used: GAS
        }
    );
}

// -------------------------------------------------------------------- saltos

#[test]
fn jump_to_valid_jumpdest_continues_there() {
    // Salta por encima del INVALID en pc=3.
    let outcome = run(&[PUSH1, 0x04, JUMP, INVALID, JUMPDEST, STOP]);
    // PUSH1(3) + JUMP(8) + JUMPDEST(1) = 12.
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 12
        }
    );
}

#[test]
fn jump_into_push_immediates_is_invalid() {
    // pc=5 es el inmediato del PUSH1 en pc=4 (un 0x5B señuelo).
    let code = [PUSH1, 0x05, JUMP, STOP, PUSH1, JUMPDEST, STOP];
    assert_eq!(
        run(&code),
        InterpreterOutcome::Halt {
            reason: Halt::InvalidJump,
            gas_used: GAS
        }
    );
}

#[test]
fn jump_out_of_bounds_is_invalid() {
    assert_eq!(
        run(&[PUSH1, 0xFF, JUMP]),
        InterpreterOutcome::Halt {
            reason: Halt::InvalidJump,
            gas_used: GAS
        }
    );
}

#[test]
fn jump_dest_wider_than_usize_is_invalid_not_panic() {
    // Destino 2^255: irrepresentable ⇒ InvalidJump (fail-closed, sin panic).
    let mut code = vec![PUSH32];
    let mut dest = [0u8; 32];
    dest[0] = 0x80;
    code.extend(dest);
    code.push(JUMP);
    assert_eq!(
        run(&code),
        InterpreterOutcome::Halt {
            reason: Halt::InvalidJump,
            gas_used: GAS
        }
    );
}

#[test]
fn jumpi_taken_when_condition_nonzero() {
    // Stack para JUMPI(dest, cond): cond primero, dest al tope.
    let code = [PUSH1, 0x01, PUSH1, 0x06, JUMPI, INVALID, JUMPDEST, STOP];
    let outcome = run(&code);
    // PUSH1(3)·2 + JUMPI(10) + JUMPDEST(1) = 17.
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 17
        }
    );
}

#[test]
fn jumpi_not_taken_when_condition_zero() {
    // Cond 0: sigue de largo y ejecuta el INVALID en pc=5.
    let code = [PUSH1, 0x00, PUSH1, 0x06, JUMPI, INVALID, JUMPDEST, STOP];
    assert_eq!(
        run(&code),
        InterpreterOutcome::Halt {
            reason: Halt::InvalidFEOpcode,
            gas_used: GAS
        }
    );
}

#[test]
fn jumpi_with_zero_condition_does_not_validate_dest() {
    // Consenso: con condición 0, un destino inválido NO halta.
    let code = [PUSH1, 0x00, PUSH1, 0xFF, JUMPI, STOP];
    assert!(run(&code).is_success());
}

// ------------------------------------------------------------------- memoria

#[test]
fn mstore_mload_roundtrip_through_memory() {
    let mut code = vec![PUSH1, 42, PUSH1, 0x00, MSTORE, PUSH1, 0x00, MLOAD];
    return_top_epilogue(&mut code);
    assert_eq!(returned_word(&run(&code)), U256::from(42u64));
}

#[test]
fn mload_at_huge_offset_is_out_of_gas() {
    // Offset 2^255: costo de expansión impagable ⇒ OOG consume todo.
    let mut code = vec![PUSH32];
    let mut offset = [0u8; 32];
    offset[0] = 0x80;
    code.extend(offset);
    code.push(MLOAD);
    assert_eq!(
        run(&code),
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: GAS
        }
    );
}

#[test]
fn return_with_zero_length_ignores_offset() {
    // RETURN(offset=2^255, len=0): el rango vacío no toca memoria ⇒ Success.
    // Stack: len primero, offset al tope.
    let mut code = vec![PUSH1, 0x00, PUSH32];
    let mut offset = [0u8; 32];
    offset[0] = 0x80;
    code.extend(offset);
    code.push(RETURN);
    match run(&code) {
        InterpreterOutcome::Success { output, .. } => assert!(output.is_empty()),
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

#[test]
fn return_full_word_roundtrips_value() {
    let mut value = [0u8; 32];
    value[0] = 0x11;
    value[31] = 0xFF;
    let mut code = vec![PUSH32];
    code.extend(value);
    return_top_epilogue(&mut code);
    match run(&code) {
        InterpreterOutcome::Success { output, .. } => assert_eq!(output.as_ref(), &value),
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

// ----------------------------------------------------------------------- gas

#[test]
fn out_of_gas_mid_program_consumes_everything() {
    // Presupuesto 8: PUSH1(3)+PUSH1(3)=6; el ADD(3) no alcanza ⇒ OOG total.
    assert_eq!(
        run_with_gas(&[PUSH1, 0x01, PUSH1, 0x02, ADD], 8),
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: 8
        }
    );
}

#[test]
fn exact_gas_budget_succeeds() {
    // PUSH1(3) + PUSH1(3) + ADD(3) = 9 exacto.
    let outcome = run_with_gas(&[PUSH1, 0x01, PUSH1, 0x02, ADD], 9);
    assert_eq!(outcome.gas_used(), 9);
    assert!(outcome.is_success());
}

// ------------------------------------------------------------- opcodes malos

#[test]
fn invalid_opcode_0xfe_halts_with_invalid_fe() {
    assert_eq!(
        run(&[INVALID]),
        InterpreterOutcome::Halt {
            reason: Halt::InvalidFEOpcode,
            gas_used: GAS
        }
    );
}

#[test]
fn unassigned_opcode_halts_with_opcode_not_found() {
    // 0x0C no está asignado en ningún fork (fail-closed).
    assert_eq!(
        run(&[0x0C]),
        InterpreterOutcome::Halt {
            reason: Halt::OpcodeNotFound,
            gas_used: GAS
        }
    );
}

// ------------------------------------------- opcodes de contexto

#[test]
fn callvalue_returns_context_value() {
    let mut code = vec![CALLVALUE];
    return_top_epilogue(&mut code);
    let context = CallContext {
        value: U256::from(42u64),
        ..context_for(&code)
    };
    assert_eq!(
        returned_word(&run_with_context(context, GAS)),
        U256::from(42u64)
    );
}

#[test]
fn address_and_caller_return_context_addresses() {
    let address = Address::new([0x11; 20]);
    let caller = Address::new([0x22; 20]);

    let mut code = vec![ADDRESS];
    return_top_epilogue(&mut code);
    let context = CallContext {
        address,
        caller,
        ..context_for(&code)
    };
    assert_eq!(
        returned_word(&run_with_context(context, GAS)),
        U256::from_be_slice(address.as_slice())
    );

    let mut code = vec![CALLER];
    return_top_epilogue(&mut code);
    let context = CallContext {
        address,
        caller,
        ..context_for(&code)
    };
    assert_eq!(
        returned_word(&run_with_context(context, GAS)),
        U256::from_be_slice(caller.as_slice())
    );
}

#[test]
fn calldatasize_returns_calldata_len() {
    let mut code = vec![CALLDATASIZE];
    return_top_epilogue(&mut code);
    let context = CallContext {
        calldata: Bytes::copy_from_slice(&[0u8; 5]),
        ..context_for(&code)
    };
    assert_eq!(
        returned_word(&run_with_context(context, GAS)),
        U256::from(5u64)
    );
}

#[test]
fn calldataload_reads_word_zero_padded() {
    // calldata = [0xAA, 0xBB]; CALLDATALOAD(0) → 0xAABB seguido de ceros.
    let mut code = vec![PUSH1, 0x00, CALLDATALOAD];
    return_top_epilogue(&mut code);
    let context = CallContext {
        calldata: Bytes::copy_from_slice(&[0xAA, 0xBB]),
        ..context_for(&code)
    };
    let mut expected = [0u8; 32];
    expected[0] = 0xAA;
    expected[1] = 0xBB;
    assert_eq!(
        returned_word(&run_with_context(context, GAS)),
        U256::from_be_slice(&expected)
    );
}

#[test]
fn calldatacopy_copies_calldata_zero_padded() {
    // calldata = [0xAA]; CALLDATACOPY(dest=0, offset=0, len=2) → mem[0]=0xAA, mem[1]=0.
    // Stack (tope primero): dest, offset, len ⇒ se apila len, offset, dest.
    let mut code = vec![
        PUSH1,
        0x02,
        PUSH1,
        0x00,
        PUSH1,
        0x00,
        CALLDATACOPY,
        PUSH1,
        0x00,
        MLOAD,
    ];
    return_top_epilogue(&mut code);
    let context = CallContext {
        calldata: Bytes::copy_from_slice(&[0xAA]),
        ..context_for(&code)
    };
    let mut expected = [0u8; 32];
    expected[0] = 0xAA;
    assert_eq!(
        returned_word(&run_with_context(context, GAS)),
        U256::from_be_slice(&expected)
    );
}

#[test]
fn codesize_returns_code_length() {
    let mut code = vec![CODESIZE];
    return_top_epilogue(&mut code);
    let expected = U256::from(code.len() as u64);
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), GAS)),
        expected
    );
}

#[test]
fn codecopy_copies_code_into_memory() {
    // CODECOPY(dest=0, offset=0, len=1) copia code[0] (=PUSH1=0x60) a mem[0].
    let mut code = vec![
        PUSH1, 0x01, PUSH1, 0x00, PUSH1, 0x00, CODECOPY, PUSH1, 0x00, MLOAD,
    ];
    return_top_epilogue(&mut code);
    let mut expected = [0u8; 32];
    expected[0] = PUSH1; // 0x60, primer byte del código
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), GAS)),
        U256::from_be_slice(&expected)
    );
}

#[test]
fn keccak256_of_empty_is_the_known_hash() {
    // KECCAK256(offset=0, len=0): no toca memoria, hashea el vacío.
    let mut code = vec![PUSH1, 0x00, PUSH1, 0x00, KECCAK256];
    return_top_epilogue(&mut code);
    let expected = U256::from_be_slice(keccak256(b"").as_slice());
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), GAS)),
        expected
    );
}

#[test]
fn keccak256_hashes_a_memory_window() {
    // Guarda un word conocido en mem[0], luego KECCAK256(offset=0, len=32).
    let mut value = [0u8; 32];
    value[31] = 0x01;
    let mut code = vec![PUSH32];
    code.extend(value);
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, KECCAK256]);
    return_top_epilogue(&mut code);
    let expected = U256::from_be_slice(keccak256(value).as_slice());
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), GAS)),
        expected
    );
}

#[test]
fn gas_pushes_remaining_after_its_own_cost() {
    // Con límite 1000 y sin gasto previo, GAS (base 2) apila 998.
    let mut code = vec![OP_GAS];
    return_top_epilogue(&mut code);
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), 1000)),
        U256::from(998u64)
    );
}

#[test]
fn pc_pushes_program_counter() {
    // PUSH1 0x00 ocupa pc 0..1; PC está en pc=2 y apila 2.
    let mut code = vec![PUSH1, 0x00, PC];
    return_top_epilogue(&mut code);
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), GAS)),
        U256::from(2u64)
    );
}

#[test]
fn msize_reports_memory_size_in_bytes() {
    // MSTORE en 0 expande a una palabra (32 bytes); MSIZE reporta 32.
    let mut code = vec![PUSH1, 0x00, PUSH1, 0x00, MSTORE, MSIZE];
    return_top_epilogue(&mut code);
    assert_eq!(
        returned_word(&run_with_context(context_for(&code), GAS)),
        U256::from(32u64)
    );
}
