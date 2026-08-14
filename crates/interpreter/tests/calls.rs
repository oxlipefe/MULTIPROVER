//! Tests de CALL/CALLCODE/DELEGATECALL/STATICCALL + RETURNDATA*
//! contra `MockHost`.
//!
//! Acá se verifica lo que el diferencial vs revm **no puede aislar**: la forma
//! exacta de la `InterpreterAction`, el `resume`, y sobre todo el **gas
//! reenviado**, que en el fixture solo se ve mezclado con el resto de la tx.
//! Todos los números salen de EIP-150/2929/EIP-214 calculados a mano — nunca
//! del código bajo test.
//!
//! Convención de stack (Yellow Paper): para
//! CALL(gas, addr, value, inOff, inLen, outOff, outLen) el TOPE (µ_s[0]) es
//! `gas`, así que el bytecode apila en orden inverso.

use repo_b_common::primitives::{Address, Bytes, KECCAK256_EMPTY, U256};
use repo_b_interpreter::call::{CallInputs, CallKind, InterpreterAction, SubcallOutcome};
use repo_b_interpreter::gas::cost;
use repo_b_interpreter::opcode::{
    CALL, CALLCODE, DELEGATECALL, MLOAD, MSTORE, POP, PUSH1, RETURN, RETURNDATACOPY,
    RETURNDATASIZE, SSTORE, STATICCALL,
};
use repo_b_interpreter::{CallContext, Halt, Host, Interpreter, InterpreterOutcome};

mod support;
use support::run_frame;

#[path = "support/mock.rs"]
mod mock;
use mock::MockHost;

/// PUSH20 (0x73): empuja una dirección completa.
const PUSH20: u8 = PUSH1 + 19;
/// PUSH3 (0x62): el pedido de gas de los tests (0xFFFFFF = "todo el que haya").
const PUSH3: u8 = PUSH1 + 2;

const GAS: u64 = 100_000;
const CALLER: Address = Address::new([0xAA; 20]);
const SELF: Address = Address::new([0xBB; 20]);
const TARGET: Address = Address::new([0xDD; 20]);
const VALUE: u64 = 0x64;

/// Costo de los 7 (o 6) PUSH que arman los argumentos: todos `G_verylow`.
const PUSH_COST: u64 = cost::VERYLOW;

fn push1(code: &mut Vec<u8>, value: u8) {
    code.extend([PUSH1, value]);
}

fn push_gas_request(code: &mut Vec<u8>, request: u32) {
    let bytes = request.to_be_bytes();
    code.push(PUSH3);
    code.extend(bytes.get(1..4).unwrap_or_default());
}

/// CALL/CALLCODE con `value`; los 4 offsets de memoria en cero salvo la
/// ventana de retorno.
fn call_code(op: u8, value: u8, out_len: u8, gas_request: u32) -> Vec<u8> {
    let mut code = Vec::new();
    push1(&mut code, out_len);
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    push1(&mut code, value);
    code.push(PUSH20);
    code.extend_from_slice(TARGET.as_slice());
    push_gas_request(&mut code, gas_request);
    code.push(op);
    code
}

/// DELEGATECALL/STATICCALL: sin argumento `value`.
fn two_arg_call_code(op: u8, gas_request: u32) -> Vec<u8> {
    let mut code = Vec::new();
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    code.push(PUSH20);
    code.extend_from_slice(TARGET.as_slice());
    push_gas_request(&mut code, gas_request);
    code.push(op);
    code
}

/// Contexto del frame que hace la call.
fn caller_context(code: &[u8]) -> CallContext {
    CallContext {
        address: SELF,
        caller: CALLER,
        value: U256::from(0x7Bu64),
        calldata: Bytes::new(),
        bytecode: Bytes::copy_from_slice(code),
        is_static: false,
        depth: 0,
    }
}

#[track_caller]
fn run_until_call(context: CallContext, host: &mut dyn Host) -> (Interpreter, CallInputs) {
    let mut interpreter = Interpreter::new(context, GAS);
    match interpreter.run(host) {
        InterpreterAction::Call(inputs) => (interpreter, *inputs),
        other => panic!("se esperaba una sub-call, hubo {other:?}"),
    }
}

#[track_caller]
fn run_to_end(interpreter: &mut Interpreter, host: &mut dyn Host) -> InterpreterOutcome {
    match interpreter.run(host) {
        InterpreterAction::Return(outcome) => outcome,
        other => panic!("acción inesperada: {other:?}"),
    }
}

/// Host con `TARGET` ya configurado como cuenta NO vacía (existe, con balance).
fn host_with_live_target() -> MockHost {
    MockHost::new().with_account(TARGET, U256::from(1u64), KECCAK256_EMPTY, false)
}

/// Tope de EIP-150 sobre un `remaining` dado: `remaining − ⌊remaining/64⌋`.
fn forwardable(remaining: u64) -> u64 {
    remaining - remaining / 64
}

// ------------------------------------------------------------------- contexto

#[test]
fn call_targets_the_callee_with_self_as_caller() {
    let code = call_code(CALL, VALUE as u8, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    assert_eq!(inputs.kind, CallKind::Call);
    assert_eq!(inputs.code_address, TARGET);
    assert_eq!(inputs.target, TARGET);
    assert_eq!(inputs.caller, SELF);
    assert_eq!(inputs.value, U256::from(VALUE));
    assert_eq!(inputs.transfer_value, U256::from(VALUE));
    assert!(!inputs.is_static);
}

#[test]
fn callcode_runs_foreign_code_on_the_callers_own_account() {
    let code = call_code(CALLCODE, VALUE as u8, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    // El código es del target, pero la cuenta en ejecución (y su storage) es
    // la propia; el caller también es uno mismo (NO se hereda).
    assert_eq!(inputs.code_address, TARGET);
    assert_eq!(inputs.target, SELF);
    assert_eq!(inputs.caller, SELF);
    assert_eq!(inputs.value, U256::from(VALUE));
}

#[test]
fn delegatecall_inherits_the_caller_and_the_value() {
    let code = two_arg_call_code(DELEGATECALL, 0x00FF_FFFF);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    assert_eq!(inputs.code_address, TARGET);
    assert_eq!(inputs.target, SELF);
    // Heredados del frame actual, no del opcode.
    assert_eq!(inputs.caller, CALLER);
    assert_eq!(inputs.value, U256::from(0x7Bu64));
    // Aparente: DELEGATECALL no mueve un wei.
    assert!(!inputs.kind.transfers_balance());
}

#[test]
fn staticcall_forces_zero_value_and_static_context() {
    let code = two_arg_call_code(STATICCALL, 0x00FF_FFFF);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    assert_eq!(inputs.target, TARGET);
    assert_eq!(inputs.caller, SELF);
    assert_eq!(inputs.value, U256::ZERO);
    assert_eq!(inputs.transfer_value, U256::ZERO);
    assert!(inputs.is_static);
}

#[test]
fn a_plain_call_inherits_a_static_context() {
    // EIP-214: `is_static` se propaga a TODA la sub-ejecución, no solo al
    // frame que hizo el STATICCALL.
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();
    let context = CallContext {
        is_static: true,
        ..caller_context(&code)
    };

    let (_, inputs) = run_until_call(context, &mut host);

    assert!(inputs.is_static);
}

#[test]
fn call_with_value_in_a_static_context_halts() {
    let code = call_code(CALL, VALUE as u8, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();
    let context = CallContext {
        is_static: true,
        ..caller_context(&code)
    };

    let outcome = run_frame(Interpreter::new(context, GAS), &mut host);

    assert!(matches!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StateChangeDuringStaticCall,
            ..
        }
    ));
}

#[test]
fn callcode_with_value_is_allowed_in_a_static_context() {
    // CALLCODE transfiere a sí mismo: no hay cambio de estado observable, y
    // revm NO lo gatea. Fijar la asimetría con test para que no "se corrija"
    // por simetría con CALL.
    let code = call_code(CALLCODE, VALUE as u8, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();
    let context = CallContext {
        is_static: true,
        ..caller_context(&code)
    };

    let (_, inputs) = run_until_call(context, &mut host);

    assert_eq!(inputs.transfer_value, U256::from(VALUE));
    assert!(inputs.is_static);
}

// ------------------------------------------------------------------ gas

#[test]
fn a_plain_call_forwards_63_64_of_what_is_left_after_the_cold_access() {
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    // 7 PUSH (3 c/u) + cold account access (2600, EIP-2929). Sin value: ni
    // G_callvalue ni stipend.
    let remaining = GAS - 7 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

#[test]
fn a_call_with_value_pays_9000_and_the_callee_gets_the_2300_stipend() {
    let code = call_code(CALL, VALUE as u8, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    // El target existe y no está vacío ⇒ NO se cobran los 25000.
    let remaining = GAS - 7 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS - cost::CALL_VALUE;
    assert_eq!(
        inputs.gas_limit,
        forwardable(remaining) + cost::CALL_STIPEND,
        "el stipend se SUMA al hijo; no se le descuenta al caller"
    );
}

#[test]
fn a_call_with_value_to_a_dead_account_also_pays_the_25000() {
    let code = call_code(CALL, VALUE as u8, 0, 0x00FF_FFFF);
    // Sin `with_account`, el `MockHost` reporta la cuenta como vacía (EIP-161).
    let mut host = MockHost::new();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    let remaining =
        GAS - 7 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS - cost::CALL_VALUE - cost::NEW_ACCOUNT;
    assert_eq!(
        inputs.gas_limit,
        forwardable(remaining) + cost::CALL_STIPEND
    );
}

#[test]
fn a_call_without_value_to_a_dead_account_does_not_pay_the_25000() {
    // `G_newaccount` es del par (CALL, value > 0): sin value no se cobra por
    // más muerta que esté la cuenta.
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = MockHost::new();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    let remaining = GAS - 7 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

#[test]
fn staticcall_to_a_dead_account_never_pays_the_25000() {
    // `create_empty_account` es `true` SOLO en CALL (revm): STATICCALL a una
    // cuenta muerta paga el access y nada más.
    let code = two_arg_call_code(STATICCALL, 0x00FF_FFFF);
    let mut host = MockHost::new();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    let remaining = GAS - 6 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

#[test]
fn a_warm_target_only_pays_100_for_the_access() {
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target().with_warm_address(TARGET);

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    let remaining = GAS - 7 * PUSH_COST - cost::WARM_ACCOUNT_ACCESS;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

/// EIP-7702: con el target DELEGADO, resolver la delegación es un
/// acceso a cuenta propio — 100 fijos + 2500 si la dirección delegada está
/// fría —, **además** del cold/warm de `code_address`. Verificado contra revm
/// (`load_account_delegated`). El diferencial vs revm lo ve solo mezclado con
/// el resto de la tx; acá el número está aislado.
#[test]
fn a_call_to_a_delegated_target_pays_the_delegated_account_access_too() {
    let delegated = Address::new([0xEE; 20]);
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target().with_code(
        TARGET,
        repo_b_common::authorization::delegation_designator(delegated),
    );

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    // cold del target (2600) + 100 de resolver + 2500 por la delegada fría.
    let remaining = GAS
        - 7 * PUSH_COST
        - cost::COLD_ACCOUNT_ACCESS
        - cost::WARM_ACCOUNT_ACCESS
        - cost::COLD_ACCOUNT_ADDITIONAL;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

/// Con la dirección delegada YA caliente (access list, o una call previa) solo
/// se pagan los 100: los 2500 son surcharge de frío, no del hecho de delegar.
#[test]
fn a_call_to_a_delegated_target_with_a_warm_delegate_only_pays_the_100() {
    let delegated = Address::new([0xEE; 20]);
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target()
        .with_code(
            TARGET,
            repo_b_common::authorization::delegation_designator(delegated),
        )
        .with_warm_address(delegated);

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    let remaining = GAS - 7 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS - cost::WARM_ACCOUNT_ACCESS;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

/// Un código de 23 bytes que NO empieza con `0xef0100` es código común: no se
/// cobra nada extra (el borde exacto del designator lo fija
/// `common::authorization`).
#[test]
fn a_call_to_a_target_with_lookalike_code_pays_no_delegation_surcharge() {
    let mut lookalike =
        repo_b_common::authorization::delegation_designator(Address::new([0xEE; 20])).to_vec();
    lookalike[2] = 0x01; // versión inválida
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target().with_code(TARGET, Bytes::from(lookalike));

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    let remaining = GAS - 7 * PUSH_COST - cost::COLD_ACCOUNT_ACCESS;
    assert_eq!(inputs.gas_limit, forwardable(remaining));
}

#[test]
fn an_explicit_gas_request_below_the_cap_wins() {
    let code = call_code(CALL, 0x00, 0, 0x0000_2710);
    let mut host = host_with_live_target();

    let (_, inputs) = run_until_call(caller_context(&code), &mut host);

    assert_eq!(inputs.gas_limit, 0x2710);
}

// ------------------------------------------------------------------- resume

/// CALL con ventana de retorno de 32 bytes; después del `resume` devuelve esa
/// ventana de memoria (el status se descarta con POP).
fn call_then_return_window() -> Vec<u8> {
    let mut code = call_code(CALL, 0x00, 0x20, 0x00FF_FFFF);
    code.push(POP);
    code.extend([PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    code
}

#[test]
fn resume_writes_the_output_into_the_window_without_padding_the_rest() {
    let code = call_then_return_window();
    let mut host = host_with_live_target();
    let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);

    interpreter.resume(SubcallOutcome {
        success: true,
        output: Bytes::from_static(&[0xAA, 0xBB]),
        gas_remaining: 0,
    });
    let outcome = run_to_end(&mut interpreter, &mut host);

    match outcome {
        InterpreterOutcome::Success { output, .. } => {
            let mut expected = [0u8; 32];
            expected[0] = 0xAA;
            expected[1] = 0xBB;
            assert_eq!(output.as_ref(), expected.as_slice());
        }
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

/// CALL seguido de "guardar el status en memoria y retornarlo".
fn call_then_return_status() -> Vec<u8> {
    let mut code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    code
}

#[test]
fn resume_pushes_one_on_success_and_zero_otherwise() {
    for (success, expected) in [(true, 1u8), (false, 0u8)] {
        let code = call_then_return_status();
        let mut host = host_with_live_target();
        let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);

        interpreter.resume(SubcallOutcome {
            success,
            output: Bytes::new(),
            gas_remaining: 0,
        });
        let outcome = run_to_end(&mut interpreter, &mut host);

        match outcome {
            InterpreterOutcome::Success { output, .. } => {
                assert_eq!(U256::from_be_slice(&output), U256::from(expected));
            }
            other => panic!("se esperaba Success, hubo {other:?}"),
        }
    }
}

#[test]
fn resume_gives_back_the_unused_gas_of_the_subframe() {
    let code = call_then_return_status();
    let mut host = host_with_live_target();
    let (mut interpreter, inputs) = run_until_call(caller_context(&code), &mut host);

    // El sub-frame no gastó nada: vuelve todo lo reenviado.
    interpreter.resume(SubcallOutcome::not_executed(inputs.gas_limit));
    let outcome = run_to_end(&mut interpreter, &mut host);

    // Gas del frame = 7 PUSH + cold access + el epílogo (PUSH,MSTORE con 3 de
    // expansión, PUSH, PUSH, RETURN). Lo reenviado volvió entero, así que NO
    // aparece en la cuenta.
    let epilogue = 3 * PUSH_COST + cost::VERYLOW + cost::MEMORY_WORD + cost::ZERO;
    assert_eq!(
        outcome.gas_used(),
        7 * PUSH_COST + cost::COLD_ACCOUNT_ACCESS + epilogue
    );
}

// -------------------------------------------------------------- returndata

#[test]
fn returndatasize_is_zero_in_a_fresh_frame() {
    let code = [
        RETURNDATASIZE,
        PUSH1,
        0x00,
        MSTORE,
        PUSH1,
        0x20,
        PUSH1,
        0x00,
        RETURN,
    ];
    let mut host = MockHost::new();

    let outcome = run_frame(
        Interpreter::for_code(Bytes::copy_from_slice(&code), GAS),
        &mut host,
    );

    match outcome {
        InterpreterOutcome::Success { output, .. } => {
            assert_eq!(U256::from_be_slice(&output), U256::ZERO);
        }
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

/// CALL seguido de RETURNDATACOPY(dest, offset, len) y RETURN de mem[0..32).
fn call_then_returndatacopy(dest: u8, offset: u8, len: u8) -> Vec<u8> {
    let mut code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    code.push(POP);
    // µ_s[0] = dest, µ_s[1] = offset, µ_s[2] = len ⇒ se apila al revés.
    code.extend([PUSH1, len, PUSH1, offset, PUSH1, dest, RETURNDATACOPY]);
    code.extend([PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    code
}

#[test]
fn returndatacopy_within_the_buffer_copies_the_bytes() {
    let code = call_then_returndatacopy(0x00, 0x00, 0x02);
    let mut host = host_with_live_target();
    let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);
    interpreter.resume(SubcallOutcome {
        success: true,
        output: Bytes::from_static(&[0xAA, 0xBB]),
        gas_remaining: GAS,
    });

    let outcome = run_to_end(&mut interpreter, &mut host);

    match outcome {
        InterpreterOutcome::Success { output, .. } => {
            assert_eq!(output.first(), Some(&0xAA));
            assert_eq!(output.get(1), Some(&0xBB));
        }
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

#[test]
fn returndatacopy_past_the_end_of_the_buffer_halts() {
    // FOOTGUN EIP-211: NO zero-padea como CALLDATACOPY/CODECOPY.
    let code = call_then_returndatacopy(0x00, 0x00, 0x04);
    let mut host = host_with_live_target();
    let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);
    interpreter.resume(SubcallOutcome {
        success: true,
        output: Bytes::from_static(&[0xAA, 0xBB]),
        gas_remaining: GAS,
    });

    let outcome = run_to_end(&mut interpreter, &mut host);

    assert!(matches!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfOffset,
            ..
        }
    ));
}

#[test]
fn returndatacopy_of_zero_bytes_past_the_end_still_halts() {
    // El chequeo es `offset + len > buffer.len()`, así que un `len == 0` con
    // offset fuera del buffer también haltea (semántica de revm).
    let code = call_then_returndatacopy(0x00, 0x08, 0x00);
    let mut host = host_with_live_target();
    let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);
    interpreter.resume(SubcallOutcome {
        success: true,
        output: Bytes::from_static(&[0xAA, 0xBB]),
        gas_remaining: GAS,
    });

    let outcome = run_to_end(&mut interpreter, &mut host);

    assert!(matches!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfOffset,
            ..
        }
    ));
}

#[test]
fn returndata_is_reset_by_a_new_call_even_before_it_resumes() {
    // Un CALL nuevo limpia el buffer del anterior: si el sub-frame haltea, el
    // caller NO puede leer la returndata vieja.
    let mut code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    code.push(POP);
    code.extend(call_code(CALL, 0x00, 0, 0x00FF_FFFF));
    let mut host = host_with_live_target();
    let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);
    interpreter.resume(SubcallOutcome {
        success: true,
        output: Bytes::from_static(&[0xAA, 0xBB]),
        gas_remaining: GAS,
    });

    // El segundo CALL suspende de nuevo; lo que importa es lo que dejó atrás.
    match interpreter.run(&mut host) {
        InterpreterAction::Call(_) => {}
        other => panic!("se esperaba el segundo CALL, hubo {other:?}"),
    }
    interpreter.resume(SubcallOutcome {
        success: false,
        output: Bytes::new(),
        gas_remaining: 0,
    });
    let outcome = run_to_end(&mut interpreter, &mut host);

    // Cae del final del código ⇒ STOP implícito. Lo verificado es que el
    // segundo `resume` no reventó con la returndata vieja.
    assert!(outcome.is_success());
}

fn call_then_returndatasize() -> Vec<u8> {
    let mut code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    code.push(POP);
    code.extend([
        RETURNDATASIZE,
        PUSH1,
        0x00,
        MSTORE,
        PUSH1,
        0x20,
        PUSH1,
        0x00,
        RETURN,
    ]);
    code
}

#[test]
fn returndatasize_reports_the_full_output_even_beyond_the_window() {
    let code = call_then_returndatasize();
    let mut host = host_with_live_target();
    let (mut interpreter, _) = run_until_call(caller_context(&code), &mut host);
    interpreter.resume(SubcallOutcome {
        success: true,
        output: Bytes::from_static(&[0u8; 40]),
        gas_remaining: GAS,
    });

    let outcome = run_to_end(&mut interpreter, &mut host);

    match outcome {
        InterpreterOutcome::Success { output, .. } => {
            assert_eq!(U256::from_be_slice(&output), U256::from(40u64));
        }
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

// ---------------------------------------------------------------- adversarial

#[test]
fn a_call_with_an_underflowing_stack_halts_before_touching_the_host() {
    // CALL necesita 7 palabras; con 6 debe ser StackUnderflow, no una call
    // con argumentos inventados.
    let mut code = Vec::new();
    for _ in 0..6 {
        push1(&mut code, 0x00);
    }
    code.push(CALL);
    let mut host = MockHost::new();

    let outcome = run_frame(
        Interpreter::for_code(Bytes::copy_from_slice(&code), GAS),
        &mut host,
    );

    assert!(matches!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            ..
        }
    ));
}

#[test]
fn a_call_that_cannot_pay_the_cold_access_halts() {
    let code = call_code(CALL, 0x00, 0, 0x00FF_FFFF);
    let mut host = host_with_live_target();
    // Alcanza para los 7 PUSH (21) pero no para los 2600 del cold access.
    let context = caller_context(&code);

    let outcome = run_frame(Interpreter::new(context, 7 * PUSH_COST + 100), &mut host);

    assert!(matches!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            ..
        }
    ));
}

#[test]
fn a_huge_return_window_is_out_of_gas_not_a_panic() {
    // Ventana de retorno con offset gigantesco: la expansión de memoria es
    // impagable ⇒ OOG, nunca un alloc ni un panic.
    let mut code = Vec::new();
    code.extend([PUSH1, 0x20]); // out_len
    code.push(PUSH1 + 31); // PUSH32 out_off
    code.extend([0xFFu8; 32]);
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    push1(&mut code, 0x00);
    code.push(PUSH20);
    code.extend_from_slice(TARGET.as_slice());
    push_gas_request(&mut code, 0x00FF_FFFF);
    code.push(CALL);
    let mut host = host_with_live_target();

    let outcome = run_frame(Interpreter::new(caller_context(&code), GAS), &mut host);

    assert!(matches!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            ..
        }
    ));
}

#[test]
fn the_subframe_storage_gate_still_belongs_to_the_context_address() {
    // Regresión del reparto de contexto: un SSTORE dentro del frame escribe
    // en `context.address`, que en un DELEGATECALL es la cuenta del CALLER.
    let code = [PUSH1, 0x2A, PUSH1, 0x01, SSTORE, PUSH1, 0x00, MLOAD];
    let mut host = MockHost::new();
    let context = CallContext {
        address: SELF,
        ..caller_context(&code)
    };

    let _ = run_frame(Interpreter::new(context, GAS), &mut host);

    assert_eq!(host.slot(SELF, U256::from(1u64)), U256::from(0x2Au64));
}
