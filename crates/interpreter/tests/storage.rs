//! Tests del seam `Host` (subset storage): SLOAD/SSTORE/
//! TLOAD/TSTORE contra `MockHost`. Los números de gas/refund de los asserts
//! salen de EIP-2929/2200/3529/1153 calculados a mano — no del código bajo
//! test (weakening-the-test vetado).
//!
//! Convención de stack (Yellow Paper, igual que `tests/programs.rs`): para
//! SSTORE(key, value) el TOPE (µ_s[0]) es `key`, por eso el `value` se apila
//! primero.

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_interpreter::gas::cost;
use repo_b_interpreter::opcode::{MSTORE, PUSH1, RETURN, SLOAD, SSTORE, TLOAD, TSTORE};
use repo_b_interpreter::{CallContext, Halt, Host, Interpreter, InterpreterOutcome};

mod support;
use support::{NoopHost, run_frame};

#[path = "support/mock.rs"]
mod mock;
use mock::MockHost;

const GAS: u64 = 100_000;
const KEY: u8 = 9;

fn run_program(code: &[u8], gas_limit: u64, host: &mut dyn Host) -> InterpreterOutcome {
    run_frame(
        Interpreter::for_code(Bytes::copy_from_slice(code), gas_limit, Spec::Prague),
        host,
    )
}

fn run_static(code: &[u8], gas_limit: u64, host: &mut dyn Host) -> InterpreterOutcome {
    let context = CallContext {
        is_static: true,
        ..CallContext::for_code(Bytes::copy_from_slice(code))
    };
    run_frame(Interpreter::new(context, gas_limit, Spec::Prague), host)
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

// -------------------------------------------------------------- matriz SSTORE

/// Un caso de la matriz EIP-2200/2929/3529: estado del slot antes del SSTORE
/// bajo test (`original`/`current`), el valor escrito (`new`), si el acceso
/// es frío, y lo esperado (costo del SSTORE en sí — sin los 2 PUSH1 previos —
/// y la secuencia de llamadas a `refund`).
struct SstoreCase {
    name: &'static str,
    original: u64,
    current: u64,
    new: u64,
    is_cold: bool,
    expected_cost: u64,
    expected_refunds: &'static [i64],
}

const SSTORE_MATRIX: &[SstoreCase] = &[
    // --- limpio (current == original): primer SSTORE del slot en la tx ---
    SstoreCase {
        name: "clean 0->0->0: no-op, base warm",
        original: 0,
        current: 0,
        new: 0,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[],
    },
    SstoreCase {
        name: "clean 0->0->5: set desde cero",
        original: 0,
        current: 0,
        new: 5,
        is_cold: false,
        expected_cost: cost::SSTORE_SET,
        expected_refunds: &[],
    },
    SstoreCase {
        name: "clean 5->5->5: no-op sobre slot ocupado",
        original: 5,
        current: 5,
        new: 5,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[],
    },
    SstoreCase {
        name: "clean 5->5->0: libera el slot, refund CLEARS",
        original: 5,
        current: 5,
        new: 0,
        is_cold: false,
        expected_cost: cost::SSTORE_RESET,
        expected_refunds: &[4800],
    },
    SstoreCase {
        name: "clean 5->5->8: reset a otro valor no-cero, sin refund",
        original: 5,
        current: 5,
        new: 8,
        is_cold: false,
        expected_cost: cost::SSTORE_RESET,
        expected_refunds: &[],
    },
    // --- dirty (current != original): no es el primer SSTORE de la tx ---
    SstoreCase {
        name: "dirty 0->5->0: deshace un set-desde-cero, refund SET_UNDO",
        original: 0,
        current: 5,
        new: 0,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[19900],
    },
    SstoreCase {
        name: "dirty 0->5->8: dirty sin volver al original, sin refund",
        original: 0,
        current: 5,
        new: 8,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[],
    },
    SstoreCase {
        name: "dirty 5->0->0: no-op dirty, refunds CLEARS se cancelan",
        original: 5,
        current: 0,
        new: 0,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[-4800, 4800],
    },
    SstoreCase {
        name: "dirty 5->0->5: vuelve al original no-cero, refund RESET_UNDO",
        original: 5,
        current: 0,
        new: 5,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[-4800, 2800],
    },
    SstoreCase {
        name: "dirty 5->8->0: limpia un slot ya-dirty, refund CLEARS",
        original: 5,
        current: 8,
        new: 0,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[4800],
    },
    SstoreCase {
        name: "dirty 5->8->5: vuelve al original no-cero, refund RESET_UNDO",
        original: 5,
        current: 8,
        new: 5,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[2800],
    },
    SstoreCase {
        name: "dirty 0->8->8: no-op dirty sobre un slot que nació en cero",
        original: 0,
        current: 8,
        new: 8,
        is_cold: false,
        expected_cost: cost::WARM_ACCESS,
        expected_refunds: &[],
    },
    // --- las mismas reglas de base, pero con el surcharge cold (EIP-2929) ---
    SstoreCase {
        name: "cold 0->0->5: set desde cero, primer acceso al slot",
        original: 0,
        current: 0,
        new: 5,
        is_cold: true,
        expected_cost: cost::SSTORE_SET + cost::COLD_SLOAD,
        expected_refunds: &[],
    },
    SstoreCase {
        name: "cold 5->5->0: libera el slot en su primer acceso",
        original: 5,
        current: 5,
        new: 0,
        is_cold: true,
        expected_cost: cost::SSTORE_RESET + cost::COLD_SLOAD,
        expected_refunds: &[4800],
    },
];

#[test]
fn sstore_matrix_charges_exact_gas_and_records_refunds() {
    for case in SSTORE_MATRIX {
        let addr = Address::ZERO;
        let key = U256::from(KEY);
        let mut host = MockHost::new().with_slot(
            addr,
            key,
            U256::from(case.original),
            U256::from(case.current),
        );
        if !case.is_cold {
            host = host.with_warm(addr, key);
        }
        let code = [PUSH1, case.new as u8, PUSH1, KEY, SSTORE];
        let outcome = run_program(&code, GAS, &mut host);
        // 2 PUSH1 (VERYLOW=3 c/u) antes del SSTORE bajo test.
        let expected_gas_used = 2 * cost::VERYLOW + case.expected_cost;
        assert_eq!(
            outcome,
            InterpreterOutcome::Success {
                output: Bytes::new(),
                gas_used: expected_gas_used,
            },
            "caso: {}",
            case.name
        );
        assert_eq!(host.refunds(), case.expected_refunds, "caso: {}", case.name);
    }
}

// ------------------------------------------------------------- sentry EIP-2200

#[test]
fn sstore_sentry_halts_at_exactly_2300_gas_remaining() {
    // 2 PUSH1 (3 c/u) + el límite deja exactamente 2300 de remaining al
    // llegar a SSTORE: el sentry haltea ANTES de tocar stack o estado.
    let gas_limit = 2 * cost::VERYLOW + cost::SSTORE_SENTRY;
    let code = [PUSH1, 5, PUSH1, KEY, SSTORE];
    let outcome = run_program(&code, gas_limit, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: gas_limit,
        }
    );
}

#[test]
fn sstore_sentry_allows_2301_gas_remaining() {
    // Un gas más que el umbral: el sentry deja pasar y el SSTORE (no-op
    // limpio, base warm) se cobra normalmente.
    let gas_limit = 2 * cost::VERYLOW + cost::SSTORE_SENTRY + 1;
    let addr = Address::ZERO;
    let key = U256::from(KEY);
    let mut host = MockHost::new()
        .with_slot(addr, key, U256::ZERO, U256::ZERO)
        .with_warm(addr, key);
    let code = [PUSH1, 0, PUSH1, KEY, SSTORE];
    let outcome = run_program(&code, gas_limit, &mut host);
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 2 * cost::VERYLOW + cost::WARM_ACCESS,
        }
    );
}

// -------------------------------------------------------------- static gate

#[test]
fn sstore_in_static_context_halts_without_touching_host() {
    let code = [PUSH1, 5, PUSH1, KEY, SSTORE];
    // `NoopHost` panicaría si algo lo llamara — el gate de static debe
    // haltear ANTES de popear stack o tocar el host.
    let outcome = run_static(&code, GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StateChangeDuringStaticCall,
            gas_used: GAS,
        }
    );
}

#[test]
fn tstore_in_static_context_halts() {
    let code = [PUSH1, 5, PUSH1, KEY, TSTORE];
    let outcome = run_static(&code, GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StateChangeDuringStaticCall,
            gas_used: GAS,
        }
    );
}

// ---------------------------------------------------------------------- SLOAD

#[test]
fn sload_cold_then_warm_in_the_same_run() {
    // Mismo slot, dos SLOAD en el mismo run: el primero es frío (2100), el
    // `MockHost` lo deja warm para el segundo (100) — sin tracking en el
    // intérprete (lo decide el host).
    let mut host = MockHost::new();
    let code = [PUSH1, KEY, SLOAD, PUSH1, 0x00, MSTORE, PUSH1, KEY, SLOAD];
    let outcome = run_program(&code, GAS, &mut host);
    // PUSH1(3) + SLOAD cold(2100) + PUSH1(3) + MSTORE(3+3 expansión) +
    // PUSH1(3) + SLOAD warm(100) = 2215.
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 2215,
        }
    );
}

#[test]
fn sload_reads_the_current_value_from_the_host() {
    let addr = Address::ZERO;
    let key = U256::from(KEY);
    let mut host = MockHost::new().with_slot(addr, key, U256::from(0u64), U256::from(42u64));
    let mut code = vec![PUSH1, KEY, SLOAD];
    return_top_epilogue(&mut code);
    let outcome = run_program(&code, GAS, &mut host);
    assert_eq!(returned_word(&outcome), U256::from(42u64));
}

#[test]
fn sload_out_of_gas_on_cold_cost_halts() {
    // Alcanza para el PUSH1 pero no para el surcharge cold (2100).
    let gas_limit = cost::VERYLOW + cost::COLD_SLOAD - 1;
    let code = [PUSH1, KEY, SLOAD];
    let outcome = run_program(&code, gas_limit, &mut MockHost::new());
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: gas_limit,
        }
    );
}

#[test]
fn sstore_out_of_gas_on_cold_cost_after_sentry_passes() {
    // El sentry (>2300) pasa, pero el costo real (SET=20000 + cold=2100)
    // no entra en el remaining — el sentry NO es suficiente garantía de que
    // el costo completo se pueda pagar.
    let gas_limit = 2 * cost::VERYLOW + cost::SSTORE_SENTRY + 1;
    let code = [PUSH1, 5, PUSH1, KEY, SSTORE]; // 0->0->5, cold ⇒ SET+COLD_SLOAD.
    let outcome = run_program(&code, gas_limit, &mut MockHost::new());
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: gas_limit,
        }
    );
}

#[test]
fn sload_on_empty_stack_underflows() {
    let outcome = run_program(&[SLOAD], GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS,
        }
    );
}

#[test]
fn sstore_on_empty_stack_underflows() {
    let outcome = run_program(&[SSTORE], GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS,
        }
    );
}

#[test]
fn sstore_with_a_single_stack_item_underflows() {
    let code = [PUSH1, KEY, SSTORE];
    let outcome = run_program(&code, GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS,
        }
    );
}

// ------------------------------------------------------------ TLOAD / TSTORE

#[test]
fn tload_on_empty_stack_underflows() {
    let outcome = run_program(&[TLOAD], GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS,
        }
    );
}

#[test]
fn tstore_on_empty_stack_underflows() {
    let outcome = run_program(&[TSTORE], GAS, &mut NoopHost);
    assert_eq!(
        outcome,
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS,
        }
    );
}

#[test]
fn tload_of_untouched_key_is_zero() {
    let mut code = vec![PUSH1, KEY, TLOAD];
    return_top_epilogue(&mut code);
    let outcome = run_program(&code, GAS, &mut MockHost::new());
    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn tstore_then_tload_roundtrips_the_value() {
    let mut host = MockHost::new();
    let mut code = vec![PUSH1, 0x2A, PUSH1, KEY, TSTORE, PUSH1, KEY, TLOAD];
    return_top_epilogue(&mut code);
    let outcome = run_program(&code, GAS, &mut host);
    assert_eq!(returned_word(&outcome), U256::from(0x2Au64));
}

#[test]
fn tload_and_tstore_cost_the_fixed_warm_access_no_cold_warm_tracking() {
    let code = [PUSH1, 5, PUSH1, KEY, TSTORE];
    let outcome = run_program(&code, GAS, &mut MockHost::new());
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: 2 * cost::VERYLOW + cost::WARM_ACCESS,
        }
    );

    let code = [PUSH1, KEY, TLOAD];
    let outcome = run_program(&code, GAS, &mut MockHost::new());
    assert_eq!(
        outcome,
        InterpreterOutcome::Success {
            output: Bytes::new(),
            gas_used: cost::VERYLOW + cost::WARM_ACCESS,
        }
    );
}

#[test]
fn tstore_never_calls_refund() {
    let mut host = MockHost::new();
    let code = [PUSH1, 5, PUSH1, KEY, TSTORE];
    let outcome = run_program(&code, GAS, &mut host);
    assert!(outcome.is_success());
    assert!(host.refunds().is_empty());
}
