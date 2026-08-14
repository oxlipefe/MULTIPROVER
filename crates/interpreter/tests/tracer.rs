//! Golden tests del step-tracer EIP-3155 (`Interpreter::run_traced`, feature
//! `tracer`). Las trazas esperadas se calculan A MANO opcode por opcode.
//! Sin la feature este archivo entero
//! desaparece (`#![cfg(feature = "tracer")]`) — nada que testear, nada que
//! compilar.

#![cfg(feature = "tracer")]

use repo_b_common::primitives::{Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_interpreter::{
    CallContext, Halt, Interpreter, RefundTrackingHost, StepRecord, StepSink,
};

mod support;
use support::NoopHost;

const DUP2: u8 = 0x81;
const SWAP1: u8 = 0x90;

/// `StepSink` que junta cada `StepRecord` en orden — el test compara la
/// secuencia completa contra la traza calculada a mano.
#[derive(Default)]
struct Collector(Vec<StepRecord>);

impl StepSink for Collector {
    fn step(&mut self, record: &StepRecord) {
        self.0.push(record.clone());
    }
}

fn trace(code: &[u8], gas_limit: u64) -> Vec<StepRecord> {
    let mut sink = Collector::default();
    let context = CallContext::for_code(Bytes::copy_from_slice(code));
    let mut tracked = RefundTrackingHost::new(&mut NoopHost);
    Interpreter::new(context, gas_limit, Spec::Prague).run_traced(&mut tracked, &mut sink);
    sink.0
}

// Helper de fixtures de test: un `StepRecord` por golden trace tiene más
// campos que el default de `too_many_arguments`; un builder sería
// sobre-ingeniería para un archivo de tests que solo construye literales.
#[allow(clippy::too_many_arguments)]
fn step(
    pc: usize,
    op: u8,
    op_name: &str,
    gas: u64,
    gas_cost: u64,
    stack: &[u64],
    mem_size: usize,
    error: Option<&'static str>,
) -> StepRecord {
    StepRecord {
        pc,
        op,
        op_name: op_name.to_string(),
        gas,
        gas_cost,
        stack: stack.iter().copied().map(U256::from).collect(),
        depth: 0,
        mem_size,
        refund: 0,
        error,
    }
}

#[test]
fn arithmetic_and_memory_golden_trace() {
    // PUSH1 5, PUSH1 10, ADD, PUSH1 0, MSTORE, STOP.
    let code = [0x60, 0x05, 0x60, 0x0a, 0x01, 0x60, 0x00, 0x52, 0x00];
    let got = trace(&code, 100);

    let expected = vec![
        step(0, 0x60, "PUSH1", 100, 3, &[], 0, None),
        step(2, 0x60, "PUSH1", 97, 3, &[5], 0, None),
        step(4, 0x01, "ADD", 94, 3, &[5, 10], 0, None),
        step(5, 0x60, "PUSH1", 91, 3, &[15], 0, None),
        // MSTORE: G_verylow(3) + expansión de 1 palabra (3·1 + 1²/512 = 3).
        step(7, 0x52, "MSTORE", 88, 6, &[15, 0], 0, None),
        step(8, 0x00, "STOP", 82, 0, &[], 32, None),
    ];
    assert_eq!(got, expected);
}

#[test]
fn jumps_golden_trace() {
    // PUSH1 3, JUMP, JUMPDEST, STOP.
    let code = [0x60, 0x03, 0x56, 0x5b, 0x00];
    let got = trace(&code, 50);

    let expected = vec![
        step(0, 0x60, "PUSH1", 50, 3, &[], 0, None),
        step(2, 0x56, "JUMP", 47, 8, &[3], 0, None),
        step(3, 0x5b, "JUMPDEST", 39, 1, &[], 0, None),
        step(4, 0x00, "STOP", 38, 0, &[], 0, None),
    ];
    assert_eq!(got, expected);
}

#[test]
fn push_dup_swap_golden_trace() {
    // PUSH1 1, PUSH1 2, DUP2, SWAP1, STOP.
    let code = [0x60, 0x01, 0x60, 0x02, DUP2, SWAP1, 0x00];
    let got = trace(&code, 30);

    let expected = vec![
        step(0, 0x60, "PUSH1", 30, 3, &[], 0, None),
        step(2, 0x60, "PUSH1", 27, 3, &[1], 0, None),
        step(4, DUP2, "DUP2", 24, 3, &[1, 2], 0, None),
        step(5, SWAP1, "SWAP1", 21, 3, &[1, 2, 1], 0, None),
        step(6, 0x00, "STOP", 18, 0, &[1, 1, 2], 0, None),
    ];
    assert_eq!(got, expected);
}

#[test]
fn halt_case_golden_trace() {
    // ADD sin operandos: stack underflow DESPUÉS de cobrar `G_verylow`.
    // `gas_cost` es el delta real del paso (3), no el gas que el frame
    // consumirá después por la trichotomy: el spend-all del Halt ocurre tras
    // emitir el record. Es la semántica de EIP-3155 y la del inspector de
    // revm — verificado paso a paso en el diferencial de 004.
    let code = [0x01];
    let got = trace(&code, 10);

    let expected = vec![step(0, 0x01, "ADD", 10, 3, &[], 0, Some("StackUnderflow"))];
    assert_eq!(got, expected);

    // La traza no cambia la semántica: el outcome final sigue siendo el
    // mismo Halt que reportaría `run` (Prohibido del task: el tracer OBSERVA).
    let mut sink = Collector::default();
    let mut tracked = RefundTrackingHost::new(&mut NoopHost);
    let outcome = Interpreter::for_code(Bytes::copy_from_slice(&code), 10, Spec::Prague)
        .run_traced(&mut tracked, &mut sink);
    assert_eq!(
        outcome,
        repo_b_interpreter::InterpreterAction::Return(
            repo_b_interpreter::InterpreterOutcome::Halt {
                reason: Halt::StackUnderflow,
                gas_used: 10,
            }
        )
    );
}
