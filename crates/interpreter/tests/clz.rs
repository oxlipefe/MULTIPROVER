//! EIP-7939 — CLZ (`0x1e`) desde Osaka.

use repo_b_common::primitives::{Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_interpreter::opcode::{CLZ, MSTORE, PUSH0, PUSH1, PUSH32, RETURN, STOP};
use repo_b_interpreter::{Halt, Interpreter, InterpreterOutcome};

mod support;
use support::{NoopHost, run_frame};

const GAS: u64 = 100_000;

fn run(code: &[u8], gas: u64) -> InterpreterOutcome {
    run_frame(
        Interpreter::for_code(Bytes::copy_from_slice(code), gas, Spec::Osaka),
        &mut NoopHost,
    )
}

fn clz_word(word: [u8; 32]) -> (U256, u64) {
    let mut code = vec![PUSH32];
    code.extend(word);
    code.extend([CLZ, PUSH0, MSTORE, PUSH1, 0x20, PUSH0, RETURN]);
    match run(&code, GAS) {
        InterpreterOutcome::Success { output, gas_used } => {
            (U256::from_be_slice(&output), gas_used)
        }
        other => panic!("CLZ tenía que terminar en éxito, no {other:?}"),
    }
}

#[test]
fn clz_covers_zero_msb_lsb_and_an_intermediate_bit() {
    let zero = [0u8; 32];
    let mut msb = [0u8; 32];
    msb[0] = 0x80;
    let mut lsb = [0u8; 32];
    lsb[31] = 0x01;
    let mut middle = [0u8; 32];
    middle[8] = 0x10; // 8 bytes + 3 bits antes del primer uno = 67.

    assert_eq!(clz_word(zero).0, U256::from(256u64));
    assert_eq!(clz_word(msb).0, U256::ZERO);
    assert_eq!(clz_word(lsb).0, U256::from(255u64));
    assert_eq!(clz_word(middle).0, U256::from(67u64));
}

#[test]
fn clz_costs_exactly_five_gas() {
    // PUSH0(2) + CLZ(5) + STOP(0).
    assert_eq!(run(&[PUSH0, CLZ, STOP], 7).gas_used(), 7);
    assert_eq!(
        run(&[PUSH0, CLZ, STOP], 6),
        InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: 6,
        }
    );
}

#[test]
fn clz_on_an_empty_stack_underflows_after_charging() {
    assert_eq!(
        run(&[CLZ], GAS),
        InterpreterOutcome::Halt {
            reason: Halt::StackUnderflow,
            gas_used: GAS,
        }
    );
}
