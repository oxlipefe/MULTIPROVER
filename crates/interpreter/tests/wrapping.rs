//! Property test del gate de Fase 1: "la aritmética U256 wrappea como la
//! spec" (PRODUCTION_PLAN §Fase 1).
//!
//! La referencia es INDEPENDIENTE del motor: cada binop se ejecuta como
//! programa completo a través de `Interpreter::run` y se compara contra
//! aritmética exacta en U512 reducida mod 2^256. Así el test detecta tanto un
//! wrapping mal heredado como un opcode que corrompa stack/memoria/output.

use alloy_primitives::{Bytes, U256, U512};
use proptest::prelude::*;
use repo_b_interpreter::opcode::{ADD, MSTORE, MUL, PUSH1, PUSH32, RETURN, SUB};
use repo_b_interpreter::{Interpreter, InterpreterOutcome};

const GAS: u64 = 1_000_000;

fn wide(v: U256) -> U512 {
    U512::from_be_slice(&v.to_be_bytes::<32>())
}

/// Reducción mod 2^256: los 32 bytes bajos del valor de 512 bits.
fn low_256(v: U512) -> U256 {
    let bytes = v.to_be_bytes::<64>();
    U256::from_be_slice(&bytes[32..])
}

/// Ejecuta `top OP second` (µ_s[0] = tope) como programa y devuelve la
/// palabra retornada.
fn run_binop(op: u8, top: U256, second: U256) -> U256 {
    let mut code = vec![PUSH32];
    code.extend(second.to_be_bytes::<32>());
    code.push(PUSH32);
    code.extend(top.to_be_bytes::<32>());
    code.push(op);
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, RETURN]);
    match Interpreter::for_code(Bytes::from(code), GAS).run() {
        InterpreterOutcome::Success { output, .. } => U256::from_be_slice(&output),
        other => panic!("el programa binop debe terminar en Success, hubo {other:?}"),
    }
}

fn u256(bytes: [u8; 32]) -> U256 {
    U256::from_be_bytes(bytes)
}

proptest! {
    /// ADD(a, b) ≡ (a + b) mod 2^256, con a = tope.
    #[test]
    fn add_wraps_like_the_spec(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let (a, b) = (u256(a), u256(b));
        // En U512 la suma de dos valores < 2^256 no desborda.
        prop_assert_eq!(run_binop(ADD, a, b), low_256(wide(a) + wide(b)));
    }

    /// MUL(a, b) ≡ (a · b) mod 2^256.
    #[test]
    fn mul_wraps_like_the_spec(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let (a, b) = (u256(a), u256(b));
        // (2^256 − 1)² < 2^512: el producto exacto entra en U512.
        prop_assert_eq!(run_binop(MUL, a, b), low_256(wide(a) * wide(b)));
    }

    /// SUB(a, b) ≡ (a − b) mod 2^256, con a = tope (µ_s[0] − µ_s[1]).
    #[test]
    fn sub_wraps_like_the_spec(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let (a, b) = (u256(a), u256(b));
        // Referencia sin underflow: a + 2^256 − b, reducido mod 2^256.
        let reference = low_256((U512::from(1u8) << 256) + wide(a) - wide(b));
        prop_assert_eq!(run_binop(SUB, a, b), reference);
    }
}
