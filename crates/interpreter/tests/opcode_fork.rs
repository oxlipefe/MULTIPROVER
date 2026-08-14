//! Gating de opcodes y de EIP-3860 por fork.
//!
//! El intérprete no sabía en qué fork corría, así que ejecutaba opcodes que no
//! existían todavía y cobraba EIP-3860 en Paris. Un opcode no activo **haltea
//! con `OpcodeNotFound`** y consume TODO el gas — no es un revert ni un no-op.

use repo_b_common::primitives::Bytes;
use repo_b_common::spec::Spec;
use repo_b_interpreter::opcode::{POP, PUSH0, PUSH1, STOP};
use repo_b_interpreter::{Halt, Interpreter, InterpreterAction, InterpreterOutcome};

mod support;
use support::{NoopHost, run_frame};

const BLOBBASEFEE: u8 = 0x4A;
const BLOBHASH: u8 = 0x49;
const MCOPY: u8 = 0x5E;
const TLOAD: u8 = 0x5C;
const TSTORE: u8 = 0x5D;
const GAS: u64 = 100_000;

fn run_at(code: &[u8], spec: Spec) -> InterpreterOutcome {
    run_frame(
        Interpreter::for_code(Bytes::copy_from_slice(code), GAS, spec),
        &mut NoopHost,
    )
}

fn halts_as_unknown_opcode(outcome: &InterpreterOutcome) -> bool {
    matches!(outcome, InterpreterOutcome::Halt { reason, .. } if *reason == Halt::OpcodeNotFound)
}

/// Tabla del gating: cada opcode con su fork de activación y un programa
/// mínimo que lo ejecuta. **Antes de su fork haltea; desde su fork, no.**
fn cases() -> [(&'static str, Spec, Vec<u8>); 6] {
    [
        ("PUSH0", Spec::Shanghai, vec![PUSH0, POP, STOP]),
        ("TLOAD", Spec::Cancun, vec![PUSH1, 0x00, TLOAD, POP, STOP]),
        (
            "TSTORE",
            Spec::Cancun,
            vec![PUSH1, 0x01, PUSH1, 0x00, TSTORE, STOP],
        ),
        (
            "MCOPY",
            Spec::Cancun,
            vec![PUSH1, 0x20, PUSH1, 0x00, PUSH1, 0x20, MCOPY, STOP],
        ),
        (
            "BLOBHASH",
            Spec::Cancun,
            vec![PUSH1, 0x00, BLOBHASH, POP, STOP],
        ),
        ("BLOBBASEFEE", Spec::Cancun, vec![BLOBBASEFEE, POP, STOP]),
    ]
}

#[test]
fn an_opcode_before_its_fork_halts_as_unknown() {
    for (name, activated_in, code) in cases() {
        for spec in [Spec::Paris, Spec::Shanghai, Spec::Cancun, Spec::Prague] {
            let outcome = run_at(&code, spec);
            if spec >= activated_in {
                assert!(
                    !halts_as_unknown_opcode(&outcome),
                    "{name} existe en {spec:?} y no debería haltear por desconocido"
                );
            } else {
                assert!(
                    halts_as_unknown_opcode(&outcome),
                    "{name} NO existe en {spec:?}: tiene que haltear con OpcodeNotFound"
                );
            }
        }
    }
}

/// EIP-3860 (Shanghai): el costo por palabra de initcode en CREATE/CREATE2.
/// **Es el bug que costó 66 casos**, y no cambia ningún resultado: solo el gas.
/// Por eso se mide observando el gas REENVIADO al sub-frame (63/64 de lo que
/// queda), no mirando el output — que es idéntico en los dos forks.
#[test]
fn the_initcode_word_cost_is_only_charged_from_shanghai() {
    const CREATE: u8 = 0xF0;
    // len = 0x40 = 64 bytes = 2 palabras de initcode.
    let code = vec![
        PUSH1, 0x40, // len
        PUSH1, 0x00, // offset
        PUSH1, 0x00, // value
        CREATE, POP, STOP,
    ];
    let paris = forwarded_gas(&code, Spec::Paris);
    let shanghai = forwarded_gas(&code, Spec::Shanghai);
    assert!(
        paris > shanghai,
        "Shanghai cobra 2 gas por palabra de initcode y Paris no, \
         así que a Shanghai le queda MENOS para reenviar"
    );
    // 2 palabras × INITCODE_WORD(2) = 4 gas de diferencia en lo que queda; el
    // 63/64 de EIP-150 se lleva una fracción, así que el reenviado difiere en
    // 4 menos lo que absorba el floor.
    assert_eq!(paris - shanghai, 4, "2 palabras × 2 gas");
}

/// Corre hasta que el frame abra el CREATE y devuelve el gas reenviado.
fn forwarded_gas(code: &[u8], spec: Spec) -> u64 {
    let mut interpreter = Interpreter::for_code(Bytes::copy_from_slice(code), GAS, spec);
    match interpreter.run(&mut NoopHost) {
        InterpreterAction::Create(inputs) => inputs.gas_limit,
        other => panic!("se esperaba que el frame abriera un CREATE, no {other:?}"),
    }
}
