//! La **métrica de cobertura**, que es lo que separa una campaña de un
//! `[SAME]` que no prueba nada.
//!
//! La regla: un fuzzer roto y un fuzzer sobre un motor limpio producen
//! exactamente el mismo output, así que "0 divergencias" no se puede leer sin
//! dos números al lado:
//!
//! 1. **Qué fracción del set de opcodes IMPLEMENTADO ejecuta el corpus.** El
//!    que no se toca nunca, no se está fuzzeando.
//! 2. **Qué fracción de los casos pasa del primer opcode.** Un generador que
//!    muere en el primer byte es ruido con buena prensa.
//!
//! El denominador se **mide**, no se declara: `implemented_opcodes` le
//! pregunta al motor byte por byte cuáles conoce, en vez de copiar la lista de
//! `opcode.rs` a mano. Una lista copiada se desactualiza en silencio el día que
//! entra un opcode nuevo — y ese día la cobertura subiría sola.

use std::collections::{BTreeMap, BTreeSet};

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;
use repo_b_evm::{HaltReason, OwnVm};

use crate::fixture::FixtureAccount;
use crate::runner::MemoryState;

/// Cuántos operandos se apilan antes del opcode bajo prueba. El opcode de más
/// aridad del set es `CALL`, con 7; 16 deja margen y no cambia el veredicto.
const PROBE_STACK_DEPTH: usize = 16;

const PROBE_SENDER: Address = Address::new([0xA1; 20]);
const PROBE_TARGET: Address = Address::new([0xB1; 20]);

/// Los opcodes que el motor **ejecuta** en este fork, medidos preguntándole.
///
/// Un byte cuenta como implementado si ejecutarlo no da `OpcodeNotFound` ni
/// `NotActivated`: las dos son las respuestas del dispatch a "ese opcode no
/// existe acá". Cualquier otro resultado —éxito, underflow, gas, salto
/// inválido— significa que el `match` lo reconoció.
pub fn implemented_opcodes(spec: Spec) -> BTreeSet<u8> {
    let mut implemented = BTreeSet::new();
    for byte in 0u16..=0xFF {
        let Ok(op) = u8::try_from(byte) else {
            continue;
        };
        if probe_is_implemented(op, spec) {
            implemented.insert(op);
        }
    }
    implemented
}

fn probe_is_implemented(op: u8, spec: Spec) -> bool {
    // `PUSH1 0x01` repetido: llena la pila sin depender de ningún otro opcode
    // que pudiera estar sin implementar.
    let mut code = Vec::new();
    for _ in 0..PROBE_STACK_DEPTH {
        code.extend_from_slice(&[0x60, 0x01]);
    }
    code.push(op);

    let mut pre: BTreeMap<Address, FixtureAccount> = BTreeMap::new();
    pre.insert(
        PROBE_SENDER,
        FixtureAccount {
            balance: U256::from(1_000_000_000_000_000_000u64),
            nonce: 0,
            code: Bytes::new(),
            storage: BTreeMap::new(),
        },
    );
    pre.insert(
        PROBE_TARGET,
        FixtureAccount {
            balance: U256::ZERO,
            nonce: 1,
            code: Bytes::from(code),
            storage: BTreeMap::new(),
        },
    );
    let state = MemoryState::from_pre(&pre);
    let env = BlockEnv {
        spec,
        chain_id: 1,
        number: 1,
        coinbase: Address::ZERO,
        timestamp: 1_000,
        gas_limit: 30_000_000,
        base_fee: 0,
        prevrandao: repo_b_common::primitives::B256::ZERO,
        blob_excess_gas: Some(0),
        blob_base_fee: None,
        blob_base_fee_update_fraction: None,
    };
    let tx = Transaction {
        tx_type: TxType::Legacy,
        sender: PROBE_SENDER,
        nonce: 0,
        to: Some(PROBE_TARGET),
        value: U256::ZERO,
        input: Bytes::new(),
        gas_limit: 1_000_000,
        gas_price: Some(0),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    };
    match OwnVm::new().execute_tx(&tx, &env, &state) {
        Ok(outcome) => !matches!(
            outcome.result,
            ExecutionResult::Halt {
                reason: HaltReason::OpcodeNotFound | HaltReason::NotActivated,
                ..
            }
        ),
        // Un error del motor no es "el opcode no existe"; es otra cosa, y
        // contarlo como implementado inflaría el denominador.
        Err(_) => false,
    }
}

/// Lo que una campaña ejercitó de verdad.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    pub cases: u64,
    /// Casos cuya traza no se pudo obtener (tx rechazada antes de ejecutar).
    pub not_executed: u64,
    pub executed_opcodes: BTreeSet<u8>,
    pub total_steps: u64,
    /// Casos que ejecutaron **como mucho un** opcode. Es el número que dice si
    /// el generador genera o hace ruido.
    pub cases_dead_at_first_opcode: u64,
    /// Casos que llegaron a 10 opcodes o más.
    pub cases_reaching_ten_steps: u64,
    pub longest_trace: u64,
}

impl Coverage {
    pub fn fraction_of_opcodes(&self, implemented: &BTreeSet<u8>) -> f64 {
        if implemented.is_empty() {
            return 0.0;
        }
        let touched = implemented
            .iter()
            .filter(|op| self.executed_opcodes.contains(op))
            .count();
        touched as f64 / implemented.len() as f64
    }

    pub fn fraction_past_first_opcode(&self) -> f64 {
        if self.cases == 0 {
            return 0.0;
        }
        let alive = self.cases.saturating_sub(self.cases_dead_at_first_opcode);
        alive as f64 / self.cases as f64
    }

    /// Los opcodes que el motor implementa y el corpus **nunca** ejecutó.
    pub fn never_executed(&self, implemented: &BTreeSet<u8>) -> Vec<u8> {
        implemented
            .iter()
            .filter(|op| !self.executed_opcodes.contains(op))
            .copied()
            .collect()
    }
}

#[cfg(feature = "diff-revm")]
mod tracing {
    use repo_b_interpreter::tracer::{StepRecord, StepSink};

    use super::Coverage;
    use crate::fuzz::generate::FuzzCase;
    use crate::runner::MemoryState;

    #[derive(Default)]
    struct OpcodeSink {
        opcodes: Vec<u8>,
    }

    impl StepSink for OpcodeSink {
        fn step(&mut self, record: &StepRecord) {
            self.opcodes.push(record.op);
        }
    }

    /// Suma un caso a la cobertura. Traza la MISMA tx que el diferencial
    /// ejecuta (`execution::trace_tx` reusa el `build_frame` de `execute_tx`),
    /// así que lo que se mide es lo que se corrió.
    pub fn observe(coverage: &mut Coverage, case: &FuzzCase) {
        coverage.cases = coverage.cases.saturating_add(1);
        let test = case.to_state_test();
        let post = case.post_case();
        let Ok(tx) = test.transaction_for(&post) else {
            coverage.not_executed = coverage.not_executed.saturating_add(1);
            return;
        };
        let env = test.block_env(case.spec);
        let state = MemoryState::from_pre(&test.pre);
        let mut sink = OpcodeSink::default();
        if repo_b_evm::execution::trace_tx(&tx, &env, &state, &mut sink).is_err() {
            coverage.not_executed = coverage.not_executed.saturating_add(1);
            return;
        }
        let steps = u64::try_from(sink.opcodes.len()).unwrap_or(u64::MAX);
        coverage.total_steps = coverage.total_steps.saturating_add(steps);
        coverage.longest_trace = coverage.longest_trace.max(steps);
        if steps <= 1 {
            coverage.cases_dead_at_first_opcode =
                coverage.cases_dead_at_first_opcode.saturating_add(1);
        }
        if steps >= 10 {
            coverage.cases_reaching_ten_steps = coverage.cases_reaching_ten_steps.saturating_add(1);
        }
        for op in sink.opcodes {
            coverage.executed_opcodes.insert(op);
        }
    }
}

#[cfg(feature = "diff-revm")]
pub use tracing::observe;

#[cfg(test)]
mod tests {
    use super::*;

    /// El denominador es una MEDICIÓN. Este test lo pinea con un número: el
    /// día que entre un opcode nuevo al motor, se pone en rojo y hay que
    /// decidir si la gramática lo genera — en vez de que la cobertura suba o
    /// baje sola sin que nadie mire.
    #[test]
    fn the_implemented_opcode_set_is_measured_and_pinned() {
        let prague = implemented_opcodes(Spec::Prague);
        assert_eq!(
            prague.len(),
            IMPLEMENTED_IN_PRAGUE,
            "cambió el set implementado: {:?}",
            prague
                .iter()
                .map(|op| format!("{op:#04x}"))
                .collect::<Vec<_>>()
        );
        // Un byte no asignado no puede estar adentro.
        assert!(!prague.contains(&0x0C));
        assert!(!prague.contains(&0x21));
        // Y los que sí, sí.
        assert!(prague.contains(&0x01), "ADD");
        assert!(prague.contains(&0x5F), "PUSH0");
        assert!(prague.contains(&0xFF), "SELFDESTRUCT");
    }

    /// El gating por fork se ve en el denominador: en Paris hay MENOS opcodes
    /// que en Prague, y los que faltan son exactamente los de Shanghai/Cancun.
    #[test]
    fn the_denominator_shrinks_in_older_forks() {
        let paris = implemented_opcodes(Spec::Paris);
        let prague = implemented_opcodes(Spec::Prague);
        assert!(paris.len() < prague.len());
        assert!(!paris.contains(&0x5F), "PUSH0 no existe en Paris");
        assert!(!paris.contains(&0x5E), "MCOPY no existe en Paris");
        assert!(paris.contains(&0x01), "ADD sí");
    }

    /// El set implementado en Prague. **Medido**, no copiado: 149 de los 256
    /// bytes del espacio de opcodes. Coincide con el conteo a mano de
    /// `opcode.rs` (12 aritméticos + 14 de comparación/bitwise + KECCAK256 +
    /// 16 de contexto de frame + 11 de entorno de bloque + 16 de
    /// memoria/storage/control + 32 PUSH + 16 DUP + 16 SWAP + 5 LOG + 10 de
    /// creación/call/terminación), y el conteo se hizo DESPUÉS de la medición.
    const IMPLEMENTED_IN_PRAGUE: usize = 149;
}
