//! Comparador de trazas EIP-3155. Genérico
//! sobre la fuente: hoy se testea con trazas doradas escritas a mano; en 004
//! un lado será el `StepRecord` de `repo-b-interpreter` (feature `tracer`) y
//! el otro el inspector EIP-3155 de revm, ambos normalizados a este mismo
//! struct antes de compararse.
//!
//! El contrato: encontrar el PRIMER paso divergente y poder formatearlo —
//! nunca solo "el root difiere".
//!
//! Sin consumidor real todavía: el bridge que llama a esto desde `main` con
//! el lado revm es 004 (Prohibido de 003: "enchufar revm acá"). Hasta
//! entonces solo lo ejercitan los tests de este módulo.
#![allow(dead_code)]

use repo_b_common::primitives::U256;

/// Un paso de traza normalizado, forma EIP-3155 (espeja
/// `repo_b_interpreter::tracer::StepRecord`, sin depender del crate: este
/// comparador es genérico sobre la fuente).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub pc: usize,
    pub op: u8,
    pub op_name: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub stack: Vec<U256>,
    pub depth: usize,
    pub mem_size: usize,
    pub refund: i64,
    pub error: Option<String>,
}

/// El primer punto donde dos trazas dejan de coincidir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    pub step: usize,
    pub ours: Option<StepRecord>,
    pub oracle: Option<StepRecord>,
}

/// Compara dos secuencias de pasos y devuelve el primer índice donde
/// difieren (por valor, campo a campo vía `PartialEq`). `None` si son
/// idénticas. Una longitud distinta diverge en el primer paso faltante (el
/// índice `min(len)`, con el lado corto en `None`).
pub fn first_divergence(ours: &[StepRecord], oracle: &[StepRecord]) -> Option<Divergence> {
    let len = ours.len().max(oracle.len());
    for step in 0..len {
        let a = ours.get(step);
        let b = oracle.get(step);
        if a != b {
            return Some(Divergence {
                step,
                ours: a.cloned(),
                oracle: b.cloned(),
            });
        }
    }
    None
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.ours, &self.oracle) {
            (Some(a), Some(b)) => write!(
                f,
                "paso {} | pc=0x{:02x} op={} | gas: nuestro {} vs oráculo {} | stack_top: {} vs {}",
                self.step,
                a.pc,
                a.op_name,
                a.gas,
                b.gas,
                stack_top(&a.stack),
                stack_top(&b.stack),
            ),
            (Some(a), None) => write!(
                f,
                "paso {} | falta en oráculo (nuestro: pc=0x{:02x} op={})",
                self.step, a.pc, a.op_name
            ),
            (None, Some(b)) => write!(
                f,
                "paso {} | falta en nuestro (oráculo: pc=0x{:02x} op={})",
                self.step, b.pc, b.op_name
            ),
            (None, None) => unreachable!("first_divergence nunca reporta (None, None)"),
        }
    }
}

fn stack_top(stack: &[U256]) -> String {
    match stack.last() {
        Some(value) => format!("0x{value:x}"),
        None => "<empty>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(pc: usize, op: u8, op_name: &str, gas: u64, stack: &[u64]) -> StepRecord {
        StepRecord {
            pc,
            op,
            op_name: op_name.to_string(),
            gas,
            gas_cost: 3,
            stack: stack.iter().copied().map(U256::from).collect(),
            depth: 0,
            mem_size: 0,
            refund: 0,
            error: None,
        }
    }

    fn sample_trace() -> Vec<StepRecord> {
        vec![
            step(0, 0x60, "PUSH1", 100, &[]),
            step(2, 0x60, "PUSH1", 97, &[5]),
            step(4, 0x55, "SSTORE", 94, &[5, 10]),
        ]
    }

    #[test]
    fn identical_traces_have_no_divergence() {
        let ours = sample_trace();
        let oracle = sample_trace();
        assert_eq!(first_divergence(&ours, &oracle), None);
    }

    #[test]
    fn gas_divergence_is_reported_at_the_exact_step() {
        let ours = sample_trace();
        let mut oracle = sample_trace();
        oracle[2].gas = 90; // diverge justo en el paso del SSTORE (índice 2).

        let mut expected_ours = sample_trace();
        let expected_oracle = oracle[2].clone();
        assert_eq!(
            first_divergence(&ours, &oracle),
            Some(Divergence {
                step: 2,
                ours: Some(expected_ours.remove(2)),
                oracle: Some(expected_oracle),
            })
        );
    }

    #[test]
    fn different_lengths_diverge_at_the_first_missing_step() {
        let ours = sample_trace();
        let oracle = sample_trace()[..2].to_vec(); // le falta el último paso.

        let mut expected_ours = sample_trace();
        assert_eq!(
            first_divergence(&ours, &oracle),
            Some(Divergence {
                step: 2,
                ours: Some(expected_ours.remove(2)),
                oracle: None,
            })
        );
    }

    #[test]
    fn divergence_formats_as_the_spec_line() {
        let divergence = Divergence {
            step: 2,
            ours: Some(step(4, 0x55, "SSTORE", 94, &[5, 10])),
            oracle: Some(step(4, 0x55, "SSTORE", 90, &[5, 10])),
        };
        assert_eq!(
            divergence.to_string(),
            "paso 2 | pc=0x04 op=SSTORE | gas: nuestro 94 vs oráculo 90 | stack_top: 0xa vs 0xa"
        );
    }
}
