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

/// Los campos del paso que los dos tracers dicen con el **mismo** significado.
///
/// Tres campos del `StepRecord` quedan afuera, y ninguno por prolijidad:
///
/// - **`op_name`** es cosmético: los dos tracers nombran distinto un opcode que
///   no existe (`UNKNOWN` de un lado, otra cosa del otro), y un nombre no es
///   consenso.
/// - **`error`** es la *razón del halt*, que es un punto ciego DECLARADO del
///   oráculo: las taxonomías de los dos motores no mapean 1:1. Compararla acá
///   sería introducir por la ventana lo que `Summary` deja afuera por la
///   puerta. Si un motor se detiene y el otro sigue, la traza diverge igual —
///   por longitud, un paso después.
/// - **`gas_cost`** es la razón MÁS fuerte, y es de diseño: el costo que un
///   paso declara se refleja en el `gas` del paso SIGUIENTE. Si se comparara el
///   costo, un opcode con el gas mal divergiría **en su propio paso** y el
///   "último paso común" sería el ANTERIOR — o sea que el sitio nombraría al
///   inocente. Dejándolo afuera, la divergencia aparece un paso después y el
///   último paso común es exactamente el opcode culpable.
///
/// Medido: con la comparación campo-a-campo cruda, un caso real de EEST
/// (`stExtCodeHash/dynamicAccountOverwriteEmpty`) divergía en el paso 1 con
/// gas y stack IDÉNTICOS —solo cambiaba el nombre de un opcode inválido— y el
/// sitio salía `op:PUSH20`, que no tiene nada que ver con la causa.
fn semantics(step: &StepRecord) -> (usize, u8, u64, usize, usize, i64, &[U256]) {
    (
        step.pc,
        step.op,
        step.gas,
        step.depth,
        step.mem_size,
        step.refund,
        &step.stack,
    )
}

fn same_semantics(a: Option<&StepRecord>, b: Option<&StepRecord>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => semantics(a) == semantics(b),
        (None, None) => true,
        _ => false,
    }
}

/// Compara dos secuencias de pasos y devuelve el primer índice donde
/// difieren **en lo que las dos trazas significan** (ver `semantics`). `None`
/// si coinciden. Una longitud distinta diverge en el primer paso faltante (el
/// índice `min(len)`, con el lado corto en `None`).
pub fn first_divergence(ours: &[StepRecord], oracle: &[StepRecord]) -> Option<Divergence> {
    let len = ours.len().max(oracle.len());
    for step in 0..len {
        let a = ours.get(step);
        let b = oracle.get(step);
        if !same_semantics(a, b) {
            return Some(Divergence {
                step,
                ours: a.cloned(),
                oracle: b.cloned(),
            });
        }
    }
    None
}

/// **Quién es el culpable** de que las dos trazas se separen — no dónde se
/// nota, que es otra cosa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Culprit {
    /// Las dos trazas dicen lo mismo paso a paso.
    Identical,
    /// Nuestro lado no ejecutó un solo opcode.
    OursEmpty,
    /// El oráculo no ejecutó un solo opcode.
    OracleEmpty,
    /// Ya difieren en el PRIMER paso: la causa es anterior a la ejecución.
    AtStart,
    /// El paso culpable, con su índice.
    Step(usize),
}

/// Resuelve el culpable de una divergencia de trazas.
///
/// **La regla tiene dos mitades y la segunda salió de una medición.** La
/// primera: si las trazas se separan en el paso `N`, el culpable es el paso
/// `N-1`, porque el `gas` de un paso es el que quedó DESPUÉS de ejecutar el
/// anterior. La segunda: eso solo vale mientras la diferencia se note enseguida
/// — y un bug de gas no siempre se nota enseguida. El descuento de 63/64 de un
/// `CALL` puede **absorber** una diferencia de 1 gas y devolverla varios pasos
/// (o varios frames) después, y entonces "el paso anterior al que se nota" es
/// un opcode inocente.
///
/// Medido: con la regla de una sola mitad, plantar UN bug en el gas de `ADD`
/// producía **31 clusters** —`op:ADD` más `op:PUSH1`, `op:PUSH2`, … `op:PUSH32`,
/// `op:POP`, `op:JUMPDEST`—, que es fragmentación de manual. Con la segunda
/// mitad da **uno**.
///
/// La segunda mitad mira el **costo declarado**: el primer paso donde los dos
/// motores dicen cobrar distinto ES el culpable, se note cuando se note. Por
/// eso `gas_cost` está afuera de `semantics` (comparar ahí correría el sitio un
/// paso hacia atrás) y adentro de acá.
pub fn culprit(ours: &[StepRecord], oracle: &[StepRecord]) -> Culprit {
    let Some(divergence) = first_divergence(ours, oracle) else {
        return Culprit::Identical;
    };
    if divergence.step == 0 {
        return match (&divergence.ours, &divergence.oracle) {
            (None, _) => Culprit::OursEmpty,
            (Some(_), None) => Culprit::OracleEmpty,
            (Some(_), Some(_)) => Culprit::AtStart,
        };
    }
    // 1. El culpable ALINEADO: el primer paso del prefijo común que ya cobraba
    //    distinto.
    if let Some(step) = ours
        .iter()
        .zip(oracle.iter())
        .take(divergence.step)
        .position(|(a, b)| a.gas_cost != b.gas_cost)
    {
        return Culprit::Step(step);
    }
    // 2. El culpable SIN alineación. Ver `constant_cost_mismatch`.
    if let Some(step) = constant_cost_mismatch(ours, oracle) {
        return Culprit::Step(step);
    }
    // 3. El último paso común.
    Culprit::Step(divergence.step.saturating_sub(1))
}

/// Un opcode de costo **constante** que los dos motores cobran distinto — sin
/// mirar alineación ninguna.
///
/// **Es la regla que hace que un bug de gas dé UN cluster y no cuarenta**, y
/// salió de una medición. El corpus de EEST trae fixtures
/// (`test_all_opcodes::test_constant_gas`) que **miden el gas y ramifican sobre
/// la medición**: son exactamente los tests escritos para detectar un cambio de
/// costo. Con un bug en el gas de `ADD`, esos programas toman otra rama, las
/// dos trazas dejan de estar alineadas **antes** de que el `ADD` corra, y "el
/// último paso común" pasa a nombrar un inocente distinto en cada caso. Medido:
/// un solo bug plantado en `ADD` daba **36 clusters** —`op:PUSH1`…`op:PUSH32`,
/// `op:POP`, `op:JUMPDEST`— con la regla de alineación sola.
///
/// La condición de costo **constante** es lo que la hace segura: un opcode que
/// cobra un solo valor de cada lado y valores distintos entre lados no puede
/// estar explicándose por el camino que tomó cada motor. Los de costo dinámico
/// (`SSTORE`, `CALL`, los que expanden memoria) quedan afuera y caen en la
/// regla de alineación, que para ellos sí sirve: su divergencia se nota donde
/// se produce.
fn constant_cost_mismatch(ours: &[StepRecord], oracle: &[StepRecord]) -> Option<usize> {
    use std::collections::{BTreeMap, BTreeSet};

    fn costs(trace: &[StepRecord]) -> BTreeMap<u8, BTreeSet<u64>> {
        let mut table: BTreeMap<u8, BTreeSet<u64>> = BTreeMap::new();
        for step in trace {
            table.entry(step.op).or_default().insert(step.gas_cost);
        }
        table
    }

    let ours_costs = costs(ours);
    let oracle_costs = costs(oracle);
    // El primero en NUESTRA traza: determinista y, además, el más temprano, que
    // es el que un humano quiere mirar.
    ours.iter().position(|step| {
        let (Some(a), Some(b)) = (ours_costs.get(&step.op), oracle_costs.get(&step.op)) else {
            return false;
        };
        a.len() == 1 && b.len() == 1 && a != b
    })
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

    /// El culpable de un bug de gas es el opcode que COBRA distinto, aunque la
    /// diferencia recién se note un paso después.
    #[test]
    fn the_culprit_is_the_opcode_that_charged_differently() {
        let mut ours = sample_trace();
        // El primer PUSH1 cobra 4 en vez de 3: el `gas` recién difiere en el
        // paso siguiente.
        ours[0].gas_cost = 4;
        ours[1].gas = 96;
        ours[2].gas = 93;
        let oracle = sample_trace();
        assert_eq!(culprit(&ours, &oracle), Culprit::Step(0));
    }

    /// **La regla sin alineación**: aunque las trazas se separen ANTES de que
    /// el opcode culpable corra, un opcode de costo constante cobrado distinto
    /// lo delata. Es lo que hace que un bug de gas dé un cluster y no cuarenta.
    #[test]
    fn a_constant_cost_mismatch_is_found_even_after_the_traces_split() {
        // Las trazas se separan en el paso 1 (otro pc, otro opcode) y el
        // culpable —el SSTORE, que cobra distinto— viene DESPUÉS.
        let ours = vec![
            step(0, 0x60, "PUSH1", 100, &[]),
            step(2, 0x50, "POP", 97, &[5]),
            step(3, 0x55, "SSTORE", 96, &[5, 10]),
        ];
        let mut oracle = vec![
            step(0, 0x60, "PUSH1", 100, &[]),
            step(2, 0x01, "ADD", 97, &[5]),
            step(3, 0x55, "SSTORE", 94, &[5, 10]),
        ];
        if let Some(last) = oracle.last_mut() {
            last.gas_cost = 9;
        }
        assert_eq!(culprit(&ours, &oracle), Culprit::Step(2));
    }

    /// Sin ninguna pista de costo, el culpable es el último paso común: el
    /// `gas` de un paso es el que quedó después de ejecutar el anterior.
    #[test]
    fn without_a_cost_mismatch_the_culprit_is_the_last_common_step() {
        let ours = sample_trace();
        let mut oracle = sample_trace();
        // Diverge en el paso 2 por el stack, sin que ningún costo difiera.
        if let Some(step) = oracle.get_mut(2) {
            step.stack = vec![U256::from(5u64), U256::from(11u64)];
        }
        assert_eq!(culprit(&ours, &oracle), Culprit::Step(1));
    }

    /// Los tres casos de borde tienen nombre propio: sin ellos, un hallazgo se
    /// quedaría sin cluster y se caería del reporte.
    #[test]
    fn the_edge_cases_have_names_of_their_own() {
        let trace = sample_trace();
        assert_eq!(culprit(&trace, &trace), Culprit::Identical);
        assert_eq!(culprit(&[], &trace), Culprit::OursEmpty);
        assert_eq!(culprit(&trace, &[]), Culprit::OracleEmpty);
        let mut other = sample_trace();
        if let Some(first) = other.first_mut() {
            first.gas = 1;
        }
        assert_eq!(culprit(&trace, &other), Culprit::AtStart);
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
