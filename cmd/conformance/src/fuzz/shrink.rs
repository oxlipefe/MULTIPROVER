//! El shrinker: de un caso que diverge a un reproductor mínimo.
//!
//! **Un caso minimizado que ya no diverge no es un caso minimizado: es un bug
//! del shrinker.** De ahí sale la forma del módulo: el shrinker no sabe qué es
//! divergir. Recibe un **predicado** y solo acepta un paso de reducción si el
//! caso reducido lo sigue satisfaciendo. El predicado que usa la campaña es
//! "diverge **por la misma diferencia**", no "diverge": un shrinker que acepta
//! cualquier divergencia te entrega el reproductor de OTRO bug.
//!
//! Que el predicado sea un parámetro tiene una consecuencia práctica: este
//! módulo NO depende de revm, así que su invariante se testea con un predicado
//! sintético y esos tests corren en `cargo test --workspace` sin la feature.
//!
//! Las reducciones operan sobre el **stream de instrucciones** (`program.rs`),
//! nunca sobre bytes: por qué, en el doc-comment de ese módulo.

use crate::fuzz::generate::FuzzCase;
use crate::fuzz::program::Instruction;

/// Tope de evaluaciones del predicado. Cada evaluación es una corrida
/// diferencial completa (dos motores), así que el presupuesto es tiempo real y
/// va acotado y nombrado, como todo recurso alimentado por el generador.
pub const MAX_SHRINK_STEPS: u32 = 3_000;

/// Qué hizo el shrinker. Se reporta con el hallazgo: un shrinker que no reduce
/// hay que verlo, no suponerlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShrinkStats {
    pub steps_tried: u32,
    pub steps_accepted: u32,
    pub size_before: usize,
    pub size_after: usize,
}

/// Minimiza `case` conservando `still_reproduces`.
///
/// **Contrato:** el caso devuelto satisface el predicado. Si el caso de
/// entrada no lo satisface, se devuelve tal cual — minimizar algo que no
/// reproduce no tiene significado.
pub fn shrink<P>(case: &FuzzCase, mut still_reproduces: P) -> (FuzzCase, ShrinkStats)
where
    P: FnMut(&FuzzCase) -> bool,
{
    let mut stats = ShrinkStats {
        size_before: case.size(),
        size_after: case.size(),
        ..ShrinkStats::default()
    };
    if !still_reproduces(case) {
        stats.steps_tried = 1;
        return (case.clone(), stats);
    }
    stats.steps_tried = 1;

    let mut current = case.clone();
    // Punto fijo: se repite la batería completa mientras algo se acepte. Una
    // reducción habilita otras (borrar un `CALL` deja huérfanas sus cuentas).
    loop {
        let accepted_before = stats.steps_accepted;
        for candidate in candidates(&current) {
            if stats.steps_tried >= MAX_SHRINK_STEPS {
                stats.size_after = current.size();
                return (current, stats);
            }
            stats.steps_tried = stats.steps_tried.saturating_add(1);
            if candidate.size() < current.size() && still_reproduces(&candidate) {
                stats.steps_accepted = stats.steps_accepted.saturating_add(1);
                current = candidate;
                break;
            }
        }
        if stats.steps_accepted == accepted_before {
            break;
        }
    }
    stats.size_after = current.size();
    (current, stats)
}

/// Todos los casos estrictamente más chicos que vale la pena probar, de mayor
/// a menor reducción: primero los bloques grandes (delta-debugging), después
/// las instrucciones sueltas, después los campos de la tx.
fn candidates(case: &FuzzCase) -> Vec<FuzzCase> {
    let mut out = Vec::new();

    // 1. Cuentas que no participan. Va primero porque borra un programa
    //    entero de un paso.
    for index in 0..case.accounts.len() {
        let is_tx_target = case
            .accounts
            .get(index)
            .is_some_and(|account| case.to == Some(account.address));
        if is_tx_target {
            continue;
        }
        let mut reduced = case.clone();
        reduced.accounts.remove(index);
        out.push(reduced);
    }

    // 2. Bloques contiguos de instrucciones, de grande a chico.
    for (account_index, account) in case.accounts.iter().enumerate() {
        if account.program.is_empty() {
            continue;
        }
        let len = account.program.len();
        let mut block = len;
        while block > 0 {
            let mut start = 0usize;
            while start < len {
                let end = start.saturating_add(block).min(len);
                let mut reduced = case.clone();
                if let Some(target) = reduced.accounts.get_mut(account_index) {
                    target.program.instructions.drain(start..end);
                    out.push(reduced);
                }
                start = end;
            }
            block /= 2;
        }
    }

    // 3. Los inmediatos de un `PUSH`: un `PUSH32 0xff…ff` que podía ser
    //    `PUSH1 0x01` esconde cuál es el valor que importa.
    for (account_index, account) in case.accounts.iter().enumerate() {
        for (instruction_index, instruction) in account.program.instructions.iter().enumerate() {
            let Instruction::Push(data) = instruction else {
                continue;
            };
            if data.is_empty() {
                continue;
            }
            for shorter in [Vec::new(), vec![0x01], vec![0x00]] {
                if shorter.len() >= data.len() {
                    continue;
                }
                let mut reduced = case.clone();
                if let Some(target) = reduced
                    .accounts
                    .get_mut(account_index)
                    .and_then(|a| a.program.instructions.get_mut(instruction_index))
                {
                    *target = Instruction::Push(shorter);
                    out.push(reduced);
                }
            }
        }
    }

    // 4. Slots de storage del pre-state.
    for (account_index, account) in case.accounts.iter().enumerate() {
        for key in account.storage.keys() {
            let mut reduced = case.clone();
            if let Some(target) = reduced.accounts.get_mut(account_index) {
                target.storage.remove(key);
                out.push(reduced);
            }
        }
    }

    // 5. Calldata: mitades primero, después la cola byte a byte.
    if !case.calldata.is_empty() {
        let len = case.calldata.len();
        for keep in [0usize, len / 4, len / 2, len.saturating_sub(1)] {
            if keep >= len {
                continue;
            }
            let mut reduced = case.clone();
            reduced.calldata.truncate(keep);
            out.push(reduced);
        }
    }

    // 6. El valor transferido. Cambia reglas (`G_callvalue`, cuenta nueva),
    //    así que solo se acepta si el predicado sobrevive.
    if !case.value.is_zero() {
        let mut reduced = case.clone();
        reduced.value = repo_b_common::primitives::U256::ZERO;
        out.push(reduced);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::generate::{TARGET, generate_case};
    use crate::fuzz::program::Instruction;

    /// La invariante central, y el motivo de que el shrinker tome un predicado:
    /// lo minimizado **sigue reproduciendo**. Predicado sintético (nada de
    /// oráculo) y a propósito **multidimensional**: exige calldata Y programa,
    /// así que un shrinker que aceptara un paso sin re-verificar lo rompería
    /// por cualquiera de las dos vías.
    ///
    /// La primera versión de este test miraba solo "existe la cuenta target", y
    /// una mutación del shrinker la dejó pasar: el target nunca se borra por otra
    /// regla, así que el predicado era verdadero pasara lo que pasara. Un hueco
    /// real, encontrado por mutación y corregido antes de cerrar.
    #[test]
    fn what_the_shrinker_returns_still_reproduces() {
        let mut case = generate_case(0xABCD, 12);
        case.calldata = vec![0xAA; 32];
        let reproduces = |candidate: &FuzzCase| {
            candidate.calldata.len() >= 4
                && candidate
                    .accounts
                    .iter()
                    .any(|account| account.address == TARGET && account.program.len() >= 3)
        };
        assert!(reproduces(&case), "el caso de partida ya no reproduce");
        let (minimized, stats) = shrink(&case, reproduces);
        assert!(reproduces(&minimized), "el minimizado dejó de reproducir");
        assert!(stats.size_after < stats.size_before, "{stats:?}");
    }

    /// Reduce de verdad: un predicado que solo mira UNA instrucción tiene que
    /// dejar un caso mucho más chico que el original.
    #[test]
    fn the_shrinker_actually_reduces() {
        let mut case = generate_case(0x1111, 3);
        // Se planta un marcador inequívoco en el target.
        if let Some(target) = case.accounts.iter_mut().find(|a| a.address == TARGET) {
            target
                .program
                .instructions
                .insert(0, Instruction::Op(crate::fuzz::opcodes::JUMPI));
        }
        let contains_marker = |candidate: &FuzzCase| {
            candidate.accounts.iter().any(|account| {
                account
                    .program
                    .instructions
                    .contains(&Instruction::Op(crate::fuzz::opcodes::JUMPI))
            })
        };
        let (minimized, stats) = shrink(&case, contains_marker);
        assert!(contains_marker(&minimized));
        assert!(
            stats.size_after < stats.size_before,
            "no redujo nada: {stats:?}"
        );
        // El caso mínimo para ese predicado es una cuenta con una sola
        // instrucción; el shrinker tiene que llegar cerca.
        assert!(
            minimized.size() <= 4,
            "el mínimo quedó en {}: {minimized:?}",
            minimized.size()
        );
    }

    /// Un caso que no reproduce desde el principio se devuelve intacto: no hay
    /// nada que minimizar y devolver "algo más chico" sería inventar un
    /// reproductor.
    #[test]
    fn a_case_that_never_reproduced_comes_back_untouched() {
        let case = generate_case(9, 9);
        let (minimized, stats) = shrink(&case, |_| false);
        assert_eq!(minimized, case);
        assert_eq!(stats.steps_accepted, 0);
    }

    /// El presupuesto es un tope duro: sin él, un predicado caro sobre un caso
    /// grande cuelga la campaña.
    #[test]
    fn the_shrinker_respects_its_step_budget() {
        let case = generate_case(0x5EED, 21);
        // Predicado que acepta todo: el shrinker reduce sin parar hasta el
        // punto fijo o el tope.
        let (_, stats) = shrink(&case, |_| true);
        assert!(stats.steps_tried <= MAX_SHRINK_STEPS);
    }

    /// El shrinker nunca borra la cuenta a la que apunta la tx: sin ella el
    /// caso deja de ser el mismo caso.
    #[test]
    fn the_tx_target_survives_shrinking() {
        let case = generate_case(0x7777, 5);
        let (minimized, _) = shrink(&case, |_| true);
        if let Some(to) = case.to {
            assert!(minimized.accounts.iter().any(|a| a.address == to));
        }
    }
}
