//! Bytecode analizado: bitmap de destinos de salto válidos, en una sola
//! pasada. Un `0x5B` dentro de los inmediatos de un PUSH **no** es un
//! `JUMPDEST` válido (regla de consenso). Determinista: `Vec<bool>`, sin
//! `HashMap`.

use alloc::vec;
use alloc::vec::Vec;

use repo_b_common::primitives::Bytes;

use crate::opcode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bytecode {
    code: Bytes,
    jumpdests: Vec<bool>,
}

impl Bytecode {
    /// Analiza `code` marcando los `JUMPDEST` que están en posición de opcode
    /// (saltando los inmediatos de cada PUSH). El bytecode es input hostil:
    /// no se asume bien formado; un PUSH truncado al final simplemente agota
    /// el cursor.
    pub fn analyze(code: Bytes) -> Self {
        let mut jumpdests = vec![false; code.len()];
        let mut pc = 0usize;
        while let Some(&op) = code.get(pc) {
            if op == opcode::JUMPDEST
                && let Some(slot) = jumpdests.get_mut(pc)
            {
                *slot = true;
            }
            pc = pc
                .saturating_add(1)
                .saturating_add(opcode::push_immediate_len(op));
        }
        Self { code, jumpdests }
    }

    pub fn code(&self) -> &[u8] {
        &self.code
    }

    pub fn len(&self) -> usize {
        self.code.len()
    }

    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }

    /// ¿`pc` es un destino de salto válido? Fuera de rango = inválido
    /// (fail-closed).
    pub fn is_valid_jumpdest(&self, pc: usize) -> bool {
        self.jumpdests.get(pc).copied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytecode(bytes: &[u8]) -> Bytecode {
        Bytecode::analyze(Bytes::copy_from_slice(bytes))
    }

    #[test]
    fn jumpdest_in_opcode_position_is_valid() {
        let code = bytecode(&[opcode::JUMPDEST, opcode::STOP]);
        assert!(code.is_valid_jumpdest(0));
        assert!(!code.is_valid_jumpdest(1));
    }

    #[test]
    fn jumpdest_inside_push_immediates_is_invalid() {
        // PUSH1 0x5B: el 0x5B en pc=1 es dato, no opcode.
        let code = bytecode(&[opcode::PUSH1, opcode::JUMPDEST, opcode::STOP]);
        assert!(!code.is_valid_jumpdest(1));
    }

    #[test]
    fn jumpdest_after_push32_immediates_is_valid() {
        let mut raw = vec![0x7F]; // PUSH32
        raw.extend([opcode::JUMPDEST; 32]); // 32 inmediatos-señuelo
        raw.push(opcode::JUMPDEST); // pc=33: opcode real
        let code = bytecode(&raw);
        for pc in 1..=32 {
            assert!(!code.is_valid_jumpdest(pc), "pc={pc} es inmediato");
        }
        assert!(code.is_valid_jumpdest(33));
    }

    #[test]
    fn truncated_push_at_end_does_not_panic_or_mark() {
        // PUSH32 con un solo byte de inmediato: cursor agotado, sin panic.
        let code = bytecode(&[0x7F, opcode::JUMPDEST]);
        assert!(!code.is_valid_jumpdest(1));
    }

    #[test]
    fn out_of_range_pc_is_never_valid() {
        let code = bytecode(&[opcode::JUMPDEST]);
        assert!(!code.is_valid_jumpdest(1));
        assert!(!code.is_valid_jumpdest(usize::MAX));
        let empty = bytecode(&[]);
        assert!(!empty.is_valid_jumpdest(0));
    }
}
