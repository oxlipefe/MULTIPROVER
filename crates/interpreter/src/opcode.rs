//! Constantes de opcodes del set de Fase 1 (fork target: Prague).
//! Solo los bytes asignados que el intérprete implementa hoy; el resto del
//! espacio es `Halt::OpcodeNotFound` en el dispatch (fail-closed).

pub const STOP: u8 = 0x00;
pub const ADD: u8 = 0x01;
pub const MUL: u8 = 0x02;
pub const SUB: u8 = 0x03;
/// KECCAK256 (a.k.a. SHA3) — hash de una ventana de memoria.
pub const KECCAK256: u8 = 0x20;
// --- opcodes de contexto de frame (slice 2.1; alimentados por `CallContext`) ---
pub const ADDRESS: u8 = 0x30;
pub const CALLER: u8 = 0x33;
pub const CALLVALUE: u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE: u8 = 0x38;
pub const CODECOPY: u8 = 0x39;
pub const POP: u8 = 0x50;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
/// EIP-2929 (cold/warm) — lectura de storage persistente (seam `Host`).
pub const SLOAD: u8 = 0x54;
/// EIP-2200/2929/3529 (sentry, cold/warm, refunds) — escritura de storage
/// persistente (seam `Host`).
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const PC: u8 = 0x58;
pub const MSIZE: u8 = 0x59;
pub const GAS: u8 = 0x5A;
pub const JUMPDEST: u8 = 0x5B;
/// EIP-1153 — lectura de transient storage (seam `Host`).
pub const TLOAD: u8 = 0x5C;
/// EIP-1153 — escritura de transient storage (seam `Host`).
pub const TSTORE: u8 = 0x5D;
/// EIP-3855 (Shanghai). Ver KNOWN de gating por fork en la ficha 01.
pub const PUSH0: u8 = 0x5F;
pub const PUSH1: u8 = 0x60;
pub const PUSH32: u8 = 0x7F;
pub const DUP1: u8 = 0x80;
pub const DUP16: u8 = 0x8F;
pub const SWAP1: u8 = 0x90;
pub const SWAP16: u8 = 0x9F;
pub const RETURN: u8 = 0xF3;
pub const REVERT: u8 = 0xFD;
/// El opcode designado inválido (EIP-141).
pub const INVALID: u8 = 0xFE;

/// Bytes inmediatos que siguen a `op`: 1..=32 para PUSH1..=PUSH32, 0 para el
/// resto (PUSH0 incluido — no tiene inmediatos).
pub fn push_immediate_len(op: u8) -> usize {
    if !(PUSH1..=PUSH32).contains(&op) {
        return 0;
    }
    // `op ∈ [PUSH1, PUSH32]` garantiza que la resta no underflowea.
    usize::from(op.wrapping_sub(PUSH1)).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push1_through_push32_have_matching_immediate_len() {
        assert_eq!(push_immediate_len(PUSH1), 1);
        assert_eq!(push_immediate_len(0x61), 2);
        assert_eq!(push_immediate_len(PUSH32), 32);
    }

    #[test]
    fn non_push_opcodes_have_no_immediates() {
        assert_eq!(push_immediate_len(PUSH0), 0);
        assert_eq!(push_immediate_len(STOP), 0);
        assert_eq!(push_immediate_len(DUP1), 0);
        assert_eq!(push_immediate_len(INVALID), 0);
    }
}
