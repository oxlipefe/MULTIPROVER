//! Constantes de opcodes del set de Fase 1 (fork target: Prague).
//! Solo los bytes asignados que el intérprete implementa hoy; el resto del
//! espacio es `Halt::OpcodeNotFound` en el dispatch (fail-closed).

pub const STOP: u8 = 0x00;
pub const ADD: u8 = 0x01;
pub const MUL: u8 = 0x02;
pub const SUB: u8 = 0x03;
// --- aritmética (slice 2.9b-2) ---
/// División sin signo. `b == 0 ⇒ 0` (regla de la EVM, no un halt).
pub const DIV: u8 = 0x04;
/// División con signo (complemento a dos, `crate::arithmetic`).
pub const SDIV: u8 = 0x05;
/// Resto sin signo. `b == 0 ⇒ 0`.
pub const MOD: u8 = 0x06;
/// Resto con signo — el signo lo fija el DIVIDENDO.
pub const SMOD: u8 = 0x07;
/// `(a + b) mod N` con el intermedio de **ancho completo** (no mod 2^256).
pub const ADDMOD: u8 = 0x08;
/// `(a · b) mod N` con el intermedio de **ancho completo**.
pub const MULMOD: u8 = 0x09;
/// Exponenciación mod 2^256. Gas dinámico por byte del exponente (EIP-160).
pub const EXP: u8 = 0x0A;
/// Extensión de signo desde el byte `b` (`crate::arithmetic::sign_extend`).
pub const SIGNEXTEND: u8 = 0x0B;
// --- comparación y bitwise (slice 2.9b-2) ---
pub const LT: u8 = 0x10;
pub const GT: u8 = 0x11;
/// Menor-que con signo — distinto de `LT`, ver `crate::arithmetic`.
pub const SLT: u8 = 0x12;
/// Mayor-que con signo.
pub const SGT: u8 = 0x13;
pub const EQ: u8 = 0x14;
pub const ISZERO: u8 = 0x15;
pub const AND: u8 = 0x16;
pub const OR: u8 = 0x17;
pub const XOR: u8 = 0x18;
pub const NOT: u8 = 0x19;
/// Byte `i` contando desde el MÁS significativo. `i >= 32 ⇒ 0`.
pub const BYTE: u8 = 0x1A;
/// EIP-145 — shift lógico a izquierda. Desplazamiento `>= 256 ⇒ 0`.
pub const SHL: u8 = 0x1B;
/// EIP-145 — shift lógico a derecha. Desplazamiento `>= 256 ⇒ 0`.
pub const SHR: u8 = 0x1C;
/// EIP-145 — shift ARITMÉTICO a derecha: satura en `0` o en `-1` según el
/// signo, no en `0` siempre.
pub const SAR: u8 = 0x1D;
/// KECCAK256 (a.k.a. SHA3) — hash de una ventana de memoria.
pub const KECCAK256: u8 = 0x20;
// --- opcodes de contexto de frame (slice 2.1; alimentados por `CallContext`) ---
pub const ADDRESS: u8 = 0x30;
/// EIP-2929 (cold/warm por dirección) — balance de una cuenta ajena (seam
/// `Host::load_account`, slice 2.4). Distinto de `SELFBALANCE` (0x47, sin
/// cold/warm, siempre la cuenta en ejecución).
pub const BALANCE: u8 = 0x31;
/// EIP-2929 (cold/warm, vía account access — slice 2.4) — ventana de 256
/// bloques hoy; `Host::block_hash` (slice 2.3). **KNOWN**: interacción con
/// EIP-2935 (Prague, history contract) sin validar — ficha 01 §2.3.
pub const BLOCKHASH: u8 = 0x40;
/// Slice 2.3 — `Host::tx().origin` (seam `interpreter::host`).
pub const ORIGIN: u8 = 0x32;
pub const CALLER: u8 = 0x33;
pub const CALLVALUE: u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE: u8 = 0x38;
pub const CODECOPY: u8 = 0x39;
/// Slice 2.3 — `Host::tx().gas_price` (effective, EIP-1559).
pub const GASPRICE: u8 = 0x3A;
/// EIP-2929 — tamaño del código de una cuenta ajena (`Host::code_by_address`,
/// slice 2.4).
pub const EXTCODESIZE: u8 = 0x3B;
/// EIP-2929 — copia código de una cuenta ajena a memoria, zero-padded más
/// allá del final (slice 2.4).
pub const EXTCODECOPY: u8 = 0x3C;
/// EIP-211 (slice 2.5) — tamaño del output del ÚLTIMO sub-call de este frame
/// (vacío al entrar al frame).
pub const RETURNDATASIZE: u8 = 0x3D;
/// EIP-211 (slice 2.5) — copia del buffer de returndata a memoria.
/// **FOOTGUN:** fuera de rango ⇒ `Halt`, NO zero-pad (al revés que
/// CALLDATACOPY/CODECOPY).
pub const RETURNDATACOPY: u8 = 0x3E;
/// EIP-1052/2929 — hash del código de una cuenta ajena; cuenta vacía
/// (EIP-161) o inexistente ⇒ 0, NUNCA `keccak("")` (slice 2.4).
pub const EXTCODEHASH: u8 = 0x3F;
// --- opcodes de entorno de bloque (slice 2.3; seam `Host::env`) ---
pub const COINBASE: u8 = 0x41;
pub const TIMESTAMP: u8 = 0x42;
pub const NUMBER: u8 = 0x43;
/// Post-Merge: `PREVRANDAO` (era `DIFFICULTY`, EIP-4399).
pub const PREVRANDAO: u8 = 0x44;
pub const GASLIMIT: u8 = 0x45;
pub const CHAINID: u8 = 0x46;
/// EIP-1884 — balance de `context.address` DEL JOURNAL (post-transfers), no
/// del `State` congelado (seam `Host::self_balance`).
pub const SELFBALANCE: u8 = 0x47;
pub const BASEFEE: u8 = 0x48;
/// EIP-4844 — `Host::tx().blob_hashes[index]` o 0 fuera de rango.
pub const BLOBHASH: u8 = 0x49;
/// EIP-7516 — `fake_exponential` de EIP-4844 ya calculado en `Host::env`.
pub const BLOBBASEFEE: u8 = 0x4A;
pub const POP: u8 = 0x50;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
/// Escribe **un solo byte** (el menos significativo de la palabra del stack).
/// Expande memoria de a 1 byte, no de a 32 — distinto de `MSTORE`.
pub const MSTORE8: u8 = 0x53;
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
/// EIP-5656 (Cancun) — copia memoria→memoria. **Los rangos pueden solaparse**
/// y la semántica es la de `memmove`, no la de `memcpy`.
pub const MCOPY: u8 = 0x5E;
/// EIP-3855 (Shanghai). Ver KNOWN de gating por fork en la ficha 01.
pub const PUSH0: u8 = 0x5F;
pub const PUSH1: u8 = 0x60;
pub const PUSH32: u8 = 0x7F;
pub const DUP1: u8 = 0x80;
pub const DUP16: u8 = 0x8F;
pub const SWAP1: u8 = 0x90;
pub const SWAP16: u8 = 0x9F;
/// LOG0..LOG4 (slice 2.3): static ⇒ `StateChangeDuringStaticCall`; emiten vía
/// `Host::log`. `n` topics = `op - LOG0` (0..=4).
pub const LOG0: u8 = 0xA0;
pub const LOG4: u8 = 0xA4;
// --- creación de contratos (slice 2.6; ADR-0002 §3) ---
/// `CREATE` — dirección derivada del `(creador, nonce)` del creador.
/// EIP-3860 (initcode metering) + EIP-170/3541 sobre el código desplegado.
pub const CREATE: u8 = 0xF0;
/// `CREATE2` (EIP-1014) — dirección derivada del `(creador, salt, keccak(initcode))`.
pub const CREATE2: u8 = 0xF5;
/// `SELFDESTRUCT` — EIP-6780 (Cancun+): solo destruye si la cuenta se creó en
/// la MISMA tx; si no, solo mueve el balance. Sin refund desde London (3529).
pub const SELFDESTRUCT: u8 = 0xFF;
// --- sub-calls (slice 2.5; ADR-0002 §3: `InterpreterAction` + frame stack) ---
/// `CALL` — contexto y storage del target, value explícito.
pub const CALL: u8 = 0xF1;
/// `CALLCODE` — código del target sobre el storage PROPIO (legacy; sigue vivo).
pub const CALLCODE: u8 = 0xF2;
/// `DELEGATECALL` (EIP-7) — código del target sobre el storage propio,
/// heredando `CALLER` y `CALLVALUE`.
pub const DELEGATECALL: u8 = 0xF4;
/// `STATICCALL` (EIP-214) — como CALL con value 0 y `is_static` propagado a
/// TODA la sub-ejecución.
pub const STATICCALL: u8 = 0xFA;
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
