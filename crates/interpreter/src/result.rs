//! Trichotomy del intérprete: Success/Revert/Halt (local al crate).
//!
//! El intérprete NO importa el seam de `repo-b-evm` (dirección de
//! dependencias): `evm` mapea `Halt → HaltReason` y `InterpreterOutcome →
//! ExecutionResult` en Fase 2. El mapping debe ser total (sin `_`).

use repo_b_common::primitives::Bytes;

/// Halt legítimo del protocolo dentro del intérprete. Consume TODO el gas
/// (distinto de REVERT, que devuelve el restante).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    OutOfGas,
    StackUnderflow,
    StackOverflow,
    InvalidJump,
    /// Opcode no asignado en el fork activo.
    OpcodeNotFound,
    /// El opcode designado inválido (`0xFE`, EIP-141).
    InvalidFEOpcode,
    /// Offset/longitud de memoria irrepresentable tras la expansión (defensa
    /// fail-closed; en la práctica el gas agota antes).
    OutOfOffset,
    /// Escritura de estado (SSTORE/TSTORE) dentro de un contexto `STATICCALL`.
    StateChangeDuringStaticCall,
    /// EIP-3860 — initcode de CREATE/CREATE2 por encima de
    /// `MAX_INITCODE_SIZE` (49152). Se chequea ANTES de cobrar el costo por
    /// palabra del initcode.
    CreateInitCodeSizeLimit,
    /// EIP-170 — el código a desplegar supera `MAX_CODE_SIZE`
    /// (24576). Lo detecta el executor al cerrar el frame de creación.
    CreateContractSizeLimit,
    /// EIP-3541 — el código a desplegar arranca con `0xEF`.
    CreateContractStartingWithEF,
    /// La dirección derivada ya está ocupada (`nonce != 0` o código no vacío).
    /// Consume TODO el gas reenviado; el bump del nonce del creador persiste.
    CreateCollision,
}

/// Resultado de correr el intérprete hasta terminar.
///
/// Semántica de gas de la trichotomy (consenso):
/// - `Success`/`Revert`: `gas_used = limit - remaining` (REVERT devuelve el
///   gas restante al caller).
/// - `Halt`: `gas_used = limit` (consume todo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpreterOutcome {
    Success { output: Bytes, gas_used: u64 },
    Revert { output: Bytes, gas_used: u64 },
    Halt { reason: Halt, gas_used: u64 },
}

impl InterpreterOutcome {
    pub fn gas_used(&self) -> u64 {
        match self {
            Self::Success { gas_used, .. }
            | Self::Revert { gas_used, .. }
            | Self::Halt { gas_used, .. } => *gas_used,
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }
}
