//! Contador de gas + gas-schedule del fork target (Prague), en UN solo lugar
//! mapeado tight a la spec (ARCHITECTURE §6.5). El gas es consenso: un costo
//! mal = divergencia. Aritmética `checked_*` explícita (overflow de
//! implementación = `Halt`, fail-closed).

use crate::result::Halt;

/// Costos estáticos por opcode (Yellow Paper apéndice G + EIPs; fork Prague).
/// Nombres de la spec para que el mapeo sea auditable línea-a-línea.
pub mod cost {
    /// `G_zero` — STOP, RETURN, REVERT.
    pub const ZERO: u64 = 0;
    /// `G_base` — POP, PUSH0 (EIP-3855).
    pub const BASE: u64 = 2;
    /// `G_verylow` — ADD, SUB, PUSH*, DUP*, SWAP*, MLOAD, MSTORE.
    pub const VERYLOW: u64 = 3;
    /// `G_low` — MUL.
    pub const LOW: u64 = 5;
    /// `G_mid` — JUMP.
    pub const MID: u64 = 8;
    /// `G_high` — JUMPI.
    pub const HIGH: u64 = 10;
    /// `G_jumpdest` — JUMPDEST.
    pub const JUMPDEST: u64 = 1;
    /// `G_keccak256` — costo base de KECCAK256.
    pub const KECCAK256: u64 = 30;
    /// `G_keccak256word` — costo por palabra (32 bytes) hasheada por KECCAK256.
    pub const KECCAK256_WORD: u64 = 6;
    /// `G_copy` — costo por palabra copiada (CALLDATACOPY/CODECOPY/…).
    pub const COPY: u64 = 3;
    /// `G_memory` — costo lineal por palabra de expansión de memoria.
    pub const MEMORY_WORD: u64 = 3;
    /// Divisor del término cuadrático de expansión de memoria (`w²/512`).
    pub const MEMORY_QUAD_DIVISOR: u64 = 512;
    /// EIP-2929 — costo de un acceso "frío" (primero en la tx) a un slot de
    /// storage. SLOAD cold y el surcharge de SSTORE cold.
    pub const COLD_SLOAD: u64 = 2100;
    /// EIP-2929 — costo de un acceso "caliente" a storage. Reusado por SLOAD
    /// warm, el costo base "dirty" de SSTORE y TLOAD/TSTORE (EIP-1153 usa el
    /// mismo número, sin distinción cold/warm).
    pub const WARM_ACCESS: u64 = 100;
    /// EIP-2200 — sentry de SSTORE: con `gas.remaining() <= SSTORE_SENTRY`
    /// haltea con `OutOfGas` antes de tocar stack o estado (protege el
    /// stipend de 2300 que financia CALL con value).
    pub const SSTORE_SENTRY: u64 = 2300;
    /// EIP-2200 — costo base de SSTORE cuando `original == 0` (primera
    /// escritura del slot en la vida de la cuenta).
    pub const SSTORE_SET: u64 = 20000;
    /// EIP-2200 — costo base de SSTORE cuando `original != 0` y
    /// `current == original` (primer cambio del slot en esta tx).
    pub const SSTORE_RESET: u64 = 2900;
}

/// Deltas de refund de SSTORE (EIP-3529). `i64` porque un refund puede
/// des-acreditarse (deshacer un `SSTORE_CLEARS` previo en la misma tx).
pub mod refund {
    /// Se libera un slot que tenía `original != 0` por primera vez en la tx.
    pub const SSTORE_CLEARS: i64 = 4800;
    /// Slot "dirty" que vuelve a su `original == 0`: deshace el costo de
    /// haberlo puesto en no-cero durante la tx.
    pub const SSTORE_SET_UNDO: i64 = 19900;
    /// Slot "dirty" que vuelve a su `original != 0`.
    pub const SSTORE_RESET_UNDO: i64 = 2800;
}

/// Contador de gas de una ejecución. `remaining` solo baja; nunca se
/// re-acredita acá (los refunds de protocolo llegan con SSTORE, Fase 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gas {
    limit: u64,
    remaining: u64,
}

impl Gas {
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            remaining: limit,
        }
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Gas consumido hasta ahora. `remaining <= limit` es invariante del tipo,
    /// pero se satura igual (fail-closed, sin panic implícito).
    pub fn used(&self) -> u64 {
        self.limit.saturating_sub(self.remaining)
    }

    /// Descuenta `amount`; si no alcanza, `Halt::OutOfGas` sin consumir
    /// parcialmente (el caller decide: un Halt consume todo vía `consume_all`).
    pub fn consume(&mut self, amount: u64) -> Result<(), Halt> {
        self.remaining = self.remaining.checked_sub(amount).ok_or(Halt::OutOfGas)?;
        Ok(())
    }

    /// Consume TODO el gas restante (semántica de Halt).
    pub fn consume_all(&mut self) {
        self.remaining = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_within_limit_updates_remaining_and_used() {
        let mut gas = Gas::new(100);
        assert_eq!(gas.consume(40), Ok(()));
        assert_eq!(gas.remaining(), 60);
        assert_eq!(gas.used(), 40);
    }

    #[test]
    fn consume_exact_remaining_succeeds() {
        let mut gas = Gas::new(10);
        assert_eq!(gas.consume(10), Ok(()));
        assert_eq!(gas.remaining(), 0);
    }

    #[test]
    fn consume_one_more_than_remaining_is_out_of_gas() {
        let mut gas = Gas::new(10);
        assert_eq!(gas.consume(11), Err(Halt::OutOfGas));
        // Fail-closed: el descuento fallido no consume parcialmente.
        assert_eq!(gas.remaining(), 10);
    }

    #[test]
    fn consume_all_zeroes_remaining() {
        let mut gas = Gas::new(100);
        gas.consume_all();
        assert_eq!(gas.remaining(), 0);
        assert_eq!(gas.used(), 100);
    }

    #[test]
    fn zero_limit_rejects_any_nonzero_cost() {
        let mut gas = Gas::new(0);
        assert_eq!(gas.consume(1), Err(Halt::OutOfGas));
        assert_eq!(gas.consume(0), Ok(()));
    }
}
