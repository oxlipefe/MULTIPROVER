//! Memoria lineal de la EVM: `Vec<u8>` contigua, expansión por palabras de 32
//! bytes con costo cuadrático `3·w + w²/512` (Yellow Paper).
//!
//! Reglas duras: el gas se cobra ANTES de redimensionar (fail-closed: sin gas
//! no hay alloc — el gas es el acotador de memoria del protocolo), toda la
//! aritmética de offsets es `checked_*`, y ningún acceso indexa crudo.

use alloc::vec::Vec;

use repo_b_common::primitives::U256;

use crate::gas::{Gas, cost};
use crate::result::Halt;

/// Tamaño de palabra de la EVM en bytes.
pub const WORD_SIZE: usize = 32;
const WORD_SIZE_U64: u64 = 32;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Memory {
    data: Vec<u8>,
}

/// Costo total de una memoria de `words` palabras: `3·w + w²/512`.
/// `None` = overflow de u64 (irrepresentable ⇒ impagable ⇒ OOG).
fn total_cost(words: u64) -> Option<u64> {
    let linear = words.checked_mul(cost::MEMORY_WORD)?;
    let quadratic = words.checked_mul(words)? / cost::MEMORY_QUAD_DIVISOR;
    linear.checked_add(quadratic)
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tamaño actual en bytes (siempre múltiplo de 32).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Garantiza que `[offset, offset+len)` es direccionable, cobrando el
    /// costo de expansión ANTES de redimensionar. Con `len == 0` no expande
    /// ni cobra (semántica de la spec: el rango vacío no toca memoria).
    pub fn expand(&mut self, offset: u64, len: u64, gas: &mut Gas) -> Result<(), Halt> {
        if len == 0 {
            return Ok(());
        }
        let end = offset.checked_add(len).ok_or(Halt::OutOfGas)?;
        let new_words = end.div_ceil(WORD_SIZE_U64);
        let current_len = u64::try_from(self.data.len()).map_err(|_| Halt::OutOfOffset)?;
        let current_words = current_len.div_ceil(WORD_SIZE_U64);
        if new_words <= current_words {
            return Ok(());
        }
        let expansion = total_cost(new_words)
            .and_then(|new| {
                let current = total_cost(current_words)?;
                new.checked_sub(current)
            })
            .ok_or(Halt::OutOfGas)?;
        gas.consume(expansion)?;
        let new_len_bytes = new_words.checked_mul(WORD_SIZE_U64).ok_or(Halt::OutOfGas)?;
        let new_len = usize::try_from(new_len_bytes).map_err(|_| Halt::OutOfOffset)?;
        self.data.resize(new_len, 0);
        Ok(())
    }

    /// MSTORE: escribe 32 bytes big-endian en `offset`. Requiere `expand`
    /// previo; un rango no direccionable es `Halt::OutOfOffset` (fail-closed).
    pub fn store_word(&mut self, offset: u64, value: U256) -> Result<(), Halt> {
        let slot = checked_range_mut(&mut self.data, offset, WORD_SIZE)?;
        slot.copy_from_slice(&value.to_be_bytes::<WORD_SIZE>());
        Ok(())
    }

    /// MLOAD: lee 32 bytes big-endian desde `offset`. Requiere `expand` previo.
    pub fn load_word(&self, offset: u64) -> Result<U256, Halt> {
        let slot = checked_range(&self.data, offset, WORD_SIZE)?;
        Ok(U256::from_be_slice(slot))
    }

    /// Slice de solo-lectura para RETURN/REVERT. Requiere `expand` previo.
    pub fn slice(&self, offset: u64, len: u64) -> Result<&[u8], Halt> {
        let len = usize::try_from(len).map_err(|_| Halt::OutOfOffset)?;
        checked_range(&self.data, offset, len)
    }

    /// Copia `len` bytes en `[dest, dest+len)` tomando de `src[src_offset..]`,
    /// **rellenando con cero** más allá del final de `src` (semántica de *COPY;
    /// EIP-211 para RETURNDATACOPY). Requiere `expand` previo a `dest+len`; un
    /// rango no direccionable es `Halt::OutOfOffset` (fail-closed).
    pub fn write_padded(
        &mut self,
        dest: u64,
        src: &[u8],
        src_offset: usize,
        len: u64,
    ) -> Result<(), Halt> {
        if len == 0 {
            return Ok(());
        }
        let len = usize::try_from(len).map_err(|_| Halt::OutOfOffset)?;
        let slot = checked_range_mut(&mut self.data, dest, len)?;
        for (i, out) in slot.iter_mut().enumerate() {
            // `src_offset + i` puede overflowear usize (offset fuente enorme) ⇒
            // fuera de `src` ⇒ byte cero.
            *out = src_offset
                .checked_add(i)
                .and_then(|idx| src.get(idx))
                .copied()
                .unwrap_or(0);
        }
        Ok(())
    }
}

fn bounds(offset: u64, len: usize) -> Result<(usize, usize), Halt> {
    let start = usize::try_from(offset).map_err(|_| Halt::OutOfOffset)?;
    let end = start.checked_add(len).ok_or(Halt::OutOfOffset)?;
    Ok((start, end))
}

fn checked_range(data: &[u8], offset: u64, len: usize) -> Result<&[u8], Halt> {
    let (start, end) = bounds(offset, len)?;
    data.get(start..end).ok_or(Halt::OutOfOffset)
}

fn checked_range_mut(data: &mut [u8], offset: u64, len: usize) -> Result<&mut [u8], Halt> {
    let (start, end) = bounds(offset, len)?;
    data.get_mut(start..end).ok_or(Halt::OutOfOffset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expanding_one_word_charges_three_gas() {
        // w=1: 3·1 + 1/512 = 3.
        let mut memory = Memory::new();
        let mut gas = Gas::new(100);
        assert_eq!(memory.expand(0, 32, &mut gas), Ok(()));
        assert_eq!(gas.used(), 3);
        assert_eq!(memory.len(), 32);
    }

    #[test]
    fn expansion_cost_is_quadratic_beyond_linear_term() {
        // w=1024: 3·1024 + 1024²/512 = 3072 + 2048 = 5120.
        let mut memory = Memory::new();
        let mut gas = Gas::new(10_000);
        assert_eq!(memory.expand(0, 1024 * 32, &mut gas), Ok(()));
        assert_eq!(gas.used(), 5120);
    }

    #[test]
    fn expansion_charges_only_the_delta() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(10_000);
        assert_eq!(memory.expand(0, 32, &mut gas), Ok(()));
        assert_eq!(memory.expand(32, 32, &mut gas), Ok(()));
        // w=2: 6 + 4/512 = 6 total; delta = 3.
        assert_eq!(gas.used(), 6);
    }

    #[test]
    fn expanding_within_current_size_is_free() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(100);
        assert_eq!(memory.expand(0, 64, &mut gas), Ok(()));
        let used = gas.used();
        assert_eq!(memory.expand(0, 32, &mut gas), Ok(()));
        assert_eq!(gas.used(), used);
    }

    #[test]
    fn zero_length_expansion_is_noop_even_at_huge_offset() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(100);
        assert_eq!(memory.expand(u64::MAX, 0, &mut gas), Ok(()));
        assert_eq!(gas.used(), 0);
        assert_eq!(memory.len(), 0);
    }

    #[test]
    fn unaffordable_expansion_is_out_of_gas_and_does_not_grow_memory() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(2);
        assert_eq!(memory.expand(0, 32, &mut gas), Err(Halt::OutOfGas));
        // Fail-closed: se cobra antes de redimensionar.
        assert_eq!(memory.len(), 0);
        assert_eq!(gas.remaining(), 2);
    }

    #[test]
    fn offset_plus_len_overflow_is_out_of_gas() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(u64::MAX);
        assert_eq!(memory.expand(u64::MAX, 1, &mut gas), Err(Halt::OutOfGas));
    }

    #[test]
    fn store_then_load_roundtrips_big_endian() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(100);
        let value = U256::from(0xDEAD_BEEFu64);
        assert_eq!(memory.expand(0, 32, &mut gas), Ok(()));
        assert_eq!(memory.store_word(0, value), Ok(()));
        assert_eq!(memory.load_word(0), Ok(value));
    }

    #[test]
    fn access_beyond_expanded_range_is_out_of_offset() {
        let memory = Memory::new();
        assert_eq!(memory.load_word(0), Err(Halt::OutOfOffset));
        let mut memory = Memory::new();
        assert_eq!(memory.store_word(0, U256::ZERO), Err(Halt::OutOfOffset));
    }

    #[test]
    fn slice_returns_exact_window() {
        let mut memory = Memory::new();
        let mut gas = Gas::new(100);
        assert_eq!(memory.expand(0, 32, &mut gas), Ok(()));
        assert_eq!(memory.store_word(0, U256::from(1u64)), Ok(()));
        assert_eq!(memory.slice(31, 1), Ok(&[1u8][..]));
        assert_eq!(memory.slice(0, 33), Err(Halt::OutOfOffset));
    }
}
