//! Stack de la EVM: palabras U256, acotado a `STACK_LIMIT` = 1024
//! (ENGINEERING_RULES §2). El límite se hace cumplir en `push`/`dup`
//! (fail-closed); todos los accesos son chequeados — sin indexing crudo.

use alloc::vec::Vec;

use repo_b_common::primitives::U256;

use crate::STACK_LIMIT;
use crate::result::Halt;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stack {
    data: Vec<U256>,
}

impl Stack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Apila `value`; `Halt::StackOverflow` si ya hay `STACK_LIMIT` elementos.
    pub fn push(&mut self, value: U256) -> Result<(), Halt> {
        if self.data.len() >= STACK_LIMIT {
            return Err(Halt::StackOverflow);
        }
        self.data.push(value);
        Ok(())
    }

    /// Desapila el tope; `Halt::StackUnderflow` si está vacío.
    pub fn pop(&mut self) -> Result<U256, Halt> {
        self.data.pop().ok_or(Halt::StackUnderflow)
    }

    /// DUP`n` (n en 1..=16): duplica el n-ésimo elemento desde el tope.
    pub fn dup(&mut self, n: usize) -> Result<(), Halt> {
        let index = self.data.len().checked_sub(n).ok_or(Halt::StackUnderflow)?;
        let value = *self.data.get(index).ok_or(Halt::StackUnderflow)?;
        self.push(value)
    }

    /// SWAP`n` (n en 1..=16): intercambia el tope con el elemento n posiciones
    /// debajo del tope.
    pub fn swap(&mut self, n: usize) -> Result<(), Halt> {
        let top = self.data.len().checked_sub(1).ok_or(Halt::StackUnderflow)?;
        let other = top.checked_sub(n).ok_or(Halt::StackUnderflow)?;
        // Índices verificados arriba (`other < top < len`): `swap` no paniquea.
        self.data.swap(top, other);
        Ok(())
    }

    /// Mira el tope sin desapilar (para tests/debugging del harness).
    pub fn peek(&self) -> Result<U256, Halt> {
        self.data.last().copied().ok_or(Halt::StackUnderflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(v: u64) -> U256 {
        U256::from(v)
    }

    #[test]
    fn push_then_pop_returns_value_lifo() {
        let mut stack = Stack::new();
        assert_eq!(stack.push(u(1)), Ok(()));
        assert_eq!(stack.push(u(2)), Ok(()));
        assert_eq!(stack.pop(), Ok(u(2)));
        assert_eq!(stack.pop(), Ok(u(1)));
    }

    #[test]
    fn pop_on_empty_stack_underflows() {
        let mut stack = Stack::new();
        assert_eq!(stack.pop(), Err(Halt::StackUnderflow));
    }

    #[test]
    fn push_at_limit_succeeds_and_one_more_overflows() {
        let mut stack = Stack::new();
        for i in 0..STACK_LIMIT {
            assert_eq!(stack.push(u(i as u64)), Ok(()));
        }
        assert_eq!(stack.len(), STACK_LIMIT);
        assert_eq!(stack.push(u(0)), Err(Halt::StackOverflow));
        // Fail-closed: el overflow no alteró el stack.
        assert_eq!(stack.len(), STACK_LIMIT);
    }

    #[test]
    fn dup1_duplicates_top() {
        let mut stack = Stack::new();
        assert_eq!(stack.push(u(7)), Ok(()));
        assert_eq!(stack.dup(1), Ok(()));
        assert_eq!(stack.pop(), Ok(u(7)));
        assert_eq!(stack.pop(), Ok(u(7)));
    }

    #[test]
    fn dup16_reaches_sixteenth_element() {
        let mut stack = Stack::new();
        for i in 1..=16u64 {
            assert_eq!(stack.push(u(i)), Ok(()));
        }
        assert_eq!(stack.dup(16), Ok(()));
        assert_eq!(stack.peek(), Ok(u(1)));
    }

    #[test]
    fn dup_beyond_depth_underflows() {
        let mut stack = Stack::new();
        assert_eq!(stack.push(u(1)), Ok(()));
        assert_eq!(stack.dup(2), Err(Halt::StackUnderflow));
    }

    #[test]
    fn dup_when_full_overflows_without_mutating() {
        let mut stack = Stack::new();
        for i in 0..STACK_LIMIT {
            assert_eq!(stack.push(u(i as u64)), Ok(()));
        }
        assert_eq!(stack.dup(1), Err(Halt::StackOverflow));
        assert_eq!(stack.len(), STACK_LIMIT);
    }

    #[test]
    fn swap1_exchanges_top_two() {
        let mut stack = Stack::new();
        assert_eq!(stack.push(u(1)), Ok(()));
        assert_eq!(stack.push(u(2)), Ok(()));
        assert_eq!(stack.swap(1), Ok(()));
        assert_eq!(stack.pop(), Ok(u(1)));
        assert_eq!(stack.pop(), Ok(u(2)));
    }

    #[test]
    fn swap_beyond_depth_underflows() {
        let mut stack = Stack::new();
        assert_eq!(stack.push(u(1)), Ok(()));
        assert_eq!(stack.swap(1), Err(Halt::StackUnderflow));
        let mut empty = Stack::new();
        assert_eq!(empty.swap(1), Err(Halt::StackUnderflow));
    }
}
