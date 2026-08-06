//! El loop de ejecución: dispatch por `match` exhaustivo sobre el byte del
//! opcode (decisión de Fase 1: legibilidad/verificabilidad > perf; ficha 01).
//!
//! Semántica de consenso implementada acá:
//! - Caer del final del código = STOP implícito.
//! - Wrapping U256 **de protocolo** explícito (ADD/MUL/SUB); overflow **de
//!   implementación** (gas/offsets) = `Halt`, fail-closed.
//! - Trichotomy: `Halt` consume TODO el gas; `Revert`/`Success` devuelven el
//!   restante al caller (reflejado en `gas_used`).

use repo_b_common::primitives::{Address, Bytes, KECCAK256_EMPTY, U256, keccak256};

use crate::bytecode::Bytecode;
use crate::context::CallContext;
use crate::gas::{Gas, cost, refund};
use crate::host::{Host, SStoreResult};
use crate::memory::Memory;
use crate::opcode;
use crate::result::{Halt, InterpreterOutcome};
use crate::stack::Stack;

/// Control de flujo interno de un paso del intérprete.
enum Control {
    /// Avanzar el pc `n` bytes (1 + inmediatos).
    Advance(usize),
    /// Salto validado a un `JUMPDEST`.
    Jump(usize),
    /// STOP (explícito o implícito).
    Stop,
    /// RETURN con `[offset, offset+len)` de memoria como output.
    Return { offset: u64, len: u64 },
    /// REVERT con output; devuelve el gas restante.
    Revert { offset: u64, len: u64 },
}

/// La máquina de pila. Ejecuta un frame de bytecode (con su `CallContext`) bajo
/// un límite de gas. (World access —SLOAD/CALL/…— llega en slice 2.2 vía `Host`.)
#[derive(Debug)]
pub struct Interpreter {
    context: CallContext,
    bytecode: Bytecode,
    stack: Stack,
    memory: Memory,
    gas: Gas,
    pc: usize,
}

impl Interpreter {
    /// Construye el intérprete para un frame. El código a ejecutar sale del
    /// `context` (`bytecode`), que también alimenta los opcodes de contexto.
    pub fn new(context: CallContext, gas_limit: u64) -> Self {
        let bytecode = Bytecode::analyze(context.bytecode.clone());
        Self {
            context,
            bytecode,
            stack: Stack::new(),
            memory: Memory::new(),
            gas: Gas::new(gas_limit),
            pc: 0,
        }
    }

    /// Conveniencia: frame "desnudo" (contexto en cero) para ejecutar código sin
    /// contexto de call — tests de opcodes puros y el arranque de una tx simple.
    pub fn for_code(code: Bytes, gas_limit: u64) -> Self {
        Self::new(CallContext::for_code(code), gas_limit)
    }

    /// Corre hasta terminar. Consume el intérprete: un frame se ejecuta una
    /// sola vez y el resultado es un valor (el motor nunca muta estado
    /// externo). `host` es todo lo que toca el mundo (ADR-0002); el
    /// intérprete no lo posee, solo lo pide prestado por el run.
    pub fn run(mut self, host: &mut dyn Host) -> InterpreterOutcome {
        loop {
            let Some(&op) = self.bytecode.code().get(self.pc) else {
                // STOP implícito al caer del final del código.
                return self.success(Bytes::new());
            };
            match self.step(op, host) {
                Ok(Control::Advance(n)) => self.pc = self.pc.saturating_add(n),
                Ok(Control::Jump(dest)) => self.pc = dest,
                Ok(Control::Stop) => return self.success(Bytes::new()),
                Ok(Control::Return { offset, len }) => {
                    return match self.output(offset, len) {
                        Ok(output) => self.success(output),
                        Err(reason) => self.halt(reason),
                    };
                }
                Ok(Control::Revert { offset, len }) => {
                    return match self.output(offset, len) {
                        Ok(output) => InterpreterOutcome::Revert {
                            output,
                            gas_used: self.gas.used(),
                        },
                        Err(reason) => self.halt(reason),
                    };
                }
                Err(reason) => return self.halt(reason),
            }
        }
    }

    /// Ejecuta el opcode `op`. Errores = `Halt` (el caller consume todo el gas).
    fn step(&mut self, op: u8, host: &mut dyn Host) -> Result<Control, Halt> {
        match op {
            opcode::STOP => Ok(Control::Stop),
            opcode::ADD => {
                self.gas.consume(cost::VERYLOW)?;
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                // Wrapping de protocolo (la EVM no paniquea en overflow aritmético).
                self.stack.push(a.wrapping_add(b))?;
                Ok(Control::Advance(1))
            }
            opcode::MUL => {
                self.gas.consume(cost::LOW)?;
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push(a.wrapping_mul(b))?;
                Ok(Control::Advance(1))
            }
            opcode::SUB => {
                self.gas.consume(cost::VERYLOW)?;
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push(a.wrapping_sub(b))?;
                Ok(Control::Advance(1))
            }
            opcode::POP => {
                self.gas.consume(cost::BASE)?;
                self.stack.pop()?;
                Ok(Control::Advance(1))
            }
            opcode::MLOAD => {
                self.gas.consume(cost::VERYLOW)?;
                let offset = word_offset(self.stack.pop()?)?;
                self.memory.expand(offset, 32, &mut self.gas)?;
                let value = self.memory.load_word(offset)?;
                self.stack.push(value)?;
                Ok(Control::Advance(1))
            }
            opcode::MSTORE => {
                self.gas.consume(cost::VERYLOW)?;
                let offset = word_offset(self.stack.pop()?)?;
                let value = self.stack.pop()?;
                self.memory.expand(offset, 32, &mut self.gas)?;
                self.memory.store_word(offset, value)?;
                Ok(Control::Advance(1))
            }
            opcode::JUMP => {
                self.gas.consume(cost::MID)?;
                let dest = self.jump_dest()?;
                Ok(Control::Jump(dest))
            }
            opcode::JUMPI => {
                self.gas.consume(cost::HIGH)?;
                let dest_raw = self.stack.pop()?;
                let condition = self.stack.pop()?;
                if condition.is_zero() {
                    Ok(Control::Advance(1))
                } else {
                    Ok(Control::Jump(validate_jump(&self.bytecode, dest_raw)?))
                }
            }
            opcode::JUMPDEST => {
                self.gas.consume(cost::JUMPDEST)?;
                Ok(Control::Advance(1))
            }
            opcode::PUSH0 => {
                // EIP-3855 (Shanghai+; fork target = Prague, ficha 01).
                self.gas.consume(cost::BASE)?;
                self.stack.push(U256::ZERO)?;
                Ok(Control::Advance(1))
            }
            opcode::PUSH1..=opcode::PUSH32 => {
                self.gas.consume(cost::VERYLOW)?;
                let n = opcode::push_immediate_len(op);
                let value = self.read_push_immediates(n);
                self.stack.push(value)?;
                Ok(Control::Advance(n.saturating_add(1)))
            }
            opcode::DUP1..=opcode::DUP16 => {
                self.gas.consume(cost::VERYLOW)?;
                // `op ∈ [DUP1, DUP16]` garantiza que la resta no underflowea.
                let n = usize::from(op.wrapping_sub(opcode::DUP1)).saturating_add(1);
                self.stack.dup(n)?;
                Ok(Control::Advance(1))
            }
            opcode::SWAP1..=opcode::SWAP16 => {
                self.gas.consume(cost::VERYLOW)?;
                let n = usize::from(op.wrapping_sub(opcode::SWAP1)).saturating_add(1);
                self.stack.swap(n)?;
                Ok(Control::Advance(1))
            }
            opcode::KECCAK256 => self.keccak256_op(),
            opcode::ADDRESS => self.push_context_word(word_from_address(self.context.address)),
            opcode::CALLER => self.push_context_word(word_from_address(self.context.caller)),
            opcode::CALLVALUE => self.push_context_word(self.context.value),
            opcode::CALLDATALOAD => {
                self.gas.consume(cost::VERYLOW)?;
                let offset = self.stack.pop()?;
                let value = self.calldata_word(offset);
                self.stack.push(value)?;
                Ok(Control::Advance(1))
            }
            opcode::CALLDATASIZE => {
                let size = len_as_word(self.context.calldata.len());
                self.push_context_word(size)
            }
            opcode::CALLDATACOPY => {
                self.gas.consume(cost::VERYLOW)?;
                let dest = self.stack.pop()?;
                let src_offset = self.stack.pop()?;
                let len = self.stack.pop()?;
                let source = self.context.calldata.clone();
                self.copy_to_memory(dest, src_offset, len, &source)?;
                Ok(Control::Advance(1))
            }
            opcode::CODESIZE => {
                let size = len_as_word(self.bytecode.len());
                self.push_context_word(size)
            }
            opcode::CODECOPY => {
                self.gas.consume(cost::VERYLOW)?;
                let dest = self.stack.pop()?;
                let src_offset = self.stack.pop()?;
                let len = self.stack.pop()?;
                let source = self.context.bytecode.clone();
                self.copy_to_memory(dest, src_offset, len, &source)?;
                Ok(Control::Advance(1))
            }
            opcode::PC => {
                let pc = len_as_word(self.pc);
                self.push_context_word(pc)
            }
            opcode::MSIZE => {
                let size = len_as_word(self.memory.len());
                self.push_context_word(size)
            }
            opcode::GAS => {
                // El valor es el gas restante DESPUÉS de descontar el propio GAS.
                self.gas.consume(cost::BASE)?;
                self.stack.push(U256::from(self.gas.remaining()))?;
                Ok(Control::Advance(1))
            }
            // --- opcodes de storage (slice 2.2; seam `Host`, ADR-0002) ---
            opcode::SLOAD => {
                let key = self.stack.pop()?;
                let load = host.sload(self.context.address, key);
                let gas_cost = if load.is_cold {
                    cost::COLD_SLOAD
                } else {
                    cost::WARM_ACCESS
                };
                self.gas.consume(gas_cost)?;
                self.stack.push(load.data)?;
                Ok(Control::Advance(1))
            }
            opcode::SSTORE => self.sstore_op(host),
            opcode::TLOAD => {
                self.gas.consume(cost::WARM_ACCESS)?;
                let key = self.stack.pop()?;
                let value = host.tload(self.context.address, key);
                self.stack.push(value)?;
                Ok(Control::Advance(1))
            }
            opcode::TSTORE => {
                if self.context.is_static {
                    return Err(Halt::StateChangeDuringStaticCall);
                }
                self.gas.consume(cost::WARM_ACCESS)?;
                let key = self.stack.pop()?;
                let value = self.stack.pop()?;
                host.tstore(self.context.address, key, value);
                Ok(Control::Advance(1))
            }
            opcode::RETURN => {
                self.gas.consume(cost::ZERO)?;
                let (offset, len) = self.output_range()?;
                Ok(Control::Return { offset, len })
            }
            opcode::REVERT => {
                self.gas.consume(cost::ZERO)?;
                let (offset, len) = self.output_range()?;
                Ok(Control::Revert { offset, len })
            }
            opcode::INVALID => Err(Halt::InvalidFEOpcode),
            // Fail-closed: todo byte no asignado en el set actual halta.
            _ => Err(Halt::OpcodeNotFound),
        }
    }

    /// Lee los `n` bytes inmediatos de un PUSH, rellenando con ceros a la
    /// derecha si el código termina antes (semántica de la spec).
    fn read_push_immediates(&self, n: usize) -> U256 {
        let mut buf = [0u8; 32];
        let code = self.bytecode.code();
        let start = self.pc.saturating_add(1);
        let end = start.saturating_add(n).min(code.len());
        let available = code.get(start..end).unwrap_or(&[]);
        // Los inmediatos son los bytes ALTOS del valor: un PUSH2 truncado a un
        // byte vale `byte << 8`, no `byte`.
        let buf_start = 32usize.saturating_sub(n);
        let buf_end = buf_start.saturating_add(available.len());
        if let Some(slot) = buf.get_mut(buf_start..buf_end) {
            slot.copy_from_slice(available);
        }
        U256::from_be_bytes(buf)
    }

    fn jump_dest(&mut self) -> Result<usize, Halt> {
        let dest_raw = self.stack.pop()?;
        validate_jump(&self.bytecode, dest_raw)
    }

    /// Pop de `(offset, len)` para RETURN/REVERT + expansión de memoria.
    fn output_range(&mut self) -> Result<(u64, u64), Halt> {
        let offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        // Con len == 0 el offset no toca memoria (no se valida ni cobra).
        let offset = if len == 0 {
            0
        } else {
            word_offset(offset_raw)?
        };
        self.memory.expand(offset, len, &mut self.gas)?;
        Ok((offset, len))
    }

    fn output(&self, offset: u64, len: u64) -> Result<Bytes, Halt> {
        if len == 0 {
            return Ok(Bytes::new());
        }
        let slice = self.memory.slice(offset, len)?;
        Ok(Bytes::copy_from_slice(slice))
    }

    fn success(&self, output: Bytes) -> InterpreterOutcome {
        InterpreterOutcome::Success {
            output,
            gas_used: self.gas.used(),
        }
    }

    /// Opcodes de contexto que cuestan `G_base` y solo apilan un valor
    /// (ADDRESS/CALLER/CALLVALUE/CALLDATASIZE/CODESIZE/PC/MSIZE).
    fn push_context_word(&mut self, value: U256) -> Result<Control, Halt> {
        self.gas.consume(cost::BASE)?;
        self.stack.push(value)?;
        Ok(Control::Advance(1))
    }

    /// KECCAK256: hash de `[offset, offset+len)` de memoria. Gas: 30 + 6·palabras
    /// + expansión. `len == 0` no toca memoria y hashea el vacío (revm-idéntico).
    fn keccak256_op(&mut self) -> Result<Control, Halt> {
        let offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let words = len.div_ceil(32);
        let word_cost = words
            .checked_mul(cost::KECCAK256_WORD)
            .ok_or(Halt::OutOfGas)?;
        self.gas.consume(cost::KECCAK256)?;
        self.gas.consume(word_cost)?;
        let hash = if len == 0 {
            KECCAK256_EMPTY
        } else {
            let offset = word_offset(offset_raw)?;
            self.memory.expand(offset, len, &mut self.gas)?;
            keccak256(self.memory.slice(offset, len)?)
        };
        self.stack.push(U256::from_be_slice(hash.as_slice()))?;
        Ok(Control::Advance(1))
    }

    /// SSTORE (EIP-2200/2929/3529), en el orden de la spec: sentry → gate de
    /// static → costo (cold surcharge + base) → refund.
    fn sstore_op(&mut self, host: &mut dyn Host) -> Result<Control, Halt> {
        // Sentry EIP-2200: protege el stipend de 2300 que financia CALL con
        // value (sin stack pops todavía — el chequeo no los necesita).
        if self.gas.remaining() <= cost::SSTORE_SENTRY {
            return Err(Halt::OutOfGas);
        }
        if self.context.is_static {
            return Err(Halt::StateChangeDuringStaticCall);
        }
        // Yellow Paper: µ_s[0] = key (tope), µ_s[1] = value.
        let key = self.stack.pop()?;
        let value = self.stack.pop()?;
        let load = host.sstore(self.context.address, key, value);
        let SStoreResult {
            original,
            current,
            new,
        } = load.data;
        let base = if new == current {
            cost::WARM_ACCESS
        } else if current == original && original.is_zero() {
            cost::SSTORE_SET
        } else if current == original {
            cost::SSTORE_RESET
        } else {
            cost::WARM_ACCESS
        };
        let surcharge = if load.is_cold { cost::COLD_SLOAD } else { 0 };
        let gas_cost = surcharge.checked_add(base).ok_or(Halt::OutOfGas)?;
        self.gas.consume(gas_cost)?;
        sstore_refund(host, original, current, new);
        Ok(Control::Advance(1))
    }

    /// Lee 32 bytes de calldata desde `offset`, con relleno de ceros más allá del
    /// final (CALLDATALOAD). Un offset irrepresentable ⇒ ventana toda-cero.
    fn calldata_word(&self, offset_raw: U256) -> U256 {
        let mut buf = [0u8; 32];
        let start = usize::try_from(offset_raw).unwrap_or(usize::MAX);
        for (i, slot) in buf.iter_mut().enumerate() {
            if let Some(byte) = start
                .checked_add(i)
                .and_then(|idx| self.context.calldata.get(idx))
            {
                *slot = *byte;
            }
        }
        U256::from_be_slice(&buf)
    }

    /// Cuerpo común de CALLDATACOPY/CODECOPY: gas `3·palabras` (base `G_verylow`
    /// ya cobrado por el caller) + expansión, y copia zero-padded a memoria.
    fn copy_to_memory(
        &mut self,
        dest_raw: U256,
        src_offset_raw: U256,
        len_raw: U256,
        source: &[u8],
    ) -> Result<(), Halt> {
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let words = len.div_ceil(32);
        let copy_cost = words.checked_mul(cost::COPY).ok_or(Halt::OutOfGas)?;
        self.gas.consume(copy_cost)?;
        if len == 0 {
            return Ok(());
        }
        let dest = word_offset(dest_raw)?;
        self.memory.expand(dest, len, &mut self.gas)?;
        let src_offset = usize::try_from(src_offset_raw).unwrap_or(usize::MAX);
        self.memory.write_padded(dest, source, src_offset, len)
    }

    /// Semántica de Halt: consume TODO el gas.
    fn halt(&mut self, reason: Halt) -> InterpreterOutcome {
        self.gas.consume_all();
        InterpreterOutcome::Halt {
            reason,
            gas_used: self.gas.used(),
        }
    }
}

/// Una dirección como palabra de stack: 20 bytes big-endian right-aligned.
fn word_from_address(addr: Address) -> U256 {
    U256::from_be_slice(addr.as_slice())
}

/// Una longitud (`usize`) como palabra de stack. Un valor que no entra en u64
/// se satura (en la práctica inalcanzable: la memoria/código están acotados por
/// gas mucho antes).
fn len_as_word(len: usize) -> U256 {
    U256::from(u64::try_from(len).unwrap_or(u64::MAX))
}

/// Offset de memoria desde el stack. Un offset que no entra en u64 es
/// impagable (el costo de expansión desborda) ⇒ OOG.
fn word_offset(raw: U256) -> Result<u64, Halt> {
    u64::try_from(raw).map_err(|_| Halt::OutOfGas)
}

/// Refund de SSTORE (EIP-3529), literal a la spec (números calculados a mano
/// en los tests, no derivados de este código).
fn sstore_refund(host: &mut dyn Host, original: U256, current: U256, new: U256) {
    if current == original {
        // Primer cambio del slot en esta tx: se libera un `original != 0`.
        if current != new && !original.is_zero() && new.is_zero() {
            host.refund(refund::SSTORE_CLEARS);
        }
        return;
    }
    // Slot "dirty": ya se tocó antes en esta misma tx.
    if !original.is_zero() {
        if current.is_zero() {
            host.refund(-refund::SSTORE_CLEARS);
        }
        if new.is_zero() {
            host.refund(refund::SSTORE_CLEARS);
        }
    }
    if new == original {
        if original.is_zero() {
            host.refund(refund::SSTORE_SET_UNDO);
        } else {
            host.refund(refund::SSTORE_RESET_UNDO);
        }
    }
}

/// Valida un destino de salto: debe entrar en usize Y ser un `JUMPDEST` en
/// posición de opcode. Todo lo demás es `Halt::InvalidJump` (fail-closed).
fn validate_jump(bytecode: &Bytecode, dest_raw: U256) -> Result<usize, Halt> {
    let dest = usize::try_from(dest_raw).map_err(|_| Halt::InvalidJump)?;
    if !bytecode.is_valid_jumpdest(dest) {
        return Err(Halt::InvalidJump);
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interpreter_at_start(code: &[u8]) -> Interpreter {
        Interpreter::for_code(Bytes::copy_from_slice(code), 0)
    }

    #[test]
    fn push_immediates_read_full_width() {
        // PUSH2 0x12 0x34 → 0x1234.
        let interpreter = interpreter_at_start(&[0x61, 0x12, 0x34]);
        assert_eq!(interpreter.read_push_immediates(2), U256::from(0x1234u64));
    }

    #[test]
    fn truncated_push_immediates_zero_pad_low_bytes() {
        // PUSH2 con un solo byte disponible: el byte leído es el ALTO del par
        // (spec: los bytes faltantes tras el fin del código son cero).
        let interpreter = interpreter_at_start(&[0x61, 0x12]);
        assert_eq!(interpreter.read_push_immediates(2), U256::from(0x1200u64));
    }

    #[test]
    fn push_with_no_immediates_available_reads_zero() {
        // PUSH32 como último byte del código: valor = 0.
        let interpreter = interpreter_at_start(&[0x7F]);
        assert_eq!(interpreter.read_push_immediates(32), U256::ZERO);
    }
}
