//! Step-tracer EIP-3155, opt-in detrás de la feature `tracer` (PHASE_2_ROADMAP
//! §Velocidad regla 6: "el tracer no contamina el guest"). Este módulo entero
//! desaparece del árbol de compilación sin la feature — no es un no-op.
//!
//! El intérprete NUNCA cambia de semántica por trazar (Prohibido, task 003):
//! `run_traced` observa exactamente los mismos `Control`/`Halt` que `run`.

use alloc::string::String;
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::receipt::Log;

use crate::host::{AccountLoad, BlockEnv, Host, SStoreResult, StateLoad, TxEnv};
use crate::opcode;
use crate::result::Halt;

/// Un paso de ejecución en formato EIP-3155. Los campos numéricos (`gas`,
/// `stack`, …) reflejan el estado **antes** de ejecutar `op` — `gas_cost` es
/// lo único calculado post-hoc (delta de gas del opcode completo, incluida
/// expansión de memoria).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    pub pc: usize,
    pub op: u8,
    pub op_name: String,
    /// Gas restante ANTES de ejecutar `op`.
    pub gas: u64,
    /// Costo total del opcode completo (incl. expansión de memoria).
    pub gas_cost: u64,
    /// Stack completo antes de `op`; tope al final.
    pub stack: Vec<U256>,
    pub depth: usize,
    pub mem_size: usize,
    /// Refund acumulado antes de `op` (EIP-3529).
    pub refund: i64,
    /// Motivo del halt si este paso termina la ejecución con error.
    pub error: Option<&'static str>,
}

/// Recibe cada `StepRecord` a medida que el intérprete avanza. `run_traced`
/// llama a `step` una vez por opcode ejecutado.
pub trait StepSink {
    fn step(&mut self, record: &StepRecord);
}

/// Decorador de `Host` solo para tracing: delega todo al host real y además
/// acumula el refund total corriendo, para poder reportarlo en `StepRecord`
/// sin agregarle un getter al seam `Host` (que se mantiene mínimo).
///
/// Lo construye **el executor**, no `run_traced`: el refund de EIP-3155 es
/// acumulado de la tx entera, así que cruza los frames. Se crea uno por
/// `run_traced` con el total heredado (`with_total`) y se lee de vuelta al
/// terminar — así el borrow del journal muere entre frames y el executor
/// puede hacer sus checkpoints.
pub struct RefundTrackingHost<'a> {
    inner: &'a mut dyn Host,
    total: i64,
}

impl<'a> RefundTrackingHost<'a> {
    pub fn new(inner: &'a mut dyn Host) -> Self {
        Self::with_total(inner, 0)
    }

    pub fn with_total(inner: &'a mut dyn Host, total: i64) -> Self {
        Self { inner, total }
    }

    pub fn total(&self) -> i64 {
        self.total
    }
}

impl Host for RefundTrackingHost<'_> {
    fn sload(&mut self, addr: Address, key: U256) -> StateLoad<U256> {
        self.inner.sload(addr, key)
    }

    fn sstore(&mut self, addr: Address, key: U256, value: U256) -> StateLoad<SStoreResult> {
        self.inner.sstore(addr, key, value)
    }

    fn tload(&mut self, addr: Address, key: U256) -> U256 {
        self.inner.tload(addr, key)
    }

    fn tstore(&mut self, addr: Address, key: U256, value: U256) {
        self.inner.tstore(addr, key, value);
    }

    fn refund(&mut self, delta: i64) {
        self.total = self.total.saturating_add(delta);
        self.inner.refund(delta);
    }

    fn env(&self) -> &BlockEnv {
        self.inner.env()
    }

    fn tx(&self) -> &TxEnv {
        self.inner.tx()
    }

    fn self_balance(&mut self, addr: Address) -> U256 {
        self.inner.self_balance(addr)
    }

    fn block_hash(&mut self, number: u64) -> B256 {
        self.inner.block_hash(number)
    }

    fn log(&mut self, log: Log) {
        self.inner.log(log);
    }

    fn load_account(&mut self, addr: Address) -> StateLoad<AccountLoad> {
        self.inner.load_account(addr)
    }

    fn code_by_address(&mut self, addr: Address) -> StateLoad<Bytes> {
        self.inner.code_by_address(addr)
    }
}

/// Nombre EIP-3155 (`opName`) del opcode. Espeja el dispatch de
/// `Interpreter::step`; los bytes no asignados (fail-closed allá) reportan
/// `"UNKNOWN"` acá — es un campo de diagnóstico, no de consenso.
pub(crate) fn op_name(op: u8) -> String {
    match op {
        opcode::STOP => String::from("STOP"),
        opcode::ADD => String::from("ADD"),
        opcode::MUL => String::from("MUL"),
        opcode::SUB => String::from("SUB"),
        opcode::KECCAK256 => String::from("KECCAK256"),
        opcode::ADDRESS => String::from("ADDRESS"),
        opcode::CALLER => String::from("CALLER"),
        opcode::CALLVALUE => String::from("CALLVALUE"),
        opcode::CALLDATALOAD => String::from("CALLDATALOAD"),
        opcode::CALLDATASIZE => String::from("CALLDATASIZE"),
        opcode::CALLDATACOPY => String::from("CALLDATACOPY"),
        opcode::CODESIZE => String::from("CODESIZE"),
        opcode::CODECOPY => String::from("CODECOPY"),
        opcode::GASPRICE => String::from("GASPRICE"),
        opcode::COINBASE => String::from("COINBASE"),
        opcode::TIMESTAMP => String::from("TIMESTAMP"),
        opcode::NUMBER => String::from("NUMBER"),
        opcode::PREVRANDAO => String::from("PREVRANDAO"),
        opcode::GASLIMIT => String::from("GASLIMIT"),
        opcode::CHAINID => String::from("CHAINID"),
        opcode::SELFBALANCE => String::from("SELFBALANCE"),
        opcode::BASEFEE => String::from("BASEFEE"),
        opcode::BLOBHASH => String::from("BLOBHASH"),
        opcode::BLOBBASEFEE => String::from("BLOBBASEFEE"),
        opcode::BLOCKHASH => String::from("BLOCKHASH"),
        opcode::ORIGIN => String::from("ORIGIN"),
        opcode::POP => String::from("POP"),
        opcode::MLOAD => String::from("MLOAD"),
        opcode::MSTORE => String::from("MSTORE"),
        opcode::SLOAD => String::from("SLOAD"),
        opcode::SSTORE => String::from("SSTORE"),
        opcode::JUMP => String::from("JUMP"),
        opcode::JUMPI => String::from("JUMPI"),
        opcode::PC => String::from("PC"),
        opcode::MSIZE => String::from("MSIZE"),
        opcode::GAS => String::from("GAS"),
        opcode::JUMPDEST => String::from("JUMPDEST"),
        opcode::TLOAD => String::from("TLOAD"),
        opcode::TSTORE => String::from("TSTORE"),
        opcode::PUSH0 => String::from("PUSH0"),
        opcode::PUSH1..=opcode::PUSH32 => {
            alloc::format!("PUSH{}", opcode::push_immediate_len(op))
        }
        opcode::DUP1..=opcode::DUP16 => {
            alloc::format!("DUP{}", op.wrapping_sub(opcode::DUP1).wrapping_add(1))
        }
        opcode::SWAP1..=opcode::SWAP16 => {
            alloc::format!("SWAP{}", op.wrapping_sub(opcode::SWAP1).wrapping_add(1))
        }
        opcode::LOG0..=opcode::LOG4 => {
            alloc::format!("LOG{}", op.wrapping_sub(opcode::LOG0))
        }
        opcode::RETURNDATASIZE => String::from("RETURNDATASIZE"),
        opcode::RETURNDATACOPY => String::from("RETURNDATACOPY"),
        opcode::CALL => String::from("CALL"),
        opcode::CALLCODE => String::from("CALLCODE"),
        opcode::DELEGATECALL => String::from("DELEGATECALL"),
        opcode::STATICCALL => String::from("STATICCALL"),
        opcode::RETURN => String::from("RETURN"),
        opcode::REVERT => String::from("REVERT"),
        opcode::INVALID => String::from("INVALID"),
        _ => String::from("UNKNOWN"),
    }
}

/// Nombre del `Halt` para el campo `error` del `StepRecord`. Mapping TOTAL
/// (sin `_`): un `Halt` nuevo sin caso acá no compila (ENGINEERING_RULES).
pub(crate) fn halt_name(reason: Halt) -> &'static str {
    match reason {
        Halt::OutOfGas => "OutOfGas",
        Halt::StackUnderflow => "StackUnderflow",
        Halt::StackOverflow => "StackOverflow",
        Halt::InvalidJump => "InvalidJump",
        Halt::OpcodeNotFound => "OpcodeNotFound",
        Halt::InvalidFEOpcode => "InvalidFEOpcode",
        Halt::OutOfOffset => "OutOfOffset",
        Halt::StateChangeDuringStaticCall => "StateChangeDuringStaticCall",
    }
}
