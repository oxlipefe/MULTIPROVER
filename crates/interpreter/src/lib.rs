//! `repo-b-interpreter` — la máquina de pila (stack/memory/gas/opcodes).
//!
//! **Fase 1 (EN CURSO).** Stack acotado a 1024, memory con costo cuadrático,
//! contador de gas mapeado tight a la spec (fork target: Prague), dispatch por
//! `match` y la trichotomy Success/Revert/Halt. La aritmética U256 modela la
//! semántica de wrapping de la EVM **explícita**.
//!
//! Decisiones de diseño y KNOWN-UNVERIFIED: `docs/knowledge/01-interpreter.md`.
//! Depende SOLO de `repo-b-common` (regla maestra de dependencias); la
//! trichotomy local se mapea al seam `Vm` en `repo-b-evm` (Fase 2).
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bytecode;
pub mod call;
pub mod context;
pub mod gas;
pub mod host;
pub mod interpreter;
pub mod memory;
pub mod opcode;
pub mod result;
pub mod stack;
#[cfg(feature = "tracer")]
pub mod tracer;

pub use bytecode::Bytecode;
pub use call::{CallInputs, CallKind, InterpreterAction, SubcallOutcome};
pub use context::CallContext;
pub use gas::Gas;
pub use host::{Host, SStoreResult, StateLoad};
pub use interpreter::Interpreter;
pub use memory::Memory;
pub use result::{Halt, InterpreterOutcome};
pub use stack::Stack;
#[cfg(feature = "tracer")]
pub use tracer::{RefundTrackingHost, StepRecord, StepSink};

/// Tope de la pila de la EVM (constante nombrada; ENGINEERING_RULES §2).
pub const STACK_LIMIT: usize = 1024;

/// Profundidad máxima de call stack (constante nombrada).
pub const CALL_DEPTH_LIMIT: usize = 1024;
