//! `repo-b-evm` — el seam `Vm`/`State` (contrato **vendoreado de zeth**, NO
//! redefinido) + la implementación del EVM propio.
//!
//! El contrato de los seams se copia tal cual de zeth para que el EVM sea
//! **drop-in** detrás del seam `Vm` de Repo A (ARCHITECTURE §5.1). Adaptado a
//! `no_std` (zeth lo tiene en `std`): usa `core::fmt`, no `std::error::Error`.
//!
//! `OwnVm` arrancó en Fase 1 como **slice mínimo fail-closed** (transferencias
//! puras; ficha 02 §alcance resuelve la tensión con el DoD de Fase 1). El set
//! completo bit-idéntico vs revm llega en Fase 2. NO redefinir las firmas.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod blob;
pub mod error;
pub mod execution;
pub(crate) mod frames;
pub mod journal;
pub mod own_vm;
pub(crate) mod precompiles;
pub mod result;
pub mod state;
pub mod types;
pub mod vm;
pub mod witness;

pub use error::{ConsensusError, HaltReason, InternalError, StateError, VmError};
pub use journal::{Checkpoint, Journal};
pub use own_vm::OwnVm;
pub use result::{ExecutionOutcome, ExecutionResult, StateChanges};
pub use state::State;
pub use types::{
    AccountInfo, AccountOverride, BlockEnv, CallRequest, CodeMetadata, SYSTEM_ADDRESS,
    SYSTEM_CALL_GAS_LIMIT, Spec, StateOverrides,
};
pub use vm::Vm;
pub use witness::ExecutionWitness;
