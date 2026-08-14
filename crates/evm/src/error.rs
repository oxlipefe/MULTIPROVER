//! Errores del seam (vendoreado de zeth, adaptado a `no_std` con `core::fmt`).
//!
//! Taxonomía: `ConsensusError` (juicio determinista sobre
//! la tx → se rechaza) vs `InternalError` (falla del motor: bug). NUNCA se
//! mezclan. `HaltReason` es un halt legítimo del protocolo (consume todo el gas).

use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum VmError {
    Consensus(ConsensusError),
    Internal(InternalError),
}

#[derive(Debug)]
pub enum ConsensusError {
    IntrinsicGasTooLow { required: u64, available: u64 },
    NonceInvalid { expected: u64, actual: u64 },
    InsufficientBalance { required: String, available: String },
    InvalidTransaction(String),
    SenderRecoveryFailed(String),
}

#[derive(Debug)]
pub enum InternalError {
    StateAccess(StateError),
    EvmInternal(String),
}

#[derive(Debug, Clone)]
pub enum StateError {
    Database(String),
}

/// Halt legítimo del protocolo. Consume TODO el gas (distinto de REVERT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    OutOfGas,
    OpcodeNotFound,
    InvalidFEOpcode,
    InvalidJump,
    NotActivated,
    StackUnderflow,
    StackOverflow,
    OutOfOffset,
    CreateCollision,
    PrecompileError,
    NonceOverflow,
    CreateContractSizeLimit,
    CreateContractStartingWithEF,
    CreateInitCodeSizeLimit,
    OverflowPayment,
    StateChangeDuringStaticCall,
    CallNotAllowedInsideStatic,
    OutOfFunds,
    CallTooDeep,
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(e) => write!(f, "consensus error: {e}"),
            Self::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntrinsicGasTooLow {
                required,
                available,
            } => {
                write!(
                    f,
                    "intrinsic gas too low: required {required}, available {available}"
                )
            }
            Self::NonceInvalid { expected, actual } => {
                write!(f, "nonce invalid: expected {expected}, got {actual}")
            }
            Self::InsufficientBalance {
                required,
                available,
            } => {
                write!(
                    f,
                    "insufficient balance: required {required}, available {available}"
                )
            }
            Self::InvalidTransaction(msg) => write!(f, "invalid transaction: {msg}"),
            Self::SenderRecoveryFailed(msg) => write!(f, "sender recovery failed: {msg}"),
        }
    }
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateAccess(e) => write!(f, "state access error: {e}"),
            Self::EvmInternal(msg) => write!(f, "evm internal error: {msg}"),
        }
    }
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "database error: {msg}"),
        }
    }
}

impl fmt::Display for HaltReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::OutOfGas => "out of gas",
            Self::OpcodeNotFound => "opcode not found",
            Self::InvalidFEOpcode => "invalid FE opcode",
            Self::InvalidJump => "invalid jump",
            Self::NotActivated => "not activated",
            Self::StackUnderflow => "stack underflow",
            Self::StackOverflow => "stack overflow",
            Self::OutOfOffset => "out of offset",
            Self::CreateCollision => "create collision",
            Self::PrecompileError => "precompile error",
            Self::NonceOverflow => "nonce overflow",
            Self::CreateContractSizeLimit => "create contract size limit",
            Self::CreateContractStartingWithEF => "create contract starting with 0xEF",
            Self::CreateInitCodeSizeLimit => "create init code size limit",
            Self::OverflowPayment => "overflow payment",
            Self::StateChangeDuringStaticCall => "state change during static call",
            Self::CallNotAllowedInsideStatic => "call not allowed inside static",
            Self::OutOfFunds => "out of funds",
            Self::CallTooDeep => "call too deep",
        };
        f.write_str(name)
    }
}

impl From<StateError> for VmError {
    fn from(err: StateError) -> Self {
        Self::Internal(InternalError::StateAccess(err))
    }
}

// `core::error::Error` está estable desde Rust 1.81; disponible en `no_std`.
impl core::error::Error for VmError {}
impl core::error::Error for ConsensusError {}
impl core::error::Error for InternalError {}
impl core::error::Error for StateError {}
