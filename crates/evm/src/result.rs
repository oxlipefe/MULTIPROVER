//! Resultado de ejecución: la **trichotomy** Success/Revert/Halt (vendoreado de
//! zeth). La semántica de gas difiere: REVERT devuelve el gas restante; Halt
//! consume TODO el gas. El EVM produce un diff (`StateChanges`), no muta estado.

use alloc::vec::Vec;

use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::Bytes;
use repo_b_common::receipt::Log;

use crate::error::HaltReason;
use crate::witness::ExecutionWitness;

pub type StateChanges = Vec<AccountUpdate>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionResult {
    Success {
        gas_used: u64,
        gas_refunded: u64,
        logs: Vec<Log>,
        output: Bytes,
    },
    Revert {
        gas_used: u64,
        output: Bytes,
    },
    Halt {
        reason: HaltReason,
        gas_used: u64,
    },
}

impl ExecutionResult {
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

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub result: ExecutionResult,
    pub state_changes: StateChanges,
    pub witness: Option<ExecutionWitness>,
}

impl ExecutionOutcome {
    pub fn noop() -> Self {
        Self {
            result: ExecutionResult::Success {
                gas_used: 0,
                gas_refunded: 0,
                logs: Vec::new(),
                output: Bytes::new(),
            },
            state_changes: Vec::new(),
            witness: None,
        }
    }
}
