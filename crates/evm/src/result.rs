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
    /// `gas_refunded` en Revert/Halt **no es decorativo** (slice 2.7c): el
    /// refund de EIP-7702 se acumula FUERA del frame y sobrevive a un revert y
    /// a un halt (revm: `post_execution::refund` corre después de
    /// `last_frame_result`, que solo descarta el refund del frame). Sin este
    /// campo, el refund que efectivamente se le devuelve al sender no sería
    /// representable — y el diferencial vs revm no podría compararlo.
    Revert {
        gas_used: u64,
        gas_refunded: u64,
        output: Bytes,
    },
    Halt {
        reason: HaltReason,
        gas_used: u64,
        gas_refunded: u64,
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

    /// Refund efectivamente liquidado (ya capado por EIP-3529 y absorbido por
    /// el floor de EIP-7623). Distinto de cero en Revert/Halt solo por
    /// EIP-7702.
    pub fn gas_refunded(&self) -> u64 {
        match self {
            Self::Success { gas_refunded, .. }
            | Self::Revert { gas_refunded, .. }
            | Self::Halt { gas_refunded, .. } => *gas_refunded,
        }
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
