//! Ejecución de UN frame de contrato desde `OwnVm` (task 004, slice 2.2).
//!
//! Alcance deliberado: **single-frame**. CALL/CREATE siguen siendo
//! `Halt::OpcodeNotFound` en el intérprete (slices 2.5/2.6); acá no hay frame
//! stack todavía — el `checkpoint`/`revert_to` del journal se usa para el
//! revert de LA tx, que es su primer consumidor real.
//!
//! Liquidación de gas (consenso):
//! - `Success` ⇒ se commitea el journal; el gas cobrado es
//!   `intrínseco + intérprete − refund`, con el refund capado a `gas_used/5`
//!   (EIP-3529).
//! - `Revert` ⇒ se revierte el journal; se cobra lo consumido (el resto vuelve).
//! - `Halt` ⇒ se revierte el journal; se consume TODO el gas de la tx.

use alloc::collections::BTreeMap;
use alloc::string::ToString;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::transaction::Transaction;
use repo_b_interpreter::context::CallContext;
use repo_b_interpreter::interpreter::Interpreter;
use repo_b_interpreter::result::{Halt, InterpreterOutcome};

use crate::error::{HaltReason, InternalError, VmError};
use crate::journal::Journal;
use crate::result::ExecutionResult;
use crate::state::State;
use crate::types::BlockEnv;

/// Lo que la ejecución de la tx le deja a la liquidación de balances.
pub(crate) struct FrameOutcome {
    pub result: ExecutionResult,
    pub storage_changes: BTreeMap<Address, BTreeMap<U256, U256>>,
    /// Gas que efectivamente paga el sender (ya neto de refund).
    pub gas_charged: u64,
    /// El value solo se mueve si la tx terminó en éxito.
    pub value_transferred: bool,
}

impl FrameOutcome {
    /// Transferencia pura (el path de Fase 1): no corre código, cobra el gas
    /// intrínseco y mueve el value.
    pub(crate) fn pure_transfer(intrinsic_gas: u64) -> Self {
        Self {
            result: ExecutionResult::Success {
                gas_used: intrinsic_gas,
                gas_refunded: 0,
                logs: alloc::vec::Vec::new(),
                output: Bytes::new(),
            },
            storage_changes: BTreeMap::new(),
            gas_charged: intrinsic_gas,
            value_transferred: true,
        }
    }
}

/// ÚNICO constructor del frame de una tx (intérprete + journal pre-warmeado).
/// Lo comparten `execute_contract` y `trace_tx`: trazar no puede divergir de
/// ejecutar porque el setup es literalmente el mismo código.
fn build_frame<'a>(
    tx: &Transaction,
    env: &BlockEnv,
    state: &'a dyn State,
    to: Address,
    bytecode: Bytes,
    intrinsic_gas: u64,
) -> Result<(Interpreter, Journal<'a>), VmError> {
    let frame_gas = tx
        .gas_limit
        .checked_sub(intrinsic_gas)
        .ok_or_else(|| internal("gas intrínseco mayor que el límite (validación rota)"))?;

    let context = CallContext {
        address: to,
        caller: tx.sender,
        value: tx.value,
        calldata: tx.input.clone(),
        bytecode,
        is_static: false,
        depth: 0,
    };

    let mut journal = Journal::new(state);
    journal.prewarm_tx(tx.sender, tx.to, env);
    Ok((Interpreter::new(context, frame_gas), journal))
}

/// Corre el bytecode de `to` en un frame de profundidad 0 sobre un `Journal`.
pub(crate) fn execute_contract(
    tx: &Transaction,
    env: &BlockEnv,
    state: &dyn State,
    to: Address,
    bytecode: Bytes,
    intrinsic_gas: u64,
) -> Result<FrameOutcome, VmError> {
    let (interpreter, mut journal) = build_frame(tx, env, state, to, bytecode, intrinsic_gas)?;
    let checkpoint = journal.checkpoint();

    let outcome = interpreter.run(&mut journal);

    // Fail-closed: un fallo de lectura del `State` durante la ejecución no se
    // aproxima como cero — aborta la tx con error interno.
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }

    settle_frame(
        &mut journal,
        outcome,
        intrinsic_gas,
        tx.gas_limit,
        checkpoint,
    )
}

/// Traduce el resultado del intérprete a gas cobrado + diff, aplicando la
/// semántica de commit/revert del journal.
fn settle_frame(
    journal: &mut Journal<'_>,
    outcome: InterpreterOutcome,
    intrinsic_gas: u64,
    tx_gas_limit: u64,
    checkpoint: crate::journal::Checkpoint,
) -> Result<FrameOutcome, VmError> {
    let spent = intrinsic_gas
        .checked_add(outcome.gas_used())
        .ok_or_else(|| internal("overflow sumando gas intrínseco y de ejecución"))?;

    match outcome {
        InterpreterOutcome::Success { output, .. } => {
            journal.commit(checkpoint);
            let refund = journal.settled_refund(spent);
            let gas_charged = spent
                .checked_sub(refund)
                .ok_or_else(|| internal("refund mayor que el gas usado (tope EIP-3529 roto)"))?;
            Ok(FrameOutcome {
                result: ExecutionResult::Success {
                    gas_used: gas_charged,
                    gas_refunded: refund,
                    logs: journal.logs().to_vec(),
                    output,
                },
                storage_changes: journal.storage_changes(),
                gas_charged,
                value_transferred: true,
            })
        }
        InterpreterOutcome::Revert { output, .. } => {
            journal.revert_to(checkpoint);
            Ok(FrameOutcome {
                result: ExecutionResult::Revert {
                    gas_used: spent,
                    output,
                },
                storage_changes: BTreeMap::new(),
                gas_charged: spent,
                value_transferred: false,
            })
        }
        InterpreterOutcome::Halt { reason, .. } => {
            journal.revert_to(checkpoint);
            // Un Halt consume TODO el gas de la tx (el intérprete ya consumió
            // todo el del frame; el intrínseco se suma).
            let gas_charged = spent.min(tx_gas_limit);
            Ok(FrameOutcome {
                result: ExecutionResult::Halt {
                    reason: halt_reason(reason),
                    gas_used: gas_charged,
                },
                storage_changes: BTreeMap::new(),
                gas_charged,
                value_transferred: false,
            })
        }
    }
}

/// `interpreter::Halt` → `HaltReason` del seam. Mapping **TOTAL** (sin `_`):
/// un `Halt` nuevo sin caso acá no compila. Obligación registrada en la ficha
/// 01 y en ADR-0002 §Consequences.
pub(crate) fn halt_reason(reason: Halt) -> HaltReason {
    match reason {
        Halt::OutOfGas => HaltReason::OutOfGas,
        Halt::StackUnderflow => HaltReason::StackUnderflow,
        Halt::StackOverflow => HaltReason::StackOverflow,
        Halt::InvalidJump => HaltReason::InvalidJump,
        Halt::OpcodeNotFound => HaltReason::OpcodeNotFound,
        Halt::InvalidFEOpcode => HaltReason::InvalidFEOpcode,
        Halt::OutOfOffset => HaltReason::OutOfOffset,
        Halt::StateChangeDuringStaticCall => HaltReason::StateChangeDuringStaticCall,
    }
}

/// Traza la ejecución de la tx (EIP-3155) emitiendo un `StepRecord` por
/// opcode. **Diagnóstico del harness diferencial**, no del motor: detrás de la
/// feature `tracer`, que en el guest está apagada (el módulo ni existe).
///
/// Reusa `build_frame`, así que traza EXACTAMENTE el frame que ejecuta
/// `execute_tx`. Devuelve `None` si `to` no tiene código (nada que trazar).
#[cfg(feature = "tracer")]
pub fn trace_tx(
    tx: &Transaction,
    env: &BlockEnv,
    state: &dyn State,
    sink: &mut dyn repo_b_interpreter::tracer::StepSink,
) -> Result<Option<InterpreterOutcome>, VmError> {
    use repo_b_common::primitives::KECCAK256_EMPTY;

    let to = tx
        .to
        .ok_or_else(|| internal("CREATE no soportado hasta el slice 2.6"))?;
    let Some(account) = state.account(to)? else {
        return Ok(None);
    };
    if account.code_hash == KECCAK256_EMPTY {
        return Ok(None);
    }
    let bytecode = state.code(account.code_hash)?;
    let intrinsic_gas = crate::own_vm::intrinsic_gas(&tx.input)?;
    let (interpreter, mut journal) = build_frame(tx, env, state, to, bytecode, intrinsic_gas)?;
    Ok(Some(interpreter.run_traced(&mut journal, sink)))
}

fn internal(msg: &str) -> VmError {
    VmError::Internal(InternalError::EvmInternal(msg.to_string()))
}
