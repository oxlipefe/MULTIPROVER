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
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::transaction::Transaction;
use repo_b_interpreter::context::CallContext;
use repo_b_interpreter::host::{BlockEnv as HostBlockEnv, TxEnv as HostTxEnv};
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

/// `evm::types::BlockEnv` (seam vendoreado, intocable) → la proyección mínima
/// que pide `interpreter::host::Host::env` (ADR-0002 §1: el intérprete solo
/// depende de `common`). `blob_base_fee` es el único campo derivado
/// (EIP-4844 `fake_exponential`); el resto es passthrough.
fn host_env(env: &BlockEnv) -> Result<HostBlockEnv, VmError> {
    Ok(HostBlockEnv {
        chain_id: env.chain_id,
        number: env.number,
        coinbase: env.coinbase,
        timestamp: env.timestamp,
        gas_limit: env.gas_limit,
        base_fee: env.base_fee,
        prevrandao: env.prevrandao,
        blob_base_fee: crate::blob::blob_base_fee(env.blob_excess_gas, env.spec)?,
    })
}

/// Inputs de un frame de contrato: agrupa lo que `build_frame`/
/// `execute_contract` necesitan (clippy `too_many_arguments`, y evita que las
/// dos funciones diverjan en qué reciben — comparten el mismo struct).
pub(crate) struct FrameRequest<'a> {
    pub tx: &'a Transaction,
    pub env: &'a BlockEnv,
    pub state: &'a dyn State,
    pub to: Address,
    pub bytecode: Bytes,
    pub intrinsic_gas: u64,
    /// Balance de `to` al arrancar el frame (`Host::self_balance`), ya
    /// calculado por el caller (`own_vm::self_balance_from_overlay`).
    pub self_balance: U256,
    /// Overlay de balances pre-frame (`Host::load_account`, slice 2.4):
    /// sender/`to` ya debitados/acreditados por fees+value, calculado por el
    /// caller (`own_vm::frame_balance_overlay`).
    pub balance_overlay: BTreeMap<Address, U256>,
    /// Precio efectivo EIP-1559 (`Host::tx().gas_price`), ya calculado por el
    /// caller (`own_vm::gas_prices`).
    pub effective_price: u128,
}

/// ÚNICO constructor del frame de una tx (intérprete + journal pre-warmeado).
/// Lo comparten `execute_contract` y `trace_tx`: trazar no puede divergir de
/// ejecutar porque el setup es literalmente el mismo código.
fn build_frame<'a>(request: FrameRequest<'a>) -> Result<(Interpreter, Journal<'a>), VmError> {
    let FrameRequest {
        tx,
        env,
        state,
        to,
        bytecode,
        intrinsic_gas,
        self_balance,
        balance_overlay,
        effective_price,
    } = request;
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

    let host_tx = HostTxEnv {
        origin: tx.sender,
        gas_price: effective_price,
        // Tx no-blob (tipo 3/4844 es el slice 2.7) ⇒ lista vacía: BLOBHASH
        // siempre 0 hasta entonces.
        blob_hashes: Vec::new(),
    };
    let mut journal = Journal::new(state)
        .with_frame_context(self_balance, host_env(env)?, host_tx)
        .with_balance_overlay(balance_overlay);
    journal.prewarm_tx(tx.sender, tx.to, env);
    Ok((Interpreter::new(context, frame_gas), journal))
}

/// Corre el bytecode de `to` en un frame de profundidad 0 sobre un `Journal`.
pub(crate) fn execute_contract(request: FrameRequest<'_>) -> Result<FrameOutcome, VmError> {
    let tx_gas_limit = request.tx.gas_limit;
    let intrinsic_gas = request.intrinsic_gas;
    let (interpreter, mut journal) = build_frame(request)?;
    let checkpoint = journal.checkpoint();

    let outcome = interpreter.run(&mut journal);

    // Fail-closed: un fallo de lectura del `State` durante la ejecución no se
    // aproxima como cero — aborta la tx con error interno.
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }

    settle_frame(&mut journal, outcome, intrinsic_gas, tx_gas_limit, checkpoint)
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
    let sender_balance = state
        .account(tx.sender)?
        .map_or(U256::ZERO, |info| info.balance);
    let (effective_price, _) = crate::own_vm::gas_prices(tx, env)?;
    let balance_overlay = crate::own_vm::frame_balance_overlay(
        tx,
        to,
        sender_balance,
        account.balance,
        effective_price,
    )?;
    let self_balance = crate::own_vm::self_balance_from_overlay(&balance_overlay, to)?;
    let (interpreter, mut journal) = build_frame(FrameRequest {
        tx,
        env,
        state,
        to,
        bytecode,
        intrinsic_gas,
        self_balance,
        balance_overlay,
        effective_price,
    })?;
    Ok(Some(interpreter.run_traced(&mut journal, sink)))
}

fn internal(msg: &str) -> VmError {
    VmError::Internal(InternalError::EvmInternal(msg.to_string()))
}
