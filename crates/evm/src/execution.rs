//! Ejecución de una tx: arma el frame raíz sobre el `Journal`, lo corre en el
//! frame stack explícito (`crate::frames`) y liquida el gas.
//!
//! Alcance (slice 2.6, task 008): **calls anidadas + creación de contratos**. El `Journal` es dueño de
//! balances y nonces, así que el orden del protocolo se modela literal:
//!
//! 1. Pre-warming de la tx (EIP-2929 §tx + EIP-3651).
//! 2. **Prepago del gas** (`gas_limit · precio efectivo`) y bump del nonce del
//!    sender — fuera de todo checkpoint: no se revierten con la tx. En una tx
//!    de CREACIÓN (`to == None`, slice 2.6) el bump del nonce lo hace la
//!    apertura del frame de creación, que necesita el valor pre-bump para
//!    derivar la dirección (orden de revm, ver `prepare`).
//! 3. Checkpoint + transferencia del `value` de la tx: eso SÍ se revierte.
//! 4. El árbol de frames.
//! 5. Devolución del gas no usado al sender y tip al coinbase.
//!
//! Liquidación de gas (consenso):
//! - `Success` ⇒ se commitea; se cobra `intrínseco + intérprete − refund`, con
//!   el refund capado a `gas_used/5` (EIP-3529).
//! - `Revert` ⇒ se revierte; se cobra lo consumido (el resto vuelve).
//! - `Halt` ⇒ se revierte; se consume TODO el gas de la tx.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::transaction::Transaction;
use repo_b_interpreter::call::{CreateInputs, CreateKind};
use repo_b_interpreter::context::CallContext;
use repo_b_interpreter::host::{BlockEnv as HostBlockEnv, TxEnv as HostTxEnv};
use repo_b_interpreter::interpreter::Interpreter;
use repo_b_interpreter::result::{Halt, InterpreterOutcome};

use crate::error::{ConsensusError, HaltReason, InternalError, VmError};
use crate::frames::{self, CreateOpening, Frame, PlainRunner};
use crate::journal::Journal;
use crate::result::{ExecutionResult, StateChanges};
use crate::state::State;
use crate::types::{BlockEnv, Spec};

/// Lo que la ejecución de la tx le deja a `OwnVm`. El gas efectivamente
/// cobrado (ya neto de refund y del clamp de EIP-7623) vive en
/// `result.gas_used()` — no hay un segundo número separado que pueda
/// desincronizarse del que ve `settle_fees`.
pub(crate) struct TxOutcome {
    pub result: ExecutionResult,
    pub state_changes: StateChanges,
}

/// Inputs de la ejecución de una tx. Agrupados en un struct para que
/// `execute_tx` y `trace_tx` no puedan diverger en qué reciben.
pub(crate) struct TxRequest<'a> {
    pub tx: &'a Transaction,
    pub env: &'a BlockEnv,
    pub state: &'a dyn State,
    /// Destino de la tx. `None` = **transacción de creación de contrato**: el
    /// frame raíz es un frame de creación (`tx.input` como initcode) y NO hay
    /// `bytecode` que cargar.
    pub to: Option<Address>,
    /// Código de `to`. Vacío ⇒ transferencia pura: el frame raíz corre código
    /// vacío, termina en `Success` con 0 de gas y el value ya se movió — el
    /// mismo camino, sin una rama especial que pueda desincronizarse.
    pub bytecode: Bytes,
    pub intrinsic_gas: u64,
    /// Precio efectivo EIP-1559 (`Host::tx().gas_price`), ya calculado por el
    /// caller (`own_vm::gas_prices`).
    pub effective_price: u128,
    /// EIP-7623 (Prague), pre-calculado por `own_vm::calldata_floor_gas`: el
    /// piso de gas que `settle` aplica al gas COBRADO real (no solo al
    /// reportado) cuando `env.spec` habilita Prague. Pasarlo ya calculado
    /// evita que `execute_tx`/`trace_tx` puedan divergir en cómo lo derivan.
    pub floor_gas: u64,
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

/// Cómo arranca la tx: con un frame listo para correr, o —solo en una tx de
/// creación cuya dirección derivada ya está ocupada— con un halt inmediato.
pub(crate) enum RootStart {
    /// `Box` por la misma razón que `CreateOpening::Opened`: el `Frame` lleva
    /// el `Interpreter` entero.
    Frame(Box<Frame>),
    Halted(InterpreterOutcome),
}

/// El estado pre-ejecución de la tx: journal pre-warmeado, gas prepagado,
/// nonce bumpeado, value transferido, y el frame raíz (de mensaje o de
/// creación).
///
/// ÚNICO constructor: lo comparten `execute_tx` y `trace_tx` — trazar no puede
/// divergir de ejecutar porque el setup es literalmente el mismo código.
fn prepare<'a>(request: &TxRequest<'a>) -> Result<(Journal<'a>, RootStart, u64), VmError> {
    let TxRequest {
        tx,
        env,
        state,
        to,
        bytecode,
        intrinsic_gas,
        effective_price,
        floor_gas: _,
    } = request;
    let frame_gas = tx
        .gas_limit
        .checked_sub(*intrinsic_gas)
        .ok_or_else(|| internal("gas intrínseco mayor que el límite (validación rota)"))?;

    let host_tx = HostTxEnv {
        origin: tx.sender,
        gas_price: *effective_price,
        // Tx no-blob (tipo 3/4844 es el slice 2.7) ⇒ lista vacía: BLOBHASH
        // siempre 0 hasta entonces.
        blob_hashes: Vec::new(),
    };
    let mut journal = Journal::new(*state).with_frame_context(host_env(env)?, host_tx);
    journal.prewarm_tx(tx.sender, tx.to, &tx.access_list, env);

    // Prepago del gas: pasa ANTES del checkpoint de la tx, así que sobrevive a
    // un revert/halt (protocolo: el sender paga igual).
    let gas_prepaid = U256::from(tx.gas_limit)
        .checked_mul(U256::from(*effective_price))
        .ok_or_else(|| internal("overflow calculando el gas prepagado"))?;
    journal
        .debit(tx.sender, gas_prepaid)
        .map_err(|_| balance_error("gas prepagado"))?;

    let Some(to) = *to else {
        // Tx de creación (`to == None`). El bump del nonce del sender NO va
        // acá: lo hace la apertura del frame de creación con el MISMO
        // `old_nonce` que deriva la dirección (revm:
        // `validate_against_state_and_deduct_caller` solo bumpea `is_call()`).
        let inputs = CreateInputs {
            creator: tx.sender,
            kind: CreateKind::Create,
            value: tx.value,
            init_code: tx.input.clone(),
            gas_limit: frame_gas,
            is_static: false,
        };
        let root = match frames::open_create_frame(&mut journal, 0, &inputs)? {
            CreateOpening::Opened(frame) => RootStart::Frame(frame),
            // Consume TODO el gas de la tx (revm: `CreateCollision` no es
            // `is_ok_or_revert`, así que nada vuelve).
            CreateOpening::Collision => RootStart::Halted(InterpreterOutcome::Halt {
                reason: Halt::CreateCollision,
                gas_used: frame_gas,
            }),
            // Inalcanzable: profundidad 0 y el balance/nonce ya validados por
            // `OwnVm`. Fail-closed igual, nunca "seguir como si nada".
            CreateOpening::NotExecuted => {
                return Err(internal(
                    "la creación top-level no abrió frame (validación de la tx rota)",
                ));
            }
        };
        return Ok((journal, root, frame_gas));
    };

    journal
        .bump_nonce(tx.sender)
        .map_err(|_| internal("overflow de nonce del sender"))?;

    // A partir de acá SÍ se revierte: el value de la tx vuelve si la
    // ejecución falla.
    let checkpoint = journal.checkpoint();
    journal
        .transfer(tx.sender, to, tx.value)
        .map_err(|_| balance_error("value de la tx"))?;

    let context = CallContext {
        address: to,
        caller: tx.sender,
        value: tx.value,
        calldata: tx.input.clone(),
        bytecode: bytecode.clone(),
        is_static: false,
        depth: 0,
    };
    Ok((
        journal,
        RootStart::Frame(Box::new(Frame::call(
            Interpreter::new(context, frame_gas),
            frame_gas,
            checkpoint,
        ))),
        frame_gas,
    ))
}

/// Corre la tx completa (frame raíz + sub-frames) y la liquida.
pub(crate) fn execute_tx(request: &TxRequest<'_>) -> Result<TxOutcome, VmError> {
    let (mut journal, root, _frame_gas) = prepare(request)?;

    let outcome = match root {
        RootStart::Frame(frame) => frames::run(&mut journal, &mut PlainRunner, *frame)?,
        RootStart::Halted(outcome) => outcome,
    };

    // Fail-closed: un fallo de lectura del `State` durante la ejecución no se
    // aproxima como cero — aborta la tx con error interno.
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }

    settle(&mut journal, request, outcome)
}

/// Traduce el resultado del frame raíz a gas cobrado + diff, y liquida los
/// balances de fee (devolución al sender, tip al coinbase).
fn settle(
    journal: &mut Journal<'_>,
    request: &TxRequest<'_>,
    outcome: InterpreterOutcome,
) -> Result<TxOutcome, VmError> {
    let tx = request.tx;
    let spent = request
        .intrinsic_gas
        .checked_add(outcome.gas_used())
        .ok_or_else(|| internal("overflow sumando gas intrínseco y de ejecución"))?;

    let (result, gas_charged) = match outcome {
        InterpreterOutcome::Success { output, .. } => {
            let refund = journal.settled_refund(spent);
            let gas_charged = spent
                .checked_sub(refund)
                .ok_or_else(|| internal("refund mayor que el gas usado (tope EIP-3529 roto)"))?;
            (
                ExecutionResult::Success {
                    gas_used: gas_charged,
                    gas_refunded: refund,
                    logs: journal.logs().to_vec(),
                    output,
                },
                gas_charged,
            )
        }
        InterpreterOutcome::Revert { output, .. } => (
            ExecutionResult::Revert {
                gas_used: spent,
                output,
            },
            spent,
        ),
        InterpreterOutcome::Halt { reason, .. } => {
            // Un Halt consume TODO el gas de la tx (el intérprete ya consumió
            // todo el del frame; el intrínseco se suma).
            let gas_charged = spent.min(tx.gas_limit);
            (
                ExecutionResult::Halt {
                    reason: halt_reason(reason),
                    gas_used: gas_charged,
                },
                gas_charged,
            )
        }
    };

    // EIP-7623 (Prague), cierre completo: el gas COBRADO real (post-refund)
    // se reemplaza por `max(gas_cobrado, floor_gas)` — verificado contra el
    // handler de revm (`post_execution::eip7623_check_gas_floor`): el clamp
    // corre DESPUÉS del refund y ANTES de `reimburse_caller`/
    // `reward_beneficiary`, así que acá tiene que pasar ANTES de
    // `settle_fees` (que mueve los balances reales de sender/coinbase) — un
    // fixture que solo mirara `gas_used` del resultado y no el balance final
    // podría pasar en verde con el clamp aplicado solo al reporte, no al
    // cobro real. Halt nunca dispara el `if`: la validación de la tx ya
    // garantiza `tx.gas_limit >= floor_gas`, y un Halt cobra `tx.gas_limit`
    // completo.
    let floor_applies = request.env.spec.is_enabled(Spec::Prague);
    let (result, gas_charged) = if floor_applies && gas_charged < request.floor_gas {
        (apply_calldata_floor(result, request.floor_gas), request.floor_gas)
    } else {
        (result, gas_charged)
    };

    settle_fees(journal, request, gas_charged)?;
    let state_changes = journal.state_changes()?;
    Ok(TxOutcome {
        result,
        state_changes,
    })
}

/// EIP-7623: reescribe el resultado con el gas floor-clampeado. Match TOTAL
/// (sin `_`): un variante nueva de `ExecutionResult` sin caso acá no compila.
/// El `Success` pierde el refund reportado (`gas_refunded: 0`): el floor lo
/// absorbe entero (idéntico a `ResultGas::final_refunded` de revm — cuando el
/// floor muerde, el refund efectivo es 0, no el crudo).
fn apply_calldata_floor(result: ExecutionResult, floor_gas: u64) -> ExecutionResult {
    match result {
        ExecutionResult::Success { output, logs, .. } => ExecutionResult::Success {
            gas_used: floor_gas,
            gas_refunded: 0,
            logs,
            output,
        },
        ExecutionResult::Revert { output, .. } => ExecutionResult::Revert {
            gas_used: floor_gas,
            output,
        },
        ExecutionResult::Halt { reason, .. } => ExecutionResult::Halt {
            reason,
            gas_used: floor_gas,
        },
    }
}

/// Devuelve al sender el gas prepagado que no se usó y le paga el tip al
/// coinbase. Fuera del checkpoint de la tx: no se revierte nunca.
fn settle_fees(
    journal: &mut Journal<'_>,
    request: &TxRequest<'_>,
    gas_charged: u64,
) -> Result<(), VmError> {
    let tx = request.tx;
    let unused = tx
        .gas_limit
        .checked_sub(gas_charged)
        .ok_or_else(|| internal("gas cobrado mayor que el límite de la tx"))?;
    let returned = U256::from(unused)
        .checked_mul(U256::from(request.effective_price))
        .ok_or_else(|| internal("overflow devolviendo el gas no usado"))?;
    journal
        .credit(tx.sender, returned)
        .map_err(|_| internal("overflow acreditando el gas devuelto al sender"))?;

    let tip = request
        .effective_price
        .checked_sub(u128::from(request.env.base_fee))
        .ok_or_else(|| internal("precio efectivo menor que base fee (invariante rota)"))?;
    let reward = U256::from(gas_charged)
        .checked_mul(U256::from(tip))
        .ok_or_else(|| internal("overflow en el reward del coinbase"))?;
    // Con tip 0 el crédito es un no-op y el diff no emite update: EIP-161, no
    // se crea el coinbase por un touch de cero (ficha 02).
    journal
        .credit(request.env.coinbase, reward)
        .map_err(|_| internal("overflow acreditando el tip al coinbase"))?;
    Ok(())
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
        Halt::CreateInitCodeSizeLimit => HaltReason::CreateInitCodeSizeLimit,
        Halt::CreateContractSizeLimit => HaltReason::CreateContractSizeLimit,
        Halt::CreateContractStartingWithEF => HaltReason::CreateContractStartingWithEF,
        Halt::CreateCollision => HaltReason::CreateCollision,
    }
}

/// Traza la ejecución de la tx (EIP-3155) emitiendo un `StepRecord` por
/// opcode, **de todos los frames**. Diagnóstico del harness diferencial, no
/// del motor: detrás de la feature `tracer`, que en el guest está apagada (el
/// módulo ni existe).
///
/// Reusa `prepare` + `frames::run`, así que traza EXACTAMENTE lo que ejecuta
/// `execute_tx`. Devuelve `None` si `to` no tiene código (nada que trazar).
#[cfg(feature = "tracer")]
pub fn trace_tx(
    tx: &Transaction,
    env: &BlockEnv,
    state: &dyn State,
    sink: &mut dyn repo_b_interpreter::tracer::StepSink,
) -> Result<Option<InterpreterOutcome>, VmError> {
    use repo_b_common::primitives::KECCAK256_EMPTY;

    let bytecode = match tx.to {
        // Tx de creación: el initcode SÍ se traza (es código que corre).
        None => Bytes::new(),
        Some(to) => {
            let Some(account) = state.account(to)? else {
                return Ok(None);
            };
            if account.code_hash == KECCAK256_EMPTY {
                return Ok(None);
            }
            state.code(account.code_hash)?
        }
    };
    let request = TxRequest {
        tx,
        env,
        state,
        to: tx.to,
        bytecode,
        intrinsic_gas: crate::own_vm::intrinsic_gas(
            &tx.input,
            tx.to.is_none(),
            &tx.access_list,
        )?,
        effective_price: crate::own_vm::gas_prices(tx, env)?.0,
        floor_gas: crate::own_vm::calldata_floor_gas(&tx.input)?,
    };
    let (mut journal, root, _frame_gas) = prepare(&request)?;
    let mut runner = crate::frames::TracingRunner {
        sink,
        refund_total: 0,
    };
    let outcome = match root {
        RootStart::Frame(frame) => frames::run(&mut journal, &mut runner, *frame)?,
        RootStart::Halted(outcome) => outcome,
    };
    Ok(Some(outcome))
}

fn internal(msg: &str) -> VmError {
    VmError::Internal(InternalError::EvmInternal(msg.to_string()))
}

/// Un movimiento de balance que la validación de la tx debió hacer imposible.
/// Se reporta como error de consenso (la tx no es ejecutable), no como bug.
fn balance_error(what: &str) -> VmError {
    VmError::Consensus(ConsensusError::InvalidTransaction(alloc::format!(
        "balance insuficiente para {what} (el chequeo previo debió atraparlo)"
    )))
}
