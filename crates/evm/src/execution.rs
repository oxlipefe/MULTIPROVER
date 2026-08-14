//! Ejecución de una tx: arma el frame raíz sobre el `Journal`, lo corre en el
//! frame stack explícito (`crate::frames`) y liquida el gas.
//!
//! Alcance: **calls anidadas + creación de contratos**. El `Journal` es dueño de
//! balances y nonces, así que el orden del protocolo se modela literal:
//!
//! 1. Pre-warming de la tx (EIP-2929 §tx + EIP-3651).
//! 2. **Prepago del gas** (`gas_limit · precio efectivo`) y bump del nonce del
//!    sender — fuera de todo checkpoint: no se revierten con la tx. En una
//!    tx de CREACIÓN (`to == None`) el bump del nonce lo hace la
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

use repo_b_common::authorization::delegation_target;
use repo_b_common::primitives::{Address, U256};
use repo_b_common::transaction::{Transaction, TxType};
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
    pub intrinsic_gas: u64,
    /// Precio efectivo EIP-1559 (`Host::tx().gas_price`), ya calculado por el
    /// caller (`own_vm::gas_prices`).
    pub effective_price: u128,
    /// EIP-7623 (Prague), pre-calculado por `own_vm::calldata_floor_gas`: el
    /// piso de gas que `settle` aplica al gas COBRADO real (no solo al
    /// reportado) cuando `env.spec` habilita Prague. Pasarlo ya calculado
    /// evita que `execute_tx`/`trace_tx` puedan divergir en cómo lo derivan.
    pub floor_gas: u64,
    /// EIP-4844, pre-calculado por `own_vm::total_blob_gas`: 0
    /// en toda tx no-4844. **Nunca se mezcla** con `intrinsic_gas`/
    /// `floor_gas`/refunds de ejecución — es un mercado de fees separado
    /// (`prepare` lo debita al precio YA resuelto del bloque, quemado
    /// completo, antes del checkpoint de la tx).
    pub blob_gas_used: u64,
}

/// `evm::types::BlockEnv` (seam vendoreado, intocable) → la proyección mínima
/// que pide `interpreter::host::Host::env`: el intérprete solo
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

/// EIP-7702: aplica la lista de autorizaciones de una tx tipo 4.
/// Devuelve el **refund** acumulado (`AUTH_EXISTING_ACCOUNT_REFUND` por cada
/// autorización aplicada sobre una cuenta que ya existía).
///
/// Orden verificado literal contra revm (`pre_execution::apply_auth_list`):
/// 1. `chain_id` distinto de 0 y del bloque ⇒ saltear.
/// 2. `nonce == u64::MAX` (bumpearlo desbordaría) ⇒ saltear.
/// 3. firma inválida (`authority == None`) ⇒ saltear. **No invalida la tx.**
/// 4. **warm de `authority` (EIP-2929) ACÁ**: después de los tres chequeos
///    anteriores y ANTES de los dos siguientes — una tupla salteada por (5) o
///    (6) deja la dirección CALIENTE igual.
/// 5. código de `authority` no vacío y que NO es designator ⇒ saltear (no se
///    pisa el código de un contrato real).
/// 6. `nonce` de `authority` distinto del declarado ⇒ saltear.
/// 7. refund si la cuenta no es (vacía ∧ inexistente en el trie).
/// 8. escribir el designator (o limpiarlo si `address == 0`) y `nonce += 1`.
fn apply_authorizations(
    journal: &mut Journal<'_>,
    tx: &Transaction,
    env: &BlockEnv,
) -> Result<u64, VmError> {
    if tx.tx_type != TxType::Eip7702 {
        return Ok(0);
    }
    let mut refunded_accounts: u64 = 0;
    for authorization in &tx.authorization_list {
        if !authorization.chain_id.is_zero() && authorization.chain_id != U256::from(env.chain_id) {
            continue;
        }
        if authorization.nonce == u64::MAX {
            continue;
        }
        let Some(authority) = authorization.authority else {
            continue;
        };
        journal.warm(authority);
        let code = journal.code_of(authority);
        if !code.is_empty() && delegation_target(&code).is_none() {
            continue;
        }
        if journal.nonce(authority) != authorization.nonce {
            continue;
        }
        if journal.authorization_refunds(authority) {
            refunded_accounts = refunded_accounts
                .checked_add(1)
                .ok_or_else(|| internal("overflow contando autorizaciones con refund"))?;
        }
        journal
            .set_delegation(authority, authorization.address)
            .map_err(|_| internal("overflow de nonce del authority (chequeo previo roto)"))?;
    }
    refunded_accounts
        .checked_mul(crate::own_vm::AUTH_EXISTING_ACCOUNT_REFUND)
        .ok_or_else(|| internal("overflow calculando el refund de EIP-7702"))
}

/// Cómo arranca la tx: con un frame listo para correr, o con un
/// `InterpreterOutcome` ya resuelto que nunca necesitó un `Interpreter` real
/// (colisión de una tx de creación, o —— una tx cuyo `to` apunta
/// directo a un precompile implementado: `resolve_precompile_outcome` corre
/// síncrono, igual que dentro de un CALL anidado, y acá no hay bytecode que
/// cargar).
pub(crate) enum RootStart {
    /// `Box` por la misma razón que `CreateOpening::Opened`: el `Frame` lleva
    /// el `Interpreter` entero.
    Frame(Box<Frame>),
    Resolved(InterpreterOutcome),
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
        intrinsic_gas,
        effective_price,
        floor_gas: _,
        blob_gas_used,
    } = request;
    let frame_gas = tx
        .gas_limit
        .checked_sub(*intrinsic_gas)
        .ok_or_else(|| internal("gas intrínseco mayor que el límite (validación rota)"))?;

    let host_block_env = host_env(env)?;
    let host_tx = HostTxEnv {
        origin: tx.sender,
        gas_price: *effective_price,
        // EIP-4844: `own_vm::execute_tx` ya validó el formato
        // (KZG version, no vacío) antes de llegar acá — vacío en toda tx
        // no-4844 por el invariante de construcción de `Transaction`.
        blob_hashes: tx.blob_versioned_hashes.clone(),
    };
    let mut journal = Journal::new(*state)
        .with_frame_context(host_block_env, host_tx)
        .with_spec(request.env.spec);
    journal.prewarm_tx(tx.sender, tx.to, &tx.access_list, env);

    // Prepago del gas: pasa ANTES del checkpoint de la tx, así que sobrevive a
    // un revert/halt (protocolo: el sender paga igual).
    let gas_prepaid = U256::from(tx.gas_limit)
        .checked_mul(U256::from(*effective_price))
        .ok_or_else(|| internal("overflow calculando el gas prepagado"))?;
    journal
        .debit(tx.sender, gas_prepaid)
        .map_err(|_| balance_error("gas prepagado"))?;

    // EIP-4844: blob fee — débito al precio YA resuelto del
    // bloque (`host_block_env.blob_base_fee`, `crate::blob::blob_base_fee`;
    // NUNCA el `max_fee_per_blob_gas` declarado, que solo gatea el chequeo de
    // balance en `own_vm`). Mismo punto temporal que el gas prepagado (ANTES
    // del checkpoint: sobrevive a un revert/halt del frame raíz) y **QUEMADO
    // COMPLETO** — a diferencia del gas de ejecución (que se devuelve
    // parcialmente en `settle_fees`), acá no hay una devolución ni un tip que
    // acreditar a nadie: verificado contra revm
    // (`pre_execution::calculate_caller_fee` mete el blob fee en el ÚNICO
    // débito de `effective_balance_spending`; ni `reimburse_caller` ni
    // `reward_beneficiary` en `post_execution` lo tocan después).
    if *blob_gas_used > 0 {
        let blob_fee = U256::from(*blob_gas_used)
            .checked_mul(U256::from(host_block_env.blob_base_fee))
            .ok_or_else(|| internal("overflow calculando el blob fee"))?;
        journal
            .debit(tx.sender, blob_fee)
            .map_err(|_| balance_error("blob fee"))?;
    }

    // El bump del nonce del sender pasa ANTES de las autorizaciones y **solo
    // en una tx con `to`** (revm: `validate_against_state_and_deduct_caller`
    // bumpea `if tx.kind().is_call()`). En una tx de CREACIÓN lo hace la
    // apertura del frame de creación —que necesita el valor pre-bump para
    // derivar la dirección—, o sea DESPUÉS de las autorizaciones: una tx tipo
    // 4 de creación que se auto-autoriza usa el nonce SIN bumpear.
    if to.is_some() {
        journal
            .bump_nonce(tx.sender)
            .map_err(|_| internal("overflow de nonce del sender"))?;
    }

    // EIP-7702: las autorizaciones se aplican DESPUÉS del prepago
    // y del bump del nonce del sender, ANTES de abrir el frame raíz — y fuera
    // de todo checkpoint (un revert de la tx no deshace una delegación).
    let auth_refund = apply_authorizations(&mut journal, tx, env)?;

    let Some(to) = *to else {
        let inputs = CreateInputs {
            creator: tx.sender,
            kind: CreateKind::Create,
            value: tx.value,
            init_code: tx.input.clone(),
            gas_limit: frame_gas,
            is_static: false,
        };
        let root = match frames::open_create_frame(&mut journal, 0, &inputs, request.env.spec)? {
            CreateOpening::Opened(frame) => RootStart::Frame(frame),
            // Consume TODO el gas de la tx (revm: `CreateCollision` no es
            // `is_ok_or_revert`, así que nada vuelve).
            CreateOpening::Collision => RootStart::Resolved(InterpreterOutcome::Halt {
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
        return Ok((journal, root, auth_refund));
    };

    // A partir de acá SÍ se revierte: el value de la tx vuelve si la
    // ejecución falla.
    let checkpoint = journal.checkpoint();
    journal
        .transfer(tx.sender, to, tx.value)
        .map_err(|_| balance_error("value de la tx"))?;

    // Una tx cuyo `to` apunta DIRECTO a una precompile
    // nunca pasa por `frames::open_frame` (eso solo resuelve CALLs anidados
    // desde DENTRO de un frame) — verificado contra revm
    // (`execution::create_init_frame` arma el MISMO `CallInputs` que un CALL
    // anidado y lo entrega al MISMO `make_call_frame` que chequea
    // `precompiles.run(...)` antes de cargar bytecode). Sin este gate, `to`
    // resolvería a bytecode VACÍO vía `code_to_execute` y la tx "tendría
    // éxito" sin correr el precompile — divergencia silenciosa. El `value` YA
    // se transfirió arriba; el
    // commit/revert de ACÁ reemplaza al que `frames::run` le haría al frame
    // raíz si hubiera uno real (acá no lo hay: `RootStart::Resolved` salta
    // `frames::run` por completo).
    if let Some(id) = crate::precompiles::precompile_for(to, request.env.spec) {
        let outcome = frames::resolve_precompile_outcome(id, &tx.input, frame_gas);
        if outcome.is_success() {
            journal.commit(checkpoint);
        } else {
            journal.revert_to(checkpoint);
        }
        return Ok((journal, RootStart::Resolved(outcome), auth_refund));
    }

    // El código del frame raíz sale del JOURNAL, no del `State`: una
    // autorización de esta misma tx puede haber delegado `to` hace tres
    // líneas (el patrón canónico de EIP-7702 es una EOA que se auto-delega y
    // se manda calldata a sí misma). `code_to_execute` resuelve UN hop
    // (revm: `create_init_frame`), y el `warm` de la delegada replica que
    // revm la cargue —sin cobrar gas— al armar el frame raíz.
    if let Some(delegated) = journal.delegation_of(to) {
        journal.warm(delegated);
    }
    let bytecode = journal.code_to_execute(to);

    let context = CallContext {
        address: to,
        caller: tx.sender,
        value: tx.value,
        calldata: tx.input.clone(),
        bytecode,
        is_static: false,
        depth: 0,
    };
    Ok((
        journal,
        RootStart::Frame(Box::new(Frame::call(
            Interpreter::new(context, frame_gas, request.env.spec),
            frame_gas,
            checkpoint,
        ))),
        auth_refund,
    ))
}

/// Corre la tx completa (frame raíz + sub-frames) y la liquida.
pub(crate) fn execute_tx(request: &TxRequest<'_>) -> Result<TxOutcome, VmError> {
    let (mut journal, root, auth_refund) = prepare(request)?;

    let outcome = match root {
        RootStart::Frame(frame) => {
            frames::run(&mut journal, &mut PlainRunner, *frame, request.env.spec)?
        }
        RootStart::Resolved(outcome) => outcome,
    };

    // Fail-closed: un fallo de lectura del `State` durante la ejecución no se
    // aproxima como cero — aborta la tx con error interno.
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }

    settle(&mut journal, request, outcome, auth_refund)
}

/// Traduce el resultado del frame raíz a gas cobrado + diff, y liquida los
/// balances de fee (devolución al sender, tip al coinbase).
fn settle(
    journal: &mut Journal<'_>,
    request: &TxRequest<'_>,
    outcome: InterpreterOutcome,
    auth_refund: u64,
) -> Result<TxOutcome, VmError> {
    let tx = request.tx;
    let spent = request
        .intrinsic_gas
        .checked_add(outcome.gas_used())
        .ok_or_else(|| internal("overflow sumando gas intrínseco y de ejecución"))?;
    let charge = |spent: u64, refund: u64| {
        spent
            .checked_sub(refund)
            .ok_or_else(|| internal("refund mayor que el gas usado (tope EIP-3529 roto)"))
    };

    let (result, gas_charged) = match outcome {
        InterpreterOutcome::Success { output, .. } => {
            let refund = journal.settled_refund_with(auth_refund, spent);
            let gas_charged = charge(spent, refund)?;
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
        // El refund acumulado DENTRO del frame se pierde con el revert, pero
        // el de EIP-7702 no: se aplicó fuera de todo frame (revm:
        // `post_execution::refund` corre después de `last_frame_result`, que
        // solo conserva el del frame `if instruction_result.is_ok()`).
        InterpreterOutcome::Revert { output, .. } => {
            let refund = capped_refund(auth_refund, spent);
            let gas_charged = charge(spent, refund)?;
            (
                ExecutionResult::Revert {
                    gas_used: gas_charged,
                    gas_refunded: refund,
                    output,
                },
                gas_charged,
            )
        }
        InterpreterOutcome::Halt { reason, .. } => {
            // Un Halt consume TODO el gas de la tx (el intérprete ya consumió
            // todo el del frame; el intrínseco se suma) — menos el refund de
            // EIP-7702, que también sobrevive al halt.
            let spent = spent.min(tx.gas_limit);
            let refund = capped_refund(auth_refund, spent);
            let gas_charged = charge(spent, refund)?;
            (
                ExecutionResult::Halt {
                    reason: halt_reason(reason),
                    gas_used: gas_charged,
                    gas_refunded: refund,
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
    // cobro real. Antes un Halt nunca disparaba el `if` (cobraba
    // `tx.gas_limit` completo y la validación garantiza `gas_limit >=
    // floor_gas`); con el refund de EIP-7702 sobreviviendo al halt, el gas
    // cobrado ya puede caer por debajo del floor — el clamp corre igual para
    // las tres ramas, sin un caso especial que pueda desincronizarse.
    let floor_applies = request.env.spec.is_enabled(Spec::Prague);
    let (result, gas_charged) = if floor_applies && gas_charged < request.floor_gas {
        (
            apply_calldata_floor(result, request.floor_gas),
            request.floor_gas,
        )
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
/// El resultado pierde el refund reportado (`gas_refunded: 0`) en las TRES
/// ramas: el floor lo absorbe entero (idéntico a `ResultGas::final_refunded`
/// de revm — cuando el floor muerde, el refund efectivo es 0, no el crudo).
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
            gas_refunded: 0,
            output,
        },
        ExecutionResult::Halt { reason, .. } => ExecutionResult::Halt {
            reason,
            gas_used: floor_gas,
            gas_refunded: 0,
        },
    }
}

/// Tope de EIP-3529 aplicado a un refund que NO viene del contador del frame
/// (el de EIP-7702): mismo `gas_used/5` que `Journal::settled_refund`.
fn capped_refund(refund: u64, gas_used: u64) -> u64 {
    refund.min(gas_used / crate::journal::REFUND_QUOTIENT)
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
    // se crea el coinbase por un touch de cero.
    journal
        .credit(request.env.coinbase, reward)
        .map_err(|_| internal("overflow acreditando el tip al coinbase"))?;
    Ok(())
}

/// `interpreter::Halt` → `HaltReason` del seam. Mapping **TOTAL** (sin `_`):
/// un `Halt` nuevo sin caso acá no compila. Obligación registrada en la ficha
/// 01 y en §Consequences.
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

    // Sin código que correr no hay nada que trazar. Una tx tipo 4 SÍ se traza
    // aunque `to` no tenga código en el pre-state: sus autorizaciones pueden
    // delegarlo antes del frame raíz.
    if let Some(to) = tx.to {
        let has_code = state
            .account(to)?
            .is_some_and(|account| account.code_hash != KECCAK256_EMPTY);
        if !has_code && tx.tx_type != TxType::Eip7702 {
            return Ok(None);
        }
    }
    let request = TxRequest {
        tx,
        env,
        state,
        to: tx.to,
        intrinsic_gas: crate::own_vm::intrinsic_gas(
            &tx.input,
            tx.to.is_none(),
            &tx.access_list,
            &tx.authorization_list,
            env.spec,
        )?,
        effective_price: crate::own_vm::gas_prices(tx, env)?.0,
        floor_gas: crate::own_vm::calldata_floor_gas(&tx.input)?,
        blob_gas_used: crate::own_vm::total_blob_gas(tx)?,
    };
    let (mut journal, root, _auth_refund) = prepare(&request)?;
    let mut runner = crate::frames::TracingRunner {
        sink,
        refund_total: 0,
    };
    let outcome = match root {
        RootStart::Frame(frame) => {
            frames::run(&mut journal, &mut runner, *frame, request.env.spec)?
        }
        RootStart::Resolved(outcome) => outcome,
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
