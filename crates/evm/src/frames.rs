//! El **frame stack explícito**: la pila de frames
//! que maneja las `InterpreterAction` sin recursión nativa.
//!
//! Por qué una `Vec` y no recursión: una cadena de 1024 CALLs no puede
//! reventar el stack nativo del guest RISC-V — el proving exige una cota
//! determinista. El bound del protocolo es `CALL_DEPTH_LIMIT`.
//!
//! Reparto de responsabilidades (deliberado):
//! - El **intérprete** resuelve la tabla de contexto de los 4 opcodes y TODO
//!   el gas (access, `G_callvalue`, `G_newaccount`, memoria, 63/64, stipend).
//! - Este executor es mecánico: checkpoint → transferir → cargar código →
//!   empujar; y al volver, commit/revert + `resume` del padre.

use alloc::boxed::Box;
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, Bytes};
use repo_b_interpreter::CALL_DEPTH_LIMIT;
use repo_b_interpreter::call::{
    CallInputs, CreateInputs, CreateKind, CreateOutcome, InterpreterAction, SubcallOutcome,
};
use repo_b_interpreter::context::CallContext;
use repo_b_interpreter::gas::{MAX_CODE_SIZE, cost};
use repo_b_interpreter::interpreter::Interpreter;
use repo_b_interpreter::result::{Halt, InterpreterOutcome};

use crate::error::{InternalError, VmError};
use crate::journal::{Checkpoint, Journal};
use crate::types::Spec;

/// EIP-161: un contrato recién creado arranca con `nonce = 1`, no 0.
const NEW_CONTRACT_NONCE: u64 = 1;

/// EIP-3541 (London): ningún código desplegado puede empezar con este byte.
const EF_PREFIX: u8 = 0xEF;

/// Cómo se corre un frame. La ÚNICA diferencia entre ejecutar y trazar: el
/// loop de frames, el commit/revert y el `resume` son literalmente el mismo
/// código, así que trazar no puede divergir de ejecutar (misma regla que
/// `build_frame` en 004).
pub(crate) trait FrameRunner {
    fn run(
        &mut self,
        interpreter: &mut Interpreter,
        journal: &mut Journal<'_>,
    ) -> InterpreterAction;
}

/// Ejecución normal (la del guest: el tracer ni existe sin su feature).
pub(crate) struct PlainRunner;

impl FrameRunner for PlainRunner {
    fn run(
        &mut self,
        interpreter: &mut Interpreter,
        journal: &mut Journal<'_>,
    ) -> InterpreterAction {
        interpreter.run(journal)
    }
}

/// Ejecución trazada (EIP-3155) — diagnóstico del harness diferencial.
/// Acarrea el refund acumulado ENTRE frames: EIP-3155 lo reporta a nivel tx.
#[cfg(feature = "tracer")]
pub(crate) struct TracingRunner<'a> {
    pub sink: &'a mut dyn repo_b_interpreter::tracer::StepSink,
    pub refund_total: i64,
}

#[cfg(feature = "tracer")]
impl FrameRunner for TracingRunner<'_> {
    fn run(
        &mut self,
        interpreter: &mut Interpreter,
        journal: &mut Journal<'_>,
    ) -> InterpreterAction {
        let mut tracked =
            repo_b_interpreter::tracer::RefundTrackingHost::with_total(journal, self.refund_total);
        let action = interpreter.run_traced(&mut tracked, self.sink);
        self.refund_total = tracked.total();
        action
    }
}

/// Qué clase de frame es. La diferencia NO es cosmética: al cerrar, un frame
/// de creación pasa por `finish_create` (EIP-170/3541 + depósito de código) y
/// le devuelve al padre una DIRECCIÓN, no un bit de status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Call,
    Create { address: Address },
}

/// Un frame vivo de la pila.
pub(crate) struct Frame {
    interpreter: Interpreter,
    /// Punto del journal al que se vuelve si el frame revierte o haltea.
    checkpoint: Checkpoint,
    /// Gas con el que arrancó (para calcular el remanente que vuelve al padre).
    gas_limit: u64,
    kind: FrameKind,
}

impl Frame {
    /// Frame de mensaje (el raíz de una tx con `to`, o el de un CALL\*).
    pub(crate) fn call(interpreter: Interpreter, gas_limit: u64, checkpoint: Checkpoint) -> Self {
        Self {
            interpreter,
            checkpoint,
            gas_limit,
            kind: FrameKind::Call,
        }
    }
}

/// Corre el árbol de frames de una tx hasta que el frame raíz termina.
///
/// El commit/revert por frame es la semántica de sub-call de EIP-140/211: lo
/// que hizo un sub-árbol revertido (storage, logs, refunds, balances, warm
/// sets) desaparece; el abuelo NUNCA ve el estado del nieto revertido.
pub(crate) fn run(
    journal: &mut Journal<'_>,
    runner: &mut dyn FrameRunner,
    root: Frame,
    spec: Spec,
) -> Result<InterpreterOutcome, VmError> {
    let mut frames = Vec::new();
    frames.push(root);

    loop {
        let action = {
            let frame = frames
                .last_mut()
                .ok_or_else(|| internal("pila de frames vacía (bug del executor)"))?;
            runner.run(&mut frame.interpreter, journal)
        };
        match action {
            InterpreterAction::Call(inputs) => {
                let depth = {
                    let frame = frames
                        .last()
                        .ok_or_else(|| internal("call sin frame activo (bug del executor)"))?;
                    frame.interpreter.depth().saturating_add(1)
                };
                match open_frame(journal, depth, &inputs, spec)? {
                    FrameOpening::Opened(frame) => frames.push(*frame),
                    FrameOpening::NotExecuted => {
                        // La call NO se ejecutó (depth excedido o sin fondos):
                        // push 0 y el gas reenviado vuelve entero. NO es halt.
                        let frame = frames
                            .last_mut()
                            .ok_or_else(|| internal("call sin frame activo (bug del executor)"))?;
                        frame
                            .interpreter
                            .resume(SubcallOutcome::not_executed(inputs.gas_limit));
                    }
                    FrameOpening::Resolved(outcome) => {
                        // Un precompile implementado corrió síncronamente: push
                        // directo al caller, sin pasar por el loop de frames.
                        let frame = frames
                            .last_mut()
                            .ok_or_else(|| internal("call sin frame activo (bug del executor)"))?;
                        frame.interpreter.resume(outcome);
                    }
                }
            }
            InterpreterAction::Create(inputs) => {
                let depth = {
                    let frame = frames
                        .last()
                        .ok_or_else(|| internal("create sin frame activo (bug del executor)"))?;
                    frame.interpreter.depth().saturating_add(1)
                };
                let rejected = match open_create_frame(journal, depth, &inputs)? {
                    CreateOpening::Opened(frame) => {
                        frames.push(*frame);
                        continue;
                    }
                    // No ejecutado: el gas reenviado vuelve ENTERO.
                    CreateOpening::NotExecuted => CreateOutcome::not_executed(inputs.gas_limit),
                    // Colisión: el gas reenviado se pierde COMPLETO.
                    CreateOpening::Collision => CreateOutcome {
                        address: None,
                        output: Bytes::new(),
                        gas_remaining: 0,
                    },
                };
                let frame = frames
                    .last_mut()
                    .ok_or_else(|| internal("create sin frame activo (bug del executor)"))?;
                frame.interpreter.resume_create(rejected);
            }
            InterpreterAction::Return(outcome) => {
                let finished = frames
                    .pop()
                    .ok_or_else(|| internal("return sin frame activo (bug del executor)"))?;
                match finished.kind {
                    FrameKind::Call => {
                        if outcome.is_success() {
                            journal.commit(finished.checkpoint);
                        } else {
                            journal.revert_to(finished.checkpoint);
                        }
                        let Some(parent) = frames.last_mut() else {
                            return Ok(outcome);
                        };
                        parent
                            .interpreter
                            .resume(subcall_outcome(&outcome, finished.gas_limit));
                    }
                    FrameKind::Create { address } => {
                        let (outcome, deployed) = finish_create(
                            journal,
                            finished.checkpoint,
                            outcome,
                            address,
                            finished.gas_limit,
                        );
                        let Some(parent) = frames.last_mut() else {
                            return Ok(outcome);
                        };
                        parent.interpreter.resume_create(create_outcome(
                            &outcome,
                            deployed,
                            finished.gas_limit,
                        ));
                    }
                }
            }
        }
    }
}

/// Traduce la trichotomy del sub-frame a lo que ve el caller.
///
/// El gas que vuelve es `gas_limit − gas_used` para los tres casos: en `Halt`
/// el intérprete ya consumió TODO (`gas_used == limit`), así que sale 0 sin
/// una rama especial que pueda desincronizarse.
fn subcall_outcome(outcome: &InterpreterOutcome, gas_limit: u64) -> SubcallOutcome {
    let output = match outcome {
        InterpreterOutcome::Success { output, .. } | InterpreterOutcome::Revert { output, .. } => {
            output.clone()
        }
        InterpreterOutcome::Halt { .. } => Bytes::new(),
    };
    SubcallOutcome {
        success: outcome.is_success(),
        output,
        gas_remaining: gas_limit.saturating_sub(outcome.gas_used()),
    }
}

/// Resultado de intentar abrir el sub-frame de un CALL/CALLCODE/DELEGATECALL/
/// STATICCALL. Mismo espíritu que `CreateOpening`: un precompile implementado
/// no corre bytecode vía `Interpreter`, así que no tiene sentido construirle
/// un `Frame` — se resuelve síncronamente (`resolve_precompile`) y el
/// resultado se empuja directo al caller sin pasar por el loop de `run`
/// (verificado contra revm `make_call_frame`: transfer del
/// `value` SIEMPRE primero, después `precompiles.run(...)`, commit/revert
/// sobre el MISMO checkpoint del transfer).
pub(crate) enum FrameOpening {
    /// `Box` por la misma razón que `CreateOpening::Opened`: el `Frame` lleva
    /// el `Interpreter` entero.
    Opened(Box<Frame>),
    /// No se ejecutó (depth excedido o balance insuficiente): push 0 y el gas
    /// reenviado vuelve ENTERO. No es un halt.
    NotExecuted,
    /// Un precompile implementado (`0x01..=0x04`) corrió síncronamente y ya
    /// tiene resultado — éxito (incluido ECRECOVER con firma inválida, que
    /// "tiene éxito" con output vacío) u OOG (el único `Err` que
    /// `precompiles::run` devuelve).
    Resolved(SubcallOutcome),
}

/// Abre el sub-frame de un `CallInputs`.
///
/// `FrameOpening::NotExecuted` = la call **no se ejecuta** y el caller pushea
/// 0 recuperando el gas: profundidad excedida o balance insuficiente. Son las
/// dos únicas razones (execution-specs `generic_call`; revm las clasifica
/// como `return_revert`, no como halt).
fn open_frame(
    journal: &mut Journal<'_>,
    depth: usize,
    inputs: &CallInputs,
    spec: Spec,
) -> Result<FrameOpening, VmError> {
    // Bound del protocolo. `>` y no `>=`: el frame raíz es profundidad 0 y el
    // límite se chequea contra la profundidad del frame NUEVO (verificado
    // contra revm `make_call_frame` y execution-specs `generic_call`).
    if depth > CALL_DEPTH_LIMIT {
        return Ok(FrameOpening::NotExecuted);
    }
    let checkpoint = journal.checkpoint();
    if inputs.kind.transfers_balance()
        && journal
            .transfer(inputs.caller, inputs.target, inputs.transfer_value)
            .is_err()
    {
        journal.revert_to(checkpoint);
        return Ok(FrameOpening::NotExecuted);
    }

    // Las precompiles ACTIVAS EN ESTE FORK arrancan WARM desde el inicio de la
    // tx (`Journal::prewarm_tx`, EIP-2929) — acá solo se resuelve, sin tocar el
    // accessed set de nuevo. Una dirección del rango que todavía no se activó
    // no entra por acá: es una cuenta vacía normal y cae al camino de abajo.
    if let Some(id) = crate::precompiles::precompile_for(inputs.code_address, spec) {
        return Ok(FrameOpening::Resolved(resolve_precompile(
            journal,
            checkpoint,
            id,
            &inputs.input,
            inputs.gas_limit,
        )));
    }

    // EIP-7702: si `code_address` tiene un designator, el frame
    // corre el código de la cuenta DELEGADA — **un solo hop**. El resto del
    // contexto (`address`, `caller`, storage) no cambia: el código delegado
    // corre como si fuera propio de la cuenta, NO como un DELEGATECALL
    // implícito. El gas del acceso a la delegada ya lo cobró el opcode
    // (`Interpreter::call_op`, vía `Host::load_delegated_account`).
    let bytecode = journal.code_to_execute(inputs.code_address);

    let context = CallContext {
        address: inputs.target,
        caller: inputs.caller,
        value: inputs.value,
        calldata: inputs.input.clone(),
        bytecode,
        is_static: inputs.is_static,
        depth,
    };
    Ok(FrameOpening::Opened(Box::new(Frame {
        interpreter: Interpreter::new(context, inputs.gas_limit),
        checkpoint,
        gas_limit: inputs.gas_limit,
        kind: FrameKind::Call,
    })))
}

/// Corre un precompile implementado SÍNCRONAMENTE (sin `Interpreter`) y
/// traduce el resultado a lo que ve el caller.
///
/// El `checkpoint` es el MISMO que cubre el transfer de `value` ya hecho por
/// `open_frame`: éxito ⇒ se queda (mismo `commit` no-op que un frame de
/// mensaje exitoso); sin gas ⇒ `revert_to` (mismo tratamiento que el `Halt`
/// de cualquier sub-frame real — verificado contra revm `make_call_frame`:
/// `result.is_ok()` commitea, si no, revierte el MISMO checkpoint del
/// transfer).
fn resolve_precompile(
    journal: &mut Journal<'_>,
    checkpoint: Checkpoint,
    id: u8,
    input: &Bytes,
    gas_limit: u64,
) -> SubcallOutcome {
    let outcome = resolve_precompile_outcome(id, input, gas_limit);
    if outcome.is_success() {
        journal.commit(checkpoint);
    } else {
        journal.revert_to(checkpoint);
    }
    // Reusa el MISMO traductor que cierra un frame de mensaje real: un
    // precompile resuelto sigue la trichotomy Success/Halt (nunca Revert, los
    // cuatro de este slice no la producen), y `subcall_outcome` ya sabe
    // convertir eso a lo que ve el caller.
    subcall_outcome(&outcome, gas_limit)
}

/// Resultado de intentar abrir un frame de creación.
pub(crate) enum CreateOpening {
    /// `Box` porque un `Frame` lleva el `Interpreter` entero: sin la
    /// indirección el enum pesa lo mismo en TODAS sus variantes (clippy
    /// `large_enum_variant`), y en el guest eso es stack desperdiciado.
    Opened(Box<Frame>),
    /// No se ejecutó (depth, fondos o nonce en `u64::MAX`): push 0 y el gas
    /// reenviado vuelve ENTERO. No es un halt.
    NotExecuted,
    /// La dirección ya estaba ocupada: push 0 y **todo** el gas reenviado se
    /// pierde. El bump del nonce del creador ya ocurrió y NO se deshace.
    Collision,
}

/// Abre el frame de un CREATE/CREATE2. **Secuencia de consenso**, verificada
/// contra revm (`make_create_frame` + `create_account_checkpoint`):
///
/// 1. depth excedido ⇒ no ejecutado, el gas reenviado vuelve ENTERO.
/// 2. balance del creador insuficiente ⇒ ídem.
/// 3. nonce del creador en `u64::MAX` ⇒ ídem (borde inalcanzable, fail-closed).
/// 4. **bump del nonce del creador AHORA**, fuera de todo checkpoint de esta
///    apertura: sobrevive incluso a la colisión del paso 6.
/// 5. dirección derivada con el nonce **pre-bump**.
/// 6. la dirección se warmea (EIP-2929) **antes** del checkpoint: queda warm
///    aunque la creación falle (orden de revm, no cosmético).
/// 7. checkpoint + colisión (`nonce != 0` o código no vacío) ⇒ push 0 y
///    **TODO el gas reenviado se pierde**, pero el bump de (4) persiste.
/// 8. transferencia del value, `nonce = 1` del contrato nuevo (EIP-161) y
///    marca "creado en esta tx" (EIP-6780).
pub(crate) fn open_create_frame(
    journal: &mut Journal<'_>,
    depth: usize,
    inputs: &CreateInputs,
) -> Result<CreateOpening, VmError> {
    if depth > CALL_DEPTH_LIMIT {
        return Ok(CreateOpening::NotExecuted);
    }
    if journal.balance(inputs.creator) < inputs.value {
        return Ok(CreateOpening::NotExecuted);
    }
    let creator_nonce = journal.nonce(inputs.creator);
    if creator_nonce == u64::MAX {
        return Ok(CreateOpening::NotExecuted);
    }
    journal
        .bump_nonce(inputs.creator)
        .map_err(|_| internal("overflow de nonce del creador (chequeo previo roto)"))?;

    let address = derive_address(inputs, creator_nonce);
    journal.warm(address);

    let checkpoint = journal.checkpoint();
    if journal.is_create_collision(address) {
        journal.revert_to(checkpoint);
        return Ok(CreateOpening::Collision);
    }
    if journal
        .transfer(inputs.creator, address, inputs.value)
        .is_err()
    {
        journal.revert_to(checkpoint);
        return Ok(CreateOpening::NotExecuted);
    }
    journal.set_nonce(address, NEW_CONTRACT_NONCE);
    journal.mark_created(address);

    let context = CallContext {
        address,
        caller: inputs.creator,
        value: inputs.value,
        // El initcode corre como CÓDIGO del frame nuevo; su calldata es vacía.
        calldata: Bytes::new(),
        bytecode: inputs.init_code.clone(),
        is_static: inputs.is_static,
        depth,
    };
    Ok(CreateOpening::Opened(Box::new(Frame {
        interpreter: Interpreter::new(context, inputs.gas_limit),
        checkpoint,
        gas_limit: inputs.gas_limit,
        kind: FrameKind::Create { address },
    })))
}

/// Derivación de la dirección del contrato nuevo. Se delega en
/// `alloy_primitives` —que es EXACTAMENTE lo que llama revm— en vez de
/// re-implementar el RLP de CREATE o la concatenación de EIP-1014.
fn derive_address(inputs: &CreateInputs, creator_nonce: u64) -> Address {
    match inputs.kind {
        CreateKind::Create => inputs.creator.create(creator_nonce),
        CreateKind::Create2 { salt } => inputs
            .creator
            .create2_from_code(salt.to_be_bytes::<32>(), &inputs.init_code),
    }
}

/// Cierra un frame de creación: decide qué pasa con el código que devolvió el
/// initcode y hace el commit/revert del checkpoint.
///
/// Orden verificado contra revm (`return_create`): revert/halt → **EIP-170**
/// → **EIP-3541** → depósito de código (`CODE_DEPOSIT`/byte del gas remanente
/// del sub-frame; EIP-2 punto 3: sin gas, la creación falla con OOG en vez de
/// dejar un contrato vacío).
///
/// Los tres fallos post-initcode revierten el checkpoint y consumen TODO el
/// gas del sub-frame (revm no los clasifica `is_ok_or_revert`, así que el
/// padre no recupera nada).
fn finish_create(
    journal: &mut Journal<'_>,
    checkpoint: Checkpoint,
    outcome: InterpreterOutcome,
    address: Address,
    gas_limit: u64,
) -> (InterpreterOutcome, Option<Address>) {
    let InterpreterOutcome::Success { output, gas_used } = outcome else {
        journal.revert_to(checkpoint);
        return (outcome, None);
    };
    let failed = |journal: &mut Journal<'_>, reason: Halt| {
        journal.revert_to(checkpoint);
        (
            InterpreterOutcome::Halt {
                reason,
                gas_used: gas_limit,
            },
            None,
        )
    };
    if output.len() > MAX_CODE_SIZE {
        return failed(journal, Halt::CreateContractSizeLimit);
    }
    if output.first() == Some(&EF_PREFIX) {
        return failed(journal, Halt::CreateContractStartingWithEF);
    }
    let Some(deposit) = u64::try_from(output.len())
        .ok()
        .and_then(|len| len.checked_mul(cost::CODE_DEPOSIT))
    else {
        return failed(journal, Halt::OutOfGas);
    };
    let Some(total_used) = gas_used
        .checked_add(deposit)
        .filter(|used| *used <= gas_limit)
    else {
        return failed(journal, Halt::OutOfGas);
    };
    journal.commit(checkpoint);
    journal.set_code(address, output);
    (
        InterpreterOutcome::Success {
            // El output de un frame de creación NO es data: es el código
            // desplegado. El caller ve returndata VACÍA (EIP-211) y una tx de
            // creación reporta el código como su output (revm: `Output::Create`).
            output: journal.code_of(address),
            gas_used: total_used,
        },
        Some(address),
    )
}

/// Traduce el cierre de un frame de creación a lo que ve el caller: dirección
/// (o 0), returndata SOLO si el initcode revirtió, y el gas remanente.
fn create_outcome(
    outcome: &InterpreterOutcome,
    deployed: Option<Address>,
    gas_limit: u64,
) -> CreateOutcome {
    let output = match outcome {
        // EIP-211: en éxito el output es código desplegado, no data.
        InterpreterOutcome::Revert { output, .. } => output.clone(),
        InterpreterOutcome::Success { .. } | InterpreterOutcome::Halt { .. } => Bytes::new(),
    };
    CreateOutcome {
        address: deployed,
        output,
        gas_remaining: gas_limit.saturating_sub(outcome.gas_used()),
    }
}

/// Corre un precompile implementado y devuelve el resultado como
/// `InterpreterOutcome` — la forma que necesita el frame RAÍZ (`execution.rs
/// ::prepare`), que no tiene un caller al que pushear un `SubcallOutcome`.
/// Comparte la lógica de gas/fallo con `resolve_precompile` (que la traduce a
/// `SubcallOutcome` para el caso de una sub-call): un solo punto que sabe
/// "cómo corre un precompile", nunca dos que puedan desincronizarse.
pub(crate) fn resolve_precompile_outcome(
    id: u8,
    input: &Bytes,
    gas_limit: u64,
) -> InterpreterOutcome {
    match crate::precompiles::run(id, input, gas_limit) {
        Ok(output) => InterpreterOutcome::Success {
            output: output.data,
            gas_used: output.gas_used,
        },
        Err(()) => InterpreterOutcome::Halt {
            reason: Halt::OutOfGas,
            gas_used: gas_limit,
        },
    }
}

fn internal(msg: &str) -> VmError {
    VmError::Internal(InternalError::EvmInternal(alloc::string::String::from(msg)))
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use repo_b_common::primitives::{B256, KECCAK256_EMPTY, U256};
    use repo_b_interpreter::call::CallKind;

    use super::*;
    use crate::error::StateError;
    use crate::state::State;
    use crate::types::{AccountInfo, CodeMetadata};

    const CALLER: Address = Address::new([0xAA; 20]);
    const TARGET: Address = Address::new([0xBB; 20]);

    /// `State` mínimo para los tests del executor: cuentas sin código.
    #[derive(Debug, Clone, Default)]
    struct BalancesOnly(BTreeMap<Address, U256>);

    impl State for BalancesOnly {
        fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
            Ok(self.0.get(&addr).map(|balance| AccountInfo {
                balance: *balance,
                nonce: 0,
                code_hash: KECCAK256_EMPTY,
            }))
        }
        fn storage(&self, _addr: Address, _key: U256) -> Result<U256, StateError> {
            Ok(U256::ZERO)
        }
        fn code(&self, _code_hash: B256) -> Result<Bytes, StateError> {
            Ok(Bytes::new())
        }
        fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
            Ok(CodeMetadata::Regular)
        }
        fn block_hash(&self, _number: u64) -> Result<B256, StateError> {
            Ok(B256::ZERO)
        }
    }

    fn inputs(kind: CallKind, transfer_value: u64) -> CallInputs {
        CallInputs {
            kind,
            code_address: TARGET,
            target: TARGET,
            caller: CALLER,
            transfer_value: U256::from(transfer_value),
            value: U256::from(transfer_value),
            input: Bytes::new(),
            gas_limit: 10_000,
            is_static: false,
        }
    }

    /// Los helpers corren en el fork target del motor. Un test que necesite
    /// otro fork llama a `open_frame` directo con su `Spec`.
    const TEST_SPEC: Spec = Spec::Prague;

    #[track_caller]
    fn opened(journal: &mut Journal<'_>, depth: usize, inputs: &CallInputs) -> bool {
        match open_frame(journal, depth, inputs, TEST_SPEC) {
            Ok(FrameOpening::Opened(_)) => true,
            Ok(_) => false,
            Err(err) => panic!("open_frame falló: {err}"),
        }
    }

    /// El bound del protocolo, testeado en el límite exacto: 1024 frames de
    /// sub-call sobre el raíz (profundidad 0). Un fixture no puede llegar acá
    /// —el 63/64 agota el gas cerca del frame 340— así que el off-by-one solo
    /// se cubre desde este test.
    #[test]
    fn the_call_depth_limit_allows_1024_and_rejects_1025() {
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);
        let call = inputs(CallKind::Call, 0);

        assert!(opened(&mut journal, CALL_DEPTH_LIMIT - 1, &call));
        assert!(opened(&mut journal, CALL_DEPTH_LIMIT, &call));
        assert!(!opened(&mut journal, CALL_DEPTH_LIMIT + 1, &call));
    }

    #[test]
    fn a_call_without_funds_does_not_open_the_frame_and_leaves_no_trace() {
        let state = BalancesOnly(BTreeMap::from([(CALLER, U256::from(10u64))]));
        let mut journal = Journal::new(&state);

        assert!(!opened(&mut journal, 1, &inputs(CallKind::Call, 1_000)));

        // Fail-closed: el checkpoint revirtió el intento, no quedó un débito a
        // medias ni una cuenta creada.
        assert_eq!(journal.balance(CALLER), U256::from(10u64));
        assert_eq!(journal.balance(TARGET), U256::ZERO);
        assert!(journal.state_changes().unwrap_or_default().is_empty());
    }

    #[test]
    fn a_call_with_funds_moves_the_balance_into_the_new_frame() {
        let state = BalancesOnly(BTreeMap::from([(CALLER, U256::from(1_000u64))]));
        let mut journal = Journal::new(&state);

        assert!(opened(&mut journal, 1, &inputs(CallKind::Call, 100)));

        assert_eq!(journal.balance(CALLER), U256::from(900u64));
        assert_eq!(journal.balance(TARGET), U256::from(100u64));
    }

    #[test]
    fn delegatecall_never_moves_balance_even_with_an_apparent_value() {
        let state = BalancesOnly(BTreeMap::from([(CALLER, U256::from(1_000u64))]));
        let mut journal = Journal::new(&state);

        assert!(opened(
            &mut journal,
            1,
            &inputs(CallKind::DelegateCall, 100)
        ));

        assert_eq!(journal.balance(CALLER), U256::from(1_000u64));
        assert_eq!(journal.balance(TARGET), U256::ZERO);
    }

    /// Con el rango completo cerrado `0x01..=0x11`, ya NO
    /// existe una dirección "reservada pero sin implementar" — `is_precompile`/
    /// `precompile_id` coinciden byte a byte en ese rango (`FIRST_PRECOMPILE
    /// == ECRECOVER`, `LAST_PRECOMPILE == LAST_IMPLEMENTED`), así que el gate
    /// fail-closed que existía para ese hueco quedó DEAD CODE
    /// y se eliminó — el test de abajo reemplaza la garantía
    /// perdida por la que sigue siendo real: una dirección FUERA del rango
    /// reservado (`0x12`, el primer byte que ya no es precompile) es una
    /// cuenta vacía normal.
    fn outside_reserved_precompile_range() -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = 0x12;
        Address::new(bytes)
    }

    #[test]
    fn a_call_just_past_the_reserved_range_is_a_plain_empty_account_not_a_precompile() {
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);
        let mut call = inputs(CallKind::Call, 0);
        call.code_address = outside_reserved_precompile_range();

        // `Opened`, NO `Resolved`: `0x12` no está en el set de precompiles de
        // ningún fork — abre un frame normal con bytecode vacío, como
        // cualquier EOA.
        assert!(opened(&mut journal, 1, &call));
    }

    #[test]
    fn the_depth_check_wins_over_the_precompile_gate() {
        // Orden de revm (`make_call_frame`): primero el depth. Una call
        // demasiado profunda a una precompile pushea 0, no explota — no
        // depende de si la precompile está implementada, así que reusa
        // IDENTITY (`0x04`, ya implementada) en vez de una dirección
        // "reservada sin implementar" que ya no existe.
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);
        let mut call = inputs(CallKind::Call, 0);
        call.code_address = identity_precompile();

        assert!(!opened(&mut journal, CALL_DEPTH_LIMIT + 1, &call));
    }

    /// Dirección de IDENTITY (`0x04`), un precompile IMPLEMENTADO por este
    /// slice: `open_frame` lo resuelve (`FrameOpening::Resolved`), no lo
    /// rechaza.
    fn identity_precompile() -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = crate::precompiles::IDENTITY;
        Address::new(bytes)
    }

    #[track_caller]
    fn open_frame_ok(journal: &mut Journal<'_>, depth: usize, inputs: &CallInputs) -> FrameOpening {
        match open_frame(journal, depth, inputs, TEST_SPEC) {
            Ok(opening) => opening,
            Err(err) => panic!("open_frame falló: {err}"),
        }
    }

    #[test]
    fn a_call_to_an_implemented_precompile_resolves_instead_of_opening_a_frame() {
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);
        let mut call = inputs(CallKind::Call, 0);
        call.code_address = identity_precompile();
        call.input = Bytes::copy_from_slice(&[0xAB, 0xCD]);

        match open_frame_ok(&mut journal, 1, &call) {
            FrameOpening::Resolved(outcome) => {
                assert!(outcome.success);
                assert_eq!(outcome.output.as_ref(), &[0xAB, 0xCD]);
            }
            _ => panic!("un precompile implementado tiene que resolver, no abrir un frame"),
        }
    }

    #[test]
    fn a_call_with_value_to_a_precompile_moves_the_balance_before_resolving() {
        // El value SIGUE transfiriéndose aunque no haya bytecode que corra.
        let state = BalancesOnly(BTreeMap::from([(CALLER, U256::from(1_000u64))]));
        let mut journal = Journal::new(&state);
        let mut call = inputs(CallKind::Call, 100);
        call.code_address = identity_precompile();

        match open_frame_ok(&mut journal, 1, &call) {
            FrameOpening::Resolved(outcome) => assert!(outcome.success),
            _ => panic!("esperaba Resolved"),
        }
        assert_eq!(journal.balance(CALLER), U256::from(900u64));
        assert_eq!(journal.balance(TARGET), U256::from(100u64));
    }

    #[test]
    fn a_precompile_out_of_gas_reverts_the_value_transfer() {
        // Sin gas suficiente, el CALL entero falla como un OOG
        // normal de sub-frame — el value transferido tiene que revertir, no
        // quedar a medio camino.
        let state = BalancesOnly(BTreeMap::from([(CALLER, U256::from(1_000u64))]));
        let mut journal = Journal::new(&state);
        let mut call = inputs(CallKind::Call, 100);
        call.code_address = identity_precompile();
        call.gas_limit = 1; // IDENTITY con input vacío cuesta 15, no alcanza.

        match open_frame_ok(&mut journal, 1, &call) {
            FrameOpening::Resolved(outcome) => {
                assert!(!outcome.success);
                assert_eq!(outcome.gas_remaining, 0);
            }
            _ => panic!("esperaba Resolved"),
        }
        assert_eq!(journal.balance(CALLER), U256::from(1_000u64));
        assert_eq!(journal.balance(TARGET), U256::ZERO);
    }

    fn create_inputs(value: u64) -> CreateInputs {
        CreateInputs {
            creator: CALLER,
            kind: CreateKind::Create,
            value: U256::from(value),
            init_code: Bytes::new(),
            gas_limit: 10_000,
            is_static: false,
        }
    }

    #[track_caller]
    fn create_opened(journal: &mut Journal<'_>, depth: usize, inputs: &CreateInputs) -> bool {
        match open_create_frame(journal, depth, inputs) {
            Ok(CreateOpening::Opened(_)) => true,
            Ok(_) => false,
            Err(err) => panic!("open_create_frame falló: {err}"),
        }
    }

    /// El bound del protocolo aplica igual a CREATE, en el límite exacto y con
    /// el mismo `>` que CALL. Un fixture no puede llegar acá (el 63/64 agota
    /// el gas mucho antes de 1024), así que el off-by-one solo se cubre desde
    /// este test.
    #[test]
    fn the_call_depth_limit_applies_to_create_as_well() {
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);
        let create = create_inputs(0);

        assert!(create_opened(&mut journal, CALL_DEPTH_LIMIT - 1, &create));
        assert!(create_opened(&mut journal, CALL_DEPTH_LIMIT, &create));
        assert!(!create_opened(&mut journal, CALL_DEPTH_LIMIT + 1, &create));
    }

    /// Un CREATE demasiado profundo NO bumpea el nonce del creador: el chequeo
    /// de profundidad va ANTES del bump (revm `make_create_frame`).
    #[test]
    fn a_create_beyond_the_depth_limit_does_not_bump_the_creator_nonce() {
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);

        assert!(!create_opened(
            &mut journal,
            CALL_DEPTH_LIMIT + 1,
            &create_inputs(0)
        ));

        assert_eq!(journal.nonce(CALLER), 0);
        assert!(journal.state_changes().unwrap_or_default().is_empty());
    }

    /// Sin fondos tampoco se bumpea: el chequeo de balance también va antes.
    #[test]
    fn a_create_without_funds_does_not_bump_the_creator_nonce() {
        let state = BalancesOnly(BTreeMap::from([(CALLER, U256::from(10u64))]));
        let mut journal = Journal::new(&state);

        assert!(!create_opened(&mut journal, 1, &create_inputs(1_000)));

        assert_eq!(journal.nonce(CALLER), 0);
        assert_eq!(journal.balance(CALLER), U256::from(10u64));
    }

    /// El nonce del creador se bumpea ANTES del checkpoint de la creación: una
    /// colisión lo deja bumpeado igual. Es el footgun de consenso del slice.
    #[test]
    fn a_colliding_create_keeps_the_creator_nonce_bumped() {
        let state = BalancesOnly::default();
        let mut journal = Journal::new(&state);
        // La dirección derivada ya tiene nonce != 0 ⇒ colisión.
        let occupied = CALLER.create(0);
        journal.set_nonce(occupied, 1);

        assert!(!create_opened(&mut journal, 1, &create_inputs(0)));

        assert_eq!(journal.nonce(CALLER), 1);
    }
}
