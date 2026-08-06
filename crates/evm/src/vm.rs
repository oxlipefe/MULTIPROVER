//! Seam `Vm` — el ÚNICO contrato entre el cliente y el motor de ejecución
//! (vendoreado de zeth, **NO redefinir**). `revm` lo implementa hoy en zeth; el
//! EVM propio lo implementará en Fase 2, drop-in detrás del seam `Vm` de Repo A.

use repo_b_common::primitives::{Address, Bytes};
use repo_b_common::transaction::Transaction;

use crate::error::VmError;
use crate::result::{ExecutionOutcome, StateChanges};
use crate::state::State;
use crate::types::{BlockEnv, CallRequest, StateOverrides};

pub trait Vm {
    fn execute_tx(
        &mut self,
        tx: &Transaction,
        env: &BlockEnv,
        state: &dyn State,
    ) -> Result<ExecutionOutcome, VmError>;

    /// System call (EIP-4788/2935): caller = `SYSTEM_ADDRESS`, sin checks de
    /// firma/nonce/balance, no descuenta gas del bloque. Si el contrato no
    /// existe, devuelve un success no-op.
    fn execute_system_call(
        &mut self,
        to: Address,
        data: Bytes,
        env: &BlockEnv,
        state: &dyn State,
    ) -> Result<ExecutionOutcome, VmError>;

    /// Abre un contexto de bloque. El EVM mantiene el journal de cambios a
    /// través de los `transact_in_block`/`system_call_in_block` hasta
    /// `finish_block`.
    fn begin_block(&mut self, env: &BlockEnv, state: &dyn State) -> Result<(), VmError>;

    /// Ejecuta una tx en el contexto del bloque. El sender se pre-recupera —
    /// el VM NO llama a `recover_signer`.
    fn transact_in_block(
        &mut self,
        tx: &Transaction,
        sender: Address,
    ) -> Result<ExecutionOutcome, VmError>;

    /// Ejecuta una system call en el contexto del bloque.
    fn system_call_in_block(
        &mut self,
        to: Address,
        data: Bytes,
    ) -> Result<ExecutionOutcome, VmError>;

    /// Cierra el contexto de bloque y devuelve todos los cambios acumulados.
    fn finish_block(&mut self) -> Result<StateChanges, VmError>;

    /// `eth_call`/estimateGas: caller arbitrario, sin firma; checks de
    /// nonce/balance/base_fee deshabilitados. El llamador descarta
    /// `state_changes` (simulación read-only).
    fn execute_call(
        &mut self,
        call: &CallRequest,
        env: &BlockEnv,
        state: &dyn State,
        overrides: Option<&StateOverrides>,
    ) -> Result<ExecutionOutcome, VmError>;
}
