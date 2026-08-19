//! `StrictState` — un `State` que sirve **solo** lo grabado y falla ruidoso
//! ante cualquier otra cosa.
//!
//! Es el juez del grabador: si la ejecución alimentada por él da el MISMO
//! resultado que contra el estado completo, el log era **suficiente**; si al
//! quitarle un ítem deja de darlo, ese ítem era **necesario**. Las dos mitades
//! juntas son la propiedad "ni más ni menos" del DoD de la fase.
//!
//! Fail-closed, nunca aproximar: un acceso no grabado es un `Err`, no un cero.
//! Un cero silencioso convertiría un witness incompleto en una ejecución que
//! "anda" y produce el root equivocado, que es exactamente el modo de falla que
//! la statelessness tiene que hacer imposible.

use alloc::boxed::Box;
use alloc::format;

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_evm::error::StateError;
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, CodeMetadata};

use crate::access_log::AccessLog;

#[derive(Debug, Clone)]
pub struct StrictState {
    log: AccessLog,
}

impl StrictState {
    #[must_use]
    pub fn new(log: AccessLog) -> Self {
        Self { log }
    }

    #[must_use]
    pub fn log(&self) -> &AccessLog {
        &self.log
    }
}

fn missing<T>(what: &str) -> Result<T, StateError> {
    Err(StateError::Database(format!(
        "acceso no grabado en el witness: {what}"
    )))
}

impl State for StrictState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        match self.log.accounts.get(&addr) {
            // `Some(None)` es ausencia PROBADA: la grabó el recorder porque la
            // ejecución preguntó y el mundo contestó "no existe".
            Some(info) => Ok(info.clone()),
            None => missing(&format!("account({addr})")),
        }
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        match self.log.storage.get(&(addr, key)) {
            Some(value) => Ok(*value),
            None => missing(&format!("storage({addr}, {key})")),
        }
    }

    fn storage_root(&self, addr: Address) -> Result<B256, StateError> {
        match self.log.storage_roots.get(&addr) {
            Some(root) => Ok(*root),
            None => missing(&format!("storage_root({addr})")),
        }
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        match self.log.code.get(&code_hash) {
            Some(code) => Ok(code.clone()),
            None => missing(&format!("code({code_hash})")),
        }
    }

    fn code_metadata(&self, code_hash: B256) -> Result<CodeMetadata, StateError> {
        match self.log.code_metadata.get(&code_hash) {
            Some(meta) => Ok(meta.clone()),
            None => missing(&format!("code_metadata({code_hash})")),
        }
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        match self.log.block_hashes.get(&number) {
            Some(hash) => Ok(*hash),
            None => missing(&format!("block_hash({number})")),
        }
    }
}

/// El seam pide `Clone` sobre `Box<dyn State>`; sin esto el motor no puede
/// abrir un bloque (`BlockState::new(state.clone_state())`).
impl StrictState {
    #[must_use]
    pub fn boxed(self) -> Box<dyn State> {
        Box::new(self)
    }
}
