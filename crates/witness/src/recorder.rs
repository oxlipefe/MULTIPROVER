//! `RecordingState` — envuelve un `State` y anota lo que le pidieron.
//!
//! **Transparente por construcción**: delega todo y no cambia un solo valor
//! devuelto, ni un `Err`. Un recorder que "arregla" algo es un motor distinto,
//! y el witness que produjera no probaría la ejecución real.
//!
//! **Vive del lado del host, no del guest.** El guest ejecuta contra el witness
//! ya armado: no graba nada. Por eso el recorder puede pagar `std` (el log
//! necesita interior mutability compartida, y el seam pide `&self` + `Send +
//! Sync`), y por eso está detrás de la feature `std` — el crate por default
//! sigue siendo `no_std`, que es lo que el `State` respaldado por witness va a
//! necesitar.
//!
//! **El log se comparte con los clones y no se copia.** No es una elección de
//! estilo: `OwnVm::begin_block` hace `BlockState::new(state.clone_state())`, o
//! sea que el motor CLONA el `State` que recibe. Con el log por valor, todo lo
//! grabado durante el bloque se perdería en el clon y el witness saldría vacío
//! justo en el camino que importa.

use std::sync::{Arc, Mutex, MutexGuard};

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_evm::error::StateError;
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, CodeMetadata};

use crate::access_log::AccessLog;

/// `Debug` a mano: `Box<dyn State>` no lo implementa (mismo motivo por el que
/// `BlockState` lo escribe a mano). Se muestra el tamaño del log, que es lo
/// único diagnosticable acá.
impl core::fmt::Debug for RecordingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordingState")
            .field("accesos", &self.guard().len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct RecordingState {
    inner: Box<dyn State>,
    log: Arc<Mutex<AccessLog>>,
}

impl RecordingState {
    #[must_use]
    pub fn new(inner: Box<dyn State>) -> Self {
        Self {
            inner,
            log: Arc::new(Mutex::new(AccessLog::default())),
        }
    }

    /// Copia del log tal como está ahora.
    #[must_use]
    pub fn log(&self) -> AccessLog {
        self.guard().clone()
    }

    /// Un `Mutex` envenenado significa que otro hilo entró en pánico mientras
    /// grababa. El dato de adentro sigue siendo el log; propagar un pánico acá
    /// convertiría un bug ajeno en un fallo del grabador, así que se recupera
    /// el contenido en vez de desenrollar. (Sin `unwrap`: el lint del
    /// workspace lo trata como error.)
    fn guard(&self) -> MutexGuard<'_, AccessLog> {
        match self.log.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Cada método: delegar primero, grabar **solo el `Ok`**. Un `Err` del `State`
/// de abajo no es un dato del witness — es una base rota, y meterlo en el log
/// haría que el replay "reprodujera" el error como si fuera estado.
impl State for RecordingState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        let info = self.inner.account(addr)?;
        self.guard().accounts.insert(addr, info.clone());
        Ok(info)
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        let value = self.inner.storage(addr, key)?;
        self.guard().storage.insert((addr, key), value);
        Ok(value)
    }

    fn storage_root(&self, addr: Address) -> Result<B256, StateError> {
        let root = self.inner.storage_root(addr)?;
        self.guard().storage_roots.insert(addr, root);
        Ok(root)
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        let code = self.inner.code(code_hash)?;
        self.guard().code.insert(code_hash, code.clone());
        Ok(code)
    }

    fn code_metadata(&self, code_hash: B256) -> Result<CodeMetadata, StateError> {
        let meta = self.inner.code_metadata(code_hash)?;
        self.guard().code_metadata.insert(code_hash, meta.clone());
        Ok(meta)
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        let hash = self.inner.block_hash(number)?;
        self.guard().block_hashes.insert(number, hash);
        Ok(hash)
    }
}
