//! Seam `State` (vendoreado de zeth). Lo que el EVM le pide al mundo: MÍNIMO
//! (6 métodos) y estable. Cada método nuevo es deuda para el motor y el modo
//! stateless. El **witness-recorder** envuelve este trait (no el motor).

use alloc::boxed::Box;

use repo_b_common::primitives::{Address, B256, Bytes, U256};

use crate::error::StateError;
use crate::types::{AccountInfo, CodeMetadata};

pub trait State: DynCloneState + Send + Sync {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError>;
    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError>;
    /// Root del trie de storage de la cuenta; `EMPTY_ROOT_HASH` si no tiene
    /// storage o si la cuenta no existe.
    ///
    /// Es la ÚNICA forma de contestar "¿esta cuenta tiene algún slot?" sin
    /// enumerar slots — y enumerar no compila al guest: ahí no hay un trie que
    /// recorrer, hay un witness con los nodos que la ejecución pidió. El root
    /// ya viene en la hoja de la cuenta, así que responderlo no agrega ni un
    /// ítem de witness. Lo consume la tercera condición de colisión de CREATE
    /// (EIP-7610).
    ///
    /// Método aparte y no un campo de `AccountInfo`: así el root se materializa
    /// SOLO en el chokepoint del CREATE, en vez de en cada carga de cuenta —
    /// que para un `State` construido desde JSON significaría hashear el trie
    /// de storage de toda cuenta tocada.
    fn storage_root(&self, addr: Address) -> Result<B256, StateError>;
    fn code(&self, code_hash: B256) -> Result<Bytes, StateError>;
    fn code_metadata(&self, code_hash: B256) -> Result<CodeMetadata, StateError>;
    fn block_hash(&self, number: u64) -> Result<B256, StateError>;
}

/// Clonado de `Box<dyn State>` sin `dyn-clone` externo (mantiene `no_std` puro).
pub trait DynCloneState {
    fn clone_state(&self) -> Box<dyn State>;
}

impl<T: State + Clone + 'static> DynCloneState for T {
    fn clone_state(&self) -> Box<dyn State> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn State> {
    fn clone(&self) -> Self {
        self.clone_state()
    }
}
