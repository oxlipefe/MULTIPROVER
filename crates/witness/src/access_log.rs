//! `AccessLog` — lo que el motor le pidió al mundo a través del seam `State`.
//!
//! **No es un `ExecutionWitness`.** Un witness son los nodos de trie que
//! *prueban* estos datos contra un root; esto es la lista de lo que la
//! ejecución *tocó*. La conversión (nodos, cadena contigua de headers,
//! pruebas de exclusión) es el paso siguiente. Mantenerlos separados es lo
//! que permite medir la cobertura del grabador sin que un bug de MPT se
//! disfrace de cobertura incompleta, y al revés.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_evm::types::{AccountInfo, CodeMetadata};

/// Registro de accesos de una ejecución, por método del seam.
///
/// **La ausencia se graba.** `accounts` mapea a `Option<AccountInfo>`, no a
/// `AccountInfo`: "la cuenta no existe" es un dato que la ejecución obtuvo y
/// que el verificador no puede reconstruir después. Un log que solo anota los
/// hits no distingue *ausente-probado* de *no-lo-pedí*.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessLog {
    pub accounts: BTreeMap<Address, Option<AccountInfo>>,
    pub storage: BTreeMap<(Address, U256), U256>,
    pub storage_roots: BTreeMap<Address, B256>,
    pub code: BTreeMap<B256, Bytes>,
    pub code_metadata: BTreeMap<B256, CodeMetadata>,
    /// **Grabado por par número→hash, y eso todavía no alcanza.** Un
    /// verificador no puede aceptar un hash suelto: hace falta la cadena
    /// contigua de headers hacia atrás para encadenar `parent_hash` y probar
    /// que el hash no es arbitrario. Eso viene con el witness real; acá se graba el par
    /// y el hueco queda dicho en vez de tapado.
    pub block_hashes: BTreeMap<u64, B256>,
}

/// La identidad de UN ítem del log, sin su valor.
///
/// Existe para el test de minimalidad: quitar un ítem y re-ejecutar. Si la
/// ejecución sobrevive sin él, ese ítem sobraba — y "el witness captura
/// exactamente lo que la ejecución tocó" pasa de eslogan a aserción.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessItem {
    Account(Address),
    Storage(Address, U256),
    StorageRoot(Address),
    Code(B256),
    CodeMetadata(B256),
    BlockHash(u64),
}

impl AccessLog {
    /// Cantidad total de ítems grabados.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Todos los ítems, en orden determinista (los `BTreeMap` lo garantizan).
    #[must_use]
    pub fn items(&self) -> Vec<AccessItem> {
        let mut items = Vec::new();
        items.extend(self.accounts.keys().copied().map(AccessItem::Account));
        items.extend(
            self.storage
                .keys()
                .map(|(addr, key)| AccessItem::Storage(*addr, *key)),
        );
        items.extend(
            self.storage_roots
                .keys()
                .copied()
                .map(AccessItem::StorageRoot),
        );
        items.extend(self.code.keys().copied().map(AccessItem::Code));
        items.extend(
            self.code_metadata
                .keys()
                .copied()
                .map(AccessItem::CodeMetadata),
        );
        items.extend(self.block_hashes.keys().copied().map(AccessItem::BlockHash));
        items
    }

    /// Copia del log sin un ítem. No muta el original.
    #[must_use]
    pub fn without(&self, item: &AccessItem) -> Self {
        let mut out = self.clone();
        match item {
            AccessItem::Account(addr) => {
                out.accounts.remove(addr);
            }
            AccessItem::Storage(addr, key) => {
                out.storage.remove(&(*addr, *key));
            }
            AccessItem::StorageRoot(addr) => {
                out.storage_roots.remove(addr);
            }
            AccessItem::Code(hash) => {
                out.code.remove(hash);
            }
            AccessItem::CodeMetadata(hash) => {
                out.code_metadata.remove(hash);
            }
            AccessItem::BlockHash(number) => {
                out.block_hashes.remove(number);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 20])
    }

    fn log() -> AccessLog {
        let mut log = AccessLog::default();
        log.accounts.insert(addr(1), None);
        log.storage.insert((addr(1), U256::from(7)), U256::from(9));
        log.block_hashes.insert(4, B256::ZERO);
        log
    }

    /// La ausencia es un ítem como cualquier otro: si no contara, un witness
    /// podría omitir la prueba de exclusión sin que la minimalidad lo note.
    #[test]
    fn an_absent_account_is_an_item_of_the_log() {
        assert_eq!(log().len(), 3);
        assert!(log().items().contains(&AccessItem::Account(addr(1))));
    }

    #[test]
    fn without_removes_exactly_one_item_and_does_not_touch_the_original() {
        let original = log();
        let recortado = original.without(&AccessItem::Storage(addr(1), U256::from(7)));
        assert_eq!(recortado.len(), 2);
        assert_eq!(original.len(), 3, "`without` no puede mutar el original");
        assert!(recortado.storage.is_empty());
    }

    /// Quitar algo que no está no puede "achicar" el log por accidente.
    #[test]
    fn without_an_item_that_is_not_there_changes_nothing() {
        let original = log();
        assert_eq!(original.without(&AccessItem::Account(addr(2))), original);
    }

    /// El orden de los ítems no puede depender del orden de inserción: el log
    /// viaja al guest y dos ejecuciones iguales tienen que producir el mismo
    /// witness, byte a byte.
    #[test]
    fn the_item_order_is_deterministic_regardless_of_insertion_order() {
        let mut a = AccessLog::default();
        a.accounts.insert(addr(3), None);
        a.accounts.insert(addr(1), None);
        let mut b = AccessLog::default();
        b.accounts.insert(addr(1), None);
        b.accounts.insert(addr(3), None);
        assert_eq!(a.items(), b.items());
    }
}
