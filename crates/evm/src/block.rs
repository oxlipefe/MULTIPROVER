//! `BlockState` — el hilo de estado ENTRE txs del mismo bloque.
//!
//! El seam `Vm` abre el bloque con un `&dyn State` (`begin_block`) y después
//! ejecuta txs sin volver a recibirlo (`transact_in_block(tx, sender)`). O sea
//! que el motor tiene que llevar él mismo lo que las txs anteriores del bloque
//! ya cambiaron: una tx que lee una cuenta escrita por la tx de más arriba no
//! puede ver el estado pre-bloque.
//!
//! `BlockState` es exactamente eso: el `State` de arranque del bloque más un
//! overlay de `AccountUpdate` acumulados. Implementa `State`, así que cada tx
//! corre contra él **por el mismo camino de siempre** — el `Journal` no sabe ni
//! le importa que abajo haya un bloque.
//!
//! El overlay usa la MISMA semántica que el consumidor del diff
//! (`AccountUpdate`): `destroyed` borra la cuenta entera, un slot en cero la
//! saca del storage, y un campo `None` no toca nada. Dos definiciones distintas
//! de "aplicar el diff" divergirían.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{
    Address, B256, Bytes, EMPTY_ROOT_HASH, KECCAK256_EMPTY, U256, keccak256,
};

use crate::error::StateError;
use crate::result::StateChanges;
use crate::state::State;
use crate::types::{AccountInfo, CodeMetadata};

/// Lo que el bloque ya cambió de una cuenta. Un campo `None` = intacto respecto
/// del `State` de arranque.
#[derive(Debug, Clone, Default)]
struct BlockAccount {
    /// La cuenta fue BORRADA dentro del bloque (SELFDESTRUCT, drain de
    /// EIP-161). A partir de acá el `State` de arranque ya no dice nada de
    /// ella: ni balance, ni nonce, ni código, ni storage. Lo que venga después
    /// (una transferencia, una re-creación) se apila sobre la cuenta vacía.
    wiped: bool,
    balance: Option<U256>,
    nonce: Option<u64>,
    code: Option<Bytes>,
    /// Slots escritos en este bloque. Un valor cero = slot borrado.
    storage: BTreeMap<U256, U256>,
}

impl BlockAccount {
    /// ¿La entrada no dice nada más que "esta cuenta se borró"?
    fn is_bare_wipe(&self) -> bool {
        self.wiped
            && self.balance.is_none()
            && self.nonce.is_none()
            && self.code.is_none()
            && self.storage.is_empty()
    }
}

/// El `State` de arranque del bloque + lo que las txs ya corridas cambiaron.
pub struct BlockState {
    base: Box<dyn State>,
    overlay: BTreeMap<Address, BlockAccount>,
    /// Código depositado dentro del bloque, indexado por hash. El seam sirve
    /// bytecode POR HASH, y el `State` de arranque no conoce el de un contrato
    /// que se creó dos txs más arriba: sin esto, la segunda tx que llama a ese
    /// contrato recibe "código desconocido" y la tx entera muere fail-closed.
    code_by_hash: BTreeMap<B256, Bytes>,
}

/// `dyn State` no es `Debug` (el seam no lo pide). Se imprime la forma, no el
/// contenido: alcanza para un panic o un log, y no obliga a nada al seam.
impl core::fmt::Debug for BlockState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockState")
            .field("cuentas_tocadas", &self.overlay.len())
            .field("codigos_nuevos", &self.code_by_hash.len())
            .finish()
    }
}

impl Clone for BlockState {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
            overlay: self.overlay.clone(),
            code_by_hash: self.code_by_hash.clone(),
        }
    }
}

/// Cuenta inexistente, tal como la lee el motor.
const ABSENT: AccountInfo = AccountInfo {
    balance: U256::ZERO,
    nonce: 0,
    code_hash: KECCAK256_EMPTY,
};

impl BlockState {
    pub fn new(base: Box<dyn State>) -> Self {
        Self {
            base,
            overlay: BTreeMap::new(),
            code_by_hash: BTreeMap::new(),
        }
    }

    /// Acumula el diff de una tx (o de las withdrawals) sobre el overlay.
    pub fn apply(&mut self, changes: &[AccountUpdate]) {
        for update in changes {
            if update.destroyed {
                self.overlay.insert(
                    update.address,
                    BlockAccount {
                        wiped: true,
                        ..BlockAccount::default()
                    },
                );
                continue;
            }
            if let Some(code) = &update.code {
                self.code_by_hash.insert(keccak256(code), code.clone());
            }
            let entry = self.overlay.entry(update.address).or_default();
            if let Some(balance) = update.balance {
                entry.balance = Some(balance);
            }
            if let Some(nonce) = update.nonce {
                entry.nonce = Some(nonce);
            }
            if let Some(code) = &update.code {
                entry.code = Some(code.clone());
            }
            for (key, value) in &update.storage {
                entry.storage.insert(*key, *value);
            }
        }
    }

    /// El diff ACUMULADO del bloque entero, en la forma que consume el cliente.
    ///
    /// Una cuenta borrada y vuelta a escribir en el mismo bloque emite DOS
    /// updates en orden: primero el borrado, después el alta. Colapsarlos en
    /// uno solo perdería el borrado del storage viejo.
    pub fn into_changes(self) -> StateChanges {
        let mut changes = Vec::new();
        for (address, account) in self.overlay {
            if account.wiped {
                changes.push(AccountUpdate {
                    address,
                    destroyed: true,
                    ..AccountUpdate::default()
                });
                if account.is_bare_wipe() {
                    continue;
                }
            }
            changes.push(AccountUpdate {
                address,
                balance: account.balance,
                nonce: account.nonce,
                code: account.code,
                storage: account.storage,
                destroyed: false,
            });
        }
        changes
    }

    /// La cuenta tal como la ve el bloque: `base` (salvo que esté borrada) con
    /// los campos del overlay encima.
    fn resolved(&self, addr: Address) -> Result<(Option<AccountInfo>, AccountInfo), StateError> {
        let Some(entry) = self.overlay.get(&addr) else {
            let base = self.base.account(addr)?;
            let info = base.clone().unwrap_or(ABSENT);
            return Ok((base, info));
        };
        let base = if entry.wiped {
            None
        } else {
            self.base.account(addr)?
        };
        let mut info = base.clone().unwrap_or(ABSENT);
        if let Some(balance) = entry.balance {
            info.balance = balance;
        }
        if let Some(nonce) = entry.nonce {
            info.nonce = nonce;
        }
        if let Some(code) = &entry.code {
            info.code_hash = if code.is_empty() {
                KECCAK256_EMPTY
            } else {
                keccak256(code)
            };
        }
        Ok((base, info))
    }
}

impl State for BlockState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        let (base, info) = self.resolved(addr)?;
        // Una cuenta que no existía en el arranque (o que el bloque borró) y
        // que sigue leyéndose toda en cero NO existe: inventarla sería crear
        // una cuenta vacía en el trie, que es justo lo que EIP-161 prohíbe.
        if base.is_none() && info == ABSENT {
            return Ok(None);
        }
        Ok(Some(info))
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        let Some(entry) = self.overlay.get(&addr) else {
            return self.base.storage(addr, key);
        };
        if let Some(value) = entry.storage.get(&key) {
            return Ok(*value);
        }
        if entry.wiped {
            return Ok(U256::ZERO);
        }
        self.base.storage(addr, key)
    }

    /// **Precisión de PREDICADO, no de root.**
    ///
    /// El único consumidor de `storage_root` es la tercera condición de
    /// colisión de CREATE (EIP-7610), que solo pregunta `!= EMPTY_ROOT_HASH`.
    /// Computar el root real de un storage con slots del bloque encima exige un
    /// MPT, y el MPT no vive en el motor: vive en el cliente. Así que este
    /// overlay contesta el predicado exacto y no el hash:
    ///
    /// - storage demostrablemente vacío ⇒ `EMPTY_ROOT_HASH`;
    /// - storage demostrablemente no vacío ⇒ `NON_EMPTY_STORAGE`, un valor
    ///   cualquiera distinto del vacío;
    /// - sin cambios de storage en el bloque ⇒ el root real del `State` de
    ///   arranque, tal cual.
    ///
    /// **Desvío conocido**, de la misma familia que el que ya documenta
    /// `Journal::has_storage`: si el bloque puso en cero TODOS los slots de una
    /// cuenta que arrancó con storage, acá sigue dando "no vacío". Distinguirlo
    /// pide enumerar slots, que es exactamente lo que este seam evita.
    fn storage_root(&self, addr: Address) -> Result<B256, StateError> {
        let Some(entry) = self.overlay.get(&addr) else {
            return self.base.storage_root(addr);
        };
        if entry.storage.values().any(|value| !value.is_zero()) {
            return Ok(NON_EMPTY_STORAGE);
        }
        if entry.wiped {
            return Ok(EMPTY_ROOT_HASH);
        }
        self.base.storage_root(addr)
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        if let Some(code) = self.code_by_hash.get(&code_hash) {
            return Ok(code.clone());
        }
        self.base.code(code_hash)
    }

    fn code_metadata(&self, code_hash: B256) -> Result<CodeMetadata, StateError> {
        self.base.code_metadata(code_hash)
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        self.base.block_hash(number)
    }
}

/// Marcador de "esta cuenta tiene algún slot vivo". Ver `storage_root`: no es
/// un root de trie y no se compara contra ninguno — se compara SOLO contra
/// `EMPTY_ROOT_HASH`. Se elige un valor imposible como root real (todo `0xff`)
/// para que, si alguna vez alguien lo tratara como hash, el fallo sea ruidoso.
const NON_EMPTY_STORAGE: B256 = B256::new([0xff; 32]);
