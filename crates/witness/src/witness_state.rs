//! `WitnessState` — un `State` que no tiene base de datos: resuelve cada
//! lectura **caminando el trie** desde el pre-state root, con los nodos del
//! witness.
//!
//! **Por qué caminar y no `verify_proof`.** El witness es una bolsa plana de
//! nodos, sin decir cuál prueba qué. Caminar el trie desde el root da la
//! verificación gratis y más fuerte: cada nodo se busca **por el hash que su
//! padre declara**, así que un nodo corrompido simplemente no aparece bajo ese
//! hash. No hay forma de colar un valor sin romper la cadena de hashes hasta la
//! raíz.
//!
//! **Los tres casos, distinguidos:**
//!
//! - el camino llega a una hoja con la clave ⇒ **valor probado**;
//! - el camino muere dentro de un nodo presente ⇒ **ausencia probada** (la
//!   cuenta no existe, y el witness lo demuestra);
//! - falta un nodo del camino ⇒ **`Err`**. No es "no existe": es *no puedo
//!   saberlo*, y confundirlos es la forma de que un witness recortado produzca
//!   un root equivocado sin que nadie lo note.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use alloy_rlp::{Decodable, Header as RlpHeader};
use alloy_trie::nodes::TrieNode;
use alloy_trie::{EMPTY_ROOT_HASH, Nibbles, TrieAccount};
use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::error::StateError;
use repo_b_evm::result::StateChanges;
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, CodeMetadata};

use crate::sparse::Update;

/// Resultado de caminar el trie: el valor, o su ausencia probada.
type Resolved = Option<Vec<u8>>;

#[derive(Debug, Clone)]
pub struct WitnessState {
    /// Nodos indexados por su propio hash. La clave la calcula ESTE lado: un
    /// nodo corrompido entra bajo otro hash y deja de encontrarse.
    nodes: BTreeMap<B256, Bytes>,
    /// Bytecodes por `keccak(code)`, calculado acá por el mismo motivo.
    codes: BTreeMap<B256, Bytes>,
    state_root: B256,
    /// Hashes de la cadena de ancestros, **ya verificados**, del padre hacia
    /// atrás: `chain[i]` es el bloque `parent_number - i`.
    chain: Vec<B256>,
    parent_number: u64,
}

impl WitnessState {
    #[must_use]
    pub fn new(witness: &ExecutionWitness, state_root: B256) -> Self {
        let index = |items: &Vec<Bytes>| {
            items
                .iter()
                .map(|item| (keccak256(item.as_ref()), item.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        Self {
            nodes: index(&witness.state),
            codes: index(&witness.codes),
            state_root,
            chain: Vec::new(),
            parent_number: 0,
        }
    }

    /// Verifica la cadena de headers y la deja lista para servir `BLOCKHASH`.
    ///
    /// **El ancla es el `parent_hash` del bloque que se está ejecutando**, que
    /// el verificador conoce porque está en el header que le dieron a probar.
    /// A partir de ahí cada header tiene que hashear a lo que el anterior
    /// declara como padre: esa cadena es la prueba, y sin ella un hash suelto
    /// no se puede contrastar contra nada.
    ///
    /// **El número de bloque NO se lee de los headers.** Si la cadena encadena
    /// desde el ancla, el elemento `i` **es** el bloque `parent_number - i` —
    /// leer el campo `number` sería confiar en un dato del propio witness en
    /// vez de en la cadena que ya lo prueba.
    pub fn with_chain(
        mut self,
        witness: &ExecutionWitness,
        anchor: B256,
        parent_number: u64,
    ) -> Result<Self, StateError> {
        let mut esperado = anchor;
        for (i, raw) in witness.headers.iter().enumerate() {
            let hash = keccak256(raw.as_ref());
            if hash != esperado {
                return Err(StateError::Database(format!(
                    "la cadena de headers no encadena en la posición {i}: se esperaba {esperado}, \
                     el header hashea a {hash}"
                )));
            }
            self.chain.push(hash);
            esperado = parent_hash_of(raw.as_ref())?;
        }
        self.parent_number = parent_number;
        Ok(self)
    }

    /// Camina el trie de `root` siguiendo `path`.
    ///
    /// `Ok(Some(v))` = probado presente. `Ok(None)` = probado ausente.
    /// `Err` = el witness no alcanza para decidir.
    fn walk(&self, root: B256, path: &Nibbles) -> Result<Resolved, StateError> {
        if root == EMPTY_ROOT_HASH {
            // Trie vacío: la ausencia está probada por el root mismo.
            return Ok(None);
        }
        let mut raw = match self.nodes.get(&root) {
            Some(node) => node.clone(),
            None => return missing(&format!("nodo {root} del trie")),
        };
        let mut offset = 0usize;
        loop {
            let node = TrieNode::decode(&mut raw.as_ref())
                .map_err(|e| StateError::Database(format!("nodo de trie ilegible: {e}")))?;
            let next = match node {
                TrieNode::EmptyRoot => return Ok(None),
                TrieNode::Leaf(leaf) => {
                    let resto = path.slice(offset..);
                    // La hoja lleva el resto de la clave: si no coincide, lo
                    // que se buscaba no está — y el propio nodo lo prueba.
                    return Ok((leaf.key == resto).then_some(leaf.value));
                }
                TrieNode::Extension(ext) => {
                    let resto = path.slice(offset..);
                    if !resto.starts_with(&ext.key) {
                        return Ok(None);
                    }
                    offset = offset.saturating_add(ext.key.len());
                    ext.child
                }
                TrieNode::Branch(branch) => {
                    if offset >= path.len() {
                        // La clave se terminó en un branch: el valor viviría en
                        // el propio branch, y en el MPT de Ethereum eso no pasa
                        // con claves de largo fijo.
                        return Ok(None);
                    }
                    let nibble = path.get_unchecked(offset);
                    if !branch.state_mask.is_bit_set(nibble) {
                        return Ok(None);
                    }
                    // La stack solo trae los hijos presentes: el índice es
                    // cuántos bits hay encendidos antes de este nibble.
                    let index = (branch.state_mask.get() & ((1u16 << nibble) - 1)).count_ones();
                    let Some(child) = branch.stack.get(index as usize) else {
                        return missing("hijo de un branch declarado por la máscara");
                    };
                    offset = offset.saturating_add(1);
                    child.clone()
                }
            };
            // Un hijo puede venir por hash (se busca en el witness) o embebido
            // (los nodos de menos de 32 bytes viajan dentro del padre).
            raw = match next.as_hash() {
                Some(hash) => match self.nodes.get(&hash) {
                    Some(node) => node.clone(),
                    None => return missing(&format!("nodo {hash} del trie")),
                },
                None => Bytes::copy_from_slice(next.as_ref()),
            };
        }
    }

    fn trie_account(&self, addr: Address) -> Result<Option<TrieAccount>, StateError> {
        let path = Nibbles::unpack(keccak256(addr));
        let Some(raw) = self.walk(self.state_root, &path)? else {
            return Ok(None);
        };
        TrieAccount::decode(&mut raw.as_slice())
            .map(Some)
            .map_err(|e| StateError::Database(format!("cuenta ilegible en el witness: {e}")))
    }

    /// El **post-state root**, computado solo desde el witness.
    ///
    /// Es la afirmación que una prueba atesta: *ejecutar sobre el pre-root da
    /// este root*. Sin esto el guest ejecuta y no puede decir nada.
    ///
    /// **Nada sale de afuera del witness.** Los campos que un `AccountUpdate` no
    /// toca se leen de la hoja vieja —que ya vino probada contra el pre-root— y
    /// el `storage_root` nuevo de cada cuenta se recomputa con el mismo trie
    /// disperso, desde el viejo. Por eso el orden es storage primero y cuentas
    /// después: el root del storage entra en la hoja de la cuenta.
    ///
    /// # Errors
    /// `Err` si al witness le falta un nodo que hace falta para reconstruir —
    /// típicamente el hermano que queda cuando un borrado colapsa un branch.
    /// Fail-closed: nunca se completa un camino con un nodo inventado.
    pub fn post_state_root(&self, changes: &StateChanges) -> Result<B256, StateError> {
        let mut updates: Vec<Update> = Vec::new();
        for update in changes {
            let path = Nibbles::unpack(keccak256(update.address));
            if update.destroyed {
                updates.push((path, None));
                continue;
            }
            let vieja = self.trie_account(update.address)?;
            let storage_root = if update.storage.is_empty() {
                vieja.as_ref().map_or(EMPTY_ROOT_HASH, |a| a.storage_root)
            } else {
                let raiz = vieja.as_ref().map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
                let slots: Vec<Update> = update
                    .storage
                    .iter()
                    .map(|(key, value)| {
                        let p = Nibbles::unpack(keccak256(B256::from(key.to_be_bytes())));
                        // Un slot en cero no se guarda: se borra. Guardarlo
                        // como cero daría un trie distinto del canónico.
                        let v = (!value.is_zero()).then(|| alloy_rlp::encode(*value));
                        (p, v)
                    })
                    .collect();
                crate::sparse::update_root(&self.nodes, raiz, &slots)?
            };
            let cuenta = TrieAccount {
                nonce: update
                    .nonce
                    .unwrap_or_else(|| vieja.as_ref().map_or(0, |a| a.nonce)),
                balance: update
                    .balance
                    .unwrap_or_else(|| vieja.as_ref().map_or(U256::ZERO, |a| a.balance)),
                storage_root,
                code_hash: update.code.as_ref().map_or_else(
                    || vieja.as_ref().map_or(KECCAK256_EMPTY, |a| a.code_hash),
                    keccak256,
                ),
            };
            updates.push((path, Some(alloy_rlp::encode(cuenta))));
        }
        crate::sparse::update_root(&self.nodes, self.state_root, &updates)
    }
}

/// El `parent_hash` de un header RLP: es su **primer** campo, así que sale de
/// saltear el prefijo de lista y decodificar 32 bytes. No hace falta un decoder
/// de header completo — y no tenerlo evita que el guest cargue con una segunda
/// definición de qué campos tiene un header.
fn parent_hash_of(raw: &[u8]) -> Result<B256, StateError> {
    let mut cursor = raw;
    let header = RlpHeader::decode(&mut cursor)
        .map_err(|e| StateError::Database(format!("header ilegible en el witness: {e}")))?;
    if !header.list {
        return Err(StateError::Database(
            "el header del witness no es una lista RLP".into(),
        ));
    }
    B256::decode(&mut cursor)
        .map_err(|e| StateError::Database(format!("`parent_hash` ilegible en el witness: {e}")))
}

fn missing<T>(what: &str) -> Result<T, StateError> {
    Err(StateError::Database(format!(
        "el witness no alcanza: falta {what}"
    )))
}

impl State for WitnessState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        Ok(self.trie_account(addr)?.map(|acc| AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce,
            code_hash: acc.code_hash,
        }))
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        // El storage se verifica contra el `storage_root` de la cuenta, que a
        // su vez ya salió probado del trie de estado: la cadena llega hasta el
        // pre-state root sin cortarse.
        let Some(acc) = self.trie_account(addr)? else {
            return Ok(U256::ZERO);
        };
        let path = Nibbles::unpack(keccak256(B256::from(key.to_be_bytes())));
        let Some(raw) = self.walk(acc.storage_root, &path)? else {
            return Ok(U256::ZERO);
        };
        U256::decode(&mut raw.as_slice())
            .map_err(|e| StateError::Database(format!("slot ilegible en el witness: {e}")))
    }

    fn storage_root(&self, addr: Address) -> Result<B256, StateError> {
        Ok(self
            .trie_account(addr)?
            .map_or(EMPTY_ROOT_HASH, |acc| acc.storage_root))
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        if code_hash == KECCAK256_EMPTY {
            return Ok(Bytes::new());
        }
        // El índice está construido por `keccak` del propio bytecode, así que
        // encontrarlo bajo este hash ES la verificación.
        match self.codes.get(&code_hash) {
            Some(code) => Ok(code.clone()),
            None => missing(&format!("el bytecode {code_hash}")),
        }
    }

    fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
        Ok(CodeMetadata::Regular)
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        // Por POSICIÓN en la cadena ya verificada. Un número que caiga fuera de
        // lo que la cadena cubre es un witness incompleto, no un cero.
        let Some(distancia) = self.parent_number.checked_sub(number) else {
            return Err(StateError::Database(format!(
                "el bloque {number} no es un ancestro del que se está ejecutando"
            )));
        };
        match usize::try_from(distancia)
            .ok()
            .and_then(|i| self.chain.get(i))
        {
            Some(hash) => Ok(*hash),
            None => missing(&format!("la cadena de headers hasta el bloque {number}")),
        }
    }
}
