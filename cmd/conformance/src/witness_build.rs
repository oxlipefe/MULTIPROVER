//! Del log de accesos al witness: el lado que **arma** los pre-images.
//!
//! Vive en el harness y no en el crate del guest porque necesita el estado
//! COMPLETO para construir los tries — y tener el estado completo es
//! exactamente lo que el guest no tiene. Mismo criterio que puso el encoding de
//! bloque de este lado.
//!
//! Lo que se retiene es el **camino** de cada clave accedida, incluidas las que
//! no existen: el camino de una clave ausente es su prueba de exclusión, y sin
//! él el consumidor no puede distinguir "no está" de "no me lo mandaron".

use std::collections::{BTreeMap, BTreeSet};

use alloy_rlp::Encodable;
use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles, TrieAccount};
use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{Address, B256, Bytes, U256, keccak256};
use repo_b_common::witness::ExecutionWitness;
use repo_b_witness::AccessLog;

use crate::fixture::FixtureAccount;
use crate::runner::storage_root_of;

/// Nodos del camino de cada `target` dentro del trie descrito por `leaves`.
///
/// `leaves` viene en orden de clave **hasheada**, que es el orden en que el
/// `HashBuilder` las exige; ordenarlas mal no da error, da un root distinto.
fn proof_nodes(leaves: &[(Nibbles, Vec<u8>)], targets: Vec<Nibbles>) -> (B256, Vec<Bytes>) {
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets));
    for (key, value) in leaves {
        builder.add_leaf(*key, value);
    }
    let root = builder.root();
    let nodes = builder
        .take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| node)
        .collect();
    (root, nodes)
}

/// Los caminos de los **hermanos** de `key`: por cada nivel, el prefijo con
/// cada uno de los otros quince nibbles.
///
/// `ProofRetainer` acepta targets de largo arbitrario y retiene los nodos cuyo
/// camino es prefijo del target, así que un target corto retiene exactamente el
/// nodo **raíz** del subárbol hermano — que es todo lo que el colapso necesita,
/// sin arrastrar el subárbol entero.
///
/// **Se piden de todos los niveles y no solo del más profundo** porque un
/// colapso puede encadenarse: fundir un branch con su único hijo puede dejar al
/// PADRE con un solo hijo, y así hacia arriba.
fn hermanos(key: &Nibbles) -> Vec<Nibbles> {
    let mut out = Vec::new();
    for d in 0..key.len() {
        let propio = key.get_unchecked(d);
        for n in 0u8..16 {
            if n == propio {
                continue;
            }
            let mut p = key.slice(..d);
            p.push(n);
            out.push(p);
        }
    }
    out
}

fn account_leaf(account: &FixtureAccount) -> Vec<u8> {
    let mut out = Vec::new();
    TrieAccount {
        nonce: account.nonce,
        balance: account.balance,
        storage_root: storage_root_of(&account.storage),
        code_hash: keccak256(&account.code),
    }
    .encode(&mut out);
    out
}

fn storage_leaves(account: &FixtureAccount) -> Vec<(Nibbles, Vec<u8>)> {
    let mut leaves: Vec<(Nibbles, Vec<u8>)> = account
        .storage
        .iter()
        .filter(|(_, value)| !value.is_zero())
        .map(|(key, value)| {
            let mut out = Vec::new();
            value.encode(&mut out);
            (
                Nibbles::unpack(keccak256(B256::from(key.to_be_bytes()))),
                out,
            )
        })
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    leaves
}

/// Igual que `build`, más la **cadena contigua de headers** que el bloque
/// necesita para probar sus `BLOCKHASH`.
///
/// La cadena va del padre hacia atrás **sin huecos** hasta el ancestro más
/// lejano que la ejecución pidió: es lo que permite encadenar `parent_hash` y
/// probar que un hash no es arbitrario. Grabar solo los números pedidos no
/// alcanzaría — un hash suelto no se contrasta contra nada.
#[must_use]
pub fn build_block(
    pre: &BTreeMap<Address, FixtureAccount>,
    log: &AccessLog,
    chain: &BTreeMap<u64, Bytes>,
    number: u64,
) -> ExecutionWitness {
    let mut witness = build(pre, log);
    let Some(mas_viejo) = log.block_hashes.keys().min().copied() else {
        return witness;
    };
    let padre = number.saturating_sub(1);
    // Del padre hacia atrás. Un eslabón que falte deja la cadena corta y el
    // consumidor lo va a rechazar: no se rellena con nada.
    witness.headers = (mas_viejo..=padre)
        .rev()
        .map_while(|n| chain.get(&n).cloned())
        .collect();
    witness
}

/// Construye el witness de lo que el log dice que se tocó.
/// Las claves cuyo cambio altera la **forma** del trie, que son las únicas que
/// necesitan hermanos.
///
/// **Son DOS causas, no una**, y confundirlas cuesta casos:
///
/// - **Borrar** puede dejar un branch con un solo hijo, y colapsarlo exige
///   resolver el hermano que quedó.
/// - **Insertar** una clave que no existía puede caer dentro de un subárbol
///   **intacto** y obligar a **partirlo** — y para partir un nodo hay que
///   tenerlo. Su proof de exclusión alcanzó para *leer* (el camino muere en un
///   branch), pero no para *escribir*.
///
/// Un cambio de valor sobre una clave que ya existía **no** altera la forma, y
/// por eso no paga hermanos.
#[derive(Debug, Default, Clone)]
pub struct ShapeChanges {
    pub accounts: BTreeSet<Address>,
    pub slots: BTreeSet<(Address, U256)>,
}

impl ShapeChanges {
    /// Se leen del diff **contra el pre-state**, que se conoce porque el witness
    /// se arma después de ejecutar — igual que en un cliente real, que ejecuta y
    /// después publica.
    #[must_use]
    pub fn of(changes: &[AccountUpdate], pre: &BTreeMap<Address, FixtureAccount>) -> Self {
        let mut out = Self::default();
        for update in changes {
            let vieja = pre.get(&update.address);
            // Borrada, o nueva.
            if update.destroyed {
                out.accounts.insert(update.address);
            }
            for (key, value) in &update.storage {
                let antes = vieja.and_then(|a| a.storage.get(key)).copied();
                let existia = antes.is_some_and(|v| !v.is_zero());
                // Un slot que se vacía (colapso) o uno que nace (partición).
                let _ = existia;
                if value.is_zero() {
                    out.slots.insert((update.address, *key));
                }
            }
        }
        out
    }
}

#[must_use]
pub fn build(pre: &BTreeMap<Address, FixtureAccount>, log: &AccessLog) -> ExecutionWitness {
    build_with(pre, log, &ShapeChanges::default())
}

/// Igual que `build`, más los **hermanos** que el colapso de un borrado
/// necesita.
///
/// **Dirigidos y no a lo bruto, y la diferencia está medida.** Pedir hermanos
/// para toda clave tocada cierra los casos y casi **duplica** el witness
/// (medido: 188 → 457 nodos, +87 % de bytes). Un cambio de valor no cambia la
/// forma del trie, así que pagar por él es pagar de más en cada bloque — y el
/// costo del witness es lo que se paga en cada prueba.
#[must_use]
pub fn build_with(
    pre: &BTreeMap<Address, FixtureAccount>,
    log: &AccessLog,
    shape: &ShapeChanges,
) -> ExecutionWitness {
    let mut leaves: Vec<(Nibbles, Vec<u8>)> = pre
        .iter()
        .map(|(addr, account)| (Nibbles::unpack(keccak256(addr)), account_leaf(account)))
        .collect();
    leaves.sort_by(|a, b| a.0.cmp(&b.0));

    // Las direcciones tocadas incluyen las que NO existen: su camino es la
    // prueba de exclusión.
    let mut touched: BTreeSet<Address> = log.accounts.keys().copied().collect();
    touched.extend(log.storage.keys().map(|(addr, _)| *addr));
    touched.extend(log.storage_roots.keys().copied());

    let mut targets: Vec<Nibbles> = touched
        .iter()
        .map(|addr| Nibbles::unpack(keccak256(addr)))
        .collect();
    for addr in &shape.accounts {
        targets.extend(hermanos(&Nibbles::unpack(keccak256(addr))));
    }
    let (_, mut nodes) = proof_nodes(&leaves, targets);

    // Un trie de storage por cuenta con slots accedidos. Una cuenta cuyo
    // storage no se tocó no aporta nodos: podado no es incompleto.
    let mut slots_by_account: BTreeMap<Address, Vec<U256>> = BTreeMap::new();
    for (addr, key) in log.storage.keys() {
        slots_by_account.entry(*addr).or_default().push(*key);
    }
    for (addr, slots) in &slots_by_account {
        let Some(account) = pre.get(addr) else {
            continue;
        };
        let mut targets: Vec<Nibbles> = slots
            .iter()
            .map(|key| Nibbles::unpack(keccak256(B256::from(key.to_be_bytes()))))
            .collect();
        for (owner, key) in &shape.slots {
            if owner == addr {
                targets.extend(hermanos(&Nibbles::unpack(keccak256(B256::from(
                    key.to_be_bytes(),
                )))));
            }
        }
        let (_, storage_nodes) = proof_nodes(&storage_leaves(account), targets);
        nodes.extend(storage_nodes);
    }

    // Dedup determinista: dos caminos comparten los nodos de arriba.
    let unique: BTreeMap<B256, Bytes> = nodes
        .into_iter()
        .map(|node| (keccak256(node.as_ref()), node))
        .collect();

    ExecutionWitness {
        state: unique.into_values().collect(),
        codes: log.code.values().cloned().collect(),
        keys: touched
            .iter()
            .map(|addr| Bytes::copy_from_slice(addr.as_slice()))
            .chain(
                log.storage
                    .keys()
                    .map(|(_, key)| Bytes::from(key.to_be_bytes::<32>().to_vec())),
            )
            .collect(),
        headers: Vec::new(),
    }
}
