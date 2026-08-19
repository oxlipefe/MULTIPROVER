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

/// Construye el witness de lo que el log dice que se tocó.
#[must_use]
pub fn build(pre: &BTreeMap<Address, FixtureAccount>, log: &AccessLog) -> ExecutionWitness {
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

    let targets: Vec<Nibbles> = touched
        .iter()
        .map(|addr| Nibbles::unpack(keccak256(addr)))
        .collect();
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
        let targets = slots
            .iter()
            .map(|key| Nibbles::unpack(keccak256(B256::from(key.to_be_bytes()))))
            .collect();
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
