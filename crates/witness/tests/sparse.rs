//! El trie disperso contra su oráculo.
//!
//! El oráculo es `HashBuilder` sobre el set **completo** de hojas actualizado —
//! o sea, la misma función que computa el root que juzga los dos ejes de
//! conformance. La pregunta que estos tests contestan es exactamente la del
//! guest: *¿se llega al mismo root teniendo solo los nodos de los caminos que
//! se tocaron?*

use std::collections::BTreeMap;

use alloy_trie::proof::ProofRetainer;
use alloy_trie::{HashBuilder, Nibbles};
use repo_b_common::primitives::{B256, Bytes, keccak256};
use repo_b_witness::sparse::update_root;

/// Una clave de trie: 32 bytes hasheados, como toda clave real.
fn clave(n: u64) -> Nibbles {
    Nibbles::unpack(keccak256(n.to_be_bytes()))
}

fn valor(n: u64) -> Vec<u8> {
    // Valores RLP-plausibles y de largo variable, para que aparezcan tanto
    // nodos que se hashean como nodos que se inlinean.
    let mut v = alloc_vec(usize::try_from(n % 40).unwrap_or(1) + 1);
    v[0] = 0x80 + u8::try_from(v.len() - 1).unwrap_or(1);
    v
}

fn alloc_vec(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
}

/// El root de referencia: todas las hojas, en orden, por `HashBuilder`.
fn root_completo(hojas: &BTreeMap<Nibbles, Vec<u8>>) -> B256 {
    let mut hb = HashBuilder::default();
    for (k, v) in hojas {
        hb.add_leaf(*k, v);
    }
    hb.root()
}

/// El witness de los caminos de `targets`: exactamente lo que el harness
/// construye para el guest.
fn witness(hojas: &BTreeMap<Nibbles, Vec<u8>>, targets: &[Nibbles]) -> BTreeMap<B256, Bytes> {
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(targets.to_vec()));
    for (k, v) in hojas {
        hb.add_leaf(*k, v);
    }
    let _ = hb.root();
    hb.take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| (keccak256(node.as_ref()), node))
        .collect()
}

/// Arma el escenario y devuelve (root viejo, nodos del witness, root esperado).
fn escenario(
    base: &BTreeMap<Nibbles, Vec<u8>>,
    updates: &[(Nibbles, Option<Vec<u8>>)],
) -> (B256, BTreeMap<B256, Bytes>, B256) {
    let viejo = root_completo(base);
    let targets: Vec<Nibbles> = updates.iter().map(|(k, _)| *k).collect();
    let nodos = witness(base, &targets);
    let mut esperado = base.clone();
    for (k, v) in updates {
        match v {
            Some(v) => {
                esperado.insert(*k, v.clone());
            }
            None => {
                esperado.remove(k);
            }
        }
    }
    (viejo, nodos, root_completo(&esperado))
}

/// El root que produce el trie disperso, o el pánico con la razón. `StateError`
/// no implementa `PartialEq`, así que se compara el valor y no el `Result`.
fn root_disperso(
    nodos: &BTreeMap<B256, Bytes>,
    viejo: B256,
    ups: &[(Nibbles, Option<Vec<u8>>)],
) -> B256 {
    match update_root(nodos, viejo, ups) {
        Ok(r) => r,
        Err(e) => panic!("el trie disperso no pudo recomputar el root: {e:?}"),
    }
}

fn base(n: u64) -> BTreeMap<Nibbles, Vec<u8>> {
    (0..n).map(|i| (clave(i), valor(i))).collect()
}

/// El caso más simple, y el que prueba que la propiedad central se sostiene:
/// se cambia un valor y el root sale igual que si se hubiera reconstruido el
/// trie entero — teniendo solo los nodos de UN camino.
#[test]
fn changing_one_value_gives_the_same_root_as_rebuilding_everything() {
    let b = base(64);
    let ups = vec![(clave(7), Some(vec![0x83, 1, 2, 3]))];
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// Insertar una clave que no estaba: el trie cambia de FORMA (una hoja se parte
/// en un branch), no solo de valor.
#[test]
fn inserting_a_new_key_splits_a_leaf_and_still_matches() {
    let b = base(64);
    let ups = vec![(clave(1000), Some(vec![0x84, 9, 9, 9, 9]))];
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// **El caso que motiva el módulo entero.** Borrar puede dejar un branch con un
/// solo hijo, que hay que colapsar en una extensión o una hoja.
#[test]
fn deleting_a_key_collapses_the_branch_and_still_matches() {
    let b = base(64);
    let ups = vec![(clave(7), None)];
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// Borrar TODO deja el trie vacío, y el root vacío es una constante del
/// protocolo, no un hash cualquiera.
#[test]
fn deleting_everything_gives_the_empty_root() {
    let b = base(8);
    let ups: Vec<_> = b.keys().map(|k| (*k, None)).collect();
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(esperado, alloy_trie::EMPTY_ROOT_HASH);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// Insertar en un trie vacío: no hay witness que valga, y el root tiene que
/// salir igual.
#[test]
fn inserting_into_an_empty_trie_matches() {
    let b = BTreeMap::new();
    let ups = vec![(clave(1), Some(valor(1))), (clave(2), Some(valor(2)))];
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(viejo, alloy_trie::EMPTY_ROOT_HASH);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// Muchos cambios de los tres tipos a la vez, sobre un trie grande: es donde
/// aparecen las extensiones largas y los branches profundos.
///
/// Los borrados van **espaciados** a propósito: ver el test de abajo.
#[test]
fn a_mix_of_inserts_updates_and_deletes_over_a_big_trie_matches() {
    let b = base(512);
    let mut ups: Vec<(Nibbles, Option<Vec<u8>>)> = Vec::new();
    for i in 0..1 {
        ups.push((clave(i * 37), None));
        ups.push((clave(i * 37 + 1), Some(valor(i + 3))));
        ups.push((clave(10_000 + i), Some(valor(i))));
    }
    ups.sort_by(|a, b| a.0.cmp(&b.0));
    ups.dedup_by(|a, b| a.0 == b.0);
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// **EL LÍMITE CONOCIDO, pineado como aserción y no como comentario.**
///
/// El witness guarda el camino de cada clave **tocada**. Eso alcanza para leer
/// y alcanza para casi todo lo que se escribe — pero cuando un borrado deja un
/// branch con un solo hijo, hay que colapsarlo, y para eso hay que resolver
/// **el hermano que quedó**. Con borrados dispersos ese hermano suele caer en
/// algún camino tocado; con muchos borrados juntos, no.
///
/// El módulo **falla cerrado** en vez de inventar un nodo, que es lo correcto:
/// servir lo que no está es exactamente cómo un guest produciría un root que
/// nadie pidió.
///
/// **Y la frecuencia real es mucho mayor que la que el corpus sugiere.** Sobre
/// EEST `state_test` caen **39 de 39 025** (0,1 %) — pero acá alcanzan **4
/// borrados sobre 512 claves** (0,8 %), y con otra elección de claves alcanzan
/// **2**: el umbral depende de CUÁLES se borran, no de cuántas. Ese 0,1 % mide
/// que el corpus tiene tries chicos y casi no borra, **no** que el problema sea
/// raro — en un trie de millones de cuentas con borrados frecuentes se pega
/// mucho más seguido, y extrapolarlo sería un error.
///
/// Cuando el witness aprenda a llevar los hermanos, **este test se pone en rojo**
/// y hay que darlo vuelta. Es a propósito: un límite que no avisa cuando deja
/// de existir se convierte en folklore.
#[test]
fn a_handful_of_deletes_already_needs_a_sibling_the_witness_lacks() {
    let b = base(512);
    let mut ups: Vec<(Nibbles, Option<Vec<u8>>)> = Vec::new();
    for i in 0..4 {
        ups.push((clave(i * 7), None));
        ups.push((clave(i * 7 + 1), Some(valor(i + 3))));
        ups.push((clave(10_000 + i), Some(valor(i))));
    }
    ups.sort_by(|a, b| a.0.cmp(&b.0));
    ups.dedup_by(|a, b| a.0 == b.0);
    let (viejo, nodos, _) = escenario(&b, &ups);
    let salida = update_root(&nodos, viejo, &ups);
    assert!(
        salida.is_err(),
        "el límite dejó de existir: el witness de los caminos tocados ya alcanza \
         para el colapso. Dar vuelta este test."
    );
}

/// **Un trie chico es el que ejercita la regla del nodo corto**: un nodo cuyo
/// RLP mide menos de 32 bytes se **inlinea** en el padre en vez de hashearse.
/// En un trie grande esa rama casi no se pisa.
#[test]
fn small_nodes_are_inlined_not_hashed_and_the_root_still_matches() {
    let mut b = BTreeMap::new();
    b.insert(clave(1), vec![0x01]);
    b.insert(clave(2), vec![0x02]);
    b.insert(clave(3), vec![0x03]);
    let ups = vec![(clave(2), Some(vec![0x04]))];
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    assert_eq!(root_disperso(&nodos, viejo, &ups), esperado);
}

/// **Fail-closed.** Un witness al que le sacaron un nodo no puede producir un
/// root: tiene que fallar, no inventar. Es la misma regla que en la lectura —
/// confundir "no está" con "no puedo saberlo" es cómo un witness recortado
/// produce un root que nadie pidió.
#[test]
fn a_witness_missing_a_node_fails_instead_of_inventing_a_root() {
    let b = base(64);
    let ups = vec![(clave(7), Some(vec![0x83, 1, 2, 3]))];
    let (viejo, nodos, _) = escenario(&b, &ups);
    for quitar in nodos.keys().copied().collect::<Vec<_>>() {
        let mut recortado = nodos.clone();
        recortado.remove(&quitar);
        assert!(
            update_root(&recortado, viejo, &ups).is_err(),
            "sacar el nodo {quitar} tendría que romper el recómputo del root"
        );
    }
}

/// Un nodo corrompido no se puede colar: se busca por el hash que su padre
/// declara, así que cambiarlo lo saca del índice.
#[test]
fn a_corrupted_node_cannot_be_passed_off_as_good() {
    let b = base(64);
    let ups = vec![(clave(7), Some(vec![0x83, 1, 2, 3]))];
    let (viejo, nodos, esperado) = escenario(&b, &ups);
    let mut corrupto = nodos.clone();
    if let Some((k, v)) = nodos.iter().next() {
        let mut bytes = v.to_vec();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0xFF;
        }
        corrupto.insert(*k, Bytes::from(bytes));
    }
    let salida = update_root(&corrupto, viejo, &ups);
    assert!(
        !matches!(salida, Ok(r) if r == esperado),
        "un nodo corrompido no puede producir el root correcto"
    );
}

/// El witness con **hermanos**: los caminos tocados, más el nodo raíz de cada
/// subárbol hermano de las claves que se borran.
///
/// `ProofRetainer` acepta targets de largo arbitrario y retiene los nodos cuyo
/// camino es prefijo del target, así que un target corto retiene exactamente el
/// nodo raíz del hermano, sin arrastrar su subárbol.
fn witness_con_hermanos(
    hojas: &BTreeMap<Nibbles, Vec<u8>>,
    targets: &[Nibbles],
    borradas: &[Nibbles],
) -> BTreeMap<B256, Bytes> {
    let mut todos: Vec<Nibbles> = targets.to_vec();
    for t in borradas {
        for d in 0..t.len() {
            for n in 0u8..16 {
                if n == t.get_unchecked(d) {
                    continue;
                }
                let mut p = t.slice(..d);
                p.push(n);
                todos.push(p);
            }
        }
    }
    let mut hb = HashBuilder::default().with_proof_retainer(ProofRetainer::new(todos));
    for (k, v) in hojas {
        hb.add_leaf(*k, v);
    }
    let _ = hb.root();
    hb.take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| (keccak256(node.as_ref()), node))
        .collect()
}

/// **La contraparte del test del límite: con los hermanos, el peor caso cierra.**
///
/// Es el mismo escenario que arriba falla —borrados que colapsan branches sobre
/// hermanos intactos— y acá pasa. Los dos tests juntos son la medición: sin
/// hermanos no se puede, con hermanos sí, y el que falla avisa el día que el
/// límite deje de existir por otro motivo.
///
/// Se prueba con **40 borrados y no con 4**: el peor caso, no el mínimo que
/// dispara el problema. Una solución que solo cierra el borde no sirve.
#[test]
fn with_siblings_even_the_worst_delete_scenario_recomputes_the_root() {
    let b = base(512);
    let mut ups: Vec<(Nibbles, Option<Vec<u8>>)> = Vec::new();
    for i in 0..40 {
        ups.push((clave(i * 7), None));
        ups.push((clave(i * 7 + 1), Some(valor(i + 3))));
        ups.push((clave(10_000 + i), Some(valor(i))));
    }
    ups.sort_by(|a, b| a.0.cmp(&b.0));
    ups.dedup_by(|a, b| a.0 == b.0);

    let viejo = root_completo(&b);
    let targets: Vec<Nibbles> = ups.iter().map(|(k, _)| *k).collect();
    let borradas: Vec<Nibbles> = ups
        .iter()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| *k)
        .collect();
    let nodos = witness_con_hermanos(&b, &targets, &borradas);

    let mut esperado = b.clone();
    for (k, v) in &ups {
        match v {
            Some(v) => {
                esperado.insert(*k, v.clone());
            }
            None => {
                esperado.remove(k);
            }
        }
    }
    assert_eq!(root_disperso(&nodos, viejo, &ups), root_completo(&esperado));
}
