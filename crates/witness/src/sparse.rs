//! El trie **disperso**: el espejo de `WitnessState`, que en vez de leer
//! **escribe**.
//!
//! `WitnessState` camina el trie desde el pre-root y verifica cada lectura.
//! Esto hace el camino de vuelta: aplica los cambios a los caminos probados y
//! **re-hashea hacia arriba** hasta un root nuevo. Sin esto el guest ejecuta
//! pero no puede producir la afirmación que una prueba atesta — *"ejecutar B
//! sobre el pre-root R da el post-root R'"* — y entonces no hay nada que probar.
//!
//! **La propiedad que lo hace posible:** un subárbol que nadie tocó no cambia,
//! así que su hash tampoco. Por eso la recursión, cuando se queda sin
//! actualizaciones para un subárbol, **devuelve la referencia tal cual y no lo
//! resuelve** — es lo que permite recomputar el root sin tener el trie entero.
//! Y es también por qué el witness alcanza: solo hacen falta los nodos de los
//! caminos que se tocaron.
//!
//! **Dónde eso deja de ser cierto, y es la trampa del módulo.** Borrar puede
//! cambiar la FORMA del trie: cuando un branch se queda con un solo hijo, hay
//! que **colapsarlo** en una extensión o una hoja, y para eso hay que resolver
//! **el hermano que quedó** — que puede no estar en ningún camino tocado. Ahí
//! el witness que alcanzaba para leer no alcanza para escribir, y este módulo
//! **falla cerrado** en vez de inventar. Servir un nodo que no está es
//! exactamente cómo un guest produciría un root que nadie pidió.
//!
//! **Todas las claves miden 64 nibbles** (son `keccak256` de 32 bytes), lo que
//! elimina de raíz varios casos del MPT general: ninguna clave es prefijo de
//! otra, y ningún branch lleva valor propio.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use alloy_rlp::Decodable;
use alloy_trie::nodes::{BranchNode, ExtensionNode, LeafNode, RlpNode, TrieNode};
use alloy_trie::{EMPTY_ROOT_HASH, Nibbles, TrieMask};
use repo_b_common::primitives::{B256, Bytes, keccak256};
use repo_b_evm::error::StateError;

/// Una actualización: el camino completo (64 nibbles) y el valor RLP nuevo, o
/// `None` para borrar.
pub type Update = (Nibbles, Option<Vec<u8>>);

/// Lo que la recursión devuelve para un subárbol.
///
/// La distinción entre `Ref` y `Node` no es cosmética: `Ref` es un subárbol que
/// **no se resolvió** —y puede no estar en el witness—, mientras que `Node` es
/// uno que se reconstruyó y del que se conoce la forma. Colapsar un branch
/// necesita la forma, así que solo se puede hacer sobre un `Node` o sobre un
/// `Ref` que se pueda resolver.
/// **La distinción no es cosmética y su ausencia costó 27 casos.**
///
/// `Ref` es una referencia a un nodo **del trie original**: se resuelve
/// buscándola en el witness. `Node` es un nodo que **esta ejecución construyó**
/// —al partir una extensión, por ejemplo— y que por definición **no está en el
/// witness**: buscarlo ahí es pedir un nodo que nunca existió.
///
/// Mezclar los dos y tratarlos como referencias resolubles es exactamente el
/// bug que hacía fallar el recómputo con un mensaje que parecía decir que al
/// witness le faltaba algo.
enum Built {
    /// El subárbol quedó vacío.
    Empty,
    /// Intacto: se devuelve su referencia sin haberlo mirado.
    Ref(RlpNode),
    /// Reconstruido: se conoce su forma.
    Node(TrieNode),
}

impl Built {
    fn into_ref(self) -> Option<RlpNode> {
        match self {
            Self::Empty => None,
            Self::Ref(r) => Some(r),
            Self::Node(n) => Some(rlp_of(&n)),
        }
    }
}

fn rlp_of(node: &TrieNode) -> RlpNode {
    let mut buf = Vec::new();
    node.rlp(&mut buf)
}

/// Aplica `updates` al trie de `root` y devuelve el root nuevo.
///
/// `nodes` es la bolsa del witness, indexada por el hash que **este lado**
/// calcula: un nodo corrompido entra bajo otro hash y deja de encontrarse, así
/// que la verificación es estructural igual que en la lectura.
///
/// # Errors
/// `Err` si el witness no tiene un nodo que hace falta resolver, o si un nodo
/// es ilegible. **Nunca** se completa un camino con un nodo inventado.
pub fn update_root(
    nodes: &BTreeMap<B256, Bytes>,
    root: B256,
    updates: &[Update],
) -> Result<B256, StateError> {
    let trie = Sparse { nodes };
    let raiz = if root == EMPTY_ROOT_HASH {
        Built::Empty
    } else {
        Built::Ref(RlpNode::word_rlp(&root))
    };
    // Orden determinista y agrupable por nibble: la recursión asume que las
    // actualizaciones de un subárbol vienen juntas.
    let mut ordenadas: Vec<Update> = updates.to_vec();
    ordenadas.sort_by(|a, b| a.0.cmp(&b.0));

    match trie.build(raiz, 0, &ordenadas)? {
        Built::Empty => Ok(EMPTY_ROOT_HASH),
        Built::Ref(r) => match r.as_hash() {
            Some(h) => Ok(h),
            // Un root de menos de 32 bytes no se inlinea en nadie: se hashea.
            None => Ok(keccak256(r.as_ref())),
        },
        Built::Node(n) => {
            let mut buf = Vec::new();
            alloy_rlp::Encodable::encode(&n, &mut buf);
            Ok(keccak256(&buf))
        }
    }
}

struct Sparse<'a> {
    nodes: &'a BTreeMap<B256, Bytes>,
}

impl Sparse<'_> {
    /// Resuelve una referencia a su nodo. Un hijo puede venir por hash (se
    /// busca en el witness) o embebido (los nodos de menos de 32 bytes viajan
    /// dentro del padre).
    /// `depth` va en el mensaje de error a propósito: cuando el witness no
    /// alcanza, saber a qué altura del trie se cortó es la diferencia entre un
    /// diagnóstico y una adivinanza.
    fn resolve_at(&self, r: &RlpNode, depth: usize) -> Result<TrieNode, StateError> {
        let raw = match r.as_hash() {
            Some(hash) => match self.nodes.get(&hash) {
                Some(node) => node.clone(),
                None => {
                    return Err(StateError::Database(format!(
                        "el witness no tiene el nodo {hash} (profundidad {depth}), y hace falta para recomputar el root"
                    )));
                }
            },
            None => Bytes::copy_from_slice(r.as_ref()),
        };
        TrieNode::decode(&mut raw.as_ref())
            .map_err(|e| StateError::Database(format!("nodo de trie ilegible: {e}")))
    }

    /// El corazón: reconstruye el subárbol colgado de `child` a profundidad
    /// `depth`, aplicándole `ups`.
    fn build(&self, child: Built, depth: usize, ups: &[Update]) -> Result<Built, StateError> {
        // **Sin actualizaciones, el subárbol no cambia y NO se resuelve.** Es la
        // propiedad que hace que un witness de los caminos tocados alcance.
        if ups.is_empty() {
            return Ok(child);
        }
        let nodo = match child {
            // Subárbol vacío: solo las inserciones tienen efecto.
            Built::Empty => return self.subtree_of(depth, &entries_of(ups)),
            // Del trie original: se busca en el witness.
            Built::Ref(r) => self.resolve_at(&r, depth)?,
            // Construido acá: ya está materializado, y buscarlo en el witness
            // sería pedir un nodo que nunca existió.
            Built::Node(n) => n,
        };

        match nodo {
            TrieNode::EmptyRoot => self.subtree_of(depth, &entries_of(ups)),
            // Una hoja es un subárbol completamente conocido: se aplana a su
            // entrada y se reconstruye junto con lo nuevo. No hace falta un
            // caso especial por cada forma de conflicto.
            TrieNode::Leaf(l) => {
                let camino = ups[0].0.slice(..depth).join(&l.key);
                let mut entradas = entries_of(ups);
                if !ups.iter().any(|(p, _)| *p == camino) {
                    entradas.push((camino, l.value.clone()));
                    entradas.sort_by(|a, b| a.0.cmp(&b.0));
                }
                self.subtree_of(depth, &entradas)
            }
            TrieNode::Extension(e) => self.build_extension(depth, &e, ups),
            TrieNode::Branch(b) => self.build_branch(depth, &b, ups),
        }
    }

    fn build_extension(
        &self,
        depth: usize,
        e: &ExtensionNode,
        ups: &[Update],
    ) -> Result<Built, StateError> {
        let fin = depth.saturating_add(e.key.len());
        let comparte = |p: &Nibbles| p.len() >= fin && p.slice(depth..fin) == e.key;

        if ups.iter().all(|(p, _)| comparte(p)) {
            // Todo cae adentro del hijo: solo se recursa y se vuelve a armar.
            let nuevo = self.build(Built::Ref(e.child.clone()), fin, ups)?;
            return Ok(self.prepend(&e.key, nuevo));
        }

        // Algo se desvía: la extensión se parte en un branch. La parte vieja
        // baja un nivel, y para eso NO hace falta resolver a su hijo: alcanza
        // con acortarle la clave (o, si medía un nibble, poner al hijo directo).
        let nibble_viejo = e.key.get_unchecked(0);
        let resto = e.key.slice(1..);
        // El lado viejo baja un nivel. Si medía un nibble, su hijo pasa directo
        // (y sigue siendo una referencia del trie original); si no, queda una
        // extensión más corta, que es un nodo **construido acá** y por eso viaja
        // como `Node` y no como referencia.
        let viejo = if resto.is_empty() {
            Built::Ref(e.child.clone())
        } else {
            Built::Node(TrieNode::Extension(ExtensionNode::new(
                resto,
                e.child.clone(),
            )))
        };
        self.branch_from(depth, Some((nibble_viejo, viejo)), ups)
    }

    fn build_branch(
        &self,
        depth: usize,
        b: &BranchNode,
        ups: &[Update],
    ) -> Result<Built, StateError> {
        let mut hijos: [Built; 16] = core::array::from_fn(|_| Built::Empty);
        let mut i = 0usize;
        for nibble in 0u8..16 {
            if b.state_mask.is_bit_set(nibble) {
                let Some(c) = b.stack.get(i) else {
                    return Err(StateError::Database(
                        "un branch declara un hijo que su stack no tiene".into(),
                    ));
                };
                hijos[nibble as usize] = Built::Ref(c.clone());
                i = i.saturating_add(1);
            }
        }
        self.assemble(depth, hijos, ups)
    }

    /// Un branch nuevo con, opcionalmente, un hijo preexistente en un nibble.
    fn branch_from(
        &self,
        depth: usize,
        preexistente: Option<(u8, Built)>,
        ups: &[Update],
    ) -> Result<Built, StateError> {
        let mut hijos: [Built; 16] = core::array::from_fn(|_| Built::Empty);
        if let Some((nibble, b)) = preexistente {
            hijos[nibble as usize] = b;
        }
        self.assemble(depth, hijos, ups)
    }

    /// Recursa en los 16 hijos, y decide la forma del resultado.
    fn assemble(
        &self,
        depth: usize,
        hijos: [Built; 16],
        ups: &[Update],
    ) -> Result<Built, StateError> {
        let mut construidos: Vec<(u8, Built)> = Vec::new();
        for (nibble, hijo) in hijos.into_iter().enumerate() {
            let n = u8::try_from(nibble).unwrap_or(0);
            let propios: Vec<Update> = ups
                .iter()
                .filter(|(p, _)| p.len() > depth && p.get_unchecked(depth) == n)
                .cloned()
                .collect();
            let nuevo = self.build(hijo, depth.saturating_add(1), &propios)?;
            if !matches!(nuevo, Built::Empty) {
                construidos.push((n, nuevo));
            }
        }

        match construidos.len() {
            0 => Ok(Built::Empty),
            // **El colapso.** Un branch con un solo hijo no existe en el MPT:
            // se funde con él. Acá es donde un witness que alcanzaba para leer
            // puede no alcanzar para escribir — si el hermano que quedó no se
            // tocó, hay que resolverlo igual.
            1 => {
                let (nibble, unico) = construidos.remove_first();
                let mut key = Nibbles::from_nibbles([nibble]);
                let nodo = match unico {
                    Built::Empty => return Ok(Built::Empty),
                    Built::Node(n) => n,
                    Built::Ref(r) => self.resolve_at(&r, depth)?,
                };
                Ok(Built::Node(match nodo {
                    TrieNode::Leaf(l) => {
                        key.extend(&l.key);
                        TrieNode::Leaf(LeafNode::new(key, l.value))
                    }
                    TrieNode::Extension(e) => {
                        key.extend(&e.key);
                        TrieNode::Extension(ExtensionNode::new(key, e.child))
                    }
                    otro => TrieNode::Extension(ExtensionNode::new(key, rlp_of(&otro))),
                }))
            }
            _ => {
                let mut mask = TrieMask::default();
                let mut stack = Vec::new();
                for (nibble, b) in construidos {
                    if let Some(r) = b.into_ref() {
                        mask.set_bit(nibble);
                        stack.push(r);
                    }
                }
                Ok(Built::Node(TrieNode::Branch(BranchNode::new(stack, mask))))
            }
        }
    }

    /// Construye un subárbol desde cero a partir de entradas completas.
    fn subtree_of(
        &self,
        depth: usize,
        entradas: &[(Nibbles, Vec<u8>)],
    ) -> Result<Built, StateError> {
        match entradas.len() {
            0 => Ok(Built::Empty),
            1 => {
                let (camino, valor) = &entradas[0];
                Ok(Built::Node(TrieNode::Leaf(LeafNode::new(
                    camino.slice(depth..),
                    valor.clone(),
                ))))
            }
            _ => {
                // Todas las claves miden lo mismo, así que dos entradas
                // distintas divergen en algún nibble: hay branch, no hoja.
                let ups: Vec<Update> = entradas
                    .iter()
                    .map(|(p, v)| (*p, Some(v.clone())))
                    .collect();
                self.branch_from(depth, None, &ups)
            }
        }
    }

    /// Le antepone `key` a un subárbol: extensión nueva, o fusión si el
    /// subárbol ya empieza con una.
    fn prepend(&self, key: &Nibbles, sub: Built) -> Built {
        match sub {
            Built::Empty => Built::Empty,
            Built::Ref(r) => Built::Node(TrieNode::Extension(ExtensionNode::new(*key, r))),
            Built::Node(n) => Built::Node(match n {
                // Dos extensiones seguidas no existen: se funden.
                TrieNode::Extension(e) => {
                    TrieNode::Extension(ExtensionNode::new(key.join(&e.key), e.child))
                }
                // Ídem una extensión sobre una hoja.
                TrieNode::Leaf(l) => TrieNode::Leaf(LeafNode::new(key.join(&l.key), l.value)),
                otro => TrieNode::Extension(ExtensionNode::new(*key, rlp_of(&otro))),
            }),
        }
    }
}

/// Las entradas que las actualizaciones dejan (las que borran no dejan nada).
fn entries_of(ups: &[Update]) -> Vec<(Nibbles, Vec<u8>)> {
    ups.iter()
        .filter_map(|(p, v)| v.as_ref().map(|v| (*p, v.clone())))
        .collect()
}

/// `Vec::remove(0)` sin el panic implícito.
trait RemoveFirst<T> {
    fn remove_first(&mut self) -> T;
}

impl RemoveFirst<(u8, Built)> for Vec<(u8, Built)> {
    fn remove_first(&mut self) -> (u8, Built) {
        if self.is_empty() {
            return (0, Built::Empty);
        }
        self.remove(0)
    }
}
