//! `ExecutionWitness` — los pre-images contra los que se ejecuta un bloque sin
//! base de datos.
//!
//! **La forma es la canónica**: cuatro listas de bytes (`state`, `codes`,
//! `keys`, `headers`), que es la del `ExecutionWitness` de
//! `alloy_rpc_types_debug` y la respuesta de `debug_executionWitness` — el
//! mismo wire format que usan zeth y RSP. No se toma la dependencia porque
//! arrastraría `std` y serde al guest, y el tipo son cuatro `Vec<Bytes>`.
//!
//! **`state` son NODOS de trie, no valores.** Ésa es toda la diferencia entre
//! un witness y una lista de accesos: un nodo se identifica por su propio hash,
//! así que un witness corrompido no puede hacerse pasar por bueno — la
//! ejecución que lo consume busca cada nodo por el hash que el padre declara.
//!
//! Vive en `common` (y no en `evm`) porque lo miran los dos lados del seam: el
//! motor lo referencia en su outcome y el backend de proving lo consume.

use alloc::vec::Vec;

use crate::primitives::Bytes;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionWitness {
    /// Nodos de trie (estado y storage juntos, como los devuelve el RPC).
    pub state: Vec<Bytes>,
    /// Bytecodes. Cada uno es su propia prueba: `keccak(code) == code_hash`.
    pub codes: Vec<Bytes>,
    /// Preimágenes de las claves hasheadas (direcciones y slots).
    pub keys: Vec<Bytes>,
    /// Headers de bloque en RLP, hacia atrás desde el padre. La **cadena
    /// contigua** es lo que permite probar un `BLOCKHASH`: un hash suelto no se
    /// puede verificar contra nada.
    pub headers: Vec<Bytes>,
}

impl ExecutionWitness {
    /// Bytes totales del witness. Es la métrica que va a importar cuando esto
    /// se pruebe: todo lo que entra acá se paga en cada bloque.
    #[must_use]
    pub fn size_in_bytes(&self) -> usize {
        let sum = |items: &Vec<Bytes>| items.iter().map(|item| item.as_ref().len()).sum::<usize>();
        sum(&self.state) + sum(&self.codes) + sum(&self.keys) + sum(&self.headers)
    }
}
