//! El provider criptográfico activo, y la referencia nativa.
//!
//! El trait `Crypto` vive en `repo-b-common` porque lo consumen **dos** crates
//! —este motor y `repo-b-guest`, donde se derivan los senders de las tx—; acá
//! vive la implementación, que es donde ya estaban las dependencias.
//!
//! # Cómo se elige el provider
//!
//! Por feature de Cargo, resuelto en compilación: el tipo `Active` es un alias,
//! así que el despacho es estático y el guest no paga una vtable. **Fail-closed
//! por construcción**: cero providers o dos a la vez no compilan, con un mensaje
//! propio para cada caso. Un default silencioso sería la forma exacta del bug
//! que este repo ya evitó en otro seam con un `Option` en vez de un default.
//!
//! Los providers de backend entran como features nuevas, con su
//! `[patch.crates-io]` o sus bindings viviendo en **su** crate y nunca acá.
//!
//! # Por qué NO hay un provider por default
//!
//! Las features de Cargo son **aditivas**: si un provider viniera prendido por
//! default, cualquier camino del grafo de dependencias que traiga este crate
//! con defaults lo volvería a encender, y "exactamente uno" dejaría de ser
//! enforzable — quedarían dos activos y ganaría el que el `cfg` mirara
//! primero. Por eso cada consumidor **nombra** el suyo. Es la misma decisión
//! que en otro seam de este repo llevó a un `Option` en vez de un default: un
//! default silencioso es la forma exacta del bug que estos gates existen para
//! hacer imposible.

#[cfg(feature = "crypto-openvm")]
pub mod openvm;
pub mod reference;

#[cfg(all(feature = "crypto-reference", not(feature = "crypto-openvm")))]
pub use reference::Reference as Active;

#[cfg(all(feature = "crypto-openvm", not(feature = "crypto-reference")))]
pub use openvm::OpenVm as Active;

#[cfg(all(feature = "crypto-reference", feature = "crypto-openvm"))]
compile_error!(
    "hay DOS providers criptográficos activos a la vez (`crypto-reference` y \
     `crypto-openvm`): tiene que haber exactamente uno. Dos matemáticas \
     creyéndose ambas la activa en un motor de consenso es peor que ninguna, y \
     con features aditivas esto es el resultado NORMAL de un `default-features \
     = true` olvidado en algún punto del grafo, no un caso raro."
);

#[cfg(not(any(feature = "crypto-reference", feature = "crypto-openvm")))]
compile_error!(
    "no hay provider criptográfico activo: hay que habilitar exactamente uno \
     (`crypto-reference` o `crypto-openvm`). Sin provider el motor no tiene \
     criptografía, y \
     elegir uno por default en silencio es la clase de bug que este gate existe \
     para hacer imposible."
);
