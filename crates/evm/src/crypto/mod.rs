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
//! Hoy el único provider es la referencia. Los de backend entran
//! como features nuevas, con su `[patch.crates-io]` o sus bindings viviendo en
//! **su** crate y nunca acá.

pub mod reference;

#[cfg(feature = "crypto-reference")]
pub use reference::Reference as Active;

#[cfg(not(any(feature = "crypto-reference")))]
compile_error!(
    "no hay provider criptográfico activo: hay que habilitar exactamente uno \
     (hoy, `crypto-reference`). Sin provider el motor no tiene criptografía, y \
     elegir uno por default en silencio es la clase de bug que este gate existe \
     para hacer imposible."
);
