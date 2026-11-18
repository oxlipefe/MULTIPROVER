//! El eje `blockchain_test` del gate de Fase 2.
//!
//! Un `blockchain_test` no es un `state_test` con más campos: trae genesis, una
//! cadena de bloques con su header completo, withdrawals y txs con firma. La
//! transición de estado (el lifecycle `begin_block`/`transact_in_block`/
//! `finish_block`) es del motor; el encoding y la verificación del bloque
//! —header, tries, bloom, RLP— son del crate `repo-b-block`, que este harness
//! consume y contrasta contra lo que el fixture publica.

pub mod driver;
pub mod dump;
pub mod eest;
pub mod fixture;
#[cfg(test)]
mod guest_case;
pub mod network;
