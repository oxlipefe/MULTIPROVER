//! El eje `blockchain_test` del gate de Fase 2.
//!
//! El otro eje (`state_test`) cerró en 39 025/39 025; este es el que mantiene
//! el gate de existencia en RED. Un `blockchain_test` no es un `state_test` con
//! más campos: trae genesis, una cadena de bloques con su header completo,
//! withdrawals y txs con firma. El corte entre el motor y este harness es el
//! mismo que reparte el trabajo con el cliente stateless: la transición de
//! estado (el lifecycle `begin_block`/`transact_in_block`/`finish_block`) es
//! del motor; el encoding y la verificación del header —tries, bloom, RLP—
//! son de acá.

pub mod driver;
pub mod eest;
pub mod encode;
pub mod fixture;
