//! `repo-b-block` — la validación de un bloque alrededor de su ejecución.
//!
//! El motor (`repo-b-evm`) hace la transición de estado; este crate hace todo
//! lo que la rodea y que es **encoding y verificación**, no ejecución:
//!
//! - el [`Header`], con su RLP y su hash;
//! - el header contra su padre ([`validate_header`]);
//! - el cuerpo contra el header (`transactionsRoot`, `withdrawalsRoot`,
//!   blob gas);
//! - lo ejecutado contra el header (`stateRoot`, `gasUsed`, `receiptsRoot`,
//!   bloom, `requestsHash`).
//!
//! Es `no_std` porque lo corren los dos lados con el MISMO código: el harness
//! de conformance, donde lo juzga el corpus de la EF, y el guest, que lo
//! ejecuta dentro de la prueba. Dos implementaciones de la misma regla pueden
//! discrepar justo en el campo que el corpus no mira.
//!
//! Toda función es pura, fail-closed y sin `panic`: un input hostil produce un
//! [`BlockError`] tipado, nunca un bloque aceptado por omisión.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
pub mod header;
pub mod requests;
pub mod roots;
pub mod validate;

pub use error::{BlockError, HeaderField};
pub use header::Header;
pub use validate::{
    PostExecution, check_blob_gas_used, check_block_rlp_size, check_requests_hash,
    check_transactions_root, check_withdrawals_root, expected_base_fee, validate_header,
    validate_post_execution,
};
