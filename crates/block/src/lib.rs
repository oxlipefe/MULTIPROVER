//! `repo-b-block` — la validación de un bloque alrededor de su ejecución.
//!
//! El motor (`repo-b-evm`) hace la transición de estado; este crate hace todo
//! lo que la rodea y que es **encoding y verificación**, no ejecución:
//!
//! - el [`Header`], con su RLP en las dos direcciones y su hash;
//! - el header contra su padre ([`validate_header`]);
//! - el bloque entero desde sus bytes ([`decode_block`]);
//! - el cuerpo contra el header (`transactionsRoot`, `withdrawalsRoot`,
//!   ommers, blob gas);
//! - lo ejecutado contra el header (`stateRoot`, `gasUsed`, `receiptsRoot`,
//!   bloom, `requestsHash`);
//! - las system calls del bloque: cuáles, con qué calldata y cuáles
//!   invalidan el bloque si fallan ([`system_calls`]).
//!
//! Es `no_std` porque lo corren los dos lados con el MISMO código: el harness
//! de conformance, donde lo juzga el corpus de la EF, y el guest, que lo
//! ejecuta dentro de la prueba. Dos implementaciones de la misma regla pueden
//! discrepar justo en el campo que el corpus no mira.
//!
//! Toda regla es pura, fail-closed y sin `panic`: un input hostil produce un
//! [`BlockError`] tipado, nunca un bloque aceptado por omisión. La única
//! función que ejecuta algo es [`run_system_calls`], y ejecuta con el motor que
//! recibe: lo que pone este crate es la política, no la EVM.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod body;
pub mod error;
pub mod header;
pub mod requests;
pub mod roots;
pub mod system_calls;
pub mod validate;

pub use body::{Block, check_body_fields, decode_block, encode_block};
pub use error::{BlockError, HeaderField};
pub use header::Header;
pub use system_calls::{
    Check, SystemCall, SystemCallError, SystemCalls, run_system_calls, system_calls,
};
pub use validate::{
    PostExecution, check_blob_gas_used, check_block_rlp_size, check_ommers, check_requests_hash,
    check_transactions_root, check_withdrawals_root, expected_base_fee, validate_fork_fields,
    validate_header, validate_post_execution,
};
