//! `repo-b-witness` — el grabador que **envuelve `State`** (statelessness).
//!
//! Dos piezas y una línea entre ellas:
//!
//! - **`RecordingState`** (host, feature `std`) envuelve un `State` completo y
//!   anota lo que la ejecución pidió, sin cambiar un valor.
//! - **`AccessLog`** y **`StrictState`** (`no_std`) son lo grabado y un `State`
//!   que sirve solo eso, fail-closed. El guest ejecuta de este lado.
//!
//! Lo que este crate **todavía no hace**: nodos de trie, verificación del
//! pre-state root, cadena contigua de headers y pruebas de exclusión. Eso es el
//! `ExecutionWitness` propiamente dicho — el formato canónico es el de
//! `alloy_rpc_types_debug`, no el tipo homónimo que `repo-b-evm` vendoreó en la
//! Fase 0, y reconciliarlos es el paso siguiente.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod access_log;
#[cfg(feature = "std")]
pub mod recorder;
pub mod strict;
pub mod witness_state;

pub use access_log::{AccessItem, AccessLog};
#[cfg(feature = "std")]
pub use recorder::RecordingState;
pub use strict::StrictState;
pub use witness_state::WitnessState;

pub use repo_b_common::witness::ExecutionWitness;
