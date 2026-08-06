//! Re-export de los primitives de Ethereum desde `alloy-primitives` (`no_std`).
//! No reimplementamos numéricos ni hashes (ENGINEERING_RULES §1).

pub use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
