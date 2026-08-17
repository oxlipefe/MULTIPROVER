//! Re-export de los primitives de Ethereum desde `alloy-primitives` (`no_std`).
//! No reimplementamos numéricos ni hashes.

pub use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};

/// Root de un trie de storage VACÍO: `keccak(rlp(""))` = `keccak(0x80)`.
///
/// Es el tercer campo del account record (`nonce, balance, storageRoot,
/// codeHash`), y "storage vacío" en el protocolo *es* `storageRoot ==
/// EMPTY_ROOT_HASH`. Va acá con el valor literal, al lado de `KECCAK256_EMPTY`,
/// y **no** se importa de `alloy-trie`: el motor consume roots, no los calcula,
/// y meter un crate de trie en `no_std` sería arrastrar toda esa maquinaria al
/// guest. Un test del runner —que sí depende de `alloy-trie`— pinea que este
/// literal y `alloy_trie::EMPTY_ROOT_HASH` son el mismo valor.
pub const EMPTY_ROOT_HASH: B256 = B256::new([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);
