//! Slice 2.6 — vectores de referencia de la derivación de direcciones.
//!
//! `fixtures/diff/create/` (37 casos, 0 divergencias) cubre la semántica de
//! consenso de CREATE/CREATE2/SELFDESTRUCT contra revm, y el bound de
//! profundidad 1024 lo gatean los unit tests de `frames.rs` (el 63/64 de
//! EIP-150 agota el gas cerca del frame 340, así que ningún fixture llega).
//!
//! Lo que queda acá es lo que ni el oráculo ni el executor pueden dar: los
//! **vectores oficiales de EIP-1014**. Fijarlos ata la fórmula a la spec y no
//! solo a "lo mismo que hace revm".

use repo_b_common::primitives::{Address, B256};

/// CREATE: `keccak256(rlp([creador, nonce]))[12..]`. El vector viene de
/// `alloy_primitives` (el mismo helper que usa revm) y queda FIJADO acá para
/// que un cambio de fórmula rompa un test, no solo el diferencial.
#[test]
fn create_derives_the_address_from_the_creator_nonce() {
    let sender = Address::new([0xa0; 20]);
    assert_eq!(
        format!("{}", sender.create(0)).to_lowercase(),
        "0xc64cd893165675fa0ad5604d39ecb5af8e073bd2"
    );
    // El nonce entra en el RLP: nonces distintos ⇒ direcciones distintas.
    assert_ne!(sender.create(0), sender.create(1));
}

/// CREATE2 (EIP-1014): los cuatro vectores de referencia de la spec, con la
/// forma `keccak256(0xff ++ address ++ salt ++ keccak256(init_code))[12..]`.
#[test]
fn create2_matches_the_eip1014_reference_vectors() {
    let vectors: [(&str, &str, &[u8], &str); 4] = [
        (
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            &[0x00],
            "0x4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38",
        ),
        (
            "0xdeadbeef00000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            &[0x00],
            "0xb928f69bb1d91cd65274e3c79d8986362984fda3",
        ),
        (
            "0xdeadbeef00000000000000000000000000000000",
            "0x000000000000000000000000feed000000000000000000000000000000000000",
            &[0x00],
            "0xd04116cdd17bebe565eb2422f2497e06cc1c9833",
        ),
        (
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            &[0xde, 0xad, 0xbe, 0xef],
            "0x70f2b2914a2a4b783faefb75f459a580616fcb5e",
        ),
    ];
    for (creator, salt, init_code, expected) in vectors {
        let creator: Address = creator.parse().unwrap_or_else(|e| panic!("creador: {e}"));
        let salt: B256 = salt.parse().unwrap_or_else(|e| panic!("salt: {e}"));
        assert_eq!(
            format!("{}", creator.create2_from_code(salt.0, init_code)).to_lowercase(),
            expected,
            "vector de EIP-1014 con salt {salt}"
        );
    }
}
