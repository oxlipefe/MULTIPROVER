//! El codec del input, contra sí mismo y contra input hostil.
//!
//! **Un round-trip prueba consistencia, no correctitud**: un encoder y un
//! decoder que compartan el mismo error dan verde. Lo que ata este codec a la
//! realidad es el corpus, donde el resultado con el que se compara **no sale del
//! codec**. Acá se prueba lo otro: que ningún byte hostil produzca algo que no
//! sea un rechazo limpio.

use repo_b_common::access_list::AccessListItem;
use repo_b_common::authorization::Authorization;
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;
use repo_b_guest::codec::{OwnedInput, decode, encode};

fn addr(n: u8) -> Address {
    Address::repeat_byte(n)
}
fn hash(n: u8) -> B256 {
    B256::repeat_byte(n)
}

/// Un input con **todo lleno**: las tres listas anidadas no vacías, los
/// opcionales en sus dos estados, y más de una tx. Un round-trip sobre un input
/// mínimo no probaría las ramas que importan.
fn input_completo() -> OwnedInput {
    OwnedInput {
        witness: ExecutionWitness {
            state: vec![Bytes::from_static(&[1, 2, 3]), Bytes::from_static(&[4])],
            codes: vec![Bytes::from_static(&[0x60, 0x00])],
            keys: vec![Bytes::from_static(&[7; 20])],
            headers: vec![Bytes::from_static(&[0xf8, 0x01])],
        },
        pre_state_root: hash(9),
        env: BlockEnv {
            spec: Spec::Prague,
            chain_id: 1,
            number: 42,
            coinbase: addr(0xcc),
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee: 7,
            prevrandao: hash(3),
            blob_excess_gas: Some(131_072),
            blob_base_fee: None,
            blob_base_fee_update_fraction: Some(3_338_477),
        },
        txs: vec![
            Transaction {
                tx_type: TxType::Eip7702,
                sender: addr(1),
                nonce: 5,
                to: Some(addr(2)),
                value: U256::from(1_000_000_000u64),
                input: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
                gas_limit: 100_000,
                gas_price: None,
                max_fee_per_gas: Some(1_000),
                max_priority_fee_per_gas: Some(1),
                access_list: vec![
                    AccessListItem {
                        address: addr(3),
                        storage_keys: vec![hash(1), hash(2)],
                    },
                    AccessListItem {
                        address: addr(4),
                        storage_keys: vec![],
                    },
                ],
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: vec![],
                authorization_list: vec![
                    Authorization {
                        chain_id: U256::from(1u64),
                        address: addr(5),
                        nonce: 0,
                        authority: Some(addr(6)),
                    },
                    // `authority: None` es firma inválida, y NO es lo mismo que
                    // la dirección cero: la EIP saltea esa tupla.
                    Authorization {
                        chain_id: U256::MAX,
                        address: Address::ZERO,
                        nonce: u64::MAX,
                        authority: None,
                    },
                ],
            },
            Transaction {
                tx_type: TxType::Legacy,
                sender: addr(8),
                nonce: 0,
                to: None,
                value: U256::ZERO,
                input: Bytes::new(),
                gas_limit: 21_000,
                gas_price: Some(1),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                access_list: vec![],
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: vec![],
                authorization_list: vec![],
            },
        ],
        withdrawals: vec![Withdrawal {
            index: 1,
            validator_index: 2,
            address: addr(7),
            amount: 32_000_000_000,
        }],
        system_calls: vec![(addr(0x0b), Bytes::from_static(&[0xaa; 32]))],
    }
}

fn igual(a: &OwnedInput, b: &OwnedInput) -> bool {
    a.witness == b.witness
        && a.pre_state_root == b.pre_state_root
        && a.env == b.env
        && a.txs == b.txs
        && a.withdrawals == b.withdrawals
        && a.system_calls == b.system_calls
}

#[test]
fn a_full_input_survives_the_round_trip() {
    let original = input_completo();
    let Ok(vuelto) = decode(&encode(&original)) else {
        panic!("un input propio tiene que decodificar");
    };
    assert!(igual(&original, &vuelto), "el round-trip cambió el input");
}

/// **Un opcional ausente no es el valor cero.** `None` y `Some(0)` tienen que
/// dar bytes distintos: confundirlos cambia el gas.
#[test]
fn an_absent_option_is_not_the_zero_value() {
    let mut con_none = input_completo();
    con_none.env.blob_base_fee = None;
    let mut con_cero = input_completo();
    con_cero.env.blob_base_fee = Some(0);
    assert_ne!(encode(&con_none), encode(&con_cero));

    let (Ok(a), Ok(b)) = (decode(&encode(&con_none)), decode(&encode(&con_cero))) else {
        panic!("los dos tienen que decodificar");
    };
    assert_eq!(a.env.blob_base_fee, None);
    assert_eq!(b.env.blob_base_fee, Some(0));
}

/// **Ningún prefijo puede paniquear ni producir un input a medio armar.** Se
/// prueban TODOS, no uno: un decoder se rompe en el byte que nadie probó.
#[test]
fn no_truncated_prefix_ever_panics_or_half_decodes() {
    let bytes = encode(&input_completo());
    for corte in 0..bytes.len() {
        assert!(
            decode(&bytes[..corte]).is_err(),
            "el prefijo de {corte} bytes decodificó algo, y no debería"
        );
    }
    assert!(decode(&bytes).is_ok(), "el input completo sí decodifica");
}

/// Bytes después del input son un rechazo: aceptarlos dejaría pasar dos inputs
/// distintos con el mismo prefijo.
#[test]
fn trailing_bytes_are_refused() {
    let mut bytes = encode(&input_completo());
    bytes.push(0);
    assert!(decode(&bytes).is_err());
}

/// **Ningún byte del formato puede ser decorativo.** Cambiar cualquiera o falla,
/// o decodifica a algo distinto; lo que no puede es dar el MISMO input, porque
/// entonces ese byte no significa nada.
#[test]
fn no_single_byte_flip_decodes_back_to_the_same_input() {
    let original = input_completo();
    let bytes = encode(&original);
    for i in 0..bytes.len() {
        let mut roto = bytes.clone();
        roto[i] ^= 0xFF;
        if let Ok(vuelto) = decode(&roto) {
            assert!(
                !igual(&original, &vuelto),
                "cambiar el byte {i} no cambió nada: ese byte no significa nada"
            );
        }
    }
}

/// Un fork que no existe se rechaza, en vez de caer en un `_ => default`.
#[test]
fn an_unknown_fork_byte_is_refused() {
    let bytes = encode(&input_completo());
    let mut cazado = false;
    for i in 0..bytes.len() {
        if bytes[i] != 3 {
            continue;
        }
        let mut roto = bytes.clone();
        roto[i] = 0x7f;
        if decode(&roto).is_err() {
            cazado = true;
            break;
        }
    }
    assert!(cazado, "romper el byte del fork tiene que dar un rechazo");
}

/// Un input vacío no es un input.
#[test]
fn an_empty_input_is_refused() {
    assert!(decode(&[]).is_err());
}
