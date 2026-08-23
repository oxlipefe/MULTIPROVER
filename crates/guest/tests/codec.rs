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
use repo_b_guest::signature::{Signature, SignedTransaction};

/// Desempaqueta o revienta con el motivo. **No se usa `expect`**: el lint está
/// prendido en este crate a propósito y vale también en los tests.
#[track_caller]
fn ok<T, E: core::fmt::Debug>(r: Result<T, E>, que: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{que}: {e:?}"),
    }
}

fn addr(n: u8) -> Address {
    Address::repeat_byte(n)
}
fn hash(n: u8) -> B256 {
    B256::repeat_byte(n)
}

/// Una firma **sintética**: sirve para el round-trip del formato, que es lo que
/// este archivo prueba. Que recupere o no es asunto de `tests/signature.rs`,
/// donde los vectores son txs reales con su sender declarado al lado.
fn firma(v: u64) -> Signature {
    Signature {
        v: U256::from(v),
        r: U256::from(0x1234_5678u64),
        s: U256::from(0x9abc_def0u64),
    }
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
        parent_hash: hash(0xab),
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
            SignedTransaction::new(
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
                            // **El `authority` que se pone acá NO viaja**: lo
                            // descarta el constructor y lo escribe la recuperación.
                            authority: Some(addr(6)),
                        },
                        Authorization {
                            chain_id: U256::MAX,
                            address: Address::ZERO,
                            nonce: u64::MAX,
                            authority: None,
                        },
                    ],
                },
                Some(1),
                firma(0),
                vec![firma(0), firma(1)],
            ),
            SignedTransaction::new(
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
                None,
                firma(27),
                vec![],
            ),
        ],
        withdrawals: vec![Withdrawal {
            index: 1,
            validator_index: 2,
            address: addr(7),
            amount: 32_000_000_000,
        }],
        // Las dos listas de system calls, **distintas entre sí**: si fueran
        // iguales, permutarlas no cambiaría los bytes y el round-trip no podría
        // probar que el formato las separa.
        opening_system_calls: vec![
            (addr(0x0b), Bytes::from_static(&[0xaa; 32])),
            (addr(0x0c), Bytes::from_static(&[0xbb; 32])),
        ],
        closing_system_calls: vec![(addr(0x70), Bytes::new()), (addr(0x72), Bytes::new())],
    }
}

fn igual(a: &OwnedInput, b: &OwnedInput) -> bool {
    a.witness == b.witness
        && a.pre_state_root == b.pre_state_root
        && a.env == b.env
        && a.txs == b.txs
        && a.withdrawals == b.withdrawals
        && a.parent_hash == b.parent_hash
        && a.opening_system_calls == b.opening_system_calls
        && a.closing_system_calls == b.closing_system_calls
}

#[test]
fn a_full_input_survives_the_round_trip() {
    let original = input_completo();
    let Ok(vuelto) = decode(&ok(encode(&original), "el input tiene que encodear")) else {
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
    assert_ne!(
        ok(encode(&con_none), "encodea"),
        ok(encode(&con_cero), "encodea")
    );

    let (Ok(a), Ok(b)) = (
        decode(&ok(encode(&con_none), "encodea")),
        decode(&ok(encode(&con_cero), "encodea")),
    ) else {
        panic!("los dos tienen que decodificar");
    };
    assert_eq!(a.env.blob_base_fee, None);
    assert_eq!(b.env.blob_base_fee, Some(0));
}

/// **Ningún prefijo puede paniquear ni producir un input a medio armar.** Se
/// prueban TODOS, no uno: un decoder se rompe en el byte que nadie probó.
#[test]
fn no_truncated_prefix_ever_panics_or_half_decodes() {
    let bytes = ok(encode(&input_completo()), "encodea");
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
    let mut bytes = ok(encode(&input_completo()), "encodea");
    bytes.push(0);
    assert!(decode(&bytes).is_err());
}

/// **Ningún byte del formato puede ser decorativo.** Cambiar cualquiera o falla,
/// o decodifica a algo distinto; lo que no puede es dar el MISMO input, porque
/// entonces ese byte no significa nada.
#[test]
fn no_single_byte_flip_decodes_back_to_the_same_input() {
    let original = input_completo();
    let bytes = ok(encode(&original), "encodea");
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
    let bytes = ok(encode(&input_completo()), "encodea");
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

/// **Arranque y cierre son dos campos y no una lista con un flag**, y esto lo
/// prueba: intercambiarlas produce bytes distintos y vuelve intercambiado.
///
/// Es la propiedad que hace irrepresentable el error que importa — que un input
/// hostil pida correr una system call de cierre al arrancar el bloque. No hay
/// byte que voltear: lo que las separa es la posición en el formato.
#[test]
fn swapping_opening_and_closing_system_calls_is_a_different_input() {
    let original = input_completo();
    let mut permutado = input_completo();
    core::mem::swap(
        &mut permutado.opening_system_calls,
        &mut permutado.closing_system_calls,
    );
    assert_ne!(encode(&original), encode(&permutado));

    let Ok(vuelto) = decode(&ok(encode(&permutado), "encodea")) else {
        panic!("el input permutado tiene que decodificar");
    };
    assert_eq!(vuelto.opening_system_calls, original.closing_system_calls);
    assert_eq!(vuelto.closing_system_calls, original.opening_system_calls);
}

/// Una lista de system calls **vacía** no es lo mismo que la lista del otro
/// momento del lifecycle: un bloque pre-Prague no tiene llamadas de cierre, y
/// eso viaja explícito.
#[test]
fn an_empty_system_call_list_round_trips_as_empty() {
    let mut sin_cierre = input_completo();
    sin_cierre.closing_system_calls = Vec::new();
    let Ok(vuelto) = decode(&ok(encode(&sin_cierre), "encodea")) else {
        panic!("un input sin llamadas de cierre tiene que decodificar");
    };
    assert!(vuelto.closing_system_calls.is_empty());
    assert_eq!(
        vuelto.opening_system_calls, sin_cierre.opening_system_calls,
        "vaciar una lista no puede correr la otra de lugar"
    );
}
