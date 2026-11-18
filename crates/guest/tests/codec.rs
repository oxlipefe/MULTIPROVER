//! Los dos codecs del input, contra sí mismos y contra input hostil.
//!
//! **Un round-trip prueba consistencia, no correctitud**: un encoder y un
//! decoder que compartan el mismo error dan verde. Lo que ata estos codecs a la
//! realidad es el corpus, donde el resultado con el que se compara **no sale del
//! codec**. Acá se prueba lo otro: que ningún byte hostil produzca algo que no
//! sea un rechazo limpio, y que el formato de un bloque no tenga dónde escribir
//! lo que el guest deriva.

use alloy_rlp::Encodable;
use repo_b_common::access_list::AccessListItem;
use repo_b_common::authorization::Authorization;
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::spec::Spec;
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;
use repo_b_guest::codec::{
    BlockInput, INPUT_VERSION, TxInput, decode_block_input, decode_tx_input, encode_block_input,
    encode_tx_input,
};
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
/// este archivo prueba. Que recupere o no es asunto de `tests/signature.rs`.
fn firma(v: u64) -> Signature {
    Signature {
        v: U256::from(v),
        r: U256::from(0x1234_5678u64),
        s: U256::from(0x9abc_def0u64),
    }
}

/// Un input de txs con **todo lleno**: las listas anidadas no vacías, los
/// opcionales en sus dos estados, y más de una tx.
fn tx_input() -> TxInput {
    TxInput {
        witness: ExecutionWitness {
            state: vec![Bytes::from_static(&[1, 2, 3]), Bytes::from_static(&[4])],
            codes: vec![Bytes::from_static(&[0x60, 0x00])],
            keys: vec![],
            headers: vec![],
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
    }
}

/// Un input de bloque con las tres listas del witness no vacías. El bloque
/// viaja como bytes opacos: este codec solo corta el sobre.
fn block_input() -> BlockInput {
    BlockInput {
        fork: Spec::Prague,
        chain_id: 1,
        block: Bytes::from_static(&[0xc3, 0xc0, 0xc0, 0xc0]),
        witness: ExecutionWitness {
            state: vec![Bytes::from_static(&[1, 2, 3]), Bytes::from_static(&[4])],
            codes: vec![Bytes::from_static(&[0x60, 0x00])],
            keys: vec![],
            headers: vec![Bytes::from_static(&[0xf8, 0x01]), Bytes::from_static(&[9])],
        },
    }
}

#[test]
fn a_full_tx_input_survives_the_round_trip() {
    let original = tx_input();
    let vuelto = ok(
        decode_tx_input(&ok(encode_tx_input(&original), "encodea")),
        "decodifica",
    );
    assert_eq!(original, vuelto, "el round-trip cambió el input");
}

#[test]
fn a_block_input_survives_the_round_trip() {
    let original = block_input();
    let vuelto = ok(
        decode_block_input(&encode_block_input(&original)),
        "decodifica",
    );
    assert_eq!(original, vuelto, "el round-trip cambió el input");
}

/// **Cada fork tiene su byte, y ningún fork comparte el de otro**, en los dos
/// formatos. Elegir el número de OTRO fork compila igual, y entonces el guest
/// ejecutaría bajo las reglas equivocadas sin que nada se queje.
#[test]
fn every_fork_round_trips_to_itself_and_to_no_other() {
    let forks = [
        Spec::Paris,
        Spec::Shanghai,
        Spec::Cancun,
        Spec::Prague,
        Spec::Osaka,
        Spec::Bpo1,
        Spec::Bpo2,
    ];
    let mut bytes_por_fork = Vec::new();
    for spec in forks {
        let mut txs = tx_input();
        txs.env.spec = spec;
        let encodeado = ok(encode_tx_input(&txs), "encodea");
        assert_eq!(ok(decode_tx_input(&encodeado), "decodifica").env.spec, spec);
        bytes_por_fork.push(encodeado);

        let mut bloque = block_input();
        bloque.fork = spec;
        let encodeado = encode_block_input(&bloque);
        assert_eq!(ok(decode_block_input(&encodeado), "decodifica").fork, spec);
        bytes_por_fork.push(encodeado);
    }
    for (i, a) in bytes_por_fork.iter().enumerate() {
        for b in bytes_por_fork.iter().skip(i + 1) {
            assert_ne!(a, b, "dos inputs distintos encodean a los mismos bytes");
        }
    }
}

/// **Un opcional ausente no es el valor cero.** Confundirlos cambia el gas.
#[test]
fn an_absent_option_is_not_the_zero_value() {
    let mut con_none = tx_input();
    con_none.env.blob_base_fee = None;
    let mut con_cero = tx_input();
    con_cero.env.blob_base_fee = Some(0);
    let a = ok(encode_tx_input(&con_none), "encodea");
    let b = ok(encode_tx_input(&con_cero), "encodea");
    assert_ne!(a, b);
    assert_eq!(
        ok(decode_tx_input(&a), "decodifica").env.blob_base_fee,
        None
    );
    assert_eq!(
        ok(decode_tx_input(&b), "decodifica").env.blob_base_fee,
        Some(0)
    );
}

/// **Ningún prefijo puede paniquear ni producir un input a medio armar.** Se
/// prueban TODOS, en los dos formatos.
#[test]
fn no_truncated_prefix_ever_panics_or_half_decodes() {
    let txs = ok(encode_tx_input(&tx_input()), "encodea");
    for corte in 0..txs.len() {
        assert!(
            decode_tx_input(&txs[..corte]).is_err(),
            "txs, corte {corte}"
        );
    }
    let bloque = encode_block_input(&block_input());
    for corte in 0..bloque.len() {
        assert!(
            decode_block_input(&bloque[..corte]).is_err(),
            "bloque, corte {corte}"
        );
    }
}

/// Bytes después del input son un rechazo.
#[test]
fn trailing_bytes_are_refused() {
    let mut txs = ok(encode_tx_input(&tx_input()), "encodea");
    txs.push(0);
    assert!(decode_tx_input(&txs).is_err());
    let mut bloque = encode_block_input(&block_input());
    bloque.push(0);
    assert!(decode_block_input(&bloque).is_err());
}

/// **Ningún byte del formato puede ser decorativo.** Cambiar cualquiera o
/// falla, o decodifica a algo distinto.
#[test]
fn no_single_byte_flip_decodes_back_to_the_same_input() {
    let original = tx_input();
    let bytes = ok(encode_tx_input(&original), "encodea");
    for i in 0..bytes.len() {
        let mut roto = bytes.clone();
        roto[i] ^= 0xFF;
        if let Ok(vuelto) = decode_tx_input(&roto) {
            assert_ne!(original, vuelto, "txs: el byte {i} no significa nada");
        }
    }
    let original = block_input();
    let bytes = encode_block_input(&original);
    for i in 0..bytes.len() {
        let mut roto = bytes.clone();
        roto[i] ^= 0xFF;
        if let Ok(vuelto) = decode_block_input(&roto) {
            assert_ne!(original, vuelto, "bloque: el byte {i} no significa nada");
        }
    }
}

/// Un fork o una versión que no existen se rechazan, en vez de caer en un
/// `_ => default`. En el input de un bloque, la versión es el primer ítem y el
/// fork el segundo.
#[test]
fn an_unknown_fork_or_version_is_refused() {
    let bytes = encode_block_input(&block_input());
    // `[0xf8|0xf9.., len, version, fork, …]` — los dos bytes después de la
    // cabecera de la lista.
    let cabecera = usize::from(bytes[0].saturating_sub(0xf7)).saturating_add(1);
    for (desplazamiento, valor) in [(0usize, INPUT_VERSION + 1), (1, 8), (1, 0x7f)] {
        let mut roto = bytes.clone();
        roto[cabecera + desplazamiento] = valor;
        assert!(
            decode_block_input(&roto).is_err(),
            "el byte {desplazamiento} = {valor} tendría que ser un rechazo"
        );
    }
}

/// Un input vacío no es un input.
#[test]
fn an_empty_input_is_refused() {
    assert!(decode_tx_input(&[]).is_err());
    assert!(decode_block_input(&[]).is_err());
}

/// Envuelve `payload` en una lista RLP.
fn list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(payload);
    out
}

/// El cuerpo de la lista exterior de un input encodeado.
fn payload_of(bytes: &[u8]) -> Vec<u8> {
    let mut cursor = bytes;
    let Ok(header) = alloy_rlp::Header::decode(&mut cursor) else {
        panic!("el input tiene que abrir como lista");
    };
    cursor[..header.payload_length].to_vec()
}

/// **Las system calls ya no se pueden inyectar.** El formato del bloque no
/// tiene dónde escribirlas: un input que les agregue las dos listas de antes
/// (arranque y cierre) detrás de sus campos es un input con campos de más, y se
/// rechaza antes de mirar el bloque.
#[test]
fn system_calls_cannot_be_injected_into_a_block_input() {
    let mut payload = payload_of(&encode_block_input(&block_input()));
    let mut llamada = Vec::new();
    addr(0x77).encode(&mut llamada);
    Bytes::from_static(&[0xaa; 32]).encode(&mut llamada);
    let lista = list(&list(&llamada));
    payload.extend_from_slice(&lista);
    payload.extend_from_slice(&lista);
    assert_eq!(
        decode_block_input(&list(&payload)),
        Err(repo_b_guest::codec::CodecError(
            "el input trae campos de más"
        ))
    );
}

/// **Tampoco un `env` ni un root de arranque**: el bloque es bytes opacos para
/// el sobre, y el sobre tiene exactamente cinco campos. El `env` de un
/// `TxInput` metido en un input de bloque es un campo de más.
#[test]
fn an_env_cannot_be_injected_into_a_block_input() {
    let mut payload = payload_of(&encode_block_input(&block_input()));
    hash(0x99).encode(&mut payload);
    assert!(decode_block_input(&list(&payload)).is_err());
}

/// **Las `keys` del witness no viajan**: un witness de bloque con una cuarta
/// lista se rechaza, y el decodificado siempre las trae vacías.
#[test]
fn the_witness_keys_do_not_travel() {
    let mut con_keys = block_input();
    con_keys.witness.keys = vec![Bytes::from_static(&[7; 20])];
    let vuelto = ok(
        decode_block_input(&encode_block_input(&con_keys)),
        "decodifica",
    );
    assert!(vuelto.witness.keys.is_empty());
    assert_eq!(vuelto, block_input());

    // Un witness con cuatro listas, armado a mano.
    let mut w = Vec::new();
    for _ in 0..4 {
        w.extend_from_slice(&list(&[]));
    }
    let mut payload = Vec::new();
    INPUT_VERSION.encode(&mut payload);
    4u8.encode(&mut payload);
    1u64.encode(&mut payload);
    Bytes::from_static(&[0xc0]).encode(&mut payload);
    payload.extend_from_slice(&list(&w));
    assert_eq!(
        decode_block_input(&list(&payload)),
        Err(repo_b_guest::codec::CodecError(
            "el witness trae más de tres listas"
        ))
    );
}
