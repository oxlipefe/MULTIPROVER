//! **El sender sale de la firma, y el oráculo es el corpus.**
//!
//! Los vectores son transacciones reales de `blockchain_tests` de EEST, con su
//! `sender` declarado al lado: el envelope firmado y su oráculo juntos. Un hash
//! de firma mal armado no da otra dirección "parecida" — da una dirección
//! cualquiera, así que el contraste es total.
//!
//! Acá viven los tres tipos que fijan las reglas distintas: una legacy
//! **pre-EIP-155** (`v = 27`, sin `chainId` en el mensaje), una tipada con
//! access list, y una 1559.

use repo_b_common::access_list::{AccessList, AccessListItem};
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_guest::signature::{SECP256K1N_HALF, Signature, SignedTransaction};

/// Desempaqueta o revienta con el motivo. **No se usa `expect`**: el lint está
/// prendido en este crate a propósito y vale también en los tests.
#[track_caller]
fn ok<T, E: core::fmt::Debug>(r: Result<T, E>, que: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{que}: {e:?}"),
    }
}

/// La contraparte: el error que un caso hostil TIENE que producir.
#[track_caller]
fn err<T: core::fmt::Debug, E>(r: Result<T, E>, que: &str) -> E {
    match r {
        Ok(v) => panic!("{que}: salió Ok({v:?})"),
        Err(e) => e,
    }
}

fn addr(hex: &str) -> Address {
    ok(hex.parse(), "dirección inválida en el vector")
}

fn u256(hex: &str) -> U256 {
    ok(hex.parse(), "U256 inválido en el vector")
}

fn bytes(hex: &str) -> Bytes {
    ok(hex.parse(), "bytes inválidos en el vector")
}

fn plantilla(tx_type: TxType) -> Transaction {
    Transaction {
        tx_type,
        // Se pone a propósito una dirección BASURA: `SignedTransaction::new`
        // tiene que descartarla. Si el sender viajara, este test pasaría con
        // ella y no probaría nada.
        sender: addr("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        nonce: 0,
        to: None,
        value: U256::ZERO,
        input: Bytes::new(),
        gas_limit: 0,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: AccessList::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    }
}

/// El despliegue del contrato de historial por el método de Nick: una legacy
/// **pre-EIP-155** con una firma inventada (`r = 0x539`) que igual recupera —
/// una dirección sin dueño. Es el caso que prueba que `v ∈ {27,28}` **no**
/// lleva `chainId` en el mensaje.
fn legacy_pre155() -> (SignedTransaction, Address) {
    let mut tx = plantilla(TxType::Legacy);
    tx.gas_price = Some(0x00e8_d4a5_1000);
    tx.gas_limit = 0x0003_d090;
    tx.input = bytes(
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f5561019e80602d5f395ff33373fffffffffffffffffffffffffffffffffffffffe1460d35760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461019a57600182026001905f5b5f82111560685781019083028483029004916001019190604d565b9093900492505050366060146088573661019a573461019a575f5260205ff35b341061019a57600154600101600155600354806004026004013381556001015f358155600101602035815560010160403590553360601b5f5260605f60143760745fa0600101600355005b6003546002548082038060021160e7575060025b5f5b8181146101295782810160040260040181607402815460601b815260140181600101548152602001816002015481526020019060030154905260010160e9565b910180921461013b5790600255610146565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff141561017357505f5b6001546001828201116101885750505f61018e565b01600190035b5f555f6001556074025ff35b5f5ffd",
    );
    let sig = Signature {
        v: u256("0x1b"),
        r: u256("0x0539"),
        s: u256("0x0c0730f92dc275b663d377a7cbb141b6600052"),
    };
    (
        SignedTransaction::new(tx, None, sig, Vec::new()),
        addr("0x13d1913d623e6a9d8811736359e50fd31fe54fca"),
    )
}

fn eip2930() -> (SignedTransaction, Address) {
    let mut tx = plantilla(TxType::Eip2930);
    tx.gas_price = Some(0x0a);
    tx.gas_limit = 0x6e0a;
    tx.to = Some(addr("0x07a533a8a5b4869372f014581858a299e53911a0"));
    tx.input = bytes(&format!("0x{}00", "01".repeat(179)));
    tx.access_list = vec![AccessListItem {
        address: addr("0x0000000000000000000000000000000000000001"),
        storage_keys: vec![B256::ZERO],
    }];
    let sig = Signature {
        v: U256::from(1u8),
        r: u256("0xf08465d1807c5f6104d89467ff7d1e8692e6f11b6319a988e1462b0191371dce"),
        s: u256("0x3279e4a6adfba2d90ef3cb74693646afda78fe9ed8bdb55c8fea40759b146db1"),
    };
    (
        SignedTransaction::new(tx, Some(1), sig, Vec::new()),
        addr("0xc6ca9ad3e72be14fc716c02e36f0b6df10993f7a"),
    )
}

fn eip1559() -> (SignedTransaction, Address) {
    let mut tx = plantilla(TxType::Eip1559);
    tx.max_priority_fee_per_gas = Some(0);
    tx.max_fee_per_gas = Some(7);
    tx.gas_limit = 0x6e0a;
    tx.to = Some(addr("0xdcfe5b63c0a3d37b0ffd5618ab90ca4562d9f17c"));
    tx.input = bytes(&format!("0x{}00", "01".repeat(179)));
    tx.access_list = vec![AccessListItem {
        address: addr("0x0000000000000000000000000000000000000001"),
        storage_keys: vec![B256::ZERO],
    }];
    let sig = Signature {
        v: U256::ZERO,
        r: u256("0x6a23a530c79a77d617acce2dc56ac22f6c343865c3a9ac11fab9cb6e2f101fe1"),
        s: u256("0x1bf257609183cdf4d1de4bec3981db04359e573ab80c343142927cceab7514ab"),
    };
    (
        SignedTransaction::new(tx, Some(1), sig, Vec::new()),
        addr("0x4ff47251626406e630b9a1180f5cf7082e582fee"),
    )
}

#[test]
fn the_sender_of_a_real_transaction_comes_out_of_its_signature() {
    for (firmada, esperado) in [legacy_pre155(), eip2930(), eip1559()] {
        let recuperada = ok(firmada.recover(1), "la firma tiene que recuperar");
        assert_eq!(recuperada.sender, esperado);
    }
}

/// **La dirección basura que el payload traía NO sobrevive.** Sin esto, todo lo
/// demás sería decorado: el campo seguiría siendo un canal por el que un input
/// hostil elige quién firmó.
#[test]
fn the_sender_of_the_payload_is_discarded_at_construction() {
    let (firmada, _) = eip1559();
    assert_eq!(firmada.payload().sender, Address::ZERO);
}

/// EIP-155: una legacy firmada para OTRA cadena no recupera el mismo sender.
/// El `chainId` está adentro del mensaje, así que cambiarlo cambia el hash.
#[test]
fn a_legacy_signature_binds_its_chain_id() {
    let mut tx = plantilla(TxType::Legacy);
    tx.gas_price = Some(0x0a);
    tx.gas_limit = 21_000;
    tx.to = Some(addr("0x0000000000000000000000000000000000000100"));
    // `v = 37 = 1·2 + 35 + 0` ⇒ chain 1, paridad 0.
    let sig = Signature {
        v: U256::from(37u8),
        r: u256("0x6a23a530c79a77d617acce2dc56ac22f6c343865c3a9ac11fab9cb6e2f101fe1"),
        s: u256("0x1bf257609183cdf4d1de4bec3981db04359e573ab80c343142927cceab7514ab"),
    };
    let firmada = SignedTransaction::new(tx, None, sig, Vec::new());
    assert!(firmada.recover(1).is_ok());
    // El mismo envelope, en la cadena 2: el `v` dice cadena 1 y no matchea.
    assert!(firmada.recover(2).is_err());
}

/// EIP-2: un `s` por encima de `n/2` **no** recupera. Es la regla de la TX, y
/// es distinta de la del precompile ECRECOVER, donde un `s` alto se normaliza
/// y recupera la misma dirección.
#[test]
fn a_transaction_with_high_s_does_not_recover() {
    let (base, esperado) = eip1559();
    let recuperada = ok(base.recover(1), "el vector bueno recupera");
    assert_eq!(recuperada.sender, esperado);

    let mut tx = base.payload().clone();
    tx.sender = Address::ZERO;
    let alto = Signature {
        v: base.signature().v,
        r: base.signature().r,
        s: SECP256K1N_HALF + U256::from(1u8),
    };
    let firmada = SignedTransaction::new(tx, base.chain_id(), alto, Vec::new());
    assert_eq!(
        err(firmada.recover(1), "un `s` alto no puede recuperar").0,
        "s por encima de secp256k1n/2 (EIP-2)"
    );
}

/// Una tx tipada firmada para otra cadena se rechaza aunque la firma sea
/// perfecta: el `chainId` es parte del payload y del consenso.
#[test]
fn a_typed_transaction_for_another_chain_is_refused() {
    let (firmada, _) = eip1559();
    assert_eq!(
        err(firmada.recover(7), "otra cadena no puede validar").0,
        "el chainId de la tx no es el del bloque"
    );
}

/// **El envelope canónico va y vuelve.** El encoder es el mismo que alimenta el
/// `transactionsTrie`, así que este round-trip ata el decoder a un encoding que
/// el corpus contrasta contra el header de cada bloque.
#[test]
fn the_canonical_envelope_round_trips() {
    for (firmada, esperado) in [legacy_pre155(), eip2930(), eip1559()] {
        let bytes = ok(firmada.encode_2718(), "el envelope tiene que encodear");
        let vuelta = ok(
            repo_b_guest::signature::decode_2718(&bytes),
            "el envelope tiene que decodificar",
        );
        assert_eq!(vuelta, firmada);
        assert_eq!(ok(vuelta.recover(1), "recupera").sender, esperado);
        assert_eq!(
            ok(vuelta.encode_2718(), "re-encodea"),
            bytes,
            "el re-encoding tiene que dar los MISMOS bytes"
        );
    }
}

/// **Tests adversariales del decoder** (§9 de `CLAUDE.md`): es input externo, y
/// el corpus solo produce envelopes bien formados — la robustez no la puede
/// juzgar.
#[test]
fn a_malformed_envelope_is_refused_instead_of_half_decoded() {
    let (firmada, _) = eip1559();
    let bueno = ok(firmada.encode_2718(), "encodea");
    let decode = repo_b_guest::signature::decode_2718;

    assert!(decode(&[]).is_err(), "envelope vacío");
    assert!(
        decode(&[0x00]).is_err(),
        "tipo 0 no es un byte de tipo válido"
    );
    assert!(decode(&[0x05, 0xc0]).is_err(), "tipo desconocido");
    // El hueco entre el último tipo y la cabecera de lista: ni tipo ni legacy.
    assert!(decode(&[0x7f, 0xc0]).is_err(), "byte de tipo sin definir");

    // Truncado: la lista declara más de lo que hay.
    assert!(decode(&bueno[..bueno.len() - 1]).is_err(), "truncado");
    // Bytes de más DESPUÉS del envelope: no se ignoran.
    let mut sobra = bueno.clone();
    sobra.push(0x00);
    assert!(decode(&sobra).is_err(), "bytes después del envelope");
    // Un envelope tipado sin cuerpo.
    assert!(decode(&[0x02]).is_err(), "tipo sin payload");
}

/// **`to = None` (tx de creación) es la cadena VACÍA, no el cero.** Confundirlos
/// da un `transactionsTrie` distinto con el mismo largo, que es la clase de bug
/// que no se ve mirando el hex. El test vivía junto al encoder del harness; se
/// mudó con el encoder.
#[test]
fn a_create_transaction_encodes_to_as_the_empty_string() {
    let (crea, _) = legacy_pre155();
    assert_eq!(crea.payload().to, None);
    let bytes = ok(crea.encode_2718(), "encodea");
    // `0x80` es la cadena vacía; la dirección cero sería `0x94` + 20 ceros.
    assert!(
        bytes.windows(1).any(|w| w == [0x80]),
        "el `to` de un CREATE tiene que ser la cadena vacía"
    );

    let mut con_cero = crea.payload().clone();
    con_cero.to = Some(Address::ZERO);
    let otra = SignedTransaction::new(con_cero, crea.chain_id(), *crea.signature(), Vec::new());
    assert_ne!(
        ok(otra.encode_2718(), "encodea"),
        bytes,
        "la dirección cero NO es la cadena vacía"
    );
}
