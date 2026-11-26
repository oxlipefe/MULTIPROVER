//! Diferencial de la **firma de una tx**: el remitente que deriva el guest
//! contra el que deriva alloy.
//!
//! El motor no ve firmas (recibe el caller resuelto, como revm), así que el
//! diferencial de ejecución es ciego a esta regla por construcción. Este set
//! compara la otra mitad: el envelope EIP-2718 firmado y el `chainId` del
//! bloque, por dos caminos independientes.
//!
//! - **Nuestro**: `decode_2718` + `SignedTransaction::recover`, la ruta del
//!   guest.
//! - **El oráculo**: `TxEnvelope::decode_2718_exact` de alloy, el chequeo de
//!   `chainId` de revm (`validate_tx_env`: una tx que trae `chainId` tiene que
//!   traer el del bloque; una tipada sin él es inválida) y `recover_signer`,
//!   que aplica EIP-2 antes de recuperar.
//!
//! El veredicto es binario por caso: los dos recuperan la MISMA dirección, o
//! los dos rechazan. Cualquier otra combinación es divergencia.
//!
//! El generador del set (`--gen-tx-signature`) construye cada envelope con
//! los tipos de alloy y firma con `k256`: el payload que se firma no sale de
//! nuestro encoder, así que un `[SAME]` no es el encoder comparado contra sí
//! mismo.

use alloy_consensus::transaction::{RlpEcdsaEncodableTx, SignerRecoverable};
use alloy_consensus::{
    SignableTransaction, Transaction as _, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxEnvelope,
    TxLegacy,
};
use alloy_eips::eip2718::Decodable2718;
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_rlp::{Encodable, Header};
use k256::ecdsa::SigningKey;
use repo_b_guest::signature::{SECP256K1N_HALF, decode_2718};
use serde_json::{Map, Value};

/// La clave que firma todos los casos (la clásica de los fixtures, `0xa94f…`).
const SECRET: [u8; 32] = [
    0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x14, 0x9e, 0xb4, 0x36, 0x59, 0x60, 0xe6, 0xa7, 0xa4, 0x5f,
    0x33, 0x43, 0x93, 0x09, 0x30, 0x61, 0x11, 0x6b, 0x19, 0x7e, 0x32, 0x40, 0x06, 0x5f, 0xf2, 0xd8,
];
/// La cadena del bloque en casi todos los casos.
const OWN_CHAIN: u64 = 1;
/// Una cadena que no es la del bloque.
const FOREIGN_CHAIN: u64 = 2;
/// El campo de caso que distingue este formato del de un `state_test`.
const CASE_KEY: &str = "txSignature";
/// `v` de una legacy EIP-155: `chainId·2 + 35 + paridad`.
const EIP155_V_OFFSET: u64 = 35;
/// `v` de una legacy pre-EIP-155: `27 + paridad`.
const PRE155_V_OFFSET: u64 = 27;
/// Los `v` legacy del barrido: los dos bordes de cada rango válido y sus
/// vecinos inválidos (26, 29, 33, 34).
const LEGACY_V_SWEEP: [u64; 12] = [26, 27, 28, 29, 33, 34, 35, 36, 37, 38, 39, 40];
/// Bytes de tipo que no son una tx: el siguiente libre después de 7702 y el
/// último del rango de EIP-2718.
const UNKNOWN_TYPE_BYTES: [u8; 2] = [0x05, 0x7f];

/// El orden del grupo de secp256k1: `n = 2·(n/2) + 1`.
fn secp256k1n() -> U256 {
    SECP256K1N_HALF
        .saturating_add(SECP256K1N_HALF)
        .saturating_add(U256::from(1u8))
}

/// `true` si el archivo es de este formato (y no un `state_test`).
pub fn is_tx_signature_file(raw: &str) -> bool {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return false;
    };
    map.values().any(|case| case.get(CASE_KEY).is_some())
}

/// Un caso: el envelope crudo y el `chainId` del bloque.
struct Case {
    name: String,
    block_chain_id: u64,
    tx_bytes: Vec<u8>,
}

fn parse(raw: &str) -> Result<Vec<Case>, String> {
    let Value::Object(map) =
        serde_json::from_str::<Value>(raw).map_err(|e| format!("JSON inválido: {e}"))?
    else {
        return Err("el set no es un objeto JSON".to_owned());
    };
    let mut cases = Vec::new();
    for (name, body) in map {
        let inner = body
            .get(CASE_KEY)
            .ok_or_else(|| format!("{name}: falta `{CASE_KEY}`"))?;
        let chain = inner
            .get("blockChainId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{name}: falta blockChainId"))?;
        let chain = u64::from_str_radix(chain.trim_start_matches("0x"), 16)
            .map_err(|e| format!("{name}: blockChainId inválido: {e}"))?;
        let bytes = inner
            .get("txbytes")
            .ok_or_else(|| format!("{name}: falta txbytes"))?;
        let bytes = crate::fixture::hex_bytes(bytes).map_err(|e| format!("{name}: {e}"))?;
        cases.push(Case {
            name,
            block_chain_id: chain,
            tx_bytes: bytes.to_vec(),
        });
    }
    Ok(cases)
}

/// Nuestra ruta: la del guest.
fn ours(case: &Case) -> Result<Address, String> {
    let firmada = decode_2718(&case.tx_bytes).map_err(|e| e.0.to_owned())?;
    let tx = firmada
        .recover(case.block_chain_id)
        .map_err(|e| e.0.to_owned())?;
    Ok(Address::from(tx.sender.into_array()))
}

/// El oráculo: decoder de alloy + chequeo de `chainId` de revm +
/// `recover_signer` (EIP-2).
fn oracle(case: &Case) -> Result<Address, String> {
    let envelope = TxEnvelope::decode_2718_exact(&case.tx_bytes)
        .map_err(|e| format!("alloy no decodifica: {e}"))?;
    match envelope.chain_id() {
        Some(chain) if chain != case.block_chain_id => {
            return Err("revm: InvalidChainId".to_owned());
        }
        None if !envelope.is_legacy() => return Err("revm: MissingChainId".to_owned()),
        _ => {}
    }
    envelope
        .recover_signer()
        .map_err(|e| format!("alloy no recupera: {e}"))
}

/// Corre un archivo del set. Devuelve `(casos, divergencias)`.
pub fn run_file(raw: &str, label: &str) -> (u32, u32) {
    let cases = match parse(raw) {
        Ok(cases) => cases,
        Err(e) => {
            eprintln!("[FAIL] {label}: {e}");
            return (0, 1);
        }
    };
    let mut ran = 0u32;
    let mut diverged = 0u32;
    for case in &cases {
        ran = ran.saturating_add(1);
        match (ours(case), oracle(case)) {
            (Ok(a), Ok(b)) if a == b => eprintln!("[SAME] {}: recuperan {a}", case.name),
            (Err(a), Err(b)) => eprintln!("[SAME] {}: los dos rechazan ({a} | {b})", case.name),
            (a, b) => {
                diverged = diverged.saturating_add(1);
                eprintln!("[DIFF] {}: nuestro {a:?} · oráculo {b:?}", case.name);
            }
        }
    }
    (ran, diverged)
}

// ---------------------------------------------------------------------------
// El generador.
// ---------------------------------------------------------------------------

/// Una firma cruda: `v`, `r`, `s` tal como viajan en el envelope.
#[derive(Clone, Copy)]
struct Vrs {
    v: U256,
    r: U256,
    s: U256,
}

/// Firma el hash con la clave fija. Devuelve `(r, s, paridad)`.
fn sign(hash: B256) -> Result<(U256, U256, u64), String> {
    let key = SigningKey::from_slice(&SECRET).map_err(|e| format!("clave inválida: {e}"))?;
    let (firma, recid) = key
        .sign_prehash_recoverable(hash.as_slice())
        .map_err(|e| format!("no se pudo firmar: {e}"))?;
    Ok((
        U256::from_be_slice(&firma.r().to_bytes()),
        U256::from_be_slice(&firma.s().to_bytes()),
        u64::from(recid.to_byte() & 1),
    ))
}

/// El envelope con una firma ARBITRARIA: los campos los encodea alloy y el
/// `v`/`r`/`s` va crudo, para poder escribir los que alloy no representaría
/// (`v = 29`, `yParity = 2`).
fn envelope<T: RlpEcdsaEncodableTx>(tx: &T, type_byte: Option<u8>, sig: Vrs) -> Vec<u8> {
    let mut payload = Vec::new();
    tx.rlp_encode_fields(&mut payload);
    sig.v.encode(&mut payload);
    sig.r.encode(&mut payload);
    sig.s.encode(&mut payload);
    let mut out = Vec::new();
    if let Some(byte) = type_byte {
        out.push(byte);
    }
    Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

fn push_case(
    out: &mut Map<String, Value>,
    name: String,
    comment: &str,
    block_chain_id: u64,
    bytes: &[u8],
) {
    let mut inner = Map::new();
    inner.insert(
        "blockChainId".to_owned(),
        Value::String(format!("0x{block_chain_id:02x}")),
    );
    inner.insert(
        "txbytes".to_owned(),
        Value::String(format!("0x{}", alloy_primitives::hex::encode(bytes))),
    );
    let mut case = Map::new();
    case.insert("_comment".to_owned(), Value::String(comment.to_owned()));
    case.insert(CASE_KEY.to_owned(), Value::Object(inner));
    out.insert(name, Value::Object(case));
}

/// Las variantes de `r`/`s` alrededor de los bordes, sobre una firma real.
fn rs_variants(real: Vrs) -> Vec<(&'static str, &'static str, Vrs)> {
    let n = secp256k1n();
    let half = SECP256K1N_HALF;
    vec![
        ("valid", "firma real: los dos recuperan la clave", real),
        (
            "s_half",
            "s = n/2: el último s que EIP-2 admite; recupera alguna clave",
            Vrs { s: half, ..real },
        ),
        (
            "s_half_plus_1",
            "s = n/2 + 1: el primero que EIP-2 rechaza",
            Vrs {
                s: half.saturating_add(U256::from(1u8)),
                ..real
            },
        ),
        (
            "r_zero",
            "r = 0: fuera de [1, n)",
            Vrs {
                r: U256::ZERO,
                ..real
            },
        ),
        (
            "s_zero",
            "s = 0: fuera de [1, n)",
            Vrs {
                s: U256::ZERO,
                ..real
            },
        ),
        ("r_n", "r = n: fuera de [1, n)", Vrs { r: n, ..real }),
        (
            "s_n",
            "s = n: fuera de [1, n) y además alto",
            Vrs { s: n, ..real },
        ),
        (
            "r_n_plus_1",
            "r = n + 1: apenas por encima del orden",
            Vrs {
                r: n.saturating_add(U256::from(1u8)),
                ..real
            },
        ),
        (
            "r_max",
            "r = 2^256 - 1: el tope de la palabra",
            Vrs {
                r: U256::MAX,
                ..real
            },
        ),
        (
            "s_max",
            "s = 2^256 - 1: el tope de la palabra",
            Vrs {
                s: U256::MAX,
                ..real
            },
        ),
    ]
}

/// Las tipadas: bordes de `r`/`s`, `yParity` fuera de `{0,1}`, paridad
/// invertida y `chainId` ajeno.
fn typed_cases<T>(
    out: &mut Map<String, Value>,
    label: &str,
    type_byte: u8,
    own: &T,
    foreign: &T,
) -> Result<(), String>
where
    T: RlpEcdsaEncodableTx + SignableTransaction<Signature>,
{
    let (r, s, parity) = sign(own.signature_hash())?;
    let real = Vrs {
        v: U256::from(parity),
        r,
        s,
    };
    for (suffix, comment, sig) in rs_variants(real) {
        let bytes = envelope(own, Some(type_byte), sig);
        push_case(out, format!("{label}_{suffix}"), comment, OWN_CHAIN, &bytes);
    }
    let otras = [
        (
            "y_parity_flipped",
            "paridad invertida: recupera OTRA clave",
            parity ^ 1,
        ),
        ("y_parity_2", "yParity = 2: fuera de {0,1}", 2),
        ("y_parity_27", "yParity = 27: un v legacy en una tipada", 27),
    ];
    for (suffix, comment, v) in otras {
        let sig = Vrs {
            v: U256::from(v),
            ..real
        };
        let bytes = envelope(own, Some(type_byte), sig);
        push_case(out, format!("{label}_{suffix}"), comment, OWN_CHAIN, &bytes);
    }
    let (r, s, parity) = sign(foreign.signature_hash())?;
    let bytes = envelope(
        foreign,
        Some(type_byte),
        Vrs {
            v: U256::from(parity),
            r,
            s,
        },
    );
    push_case(
        out,
        format!("{label}_chain_foreign"),
        "firmada bien para la cadena 2 y presentada en un bloque de la cadena 1",
        OWN_CHAIN,
        &bytes,
    );
    push_case(
        out,
        format!("{label}_chain_foreign_in_its_own_block"),
        "la misma tx en un bloque de la cadena 2: válida",
        FOREIGN_CHAIN,
        &bytes,
    );
    Ok(())
}

/// La legacy: bordes de `r`/`s` y el barrido de `v` contra un bloque propio y
/// uno ajeno. Cada `v` válido se firma sobre el mensaje que ese `v` describe
/// (pre-155 o EIP-155 con su cadena), así que el caso aísla la regla del `v`
/// y del `chainId`, no un hash equivocado.
fn legacy_cases(out: &mut Map<String, Value>) -> Result<(), String> {
    let base = TxLegacy {
        chain_id: Some(OWN_CHAIN),
        nonce: 0,
        gas_price: 10,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0xb9)),
        value: U256::from(1u8),
        input: Bytes::new(),
    };
    let (r, s, parity) = sign(base.signature_hash())?;
    let real = Vrs {
        v: U256::from(
            OWN_CHAIN
                .saturating_mul(2)
                .saturating_add(EIP155_V_OFFSET)
                .saturating_add(parity),
        ),
        r,
        s,
    };
    for (suffix, comment, sig) in rs_variants(real) {
        let bytes = envelope(&base, None, sig);
        push_case(out, format!("legacy_{suffix}"), comment, OWN_CHAIN, &bytes);
    }
    for v in LEGACY_V_SWEEP {
        // La cadena que ese `v` declara: `None` para pre-155, `Some` para
        // EIP-155, y la propia para los `v` inválidos (el hash da igual).
        let chain = if v == PRE155_V_OFFSET || v == PRE155_V_OFFSET.saturating_add(1) {
            None
        } else if v >= EIP155_V_OFFSET {
            Some(v.saturating_sub(EIP155_V_OFFSET) / 2)
        } else {
            Some(OWN_CHAIN)
        };
        let tx = TxLegacy {
            chain_id: chain,
            ..base.clone()
        };
        let (r, s, _) = sign(tx.signature_hash())?;
        let bytes = envelope(
            &tx,
            None,
            Vrs {
                v: U256::from(v),
                r,
                s,
            },
        );
        for block in [OWN_CHAIN, FOREIGN_CHAIN] {
            push_case(
                out,
                format!("legacy_v_{v}_block_chain_{block}"),
                "barrido de v: el v elige el mensaje y la cadena; la paridad puede no ser la \
                 de la firma, y entonces los dos tienen que recuperar la MISMA otra clave",
                block,
                &bytes,
            );
        }
    }
    Ok(())
}

/// Bordes de **estructura** sobre un envelope válido: bytes sobrantes, tipo
/// desconocido y payload truncado. Ninguno es una tx, y los dos lados tienen
/// que rechazarlo antes de recuperar nada.
fn structural_cases(out: &mut Map<String, Value>, label: &str, valid: &[u8], typed: bool) {
    let mut sobrante = valid.to_vec();
    sobrante.push(0x00);
    push_case(
        out,
        format!("{label}_trailing_byte"),
        "envelope válido con un byte de más al final",
        OWN_CHAIN,
        &sobrante,
    );
    let truncado = valid
        .get(..valid.len().saturating_sub(1))
        .unwrap_or_default();
    push_case(
        out,
        format!("{label}_truncated"),
        "envelope válido sin su último byte",
        OWN_CHAIN,
        truncado,
    );
    if typed {
        for byte in UNKNOWN_TYPE_BYTES {
            let mut otro = valid.to_vec();
            if let Some(first) = otro.first_mut() {
                *first = byte;
            }
            push_case(
                out,
                format!("{label}_unknown_type_0x{byte:02x}"),
                "el mismo cuerpo con un byte de tipo que EIP-2718 no define acá",
                OWN_CHAIN,
                &otro,
            );
        }
    }
}

/// Un envelope válido (firma real) para los bordes de estructura.
fn valid_envelope<T>(
    tx: &T,
    type_byte: Option<u8>,
    legacy_chain: Option<u64>,
) -> Result<Vec<u8>, String>
where
    T: RlpEcdsaEncodableTx + SignableTransaction<Signature>,
{
    let (r, s, parity) = sign(tx.signature_hash())?;
    let v = match legacy_chain {
        Some(chain) => chain
            .saturating_mul(2)
            .saturating_add(EIP155_V_OFFSET)
            .saturating_add(parity),
        None => parity,
    };
    Ok(envelope(
        tx,
        type_byte,
        Vrs {
            v: U256::from(v),
            r,
            s,
        },
    ))
}

/// El set entero, como JSON listo para escribir.
///
/// # Errors
/// Si `k256` no puede firmar (no debería: la clave es fija y válida).
pub fn generate() -> Result<String, String> {
    let mut out = Map::new();
    legacy_cases(&mut out)?;

    let to = Address::repeat_byte(0xb9);
    let t2930 = |chain_id| TxEip2930 {
        chain_id,
        gas_price: 10,
        gas_limit: 30_000,
        to: TxKind::Call(to),
        value: U256::from(1u8),
        ..Default::default()
    };
    typed_cases(
        &mut out,
        "eip2930",
        0x01,
        &t2930(OWN_CHAIN),
        &t2930(FOREIGN_CHAIN),
    )?;

    let t1559 = |chain_id| TxEip1559 {
        chain_id,
        max_fee_per_gas: 20,
        max_priority_fee_per_gas: 1,
        gas_limit: 21_000,
        to: TxKind::Call(to),
        value: U256::from(1u8),
        ..Default::default()
    };
    typed_cases(
        &mut out,
        "eip1559",
        0x02,
        &t1559(OWN_CHAIN),
        &t1559(FOREIGN_CHAIN),
    )?;
    let legacy = TxLegacy {
        chain_id: Some(OWN_CHAIN),
        gas_price: 10,
        gas_limit: 21_000,
        to: TxKind::Call(to),
        value: U256::from(1u8),
        ..Default::default()
    };
    let valid = valid_envelope(&legacy, None, Some(OWN_CHAIN))?;
    structural_cases(&mut out, "legacy", &valid, false);
    let valid = valid_envelope(&t1559(OWN_CHAIN), Some(0x02), None)?;
    structural_cases(&mut out, "eip1559", &valid, true);

    let t4844 = |chain_id| TxEip4844 {
        chain_id,
        max_fee_per_gas: 20,
        max_priority_fee_per_gas: 1,
        gas_limit: 21_000,
        to,
        max_fee_per_blob_gas: 1,
        blob_versioned_hashes: vec![B256::with_last_byte(1)],
        ..Default::default()
    };
    typed_cases(
        &mut out,
        "eip4844",
        0x03,
        &t4844(OWN_CHAIN),
        &t4844(FOREIGN_CHAIN),
    )?;

    // Una tupla con firma de relleno: la regla bajo prueba es la firma de la
    // tx, pero la tupla entra al hash que se firma y así lo ejercita.
    let tupla = SignedAuthorization::new_unchecked(
        Authorization {
            chain_id: U256::from(OWN_CHAIN),
            address: Address::repeat_byte(0xd0),
            nonce: 0,
        },
        0,
        U256::from(1u8),
        U256::from(1u8),
    );
    let t7702 = |chain_id| TxEip7702 {
        chain_id,
        max_fee_per_gas: 20,
        max_priority_fee_per_gas: 1,
        gas_limit: 50_000,
        to,
        authorization_list: vec![tupla.clone()],
        ..Default::default()
    };
    typed_cases(
        &mut out,
        "eip7702",
        0x04,
        &t7702(OWN_CHAIN),
        &t7702(FOREIGN_CHAIN),
    )?;

    serde_json::to_string_pretty(&Value::Object(out))
        .map(|s| format!("{s}\n"))
        .map_err(|e| format!("no se pudo serializar: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El set commiteado es exactamente lo que el generador produce: un
    /// fixture editado a mano (o un generador cambiado sin regenerar) deja de
    /// ser evidencia de lo que el generador dice que prueba.
    #[test]
    fn the_committed_set_is_what_the_generator_produces() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/diff/tx-signature/tx-signature.json");
        let committed = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => panic!("no se pudo leer {}: {e}", path.display()),
        };
        match generate() {
            Ok(fresh) => assert_eq!(
                committed, fresh,
                "regenerá con scripts/gen-tx-signature-fixtures.sh"
            ),
            Err(e) => panic!("el generador falló: {e}"),
        }
    }

    /// El formato se reconoce por su campo de caso, y un `state_test` no se
    /// confunde con él.
    #[test]
    fn the_format_is_detected_by_its_case_key() {
        assert!(is_tx_signature_file(
            r#"{"c": {"txSignature": {"blockChainId": "0x01", "txbytes": "0x"}}}"#
        ));
        assert!(!is_tx_signature_file(r#"{"c": {"transaction": {}}}"#));
        assert!(!is_tx_signature_file("no es json"));
    }

    /// Un envelope vacío lo rechazan los dos: el veredicto es acuerdo, no un
    /// panic de ninguno de los dos decoders.
    #[test]
    fn an_empty_envelope_is_rejected_by_both_sides() {
        let case = Case {
            name: "vacio".to_owned(),
            block_chain_id: OWN_CHAIN,
            tx_bytes: Vec::new(),
        };
        assert!(ours(&case).is_err());
        assert!(oracle(&case).is_err());
    }
}
