//! EIP-7685 — los *general purpose execution layer requests* y su commitment.
//!
//! Tres fuentes, y cada una falla distinto:
//!
//! - **tipo 0, depósitos (EIP-6110):** se parsean de los **logs** que el
//!   contrato de depósito emitió durante el bloque. El layout del evento se
//!   **valida**, no se asume: un log con la forma equivocada invalida el bloque.
//! - **tipo 1, withdrawal requests (EIP-7002):** el **output crudo** de la
//!   system call al predeploy. El contrato ya serializa; acá no se re-formatea.
//! - **tipo 2, consolidations (EIP-7251):** ídem, con su propio predeploy.
//!
//! Vive en el harness y no en el motor por el mismo corte que `encode.rs`:
//! es derivación y verificación del header, no transición de estado. Y por la
//! misma regla, **nada de esto se compara contra sí mismo**: el `requestsHash`
//! se computa de lo que el bloque produjo y se contrasta contra el campo del
//! header. Tomar el hash del fixture convertiría el chequeo en tautología.

use repo_b_common::primitives::{Address, B256};
use repo_b_common::receipt::{Log, Receipt};
use sha2::{Digest, Sha256};

/// EIP-6110 — el contrato de depósito del consensus layer. Vive acá y no en el
/// motor (a diferencia de las tres direcciones de system call): el EVM nunca lo
/// llama, es el harness el que reconoce sus logs al derivar los requests.
/// (`0x00000000219ab540356cBB839Cbe05303d7705Fa`.)
pub const DEPOSIT_CONTRACT_ADDRESS: Address = Address::new([
    0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe, 0x05, 0x30,
    0x3d, 0x77, 0x05, 0xfa,
]);

/// EIP-6110 — `keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)")`, el
/// primer topic del evento.
///
/// **La dirección sola NO alcanza como filtro**, y eso lo decidió el corpus:
/// los 4 casos de `test_extra_logs` son bloques VÁLIDOS en los que el contrato
/// de depósito emite además otro evento (uno de ellos, sin topics). Sin este
/// chequeo, ese log entra al parser de depósitos, falla el largo de 576 y el
/// harness rechaza un bloque bueno. Un log del contrato que no es un
/// `DepositEvent` se **ignora**; no invalida nada.
const DEPOSIT_EVENT_SIGNATURE_HASH: B256 = B256::new([
    0x64, 0x9b, 0xbc, 0x62, 0xd0, 0xe3, 0x13, 0x42, 0xaf, 0xea, 0x4e, 0x5c, 0xd8, 0x2d, 0x40, 0x49,
    0xe7, 0xe1, 0xee, 0x91, 0x2f, 0xc0, 0x88, 0x9a, 0xa7, 0x90, 0x80, 0x3b, 0xe3, 0x90, 0x38, 0xc5,
]);

/// Los tres tipos de request, en el orden ASCENDENTE que EIP-7685 exige. El
/// byte de tipo va adelante de la lista serializada de esa fuente.
pub const DEPOSIT_REQUEST_TYPE: u8 = 0x00;
pub const WITHDRAWAL_REQUEST_TYPE: u8 = 0x01;
pub const CONSOLIDATION_REQUEST_TYPE: u8 = 0x02;

/// EIP-6110 — el largo EXACTO del `data` de un `DepositEvent`. No hay
/// right-pad: un log de otro largo es un layout inválido, no un evento corto.
const DEPOSIT_EVENT_LENGTH: usize = 576;

/// Los cinco offsets y los cinco tamaños del ABI del evento, en el orden en el
/// que aparecen. Cada uno es una palabra de 32 bytes con un valor FIJO: el
/// contrato de depósito canónico emite siempre la misma forma, así que
/// cualquier desvío es un contrato modificado y el bloque es inválido.
///
/// Se validan los diez: el set los ejercita uno por uno (20 fixtures de
/// `test_invalid_layout`, cada campo con `0` y con `2^256−1`).
const DEPOSIT_LAYOUT: [(usize, u64, &str); 10] = [
    (0, 160, "offset de pubkey"),
    (32, 256, "offset de withdrawal credentials"),
    (64, 320, "offset de amount"),
    (96, 384, "offset de signature"),
    (128, 512, "offset de index"),
    (160, 48, "tamaño de pubkey"),
    (256, 32, "tamaño de withdrawal credentials"),
    (320, 8, "tamaño de amount"),
    (384, 96, "tamaño de signature"),
    (512, 8, "tamaño de index"),
];

/// Los cinco campos del request de depósito, como `(offset, largo)` dentro del
/// `data` del log. El request serializado es su concatenación, sin padding.
const DEPOSIT_FIELDS: [(usize, usize); 5] = [
    (192, 48), // pubkey
    (288, 32), // withdrawal credentials
    (352, 8),  // amount
    (416, 96), // signature
    (544, 8),  // index
];

/// Largo del request de depósito serializado: la suma de los cinco campos.
pub const DEPOSIT_REQUEST_LENGTH: usize = 48 + 32 + 8 + 96 + 8;

/// Un request es su byte de tipo seguido de la lista serializada de esa fuente.
/// Una fuente que no produjo nada **no entra**: EIP-7685 excluye del hash toda
/// lista vacía, y ese es el motivo por el que un bloque sin requests tiene el
/// `requestsHash` de la cadena de bytes vacía y no el de tres listas nulas.
fn typed_request(request_type: u8, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(request_type);
    out.extend_from_slice(payload);
    Some(out)
}

/// EIP-7685 — `sha256(sha256(request_0) ‖ sha256(request_1) ‖ …)`.
///
/// **SHA-256, no Keccak**: es el único commitment del header que no usa la
/// función de hash de la EVM, porque lo consume el consensus layer.
pub fn requests_hash(requests: &[Vec<u8>]) -> B256 {
    let mut outer = Sha256::new();
    for request in requests {
        outer.update(Sha256::digest(request));
    }
    B256::new(outer.finalize().into())
}

/// Arma la lista de requests del bloque, en el orden ascendente de tipo.
///
/// `withdrawal_output` y `consolidation_output` son el output CRUDO de las dos
/// system calls; los depósitos salen de los logs de los receipts.
pub fn collect(
    receipts: &[Receipt],
    withdrawal_output: &[u8],
    consolidation_output: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let deposits = parse_deposits(receipts)?;
    Ok([
        typed_request(DEPOSIT_REQUEST_TYPE, &deposits),
        typed_request(WITHDRAWAL_REQUEST_TYPE, withdrawal_output),
        typed_request(CONSOLIDATION_REQUEST_TYPE, consolidation_output),
    ]
    .into_iter()
    .flatten()
    .collect())
}

/// EIP-6110: los depósitos del bloque, concatenados en el orden en el que se
/// emitieron. Un log del contrato de depósito con un layout que no es el
/// canónico **invalida el bloque** — no se saltea.
fn parse_deposits(receipts: &[Receipt]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for receipt in receipts {
        for log in &receipt.logs {
            if log.address != DEPOSIT_CONTRACT_ADDRESS
                || log.topics.first() != Some(&DEPOSIT_EVENT_SIGNATURE_HASH)
            {
                continue;
            }
            out.extend_from_slice(&extract_deposit_data(log)?);
        }
    }
    Ok(out)
}

/// Valida el layout del `DepositEvent` y devuelve el request serializado.
fn extract_deposit_data(log: &Log) -> Result<[u8; DEPOSIT_REQUEST_LENGTH], String> {
    let data = log.data.as_ref();
    if data.len() != DEPOSIT_EVENT_LENGTH {
        return Err(format!(
            "log del contrato de depósito con {} bytes de data (el evento son {DEPOSIT_EVENT_LENGTH})",
            data.len()
        ));
    }
    for (offset, expected, what) in DEPOSIT_LAYOUT {
        let word = &data[offset..offset + 32];
        // La palabra tiene 32 bytes y el valor esperado entra en 8: los 24
        // bytes de arriba TIENEN que ser cero. Compararlos por separado evita
        // truncar un `2^256−1` a un `u64` que casualmente calce — que es
        // exactamente el vector `value_max_uint256` del set.
        let (high, low) = word.split_at(24);
        if high.iter().any(|byte| *byte != 0) || u64::from_be_bytes(as_word(low)?) != expected {
            return Err(format!("layout del DepositEvent: {what} no es {expected}"));
        }
    }
    let mut request = [0u8; DEPOSIT_REQUEST_LENGTH];
    let mut cursor = 0;
    for (offset, length) in DEPOSIT_FIELDS {
        request[cursor..cursor + length].copy_from_slice(&data[offset..offset + length]);
        cursor += length;
    }
    Ok(request)
}

fn as_word(bytes: &[u8]) -> Result<[u8; 8], String> {
    bytes
        .try_into()
        .map_err(|_| "palabra de layout con largo inesperado".to_owned())
}

#[cfg(test)]
mod tests {
    use repo_b_common::primitives::Bytes;

    use super::*;

    /// El `requestsHash` de un bloque SIN requests es el SHA-256 de la cadena
    /// vacía — no el de tres listas nulas. Es el valor que traen 30 de los 31
    /// headers del fixture `test_valid_multi_type_requests.json`, y la
    /// evidencia de que una lista vacía se EXCLUYE en vez de entrar vacía.
    #[test]
    fn no_requests_is_the_hash_of_the_empty_string() {
        let empty = requests_hash(&[]);
        assert_eq!(
            format!("{empty}"),
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Las tres fuentes vacías dan lo MISMO que ninguna fuente: si una lista
        // vacía entrara al hash, esto no cerraría.
        assert_eq!(collect(&[], &[], &[]), Ok(Vec::new()));
    }

    /// El orden de los tipos es parte del commitment: invertirlo da otro hash.
    #[test]
    fn the_type_order_changes_the_commitment() {
        let ascending = vec![
            vec![WITHDRAWAL_REQUEST_TYPE, 0xaa],
            vec![CONSOLIDATION_REQUEST_TYPE, 0xbb],
        ];
        let descending = vec![
            vec![CONSOLIDATION_REQUEST_TYPE, 0xbb],
            vec![WITHDRAWAL_REQUEST_TYPE, 0xaa],
        ];
        assert_ne!(requests_hash(&ascending), requests_hash(&descending));
    }

    /// El output de las system calls entra CRUDO, con su byte de tipo adelante.
    #[test]
    fn the_system_call_output_enters_raw_behind_its_type_byte() {
        assert_eq!(
            collect(&[], &[0x11, 0x22], &[0x33]),
            Ok(vec![
                vec![WITHDRAWAL_REQUEST_TYPE, 0x11, 0x22],
                vec![CONSOLIDATION_REQUEST_TYPE, 0x33],
            ])
        );
    }

    /// Un byte reconocible por campo, en el orden de `DEPOSIT_FIELDS`.
    const FIELD_MARKERS: [u8; 5] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4];

    /// Un `DepositEvent` canónico: los diez campos de layout en su lugar y los
    /// cinco valores concatenados sin padding.
    fn canonical_deposit_log() -> Log {
        let mut data = vec![0u8; DEPOSIT_EVENT_LENGTH];
        for (offset, expected, _) in DEPOSIT_LAYOUT {
            data[offset + 24..offset + 32].copy_from_slice(&expected.to_be_bytes());
        }
        // Un byte reconocible al principio de cada campo, para poder afirmar
        // que se copian en orden y desde el offset correcto.
        for ((offset, _), marker) in DEPOSIT_FIELDS.iter().zip(FIELD_MARKERS) {
            data[*offset] = marker;
        }
        Log {
            address: DEPOSIT_CONTRACT_ADDRESS,
            topics: vec![DEPOSIT_EVENT_SIGNATURE_HASH],
            data: Bytes::from(data),
        }
    }

    /// La constante no se copia de memoria: se deriva de la firma del evento.
    #[test]
    fn the_event_signature_hash_is_the_keccak_of_its_signature() {
        assert_eq!(
            repo_b_common::primitives::keccak256(
                b"DepositEvent(bytes,bytes,bytes,bytes,bytes)".as_slice()
            ),
            DEPOSIT_EVENT_SIGNATURE_HASH
        );
    }

    /// Un log del contrato de depósito que **no** es un `DepositEvent` se
    /// ignora, aunque su data sea basura: son los 4 casos VÁLIDOS de
    /// `test_extra_logs`, uno de ellos sin ningún topic.
    #[test]
    fn a_non_deposit_event_from_the_deposit_contract_is_ignored() {
        let junk = Bytes::from(vec![0xff; 32]);
        for topics in [Vec::new(), vec![B256::new([0x11; 32])]] {
            let receipt = Receipt {
                success: true,
                cumulative_gas_used: 0,
                logs: vec![Log {
                    address: DEPOSIT_CONTRACT_ADDRESS,
                    topics,
                    data: junk.clone(),
                }],
            };
            assert_eq!(parse_deposits(&[receipt]), Ok(Vec::new()));
        }
    }

    #[test]
    fn a_canonical_deposit_event_yields_its_five_fields_in_order() {
        // Los cinco campos, concatenados sin padding: el marcador de cada uno
        // cae donde termina el anterior.
        let mut expected = [0u8; DEPOSIT_REQUEST_LENGTH];
        let mut cursor = 0;
        for ((_, length), marker) in DEPOSIT_FIELDS.iter().zip(FIELD_MARKERS) {
            expected[cursor] = marker;
            cursor += length;
        }
        assert_eq!(cursor, DEPOSIT_REQUEST_LENGTH);
        assert_eq!(extract_deposit_data(&canonical_deposit_log()), Ok(expected));
    }

    /// Los dos vectores del set por cada campo: `0` y `2^256−1`. El segundo es
    /// el que exige comparar la palabra ENTERA — truncada a 8 bytes,
    /// `2^256−1` da `u64::MAX`, que no calza con ningún valor esperado, pero un
    /// valor como `2^64 + 160` sí calzaría con el offset de pubkey.
    #[test]
    fn every_layout_field_is_validated_against_zero_and_max() {
        for (offset, _, _) in DEPOSIT_LAYOUT {
            let mut zeroed = canonical_deposit_log();
            let mut data = zeroed.data.to_vec();
            data[offset + 24..offset + 32].copy_from_slice(&0u64.to_be_bytes());
            zeroed.data = Bytes::from(data);
            assert!(
                extract_deposit_data(&zeroed).is_err(),
                "el campo en {offset} en CERO tiene que rechazarse"
            );

            let mut maxed = canonical_deposit_log();
            let mut data = maxed.data.to_vec();
            data[offset..offset + 32].fill(0xff);
            maxed.data = Bytes::from(data);
            assert!(
                extract_deposit_data(&maxed).is_err(),
                "el campo en {offset} en 2^256−1 tiene que rechazarse"
            );

            // El vector que solo caza la comparación de la palabra COMPLETA:
            // los 8 bytes bajos son el valor correcto y hay basura arriba.
            let mut smuggled = canonical_deposit_log();
            let mut data = smuggled.data.to_vec();
            data[offset] = 0x01;
            smuggled.data = Bytes::from(data);
            assert!(
                extract_deposit_data(&smuggled).is_err(),
                "el campo en {offset} con los bytes altos sucios tiene que rechazarse"
            );
        }
    }

    /// El largo es EXACTO: ni un byte de más ni de menos (los dos vectores de
    /// `test_invalid_log_length`).
    #[test]
    fn the_event_length_is_exact() {
        for length in [DEPOSIT_EVENT_LENGTH - 1, DEPOSIT_EVENT_LENGTH + 1] {
            let mut log = canonical_deposit_log();
            let mut data = log.data.to_vec();
            data.resize(length, 0);
            log.data = Bytes::from(data);
            assert!(extract_deposit_data(&log).is_err());
        }
    }

    /// Un log de OTRA dirección se ignora, aunque su data sea basura: el
    /// contrato de depósito es el único que produce requests de tipo 0.
    #[test]
    fn a_log_from_another_address_is_ignored() {
        let receipt = Receipt {
            success: true,
            cumulative_gas_used: 0,
            logs: vec![Log {
                address: Address::new([0x42; 20]),
                topics: Vec::new(),
                data: Bytes::from(vec![0xff; 10]),
            }],
        };
        assert_eq!(parse_deposits(&[receipt]), Ok(Vec::new()));
    }
}
