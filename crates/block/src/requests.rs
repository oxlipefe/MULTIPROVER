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
//! El `requestsHash` se computa de lo que el bloque produjo y se contrasta
//! contra el campo del header; tomarlo del header sería una tautología.

use alloc::vec::Vec;

use alloy_primitives::{Address, B256};
use repo_b_common::crypto::Crypto;
use repo_b_common::receipt::{Log, Receipt};
use repo_b_evm::crypto::Active;

use crate::error::BlockError;

/// EIP-6110 — el contrato de depósito del consensus layer. El EVM nunca lo
/// llama: lo que se reconoce son sus logs al derivar los requests.
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
/// de depósito emite además otro evento (uno de ellos, sin topics). Un log del
/// contrato que no es un `DepositEvent` se **ignora**; no invalida nada.
pub const DEPOSIT_EVENT_SIGNATURE_HASH: B256 = B256::new([
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

/// Una palabra del ABI.
const WORD: usize = 32;
/// Los bytes altos de una palabra de layout: el valor esperado entra en los 8
/// de abajo, así que los 24 de arriba TIENEN que ser cero.
const WORD_HIGH: usize = 24;

/// Los cinco offsets y los cinco tamaños del ABI del evento, en el orden en el
/// que aparecen. Cada uno es una palabra de 32 bytes con un valor FIJO: el
/// contrato de depósito canónico emite siempre la misma forma, así que
/// cualquier desvío es un contrato modificado y el bloque es inválido.
///
/// Se validan los diez: el corpus los ejercita uno por uno (cada campo con `0`
/// y con `2^256−1`).
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
/// lista vacía, y por eso un bloque sin requests tiene el `requestsHash` de la
/// cadena vacía y no el de tres listas nulas.
fn typed_request(request_type: u8, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(payload.len().saturating_add(1));
    out.push(request_type);
    out.extend_from_slice(payload);
    Some(out)
}

/// EIP-7685 — `sha256(sha256(request_0) ‖ sha256(request_1) ‖ …)`.
///
/// **SHA-256, no Keccak**: es el único commitment del header que no usa la
/// función de hash de la EVM, porque lo consume el consensus layer. Pasa por el
/// seam `Crypto`, como toda la criptografía del motor.
#[must_use]
pub fn requests_hash(requests: &[Vec<u8>]) -> B256 {
    let mut concatenated = Vec::with_capacity(requests.len().saturating_mul(WORD));
    for request in requests {
        concatenated.extend_from_slice(&Active::sha256(request));
    }
    B256::new(Active::sha256(&concatenated))
}

/// Arma la lista de requests del bloque, en el orden ascendente de tipo.
///
/// `withdrawal_output` y `consolidation_output` son el output CRUDO de las dos
/// system calls; los depósitos salen de los logs de los receipts.
pub fn collect_requests(
    receipts: &[Receipt],
    withdrawal_output: &[u8],
    consolidation_output: &[u8],
) -> Result<Vec<Vec<u8>>, BlockError> {
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
fn parse_deposits(receipts: &[Receipt]) -> Result<Vec<u8>, BlockError> {
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
fn extract_deposit_data(log: &Log) -> Result<[u8; DEPOSIT_REQUEST_LENGTH], BlockError> {
    let data = log.data.as_ref();
    if data.len() != DEPOSIT_EVENT_LENGTH {
        return Err(BlockError::DepositLayout {
            reason: "el data del evento no mide 576 bytes",
        });
    }
    for (offset, expected, what) in DEPOSIT_LAYOUT {
        let word = slice(data, offset, WORD)?;
        // Los bytes altos se comparan por separado: truncar un `2^256−1` a un
        // `u64` que casualmente calce es exactamente el vector
        // `value_max_uint256` del corpus.
        let (high, low) = word.split_at_checked(WORD_HIGH).ok_or(LAYOUT_BUG)?;
        let low: [u8; 8] = low.try_into().map_err(|_| LAYOUT_BUG)?;
        if high.iter().any(|byte| *byte != 0) || u64::from_be_bytes(low) != expected {
            return Err(BlockError::DepositLayout { reason: what });
        }
    }
    let mut request = [0u8; DEPOSIT_REQUEST_LENGTH];
    let mut cursor = 0usize;
    for (offset, length) in DEPOSIT_FIELDS {
        let end = cursor.checked_add(length).ok_or(LAYOUT_BUG)?;
        request
            .get_mut(cursor..end)
            .ok_or(LAYOUT_BUG)?
            .copy_from_slice(slice(data, offset, length)?);
        cursor = end;
    }
    Ok(request)
}

/// Inalcanzable con las tablas de arriba y un `data` de 576 bytes; existe para
/// que un error en las tablas sea un rechazo y no un `panic`.
const LAYOUT_BUG: BlockError = BlockError::DepositLayout {
    reason: "tabla de layout fuera del evento",
};

fn slice(data: &[u8], offset: usize, length: usize) -> Result<&[u8], BlockError> {
    let end = offset.checked_add(length).ok_or(LAYOUT_BUG)?;
    data.get(offset..end).ok_or(LAYOUT_BUG)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use repo_b_common::primitives::Bytes;

    use super::*;

    /// El `requestsHash` de un bloque SIN requests es el SHA-256 de la cadena
    /// vacía — no el de tres listas nulas.
    #[test]
    fn no_requests_is_the_hash_of_the_empty_string() {
        let empty = requests_hash(&[]);
        assert_eq!(
            alloc::format!("{empty}"),
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(collect_requests(&[], &[], &[]), Ok(Vec::new()));
    }

    /// El orden de los tipos es parte del commitment.
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
            collect_requests(&[], &[0x11, 0x22], &[0x33]),
            Ok(vec![
                vec![WITHDRAWAL_REQUEST_TYPE, 0x11, 0x22],
                vec![CONSOLIDATION_REQUEST_TYPE, 0x33],
            ])
        );
    }

    const FIELD_MARKERS: [u8; 5] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4];

    fn write(data: &mut [u8], at: usize, bytes: &[u8]) {
        let end = at.saturating_add(bytes.len());
        match data.get_mut(at..end) {
            Some(target) => target.copy_from_slice(bytes),
            None => panic!("escritura del test fuera del evento"),
        }
    }

    /// Un `DepositEvent` canónico, con un byte reconocible por campo.
    fn canonical_deposit_log() -> Log {
        let mut data = vec![0u8; DEPOSIT_EVENT_LENGTH];
        for (offset, expected, _) in DEPOSIT_LAYOUT {
            write(&mut data, offset + WORD_HIGH, &expected.to_be_bytes());
        }
        for ((offset, _), marker) in DEPOSIT_FIELDS.iter().zip(FIELD_MARKERS) {
            write(&mut data, *offset, &[marker]);
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
    /// ignora, aunque su data sea basura.
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
        let mut expected = [0u8; DEPOSIT_REQUEST_LENGTH];
        let mut cursor = 0;
        for ((_, length), marker) in DEPOSIT_FIELDS.iter().zip(FIELD_MARKERS) {
            write(&mut expected, cursor, &[marker]);
            cursor += length;
        }
        assert_eq!(cursor, DEPOSIT_REQUEST_LENGTH);
        assert_eq!(extract_deposit_data(&canonical_deposit_log()), Ok(expected));
    }

    /// Los dos vectores del corpus por cada campo (`0` y `2^256−1`), y el que
    /// solo caza la comparación de la palabra COMPLETA.
    #[test]
    fn every_layout_field_is_validated_against_zero_and_max() {
        for (offset, _, _) in DEPOSIT_LAYOUT {
            let mutations: [fn(&mut Vec<u8>, usize); 3] = [
                |data, offset| write(data, offset + WORD_HIGH, &0u64.to_be_bytes()),
                |data, offset| write(data, offset, &[0xff; WORD]),
                |data, offset| write(data, offset, &[0x01]),
            ];
            for mutate in mutations {
                let mut log = canonical_deposit_log();
                let mut data = log.data.to_vec();
                mutate(&mut data, offset);
                log.data = Bytes::from(data);
                assert!(
                    extract_deposit_data(&log).is_err(),
                    "el campo en {offset} mutado tiene que rechazarse"
                );
            }
        }
    }

    /// El largo es EXACTO: ni un byte de más ni de menos.
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

    /// Un log de OTRA dirección se ignora, aunque su data sea basura.
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
