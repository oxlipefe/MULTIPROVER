//! Precompiles básicas (slice 2.8a, task 012): ECRECOVER, SHA256, RIPEMD160,
//! IDENTITY. El resto del rango reservado (`0x05..=0x11`, MODEXP/BN254/
//! BLAKE2F/KZG/BLS12-381) sigue fail-closed en `frames.rs` — dueño de
//! 2.8b-2.8f.
//!
//! **No es un opcode.** Un precompile corre SÍNCRONAMENTE contra
//! `(input, gas_limit)` y no toca el `Journal` ni el frame stack — eso lo
//! decide el CALLER (`frames.rs::open_frame`/la apertura del frame raíz), que
//! ya transfirió el `value` y sabe cómo traducir el resultado a lo que ve el
//! caller. Esta separación es deliberada: los mismos 4 precompiles se pueden
//! testear con inputs/gas puros, sin journal ni checkpoint de por medio.
//!
//! Verificado contra el source real de `revm-precompile` =34.0.0 vendoreado
//! (`secp256k1.rs`/`secp256k1/k256.rs`/`hash.rs`/`identity.rs`,
//! `utilities.rs::calc_linear_cost`) — no reconstrucción de memoria.

use alloc::vec::Vec;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use repo_b_common::primitives::{Bytes, keccak256};
use ripemd::Digest as _;

/// Direcciones (último byte) de los cuatro precompiles que este slice
/// implementa. `frames::LAST_PRECOMPILE` sigue siendo el borde del rango
/// RESERVADO completo (hasta BLS12-381, EIP-2537) — estos IDs son el
/// subconjunto que además sabe CORRER.
pub(crate) const ECRECOVER: u8 = 0x01;
pub(crate) const SHA256: u8 = 0x02;
pub(crate) const RIPEMD160: u8 = 0x03;
pub(crate) const IDENTITY: u8 = 0x04;
pub(crate) const LAST_IMPLEMENTED: u8 = IDENTITY;

const ECRECOVER_GAS: u64 = 3_000;
const SHA256_BASE_GAS: u64 = 60;
const SHA256_WORD_GAS: u64 = 12;
const RIPEMD160_BASE_GAS: u64 = 600;
const RIPEMD160_WORD_GAS: u64 = 120;
const IDENTITY_BASE_GAS: u64 = 15;
const IDENTITY_WORD_GAS: u64 = 3;

/// Tamaño del input right-padded de ECRECOVER: 32 (hash) + 32 (`v`) + 32
/// (`r`) + 32 (`s`).
const ECRECOVER_INPUT_LEN: usize = 128;

/// Resultado de correr un precompile con éxito: gas efectivamente cobrado
/// (`<= gas_limit`, YA verificado) y el output.
pub(crate) struct Output {
    pub gas_used: u64,
    pub data: Bytes,
}

/// Corre el precompile `id` (el caller YA validó que está en
/// `ECRECOVER..=LAST_IMPLEMENTED`, ver `frames::precompile_id`).
///
/// `Err(())` = sin gas suficiente: el ÚNICO modo de fallo compartido por los
/// cuatro (task 012 §4) — el caller lo trata como el OOG normal de cualquier
/// sub-frame, no como un caso especial. ECRECOVER tiene ADEMÁS un modo de
/// fallo propio (firma inválida) que **no** es un `Err` acá: es un `Ok` con
/// output vacío (§4 del task-file, verificado contra `secp256k1.rs`).
pub(crate) fn run(id: u8, input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    match id {
        ECRECOVER => ecrecover(input, gas_limit),
        SHA256 => hash_precompile(input, gas_limit, SHA256_BASE_GAS, SHA256_WORD_GAS, sha256),
        RIPEMD160 => hash_precompile(
            input,
            gas_limit,
            RIPEMD160_BASE_GAS,
            RIPEMD160_WORD_GAS,
            ripemd160,
        ),
        IDENTITY => identity(input, gas_limit),
        _ => Err(()), // inalcanzable: el caller ya filtró el rango.
    }
}

/// `60 + 12·⌈len/32⌉` (SHA256) / `600 + 120·⌈len/32⌉` (RIPEMD160) /
/// `15 + 3·⌈len/32⌉` (IDENTITY) — misma fórmula lineal, verificada contra
/// `calc_linear_cost` de revm. `checked_*` explícito: un `len` que no entra
/// en `u64` o un costo que desborda son fail-closed (tratados como OOG, nunca
/// wrapping) — inalcanzable en la práctica (el gas de memoria del CALL que
/// arma el input ya lo habría agotado mucho antes).
fn linear_cost(len: usize, base: u64, per_word: u64) -> Option<u64> {
    let len = u64::try_from(len).ok()?;
    let words = len.checked_add(31)?.checked_div(32)?;
    words.checked_mul(per_word)?.checked_add(base)
}

fn hash_precompile(
    input: &[u8],
    gas_limit: u64,
    base: u64,
    per_word: u64,
    digest: fn(&[u8]) -> Bytes,
) -> Result<Output, ()> {
    let gas_used = linear_cost(input.len(), base, per_word).ok_or(())?;
    if gas_used > gas_limit {
        return Err(());
    }
    Ok(Output {
        gas_used,
        data: digest(input),
    })
}

fn sha256(input: &[u8]) -> Bytes {
    let digest = sha2::Sha256::digest(input);
    Bytes::copy_from_slice(digest.as_ref())
}

/// RIPEMD160 produce 20 bytes; la EVM los quiere left-padded a 32 (12 bytes
/// de cero + los 20 del hash) — mismo layout que revm (`hash.rs`: escribe el
/// digest directo en `output[12..]`, dejando el resto en el cero con el que
/// arrancó el buffer).
fn ripemd160(input: &[u8]) -> Bytes {
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher.finalize_into((&mut output[12..]).into());
    Bytes::copy_from_slice(&output)
}

fn identity(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    let gas_used = linear_cost(input.len(), IDENTITY_BASE_GAS, IDENTITY_WORD_GAS).ok_or(())?;
    if gas_used > gas_limit {
        return Err(());
    }
    Ok(Output {
        gas_used,
        data: Bytes::copy_from_slice(input),
    })
}

/// ECRECOVER (`0x01`). Costo FLAT (task 012 §2) — a diferencia de los otros
/// tres, no depende de `len(input)`.
///
/// Semántica de fallo (task 012 §4, verificada contra `secp256k1.rs`/
/// `secp256k1/k256.rs` de revm-precompile =34.0.0): la ÚNICA `Err` es sin gas
/// suficiente. Cualquier firma inválida —`v` fuera de `{27,28}`, `r`/`s` en 0
/// o `>= n` (rechazados por `Signature::from_slice`, que exige el rango
/// `1..n`), o una recuperación que matemáticamente no da un punto en la curva
/// (`recover_from_prehash` con un `r` que no decomprime)— es un CALL
/// EXITOSO con el gas cobrado igual y el output VACÍO, nunca un halt.
///
/// **Corrección sobre la reconstrucción del task-file (verificada contra el
/// source, no asumida): "s" alto NO se rechaza.** `k256`
/// (`ecdsa::Signature::normalize_s`) normaliza cualquier `s` alto a su
/// complemento `n - s` y flipea el bit de paridad de `v` — la EIP-2 de "low
/// s" es una regla de VALIDACIÓN DE TX (`Transaction.sender`, fuera de este
/// slice), no del precompile. Una firma de `s` alto recupera la MISMA
/// dirección que su contraparte de `s` bajo (malleability clásica de
/// secp256k1) — ver el fixture `ecrecover.json` y el finding en el
/// attempt_log.
fn ecrecover(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    if ECRECOVER_GAS > gas_limit {
        return Err(());
    }
    let padded = right_pad(input, ECRECOVER_INPUT_LEN);
    let empty = || {
        Ok(Output {
            gas_used: ECRECOVER_GAS,
            data: Bytes::new(),
        })
    };
    // `v`: entero big-endian de 32 bytes, válido solo si vale 27 o 28.
    let Some(v_byte) = padded.get(63).copied() else {
        return empty();
    };
    if !padded[32..63].iter().all(|byte| *byte == 0) || !matches!(v_byte, 27 | 28) {
        return empty();
    }
    let recid_byte = v_byte - 27;

    let Some(address) = recover_address(&padded[64..128], recid_byte, &padded[0..32]) else {
        return empty();
    };
    Ok(Output {
        gas_used: ECRECOVER_GAS,
        data: address,
    })
}

/// `None` = firma inválida en cualquiera de sus formas (rango de `r`/`s`,
/// `RecoveryId` inválido — inalcanzable acá porque `recid_byte` ya viene de
/// `{0,1}` tras el `v` normalizado, o recuperación que no da un punto
/// válido). El caller lo traduce a "éxito con output vacío" (§4).
fn recover_address(sig_bytes: &[u8], recid_byte: u8, msg: &[u8]) -> Option<Bytes> {
    let mut signature = Signature::from_slice(sig_bytes).ok()?;
    let mut recid_byte = recid_byte;
    // BIP-62 / RustCrypto `normalize_s`: un `s` alto se reemplaza por `n - s`
    // y el bit de paridad de la recovery id se invierte — la MISMA firma
    // matemáticamente, no una rechazada (ver doc de `ecrecover`).
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        recid_byte ^= 1;
    }
    let recovery_id = RecoveryId::from_byte(recid_byte)?;
    let key = VerifyingKey::recover_from_prehash(msg, &signature, recovery_id).ok()?;
    // Layout de revm (`secp256k1/k256.rs`): keccak256 de los 64 bytes de
    // punto sin comprimir (se descarta el primer byte 0x04 del encoding
    // sec1), los primeros 12 bytes del hash se ponen en cero y el resto
    // queda como los 20 bytes de la dirección, left-padded a 32.
    let uncompressed = key.to_encoded_point(false);
    let mut hash = keccak256(&uncompressed.as_bytes()[1..]);
    hash.0[..12].fill(0);
    Some(Bytes::copy_from_slice(hash.as_slice()))
}

/// Right-pad con ceros hasta `len` (ECRECOVER siempre lee una ventana fija de
/// 128 bytes, con o sin suficiente input — mismo `right_pad` de revm).
fn right_pad(input: &[u8], len: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    let n = input.len().min(len);
    out[..n].copy_from_slice(&input[..n]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector real de secp256k1: firma generada con `k256::ecdsa::SigningKey`
    /// sobre una clave privada fija (RFC6979 determinista — no un valor
    /// inventado a mano) en un generador standalone (offline, fuera de este
    /// crate `no_std` porque firmar no es algo que el motor necesite; solo
    /// recuperar). Verificado ahí mismo con un round-trip firmar→recuperar→
    /// misma dirección ANTES de copiar los bytes acá. Los MISMOS bytes están
    /// en `scripts/gen-precompile-basic-fixtures.py`, para que el fixture del
    /// diferencial vs revm ejercite exactamente esta firma.
    const MSG: [u8; 32] = hex32("c84960bf5f880448ea5fa2d25a2095f677fb4b11e026748e205594f9e77a4a79");
    const R: [u8; 32] = hex32("46072087b50b111047dbdd86dc58a4ac8d597693950eb2e2d37d733107b55dfd");
    const S_LOW: [u8; 32] =
        hex32("65c753fef8762f3662275adea6691bd2c623af4ebd14447ea503aa1af5b9bfe6");
    const V_LOW: u8 = 27;
    /// `n - S_LOW` (secp256k1 order) con `v` de paridad flipeada: la MISMA
    /// firma bajo malleability (BIP-62) — normaliza al par de arriba
    /// (verificado en el generador).
    const S_HIGH: [u8; 32] =
        hex32("9a38ac010789d0c99dd8a5215996e42bf48b2d97f2345bbd1aceb471da7c815b");
    const V_HIGH: u8 = 28;
    /// Dirección esperada (últimos 20 bytes de este hash de 32).
    const EXPECTED_ADDR: [u8; 32] =
        hex32("00000000000000000000000019e7e376e7c213b7e7e7e46cc70a5dd086daff2a");

    /// `r` para el que NINGUNA paridad decomprime a un punto de la curva
    /// (buscado por fuerza bruta en el generador desde `r=1`) — el caso
    /// "recuperación matemáticamente inválida" de la task 012 §4, distinto de
    /// "v fuera de {27,28}" y de "r/s fuera de rango".
    const NO_POINT_MSG: [u8; 32] =
        hex32("428b06553b786f37d274e3940d822d5a59f0c5c9417289e8b3cb341083e2a3c1");
    const NO_POINT_R: [u8; 32] =
        hex32("0000000000000000000000000000000000000000000000000000000000000005");
    const NO_POINT_S: [u8; 32] =
        hex32("0101010101010101010101010101010101010101010101010101010101010101");

    /// Parseo hex sin dependencias (const, evaluado en compile-time): el
    /// input real de un precompile no pasa por acá, solo estos vectores fijos
    /// de test. `s` es un literal de 64 caracteres hex (32 bytes) — un largo
    /// distinto no compila (asegurado por el `assert!` interno).
    const fn hex32(s: &str) -> [u8; 32] {
        let bytes = s.as_bytes();
        assert!(
            bytes.len() == 64,
            "el vector de test debe tener 64 hex chars"
        );
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = hex_byte(bytes[i * 2]) * 16 + hex_byte(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn hex_byte(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("carácter hex inválido en un vector de test"),
        }
    }

    fn ecrecover_input(msg: [u8; 32], v: u8, r: [u8; 32], s: [u8; 32]) -> alloc::vec::Vec<u8> {
        let mut input = alloc::vec![0u8; 128];
        input[0..32].copy_from_slice(&msg);
        input[63] = v;
        input[64..96].copy_from_slice(&r);
        input[96..128].copy_from_slice(&s);
        input
    }

    #[track_caller]
    fn must_run(id: u8, input: &[u8], gas_limit: u64) -> Output {
        match run(id, input, gas_limit) {
            Ok(output) => output,
            Err(()) => panic!("run() no debería fallar acá (gas suficiente)"),
        }
    }

    #[test]
    fn ecrecover_with_a_valid_signature_recovers_the_signer_address() {
        let input = ecrecover_input(MSG, V_LOW, R, S_LOW);
        let output = must_run(ECRECOVER, &input, ECRECOVER_GAS);
        assert_eq!(output.gas_used, ECRECOVER_GAS);
        assert_eq!(output.data.as_ref(), &EXPECTED_ADDR[..]);
    }

    /// Corrección sobre la reconstrucción del task-file (ver doc de
    /// `ecrecover`): "s" alto NO se rechaza, recupera la MISMA dirección.
    #[test]
    fn ecrecover_with_a_high_s_signature_recovers_the_same_address_via_malleability() {
        let input = ecrecover_input(MSG, V_HIGH, R, S_HIGH);
        let output = must_run(ECRECOVER, &input, ECRECOVER_GAS);
        assert_eq!(output.data.as_ref(), &EXPECTED_ADDR[..]);
    }

    #[test]
    fn ecrecover_with_an_invalid_v_succeeds_with_empty_output() {
        let input = ecrecover_input(MSG, 5, R, S_LOW);
        let output = must_run(ECRECOVER, &input, ECRECOVER_GAS);
        assert_eq!(output.gas_used, ECRECOVER_GAS);
        assert!(output.data.is_empty());
    }

    #[test]
    fn ecrecover_with_a_signature_that_recovers_no_valid_point_succeeds_with_empty_output() {
        let input = ecrecover_input(NO_POINT_MSG, 27, NO_POINT_R, NO_POINT_S);
        let output = must_run(ECRECOVER, &input, ECRECOVER_GAS);
        assert!(output.data.is_empty());
    }

    #[test]
    fn ecrecover_out_of_gas_is_the_only_err() {
        let input = ecrecover_input(MSG, V_LOW, R, S_LOW);
        assert!(run(ECRECOVER, &input, ECRECOVER_GAS - 1).is_err());
    }

    #[test]
    fn sha256_of_empty_input_matches_the_known_digest() {
        let output = must_run(SHA256, &[], 1_000);
        assert_eq!(output.gas_used, SHA256_BASE_GAS);
        assert_eq!(
            output.data.as_ref(),
            &hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[..]
        );
    }

    #[test]
    fn sha256_charges_a_full_word_for_one_byte_over_the_boundary() {
        // 33 bytes cruza el borde de una palabra de 32: ⌈33/32⌉ = 2.
        let output = must_run(SHA256, &[0u8; 33], 1_000);
        assert_eq!(output.gas_used, SHA256_BASE_GAS + 2 * SHA256_WORD_GAS);
    }

    #[test]
    fn ripemd160_left_pads_the_20_byte_digest_to_32() {
        let output = must_run(RIPEMD160, &[], 10_000);
        assert_eq!(output.gas_used, RIPEMD160_BASE_GAS);
        assert_eq!(output.data.len(), 32);
        assert!(output.data[..12].iter().all(|byte| *byte == 0));
        // digest RIPEMD160("") conocido.
        assert_eq!(
            &output.data[12..],
            &hex32("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31")[12..]
        );
    }

    #[test]
    fn identity_copies_the_input_byte_for_byte() {
        let input = [1u8, 2, 3, 4, 5];
        let output = must_run(IDENTITY, &input, 100);
        assert_eq!(output.gas_used, IDENTITY_BASE_GAS + IDENTITY_WORD_GAS);
        assert_eq!(output.data.as_ref(), &input[..]);
    }

    #[test]
    fn identity_out_of_gas() {
        assert!(run(IDENTITY, &[0u8; 64], 1).is_err());
    }
}
