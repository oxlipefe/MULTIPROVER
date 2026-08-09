//! Precompiles básicas (slice 2.8a, task 012): ECRECOVER, SHA256, RIPEMD160,
//! IDENTITY. Slice 2.8b (task 013) suma MODEXP. El resto del rango reservado
//! (`0x06..=0x11`, BN254/BLAKE2F/KZG/BLS12-381) sigue fail-closed en
//! `frames.rs` — dueño de 2.8c-2.8f.
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
use repo_b_common::primitives::{Bytes, U256, keccak256};
use ripemd::Digest as _;

/// Direcciones (último byte) de los precompiles que este slice implementa
/// (2.8a + 2.8b). `frames::LAST_PRECOMPILE` sigue siendo el borde del rango
/// RESERVADO completo (hasta BLS12-381, EIP-2537) — estos IDs son el
/// subconjunto que además sabe CORRER.
pub(crate) const ECRECOVER: u8 = 0x01;
pub(crate) const SHA256: u8 = 0x02;
pub(crate) const RIPEMD160: u8 = 0x03;
pub(crate) const IDENTITY: u8 = 0x04;
/// MODEXP (task 013, slice 2.8b, EIP-198/EIP-2565). Aislado en su propio
/// sub-slice: `aurora-engine-modexp` es el eslabón de peor pedigrí de
/// auditoría del set (research `docs/PHASE_2_ROADMAP.md` 2026-08-09).
pub(crate) const MODEXP: u8 = 0x05;
pub(crate) const LAST_IMPLEMENTED: u8 = MODEXP;

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

/// EIP-2565 (Berlin) — el repricing vigente para Cancun+Prague, el scope de
/// este repo. NO EIP-7883/EIP-7823 (Osaka): esos repricean/limitan de nuevo
/// y están fuera de scope (task 013 §Prohibido).
const MODEXP_MIN_GAS: u64 = 200;
/// Multiplicador del término `8·(exp_len-32)` de `calculate_iteration_count`
/// cuando el exponente declarado supera 32 bytes.
const MODEXP_ITERATION_MULTIPLIER: u64 = 8;
const MODEXP_GAS_DIVISOR: u64 = 3;
/// `<length_of_BASE> <length_of_EXPONENT> <length_of_MODULUS>`, 32 bytes
/// big-endian cada uno (EIP-198).
const MODEXP_HEADER_LEN: usize = 96;

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
        MODEXP => modexp(input, gas_limit),
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
/// 128 bytes, con o sin suficiente input — mismo `right_pad` de revm). Si
/// `input` es más largo que `len`, se trunca (no es el caso de ECRECOVER,
/// pero MODEXP lo reusa para tallar el header de 96 bytes exactos de un
/// input arbitrariamente largo).
fn right_pad(input: &[u8], len: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    let n = input.len().min(len);
    out[..n].copy_from_slice(&input[..n]);
    out
}

/// MODEXP (`0x05`, EIP-198, repriced por EIP-2565/Berlin — el repricing
/// vigente para Cancun+Prague, NO Osaka). Verificado contra el source real de
/// `revm-precompile` =34.0.0 vendoreado (`modexp.rs::{berlin_run,
/// berlin_gas_calc, calculate_iteration_count, run_inner}`, task 013
/// attempt_log it.1) — no reconstrucción de memoria.
///
/// A diferencia de ECRECOVER (task 012 §4), bajo Berlin MODEXP NO tiene un
/// modo "éxito con output vacío" propio del algoritmo: cualquier terna
/// `(base, exponente, módulo)` bien formada produce un resultado real y
/// consume gas real. El ÚNICO `Err(())` es "no se puede correr" — sin gas
/// suficiente (incluido el caso de un `base_len`/`mod_len` declarado que no
/// entra en `usize`, que revm modela con su propio halt reason pero que acá
/// comparte el mismo `Err(())` del resto del módulo, mismo criterio que 012).
fn modexp(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    if MODEXP_MIN_GAS > gas_limit {
        return Err(());
    }

    // Header: 3 longitudes de 32 bytes big-endian. `right_pad` tolera un
    // input más corto (o más largo) que 96 bytes.
    let header = right_pad(input, MODEXP_HEADER_LEN);
    let base_len_word = u256_at(&header, 0);
    let exp_len_word = u256_at(&header, 32);
    let mod_len_word = u256_at(&header, 64);

    // `base_len`/`mod_len` gobiernan cuánto se asigna más abajo: si el valor
    // declarado no entra en `usize`, fail-closed explícito (NUNCA wrapping o
    // truncar en silencio). `exp_len` en cambio satura a `usize::MAX` —igual
    // que revm— porque no gobierna ninguna asignación por sí solo (ver nota
    // de seguridad debajo del atajo base_len==0&&mod_len==0): un `exp_len`
    // absurdo siempre termina rechazado por el chequeo de gas.
    let base_len = usize::try_from(base_len_word).map_err(|_| ())?;
    let mod_len = usize::try_from(mod_len_word).map_err(|_| ())?;
    let exp_len = usize::try_from(exp_len_word).unwrap_or(usize::MAX);

    let body = input.get(MODEXP_HEADER_LEN..).unwrap_or(&[]);
    let exp_highp = modexp_exp_highp(body, base_len, exp_len);

    let gas_used = modexp_gas(base_len, exp_len, mod_len, exp_highp);
    if gas_used > gas_limit {
        return Err(());
    }

    // Atajo de revm: módulo Y base vacíos ⇒ éxito inmediato con output
    // vacío, el gas YA calculado se cobra igual. Corre ANTES de tallar/
    // asignar el input real — es la guarda que hace inalcanzable el caso
    // patológico de un `exp_len` saturado a `usize::MAX` con un
    // `right_pad(body, total_len)` de ese tamaño: solo llega acá si
    // `max(base_len, mod_len) == 0`, y en ese caso `multiplication_
    // complexity` (gobernada por `max_len`) es CERO, así que CUALQUIER
    // `exp_len` (por más absurdo que sea) da `gas_used == MODEXP_MIN_GAS` —
    // el único escenario donde un `exp_len` no acotado podría sobrevivir el
    // chequeo de gas de arriba, y es EXACTAMENTE el que este atajo
    // intercepta antes de asignar nada proporcional a `exp_len`.
    if base_len == 0 && mod_len == 0 {
        return Ok(Output {
            gas_used,
            data: Bytes::new(),
        });
    }

    let total_len = base_len.saturating_add(exp_len).saturating_add(mod_len);
    let padded = right_pad(body, total_len);
    let (base, rest) = padded.split_at(base_len);
    let (exponent, modulus) = rest.split_at(exp_len);
    debug_assert_eq!(modulus.len(), mod_len);

    let output = aurora_engine_modexp::modexp(base, exponent, modulus);
    Ok(Output {
        gas_used,
        data: left_pad_modexp_output(&output, mod_len),
    })
}

/// Lee una palabra de 32 bytes big-endian en `bytes[offset..offset+32]`,
/// cero si `bytes` no llega hasta ahí (fail-closed vía `get`, sin indexar
/// crudo — `bytes` siempre tiene exactamente `MODEXP_HEADER_LEN` acá, pero la
/// función no depende de esa invariante para ser segura).
fn u256_at(bytes: &[u8], offset: usize) -> U256 {
    let mut word = [0u8; 32];
    if let Some(slice) = bytes.get(offset..offset.saturating_add(32)) {
        word.copy_from_slice(slice);
    }
    U256::from_be_bytes(word)
}

/// `ADJUSTED_EXPONENT_LENGTH` de EIP-2565: los primeros `min(exp_len, 32)`
/// bytes REALES del exponente (offset `base_len` en `body`, right-pad si
/// falta), reinterpretados como el entero de 32 bytes que resulta de
/// left-pad-earlos — NO un right-pad ingenuo. Si `exp_len < 32`, esto
/// reconstruye el valor exacto del exponente (que cabe entero en esos
/// bytes); si `exp_len >= 32`, son los 32 bytes más significativos, usados
/// solo para estimar el costo (no el valor real completo).
fn modexp_exp_highp(body: &[u8], base_len: usize, exp_len: usize) -> U256 {
    let window_len = exp_len.min(32);
    // Bytes REALES disponibles en la ventana `[base_len, base_len+window_len)`
    // — clampeados a `body.len()` en ambos extremos (fail-closed vía `min`,
    // sin indexar crudo): si `body` no llega tan lejos, el resto de la
    // ventana queda implícitamente en cero (right-pad).
    let available_start = base_len.min(body.len());
    let available_end = body.len().min(base_len.saturating_add(window_len));
    let available = &body[available_start..available_end];

    let mut padded = [0u8; 32];
    // Left-pad de la ventana (right-padded) a 32 bytes: los bytes reales van
    // al FINAL del buffer, dejando el resto (incluida la cola right-padded
    // de la ventana) en cero.
    let dest_start = padded.len().saturating_sub(window_len);
    padded[dest_start..dest_start.saturating_add(available.len())].copy_from_slice(available);
    U256::from_be_bytes(padded)
}

/// Gas de EIP-2565 (Berlin): `max(200, multiplication_complexity ·
/// iteration_count / 3)`. Todo el producto intermedio corre en `U256` (igual
/// que revm) para no desbordar `u64` con un `max_len`/`iteration_count`
/// adversarial — el resultado se satura de vuelta a `u64` al final, lo que
/// para un input patológico da un costo enorme (rechazado por el chequeo de
/// gas del caller), nunca un panic ni un wrapping silencioso.
fn modexp_gas(base_len: usize, exp_len: usize, mod_len: usize, exp_highp: U256) -> u64 {
    let max_len = u64::try_from(base_len.max(mod_len)).unwrap_or(u64::MAX);
    // `ceil(max_len/8)`: fail-closed (satura a un `words` enorme) ante el
    // overflow inalcanzable de `max_len + 7` cuando `max_len` ya está cerca
    // de `u64::MAX` — un `words` enorme solo empuja el gas hacia arriba,
    // nunca hacia abajo.
    let words = max_len.saturating_add(7) / 8;
    // Up-cast a U256 ANTES de elevar al cuadrado: `words < 2^64` ⇒
    // `words² < 2^128`, no desborda (mismo comentario que revm).
    let multiplication_complexity = U256::from(words) * U256::from(words);

    let exp_len = u64::try_from(exp_len).unwrap_or(u64::MAX);
    let iteration_count = modexp_iteration_count(exp_len, exp_highp);

    let gas =
        multiplication_complexity * U256::from(iteration_count) / U256::from(MODEXP_GAS_DIVISOR);
    let gas: u64 = gas.saturating_to();
    gas.max(MODEXP_MIN_GAS)
}

/// `calculate_iteration_count` de EIP-2565, verificado contra revm.
fn modexp_iteration_count(exp_len: u64, exp_highp: U256) -> u64 {
    let bit_len = exp_highp.bit_len() as u64;
    let count = if exp_len <= 32 && exp_highp.is_zero() {
        0
    } else if exp_len <= 32 {
        // `exp_highp != 0` en esta rama (la rama de arriba ya cubrió el
        // cero) ⇒ `bit_len >= 1`, la resta nunca desborda — `saturating_sub`
        // igual, por si el invariante alguna vez deja de sostenerse.
        bit_len.saturating_sub(1)
    } else {
        MODEXP_ITERATION_MULTIPLIER
            .saturating_mul(exp_len.saturating_sub(32))
            .saturating_add(bit_len.max(1).saturating_sub(1))
    };
    count.max(1)
}

/// Left-pad del resultado de `aurora_engine_modexp::modexp` a EXACTAMENTE
/// `mod_len` bytes (el resultado de un módulo nunca excede su propio largo
/// en bytes, pero el `min`/`saturating_sub` de acá no depende de esa
/// invariante para ser seguro).
fn left_pad_modexp_output(output: &[u8], mod_len: usize) -> Bytes {
    let n = output.len().min(mod_len);
    let mut result = alloc::vec![0u8; mod_len];
    result[mod_len.saturating_sub(n)..].copy_from_slice(&output[output.len().saturating_sub(n)..]);
    Bytes::from(result)
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

    // ------------------------------------------------------------- MODEXP

    /// Arma el input EIP-198: 3 headers de 32 bytes + base + exponente +
    /// módulo, sin padding adicional (la función bajo test es la que debe
    /// tolerar/rellenar lo que falte).
    fn modexp_input(base: &[u8], exp: &[u8], modulus: &[u8]) -> alloc::vec::Vec<u8> {
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&len_header(base.len()));
        input.extend_from_slice(&len_header(exp.len()));
        input.extend_from_slice(&len_header(modulus.len()));
        input.extend_from_slice(base);
        input.extend_from_slice(exp);
        input.extend_from_slice(modulus);
        input
    }

    fn len_header(len: usize) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&(len as u64).to_be_bytes());
        word
    }

    /// Parseo hex NO const (a diferencia de `hex32`): usado solo para
    /// vectores de largo variable (el exponente/módulo de 32 bytes de
    /// `eip198_example_1` sí podría ser `hex32`, pero se reusa `hex_byte`
    /// para no duplicar el parser).
    fn hex_vec(s: &str) -> alloc::vec::Vec<u8> {
        let bytes = s.as_bytes();
        assert!(bytes.len().is_multiple_of(2), "hex de longitud impar");
        (0..bytes.len())
            .step_by(2)
            .map(|i| hex_byte(bytes[i]) * 16 + hex_byte(bytes[i + 1]))
            .collect()
    }

    /// `3^2 mod 5 = 4`, verificado a mano (no contra revm): el caso más
    /// simple para confirmar el parseo del header y el atajo por el que NO
    /// pasa (ni `base_len==0`, ni `mod_len==0`). `max_len=1 ⇒
    /// multiplication_complexity=1`, `exp_highp=2 ⇒ iteration_count=1` ⇒
    /// `gas = max(200, 1·1/3=0) = 200` — el piso de EIP-2565 domina.
    #[test]
    fn modexp_computes_a_small_case_verified_by_hand() {
        let input = modexp_input(&[3], &[2], &[5]);
        let output = must_run(MODEXP, &input, 10_000);
        assert_eq!(output.gas_used, MODEXP_MIN_GAS);
        assert_eq!(output.data.as_ref(), &[4]);
    }

    /// Vector real de EIP-198 (el mismo que trae
    /// `revm-precompile-34.0.0/src/modexp.rs::tests::TESTS`, `eip198_
    /// example_1`, task 013 attempt_log it.1): `3^E mod M = 1` con `E`/`M`
    /// de 32 bytes cada uno. Gas verificado a mano contra EIP-2565:
    /// `max_len=32 ⇒ words=4 ⇒ multiplication_complexity=16`; `exp_highp`
    /// tiene el bit más alto seteado (empieza en `0xff...`) ⇒ `bit_len=256
    /// ⇒ iteration_count=255`; `gas = max(200, 16·255/3=1360) = 1360`.
    #[test]
    fn modexp_matches_the_eip198_example_1_vector() {
        let exp = hex_vec("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
        let modulus = hex_vec("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
        let input = modexp_input(&[3], &exp, &modulus);
        let output = must_run(MODEXP, &input, 10_000);
        assert_eq!(output.gas_used, 1_360);
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(output.data.as_ref(), &expected[..]);
    }

    /// El atajo de `run_inner` (task 013 §3): `base_len==0 && mod_len==0`
    /// ⇒ éxito inmediato con output vacío, SIN correr `aurora_engine_
    /// modexp::modexp` — el gas ya calculado (el piso, acá) se cobra igual.
    #[test]
    fn modexp_with_zero_base_and_zero_modulus_takes_the_shortcut() {
        let input = modexp_input(&[], &[2], &[]);
        let output = must_run(MODEXP, &input, 10_000);
        assert_eq!(output.gas_used, MODEXP_MIN_GAS);
        assert!(output.data.is_empty());
    }

    /// `mod_len==0` con `base_len>0` NO es el atajo de arriba (no cumple
    /// `base_len==0`): pasa por el camino normal, y `aurora_engine_modexp`
    /// da el mismo resultado (módulo cero ⇒ output vacío) por otra vía —
    /// confirma que ambos caminos coinciden (task 013 §5).
    #[test]
    fn modexp_with_zero_modulus_and_nonzero_base_is_empty_via_the_normal_path() {
        let input = modexp_input(&[3], &[2], &[]);
        let output = must_run(MODEXP, &input, 10_000);
        assert_eq!(output.gas_used, MODEXP_MIN_GAS);
        assert!(output.data.is_empty());
    }

    #[test]
    fn modexp_out_of_gas_is_an_err() {
        let input = modexp_input(&[3], &[2], &[5]);
        assert!(run(MODEXP, &input, MODEXP_MIN_GAS - 1).is_err());
    }

    /// `base_len` declarado como un valor que NO entra en `usize` (acá,
    /// `2^248`): fail-closed explícito (`Err`), nunca un panic ni un
    /// wrapping — el caso que motiva `usize::try_from(..).map_err(|_| ())?`
    /// en vez de un cast crudo.
    #[test]
    fn modexp_with_a_base_length_that_does_not_fit_in_usize_is_rejected() {
        let mut huge = [0u8; 32];
        huge[0] = 1;
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&huge); // base_len ~ 2^248
        input.extend_from_slice(&[0u8; 32]); // exp_len = 0
        input.extend_from_slice(&[0u8; 32]); // mod_len = 0
        assert!(run(MODEXP, &input, 10_000).is_err());
    }

    /// El caso de seguridad central del slice (task 013 §6): `exp_len`
    /// declarado como un valor que NO entra en `usize` (acá, `2^248`) satura
    /// a `usize::MAX` en vez de fallar (§3) — pero con `base_len==0 &&
    /// mod_len==0`, `multiplication_complexity` es CERO, así que el atajo de
    /// éxito-vacío intercepta el caso ANTES de que el executor intente
    /// tallar/asignar algo proporcional a `exp_len`. Si esta guardia
    /// estuviera mal ordenada, este test colgaría o abortaría por OOM en vez
    /// de terminar en microsegundos.
    #[test]
    fn modexp_with_an_unbounded_exponent_length_and_zero_base_and_modulus_stays_cheap_and_safe() {
        let mut huge = [0u8; 32];
        huge[0] = 1;
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&[0u8; 32]); // base_len = 0
        input.extend_from_slice(&huge); // exp_len ~ 2^248 (satura a usize::MAX)
        input.extend_from_slice(&[0u8; 32]); // mod_len = 0
        let output = must_run(MODEXP, &input, 10_000);
        assert_eq!(output.gas_used, MODEXP_MIN_GAS);
        assert!(output.data.is_empty());
    }
}
