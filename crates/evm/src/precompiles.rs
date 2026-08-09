//! Precompiles básicas (slice 2.8a, task 012): ECRECOVER, SHA256, RIPEMD160,
//! IDENTITY. Slice 2.8b (task 013) suma MODEXP. Slice 2.8c (task 014) suma
//! BN254 (ADD/MUL/PAIRING). Slice 2.8d (task 015) suma BLAKE2F. Slice 2.8e
//! (task 016) suma KZG point evaluation. El resto del rango reservado
//! (`0x0b..=0x11`, BLS12-381) sigue fail-closed en `frames.rs` — dueño de
//! 2.8f.
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

use core::ops::Neg;

use alloc::vec::Vec;

use ark_bls12_381::{
    Bls12_381, Fr as Bls12Fr, G1Affine as Bls12G1Affine, G2Affine as Bls12G2Affine,
};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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
/// BN254 (task 014, slice 2.8c, EIP-196/EIP-197). Primer slice de este repo
/// que usa criptografía de curvas elípticas de pairing (`arkworks`).
pub(crate) const BN254_ADD: u8 = 0x06;
pub(crate) const BN254_MUL: u8 = 0x07;
pub(crate) const BN254_PAIRING: u8 = 0x08;
/// BLAKE2F (task 015, slice 2.8d, EIP-152). Sin dependencia externa: la
/// función de compresión se porta directo del source de `revm-precompile`
/// (aritmética nativa de `u64`, nada que un crate resuelva mejor).
pub(crate) const BLAKE2F: u8 = 0x09;
/// KZG point evaluation (task 016, slice 2.8e, EIP-4844). Primera
/// dependencia nueva desde 2.8c (`ark-bls12-381`, curva distinta de BN254).
pub(crate) const KZG_POINT_EVALUATION: u8 = 0x0a;
pub(crate) const LAST_IMPLEMENTED: u8 = KZG_POINT_EVALUATION;

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

/// EIP-1108 (Istanbul) — el repricing vigente para Cancun+Prague (task 014
/// §Prohibido: NO usar las constantes de Byzantium, 3-13x más caras y que
/// este repo nunca activa).
const BN254_ADD_GAS: u64 = 150;
const BN254_MUL_GAS: u64 = 6_000;
const BN254_PAIRING_BASE_GAS: u64 = 45_000;
const BN254_PAIRING_PER_POINT_GAS: u64 = 34_000;

/// Largo de un `Fq` (elemento del campo base) codificado big-endian.
const FQ_LEN: usize = 32;
/// Largo de un punto G1 sin comprimir: dos `Fq` (`x`, `y`).
const G1_LEN: usize = 2 * FQ_LEN;
/// Largo de un `Fq2` sin comprimir: dos `Fq`.
const FQ2_LEN: usize = 2 * FQ_LEN;
/// Largo de un punto G2 sin comprimir: dos `Fq2` (`x`, `y`).
const G2_LEN: usize = 2 * FQ2_LEN;
/// ADD toma dos puntos G1.
const BN254_ADD_INPUT_LEN: usize = 2 * G1_LEN;
/// MUL toma un punto G1 y un escalar de 32 bytes.
const BN254_MUL_INPUT_LEN: usize = G1_LEN + 32;
/// Cada par de PAIRING es un G1 (64) + un G2 (128).
const BN254_PAIR_ELEMENT_LEN: usize = G1_LEN + G2_LEN;

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
        BN254_ADD => bn254_add(input, gas_limit),
        BN254_MUL => bn254_mul(input, gas_limit),
        BN254_PAIRING => bn254_pairing(input, gas_limit),
        BLAKE2F => blake2f(input, gas_limit),
        KZG_POINT_EVALUATION => kzg_point_evaluation(input, gas_limit),
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

/// BN254 ADD/MUL/PAIRING (EIP-196/EIP-197, task 014 §1-§4). A diferencia de
/// ECRECOVER/MODEXP, esta familia SÍ tiene fallos propios del algoritmo (un
/// punto que no es miembro válido del campo, que no está en la curva o que
/// no está en el subgrupo correcto) — verificado contra
/// `revm-precompile::interface.rs::PrecompileHalt`/`call_eth_precompile`:
/// CUALQUIER variante de `PrecompileHalt` (`OutOfGas` incluido) se traduce
/// al MISMO `PrecompileOutput::halt`, sin distinción de tratamiento — el
/// `Err(())` único y compartido de este módulo desde 2.8a sigue siendo el
/// modelo correcto, no hace falta un segundo tipo de fallo.
///
/// Backend real: `arkworks` (`ark-bn254`/`ark-ec`/`ark-ff`/`ark-serialize`),
/// el MISMO que el `revm` pineado acá activa sin el feature `bn` (research
/// de `PHASE_2_ROADMAP.md`, re-confirmado en el attempt_log de este task).
/// Verificado línea a línea contra `revm-precompile-34.0.0/src/bn254/
/// arkworks.rs` — no reconstrucción de memoria.
/// Lee un `Fq` (elemento del campo base) de 32 bytes big-endian. `Fq::
/// deserialize_uncompressed` exige un miembro válido del campo (`< p`); un
/// byte-string que no lo es es el primer modo de fallo de esta familia.
fn read_fq(bytes: &[u8]) -> Result<Fq, ()> {
    let mut little_endian = [0u8; FQ_LEN];
    little_endian.copy_from_slice(bytes);
    little_endian.reverse();
    Fq::deserialize_uncompressed(&little_endian[..]).map_err(|_| ())
}

/// Lee un `Fq2` de 64 bytes. **Orden invertido, verificado contra `read_fq2`
/// de revm: el componente `y` (segunda coordenada) se lee PRIMERO, después
/// `x`** — la trampa de transcripción central de este slice (task 014 §3).
fn read_fq2(bytes: &[u8]) -> Result<Fq2, ()> {
    let y = read_fq(&bytes[..FQ_LEN])?;
    let x = read_fq(&bytes[FQ_LEN..2 * FQ_LEN])?;
    Ok(Fq2::new(x, y))
}

/// Construye un punto G1 a partir de coordenadas afines. `(0,0)` es el
/// punto al infinito por convención de la EVM — `G1Affine` no puede
/// representarlo como un punto "en la curva" real, así que se detecta
/// ANTES de chequear curva/subgrupo (mismo orden que `new_g1_point` de
/// revm).
fn new_g1_point(x: Fq, y: Fq) -> Result<G1Affine, ()> {
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(());
    }
    Ok(point)
}

/// Análogo de `new_g1_point` para G2.
fn new_g2_point(x: Fq2, y: Fq2) -> Result<G2Affine, ()> {
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::zero());
    }
    let point = G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(());
    }
    Ok(point)
}

fn read_g1_point(bytes: &[u8]) -> Result<G1Affine, ()> {
    let x = read_fq(&bytes[..FQ_LEN])?;
    let y = read_fq(&bytes[FQ_LEN..2 * FQ_LEN])?;
    new_g1_point(x, y)
}

fn read_g2_point(bytes: &[u8]) -> Result<G2Affine, ()> {
    let x = read_fq2(&bytes[..FQ2_LEN])?;
    let y = read_fq2(&bytes[FQ2_LEN..2 * FQ2_LEN])?;
    new_g2_point(x, y)
}

/// El escalar de MUL NO necesita ser canónico (task 014 §3): `Fr::
/// from_be_bytes_mod_order` reduce cualquier valor de 32 bytes módulo el
/// orden del grupo — a diferencia de `read_fq`, esto nunca falla.
fn read_scalar(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Codifica un G1 en 64 bytes big-endian (`x` seguido de `y`); el punto al
/// infinito se codifica como 64 ceros (`point.xy()` da `None` para el
/// punto al infinito). La serialización de un `Fq` en un buffer de
/// EXACTAMENTE `FQ_LEN` bytes es infalible por invariante de tipo (no
/// depende del input hostil) — igual se propaga como `Err(())` en vez de
/// `expect`/`unwrap`, fail-closed por si esa invariante alguna vez deja de
/// sostenerse (p.ej. un cambio de versión de `ark-serialize`).
fn encode_g1_point(point: G1Affine) -> Result<Bytes, ()> {
    let mut output = [0u8; G1_LEN];
    if let Some((x, y)) = point.xy() {
        write_fq_be(&mut output[..FQ_LEN], x)?;
        write_fq_be(&mut output[FQ_LEN..], y)?;
    }
    Ok(Bytes::copy_from_slice(&output))
}

fn write_fq_be(dest: &mut [u8], value: Fq) -> Result<(), ()> {
    let mut little_endian = [0u8; FQ_LEN];
    value
        .serialize_uncompressed(&mut little_endian[..])
        .map_err(|_| ())?;
    little_endian.reverse();
    dest.copy_from_slice(&little_endian);
    Ok(())
}

/// ADD (`0x06`). Costo FLAT (task 014 §2, EIP-1108/Istanbul).
fn bn254_add(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    if BN254_ADD_GAS > gas_limit {
        return Err(());
    }
    let padded = right_pad(input, BN254_ADD_INPUT_LEN);
    let p1 = read_g1_point(&padded[..G1_LEN])?;
    let p2 = read_g1_point(&padded[G1_LEN..])?;
    let p1_projective: G1Projective = p1.into();
    let sum = p1_projective + p2;
    Ok(Output {
        gas_used: BN254_ADD_GAS,
        data: encode_g1_point(sum.into_affine())?,
    })
}

/// MUL (`0x07`). Costo FLAT.
fn bn254_mul(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    if BN254_MUL_GAS > gas_limit {
        return Err(());
    }
    let padded = right_pad(input, BN254_MUL_INPUT_LEN);
    let point = read_g1_point(&padded[..G1_LEN])?;
    let scalar = read_scalar(&padded[G1_LEN..G1_LEN + 32]);
    let result = point.mul_bigint(scalar.into_bigint());
    Ok(Output {
        gas_used: BN254_MUL_GAS,
        data: encode_g1_point(result.into_affine())?,
    })
}

/// PAIRING (`0x08`). Gas `45000 + 34000·k` con `k = ⌊len/192⌋` (task 014
/// §2: el gas se calcula con la división ENTERA incluso si `len` no es
/// múltiplo exacto — el chequeo de gas corre ANTES que el chequeo de largo
/// exacto, mismo orden que `run_pair` de revm). Sin right-pad: el input se
/// parte en bloques de 192 bytes exactos.
///
/// Input vacío ⇒ éxito, `true` (task 014 §4 — **a diferencia de
/// EIP-2537/BLS12-381, 2.8f, que rechaza el input vacío; no generalizar**).
/// Un par con G1 o G2 al infinito se SALTEA del cómputo real; si todos los
/// pares terminan salteados (o el input era vacío), el resultado es `true`
/// por vacuidad.
fn bn254_pairing(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    let num_pairs = input.len() / BN254_PAIR_ELEMENT_LEN;
    let num_pairs_u64 = u64::try_from(num_pairs).map_err(|_| ())?;
    let gas_used = BN254_PAIRING_BASE_GAS
        .checked_add(
            BN254_PAIRING_PER_POINT_GAS
                .checked_mul(num_pairs_u64)
                .ok_or(())?,
        )
        .ok_or(())?;
    if gas_used > gas_limit {
        return Err(());
    }
    if !input.len().is_multiple_of(BN254_PAIR_ELEMENT_LEN) {
        return Err(());
    }

    let mut g1_points = Vec::with_capacity(num_pairs);
    let mut g2_points = Vec::with_capacity(num_pairs);
    for index in 0..num_pairs {
        let start = index.saturating_mul(BN254_PAIR_ELEMENT_LEN);
        let g1_bytes = &input[start..start + G1_LEN];
        let g2_bytes = &input[start + G1_LEN..start + BN254_PAIR_ELEMENT_LEN];
        let g1 = read_g1_point(g1_bytes)?;
        let g2 = read_g2_point(g2_bytes)?;
        if !g1.is_zero() && !g2.is_zero() {
            g1_points.push(g1);
            g2_points.push(g2);
        }
    }

    let holds = g1_points.is_empty() || Bn254::multi_pairing(&g1_points, &g2_points).0.is_one();
    let mut data = [0u8; 32];
    if holds {
        data[31] = 1;
    }
    Ok(Output {
        gas_used,
        data: Bytes::copy_from_slice(&data),
    })
}

/// `<4 bytes rounds><64 bytes h><128 bytes m><8 bytes t_0><8 bytes t_1><1 byte f>`
/// (EIP-152). Sin dependencia externa: la función de compresión de BLAKE2b
/// se porta de `revm-precompile-34.0.0/src/blake2.rs::algo` (rama PORTABLE
/// únicamente — la rama `avx2` no aplica a `no_std`/RISC-V).
const BLAKE2F_INPUT_LEN: usize = 213;
/// `F_ROUND` de revm: el único precompile hasta ahora sin piso ni costo
/// flat — `rounds == 0` cuesta `0` y tiene éxito.
const BLAKE2F_ROUND_GAS: u64 = 1;

/// BLAKE2F (`0x09`). A diferencia de TODOS los precompiles anteriores
/// (ECRECOVER/SHA256/RIPEMD160/IDENTITY/MODEXP/BN254, que toleran un input
/// más corto que lo declarado vía right-pad), el largo tiene que ser
/// EXACTAMENTE 213 bytes — verificado ANTES del gas (task 015 §2/§4). `h`/
/// `m`/`t_0`/`t_1` son LITTLE-ENDIAN (al revés de la convención big-endian
/// de todos los precompiles anteriores); `rounds` es la ÚNICA excepción,
/// big-endian, verificado contra `blake2.rs::run`.
fn blake2f(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    if input.len() != BLAKE2F_INPUT_LEN {
        return Err(());
    }

    let rounds = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let gas_used = u64::from(rounds).checked_mul(BLAKE2F_ROUND_GAS).ok_or(())?;
    if gas_used > gas_limit {
        return Err(());
    }

    let f = match input[212] {
        0 => false,
        1 => true,
        _ => return Err(()),
    };

    let mut h = [0u64; 8];
    for (word, chunk) in h.iter_mut().zip(input[4..68].chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
    }

    let mut m = [0u64; 16];
    for (word, chunk) in m.iter_mut().zip(input[68..196].chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
    }

    let t_0 = u64::from_le_bytes(input[196..204].try_into().unwrap_or([0u8; 8]));
    let t_1 = u64::from_le_bytes(input[204..212].try_into().unwrap_or([0u8; 8]));

    blake2b::compress(rounds, &mut h, &m, [t_0, t_1], f);

    let mut data = [0u8; 64];
    for (chunk, word) in data.chunks_exact_mut(8).zip(h.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(Output {
        gas_used,
        data: Bytes::copy_from_slice(&data),
    })
}

/// Puerto directo de `revm-precompile-34.0.0/src/blake2.rs::algo` (rama
/// PORTABLE). No es una reimplementación: los nombres, el orden y la
/// aritmética son los mismos, solo cambia dónde vive el código — es
/// criptografía verificada, no se re-deriva (mismo principio de "no rolear
/// cripto propia" aplicado a copiar en vez de reescribir, task 015 §1).
mod blake2b {
    /// RFC 7693 §2.7.
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    const IV: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    #[allow(clippy::many_single_char_names)]
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        let mut va = v[a];
        let mut vb = v[b];
        let mut vc = v[c];
        let mut vd = v[d];

        va = va.wrapping_add(vb).wrapping_add(x);
        vd = (vd ^ va).rotate_right(32);
        vc = vc.wrapping_add(vd);
        vb = (vb ^ vc).rotate_right(24);

        va = va.wrapping_add(vb).wrapping_add(y);
        vd = (vd ^ va).rotate_right(16);
        vc = vc.wrapping_add(vd);
        vb = (vb ^ vc).rotate_right(63);

        v[a] = va;
        v[b] = vb;
        v[c] = vc;
        v[d] = vd;
    }

    fn round(v: &mut [u64; 16], m: &[u64; 16], r: usize) {
        let s = &SIGMA[r % 10];
        g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    /// `t`: `[t_0, t_1]` (offset counter). `f`: bandera de último bloque.
    pub(super) fn compress(rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], f: bool) {
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(h);
        v[8..].copy_from_slice(&IV);

        v[12] ^= t[0];
        v[13] ^= t[1];
        if f {
            v[14] = !v[14];
        }
        for i in 0..rounds as usize {
            round(&mut v, m, i);
        }
        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

/// `<versioned_hash 32><z 32><y 32><commitment 48><proof 48>` (EIP-4844,
/// task 016 §2). EXACTO, sin right-pad (mismo criterio estricto que
/// BLAKE2F). `z`/`y` son escalares big-endian — al revés de la trampa
/// little-endian de BLAKE2F (task 015), verificar contra el source, no
/// asumir consistencia entre slices.
const KZG_INPUT_LEN: usize = 192;
/// Costo FLAT (task 016 §3) — el más simple de los seis precompiles de 2.8
/// en este eje: ni por bytes (SHA256/RIPEMD160) ni por rounds (BLAKE2F) ni
/// por puntos (BN254 PAIRING).
const KZG_GAS: u64 = 50_000;
/// `VERSIONED_HASH_VERSION_KZG` de EIP-4844.
const KZG_VERSIONED_HASH_VERSION: u8 = 0x01;

/// `[τ]₂` de la ceremonia KZG de Ethereum (`trusted_setup_4096.json`,
/// `g2_monomial_1`) — punto PÚBLICO, no un secreto. Copiado byte a byte de
/// `revm-precompile-34.0.0/src/bls12_381_const.rs::
/// TRUSTED_SETUP_TAU_G2_BYTES` (task 016 §1/`Leer antes`; generado con
/// Python `bytes.fromhex(...)` para evitar un error de transcripción a
/// mano en un array de 96 bytes).
#[rustfmt::skip]
const KZG_TRUSTED_SETUP_TAU_G2_BYTES: [u8; 96] = [
    0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28, 0x84, 0x3b, 0xc2, 0x87,
    0x23, 0x0a, 0xf3, 0x89, 0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xa8,
    0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a, 0xc5, 0x3d, 0x29, 0x14, 0xe5, 0x87,
    0x0c, 0xb4, 0x52, 0xd2, 0xaf, 0xaa, 0xab, 0x24, 0xf3, 0x49, 0x9f, 0x72,
    0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14, 0x73, 0x44, 0x29, 0xb7,
    0xb3, 0x86, 0x08, 0xe2, 0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9,
    0xa3, 0x68, 0x51, 0x47, 0x7b, 0xa4, 0xc6, 0x0b, 0x08, 0x70, 0x41, 0xde,
    0x62, 0x10, 0x00, 0xed, 0xc9, 0x8e, 0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2,
];

/// `FIELD_ELEMENTS_PER_BLOB` (4096, u256 big-endian) ++ `BLS_MODULUS` (32
/// bytes big-endian) — el output de ÉXITO es CONSTANTE, no derivado del
/// cómputo (task 016 §6). Copiado byte a byte de `RETURN_VALUE` en
/// `kzg_point_evaluation.rs`, mismo criterio de generación que
/// `KZG_TRUSTED_SETUP_TAU_G2_BYTES`.
#[rustfmt::skip]
const KZG_RETURN_VALUE: [u8; 64] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x73, 0xed, 0xa7, 0x53,
    0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x01,
];

/// KZG point evaluation (`0x0A`, EIP-4844). Verifica que `commitment`
/// evalúa a `y` en el punto `z` (formalmente: `p(z) = y` para el polinomio
/// comprometido por `commitment`), usando `proof` como testigo — vía el
/// pairing check de la Spec §5, puerto directo de
/// `kzg_point_evaluation/arkworks.rs::verify_kzg_proof` de revm.
///
/// A diferencia de BN254 (que reduce escalares fuera de rango módulo el
/// orden del grupo, `read_scalar`), `z`/`y` acá deben ser CANÓNICOS —
/// `read_scalar_canonical` de revm, portado como `read_canonical_scalar`
/// (task 016 §4).
fn kzg_point_evaluation(input: &[u8], gas_limit: u64) -> Result<Output, ()> {
    if KZG_GAS > gas_limit {
        return Err(());
    }
    if input.len() != KZG_INPUT_LEN {
        return Err(());
    }

    let versioned_hash = &input[0..32];
    let z = &input[32..64];
    let y = &input[64..96];
    let commitment = &input[96..144];
    let proof = &input[144..192];

    if kzg_versioned_hash(commitment) != versioned_hash {
        return Err(());
    }

    let commitment_point = read_kzg_g1_compressed(commitment)?;
    let proof_point = read_kzg_g1_compressed(proof)?;
    let z_fr = read_canonical_scalar(z)?;
    let y_fr = read_canonical_scalar(y)?;

    if !verify_kzg_proof(&commitment_point, &z_fr, &y_fr, &proof_point)? {
        return Err(());
    }

    Ok(Output {
        gas_used: KZG_GAS,
        data: Bytes::copy_from_slice(&KZG_RETURN_VALUE),
    })
}

/// `VERSIONED_HASH_VERSION_KZG ++ sha256(commitment)[1..]` — mismo `sha256`
/// de 2.8a (`SHA256`, `0x02`), sin dependencia nueva para esto.
fn kzg_versioned_hash(commitment: &[u8]) -> [u8; 32] {
    let mut hash: [u8; 32] = sha256(commitment)[..].try_into().unwrap_or([0u8; 32]);
    hash[0] = KZG_VERSIONED_HASH_VERSION;
    hash
}

/// Parsea un punto G1 COMPRIMIDO (48 bytes) de BLS12-381. Input EXTERNO:
/// `deserialize_compressed` CHECKED (valida curva + subgrupo), NUNCA la
/// variante `_unchecked` (task 016 §4/`Prohibido` — esa es solo para
/// `KZG_TRUSTED_SETUP_TAU_G2_BYTES`, ya confiable).
fn read_kzg_g1_compressed(bytes: &[u8]) -> Result<Bls12G1Affine, ()> {
    Bls12G1Affine::deserialize_compressed(bytes).map_err(|_| ())
}

/// Lee un escalar `Fr` de 32 bytes big-endian y rechaza representaciones NO
/// canónicas (`from_be_bytes_mod_order` reduce cualquier valor módulo el
/// orden del grupo; el round-trip serializado detecta si eso REALMENTE
/// redujo algo). A diferencia de `read_scalar` de BN254 (task 014 §3, que
/// tolera cualquier valor porque MUL no lo necesita canónico), EIP-4844
/// exige que `z`/`y` sean canónicos (task 016 §4, `read_scalar_canonical`
/// de revm).
fn read_canonical_scalar(bytes: &[u8]) -> Result<Bls12Fr, ()> {
    let scalar = Bls12Fr::from_be_bytes_mod_order(bytes);
    let mut roundtrip = [0u8; 32];
    let big = scalar.into_bigint().to_bytes_be();
    let offset = 32usize.checked_sub(big.len()).ok_or(())?;
    roundtrip[offset..].copy_from_slice(&big);
    if roundtrip != bytes {
        return Err(());
    }
    Ok(scalar)
}

/// El pairing check de la Spec §5: `e(P-y, -G₂) · e(proof, X-z) == 1`, con
/// `P-y = commitment - [y]G₁` y `X-z = [τ]₂ - [z]G₂`. Puerto directo de
/// `kzg_point_evaluation/arkworks.rs::verify_kzg_proof`.
///
/// `Err(())`: solo si `KZG_TRUSTED_SETUP_TAU_G2_BYTES` no parseara — no
/// debería ocurrir NUNCA (es una constante embebida verificada, task 016
/// §1), pero se propaga fail-closed en vez de `expect`/`unwrap` (mismo
/// criterio que `encode_g1_point` de 2.8c: ninguna invariante de tipo
/// justifica un panic, ni siquiera una "infalible").
fn verify_kzg_proof(
    commitment: &Bls12G1Affine,
    z: &Bls12Fr,
    y: &Bls12Fr,
    proof: &Bls12G1Affine,
) -> Result<bool, ()> {
    let g1 = Bls12G1Affine::generator();
    let g2 = Bls12G2Affine::generator();

    let y_g1 = g1.mul_bigint(y.into_bigint()).into_affine();
    let p_minus_y = (commitment.into_group() - y_g1.into_group()).into_affine();

    let tau_g2 = kzg_trusted_setup_tau_g2()?;
    let z_g2 = g2.mul_bigint(z.into_bigint()).into_affine();
    let x_minus_z = (tau_g2.into_group() - z_g2.into_group()).into_affine();

    let neg_g2 = g2.neg();

    Ok(
        Bls12_381::multi_pairing([p_minus_y, *proof], [neg_g2, x_minus_z])
            .0
            .is_one(),
    )
}

/// Parsea `KZG_TRUSTED_SETUP_TAU_G2_BYTES` una vez por llamada — sin cache
/// estática: este repo no tiene un precedente de `OnceLock`/equivalente
/// `no_std` para este propósito (task 016 §5), y parsear un punto G2 fijo
/// no es el cuello de botella de este slice. `_unchecked`: es un dato
/// EMBEBIDO, ya confiable, no input externo (task 016 §4/`Prohibido`).
fn kzg_trusted_setup_tau_g2() -> Result<Bls12G2Affine, ()> {
    Bls12G2Affine::deserialize_compressed_unchecked(&KZG_TRUSTED_SETUP_TAU_G2_BYTES[..])
        .map_err(|_| ())
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

    // -------------------------------------------------------------- BN254

    /// Vector real de `revm-precompile-34.0.0/src/bn254.rs::tests::
    /// test_bn254_add` (primer caso) — NO inventado a mano.
    #[test]
    fn bn254_add_matches_the_revm_test_vector() {
        let input = hex_vec(
            "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9\
             063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266\
             07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed\
             06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7",
        );
        let expected = hex_vec(
            "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703\
             301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915",
        );
        let output = must_run(BN254_ADD, &input, BN254_ADD_GAS);
        assert_eq!(output.gas_used, BN254_ADD_GAS);
        assert_eq!(output.data.as_ref(), expected.as_slice());
    }

    #[test]
    fn bn254_add_of_two_points_at_infinity_stays_at_infinity() {
        let input = alloc::vec![0u8; BN254_ADD_INPUT_LEN];
        let output = must_run(BN254_ADD, &input, BN254_ADD_GAS);
        assert!(output.data.iter().all(|byte| *byte == 0));
    }

    /// Input vacío ⇒ `right_pad` lo trata como `(0,0)+(0,0)`, mismo
    /// resultado que el caso de arriba (task 014 §3, right-pad de ADD/MUL).
    #[test]
    fn bn254_add_with_no_input_is_the_point_at_infinity_plus_itself() {
        let output = must_run(BN254_ADD, &[], BN254_ADD_GAS);
        assert!(output.data.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bn254_add_of_a_point_not_on_the_curve_fails() {
        let input = alloc::vec![0x11u8; BN254_ADD_INPUT_LEN];
        assert!(run(BN254_ADD, &input, BN254_ADD_GAS).is_err());
    }

    #[test]
    fn bn254_add_out_of_gas_is_an_err() {
        let input = alloc::vec![0u8; BN254_ADD_INPUT_LEN];
        assert!(run(BN254_ADD, &input, BN254_ADD_GAS - 1).is_err());
    }

    /// Vector real de `test_bn254_mul`.
    #[test]
    fn bn254_mul_matches_the_revm_test_vector() {
        let input = hex_vec(
            "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7\
             21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204\
             00000000000000000000000000000000000000000000000011138ce750fa15c2",
        );
        let expected = hex_vec(
            "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c\
             031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc",
        );
        let output = must_run(BN254_MUL, &input, BN254_MUL_GAS);
        assert_eq!(output.gas_used, BN254_MUL_GAS);
        assert_eq!(output.data.as_ref(), expected.as_slice());
    }

    /// Punto al infinito por cualquier escalar: sigue siendo el punto al
    /// infinito (mismo principio que el "Zero multiplication test" de
    /// `test_bn254_mul`, con un escalar propio más simple de leer — el
    /// resultado no depende del valor del escalar cuando el punto ya es la
    /// identidad).
    #[test]
    fn bn254_mul_of_the_point_at_infinity_stays_at_infinity() {
        let mut input = alloc::vec![0u8; BN254_MUL_INPUT_LEN];
        input[BN254_MUL_INPUT_LEN - 1] = 2; // escalar = 2
        let output = must_run(BN254_MUL, &input, BN254_MUL_GAS);
        assert!(output.data.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bn254_mul_of_a_point_not_on_the_curve_fails() {
        let mut input = alloc::vec![0x11u8; BN254_MUL_INPUT_LEN];
        input[BN254_MUL_INPUT_LEN - 1] = 0x0f;
        assert!(run(BN254_MUL, &input, BN254_MUL_GAS).is_err());
    }

    #[test]
    fn bn254_mul_out_of_gas_is_an_err() {
        let input = alloc::vec![0u8; BN254_MUL_INPUT_LEN];
        assert!(run(BN254_MUL, &input, BN254_MUL_GAS - 1).is_err());
    }

    /// Vector real de `test_bn254_pair` (2 pares, resultado `true`) — el
    /// mismo vector ejercita el orden invertido de `Fq2` en G2 (task 014
    /// §3): sus dos componentes NO son simétricas, así que un left/right
    /// swap accidental daría un punto distinto (fail-closed por curva, o un
    /// resultado de pairing distinto).
    const PAIRING_TWO_TRUE_PAIRS: &str = "\
        1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59\
        3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41\
        209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7\
        04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678\
        2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d\
        120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550\
        111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c\
        2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411\
        198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
        1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
        090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
        12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

    #[test]
    fn bn254_pairing_matches_the_revm_test_vector() {
        let input = hex_vec(PAIRING_TWO_TRUE_PAIRS);
        let expected_gas = BN254_PAIRING_BASE_GAS + 2 * BN254_PAIRING_PER_POINT_GAS;
        let output = must_run(BN254_PAIRING, &input, expected_gas);
        assert_eq!(output.gas_used, expected_gas);
        assert_eq!(output.data[31], 1);
        assert!(output.data[..31].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bn254_pairing_of_empty_input_is_true() {
        let output = must_run(BN254_PAIRING, &[], BN254_PAIRING_BASE_GAS);
        assert_eq!(output.gas_used, BN254_PAIRING_BASE_GAS);
        assert_eq!(output.data[31], 1);
    }

    /// G1 al infinito con un G2 real: el par se saltea, resultado `true`
    /// (vacuidad) — vector "point at infinity" de `test_bn254_pair`.
    #[test]
    fn bn254_pairing_with_a_g1_point_at_infinity_is_skipped_and_stays_true() {
        let input = hex_vec(
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7\
             04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678\
             2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d\
             120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550",
        );
        let output = must_run(
            BN254_PAIRING,
            &input,
            BN254_PAIRING_BASE_GAS + BN254_PAIRING_PER_POINT_GAS,
        );
        assert_eq!(output.data[31], 1);
    }

    #[test]
    fn bn254_pairing_of_a_point_not_on_the_curve_fails() {
        let input = alloc::vec![0x11u8; BN254_PAIR_ELEMENT_LEN];
        let gas = BN254_PAIRING_BASE_GAS + BN254_PAIRING_PER_POINT_GAS;
        assert!(run(BN254_PAIRING, &input, gas).is_err());
    }

    #[test]
    fn bn254_pairing_with_a_length_not_a_multiple_of_the_element_size_fails() {
        let input = alloc::vec![0x11u8; BN254_PAIR_ELEMENT_LEN - 32];
        assert!(run(BN254_PAIRING, &input, 1_000_000).is_err());
    }

    #[test]
    fn bn254_pairing_out_of_gas_is_an_err() {
        let input = hex_vec(PAIRING_TWO_TRUE_PAIRS);
        let required = BN254_PAIRING_BASE_GAS + 2 * BN254_PAIRING_PER_POINT_GAS;
        assert!(run(BN254_PAIRING, &input, required - 1).is_err());
    }

    // ------------------------------------------------------------ BLAKE2F

    /// Vector A del EIP-152 (el mismo `h0` que trae, casualmente,
    /// `revm-precompile-34.0.0/src/blake2.rs::tests::perfblake2`): `F(h0,
    /// "abc" padded, t=(3,0), f=true, rounds=12)` con
    /// `h0 = IV XOR (0x01010000|digest_len)` es EXACTAMENTE la inicialización
    /// estándar de BLAKE2b-512 para un mensaje de un solo bloque —
    /// verificado independientemente contra `hashlib.blake2b(b"abc",
    /// digest_size=64)` de Python (no contra este motor ni de memoria), ver
    /// el attempt_log de 015 it.1.
    #[test]
    fn blake2f_f_of_a_single_block_hash_matches_the_standard_blake2b_of_abc() {
        let input = hex_vec(
            "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        );
        let expected = hex_vec(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        );
        let output = must_run(BLAKE2F, &input, 12);
        assert_eq!(output.gas_used, 12);
        assert_eq!(output.data.as_ref(), expected.as_slice());
    }

    /// `rounds=0` cuesta `0` de gas y tiene éxito — el único precompile
    /// hasta ahora sin piso ni costo flat (task 015 §3). `h` propio (no
    /// IV), `t=(5,7)`, `f=false`: ejercita que el estado de entrada
    /// realmente se usa. Vector generado y verificado con una
    /// reimplementación independiente en Python (mismo algoritmo, ver
    /// attempt_log it.1), no contra este motor.
    #[test]
    fn blake2f_zero_rounds_costs_zero_gas_and_uses_the_input_state() {
        let input = hex_vec(
            "000000000101010101010101020202020202020203030303030303030404040404040404050505050505050506060606060606060707070707070707080808080808080800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000070000000000000000",
        );
        let expected = hex_vec(
            "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d482e6ad7f520e51186c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
        );
        let output = must_run(BLAKE2F, &input, 0);
        assert_eq!(output.gas_used, 0);
        assert_eq!(output.data.as_ref(), expected.as_slice());
    }

    #[test]
    fn blake2f_with_a_length_other_than_213_fails() {
        assert!(run(BLAKE2F, &[0u8; 212], 1_000_000).is_err());
        assert!(run(BLAKE2F, &[0u8; 214], 1_000_000).is_err());
        assert!(run(BLAKE2F, &[], 1_000_000).is_err());
    }

    #[test]
    fn blake2f_with_an_invalid_final_block_flag_fails() {
        let mut input = alloc::vec![0u8; BLAKE2F_INPUT_LEN];
        input[212] = 2;
        assert!(run(BLAKE2F, &input, 1_000_000).is_err());
    }

    #[test]
    fn blake2f_out_of_gas_is_an_err() {
        let mut input = alloc::vec![0u8; BLAKE2F_INPUT_LEN];
        // rounds = 10 (big-endian en los primeros 4 bytes).
        input[3] = 10;
        assert!(run(BLAKE2F, &input, 9).is_err());
        assert!(must_run(BLAKE2F, &input, 10).gas_used == 10);
    }

    // ---------------------------------------------------- KZG POINT-EVAL

    /// Vector real de `kzg_point_evaluation.rs::tests::basic_test`
    /// (`c-kzg-4844` upstream) — `commitment`/`z`/`y`/`proof` transcritos
    /// del source, `versioned_hash` calculado con `hashlib.sha256` de
    /// Python (no de memoria, ver attempt_log de 016 it.1).
    #[test]
    fn kzg_point_evaluation_with_the_c_kzg_reference_vector_succeeds() {
        let input = hex_vec(
            "01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000001522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e98f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        );
        let expected = hex_vec(
            "000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        );
        let output = must_run(KZG_POINT_EVALUATION, &input, KZG_GAS);
        assert_eq!(output.gas_used, KZG_GAS);
        assert_eq!(output.data.as_ref(), expected.as_slice());
    }

    /// El `versioned_hash` declarado no coincide con
    /// `sha256(commitment)` — mismo `commitment`/`z`/`y`/`proof` del vector
    /// de arriba, primer byte del `versioned_hash` mutado (sigue siendo
    /// `0x01` de versión válida, pero ya no hashea al mismo valor).
    #[test]
    fn kzg_point_evaluation_fails_when_the_versioned_hash_does_not_match_the_commitment() {
        let mut input = hex_vec(
            "01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000001522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e98f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        );
        input[1] ^= 0xff;
        assert!(run(KZG_POINT_EVALUATION, &input, KZG_GAS).is_err());
    }

    /// La prueba KZG no verifica contra el `commitment`/`z`/`y` declarados
    /// (`proof` mutado un byte, sigue siendo un punto G1 válido pero de otra
    /// prueba) — falla en el pairing check, no en el parseo (task 016 §7,
    /// distingue esta clase del punto malformado de abajo aunque ambas
    /// colapsen al mismo `Err(())`).
    #[test]
    fn kzg_point_evaluation_fails_when_the_proof_does_not_verify() {
        let mut input = hex_vec(
            "01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000001522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e98f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        );
        // z: primer byte del campo `z` (offset 32) decrementado en 1
        // (0x73 → 0x72) — CANÓNICO por construcción (un byte líder menor,
        // mismo largo, es un valor estrictamente menor, nunca cruza el
        // módulo) a diferencia de mutar el byte final, que arriesga cruzar
        // `BLS_MODULUS` (el vector real usa `z = BLS_MODULUS - 1`, el
        // máximo canónico) y disparar el chequeo de canonicidad en vez del
        // pairing — no lo que este test quiere ejercitar.
        input[32] -= 1;
        assert!(run(KZG_POINT_EVALUATION, &input, KZG_GAS).is_err());
    }

    /// `z = BLS_MODULUS + (BLS_MODULUS - 1)` (`2p-1`, byte-representable en
    /// 32 bytes — `p` tiene 255 bits, `2p-1` cabe justo en 256 — pero FUERA
    /// del rango canónico `[0, p)`) — a diferencia de `read_scalar` de
    /// BN254 (2.8c, que reduce cualquier valor módulo el orden porque MUL
    /// no lo necesita canónico), EIP-4844 exige que `z`/`y` sean canónicos
    /// (task 016 §4).
    ///
    /// **Construcción deliberada, no `z = BLS_MODULUS` a secas:** `2p-1
    /// mod p == p-1`, exactamente el `z` REAL que usa el vector de
    /// `basic_test` — si el chequeo de canonicidad estuviera roto (mutation
    /// testing del attempt_log de 016 it.3), `Fr::from_be_bytes_mod_order`
    /// reduciría `2p-1` al `z` correcto y el pairing VERIFICARÍA (`y`/
    /// `commitment`/`proof` son los reales para ese `z`) — el test pasaría
    /// igual pero por la razón EQUIVOCADA. Con `z = BLS_MODULUS` (reduce a
    /// `0`, no al `z` real), el pairing fallaría de todas formas SIN que el
    /// chequeo de canonicidad hiciera nada — un test que no prueba lo que
    /// dice probar, el mismo patrón exacto que el bug de fixtures de 2.8c/
    /// 2.8d pero en un unit test en vez de un fixture.
    #[test]
    fn kzg_point_evaluation_fails_when_z_is_not_a_canonical_scalar() {
        let mut input = hex_vec(
            "01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000001522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e98f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        );
        let non_canonical_z =
            hex_vec("e7db4ea6533afa906673b0101343b00aa77b4805fffcb7fdfffffffe00000001");
        input[32..64].copy_from_slice(&non_canonical_z);
        assert!(run(KZG_POINT_EVALUATION, &input, KZG_GAS).is_err());
    }

    #[test]
    fn kzg_point_evaluation_fails_on_a_length_other_than_192() {
        assert!(run(KZG_POINT_EVALUATION, &[0u8; 191], KZG_GAS).is_err());
        assert!(run(KZG_POINT_EVALUATION, &[0u8; 193], KZG_GAS).is_err());
        assert!(run(KZG_POINT_EVALUATION, &[], KZG_GAS).is_err());
    }

    #[test]
    fn kzg_point_evaluation_fails_when_the_commitment_is_not_a_valid_g1_point() {
        let mut input = alloc::vec![0u8; KZG_INPUT_LEN];
        // Byte de flags de compresión (bit alto seteado) + resto arbitrario:
        // no describe ningún punto real de la curva.
        input[96] = 0xff;
        for byte in &mut input[97..144] {
            *byte = 0x11;
        }
        assert!(run(KZG_POINT_EVALUATION, &input, KZG_GAS).is_err());
    }

    /// `commitment` es un punto REAL de la curva (`x=5`, `y` es la raíz
    /// cuadrada real de `x³+4` en `Fq`) pero FUERA del subgrupo de orden
    /// primo (el cofactor de G1 en BLS12-381 es ~76 bits — casi cualquier
    /// `x` válido cae fuera del subgrupo; generado offline con un
    /// mini-proyecto Cargo standalone que usa `ark-bls12-381` directo,
    /// mismo patrón que el vector de ECRECOVER de 012 — ver attempt_log de
    /// 016 it.3). Distingue esta clase de `..._is_not_a_valid_g1_point`
    /// (bytes de flags inconsistentes, rechazado en la decompresión misma)
    /// — acá la decompresión SÍ produce un punto, el chequeo de subgrupo es
    /// lo único que lo rechaza (`deserialize_compressed` CHECKED, task 016
    /// §4/`Prohibido`: nunca `_unchecked` para input externo).
    #[test]
    fn kzg_point_evaluation_fails_when_the_commitment_is_on_curve_but_off_subgroup() {
        let input = hex_vec(
            "0189c5f7d80c24e1f95b2f6fc04898fc2048cefa2bcdffc177fa05d446ca8b1b73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000000001522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c",
        );
        assert!(run(KZG_POINT_EVALUATION, &input, KZG_GAS).is_err());
    }

    #[test]
    fn kzg_point_evaluation_out_of_gas_is_an_err() {
        let input = alloc::vec![0u8; KZG_INPUT_LEN];
        assert!(run(KZG_POINT_EVALUATION, &input, KZG_GAS - 1).is_err());
    }
}
