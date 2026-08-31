//! La implementación de **referencia** del seam `Crypto`.
//!
//! Puro Rust `no_std`, con las mismas dependencias y las mismas versiones que
//! el `revm` pineado en este repo activa: `k256`, `sha2`, `ripemd`,
//! `aurora-engine-modexp` y `arkworks` (`ark-bn254`, `ark-bls12-381`). La
//! matemática se movió acá **verbatim** desde `precompiles.rs`, con sus
//! comentarios: cada línea de esta familia costó cara de escribir, y mudarla de
//! lugar no es re-derivarla.
//!
//! **No es un fallback degradado: es el árbitro.** Es la que corre en los cinco
//! ejes nativos, la que el diferencial vs `revm` y EEST validan, y la que el
//! escalón de conformance dentro del zkVM usa como oráculo de cada caso. Cuando
//! los N backends aceleren, sigue siendo el tercer testigo que no leyó el header
//! de ninguno de ellos.

use alloc::vec::Vec;
use core::ops::Neg;

use ark_bls12_381::{
    Bls12_381, Fq as Bls12Fq, Fq2 as Bls12Fq2, Fr as Bls12Fr, G1Affine as Bls12G1Affine,
    G1Projective as Bls12G1Projective, G2Affine as Bls12G2Affine,
    G2Projective as Bls12G2Projective,
};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use repo_b_common::crypto::{
    BLS12_FP_LEN, BLS12_FP2_LEN, BLS12_G1_COMPRESSED_LEN, BLS12_G1_LEN, BLS12_G2_COMPRESSED_LEN,
    BLS12_G2_LEN, BLS12_SCALAR_LEN, BN254_G1_LEN, BN254_SCALAR_LEN, Bls12G1MsmPair, Bls12G2MsmPair,
    Bls12PairingPair, Bn254PairingPair, Crypto,
};
use ripemd::Digest as _;

/// Largo de un `Fq` de BN254.
const FQ_LEN: usize = 32;
/// Largo de un `Fq2` de BN254.
const FQ2_LEN: usize = 2 * FQ_LEN;

/// El provider de referencia. Tipo sin datos: el despacho es estático.
pub struct Reference;

// ------------------------------------------------------------------- BN254

/// Lee un `Fq` (elemento del campo base) de 32 bytes big-endian. `Fq::
/// deserialize_uncompressed` exige un miembro válido del campo (`< p`); un
/// byte-string que no lo es el primer modo de fallo de esta familia.
fn read_fq(bytes: &[u8]) -> Result<Fq, ()> {
    let mut little_endian = [0u8; FQ_LEN];
    little_endian.copy_from_slice(bytes);
    little_endian.reverse();
    Fq::deserialize_uncompressed(&little_endian[..]).map_err(|_| ())
}

/// Lee un `Fq2` de 64 bytes. **Orden invertido, verificado contra `read_fq2`
/// de revm: el componente `y` (segunda coordenada) se lee PRIMERO, después
/// `x`** — la trampa de transcripción central del slice que lo escribió.
fn read_fq2(bytes: &[u8]) -> Result<Fq2, ()> {
    let y = read_fq(&bytes[..FQ_LEN])?;
    let x = read_fq(&bytes[FQ_LEN..2 * FQ_LEN])?;
    Ok(Fq2::new(x, y))
}

/// Construye un punto G1 a partir de coordenadas afines. `(0,0)` es el punto al
/// infinito por convención de la EVM — `G1Affine` no puede representarlo como un
/// punto "en la curva" real, así que se detecta ANTES de chequear
/// curva/subgrupo (mismo orden que `new_g1_point` de revm).
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

fn write_fq_be(dest: &mut [u8], value: Fq) -> Result<(), ()> {
    let mut little_endian = [0u8; FQ_LEN];
    value
        .serialize_uncompressed(&mut little_endian[..])
        .map_err(|_| ())?;
    little_endian.reverse();
    dest.copy_from_slice(&little_endian);
    Ok(())
}

/// Codifica un G1 en 64 bytes big-endian (`x` seguido de `y`); el punto al
/// infinito se codifica como 64 ceros (`point.xy()` da `None` para él). La
/// serialización de un `Fq` en un buffer de EXACTAMENTE `FQ_LEN` bytes es
/// infalible por invariante de tipo (no depende del input hostil) — igual se
/// propaga como `Err(())` en vez de `expect`/`unwrap`, fail-closed por si esa
/// invariante alguna vez deja de sostenerse.
fn encode_g1_point(point: G1Affine) -> Result<[u8; BN254_G1_LEN], ()> {
    let mut output = [0u8; BN254_G1_LEN];
    if let Some((x, y)) = point.xy() {
        write_fq_be(&mut output[..FQ_LEN], x)?;
        write_fq_be(&mut output[FQ_LEN..], y)?;
    }
    Ok(output)
}

// -------------------------------------------------------------- BLS12-381

/// Lee un `Fp` de 48 bytes big-endian **canónicos** — el padding a 64 que
/// EIP-2537 define lo saca el caller antes de llegar acá.
fn bls12_read_fp(bytes: &[u8]) -> Result<Bls12Fq, ()> {
    let mut little_endian = [0u8; BLS12_FP_LEN];
    little_endian.copy_from_slice(bytes);
    little_endian.reverse();
    Bls12Fq::deserialize_uncompressed(&little_endian[..]).map_err(|_| ())
}

fn bls12_write_fp(dest: &mut [u8], value: Bls12Fq) -> Result<(), ()> {
    let mut little_endian = [0u8; BLS12_FP_LEN];
    value
        .serialize_uncompressed(&mut little_endian[..])
        .map_err(|_| ())?;
    little_endian.reverse();
    dest.copy_from_slice(&little_endian);
    Ok(())
}

/// Lee un `Fp2` de 96 bytes (2×`Fp`, orden DIRECTO `c0, c1` — sin la inversión
/// de BN254).
fn bls12_read_fp2(bytes: &[u8]) -> Result<Bls12Fq2, ()> {
    let c0 = bls12_read_fp(&bytes[..BLS12_FP_LEN])?;
    let c1 = bls12_read_fp(&bytes[BLS12_FP_LEN..BLS12_FP2_LEN])?;
    Ok(Bls12Fq2::new(c0, c1))
}

/// Construye un punto G1. `(0,0)` es el punto al infinito por convención de la
/// EVM. `require_subgroup` **lo decide el caller**: es la política de EIP-2537
/// (ADD sin chequeo, MSM/PAIRING con), y no vive de este lado.
fn bls12_new_g1_point(x: Bls12Fq, y: Bls12Fq, require_subgroup: bool) -> Result<Bls12G1Affine, ()> {
    if x.is_zero() && y.is_zero() {
        return Ok(Bls12G1Affine::zero());
    }
    let point = Bls12G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(());
    }
    if require_subgroup && !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(());
    }
    Ok(point)
}

fn bls12_new_g2_point(
    x: Bls12Fq2,
    y: Bls12Fq2,
    require_subgroup: bool,
) -> Result<Bls12G2Affine, ()> {
    if x.is_zero() && y.is_zero() {
        return Ok(Bls12G2Affine::zero());
    }
    let point = Bls12G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(());
    }
    if require_subgroup && !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(());
    }
    Ok(point)
}

fn bls12_read_g1(bytes: &[u8; BLS12_G1_LEN], require_subgroup: bool) -> Result<Bls12G1Affine, ()> {
    let x = bls12_read_fp(&bytes[..BLS12_FP_LEN])?;
    let y = bls12_read_fp(&bytes[BLS12_FP_LEN..])?;
    bls12_new_g1_point(x, y, require_subgroup)
}

fn bls12_read_g2(bytes: &[u8; BLS12_G2_LEN], require_subgroup: bool) -> Result<Bls12G2Affine, ()> {
    let x = bls12_read_fp2(&bytes[..BLS12_FP2_LEN])?;
    let y = bls12_read_fp2(&bytes[BLS12_FP2_LEN..])?;
    bls12_new_g2_point(x, y, require_subgroup)
}

/// El escalar de MSM NO necesita ser canónico: se reduce mod `r`.
fn bls12_read_scalar(bytes: &[u8]) -> Bls12Fr {
    Bls12Fr::from_be_bytes_mod_order(bytes)
}

fn bls12_encode_g1(point: Bls12G1Affine) -> Result<[u8; BLS12_G1_LEN], ()> {
    let mut output = [0u8; BLS12_G1_LEN];
    if let Some((x, y)) = point.xy() {
        bls12_write_fp(&mut output[..BLS12_FP_LEN], x)?;
        bls12_write_fp(&mut output[BLS12_FP_LEN..], y)?;
    }
    Ok(output)
}

fn bls12_encode_g2(point: Bls12G2Affine) -> Result<[u8; BLS12_G2_LEN], ()> {
    let mut output = [0u8; BLS12_G2_LEN];
    if let Some((x, y)) = point.xy() {
        bls12_write_fp(&mut output[..BLS12_FP_LEN], x.c0)?;
        bls12_write_fp(&mut output[BLS12_FP_LEN..2 * BLS12_FP_LEN], x.c1)?;
        bls12_write_fp(&mut output[2 * BLS12_FP_LEN..3 * BLS12_FP_LEN], y.c0)?;
        bls12_write_fp(&mut output[3 * BLS12_FP_LEN..], y.c1)?;
    }
    Ok(output)
}

/// Puerto directo de `WBMap::map_to_curve(...).clear_cofactor()` — el mapa
/// SWU+isogeny ya viene de `arkworks`, no se re-deriva. `Err(())`:
/// `map_to_curve` es infalible para BLS12-381 (revm lo marca con `.expect`),
/// pero se propaga fail-closed de todas formas.
fn bls12_map_to_g1(fp: Bls12Fq) -> Result<Bls12G1Affine, ()> {
    let point = WBMap::map_to_curve(fp).map_err(|_| ())?;
    Ok(point.clear_cofactor())
}

fn bls12_map_to_g2(fp2: Bls12Fq2) -> Result<Bls12G2Affine, ()> {
    let point = WBMap::map_to_curve(fp2).map_err(|_| ())?;
    Ok(point.clear_cofactor())
}

impl Crypto for Reference {
    fn sha256(input: &[u8]) -> [u8; 32] {
        let digest = sha2::Sha256::digest(input);
        let mut output = [0u8; 32];
        output.copy_from_slice(&digest);
        output
    }

    fn ripemd160(input: &[u8]) -> [u8; 20] {
        let mut hasher = ripemd::Ripemd160::new();
        hasher.update(input);
        let digest = hasher.finalize();
        let mut output = [0u8; 20];
        output.copy_from_slice(&digest);
        output
    }

    /// `k256` normaliza un `s` alto (lo reduce a `n-s` y flipea `v`), así que un
    /// `s` alto **no se rechaza**: recupera la MISMA dirección. Es malleability,
    /// no EIP-2 — verificado contra el source de revm, y esa conclusión no se
    /// re-deriva acá.
    fn secp256k1_ecrecover(
        message_hash: &[u8; 32],
        signature: &[u8; 64],
        recovery_id: u8,
    ) -> Result<[u8; 64], ()> {
        let mut sig = Signature::from_slice(signature).map_err(|_| ())?;
        let mut recovery_id = recovery_id;
        // BIP-62 / RustCrypto `normalize_s`: un `s` alto se reemplaza por `n - s`
        // y el bit de paridad de la recovery id se invierte — la MISMA firma
        // matemáticamente, no una rechazada.
        if let Some(normalized) = sig.normalize_s() {
            sig = normalized;
            recovery_id ^= 1;
        }
        let recid = RecoveryId::from_byte(recovery_id).ok_or(())?;
        let key = VerifyingKey::recover_from_prehash(message_hash, &sig, recid).map_err(|_| ())?;
        let point = key.to_encoded_point(false);
        let bytes = point.as_bytes();
        // `to_encoded_point(false)` da 65 bytes: el prefijo `0x04` y después
        // `x ‖ y`. El prefijo no es parte de la clave.
        if bytes.len() != 65 {
            return Err(());
        }
        let mut output = [0u8; 64];
        output.copy_from_slice(&bytes[1..]);
        Ok(output)
    }

    fn modexp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8> {
        aurora_engine_modexp::modexp(base, exponent, modulus)
    }

    fn bn254_g1_add(
        p1: &[u8; BN254_G1_LEN],
        p2: &[u8; BN254_G1_LEN],
    ) -> Result<[u8; BN254_G1_LEN], ()> {
        let a = read_g1_point(p1)?;
        let b = read_g1_point(p2)?;
        let a_projective: G1Projective = a.into();
        encode_g1_point((a_projective + b).into_affine())
    }

    fn bn254_g1_mul(
        point: &[u8; BN254_G1_LEN],
        scalar: &[u8; BN254_SCALAR_LEN],
    ) -> Result<[u8; BN254_G1_LEN], ()> {
        let p = read_g1_point(point)?;
        let s = Fr::from_be_bytes_mod_order(scalar);
        encode_g1_point(p.mul_bigint(s.into_bigint()).into_affine())
    }

    fn bn254_pairing_check(pairs: &[Bn254PairingPair]) -> Result<bool, ()> {
        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());
        for (g1_bytes, g2_bytes) in pairs {
            let g1 = read_g1_point(g1_bytes)?;
            let g2 = read_g2_point(g2_bytes)?;
            // Un par con un punto al infinito contribuye `e(∞, Q) = 1` al
            // producto: se saltea el cómputo, nunca la validación.
            if !g1.is_zero() && !g2.is_zero() {
                g1_points.push(g1);
                g2_points.push(g2);
            }
        }
        Ok(g1_points.is_empty() || Bn254::multi_pairing(&g1_points, &g2_points).0.is_one())
    }

    fn bls12_g1_add(
        p1: &[u8; BLS12_G1_LEN],
        p2: &[u8; BLS12_G1_LEN],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G1_LEN], ()> {
        let a = bls12_read_g1(p1, require_subgroup)?;
        let b = bls12_read_g1(p2, require_subgroup)?;
        bls12_encode_g1((a.into_group() + b).into_affine())
    }

    fn bls12_g2_add(
        p1: &[u8; BLS12_G2_LEN],
        p2: &[u8; BLS12_G2_LEN],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G2_LEN], ()> {
        let a = bls12_read_g2(p1, require_subgroup)?;
        let b = bls12_read_g2(p2, require_subgroup)?;
        bls12_encode_g2((a.into_group() + b).into_affine())
    }

    fn bls12_g1_msm(
        pairs: &[Bls12G1MsmPair],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G1_LEN], ()> {
        let mut points = Vec::with_capacity(pairs.len());
        let mut scalars = Vec::with_capacity(pairs.len());
        for (point_bytes, scalar_bytes) in pairs {
            // El punto se valida SIEMPRE, aunque su escalar sea cero: un escalar
            // cero no exime al punto de ser válido (EIP-2537).
            let point = bls12_read_g1(point_bytes, require_subgroup)?;
            if scalar_bytes.iter().all(|byte| *byte == 0) {
                continue;
            }
            points.push(point);
            scalars.push(bls12_read_scalar(scalar_bytes));
        }
        let result = if points.is_empty() {
            Bls12G1Affine::zero()
        } else {
            Bls12G1Projective::msm(&points, &scalars)
                .map_err(|_| ())?
                .into_affine()
        };
        bls12_encode_g1(result)
    }

    fn bls12_g2_msm(
        pairs: &[Bls12G2MsmPair],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G2_LEN], ()> {
        let mut points = Vec::with_capacity(pairs.len());
        let mut scalars = Vec::with_capacity(pairs.len());
        for (point_bytes, scalar_bytes) in pairs {
            let point = bls12_read_g2(point_bytes, require_subgroup)?;
            if scalar_bytes.iter().all(|byte| *byte == 0) {
                continue;
            }
            points.push(point);
            scalars.push(bls12_read_scalar(scalar_bytes));
        }
        let result = if points.is_empty() {
            Bls12G2Affine::zero()
        } else {
            Bls12G2Projective::msm(&points, &scalars)
                .map_err(|_| ())?
                .into_affine()
        };
        bls12_encode_g2(result)
    }

    fn bls12_pairing_check(pairs: &[Bls12PairingPair], require_subgroup: bool) -> Result<bool, ()> {
        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());
        for (g1_bytes, g2_bytes) in pairs {
            let g1 = bls12_read_g1(g1_bytes, require_subgroup)?;
            let g2 = bls12_read_g2(g2_bytes, require_subgroup)?;
            if !g1.is_zero() && !g2.is_zero() {
                g1_points.push(g1);
                g2_points.push(g2);
            }
        }
        Ok(g1_points.is_empty() || Bls12_381::multi_pairing(&g1_points, &g2_points).0.is_one())
    }

    fn bls12_map_fp_to_g1(element: &[u8; BLS12_FP_LEN]) -> Result<[u8; BLS12_G1_LEN], ()> {
        let fp = bls12_read_fp(element)?;
        bls12_encode_g1(bls12_map_to_g1(fp)?)
    }

    fn bls12_map_fp2_to_g2(element: &[u8; BLS12_FP2_LEN]) -> Result<[u8; BLS12_G2_LEN], ()> {
        let fp2 = bls12_read_fp2(element)?;
        bls12_encode_g2(bls12_map_to_g2(fp2)?)
    }

    /// El round-trip serializado detecta si `from_be_bytes_mod_order` REALMENTE
    /// redujo algo, que es lo que distingue un escalar canónico de uno que no.
    fn bls12_scalar_is_canonical(scalar: &[u8; BLS12_SCALAR_LEN]) -> bool {
        let value = Bls12Fr::from_be_bytes_mod_order(scalar);
        let mut roundtrip = [0u8; BLS12_SCALAR_LEN];
        let big = value.into_bigint().to_bytes_be();
        let Some(offset) = BLS12_SCALAR_LEN.checked_sub(big.len()) else {
            return false;
        };
        roundtrip[offset..].copy_from_slice(&big);
        roundtrip == *scalar
    }

    fn bls12_scalar_neg(scalar: &[u8; BLS12_SCALAR_LEN]) -> [u8; BLS12_SCALAR_LEN] {
        let value = Bls12Fr::from_be_bytes_mod_order(scalar).neg();
        let mut output = [0u8; BLS12_SCALAR_LEN];
        let big = value.into_bigint().to_bytes_be();
        let offset = BLS12_SCALAR_LEN.saturating_sub(big.len());
        output[offset..].copy_from_slice(&big);
        output
    }

    /// `deserialize_compressed` CHECKED (valida curva + subgrupo), nunca la
    /// variante `_unchecked`: esto es input externo.
    fn bls12_g1_decompress(
        bytes: &[u8; BLS12_G1_COMPRESSED_LEN],
    ) -> Result<[u8; BLS12_G1_LEN], ()> {
        let point = Bls12G1Affine::deserialize_compressed(&bytes[..]).map_err(|_| ())?;
        bls12_encode_g1(point)
    }

    fn bls12_g2_decompress(
        bytes: &[u8; BLS12_G2_COMPRESSED_LEN],
    ) -> Result<[u8; BLS12_G2_LEN], ()> {
        let point = Bls12G2Affine::deserialize_compressed(&bytes[..]).map_err(|_| ())?;
        bls12_encode_g2(point)
    }

    fn bls12_g1_generator() -> Result<[u8; BLS12_G1_LEN], ()> {
        bls12_encode_g1(Bls12G1Affine::generator())
    }

    fn bls12_g2_generator() -> Result<[u8; BLS12_G2_LEN], ()> {
        bls12_encode_g2(Bls12G2Affine::generator())
    }
}
