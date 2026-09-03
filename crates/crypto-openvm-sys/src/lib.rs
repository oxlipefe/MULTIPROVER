//! Las llamadas crudas a los símbolos aceleradores de OpenVM, y nada más.
//!
//! # Por qué este crate existe
//!
//! El backend OpenVM implementa la interfaz C de aceleradores de `eth-act`
//! (`zkvm_accelerators.h`) sobre sus propias intrínsecas RISC-V. Llamar a esos
//! símbolos exige `unsafe`, y el workspace del motor declara
//! `unsafe_code = "forbid"` — que es absoluto y no se levanta con un `allow`.
//!
//! Así que el `unsafe` vive acá, en el crate más chico posible, y **ninguna
//! regla de consenso se decide de este lado**: estas funciones traducen bytes a
//! punteros, llaman, y devuelven `Result<_, ()>` según el status. Qué se llama,
//! con qué política y qué se hace ante un fallo se decide en `crates/evm`, que
//! sí hereda el `forbid`.
//!
//! # Los tipos son `repr(C, align(8))` y no `[u8; N]` pelado
//!
//! El header declara cada buffer como un `struct` con `ALIGN8`. Un `[u8; N]` de
//! Rust tiene alineación 1: pasar su puntero cumpliría la firma y violaría el
//! contrato. Por eso cada tamaño tiene su tipo, y los arrays entran y salen por
//! copia.
//!
//! # Los símbolos no se resuelven acá
//!
//! Los provee `ere-platform-openvm` al linkear el binario del guest, con su
//! feature `zkvm-accelerator` (default). Un build que habilite este provider
//! sin ese linkeo **no linkea**, que es la falla correcta: ruidosa y temprana.

#![no_std]
// `Err(())` sin tipo propio es la misma decisión que toma el trait `Crypto`: en
// esta familia el caller nunca ramifica por el motivo, y el status del símbolo
// no trae más información que "falló". Un enum acá sería superficie que nadie
// lee.
#![allow(clippy::result_unit_err)]

extern crate alloc;

use alloc::vec::Vec;

/// `ZKVM_EOK` del header. Cualquier otro valor es fallo.
const ZKVM_EOK: i32 = 0;

macro_rules! bytes_tipo {
    ($nombre:ident, $largo:expr) => {
        #[repr(C, align(8))]
        #[derive(Clone, Copy)]
        pub struct $nombre {
            pub data: [u8; $largo],
        }
        impl $nombre {
            #[must_use]
            pub const fn new(data: [u8; $largo]) -> Self {
                Self { data }
            }
        }
    };
}

bytes_tipo!(Bytes32, 32);
bytes_tipo!(Bytes48, 48);
bytes_tipo!(Bytes64, 64);
bytes_tipo!(Bytes96, 96);
bytes_tipo!(Bytes128, 128);
bytes_tipo!(Bytes192, 192);

/// `zkvm_bn254_pairing_pair`: un G1 de 64 y un G2 de 128, en ese orden.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Bn254PairingPair {
    pub g1: Bytes64,
    pub g2: Bytes128,
}

/// `zkvm_bls12_381_g1_msm_pair`: el punto y después el escalar.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Bls12G1MsmPair {
    pub point: Bytes96,
    pub scalar: Bytes32,
}

/// `zkvm_bls12_381_g2_msm_pair`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Bls12G2MsmPair {
    pub point: Bytes192,
    pub scalar: Bytes32,
}

/// `zkvm_bls12_381_pairing_pair`.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Bls12PairingPair {
    pub g1: Bytes96,
    pub g2: Bytes192,
}

// Las declaraciones, transcritas de `zkvm_accelerators.h`. El orden de los
// parámetros y el ancho de cada buffer son parte del contrato: un error acá no
// da error de compilación, da resultados equivocados.
unsafe extern "C" {
    fn zkvm_sha256(data: *const u8, len: usize, output: *mut Bytes32) -> i32;
    fn zkvm_ripemd160(data: *const u8, len: usize, output: *mut Bytes32) -> i32;
    fn zkvm_secp256k1_ecrecover(
        msg: *const Bytes32,
        sig: *const Bytes64,
        recid: u8,
        output: *mut Bytes64,
    ) -> i32;
    fn zkvm_modexp(
        base: *const u8,
        base_len: usize,
        exp: *const u8,
        exp_len: usize,
        modulus: *const u8,
        mod_len: usize,
        output: *mut u8,
    ) -> i32;
    fn zkvm_bn254_g1_add(p1: *const Bytes64, p2: *const Bytes64, result: *mut Bytes64) -> i32;
    fn zkvm_bn254_g1_mul(
        point: *const Bytes64,
        scalar: *const Bytes32,
        result: *mut Bytes64,
    ) -> i32;
    fn zkvm_bn254_pairing(pairs: *const Bn254PairingPair, num: usize, verified: *mut bool) -> i32;
    fn zkvm_bls12_g1_add(p1: *const Bytes96, p2: *const Bytes96, result: *mut Bytes96) -> i32;
    fn zkvm_bls12_g2_add(p1: *const Bytes192, p2: *const Bytes192, result: *mut Bytes192) -> i32;
    fn zkvm_bls12_g1_msm(pairs: *const Bls12G1MsmPair, num: usize, result: *mut Bytes96) -> i32;
    fn zkvm_bls12_g2_msm(pairs: *const Bls12G2MsmPair, num: usize, result: *mut Bytes192) -> i32;
    fn zkvm_bls12_pairing(pairs: *const Bls12PairingPair, num: usize, verified: *mut bool) -> i32;
    fn zkvm_bls12_map_fp_to_g1(element: *const Bytes48, result: *mut Bytes96) -> i32;
    fn zkvm_bls12_map_fp2_to_g2(element: *const Bytes96, result: *mut Bytes192) -> i32;
}

/// Llama a un símbolo que llena un buffer de salida y devuelve status.
///
/// El patrón se repite en 12 de las 14 funciones y tenerlo una sola vez evita
/// que una de ellas se olvide de mirar el status — que sería aceptar un buffer
/// sin inicializar como si fuera un resultado.
macro_rules! llamar {
    ($tipo:ty, $largo:expr, $call:expr) => {{
        let mut salida = <$tipo>::new([0u8; $largo]);
        // SAFETY: `salida` es un valor propio, vivo y con la alineación que el
        // header pide (la da `repr(align(8))` del tipo). Los punteros de
        // entrada salen de referencias vivas del caller. El símbolo escribe a
        // lo sumo el ancho declarado, que es el del tipo.
        let status = unsafe { $call(&raw mut salida) };
        if status == ZKVM_EOK {
            Ok(salida.data)
        } else {
            Err(())
        }
    }};
}

/// SHA-256.
pub fn sha256(input: &[u8]) -> Result<[u8; 32], ()> {
    llamar!(Bytes32, 32, |out| zkvm_sha256(
        input.as_ptr(),
        input.len(),
        out
    ))
}

/// RIPEMD-160. **El símbolo devuelve 32 bytes con el digest alineado a
/// derecha**; recortar a los últimos 20 es del lado de `crates/evm`, que es
/// donde vive la regla del precompile.
pub fn ripemd160(input: &[u8]) -> Result<[u8; 32], ()> {
    llamar!(Bytes32, 32, |out| zkvm_ripemd160(
        input.as_ptr(),
        input.len(),
        out
    ))
}

/// Recuperación ECDSA sobre secp256k1. Devuelve el punto sin comprimir de 64
/// bytes, sin el prefijo `0x04`.
pub fn secp256k1_ecrecover(
    message_hash: &[u8; 32],
    signature: &[u8; 64],
    recovery_id: u8,
) -> Result<[u8; 64], ()> {
    let msg = Bytes32::new(*message_hash);
    let sig = Bytes64::new(*signature);
    llamar!(Bytes64, 64, |out| zkvm_secp256k1_ecrecover(
        &raw const msg,
        &raw const sig,
        recovery_id,
        out
    ))
}

/// `base^exp mod modulus`. La salida es de **exactamente `modulus.len()`
/// bytes**, con padding de ceros a izquierda (EIP-198).
///
/// El acelerador solo acelera el módulo del campo escalar de BN254; cualquier
/// otro corre en software, el mismo que usa la referencia.
pub fn modexp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>, ()> {
    let mut salida = alloc::vec![0u8; modulus.len()];
    // SAFETY: los tres slices de entrada están vivos durante la llamada.
    // `salida` tiene exactamente `modulus.len()` bytes, que es lo que el
    // símbolo declara escribir. Un módulo vacío da un slice vacío y el símbolo
    // no escribe nada.
    let status = unsafe {
        zkvm_modexp(
            base.as_ptr(),
            base.len(),
            exponent.as_ptr(),
            exponent.len(),
            modulus.as_ptr(),
            modulus.len(),
            salida.as_mut_ptr(),
        )
    };
    if status == ZKVM_EOK {
        Ok(salida)
    } else {
        Err(())
    }
}

/// Suma de puntos en G1 de BN254.
pub fn bn254_g1_add(p1: &[u8; 64], p2: &[u8; 64]) -> Result<[u8; 64], ()> {
    let (a, b) = (Bytes64::new(*p1), Bytes64::new(*p2));
    llamar!(Bytes64, 64, |out| zkvm_bn254_g1_add(
        &raw const a,
        &raw const b,
        out
    ))
}

/// Multiplicación escalar en G1 de BN254.
pub fn bn254_g1_mul(point: &[u8; 64], scalar: &[u8; 32]) -> Result<[u8; 64], ()> {
    let (p, s) = (Bytes64::new(*point), Bytes32::new(*scalar));
    llamar!(Bytes64, 64, |out| zkvm_bn254_g1_mul(
        &raw const p,
        &raw const s,
        out
    ))
}

/// Chequeo de pairing de BN254.
pub fn bn254_pairing_check(pairs: &[Bn254PairingPair]) -> Result<bool, ()> {
    let mut verificado = false;
    // SAFETY: `pairs` es un slice vivo de structs `repr(C)` con el layout que
    // el header declara; `verificado` es un `bool` propio y vivo. Con
    // `pairs.len() == 0` el símbolo recibe un puntero potencialmente colgado
    // pero con largo cero, que es lo que la interfaz C admite.
    let status = unsafe { zkvm_bn254_pairing(pairs.as_ptr(), pairs.len(), &raw mut verificado) };
    if status == ZKVM_EOK {
        Ok(verificado)
    } else {
        Err(())
    }
}

/// Suma de puntos en G1 de BLS12-381. **El símbolo NO chequea subgrupo** — la
/// política de EIP-2537 está cableada adentro y el caller tiene que saberlo.
pub fn bls12_g1_add(p1: &[u8; 96], p2: &[u8; 96]) -> Result<[u8; 96], ()> {
    let (a, b) = (Bytes96::new(*p1), Bytes96::new(*p2));
    llamar!(Bytes96, 96, |out| zkvm_bls12_g1_add(
        &raw const a,
        &raw const b,
        out
    ))
}

/// Suma de puntos en G2 de BLS12-381. **Tampoco chequea subgrupo.**
pub fn bls12_g2_add(p1: &[u8; 192], p2: &[u8; 192]) -> Result<[u8; 192], ()> {
    let (a, b) = (Bytes192::new(*p1), Bytes192::new(*p2));
    llamar!(Bytes192, 192, |out| zkvm_bls12_g2_add(
        &raw const a,
        &raw const b,
        out
    ))
}

/// MSM en G1 de BLS12-381. **El símbolo SIEMPRE exige subgrupo.**
pub fn bls12_g1_msm(pairs: &[Bls12G1MsmPair]) -> Result<[u8; 96], ()> {
    llamar!(Bytes96, 96, |out| zkvm_bls12_g1_msm(
        pairs.as_ptr(),
        pairs.len(),
        out
    ))
}

/// MSM en G2 de BLS12-381. **Siempre exige subgrupo.**
pub fn bls12_g2_msm(pairs: &[Bls12G2MsmPair]) -> Result<[u8; 192], ()> {
    llamar!(Bytes192, 192, |out| zkvm_bls12_g2_msm(
        pairs.as_ptr(),
        pairs.len(),
        out
    ))
}

/// Chequeo de pairing de BLS12-381. **Siempre exige subgrupo.**
pub fn bls12_pairing_check(pairs: &[Bls12PairingPair]) -> Result<bool, ()> {
    let mut verificado = false;
    // SAFETY: igual que en `bn254_pairing_check`.
    let status = unsafe { zkvm_bls12_pairing(pairs.as_ptr(), pairs.len(), &raw mut verificado) };
    if status == ZKVM_EOK {
        Ok(verificado)
    } else {
        Err(())
    }
}

/// `map_fp_to_g1` de EIP-2537.
pub fn bls12_map_fp_to_g1(element: &[u8; 48]) -> Result<[u8; 96], ()> {
    let e = Bytes48::new(*element);
    llamar!(Bytes96, 96, |out| zkvm_bls12_map_fp_to_g1(
        &raw const e,
        out
    ))
}

/// `map_fp2_to_g2` de EIP-2537.
pub fn bls12_map_fp2_to_g2(element: &[u8; 96]) -> Result<[u8; 192], ()> {
    let e = Bytes96::new(*element);
    llamar!(Bytes192, 192, |out| zkvm_bls12_map_fp2_to_g2(
        &raw const e,
        out
    ))
}
