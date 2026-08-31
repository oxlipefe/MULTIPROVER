//! El seam `Crypto` — **N matemáticas, UNA regla**.
//!
//! Este trait es el único lugar por el que la criptografía cruza al motor. Cada
//! backend de proving inyecta su implementación de la **matemática**; la
//! **semántica de Ethereum** —parsing, padding, largos exactos, política de
//! chequeo de subgrupo por operación, orden de validación, modelo de error y
//! gas— se queda del lado del caller, única, en `precompiles.rs`.
//!
//! # Por qué las firmas no son las del estándar C, aunque se le parezcan
//!
//! `eth-act/zkvm-standards` publica `zkvm_accelerators.h`, y hay dos
//! implementaciones suyas en nuestro grafo de dependencias (SP1 vía `libzkevm`,
//! OpenVM vía `ere-platform-openvm`). Su README promete *"raw cryptographic
//! operations without Ethereum-specific constraints"*, pero **las firmas no
//! cumplen esa promesa**: `zkvm_bls12_g1_add` decodifica sus puntos **sin**
//! chequeo de subgrupo y `zkvm_bls12_g1_msm` **con** él — o sea que la política
//! de EIP-2537 vive adentro del acelerador. Medido en las dos implementaciones,
//! no deducido del texto.
//!
//! Bindear esos símbolos tal cual metería una regla de consenso adentro de cada
//! provider, y habría **N copias** de una trampa de consenso que hoy está
//! cerrada en un solo lugar. Por eso
//! acá la política viaja como **parámetro explícito** (`require_subgroup`): el
//! motor la decide una sola vez, en el call-site, y el provider la obedece. Un
//! provider que quiera bindear el ABI de C sigue pudiendo hacerlo —mapeando
//! `require_subgroup == false` al símbolo que no chequea— sin que el motor se
//! entere.
//!
//! # Qué NO cruza el seam
//!
//! - **El padding de EIP-2537.** Acá los puntos viajan en su largo **canónico**
//!   (G1 96 B, G2 192 B, `Fp` 48 B), no en el padded a múltiplos de 32 que el
//!   EIP define. El relleno de ceros es semántica de Ethereum.
//! - **La composición de KZG.** El seam expone MSM y pairing; el chequeo de
//!   EIP-4844 se compone del lado del motor, con su `versioned_hash` y su
//!   trusted setup. `zkvm_kzg_point_eval` no se bindea.
//! - **El gas, los largos de input, el right-pad y el modelo de error.**
//! - **Keccak**, que ya tiene chokepoint propio en `primitives.rs` y cuyo hook
//!   de aceleración es el feature `native-keccak` de `alloy-primitives`.
//! - **BLAKE2F**, que es un puerto propio sin dependencia externa y que ninguna
//!   de las dos implementaciones del estándar acelera: entra el día que un
//!   backend lo acelere, no antes.

use alloc::vec::Vec;

/// Largo canónico de un punto G1 de BN254 (`x ‖ y`, 32 B big-endian cada uno).
pub const BN254_G1_LEN: usize = 64;
/// Largo canónico de un punto G2 de BN254.
pub const BN254_G2_LEN: usize = 128;
/// Largo de un escalar de BN254. **No** se exige canónico: se reduce mod `r`.
pub const BN254_SCALAR_LEN: usize = 32;

/// Largo canónico de un `Fp` de BLS12-381 — 48 B, **sin** el padding a 64 del EIP.
pub const BLS12_FP_LEN: usize = 48;
/// Largo canónico de un `Fp2` de BLS12-381 (`c0 ‖ c1`, orden directo).
pub const BLS12_FP2_LEN: usize = 2 * BLS12_FP_LEN;
/// Largo canónico de un punto G1 de BLS12-381.
pub const BLS12_G1_LEN: usize = 2 * BLS12_FP_LEN;
/// Largo de un punto G1 de BLS12-381 **comprimido**, que es como EIP-4844
/// transporta el commitment y el proof de KZG.
pub const BLS12_G1_COMPRESSED_LEN: usize = 48;
/// Largo de un punto G2 de BLS12-381 comprimido.
pub const BLS12_G2_COMPRESSED_LEN: usize = 96;
/// Largo canónico de un punto G2 de BLS12-381.
pub const BLS12_G2_LEN: usize = 2 * BLS12_FP2_LEN;
/// Largo de un escalar de BLS12-381.
pub const BLS12_SCALAR_LEN: usize = 32;

/// Un par `(G1, G2)` de un pairing de BN254, en bytes canónicos.
pub type Bn254PairingPair = ([u8; BN254_G1_LEN], [u8; BN254_G2_LEN]);
/// Un par `(punto, escalar)` de un MSM de G1 de BLS12-381.
pub type Bls12G1MsmPair = ([u8; BLS12_G1_LEN], [u8; BLS12_SCALAR_LEN]);
/// Un par `(punto, escalar)` de un MSM de G2 de BLS12-381.
pub type Bls12G2MsmPair = ([u8; BLS12_G2_LEN], [u8; BLS12_SCALAR_LEN]);
/// Un par `(G1, G2)` de un pairing de BLS12-381.
pub type Bls12PairingPair = ([u8; BLS12_G1_LEN], [u8; BLS12_G2_LEN]);

/// La matemática criptográfica que el motor necesita, sin una sola regla de
/// Ethereum adentro.
///
/// Todos los métodos son **asociados** (sin `self`) a propósito: el provider
/// activo es un tipo sin datos y el despacho es estático, así que en el guest no
/// hay vtable ni indirección que el circuito tenga que pagar.
///
/// # El contrato del error
///
/// `Err(())` significa **"la matemática no se pudo hacer con este input"** — un
/// punto fuera de la curva, un elemento de campo no canónico, un punto fuera del
/// subgrupo **cuando el caller lo exigió**. Nunca significa "esto viola una
/// regla de Ethereum": eso lo decide el caller antes o después, nunca acá.
///
/// Un provider que no pueda honrar la combinación de argumentos que se le pide
/// **devuelve `Err`**; no elige otra política en silencio.
// `Err(())` sin tipo de error propio es DELIBERADO, y es la misma decisión que
// vale para `precompiles.rs`: en esta familia el caller nunca
// ramifica por el motivo del fallo —todos los caminos terminan en el mismo halt
// o en el mismo output vacío—, así que un enum de errores sería superficie que
// nadie lee. `clippy::result_unit_err` avisa de esto justamente porque en una
// API pública suele ser un olvido; acá no lo es.
#[allow(clippy::result_unit_err)]
pub trait Crypto {
    // ---------------------------------------------------------------- hashes

    /// SHA-256 (precompile `0x02`, y el `versioned_hash` de EIP-4844).
    fn sha256(input: &[u8]) -> [u8; 32];

    /// RIPEMD-160 (precompile `0x03`). Devuelve los 20 bytes crudos: el padding
    /// a 32 que el precompile publica es del caller.
    fn ripemd160(input: &[u8]) -> [u8; 20];

    // ----------------------------------------------------------- secp256k1

    /// Recuperación ECDSA sobre secp256k1.
    ///
    /// Devuelve la clave pública **sin comprimir y sin el byte de prefijo**
    /// (`x ‖ y`, 64 B). Derivar la dirección de ahí —el keccak de esos 64
    /// bytes, sus últimos 20— es del caller: eso es Ethereum, no secp256k1.
    ///
    /// `recovery_id` es 0 o 1. La normalización de un `s` alto es parte de la
    /// recuperación y **no** un rechazo: recupera la MISMA dirección
    /// (malleability, no EIP-2 — verificado contra el source de revm).
    fn secp256k1_ecrecover(
        message_hash: &[u8; 32],
        signature: &[u8; 64],
        recovery_id: u8,
    ) -> Result<[u8; 64], ()>;

    // -------------------------------------------------------------- modexp

    /// `base^exponent mod modulus` con operandos de largo arbitrario
    /// (precompile `0x05`). El gas de EIP-2565, los largos y el left-pad del
    /// resultado son del caller.
    fn modexp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Vec<u8>;

    // --------------------------------------------------------------- BN254

    /// Suma de dos puntos G1 (precompile `0x06`, EIP-196).
    ///
    /// No lleva parámetro de política porque en BN254 no hay dos políticas que
    /// elegir: G1 tiene cofactor 1, así que estar en la curva y estar en el
    /// subgrupo son la misma condición, y el chequeo se hace siempre. `(0, 0)`
    /// es el punto al infinito.
    fn bn254_g1_add(
        p1: &[u8; BN254_G1_LEN],
        p2: &[u8; BN254_G1_LEN],
    ) -> Result<[u8; BN254_G1_LEN], ()>;

    /// Multiplicación escalar en G1 (precompile `0x07`, EIP-196). El escalar se
    /// reduce mod `r`; no se exige canónico.
    fn bn254_g1_mul(
        point: &[u8; BN254_G1_LEN],
        scalar: &[u8; BN254_SCALAR_LEN],
    ) -> Result<[u8; BN254_G1_LEN], ()>;

    /// Chequeo de pairing (precompile `0x08`, EIP-197): ¿el producto de los
    /// pairings da 1?
    ///
    /// **El caller NO filtra los pares al infinito, y es a propósito:** en el
    /// motor un punto inválido cuyo compañero es el infinito se rechaza igual
    /// así que si el filtro corriera de este lado esos puntos nunca se
    /// validarían. El provider valida **todos** los pares y saltea el cómputo de
    /// los que tengan un punto al infinito —`e(∞, Q) = 1`, no cambia el
    /// producto—. Una lista vacía es `Ok(true)` por vacuidad; que el input vacío
    /// sea éxito en BN254 y rechazo en EIP-2537 lo decide el caller.
    fn bn254_pairing_check(pairs: &[Bn254PairingPair]) -> Result<bool, ()>;

    // --------------------------------------------------------- BLS12-381

    /// Suma en G1 (precompile `0x0b`, EIP-2537).
    ///
    /// `require_subgroup` es la política del EIP y la fija el caller: G1ADD la
    /// pide en `false`, MSM y PAIRING en `true`.
    fn bls12_g1_add(
        p1: &[u8; BLS12_G1_LEN],
        p2: &[u8; BLS12_G1_LEN],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G1_LEN], ()>;

    /// Suma en G2 (precompile `0x0d`, EIP-2537). Ver `bls12_g1_add`.
    fn bls12_g2_add(
        p1: &[u8; BLS12_G2_LEN],
        p2: &[u8; BLS12_G2_LEN],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G2_LEN], ()>;

    /// Multi-scalar multiplication en G1 (precompile `0x0c`, EIP-2537).
    /// Lista vacía ⇒ el punto al infinito.
    ///
    /// **Todos los puntos se validan, aunque su escalar sea cero.** El caller
    /// pasa los pares completos justamente para eso: un escalar cero no exime al
    /// punto de ser válido (EIP-2537), y hay un test que lo pinea.
    fn bls12_g1_msm(
        pairs: &[Bls12G1MsmPair],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G1_LEN], ()>;

    /// Multi-scalar multiplication en G2 (precompile `0x0e`, EIP-2537).
    fn bls12_g2_msm(
        pairs: &[Bls12G2MsmPair],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G2_LEN], ()>;

    /// Chequeo de pairing (precompile `0x0f`, EIP-2537). Que el input vacío se
    /// rechace —al revés de BN254— lo decide el caller: acá una lista vacía es
    /// `Ok(true)`.
    fn bls12_pairing_check(pairs: &[Bls12PairingPair], require_subgroup: bool) -> Result<bool, ()>;

    /// `map_fp_to_G1` (precompile `0x10`, EIP-2537): mapeo a la curva más
    /// `clear_cofactor`, o sea que el resultado está en el subgrupo por
    /// construcción.
    fn bls12_map_fp_to_g1(element: &[u8; BLS12_FP_LEN]) -> Result<[u8; BLS12_G1_LEN], ()>;

    /// `map_fp2_to_G2` (precompile `0x11`, EIP-2537).
    fn bls12_map_fp2_to_g2(element: &[u8; BLS12_FP2_LEN]) -> Result<[u8; BLS12_G2_LEN], ()>;

    /// ¿Es este escalar de BLS12-381 **canónico** (menor que el orden del
    /// subgrupo)? Lo necesita KZG, que a diferencia del escalar de MSM sí lo
    /// exige. Es una pregunta sobre el campo, no sobre Ethereum.
    fn bls12_scalar_is_canonical(scalar: &[u8; BLS12_SCALAR_LEN]) -> bool;

    /// La negación de un escalar mod `r`, que KZG usa para expresar una resta de
    /// puntos como un MSM.
    fn bls12_scalar_neg(scalar: &[u8; BLS12_SCALAR_LEN]) -> [u8; BLS12_SCALAR_LEN];

    /// Descomprime un punto G1 de 48 bytes, **validando curva y subgrupo**. Es
    /// el camino del commitment y el proof de EIP-4844, que son input externo.
    fn bls12_g1_decompress(bytes: &[u8; BLS12_G1_COMPRESSED_LEN])
    -> Result<[u8; BLS12_G1_LEN], ()>;

    /// Descomprime un punto G2 de 96 bytes, validando curva y subgrupo. Es el
    /// camino del `[τ]₂` del trusted setup de EIP-4844.
    fn bls12_g2_decompress(bytes: &[u8; BLS12_G2_COMPRESSED_LEN])
    -> Result<[u8; BLS12_G2_LEN], ()>;

    /// El generador de G1. Es un parámetro de la curva, no de Ethereum.
    fn bls12_g1_generator() -> Result<[u8; BLS12_G1_LEN], ()>;

    /// El generador de G2.
    fn bls12_g2_generator() -> Result<[u8; BLS12_G2_LEN], ()>;
}
