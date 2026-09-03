//! El provider criptográfico de **OpenVM**: la misma regla, otra matemática.
//!
//! # Para qué existe
//!
//! El multiproof no compra nada si las dos pruebas comparten el modo de falla.
//! Con la referencia en los dos backends, las curvas las resuelve `arkworks` en
//! ambos: un bug suyo saldría **idéntico** en las dos pruebas y el contraste de
//! journals no lo vería. Este provider hace que dejen de compartirlo — los
//! símbolos aceleradores de OpenVM resuelven con sus propios tipos, generados
//! por `moduli_declare!`/`sw_declare!` sobre instrucciones RISC-V, sin tocar
//! `arkworks`.
//!
//! # Qué se decide acá y qué no
//!
//! El `unsafe` de la llamada vive en el crate `-sys`; este archivo hereda el
//! `forbid(unsafe_code)` del workspace. Acá se decide lo único que es de
//! consenso: **qué método usa el símbolo, cuál cae a la referencia, y cuándo
//! hay que negarse**.
//!
//! # Los 6 que caen a `Reference`, y por qué
//!
//! El estándar no expone símbolo para los auxiliares de KZG
//! (`scalar_is_canonical`, `scalar_neg`, los dos `decompress` y los dos
//! generadores). Delegan explícitamente a la referencia, que es la misma
//! matemática que ya validan los cinco ejes nativos. Delegar **dicho** no es lo
//! mismo que delegar en silencio: si mañana aparece un símbolo, se ve dónde
//! engancharlo.

use repo_b_common::crypto::{
    BLS12_FP_LEN, BLS12_FP2_LEN, BLS12_G1_COMPRESSED_LEN, BLS12_G1_LEN, BLS12_G2_COMPRESSED_LEN,
    BLS12_G2_LEN, BLS12_SCALAR_LEN, BN254_G1_LEN, BN254_SCALAR_LEN, Bls12G1MsmPair, Bls12G2MsmPair,
    Bls12PairingPair, Bn254PairingPair, Crypto,
};
use repo_b_crypto_openvm_sys as sys;

use super::reference::Reference;

/// El provider acelerado de OpenVM.
pub struct OpenVm;

/// La política de EIP-2537 que cada símbolo trae **cableada adentro**.
///
/// `zkvm_bls12_g1_add`/`g2_add` decodifican **sin** chequeo de subgrupo, y
/// `msm`/`pairing` **siempre** con él. Ninguno de los cinco toma un parámetro.
/// Nuestro trait sí lo toma, así que un pedido con la política contraria no se
/// puede satisfacer — y el contrato del trait dice qué hacer entonces: *"un
/// provider que no pueda honrar la combinación de argumentos que se le pide
/// devuelve `Err`; no elige otra política en silencio"*.
///
/// Hoy `precompiles.rs` siempre pide exactamente la combinación que cada
/// símbolo cablea, así que esta guarda no se dispara nunca. Eso la vuelve fácil
/// de omitir y es justamente por lo que está: lo que hoy es una coincidencia
/// afortunada del caller mañana es una divergencia de consenso silenciosa.
const fn honra(cableado: bool, pedido: bool) -> Result<(), ()> {
    if cableado == pedido { Ok(()) } else { Err(()) }
}

/// Lo que `g1_add` y `g2_add` cablean.
const ADD_CHEQUEA_SUBGRUPO: bool = false;
/// Lo que `msm` y `pairing` cablean.
const MSM_CHEQUEA_SUBGRUPO: bool = true;

impl Crypto for OpenVm {
    // ------------------------------------------------------------- hashes

    fn sha256(input: &[u8]) -> [u8; 32] {
        // El símbolo no tiene modo de fallo para un hash: un `Err` acá sería el
        // acelerador roto, no un input malo. La referencia contesta lo mismo y
        // no hay decisión de consenso que tomar.
        sys::sha256(input).unwrap_or_else(|()| Reference::sha256(input))
    }

    fn ripemd160(input: &[u8]) -> [u8; 20] {
        // El símbolo devuelve 32 bytes con el digest alineado a DERECHA (los
        // primeros 12 en cero). El recorte es la regla del precompile y vive
        // acá, no del lado del FFI.
        match sys::ripemd160(input) {
            Ok(ancho) => {
                let mut salida = [0u8; 20];
                salida.copy_from_slice(&ancho[12..]);
                salida
            }
            Err(()) => Reference::ripemd160(input),
        }
    }

    // ----------------------------------------------------------- secp256k1

    fn secp256k1_ecrecover(
        message_hash: &[u8; 32],
        signature: &[u8; 64],
        recovery_id: u8,
    ) -> Result<[u8; 64], ()> {
        sys::secp256k1_ecrecover(message_hash, signature, recovery_id)
    }

    // -------------------------------------------------------------- modexp

    fn modexp(base: &[u8], exponent: &[u8], modulus: &[u8]) -> alloc::vec::Vec<u8> {
        // El acelerador solo acelera el módulo del campo escalar de BN254;
        // cualquier otro corre en el MISMO software que la referencia. Se llama
        // igual para los dos casos: el corte lo hace el símbolo, no nosotros, y
        // duplicar ese criterio acá sería un segundo lugar donde puede diverger.
        sys::modexp(base, exponent, modulus)
            .unwrap_or_else(|()| Reference::modexp(base, exponent, modulus))
    }

    // --------------------------------------------------------------- BN254

    fn bn254_g1_add(
        p1: &[u8; BN254_G1_LEN],
        p2: &[u8; BN254_G1_LEN],
    ) -> Result<[u8; BN254_G1_LEN], ()> {
        sys::bn254_g1_add(p1, p2)
    }

    fn bn254_g1_mul(
        point: &[u8; BN254_G1_LEN],
        scalar: &[u8; BN254_SCALAR_LEN],
    ) -> Result<[u8; BN254_G1_LEN], ()> {
        sys::bn254_g1_mul(point, scalar)
    }

    fn bn254_pairing_check(pairs: &[Bn254PairingPair]) -> Result<bool, ()> {
        let crudos: alloc::vec::Vec<sys::Bn254PairingPair> = pairs
            .iter()
            .map(|(g1, g2)| sys::Bn254PairingPair {
                g1: sys::Bytes64::new(*g1),
                g2: sys::Bytes128::new(*g2),
            })
            .collect();
        sys::bn254_pairing_check(&crudos)
    }

    // ---------------------------------------------------------- BLS12-381

    fn bls12_g1_add(
        p1: &[u8; BLS12_G1_LEN],
        p2: &[u8; BLS12_G1_LEN],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G1_LEN], ()> {
        honra(ADD_CHEQUEA_SUBGRUPO, require_subgroup)?;
        sys::bls12_g1_add(p1, p2)
    }

    fn bls12_g2_add(
        p1: &[u8; BLS12_G2_LEN],
        p2: &[u8; BLS12_G2_LEN],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G2_LEN], ()> {
        honra(ADD_CHEQUEA_SUBGRUPO, require_subgroup)?;
        sys::bls12_g2_add(p1, p2)
    }

    fn bls12_g1_msm(
        pairs: &[Bls12G1MsmPair],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G1_LEN], ()> {
        honra(MSM_CHEQUEA_SUBGRUPO, require_subgroup)?;
        let crudos: alloc::vec::Vec<sys::Bls12G1MsmPair> = pairs
            .iter()
            .map(|(point, scalar)| sys::Bls12G1MsmPair {
                point: sys::Bytes96::new(*point),
                scalar: sys::Bytes32::new(*scalar),
            })
            .collect();
        sys::bls12_g1_msm(&crudos)
    }

    fn bls12_g2_msm(
        pairs: &[Bls12G2MsmPair],
        require_subgroup: bool,
    ) -> Result<[u8; BLS12_G2_LEN], ()> {
        honra(MSM_CHEQUEA_SUBGRUPO, require_subgroup)?;
        let crudos: alloc::vec::Vec<sys::Bls12G2MsmPair> = pairs
            .iter()
            .map(|(point, scalar)| sys::Bls12G2MsmPair {
                point: sys::Bytes192::new(*point),
                scalar: sys::Bytes32::new(*scalar),
            })
            .collect();
        sys::bls12_g2_msm(&crudos)
    }

    fn bls12_pairing_check(pairs: &[Bls12PairingPair], require_subgroup: bool) -> Result<bool, ()> {
        honra(MSM_CHEQUEA_SUBGRUPO, require_subgroup)?;
        // Una lista vacía es `Ok(true)` por contrato del trait, y se contesta
        // ACÁ en vez de delegarla: que el input vacío se rechace o no es regla
        // del caller (BLS12-381 lo rechaza, BN254 no), y no se le pregunta a un
        // símbolo que no la conoce.
        if pairs.is_empty() {
            return Ok(true);
        }
        let crudos: alloc::vec::Vec<sys::Bls12PairingPair> = pairs
            .iter()
            .map(|(g1, g2)| sys::Bls12PairingPair {
                g1: sys::Bytes96::new(*g1),
                g2: sys::Bytes192::new(*g2),
            })
            .collect();
        sys::bls12_pairing_check(&crudos)
    }

    fn bls12_map_fp_to_g1(element: &[u8; BLS12_FP_LEN]) -> Result<[u8; BLS12_G1_LEN], ()> {
        sys::bls12_map_fp_to_g1(element)
    }

    fn bls12_map_fp2_to_g2(element: &[u8; BLS12_FP2_LEN]) -> Result<[u8; BLS12_G2_LEN], ()> {
        sys::bls12_map_fp2_to_g2(element)
    }

    // ------------------- los 6 sin símbolo: delegan, y está dicho ---------

    fn bls12_scalar_is_canonical(scalar: &[u8; BLS12_SCALAR_LEN]) -> bool {
        Reference::bls12_scalar_is_canonical(scalar)
    }

    fn bls12_scalar_neg(scalar: &[u8; BLS12_SCALAR_LEN]) -> [u8; BLS12_SCALAR_LEN] {
        Reference::bls12_scalar_neg(scalar)
    }

    fn bls12_g1_decompress(
        bytes: &[u8; BLS12_G1_COMPRESSED_LEN],
    ) -> Result<[u8; BLS12_G1_LEN], ()> {
        Reference::bls12_g1_decompress(bytes)
    }

    fn bls12_g2_decompress(
        bytes: &[u8; BLS12_G2_COMPRESSED_LEN],
    ) -> Result<[u8; BLS12_G2_LEN], ()> {
        Reference::bls12_g2_decompress(bytes)
    }

    fn bls12_g1_generator() -> Result<[u8; BLS12_G1_LEN], ()> {
        Reference::bls12_g1_generator()
    }

    fn bls12_g2_generator() -> Result<[u8; BLS12_G2_LEN], ()> {
        Reference::bls12_g2_generator()
    }
}

#[cfg(test)]
mod tests {
    use super::{ADD_CHEQUEA_SUBGRUPO, MSM_CHEQUEA_SUBGRUPO, honra};

    /// La guarda de §3.2: pedir la política contraria a la que el símbolo
    /// cablea **se rechaza**, no se ignora.
    ///
    /// Este test es lo único que la ejercita: `precompiles.rs` siempre pide la
    /// combinación que cada símbolo trae, así que ningún eje puede verla. Es un
    /// hueco de cobertura estructural, no un olvido — y por eso se pinea acá.
    #[test]
    fn a_policy_the_symbol_cannot_honor_is_refused_instead_of_ignored() {
        assert!(honra(ADD_CHEQUEA_SUBGRUPO, false).is_ok());
        assert!(honra(ADD_CHEQUEA_SUBGRUPO, true).is_err());
        assert!(honra(MSM_CHEQUEA_SUBGRUPO, true).is_ok());
        assert!(honra(MSM_CHEQUEA_SUBGRUPO, false).is_err());
    }

    /// Las dos constantes describen lo que los símbolos hacen, y no son la
    /// misma. Si alguien las igualara, la guarda de arriba pasaría a ser un
    /// no-op sin que ningún test lo notara.
    #[test]
    fn the_two_hardwired_policies_are_not_the_same() {
        assert_ne!(ADD_CHEQUEA_SUBGRUPO, MSM_CHEQUEA_SUBGRUPO);
    }
}
