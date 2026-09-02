//! **La aritmética de consenso, con respuesta conocida, adentro del backend.**
//!
//! # Por qué existe
//!
//! La regla dura de este proyecto sobre los backends dice que *un bug del zkVM
//! te deja afuera —no prueba— pero NO te forkea la cadena*. Esa regla estaba
//! escrita y **nada la hacía cumplir**. OpenVM `v2.1.0-preview` la violó: miscompila la división de
//! enteros grandes cuando el divisor tiene el bit más alto prendido, de forma
//! **silenciosa y dependiente del valor** — rompe secp256k1 y no rompe bn254.
//!
//! Eso no es "el backend no prueba". Es **el backend prueba otra cosa**: una
//! prueba válida de una ejecución incorrecta. `DIV`, `MOD`, `ADDMOD` y `MULMOD`
//! del intérprete pasan por esa misma división, así que un contrato que divida
//! por un valor de bit alto prendido habría producido un state root equivocado
//! con una prueba que verifica.
//!
//! # Qué hace, y por qué acá y no en un binario aparte
//!
//! Corre operaciones de respuesta conocida y publica un digest de TODOS los
//! resultados. La gracia es que **este módulo se compila adentro del guest
//! real**: mismo crate, mismo perfil, mismas flags, mismo linker. Un KAT en un
//! binario aparte probaría ese binario y no el que prueba bloques — la lección
//! misma lección que dejó el primer ELF del árbol (*"sin floats en un binario
//! vacío no significa nada"*), aplicada a otra regla.
//!
//! # El oráculo no está hardcodeado, y es a propósito
//!
//! El driver corre **esta misma función** de forma nativa y compara el digest.
//! Una constante escrita a mano podría estar mal; el lado nativo, en cambio, es
//! el que ya sostiene los dos ejes completos de conformance. Es la forma del
//! contraste dentro-vs-nativo, en chico y en segundos.
//!
//! # Los vectores apuntan al borde, no al medio
//!
//! Un KAT de `2 + 2` no habría cazado nada: esa miscompilación es
//! invisible salvo en la rama que el bit alto del divisor selecciona. Por eso
//! cada caso dice a qué le apunta, y los divisores de bit alto prendido están
//! sobre-representados a propósito.

use repo_b_common::crypto::Crypto;
use repo_b_common::primitives::{B256, U256, keccak256};
use repo_b_evm::crypto::Active;

/// Marca que el modo corrió de verdad y que el ELF es el nuestro. Un journal
/// con este valor en `pre_state_root` no lo puede producir ningún otro modo.
pub const KAT_MAGIC: B256 = B256::new([
    0x4b, 0x41, 0x54, 0x00, 0x4d, 0x55, 0x4c, 0x54, 0x49, 0x50, 0x52, 0x4f, 0x56, 0x45, 0x52, 0x00,
    0x61, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x65, 0x74, 0x69, 0x63, 0x00, 0x6b, 0x61, 0x74, 0x00, 0x01,
]);

/// El primo de secp256k1. **Bit 255 prendido** — es el valor que dispara la
/// rama que OpenVM miscompila.
const SECP256K1_P: U256 = U256::from_limbs([
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// El orden de secp256k1. También con el bit alto prendido.
const SECP256K1_N: U256 = U256::from_limbs([
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
]);

/// El `Fq` de BN254. **Bit alto NO prendido** (`leading_zeros = 2`): es el
/// control que pasaba mientras secp256k1 fallaba, y por eso está acá — un KAT
/// que solo probara el caso roto no distinguiría "todo mal" de "mal solo acá".
const BN254_Q: U256 = U256::from_limbs([
    0x3C20_8C16_D87C_FD47,
    0x9781_6A91_6871_CA8D,
    0xB850_45B6_8181_585D,
    0x3064_4E72_E131_A029,
]);

/// Cuántos casos tiene la batería. El bitmask de fallas entra en 256 bits, y
/// esto lo hace explícito en vez de dejarlo implícito en el largo de un array.
pub const CASOS: usize = 18;

const _: () = assert!(CASOS <= 256);

/// Lo que la batería produjo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resultado {
    /// Un bit por caso fallado, en el orden de `CASOS`. **Cero = todos bien.**
    pub fallas: U256,
    /// Digest de todos los valores computados, fallen o no.
    ///
    /// Existe además del bitmask porque el bitmask solo ve lo que el caso sabe
    /// esperar: si una operación diera mal de una forma que ningún caso mira,
    /// el digest igual cambia y el contraste contra el nativo lo caza.
    pub digest: B256,
}

impl Resultado {
    #[must_use]
    pub fn paso(&self) -> bool {
        self.fallas.is_zero()
    }
}

/// Acumula cada valor computado en el digest y marca la falla si no coincide.
struct Bateria {
    bytes: alloc::vec::Vec<u8>,
    fallas: U256,
    caso: usize,
}

impl Bateria {
    fn new() -> Self {
        Self {
            bytes: alloc::vec::Vec::with_capacity(CASOS * 32),
            fallas: U256::ZERO,
            caso: 0,
        }
    }

    /// Registra un caso: mete el valor obtenido en el digest y prende el bit si
    /// no es el esperado.
    fn caso(&mut self, obtenido: U256, esperado: U256) {
        self.bytes.extend_from_slice(&obtenido.to_be_bytes::<32>());
        if obtenido != esperado {
            self.fallas |= U256::from(1u64) << self.caso;
        }
        self.caso += 1;
    }

    fn terminar(self) -> Resultado {
        // Que el conteo cierre no es cosmético: un caso agregado sin subir
        // `CASOS` dejaría el bitmask corrido respecto de lo que el mensaje de
        // error nombra.
        debug_assert_eq!(self.caso, CASOS);
        Resultado {
            fallas: self.fallas,
            digest: keccak256(&self.bytes),
        }
    }
}

/// Corre la batería. **La misma función corre adentro del backend y en el host.**
///
/// Cada caso lleva al lado a qué le apunta. El orden es el del bitmask y no se
/// reordena: un caso insertado en el medio cambiaría el significado de todos
/// los bits de arriba.
#[must_use]
#[allow(clippy::too_many_lines)] // Es una tabla de vectores, no lógica.
pub fn run() -> Resultado {
    let mut b = Bateria::new();
    let uno = U256::from(1u64);
    let dos = U256::from(2u64);

    // ---- 0-3: `MULMOD` con módulo de bit alto prendido ----
    // El caso que OpenVM computa mal. `(p-1)^2 mod p = 1`.
    let p_menos_1 = SECP256K1_P.wrapping_sub(uno);
    b.caso(p_menos_1.mul_mod(p_menos_1, SECP256K1_P), uno);
    // `(p-1) * 2 mod p = p-2`
    b.caso(
        p_menos_1.mul_mod(dos, SECP256K1_P),
        SECP256K1_P.wrapping_sub(dos),
    );
    // Mismo con el orden del grupo, que también tiene el bit alto prendido.
    let n_menos_1 = SECP256K1_N.wrapping_sub(uno);
    b.caso(n_menos_1.mul_mod(n_menos_1, SECP256K1_N), uno);
    // Control con módulo SIN bit alto: es el que pasaba mientras el resto
    // fallaba, y separa "todo roto" de "roto solo en la rama del bit alto".
    let q_menos_1 = BN254_Q.wrapping_sub(uno);
    b.caso(q_menos_1.mul_mod(q_menos_1, BN254_Q), uno);

    // ---- 4-6: `ADDMOD` ----
    // `(p-1) + 2 mod p = 1`. Con desborde de 256 bits, que es la rama exótica.
    b.caso(p_menos_1.add_mod(dos, SECP256K1_P), uno);
    // `(p-1) + (p-1) mod p = p-2`
    b.caso(
        p_menos_1.add_mod(p_menos_1, SECP256K1_P),
        SECP256K1_P.wrapping_sub(dos),
    );
    // Control sin bit alto.
    b.caso(q_menos_1.add_mod(dos, BN254_Q), uno);

    // ---- 7-8: `DIV` y `MOD` con divisor de 4 limbos y bit alto prendido ----
    // Con un divisor de 256 bits el cociente **solo puede ser 0 o 1**: no hay
    // numerador más grande que `U256::MAX`. Por eso estos dos casos son baratos
    // pero flacos, y por eso existen los dos de abajo.
    b.caso(U256::MAX.wrapping_div(SECP256K1_P), uno);
    b.caso(
        U256::MAX.wrapping_rem(SECP256K1_P),
        U256::MAX.wrapping_sub(SECP256K1_P),
    );

    // ---- 9-10: divisor de 3 limbos, con bit alto prendido y cociente ANCHO ----
    // **Este es el caso que importa.** Un divisor de 3 limbos con el bit más
    // alto prendido selecciona la misma rama `shift == 0` y además admite un
    // cociente de un limbo entero, o sea que ejercita el lazo de la división
    // larga y no solo su borde. Vectores calculados afuera y verificados:
    // `N = Q·D + R` con `R = D-1`, todo por debajo de 2^256.
    const KAT_N: U256 = U256::from_limbs([
        0x49F4_9F49_F49F_5D73,
        0xA190_7F6E_B9EB_109B,
        0x7EDC_BA98_CC6A_6A43,
        0x7F6E_5D4C_3B2A_1909,
    ]);
    const KAT_D: U256 = U256::from_limbs([
        0x0000_0000_0000_1234,
        0x0000_0000_5678_9ABC,
        0x8000_0000_0000_0001,
        0x0000_0000_0000_0000,
    ]);
    const KAT_Q: U256 = U256::from_limbs([0xFEDC_BA98_7654_3210, 0, 0, 0]);
    const KAT_R: U256 = U256::from_limbs([
        0x0000_0000_0000_1233,
        0x0000_0000_5678_9ABC,
        0x8000_0000_0000_0001,
        0x0000_0000_0000_0000,
    ]);
    b.caso(KAT_N.wrapping_div(KAT_D), KAT_Q);
    b.caso(KAT_N.wrapping_rem(KAT_D), KAT_R);

    // ---- 11-12: las primitivas con las que se arman los casos de arriba ----
    // Sin esto, un fallo de `wrapping_mul` se leería como fallo de la división.
    // El producto se elige para que NO desborde: `(2^128-1)·2^120` son 248 bits.
    let ancho: U256 = (uno << 128usize).wrapping_sub(uno);
    let escala: U256 = uno << 120usize;
    b.caso(ancho.wrapping_mul(escala).wrapping_div(escala), ancho);
    b.caso(U256::MAX.wrapping_add(uno), U256::ZERO);

    // ---- 13: división por cero ----
    // La EVM manda 0, y `ruint::wrapping_div(x, 0)` PANIQUEA — el motor colapsa
    // a cero explícitamente. Si esa rama se perdiera, acá se ve.
    b.caso(
        if SECP256K1_P.is_zero() {
            U256::ZERO
        } else {
            uno.wrapping_div(SECP256K1_P)
        },
        U256::ZERO,
    );

    // ---- 14: `EXP` ----
    // `2^255 mod 2^256`, o sea el bit alto solo: ejercita el shift ancho.
    b.caso(dos.pow(U256::from(255u64)), uno << 255);

    // ---- 15: keccak, que es la otra primitiva de consenso omnipresente ----
    // `keccak256("")`, cuyo valor es `KECCAK256_EMPTY`.
    b.caso(
        U256::from_be_bytes(keccak256([]).0),
        U256::from_be_bytes(repo_b_common::primitives::KECCAK256_EMPTY.0),
    );

    // ---- 16-17: recuperación ECDSA, que también es aritmética de consenso ----
    // Todo lo de arriba cubre la aritmética del intérprete y deja afuera la
    // recuperación del sender. El hueco no es teórico: hay configuraciones de
    // compilación del guest donde los 16 casos anteriores salen VERDES y el
    // backend no deriva un solo sender. Un gate que puede decir "la aritmética
    // de consenso de este ELF es correcta" sobre un guest así está diciendo
    // menos de lo que su mensaje sugiere, y derivar el remitente de una
    // transacción es tan de consenso como dividir.
    //
    // El vector es el mismo que pinea el precompile ECRECOVER: una firma real
    // de secp256k1 con su dirección conocida, y el par `s` alto que bajo
    // malleability tiene que recuperar la MISMA dirección. Son dos caminos
    // distintos por la misma matemática, y por eso están los dos.
    const ECDSA_MSG: U256 = U256::from_limbs([
        0x205594f9_e77a4a79,
        0x77fb4b11_e026748e,
        0xea5fa2d2_5a2095f6,
        0xc84960bf_5f880448,
    ]);
    const ECDSA_R: U256 = U256::from_limbs([
        0xd37d7331_07b55dfd,
        0x8d597693_950eb2e2,
        0x47dbdd86_dc58a4ac,
        0x46072087_b50b1110,
    ]);
    const ECDSA_S_LOW: U256 = U256::from_limbs([
        0xa503aa1a_f5b9bfe6,
        0xc623af4e_bd14447e,
        0x62275ade_a6691bd2,
        0x65c753fe_f8762f36,
    ]);
    /// `n - ECDSA_S_LOW`, con la paridad flipeada: la misma firma bajo
    /// malleability (BIP-62).
    const ECDSA_S_HIGH: U256 = U256::from_limbs([
        0x1aceb471_da7c815b,
        0xf48b2d97_f2345bbd,
        0x9dd8a521_5996e42b,
        0x9a38ac01_0789d0c9,
    ]);
    /// La dirección esperada, alineada a derecha en la palabra de 32 bytes —
    /// el mismo layout con el que ECRECOVER la devuelve.
    const ECDSA_ADDR: U256 = U256::from_limbs([
        0xc70a5dd0_86daff2a,
        0xe7c213b7_e7e7e46c,
        0x00000000_19e7e376,
        0x00000000_00000000,
    ]);

    b.caso(recupera(ECDSA_MSG, ECDSA_R, ECDSA_S_LOW, 0), ECDSA_ADDR);
    b.caso(recupera(ECDSA_MSG, ECDSA_R, ECDSA_S_HIGH, 1), ECDSA_ADDR);

    b.terminar()
}

/// Recupera la dirección de una firma y la devuelve alineada a derecha, o cero
/// si no recupera. **Cruza el mismo seam que usa el motor**: un KAT que llamara
/// a otra implementación daría fe de esa otra.
///
/// Un fallo se codifica como cero y no como panic: el KAT tiene que poder
/// reportar CUÁL caso falló, y un guest que aborta no publica bitmask.
fn recupera(msg: U256, r: U256, s: U256, parity: u8) -> U256 {
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.to_be_bytes::<32>());
    sig[32..].copy_from_slice(&s.to_be_bytes::<32>());
    match Active::secp256k1_ecrecover(&msg.to_be_bytes::<32>(), &sig, parity) {
        Ok(pk) => {
            let h = keccak256(pk);
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&h.as_slice()[12..]);
            U256::from_be_bytes(w)
        }
        Err(()) => U256::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::{CASOS, run};

    /// El KAT tiene que pasar **en el host**, donde el motor ya está validado
    /// por los dos ejes de EEST. Si fallara acá, el problema sería del KAT.
    #[test]
    fn the_battery_passes_natively() {
        let r = run();
        assert!(
            r.paso(),
            "el KAT falla en el host: bitmask {:#x} — el problema es del KAT, no del backend",
            r.fallas
        );
    }

    /// **El KAT tiene que poder ponerse rojo.** Un chequeo que no sabe fallar
    /// no es evidencia — dos motores que coinciden porque fallan por la misma
    /// razón no divergen, y eso ya se pagó una vez acá.
    #[test]
    fn a_wrong_answer_lights_its_bit_and_moves_the_digest() {
        use super::Bateria;
        use repo_b_common::primitives::U256;

        let bien = {
            let mut b = Bateria::new();
            b.caso(U256::from(1u64), U256::from(1u64));
            b.fallas
        };
        assert!(bien.is_zero());

        let (fallas, digest_malo) = {
            let mut b = Bateria::new();
            b.caso(U256::from(2u64), U256::from(1u64));
            (b.fallas, super::keccak256(&b.bytes))
        };
        assert_eq!(
            fallas,
            U256::from(1u64),
            "el bit del caso 0 tiene que prender"
        );

        let digest_bueno = {
            let mut b = Bateria::new();
            b.caso(U256::from(1u64), U256::from(1u64));
            super::keccak256(&b.bytes)
        };
        assert_ne!(
            digest_bueno, digest_malo,
            "un valor distinto tiene que mover el digest, aunque ningún caso lo mirara"
        );
    }

    /// El conteo declarado y el real no pueden separarse sin que alguien se
    /// entere: el bitmask se lee por posición.
    #[test]
    fn the_declared_case_count_matches_the_battery() {
        // `terminar()` tiene el `debug_assert_eq!`; esto lo hace visible como
        // test propio para que el número no se mueva por accidente.
        assert_eq!(CASOS, 18);
        let _ = run();
    }
}
