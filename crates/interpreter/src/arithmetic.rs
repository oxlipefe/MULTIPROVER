//! Aritmética con signo en complemento a dos sobre `U256` (slice 2.9b-2).
//!
//! La EVM no tiene un tipo con signo: `SDIV`/`SMOD`/`SLT`/`SGT`/`SIGNEXTEND`
//! **reinterpretan** la misma palabra de 256 bits como complemento a dos. Vive
//! en su propio módulo porque es la única parte del intérprete donde el mismo
//! valor tiene dos lecturas, y confundirlas es una divergencia de consenso
//! silenciosa (no un panic).
//!
//! Reglas duras que gobiernan todo el módulo:
//! - **División por cero da 0**, no un halt. Es la regla de la EVM, no un
//!   atajo (Yellow Paper §Appendix H: `SDIV(a,0) = 0`).
//! - **`MIN / -1` da `MIN`**, no un overflow: es el único par donde el
//!   resultado no entra en el rango con signo, y la EVM lo define por wrapping.
//! - **El signo de `SMOD` lo fija el DIVIDENDO**, no el divisor
//!   (`-8 % 3 = -2`, no `1`). Es la convención de C/Rust (truncada), no la
//!   matemática (euclidiana).
//! - Cero `+ - *` crudo: todo es `wrapping_*` explícito, y el wrapping ES la
//!   semántica del protocolo acá, no un accidente heredado.

use repo_b_common::primitives::U256;

/// El bit de signo del complemento a dos: el más significativo.
const SIGN_BIT: usize = 255;

/// ¿La palabra, leída como complemento a dos, es negativa?
fn is_negative(value: U256) -> bool {
    value.bit(SIGN_BIT)
}

/// Magnitud absoluta de una palabra con signo. Para `MIN` devuelve `MIN`
/// (su negado es él mismo: `|MIN|` no entra en el rango positivo), que es
/// exactamente lo que las divisiones de abajo necesitan.
fn absolute(value: U256) -> U256 {
    if is_negative(value) {
        value.wrapping_neg()
    } else {
        value
    }
}

/// `SDIV` (0x05) — división truncada con signo. `b == 0 ⇒ 0`.
///
/// El caso `MIN / -1` sale solo: `absolute(MIN) == MIN`, `absolute(-1) == 1`,
/// el cociente es `MIN`, los signos difieren, y `wrapping_neg(MIN) == MIN`.
/// No necesita rama propia — pero sí un test propio, porque "sale solo" es
/// una afirmación sobre el complemento a dos, no una garantía del código.
pub fn signed_div(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::ZERO;
    }
    let quotient = absolute(a).wrapping_div(absolute(b));
    if is_negative(a) == is_negative(b) {
        quotient
    } else {
        quotient.wrapping_neg()
    }
}

/// `SMOD` (0x07) — resto con signo del DIVIDENDO. `b == 0 ⇒ 0`.
pub fn signed_rem(a: U256, b: U256) -> U256 {
    if b.is_zero() {
        return U256::ZERO;
    }
    let remainder = absolute(a).wrapping_rem(absolute(b));
    if is_negative(a) {
        remainder.wrapping_neg()
    } else {
        remainder
    }
}

/// `SLT` (0x12) — menor-que con signo.
///
/// Con signos distintos manda el signo; con el mismo signo, el orden sin
/// signo del complemento a dos coincide con el orden con signo.
pub fn signed_lt(a: U256, b: U256) -> bool {
    match (is_negative(a), is_negative(b)) {
        (true, false) => true,
        (false, true) => false,
        _ => a < b,
    }
}

/// `SGT` (0x13) — mayor-que con signo.
pub fn signed_gt(a: U256, b: U256) -> bool {
    signed_lt(b, a)
}

/// `SIGNEXTEND` (0x0B) — extiende el signo de `value` tomándolo como un
/// entero de `byte_index + 1` bytes. Con `byte_index >= 31` el valor ya ocupa
/// la palabra entera y se devuelve intacto (**no** es un error).
pub fn sign_extend(byte_index: U256, value: U256) -> U256 {
    const LAST_BYTE: u64 = 31;
    const BITS_PER_BYTE: u64 = 8;

    let Ok(index) = u64::try_from(byte_index) else {
        return value;
    };
    if index >= LAST_BYTE {
        return value;
    }
    // `index <= 30` ⇒ `bit_index <= 247`, entra en usize sin riesgo.
    let bit_index = index
        .saturating_mul(BITS_PER_BYTE)
        .saturating_add(BITS_PER_BYTE - 1);
    let Ok(bit_index) = usize::try_from(bit_index) else {
        return value;
    };
    let mask = (U256::from(1u64) << bit_index).wrapping_sub(U256::from(1u64));
    if value.bit(bit_index) {
        value | !mask
    } else {
        value & mask
    }
}

/// `BYTE` (0x1A) — el byte `index` de `value` contando desde el **más
/// significativo**. `index >= 32 ⇒ 0`.
///
/// `ruint::byte()` indexa al revés (desde el menos significativo), así que la
/// conversión `31 - index` es obligatoria — invertirla es una divergencia que
/// ningún tipo atrapa.
pub fn byte_at(index: U256, value: U256) -> U256 {
    const BYTES: u64 = 32;

    let Ok(index) = u64::try_from(index) else {
        return U256::ZERO;
    };
    if index >= BYTES {
        return U256::ZERO;
    }
    let from_least_significant = BYTES.saturating_sub(1).saturating_sub(index);
    let Ok(from_least_significant) = usize::try_from(from_least_significant) else {
        return U256::ZERO;
    };
    U256::from(value.byte(from_least_significant))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `MIN` con signo (`-2^255`): la única palabra que es su propio negado.
    /// Vive en los tests porque el código de producción no la necesita — las
    /// funciones de arriba tratan el caso por wrapping, sin nombrarlo.
    fn min_negative() -> U256 {
        U256::from(1u64) << SIGN_BIT
    }

    /// `-1` en complemento a dos.
    fn neg_one() -> U256 {
        U256::MAX
    }

    /// `-n` para un `n` chico.
    fn neg(n: u64) -> U256 {
        U256::from(n).wrapping_neg()
    }

    #[test]
    fn signed_div_truncates_toward_zero_with_the_right_sign() {
        assert_eq!(
            signed_div(U256::from(8u64), U256::from(3u64)),
            U256::from(2u64)
        );
        assert_eq!(signed_div(neg(8), U256::from(3u64)), neg(2));
        assert_eq!(signed_div(U256::from(8u64), neg(3)), neg(2));
        assert_eq!(signed_div(neg(8), neg(3)), U256::from(2u64));
    }

    #[test]
    fn division_by_zero_is_zero_not_a_halt() {
        assert_eq!(signed_div(U256::from(8u64), U256::ZERO), U256::ZERO);
        assert_eq!(signed_rem(U256::from(8u64), U256::ZERO), U256::ZERO);
        assert_eq!(signed_div(neg(8), U256::ZERO), U256::ZERO);
    }

    /// El único par donde el resultado con signo no existe. La EVM lo define
    /// por wrapping: `MIN / -1 == MIN`.
    #[test]
    fn min_divided_by_negative_one_wraps_to_min() {
        assert_eq!(signed_div(min_negative(), neg_one()), min_negative());
        assert_eq!(signed_rem(min_negative(), neg_one()), U256::ZERO);
    }

    /// El signo del resto lo fija el DIVIDENDO (truncada, no euclidiana).
    #[test]
    fn signed_rem_takes_the_sign_of_the_dividend() {
        assert_eq!(signed_rem(neg(8), U256::from(3u64)), neg(2));
        assert_eq!(signed_rem(U256::from(8u64), neg(3)), U256::from(2u64));
        assert_eq!(signed_rem(neg(8), neg(3)), neg(2));
    }

    #[test]
    fn signed_comparison_orders_across_the_sign_boundary() {
        // -1 < 1, aunque SIN signo `-1` es el máximo.
        assert!(signed_lt(neg_one(), U256::from(1u64)));
        assert!(!signed_lt(U256::from(1u64), neg_one()));
        assert!(signed_gt(U256::from(1u64), neg_one()));
        // Mismo signo: el orden sin signo sirve.
        assert!(signed_lt(neg(8), neg(3)));
        assert!(signed_lt(U256::from(3u64), U256::from(8u64)));
        // MIN es el menor de todos; MAX_signed el mayor.
        let max_signed = min_negative().wrapping_sub(U256::from(1u64));
        assert!(signed_lt(min_negative(), max_signed));
        assert!(!signed_lt(min_negative(), min_negative()));
    }

    #[test]
    fn sign_extend_widens_a_negative_byte_to_the_full_word() {
        // 0xFF como int8 = -1 ⇒ toda la palabra en unos.
        assert_eq!(sign_extend(U256::ZERO, U256::from(0xFFu64)), U256::MAX);
        // 0x7F como int8 = 127 ⇒ intacto.
        assert_eq!(
            sign_extend(U256::ZERO, U256::from(0x7Fu64)),
            U256::from(0x7Fu64)
        );
        // Los bytes por encima del índice se DESCARTAN, no se conservan.
        assert_eq!(
            sign_extend(U256::ZERO, U256::from(0xAB7Fu64)),
            U256::from(0x7Fu64)
        );
    }

    #[test]
    fn sign_extend_at_or_past_the_last_byte_is_the_identity() {
        let value = U256::from(0xDEADBEEFu64);
        assert_eq!(sign_extend(U256::from(31u64), value), value);
        assert_eq!(sign_extend(U256::from(32u64), value), value);
        assert_eq!(sign_extend(U256::MAX, value), value);
    }

    /// `BYTE` cuenta desde el byte MÁS significativo; `ruint` desde el menos.
    /// Invertir la conversión es una divergencia que ningún tipo atrapa.
    #[test]
    fn byte_at_indexes_from_the_most_significant_byte() {
        let value = U256::from(0xAABBu64);
        // Los 30 bytes altos son cero; 0xAA está en el índice 30, 0xBB en el 31.
        assert_eq!(byte_at(U256::ZERO, value), U256::ZERO);
        assert_eq!(byte_at(U256::from(30u64), value), U256::from(0xAAu64));
        assert_eq!(byte_at(U256::from(31u64), value), U256::from(0xBBu64));
        // Fuera de rango ⇒ 0, sin halt.
        assert_eq!(byte_at(U256::from(32u64), value), U256::ZERO);
        assert_eq!(byte_at(U256::MAX, value), U256::ZERO);
        // El byte más significativo de MAX es 0xFF.
        assert_eq!(byte_at(U256::ZERO, U256::MAX), U256::from(0xFFu64));
    }

    /// Pin de comportamiento de `ruint`, no de nuestro código: `add_mod`/
    /// `mul_mod` con módulo cero devuelven cero, que es justo la regla de la
    /// EVM para ADDMOD/MULMOD. El intérprete se apoya en eso; si una versión
    /// futura de `ruint` lo cambiara, este test cae antes que el consenso.
    #[test]
    fn ruint_mod_by_zero_matches_the_evm_rule() {
        let a = U256::from(7u64);
        let b = U256::from(3u64);
        assert_eq!(a.add_mod(b, U256::ZERO), U256::ZERO);
        assert_eq!(a.mul_mod(b, U256::ZERO), U256::ZERO);
        // **El intermedio es de ancho completo, no mod 2^256.** Los módulos
        // están elegidos para que las dos lecturas DIFIERAN — con potencias de
        // 2 el test no probaría nada:
        //   (MAX + 1) = 2^256 ≡ 1 (mod 3); con wrapping previo sería 0 ≡ 0.
        assert_eq!(
            U256::MAX.add_mod(U256::from(1u64), U256::from(3u64)),
            U256::from(1u64)
        );
        //   MAX ≡ 1 (mod 7) ⇒ MAX·2 ≡ 2; con wrapping previo, 2^256−2 ≡ 0.
        assert_eq!(
            U256::MAX.mul_mod(U256::from(2u64), U256::from(7u64)),
            U256::from(2u64)
        );
    }

    /// Pin de `wrapping_pow`: `0^0 == 1` (regla de la EVM) y el desborde
    /// wrappea mod 2^256 en vez de paniquear.
    #[test]
    fn ruint_pow_matches_the_evm_rule() {
        assert_eq!(U256::ZERO.wrapping_pow(U256::ZERO), U256::from(1u64));
        assert_eq!(
            U256::from(2u64).wrapping_pow(U256::from(300u64)),
            U256::ZERO
        );
        assert_eq!(
            U256::from(3u64).wrapping_pow(U256::from(4u64)),
            U256::from(81u64)
        );
    }

    /// Pin de los shifts: `>= 256` satura (0, o todo unos para SAR negativo)
    /// en vez de ser UB o wrappear el contador.
    #[test]
    fn ruint_shifts_saturate_past_the_word_width() {
        let seven = U256::from(7u64);
        assert_eq!(seven.wrapping_shl(300), U256::ZERO);
        assert_eq!(seven.wrapping_shr(300), U256::ZERO);
        assert_eq!(seven.arithmetic_shr(300), U256::ZERO);
        // SAR de un negativo satura en -1, no en 0.
        assert_eq!(U256::MAX.arithmetic_shr(300), U256::MAX);
        assert_eq!(min_negative().arithmetic_shr(255), U256::MAX);
    }
}
