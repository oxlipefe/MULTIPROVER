//! Validación de header — las reglas de EIP-1559 que hacen inválido a un
//! bloque por lo que declara, no por lo que ejecuta.
//!
//! Vive en el harness y no en el motor: es verificación de encoding del bloque,
//! no transición de estado. En producción lo hace el cliente stateless antes de
//! llamar al `Vm`.
//!
//! Funciones puras sobre el header del padre. El harness no se autovalida: lo
//! que estas reglas calculan se contrasta contra el campo que el fixture
//! publica, y el juez de que no rechazan de más son los bloques válidos.

/// Piso absoluto del `gasLimit` de un bloque (Yellow Paper).
pub const MIN_GAS_LIMIT: u64 = 5_000;
/// EIP-1559 — el `gasLimit` no puede moverse `parent/1024` o más respecto del
/// padre. La comparación es `>=`, no `>`: el borde exacto ya es inválido.
pub const GAS_LIMIT_BOUND_DIVISOR: u64 = 1_024;
/// EIP-1559 — `gasTarget = gasLimit / 2`.
pub const ELASTICITY_MULTIPLIER: u64 = 2;
/// EIP-1559 — el `baseFee` no puede moverse más de 1/8 por bloque.
pub const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;

/// EIP-1559: el `gasLimit` declarado es admisible dado el del padre.
pub fn check_gas_limit(parent_gas_limit: u64, gas_limit: u64) -> Result<(), String> {
    if gas_limit < MIN_GAS_LIMIT {
        return Err(format!(
            "gasLimit {gas_limit} por debajo del mínimo {MIN_GAS_LIMIT}"
        ));
    }
    let delta = parent_gas_limit.abs_diff(gas_limit);
    let bound = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR;
    if delta >= bound {
        return Err(format!(
            "gasLimit {gas_limit} se aparta {delta} del padre {parent_gas_limit} (máximo < {bound})"
        ));
    }
    Ok(())
}

/// EIP-1559: el `baseFeePerGas` que el hijo TIENE que declarar, dado el padre.
///
/// Todo el producto intermedio va en `u128`: `parent_base_fee · gas_used` sobre
/// un input hostil desborda `u64` sin esfuerzo, y un wrap silencioso acá sería
/// aceptar un bloque que el protocolo rechaza.
pub fn expected_base_fee(
    parent_gas_limit: u64,
    parent_gas_used: u64,
    parent_base_fee: u64,
) -> Result<u64, String> {
    let target = parent_gas_limit / ELASTICITY_MULTIPLIER;
    if target == 0 {
        // Inalcanzable con un padre válido (`MIN_GAS_LIMIT` lo impide), pero
        // dividir por cero sería un panic y en este repo el panic no es una
        // opción: se dice en voz alta.
        return Err(format!(
            "el padre declara gasLimit {parent_gas_limit}: gasTarget cero"
        ));
    }
    let base = u128::from(parent_base_fee);
    let target = u128::from(target);
    let used = u128::from(parent_gas_used);

    let next = if used == target {
        base
    } else if used > target {
        let delta = base * (used - target) / target / u128::from(BASE_FEE_MAX_CHANGE_DENOMINATOR);
        base.saturating_add(delta.max(1))
    } else {
        let delta = base * (target - used) / target / u128::from(BASE_FEE_MAX_CHANGE_DENOMINATOR);
        base.saturating_sub(delta)
    };
    u64::try_from(next).map_err(|_| format!("baseFeePerGas esperado fuera de u64: {next}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Los tres vectores de `BlockException.INVALID_GASLIMIT` del set, con el
    /// padre que traen (`gasLimit` 5000). El de 4999 es el que separa las dos
    /// reglas: cae dentro del bound de 1024 y aun así es inválido por el piso.
    #[test]
    fn the_gas_limit_vectors_of_the_set_are_rejected() {
        assert!(check_gas_limit(5_000, 0).is_err());
        assert!(check_gas_limit(5_000, 1).is_err());
        assert!(check_gas_limit(5_000, 4_999).is_err());
    }

    #[test]
    fn a_gas_limit_below_the_bound_is_rejected_even_if_above_the_floor() {
        // padre 1 048 576 ⇒ bound 1024. El borde exacto YA es inválido.
        assert!(check_gas_limit(1_048_576, 1_048_576 + 1_024).is_err());
        assert!(check_gas_limit(1_048_576, 1_048_576 - 1_024).is_err());
        assert!(check_gas_limit(1_048_576, 1_048_576 + 1_023).is_ok());
        assert!(check_gas_limit(1_048_576, 1_048_576 - 1_023).is_ok());
    }

    #[test]
    fn an_unchanged_gas_limit_is_always_valid() {
        assert!(check_gas_limit(30_000_000, 30_000_000).is_ok());
    }

    /// El caso del set: padre vacío (`gasUsed` 0) ⇒ el `baseFee` no baja porque
    /// el descuento entero da cero. El fixture que declara 1 es inválido.
    #[test]
    fn an_empty_parent_keeps_the_base_fee() {
        assert_eq!(expected_base_fee(0x0727_0e00, 0, 7), Ok(7));
    }

    #[test]
    fn a_parent_at_target_keeps_the_base_fee() {
        assert_eq!(expected_base_fee(2_000_000, 1_000_000, 1_000), Ok(1_000));
    }

    #[test]
    fn a_full_parent_raises_the_base_fee_by_an_eighth() {
        // target = 1 000 000, used = 2 000 000 ⇒ delta = 1000·1/8 = 125.
        assert_eq!(expected_base_fee(2_000_000, 2_000_000, 1_000), Ok(1_125));
    }

    /// El `max(delta, 1)`: con el padre por encima del target el fee SIEMPRE
    /// sube al menos 1, aunque la división entera dé cero.
    #[test]
    fn above_target_the_base_fee_rises_at_least_one() {
        assert_eq!(expected_base_fee(2_000_000, 1_000_001, 1), Ok(2));
    }

    #[test]
    fn an_idle_parent_lowers_the_base_fee_by_an_eighth() {
        // target = 1 000 000, used = 0 ⇒ delta = 8000·1/8 = 1000.
        assert_eq!(expected_base_fee(2_000_000, 0, 8_000), Ok(7_000));
    }

    /// Un `baseFee` grande por un `gasUsed` grande desborda `u64` en el
    /// producto intermedio. En `u128` no.
    #[test]
    fn the_intermediate_product_does_not_overflow() {
        let huge = u64::MAX / 2;
        assert!(expected_base_fee(30_000_000, 30_000_000, huge).is_ok());
    }

    #[test]
    fn a_parent_without_gas_target_is_loud_instead_of_panicking() {
        assert!(expected_base_fee(1, 0, 7).is_err());
    }
}
