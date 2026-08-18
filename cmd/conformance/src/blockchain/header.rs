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

use repo_b_evm::types::Spec;

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

/// Lo que el header declara sobre blobs (EIP-4844), y lo que el bloque
/// realmente lleva. Agrupado para que las tres reglas de abajo no puedan
/// recibir los argumentos cruzados.
#[derive(Debug, Clone, Copy)]
pub struct BlobGas {
    pub parent_excess: u64,
    pub parent_used: u64,
    pub declared_excess: u64,
    pub declared_used: u64,
    /// `GAS_PER_BLOB ×` los blobs que suman las txs del bloque.
    pub computed_used: u64,
}

/// EIP-4844 — las tres reglas de blob gas del header, en el orden en el que un
/// cliente las descubre.
///
/// El `TARGET` y el `MAX` salen de `blob::blob_params(spec)`, la MISMA tabla
/// por fork que consume el motor: EIP-7691 los mueve en Prague y una constante
/// local acá pasaría Cancun entero en verde y rompería Prague en silencio.
pub fn check_blob_gas(blob: BlobGas, spec: Spec) -> Result<(), String> {
    let params = repo_b_evm::blob::blob_params(spec);
    let expected_excess =
        repo_b_evm::blob::excess_blob_gas(blob.parent_excess, blob.parent_used, spec);
    if blob.declared_excess != expected_excess {
        return Err(format!(
            "excessBlobGas declarado {}, la fórmula de EIP-4844 exige {expected_excess} \
             (padre: excess {} + used {} − target {})",
            blob.declared_excess,
            blob.parent_excess,
            blob.parent_used,
            params.target_blob_gas()
        ));
    }
    if blob.declared_used != blob.computed_used {
        return Err(format!(
            "blobGasUsed declarado {}, las txs del bloque suman {}",
            blob.declared_used, blob.computed_used
        ));
    }
    // El tope es de BLOQUE, no de tx: el chequeo por-tx del motor (≤ max
    // blobs) deja pasar N txs chicas cuya suma se pasa. Medido: de los 28
    // fixtures de `test_invalid_block_blob_count`, **una sola** es una tx de 7
    // blobs; las otras 27 reparten los 7 entre varias txs de ≤6.
    if blob.declared_used > params.max_blob_gas() {
        return Err(format!(
            "blobGasUsed {} por encima del máximo del bloque {} ({} blobs)",
            blob.declared_used,
            params.max_blob_gas(),
            params.max_blobs
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

    const GAS_PER_BLOB: u64 = repo_b_evm::blob::GAS_PER_BLOB;

    /// **La trampa del slice, del lado del harness.** EIP-7691 mueve el target
    /// en Prague, así que el MISMO par (padre, header) es válido en un fork e
    /// inválido en el otro. El corpus de Cancun **no puede ver esto**: acá
    /// Prague todavía no está en scope, y una constante hardcodeada pasaría
    /// los 17 685 en verde. Este test es la única evidencia disponible hoy.
    #[test]
    fn the_same_header_is_valid_in_cancun_and_invalid_in_prague() {
        // Padre con 6 blobs y sin excedente ⇒ hijo con 3 blobs de excedente en
        // Cancun (6 − 3), y con 0 en Prague (6 − 6).
        let blob = BlobGas {
            parent_excess: 0,
            parent_used: 6 * GAS_PER_BLOB,
            declared_excess: 3 * GAS_PER_BLOB,
            declared_used: 0,
            computed_used: 0,
        };
        assert!(check_blob_gas(blob, Spec::Cancun).is_ok());
        assert!(check_blob_gas(blob, Spec::Prague).is_err());
    }

    /// El tope de `blobGasUsed` también es por fork: 7 blobs se pasan en Cancun
    /// (máximo 6) y entran en Prague (máximo 9).
    #[test]
    fn the_block_blob_limit_moves_with_the_fork() {
        let seven = BlobGas {
            parent_excess: 0,
            parent_used: 0,
            declared_excess: 0,
            declared_used: 7 * GAS_PER_BLOB,
            computed_used: 7 * GAS_PER_BLOB,
        };
        assert!(check_blob_gas(seven, Spec::Cancun).is_err());
        // En Prague el excedente esperado del hijo con este padre sigue siendo
        // 0, así que la única regla que cambia de veredicto es el tope.
        assert!(check_blob_gas(seven, Spec::Prague).is_ok());
    }

    /// El tope es de BLOQUE, no de tx — la trampa de la regla. Una
    /// suma de txs chicas que se pasa es inválida aunque ninguna tx sola lo
    /// esté — es el caso de 27 de los 28 fixtures de `test_invalid_block_blob_count`.
    #[test]
    fn a_declared_blob_gas_that_disagrees_with_the_transactions_is_rejected() {
        let lying = BlobGas {
            parent_excess: 0,
            parent_used: 0,
            declared_excess: 0,
            declared_used: 2 * GAS_PER_BLOB,
            computed_used: 3 * GAS_PER_BLOB,
        };
        assert!(check_blob_gas(lying, Spec::Cancun).is_err());
    }
}
