//! EIP-4844/7691 — los parámetros de blob **por fork** y el precio del blob gas.
//!
//! Todo lo que EIP-7691 mueve en Prague (el target, el máximo por bloque y la
//! fracción de actualización) vive en UNA tabla `const` por fork, resuelta por
//! UNA función (`blob_params`) — misma forma que el set de precompiles por fork.
//! Un `if spec.is_enabled(...)` repartido por el motor sería la manera de que un
//! número de Cancun sobreviva a Prague sin que nada lo delate: el síntoma sería
//! un `excessBlobGas` que no cierra, sin ninguna pista de por qué.
//!
//! Vive en `evm` (no en `interpreter`): es quien arma el frame el que calcula el
//! precio ya resuelto — el intérprete solo lo apila
//! (`interpreter::host::BlockEnv`).

use alloc::string::ToString;

use crate::error::{InternalError, VmError};
use crate::types::Spec;

/// EIP-4844 — gas por blob (2¹⁷). **No cambia con el fork**: lo que EIP-7691
/// mueve es cuántos blobs entran, no cuánto gas vale cada uno. Verificado
/// contra `revm` (`primitives::eip4844::GAS_PER_BLOB`).
pub const GAS_PER_BLOB: u64 = 131_072;

/// EIP-4844 — piso del precio del blob gas.
const MIN_BASE_FEE_PER_BLOB_GAS: u128 = 1;
/// EIP-7918 (Osaka): `BLOB_BASE_COST * base_fee > GAS_PER_BLOB * blob_fee`
/// con `BLOB_BASE_COST = 2^13` y `GAS_PER_BLOB = 2^17` es exactamente
/// `base_fee > 16 * blob_fee`.
const BLOB_RESERVE_PRICE_RATIO: u128 = 16;

/// Los parámetros de blob de un fork.
///
/// `target_blobs`/`max_blobs` se guardan **en blobs y no en gas**: es la unidad
/// en la que los declaran EIP-4844 y EIP-7691, y el gas se deriva multiplicando
/// por `GAS_PER_BLOB`. Guardar el gas ya multiplicado invitaría a que alguien
/// compare un tope en gas contra un conteo de blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobParams {
    /// Blobs por bloque a los que el mercado tiende (`TARGET_BLOB_NUMBER`).
    pub target_blobs: u64,
    /// Blobs máximos por bloque (`MAX_BLOB_NUMBER`). El límite por transacción
    /// es una regla separada: desde Osaka, EIP-7594 fija 6 aunque el bloque
    /// todavía admita 9.
    pub max_blobs: u64,
    /// Denominador de la `fake_exponential` del precio.
    pub update_fraction: u64,
}

impl BlobParams {
    /// `TARGET_BLOB_GAS_PER_BLOCK` — el sustraendo del acumulador padre→hijo.
    #[must_use]
    pub fn target_blob_gas(self) -> u64 {
        self.target_blobs.saturating_mul(GAS_PER_BLOB)
    }

    /// `MAX_BLOB_GAS_PER_BLOCK` — el tope duro del `blobGasUsed` de un bloque.
    #[must_use]
    pub fn max_blob_gas(self) -> u64 {
        self.max_blobs.saturating_mul(GAS_PER_BLOB)
    }
}

/// EIP-4844 (Cancun): target 3, máximo 6.
const CANCUN: BlobParams = BlobParams {
    target_blobs: 3,
    max_blobs: 6,
    update_fraction: 3_338_477,
};

/// EIP-7691 (Prague): sube target y máximo, **y con ellos la fracción** — los
/// tres números se mueven juntos y por eso viajan juntos en la misma tabla.
/// Verificado contra `revm-primitives::eip4844`
/// (`MAX_BLOB_NUMBER_PER_BLOCK_PRAGUE = 9`,
/// `BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE = 5_007_716`).
const PRAGUE: BlobParams = BlobParams {
    target_blobs: 6,
    max_blobs: 9,
    update_fraction: 5_007_716,
};

/// Osaka conserva el schedule de Prague. La fila es explícita porque desde
/// EIP-7892 los parámetros son configuración por fork: heredar Prague por un
/// `>=` convertiría un cambio futuro en una regresión silenciosa.
const OSAKA: BlobParams = BlobParams {
    target_blobs: 6,
    max_blobs: 9,
    update_fraction: 5_007_716,
};

/// La ÚNICA puerta a los parámetros de blob. Pre-Cancun no hay blobs y ninguna
/// de las reglas de este módulo se consulta; devolver los de Cancun no habilita
/// nada (las tres puertas —validación de tx, header y precio— están gateadas
/// por `Spec::Cancun` río arriba).
#[must_use]
pub fn blob_params(spec: Spec) -> BlobParams {
    if spec.is_enabled(Spec::Osaka) {
        OSAKA
    } else if spec.is_enabled(Spec::Prague) {
        PRAGUE
    } else {
        CANCUN
    }
}

/// Fracción de actualización por fork. `pub` (no `pub(crate)`): el harness
/// diferencial (`cmd/conformance`) la reusa para que revm calcule el mismo
/// precio con la MISMA constante — dos copias del número serían una segunda
/// fuente de verdad que puede driftear.
#[must_use]
pub fn update_fraction(spec: Spec) -> u64 {
    blob_params(spec).update_fraction
}

/// EIP-4844 — el `excessBlobGas` que el hijo TIENE que declarar, dado el padre.
///
/// `parent.excess + parent.used − TARGET`, con **piso en cero** (la resta no
/// puede irse a negativo: un bloque bajo el target no genera "excedente
/// negativo" que compense al siguiente). `saturating_sub` ES la regla, no una
/// defensa contra el underflow.
pub fn excess_blob_gas(
    parent_excess: u64,
    parent_blob_gas_used: u64,
    parent_base_fee: u64,
    spec: Spec,
) -> Result<u64, VmError> {
    let params = blob_params(spec);
    let total = parent_excess
        .checked_add(parent_blob_gas_used)
        .ok_or_else(overflow)?;
    let target = params.target_blob_gas();
    if total < target {
        return Ok(0);
    }

    // EIP-7918 (Osaka): 8192*execution_base_fee > 131072*blob_base_fee
    // se simplifica exactamente a `execution_base_fee > 16*blob_base_fee`.
    // `saturating_mul` es seguro para el veredicto: si el RHS real excede
    // u128, necesariamente es mayor que cualquier `u64` del LHS.
    let below_reserve = if spec.is_enabled(Spec::Osaka) {
        let parent_blob_base_fee = blob_base_fee(Some(parent_excess), spec)?;
        u128::from(parent_base_fee) > parent_blob_base_fee.saturating_mul(BLOB_RESERVE_PRICE_RATIO)
    } else {
        false
    };

    if below_reserve {
        // `max_blobs >= target_blobs` en toda fila del schedule; si una fila
        // nueva lo rompiera, se corta con error en vez de envolver.
        let reserve_blobs = params
            .max_blobs
            .checked_sub(params.target_blobs)
            .ok_or_else(|| {
                VmError::Internal(InternalError::EvmInternal(
                    "schedule de blobs con target por encima del máximo".to_string(),
                ))
            })?;
        let scaled_used = u128::from(parent_blob_gas_used)
            .checked_mul(u128::from(reserve_blobs))
            .ok_or_else(overflow)?
            .checked_div(u128::from(params.max_blobs))
            .ok_or_else(overflow)?;
        let next = u128::from(parent_excess)
            .checked_add(scaled_used)
            .ok_or_else(overflow)?;
        return u64::try_from(next).map_err(|_| overflow());
    }

    Ok(total.saturating_sub(target))
}

/// `blob_base_fee`: sin contexto de blobs en el `BlockEnv` (`None` — pre-Cancun
/// o bloque sin el campo poblado) el opcode no tiene valor de protocolo: 0.
///
/// Devuelve `u128` y no `u64`: con un `excessBlobGas` alto —pero perfectamente
/// alcanzable, y presente en el set de EEST— el precio pasa de `u64::MAX` y
/// truncarlo sería cobrar un blob fee equivocado. `BLOBBASEFEE` apila una
/// palabra de 256 bits, así que el tipo angosto no venía de la EVM.
pub(crate) fn blob_base_fee(excess_blob_gas: Option<u64>, spec: Spec) -> Result<u128, VmError> {
    let Some(excess) = excess_blob_gas else {
        return Ok(0);
    };
    let fraction = u128::from(update_fraction(spec));
    fake_exponential(MIN_BASE_FEE_PER_BLOB_GAS, u128::from(excess), fraction)
}

/// `fake_exponential` del EIP-4844 (aproximación entera de
/// `factor * e^(numerator/denominator)`), idéntica a la referencia de la EIP.
fn fake_exponential(factor: u128, numerator: u128, denominator: u128) -> Result<u128, VmError> {
    let mut i: u128 = 1;
    let mut output: u128 = 0;
    let mut numerator_accum = factor.checked_mul(denominator).ok_or_else(overflow)?;
    while numerator_accum > 0 {
        output = output.checked_add(numerator_accum).ok_or_else(overflow)?;
        let step = numerator_accum
            .checked_mul(numerator)
            .ok_or_else(overflow)?;
        let denom_i = denominator.checked_mul(i).ok_or_else(overflow)?;
        numerator_accum = step / denom_i;
        i = i.checked_add(1).ok_or_else(overflow)?;
    }
    Ok(output / denominator)
}

fn overflow() -> VmError {
    VmError::Internal(InternalError::EvmInternal(
        "overflow calculando el blob base fee (EIP-4844)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_blob_context_is_zero() {
        assert_eq!(
            blob_base_fee(None, Spec::Cancun).map_err(|e| e.to_string()),
            Ok(0)
        );
    }

    #[test]
    fn zero_excess_is_the_floor_regardless_of_the_fork_fraction() {
        // fake_exponential(1, 0, d) == 1 para cualquier d != 0 (primera
        // iteración: output = d, numerator_accum pasa a 0, output/d = 1).
        assert_eq!(
            blob_base_fee(Some(0), Spec::Cancun).map_err(|e| e.to_string()),
            Ok(1)
        );
        assert_eq!(
            blob_base_fee(Some(0), Spec::Prague).map_err(|e| e.to_string()),
            Ok(1)
        );
    }

    #[test]
    fn excess_gas_raises_the_price() {
        let low = blob_base_fee(Some(1_000_000), Spec::Cancun).unwrap_or(0);
        let high = blob_base_fee(Some(10_000_000), Spec::Cancun).unwrap_or(0);
        assert!(high > low);
    }

    /// El caso que el corpus destapó: con `excessBlobGas` de 1130 blobs el
    /// precio **pasa de `u64::MAX`**. En `u64` esto era un `internal error` que
    /// mataba la tx entera; el valor es legítimo y tiene que salir entero.
    #[test]
    fn a_high_excess_overflows_u64_and_still_has_an_exact_price() {
        let excess = 1130 * GAS_PER_BLOB;
        let price = blob_base_fee(Some(excess), Spec::Cancun).unwrap_or(0);
        assert!(
            price > u128::from(u64::MAX),
            "el precio {price} tiene que pasarse de u64 para que este test mida algo"
        );
    }

    /// EIP-7691: el fork **no cambia `GAS_PER_BLOB`**, cambia cuántos blobs
    /// entran — y los tres números se mueven juntos.
    #[test]
    fn prague_raises_target_max_and_fraction_over_cancun() {
        let cancun = blob_params(Spec::Cancun);
        let prague = blob_params(Spec::Prague);
        assert!(prague.target_blobs > cancun.target_blobs);
        assert!(prague.max_blobs > cancun.max_blobs);
        assert!(prague.update_fraction > cancun.update_fraction);
        assert_eq!(cancun.target_blob_gas(), 3 * GAS_PER_BLOB);
        assert_eq!(cancun.max_blob_gas(), 6 * GAS_PER_BLOB);
        assert_eq!(prague.target_blob_gas(), 6 * GAS_PER_BLOB);
        assert_eq!(prague.max_blob_gas(), 9 * GAS_PER_BLOB);
    }

    /// El acumulador padre→hijo, **con el target del fork del hijo**. Es la
    /// trampa del slice: el MISMO padre da dos hijos distintos según el fork, y
    /// una constante hardcodeada a Cancun pasaría todo Cancun en verde.
    #[test]
    fn the_same_parent_yields_a_different_excess_in_each_fork() {
        // Padre con 6 blobs usados y sin excedente previo.
        let parent_used = 6 * GAS_PER_BLOB;
        // Cancun: 6 − 3 = 3 blobs de excedente.
        assert_eq!(
            excess_blob_gas(0, parent_used, 1, Spec::Cancun).map_err(|e| e.to_string()),
            Ok(3 * GAS_PER_BLOB)
        );
        // Prague: 6 − 6 = 0.
        assert_eq!(
            excess_blob_gas(0, parent_used, 1, Spec::Prague).map_err(|e| e.to_string()),
            Ok(0)
        );
    }

    /// El piso en cero ES la regla: un bloque por debajo del target no deja
    /// excedente negativo que le descuente al siguiente.
    #[test]
    fn a_parent_below_target_leaves_no_excess() {
        assert_eq!(
            excess_blob_gas(0, GAS_PER_BLOB, 1, Spec::Cancun).map_err(|e| e.to_string()),
            Ok(0)
        );
        assert_eq!(
            excess_blob_gas(0, 0, 1, Spec::Cancun).map_err(|e| e.to_string()),
            Ok(0)
        );
    }

    #[test]
    fn the_excess_accumulates_over_the_parents_own_excess() {
        // 4 de excedente + 6 usados − 3 de target = 7 blobs.
        assert_eq!(
            excess_blob_gas(4 * GAS_PER_BLOB, 6 * GAS_PER_BLOB, 1, Spec::Cancun)
                .map_err(|e| e.to_string()),
            Ok(7 * GAS_PER_BLOB)
        );
    }

    #[test]
    fn osaka_reserve_price_changes_the_excess_update_on_the_strict_boundary() {
        // parent_excess=0 => blob base fee 1. En el borde 16 la reserva no
        // aplica (`>`), y con 17 sí. El padre usa 6 blobs (el target), donde
        // las dos ramas difieren: la normal da 6-6 = 0 blobs de exceso y la de
        // reserva 6·(9-6)/9 = 2. Con 9 blobs (el máximo) ambas darían 3 y el
        // test no distinguiría las ramas.
        let used = 6 * GAS_PER_BLOB;
        assert_eq!(
            excess_blob_gas(0, used, 16, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(0)
        );
        assert_eq!(
            excess_blob_gas(0, used, 17, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(2 * GAS_PER_BLOB)
        );
        // Prague no conoce EIP-7918 aunque el precio de ejecución sea alto.
        assert_eq!(
            excess_blob_gas(0, used, 17, Spec::Prague).map_err(|e| e.to_string()),
            Ok(0)
        );
    }

    #[test]
    fn osaka_parent_exactly_at_target_with_active_reserve_takes_the_reserve_branch() {
        // `excess + used == target` no cae en el piso de cero (ese es `<`):
        // con la reserva activa, el exceso crece por la rama de EIP-7918.
        let parent_excess = GAS_PER_BLOB;
        let used = 5 * GAS_PER_BLOB;
        assert_eq!(
            parent_excess + used,
            blob_params(Spec::Osaka).target_blob_gas()
        );
        assert_eq!(
            blob_base_fee(Some(parent_excess), Spec::Osaka).map_err(|e| e.to_string()),
            Ok(1)
        );
        assert_eq!(
            excess_blob_gas(parent_excess, used, 16, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(0)
        );
        assert_eq!(
            excess_blob_gas(parent_excess, used, 17, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(parent_excess + used * 3 / 9)
        );
    }

    #[test]
    fn osaka_reserve_boundary_scales_with_a_blob_price_above_one() {
        // Precio blob del padre 2: el borde pasa a 32. Igual (`32 == 16·2`)
        // sigue la regla normal; uno más activa la reserva.
        let parent_excess = 3_341_000 + GAS_PER_BLOB;
        let used = 7 * GAS_PER_BLOB;
        assert_eq!(
            blob_base_fee(Some(parent_excess), Spec::Osaka).map_err(|e| e.to_string()),
            Ok(2)
        );
        assert_eq!(
            excess_blob_gas(parent_excess, used, 32, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(parent_excess + used - 6 * GAS_PER_BLOB)
        );
        assert_eq!(
            excess_blob_gas(parent_excess, used, 33, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(parent_excess + used * 3 / 9)
        );
    }

    #[test]
    fn osaka_reserve_compares_against_the_parent_blob_price_not_the_childs() {
        // En este punto el precio blob del padre todavía es 1, pero el exceso
        // que resultaría de la regla normal (`parent + 7 - 6`) ya vale 2. Con
        // base_fee=17 la comparación correcta contra el PADRE activa reserva;
        // comparar contra el supuesto precio del hijo (32) no la activaría.
        let parent_excess = 3_341_000;
        let used = 7 * GAS_PER_BLOB;
        assert_eq!(
            blob_base_fee(Some(parent_excess), Spec::Osaka).map_err(|e| e.to_string()),
            Ok(1)
        );
        assert_eq!(
            blob_base_fee(Some(parent_excess + GAS_PER_BLOB), Spec::Osaka)
                .map_err(|e| e.to_string()),
            Ok(2)
        );
        assert_eq!(
            excess_blob_gas(parent_excess, used, 17, Spec::Osaka).map_err(|e| e.to_string()),
            Ok(parent_excess + used * 3 / 9)
        );
    }
}
