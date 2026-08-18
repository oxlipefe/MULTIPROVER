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
    /// Blobs máximos por bloque (`MAX_BLOB_NUMBER`). Una tx no puede exceder el
    /// máximo del BLOQUE, así que este número es también el tope por tx.
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

/// La ÚNICA puerta a los parámetros de blob. Pre-Cancun no hay blobs y ninguna
/// de las reglas de este módulo se consulta; devolver los de Cancun no habilita
/// nada (las tres puertas —validación de tx, header y precio— están gateadas
/// por `Spec::Cancun` río arriba).
#[must_use]
pub fn blob_params(spec: Spec) -> BlobParams {
    if spec.is_enabled(Spec::Prague) {
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
#[must_use]
pub fn excess_blob_gas(parent_excess: u64, parent_blob_gas_used: u64, spec: Spec) -> u64 {
    parent_excess
        .saturating_add(parent_blob_gas_used)
        .saturating_sub(blob_params(spec).target_blob_gas())
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
            excess_blob_gas(0, parent_used, Spec::Cancun),
            3 * GAS_PER_BLOB
        );
        // Prague: 6 − 6 = 0.
        assert_eq!(excess_blob_gas(0, parent_used, Spec::Prague), 0);
    }

    /// El piso en cero ES la regla: un bloque por debajo del target no deja
    /// excedente negativo que le descuente al siguiente.
    #[test]
    fn a_parent_below_target_leaves_no_excess() {
        assert_eq!(excess_blob_gas(0, GAS_PER_BLOB, Spec::Cancun), 0);
        assert_eq!(excess_blob_gas(0, 0, Spec::Cancun), 0);
    }

    #[test]
    fn the_excess_accumulates_over_the_parents_own_excess() {
        // 4 de excedente + 6 usados − 3 de target = 7 blobs.
        assert_eq!(
            excess_blob_gas(4 * GAS_PER_BLOB, 6 * GAS_PER_BLOB, Spec::Cancun),
            7 * GAS_PER_BLOB
        );
    }
}
