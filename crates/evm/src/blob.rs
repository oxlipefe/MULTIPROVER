//! EIP-4844/7691 — precio del blob gas (`BLOBBASEFEE`, 0x4A). Fórmula
//! `fake_exponential` del EIP sobre el gas excedente de blobs del bloque, con
//! la fracción de actualización por fork (EIP-7691 la sube en Prague). Vive en
//! `evm` (no en `interpreter`): es quien arma el frame el que calcula el valor
//! ya resuelto — el intérprete solo lo apila (`interpreter::host::BlockEnv`).

use alloc::string::ToString;

use crate::error::{InternalError, VmError};
use crate::types::Spec;

/// EIP-4844 — piso del precio del blob gas.
const MIN_BASE_FEE_PER_BLOB_GAS: u128 = 1;
/// EIP-4844 — fracción de actualización hasta Prague.
const UPDATE_FRACTION_CANCUN: u64 = 3_338_477;
/// EIP-7691 (Prague) — la fracción sube junto con el target de blobs por bloque.
const UPDATE_FRACTION_PRAGUE: u64 = 5_007_716;

/// Fracción de actualización por fork (EIP-4844 §Cancun / EIP-7691 §Prague).
/// `pub` (no `pub(crate)`): el harness diferencial (`cmd/conformance`) la
/// reusa para que revm calcule el mismo precio con la MISMA constante — dos
/// copias del número serían una segunda fuente de verdad que puede driftear.
pub fn update_fraction(spec: Spec) -> u64 {
    if spec.is_enabled(Spec::Prague) {
        UPDATE_FRACTION_PRAGUE
    } else {
        UPDATE_FRACTION_CANCUN
    }
}

/// `blob_base_fee`: sin contexto de blobs en el `BlockEnv` (`None` — pre-
/// Cancun o bloque sin el campo poblado) el opcode no tiene valor de
/// protocolo en este slice: 0.
pub(crate) fn blob_base_fee(excess_blob_gas: Option<u64>, spec: Spec) -> Result<u64, VmError> {
    let Some(excess) = excess_blob_gas else {
        return Ok(0);
    };
    let fraction = u128::from(update_fraction(spec));
    let price = fake_exponential(MIN_BASE_FEE_PER_BLOB_GAS, u128::from(excess), fraction)?;
    u64::try_from(price).map_err(|_| overflow())
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
}
