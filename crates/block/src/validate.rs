//! Las reglas de validez de un bloque, fuera de la ejecución.
//!
//! Tres momentos, en el orden en que un cliente los recorre:
//!
//! 1. **El header contra su padre** ([`validate_header`]): lo que hace inválido
//!    a un bloque por lo que DECLARA, sin correr una sola tx. Es
//!    `validate_header` de `execution-specs` (`forks/<fork>/fork.py`).
//! 2. **El cuerpo contra el header**: txs, withdrawals, ommers y blob gas.
//! 3. **Lo ejecutado contra el header** ([`validate_post_execution`]): los
//!    roots y el gas que produjo el motor.
//!
//! El fork de entrada es el del bloque. El piso es Paris: todas las reglas de
//! acá son las post-Merge, y un fork anterior no es representable en `Spec`.

use alloy_primitives::{B256, Bloom};
use repo_b_common::spec::Spec;
use repo_b_common::withdrawal::Withdrawal;

use crate::error::{BlockError, HeaderField};
use crate::header::Header;
use crate::roots;

/// Piso absoluto del `gasLimit` de un bloque (Yellow Paper,
/// `GAS_LIMIT_MINIMUM`).
pub const MIN_GAS_LIMIT: u64 = 5_000;
/// El `gasLimit` no puede moverse `parent/1024` o más respecto del padre. La
/// comparación es `>=`: el borde exacto ya es inválido.
pub const GAS_LIMIT_BOUND_DIVISOR: u64 = 1_024;
/// EIP-1559 — `gasTarget = gasLimit / 2`.
pub const ELASTICITY_MULTIPLIER: u64 = 2;
/// EIP-1559 — el `baseFee` no puede moverse más de 1/8 por bloque.
pub const BASE_FEE_MAX_CHANGE_DENOMINATOR: u64 = 8;
/// EIP-7934: 10 MiB del bloque de consenso menos 2 MiB de margen para el CL.
pub const MAX_RLP_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// EIP-7934: el RLP del bloque **entero** —el objeto recibido, no una
/// re-codificación— no puede pasar de [`MAX_RLP_BLOCK_SIZE`] desde Osaka.
pub fn check_block_rlp_size(spec: Spec, encoded_len: usize) -> Result<(), BlockError> {
    if spec.is_enabled(Spec::Osaka) && encoded_len > MAX_RLP_BLOCK_SIZE {
        return Err(BlockError::BlockRlpTooLarge {
            len: encoded_len,
            max: MAX_RLP_BLOCK_SIZE,
        });
    }
    Ok(())
}

/// El `gasLimit` declarado es admisible dado el del padre.
pub fn check_gas_limit(parent_gas_limit: u64, gas_limit: u64) -> Result<(), BlockError> {
    if gas_limit < MIN_GAS_LIMIT {
        return Err(BlockError::GasLimitBelowMinimum {
            gas_limit,
            minimum: MIN_GAS_LIMIT,
        });
    }
    let delta = parent_gas_limit.abs_diff(gas_limit);
    // Divisor constante distinto de cero: la división no puede fallar.
    let bound = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR;
    if delta >= bound {
        return Err(BlockError::GasLimitOutOfBounds {
            gas_limit,
            parent_gas_limit,
            delta,
            bound,
        });
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
) -> Result<u64, BlockError> {
    let underivable = BlockError::BaseFeeUnderivable { parent_gas_limit };
    let target = parent_gas_limit / ELASTICITY_MULTIPLIER;
    if target == 0 {
        // Inalcanzable con un padre válido (`MIN_GAS_LIMIT` lo impide), pero
        // dividir por cero sería un panic.
        return Err(underivable);
    }
    let base = u128::from(parent_base_fee);
    let target = u128::from(target);
    let used = u128::from(parent_gas_used);
    let denominator = u128::from(BASE_FEE_MAX_CHANGE_DENOMINATOR);
    // `base · |used − target| / target / 8`. Los dos factores entran en 64
    // bits, así que el producto entra en 128: el `checked` no falla nunca, y
    // existe para que un cambio de tipos no lo vuelva un wrap.
    let delta = |gap: u128| {
        base.checked_mul(gap)
            .and_then(|scaled| scaled.checked_div(target))
            .and_then(|per_target| per_target.checked_div(denominator))
    };

    let next = if used == target {
        base
    } else if used > target {
        let gap = used.checked_sub(target).ok_or(underivable.clone())?;
        let change = delta(gap).ok_or(underivable.clone())?;
        base.saturating_add(change.max(1))
    } else {
        let gap = target.checked_sub(used).ok_or(underivable.clone())?;
        let change = delta(gap).ok_or(underivable.clone())?;
        base.saturating_sub(change)
    };
    u64::try_from(next).map_err(|_| underivable)
}

/// EIP-4844: el `excessBlobGas` declarado es el que la fórmula exige dado el
/// padre. El `TARGET` sale de `blob::blob_params(spec)`, la MISMA tabla por fork
/// que consume el motor: EIP-7691 lo mueve en Prague, y una constante local
/// pasaría Cancun entero en verde y rompería Prague en silencio.
fn check_excess_blob_gas(header: &Header, parent: &Header, spec: Spec) -> Result<(), BlockError> {
    let declared = header.excess_blob_gas.ok_or(BlockError::MissingField {
        field: HeaderField::ExcessBlobGas,
        spec,
    })?;
    let parent_excess = parent
        .excess_blob_gas
        .ok_or(BlockError::ParentFieldMissing {
            field: HeaderField::ExcessBlobGas,
        })?;
    let parent_used = parent.blob_gas_used.ok_or(BlockError::ParentFieldMissing {
        field: HeaderField::BlobGasUsed,
    })?;
    let parent_base_fee = parent
        .base_fee_per_gas
        .ok_or(BlockError::ParentFieldMissing {
            field: HeaderField::BaseFeePerGas,
        })?;
    let expected =
        repo_b_evm::blob::excess_blob_gas(parent_excess, parent_used, parent_base_fee, spec)
            .map_err(|_| BlockError::ExcessBlobGasUnderivable)?;
    if declared != expected {
        return Err(BlockError::ExcessBlobGas {
            declared,
            expected,
            parent_excess,
            parent_used,
            target: repo_b_evm::blob::blob_params(spec).target_blob_gas(),
        });
    }
    Ok(())
}

/// El header contra su padre: `validate_header` de `execution-specs`.
pub fn validate_header(header: &Header, parent: &Header, spec: Spec) -> Result<(), BlockError> {
    check_gas_limit(parent.gas_limit, header.gas_limit)?;

    let base_fee = header.base_fee_per_gas.ok_or(BlockError::MissingField {
        field: HeaderField::BaseFeePerGas,
        spec,
    })?;
    let parent_base_fee = parent
        .base_fee_per_gas
        .ok_or(BlockError::ParentFieldMissing {
            field: HeaderField::BaseFeePerGas,
        })?;
    let expected = expected_base_fee(parent.gas_limit, parent.gas_used, parent_base_fee)?;
    if expected != base_fee {
        return Err(BlockError::BaseFee {
            declared: base_fee,
            expected,
        });
    }

    if spec.is_enabled(Spec::Cancun) {
        check_excess_blob_gas(header, parent, spec)?;
    }

    Ok(())
}

/// EIP-4844, del lado del cuerpo: el `blobGasUsed` declarado es lo que suman
/// las txs del bloque (`computed_used = GAS_PER_BLOB ×` sus blobs), y no pasa
/// el tope del bloque.
///
/// El tope es de BLOQUE, no de tx: el chequeo por tx del motor deja pasar N
/// txs chicas cuya suma se pasa.
pub fn check_blob_gas_used(
    header: &Header,
    computed_used: u64,
    spec: Spec,
) -> Result<(), BlockError> {
    let declared = header.blob_gas_used.ok_or(BlockError::MissingField {
        field: HeaderField::BlobGasUsed,
        spec,
    })?;
    if declared != computed_used {
        return Err(BlockError::BlobGasUsed {
            declared,
            computed: computed_used,
        });
    }
    let params = repo_b_evm::blob::blob_params(spec);
    if declared > params.max_blob_gas() {
        return Err(BlockError::BlobGasAboveMax {
            declared,
            max: params.max_blob_gas(),
            max_blobs: params.max_blobs,
        });
    }
    Ok(())
}

/// El `transactionsRoot` del header es el de los envelopes del cuerpo.
pub fn check_transactions_root<T: AsRef<[u8]>>(
    header: &Header,
    encoded_transactions: &[T],
) -> Result<(), BlockError> {
    let computed = roots::transactions_root(encoded_transactions);
    if computed != header.transactions_root {
        return Err(BlockError::TransactionsRoot {
            declared: header.transactions_root,
            computed,
        });
    }
    Ok(())
}

/// EIP-4895: el `withdrawalsRoot` del header es el de las withdrawals del
/// cuerpo.
pub fn check_withdrawals_root(
    header: &Header,
    withdrawals: &[Withdrawal],
) -> Result<(), BlockError> {
    let Some(declared) = header.withdrawals_root else {
        return Ok(());
    };
    let computed = roots::withdrawals_root(withdrawals);
    if computed != declared {
        return Err(BlockError::WithdrawalsRoot { declared, computed });
    }
    Ok(())
}

/// EIP-7685: el `requestsHash` del header es el de los requests que el bloque
/// produjo. Post-Prague el campo es obligatorio: un header sin él es inválido,
/// no un bloque sin requests.
pub fn check_requests_hash(header: &Header, computed: B256, spec: Spec) -> Result<(), BlockError> {
    let declared = header.requests_hash.ok_or(BlockError::MissingField {
        field: HeaderField::RequestsHash,
        spec,
    })?;
    if declared != computed {
        return Err(BlockError::RequestsHash { declared, computed });
    }
    Ok(())
}

/// Lo que produjo la ejecución del bloque, ya reducido a lo que el header
/// compromete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostExecution {
    /// El root MPT del post-state.
    pub state_root: B256,
    /// El gas acumulado del último receipt (cero si no hay txs).
    pub gas_used: u64,
    /// [`roots::receipts_root`] de los receipts ejecutados.
    pub receipts_root: B256,
    /// [`roots::block_logs_bloom`] de los receipts ejecutados.
    pub logs_bloom: Bloom,
}

/// Lo ejecutado contra el header. El orden pone primero el `stateRoot`, que es
/// la transición de estado (lo que el motor decide), y después la maquinaria de
/// encoding: así un bug del motor no se esconde detrás de uno del encoder.
pub fn validate_post_execution(
    header: &Header,
    executed: &PostExecution,
) -> Result<(), BlockError> {
    if executed.state_root != header.state_root {
        return Err(BlockError::StateRoot {
            declared: header.state_root,
            computed: executed.state_root,
        });
    }
    if executed.gas_used != header.gas_used {
        return Err(BlockError::GasUsed {
            declared: header.gas_used,
            computed: executed.gas_used,
        });
    }
    if executed.receipts_root != header.receipts_root {
        return Err(BlockError::ReceiptsRoot {
            declared: header.receipts_root,
            computed: executed.receipts_root,
        });
    }
    if executed.logs_bloom != header.logs_bloom {
        return Err(BlockError::LogsBloom);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::tests::prague_genesis;

    const GAS_PER_BLOB: u64 = repo_b_evm::blob::GAS_PER_BLOB;

    #[test]
    fn osaka_rlp_limit_is_inclusive_and_does_not_exist_in_prague() {
        assert!(check_block_rlp_size(Spec::Osaka, MAX_RLP_BLOCK_SIZE).is_ok());
        assert!(check_block_rlp_size(Spec::Osaka, MAX_RLP_BLOCK_SIZE + 1).is_err());
        assert!(check_block_rlp_size(Spec::Prague, MAX_RLP_BLOCK_SIZE + 1).is_ok());
    }

    /// Los tres vectores de `BlockException.INVALID_GASLIMIT` del corpus, con
    /// el padre que traen (`gasLimit` 5000). El de 4999 separa las dos reglas:
    /// cae dentro del bound de 1024 y aun así es inválido por el piso.
    #[test]
    fn the_gas_limit_vectors_of_the_corpus_are_rejected() {
        assert!(check_gas_limit(5_000, 0).is_err());
        assert!(check_gas_limit(5_000, 1).is_err());
        assert!(check_gas_limit(5_000, 4_999).is_err());
    }

    #[test]
    fn a_gas_limit_at_the_bound_is_rejected_even_if_above_the_floor() {
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

    /// Padre vacío (`gasUsed` 0) ⇒ el `baseFee` no baja porque el descuento
    /// entero da cero.
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
        assert_eq!(expected_base_fee(2_000_000, 2_000_000, 1_000), Ok(1_125));
    }

    /// Con el padre por encima del target el fee SIEMPRE sube al menos 1.
    #[test]
    fn above_target_the_base_fee_rises_at_least_one() {
        assert_eq!(expected_base_fee(2_000_000, 1_000_001, 1), Ok(2));
    }

    #[test]
    fn an_idle_parent_lowers_the_base_fee_by_an_eighth() {
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
    fn a_parent_without_gas_target_is_an_error_instead_of_a_panic() {
        assert!(expected_base_fee(1, 0, 7).is_err());
    }

    /// Un padre Cancun/Prague con 6 blobs, y un hijo válido sobre él salvo por
    /// lo que el test cambie.
    fn blob_pair(parent_used_blobs: u64, declared_excess: u64) -> (Header, Header) {
        let mut parent = prague_genesis();
        parent.blob_gas_used = Some(parent_used_blobs * GAS_PER_BLOB);
        parent.base_fee_per_gas = Some(1);
        let mut child = parent.clone();
        child.excess_blob_gas = Some(declared_excess);
        child.base_fee_per_gas = expected_base_fee(parent.gas_limit, parent.gas_used, 1).ok();
        (parent, child)
    }

    /// **La trampa del fork.** EIP-7691 mueve el target en Prague, así que el
    /// MISMO par (padre, header) es válido en un fork e inválido en el otro.
    #[test]
    fn the_same_header_is_valid_in_cancun_and_invalid_in_prague() {
        // Padre con 6 blobs y sin excedente ⇒ hijo con 3 blobs de excedente en
        // Cancun (6 − 3), y con 0 en Prague (6 − 6).
        let (parent, child) = blob_pair(6, 3 * GAS_PER_BLOB);
        assert!(check_excess_blob_gas(&child, &parent, Spec::Cancun).is_ok());
        assert!(matches!(
            check_excess_blob_gas(&child, &parent, Spec::Prague),
            Err(BlockError::ExcessBlobGas { .. })
        ));
    }

    /// El tope de `blobGasUsed` también es por fork: 7 blobs se pasan en Cancun
    /// (máximo 6) y entran en Prague (máximo 9).
    #[test]
    fn the_block_blob_limit_moves_with_the_fork() {
        let (_, mut child) = blob_pair(0, 0);
        child.blob_gas_used = Some(7 * GAS_PER_BLOB);
        assert!(matches!(
            check_blob_gas_used(&child, 7 * GAS_PER_BLOB, Spec::Cancun),
            Err(BlockError::BlobGasAboveMax { .. })
        ));
        assert!(check_blob_gas_used(&child, 7 * GAS_PER_BLOB, Spec::Prague).is_ok());
    }

    /// El tope es de BLOQUE, no de tx: el declarado tiene que ser lo que suman
    /// las txs.
    #[test]
    fn a_declared_blob_gas_that_disagrees_with_the_transactions_is_rejected() {
        let (_, mut child) = blob_pair(0, 0);
        child.blob_gas_used = Some(2 * GAS_PER_BLOB);
        assert!(matches!(
            check_blob_gas_used(&child, 3 * GAS_PER_BLOB, Spec::Cancun),
            Err(BlockError::BlobGasUsed { .. })
        ));
    }

    /// Un padre al que le falta un campo que la regla necesita no es un hijo
    /// inválido: es una regla que no se puede evaluar, y se dice.
    #[test]
    fn a_parent_without_blob_fields_is_reported_as_such() {
        let (mut parent, child) = blob_pair(0, 0);
        parent.excess_blob_gas = None;
        assert_eq!(
            check_excess_blob_gas(&child, &parent, Spec::Cancun),
            Err(BlockError::ParentFieldMissing {
                field: HeaderField::ExcessBlobGas
            })
        );
    }

    #[test]
    fn the_withdrawals_root_is_the_one_of_the_body() {
        let header = prague_genesis();
        assert!(check_withdrawals_root(&header, &[]).is_ok());
        let one = Withdrawal {
            index: 0,
            validator_index: 0,
            address: alloy_primitives::Address::ZERO,
            amount: 1,
        };
        assert!(matches!(
            check_withdrawals_root(&header, &[one]),
            Err(BlockError::WithdrawalsRoot { .. })
        ));
    }

    #[test]
    fn every_post_execution_commitment_is_checked() {
        let header = prague_genesis();
        let good = PostExecution {
            state_root: header.state_root,
            gas_used: header.gas_used,
            receipts_root: header.receipts_root,
            logs_bloom: header.logs_bloom,
        };
        assert_eq!(validate_post_execution(&header, &good), Ok(()));
        type Mutation = fn(&mut PostExecution);
        type Verdict = fn(&BlockError) -> bool;
        let cases: [(Mutation, Verdict); 4] = [
            (
                |p| p.state_root = B256::repeat_byte(1),
                |e| matches!(e, BlockError::StateRoot { .. }),
            ),
            (
                |p| p.gas_used = 1,
                |e| matches!(e, BlockError::GasUsed { .. }),
            ),
            (
                |p| p.receipts_root = B256::repeat_byte(2),
                |e| matches!(e, BlockError::ReceiptsRoot { .. }),
            ),
            (
                |p| p.logs_bloom = Bloom::repeat_byte(3),
                |e| matches!(e, BlockError::LogsBloom),
            ),
        ];
        for (mutate, expected) in cases {
            let mut bad = good.clone();
            mutate(&mut bad);
            match validate_post_execution(&header, &bad) {
                Err(e) => assert!(expected(&e), "veredicto equivocado: {e}"),
                Ok(()) => panic!("una mutación post-ejecución pasó"),
            }
        }
    }

    #[test]
    fn the_requests_hash_is_checked_and_required() {
        let header = prague_genesis();
        let Some(declared) = header.requests_hash else {
            panic!("el genesis de Prague trae requestsHash");
        };
        assert!(check_requests_hash(&header, declared, Spec::Prague).is_ok());
        assert!(matches!(
            check_requests_hash(&header, B256::ZERO, Spec::Prague),
            Err(BlockError::RequestsHash { .. })
        ));
        let mut without = header;
        without.requests_hash = None;
        assert!(matches!(
            check_requests_hash(&without, declared, Spec::Prague),
            Err(BlockError::MissingField { .. })
        ));
    }

    #[test]
    fn the_transactions_root_is_the_one_of_the_body() {
        let header = prague_genesis();
        assert!(check_transactions_root::<&[u8]>(&header, &[]).is_ok());
        assert!(matches!(
            check_transactions_root(&header, &[[0x80u8]]),
            Err(BlockError::TransactionsRoot { .. })
        ));
    }
}
