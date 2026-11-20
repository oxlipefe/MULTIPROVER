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
//!
//! **Bloques de transición.** De los campos que un fork agrega al header, solo
//! dos se leen del PADRE: `excessBlobGas` y `blobGasUsed`, y el primer bloque de
//! Cancun los evalúa en cero (ver `parent_blob_gas`). `parentBeaconBlockRoot`,
//! `withdrawalsRoot` y `requestsHash` son del propio bloque y no tienen caso de
//! transición. El de `baseFeePerGas` (London fija `INITIAL_BASE_FEE` en su
//! primer bloque) es pre-Merge y queda fuera del piso.

use alloy_primitives::{B64, B256, Bloom};
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
/// EIP-7934: tamaño máximo del bloque de consenso, 10 MiB.
pub const MAX_BLOCK_SIZE: usize = 10_485_760;
/// EIP-7934: margen que se reserva para el envoltorio de la capa de consenso,
/// 2 MiB.
pub const SAFETY_MARGIN: usize = 2_097_152;
/// EIP-7934: `MAX_BLOCK_SIZE - SAFETY_MARGIN` = 8 MiB, inclusivo. La resta se
/// evalúa en compilación: un underflow es un error de build, no un tope roto.
pub const MAX_RLP_BLOCK_SIZE: usize = match MAX_BLOCK_SIZE.checked_sub(SAFETY_MARGIN) {
    Some(max) => max,
    None => panic!("EIP-7934: SAFETY_MARGIN mayor que MAX_BLOCK_SIZE"),
};

/// El `extraData` admite a lo sumo 32 bytes.
pub const MAX_EXTRA_DATA_BYTES: usize = 32;
/// EIP-3675: el `ommersHash` post-Merge es `keccak(rlp([]))`.
pub const EMPTY_OMMERS_HASH: B256 = B256::new([
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
]);
/// EIP-3675: el `nonce` de PoW post-Merge es cero.
pub const POST_MERGE_NONCE: B64 = B64::ZERO;

/// Desde qué fork existe cada campo del tail. London queda debajo del piso, así
/// que `baseFeePerGas` es obligatorio en todo fork representable.
const FORK_FIELDS: [(HeaderField, Spec); 6] = [
    (HeaderField::BaseFeePerGas, Spec::Paris),
    (HeaderField::WithdrawalsRoot, Spec::Shanghai),
    (HeaderField::BlobGasUsed, Spec::Cancun),
    (HeaderField::ExcessBlobGas, Spec::Cancun),
    (HeaderField::ParentBeaconBlockRoot, Spec::Cancun),
    (HeaderField::RequestsHash, Spec::Prague),
];

fn is_present(header: &Header, field: HeaderField) -> bool {
    match field {
        HeaderField::BaseFeePerGas => header.base_fee_per_gas.is_some(),
        HeaderField::WithdrawalsRoot => header.withdrawals_root.is_some(),
        HeaderField::BlobGasUsed => header.blob_gas_used.is_some(),
        HeaderField::ExcessBlobGas => header.excess_blob_gas.is_some(),
        HeaderField::ParentBeaconBlockRoot => header.parent_beacon_block_root.is_some(),
        HeaderField::RequestsHash => header.requests_hash.is_some(),
    }
}

/// Cada fork tiene su propio tipo de header en `execution-specs`: un campo que
/// el fork exige y falta, o uno que el fork todavía no tiene, es un header que
/// no decodifica en ese fork. Acá el tipo es uno solo con `Option`, así que la
/// regla se aplica explícita.
pub fn validate_fork_fields(header: &Header, spec: Spec) -> Result<(), BlockError> {
    for (field, since) in FORK_FIELDS {
        match (spec.is_enabled(since), is_present(header, field)) {
            (true, false) => return Err(BlockError::MissingField { field, spec }),
            (false, true) => return Err(BlockError::UnexpectedField { field, spec }),
            _ => {}
        }
    }
    Ok(())
}

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

/// El primer fork cuyo header trae `blobGasUsed` y `excessBlobGas` (EIP-4844).
const BLOB_FIELDS_FORK: Spec = Spec::Cancun;
/// El fork inmediatamente anterior a [`BLOB_FIELDS_FORK`]: la forma de header
/// que puede ser padre del primer bloque con campos de blob.
const PRE_BLOB_FIELDS_FORK: Spec = Spec::Shanghai;

/// `(excessBlobGas, blobGasUsed)` del padre, tal como los lee la fórmula.
///
/// **El bloque de transición.** EIP-4844: *"for the first post-fork block, both
/// `parent.blob_gas_used` and `parent.excess_blob_gas` are evaluated as 0"*.
/// La regla vale SOLO cuando el hijo es del primer fork con campos de blob y el
/// padre tiene, entera, la forma de header del fork anterior (sin los dos
/// campos y sin `parentBeaconBlockRoot`). Cualquier otro faltante —un padre
/// Cancun al que le falta uno, o un hijo de un fork posterior sobre un padre
/// sin campos— es un padre con el que la regla no se puede evaluar, y se
/// reporta.
///
/// Lo segundo es más estricto que la letra de `execution-specs` (Prague y Osaka
/// también leen cero si el padre no es de su fork ni del anterior), y a
/// propósito: ese padre solo existe en una cadena que se saltea Cancun, que no
/// es ninguna de las que este motor valida.
fn parent_blob_gas(parent: &Header, spec: Spec) -> Result<(u64, u64), BlockError> {
    match (parent.excess_blob_gas, parent.blob_gas_used) {
        (Some(excess), Some(used)) => Ok((excess, used)),
        (None, None)
            if spec == BLOB_FIELDS_FORK
                && validate_fork_fields(parent, PRE_BLOB_FIELDS_FORK).is_ok() =>
        {
            Ok((0, 0))
        }
        (None, _) => Err(BlockError::ParentFieldMissing {
            field: HeaderField::ExcessBlobGas,
        }),
        (Some(_), None) => Err(BlockError::ParentFieldMissing {
            field: HeaderField::BlobGasUsed,
        }),
    }
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
    let (parent_excess, parent_used) = parent_blob_gas(parent, spec)?;
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

/// El header contra su padre: `validate_header` de `execution-specs`, más la
/// presencia de los campos por fork.
///
/// `parent` es el header del bloque al que este se encadena; su hash se
/// recomputa acá (`keccak(rlp(parent))`) y no se recibe, para que no exista un
/// camino por el que un hash declarado se compare contra sí mismo.
///
/// El orden no cambia el veredicto, solo qué razón se reporta cuando un header
/// viola dos reglas: primero la forma, después las reglas que el corpus de la
/// EF discrimina (gas limit, base fee, excess blob gas) y al final las que no.
pub fn validate_header(header: &Header, parent: &Header, spec: Spec) -> Result<(), BlockError> {
    validate_fork_fields(header, spec)?;

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

    if header.gas_used > header.gas_limit {
        return Err(BlockError::GasUsedAboveLimit {
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
        });
    }
    if header.timestamp <= parent.timestamp {
        return Err(BlockError::TimestampNotAfterParent {
            timestamp: header.timestamp,
            parent_timestamp: parent.timestamp,
        });
    }
    // `checked_add`: un padre en `u64::MAX` no tiene hijo representable, y un
    // wrap a cero lo haría encadenar con el genesis.
    if parent.number.checked_add(1) != Some(header.number) {
        return Err(BlockError::NumberNotParentPlusOne {
            number: header.number,
            parent_number: parent.number,
        });
    }
    if header.extra_data.len() > MAX_EXTRA_DATA_BYTES {
        return Err(BlockError::ExtraDataTooLong {
            len: header.extra_data.len(),
            max: MAX_EXTRA_DATA_BYTES,
        });
    }
    if !header.difficulty.is_zero() {
        return Err(BlockError::NonZeroDifficulty);
    }
    if header.nonce != POST_MERGE_NONCE {
        return Err(BlockError::NonZeroNonce);
    }
    if header.ommers_hash != EMPTY_OMMERS_HASH {
        return Err(BlockError::NonEmptyOmmersHash {
            declared: header.ommers_hash,
        });
    }
    let computed = parent.hash();
    if header.parent_hash != computed {
        return Err(BlockError::ParentHash {
            declared: header.parent_hash,
            computed,
        });
    }
    Ok(())
}

/// Post-Merge el cuerpo no trae ommers (`execution-specs`:
/// `if block.ommers != (): raise InvalidBlock`). El `ommersHash` del header lo
/// juzga [`validate_header`]; esto juzga la lista.
pub fn check_ommers(ommers_count: usize) -> Result<(), BlockError> {
    if ommers_count != 0 {
        return Err(BlockError::NonEmptyOmmers {
            count: ommers_count,
        });
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
/// cuerpo. Sin `withdrawalsRoot` (pre-Shanghai) el cuerpo no puede traer
/// withdrawals: no habría dónde comprometerlas.
pub fn check_withdrawals_root(
    header: &Header,
    withdrawals: &[Withdrawal],
) -> Result<(), BlockError> {
    let Some(declared) = header.withdrawals_root else {
        if withdrawals.is_empty() {
            return Ok(());
        }
        return Err(BlockError::WithdrawalsWithoutRoot {
            count: withdrawals.len(),
        });
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
    use alloc::vec;

    use crate::header::tests::prague_genesis;

    const GAS_PER_BLOB: u64 = repo_b_evm::blob::GAS_PER_BLOB;

    /// La aritmética de los tests también es explícita: un overflow acá es un
    /// test mal escrito, y se dice en vez de envolver.
    #[track_caller]
    fn plus(a: u64, b: u64) -> u64 {
        match a.checked_add(b) {
            Some(sum) => sum,
            None => panic!("overflow en el test: {a} + {b}"),
        }
    }

    #[track_caller]
    fn minus(a: u64, b: u64) -> u64 {
        match a.checked_sub(b) {
            Some(difference) => difference,
            None => panic!("underflow en el test: {a} - {b}"),
        }
    }

    #[track_caller]
    fn plus_usize(a: usize, b: usize) -> usize {
        match a.checked_add(b) {
            Some(sum) => sum,
            None => panic!("overflow en el test: {a} + {b}"),
        }
    }

    /// El blob gas de `count` blobs.
    #[track_caller]
    fn blobs(count: u64) -> u64 {
        match count.checked_mul(GAS_PER_BLOB) {
            Some(gas) => gas,
            None => panic!("overflow en el test: {count} blobs"),
        }
    }

    #[test]
    fn osaka_rlp_limit_is_inclusive_and_does_not_exist_in_prague() {
        assert!(check_block_rlp_size(Spec::Osaka, MAX_RLP_BLOCK_SIZE).is_ok());
        assert!(check_block_rlp_size(Spec::Osaka, plus_usize(MAX_RLP_BLOCK_SIZE, 1)).is_err());
        assert!(check_block_rlp_size(Spec::Prague, plus_usize(MAX_RLP_BLOCK_SIZE, 1)).is_ok());
    }

    /// Los números del EIP y de `execution-specs` (`forks/osaka/fork.py`), y
    /// el tope rige en todo fork desde Osaka: los BPO no lo cambian.
    #[test]
    fn the_rlp_limit_is_the_eip_number_and_holds_in_the_bpo_forks() {
        assert_eq!(MAX_RLP_BLOCK_SIZE, 8_388_608);
        for spec in [Spec::Osaka, Spec::Bpo1, Spec::Bpo2] {
            assert!(
                check_block_rlp_size(spec, MAX_RLP_BLOCK_SIZE).is_ok(),
                "{spec:?}"
            );
            assert_eq!(
                check_block_rlp_size(spec, plus_usize(MAX_RLP_BLOCK_SIZE, 1)),
                Err(BlockError::BlockRlpTooLarge {
                    len: plus_usize(MAX_RLP_BLOCK_SIZE, 1),
                    max: MAX_RLP_BLOCK_SIZE,
                }),
                "{spec:?}"
            );
        }
        for spec in [Spec::Paris, Spec::Shanghai, Spec::Cancun, Spec::Prague] {
            assert!(check_block_rlp_size(spec, usize::MAX).is_ok(), "{spec:?}");
        }
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
        assert!(check_gas_limit(1_048_576, plus(1_048_576, 1_024)).is_err());
        assert!(check_gas_limit(1_048_576, minus(1_048_576, 1_024)).is_err());
        assert!(check_gas_limit(1_048_576, plus(1_048_576, 1_023)).is_ok());
        assert!(check_gas_limit(1_048_576, minus(1_048_576, 1_023)).is_ok());
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
        parent.blob_gas_used = Some(blobs(parent_used_blobs));
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
        let (parent, child) = blob_pair(6, blobs(3));
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
        child.blob_gas_used = Some(blobs(7));
        assert!(matches!(
            check_blob_gas_used(&child, blobs(7), Spec::Cancun),
            Err(BlockError::BlobGasAboveMax { .. })
        ));
        assert!(check_blob_gas_used(&child, blobs(7), Spec::Prague).is_ok());
    }

    /// El tope es de BLOQUE, no de tx: el declarado tiene que ser lo que suman
    /// las txs.
    #[test]
    fn a_declared_blob_gas_that_disagrees_with_the_transactions_is_rejected() {
        let (_, mut child) = blob_pair(0, 0);
        child.blob_gas_used = Some(blobs(2));
        assert!(matches!(
            check_blob_gas_used(&child, blobs(3), Spec::Cancun),
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

    /// Un hijo válido del genesis de Prague: cada test de abajo rompe UNA regla
    /// sobre esto, así que la falla que ve es la de esa regla y no otra.
    fn valid_child(parent: &Header) -> Header {
        let mut child = parent.clone();
        child.parent_hash = parent.hash();
        child.number = plus(parent.number, 1);
        child.timestamp = plus(parent.timestamp, 12);
        child.base_fee_per_gas = parent
            .base_fee_per_gas
            .and_then(|fee| expected_base_fee(parent.gas_limit, parent.gas_used, fee).ok());
        child
    }

    #[track_caller]
    fn verdict(mutate: impl FnOnce(&mut Header)) -> Result<(), BlockError> {
        let parent = prague_genesis();
        let mut child = valid_child(&parent);
        mutate(&mut child);
        validate_header(&child, &parent, Spec::Prague)
    }

    #[test]
    fn the_valid_child_passes_every_rule() {
        assert_eq!(verdict(|_| {}), Ok(()));
    }

    #[test]
    fn gas_used_above_the_limit_is_rejected_and_equal_is_not() {
        assert!(matches!(
            verdict(|h| h.gas_used = plus(h.gas_limit, 1)),
            Err(BlockError::GasUsedAboveLimit { .. })
        ));
        assert_eq!(verdict(|h| h.gas_used = h.gas_limit), Ok(()));
    }

    #[test]
    fn a_timestamp_not_after_the_parent_is_rejected() {
        assert!(matches!(
            verdict(|h| h.timestamp = 0),
            Err(BlockError::TimestampNotAfterParent { .. })
        ));
        assert_eq!(verdict(|h| h.timestamp = 1), Ok(()));
    }

    #[test]
    fn the_number_is_exactly_the_parent_plus_one() {
        for number in [0, 2, u64::MAX] {
            assert!(
                matches!(
                    verdict(|h| h.number = number),
                    Err(BlockError::NumberNotParentPlusOne { .. })
                ),
                "number {number}"
            );
        }
    }

    /// Un padre en `u64::MAX` no tiene hijo: el `+ 1` no puede envolver a cero.
    ///
    /// El veredicto no depende del orden de los chequeos: el control muestra
    /// que el MISMO hijo, sobre un padre un número antes, pasa todas las
    /// reglas, así que con el padre en `u64::MAX` la única que puede fallar es
    /// la del número, y se exige esa variante con sus valores.
    #[test]
    fn a_parent_at_the_last_number_has_no_child() {
        let mut parent = prague_genesis();
        parent.number = minus(u64::MAX, 1);
        let child = valid_child(&parent);
        assert_eq!(child.number, u64::MAX);
        assert_eq!(validate_header(&child, &parent, Spec::Prague), Ok(()));

        parent.number = u64::MAX;
        for number in [0, u64::MAX] {
            let mut orphan = child.clone();
            orphan.parent_hash = parent.hash();
            orphan.number = number;
            assert_eq!(
                validate_header(&orphan, &parent, Spec::Prague),
                Err(BlockError::NumberNotParentPlusOne {
                    number,
                    parent_number: u64::MAX,
                }),
                "number {number}"
            );
        }
    }

    #[test]
    fn extra_data_is_capped_at_32_bytes_inclusive() {
        assert_eq!(
            verdict(|h| h.extra_data = vec![0xee; MAX_EXTRA_DATA_BYTES].into()),
            Ok(())
        );
        assert!(matches!(
            verdict(|h| h.extra_data = vec![0xee; plus_usize(MAX_EXTRA_DATA_BYTES, 1)].into()),
            Err(BlockError::ExtraDataTooLong { .. })
        ));
    }

    #[test]
    fn the_post_merge_pow_fields_are_zero() {
        assert_eq!(
            verdict(|h| h.difficulty = alloy_primitives::U256::from(1)),
            Err(BlockError::NonZeroDifficulty)
        );
        assert_eq!(
            verdict(|h| h.nonce = B64::repeat_byte(1)),
            Err(BlockError::NonZeroNonce)
        );
        assert!(matches!(
            verdict(|h| h.ommers_hash = B256::ZERO),
            Err(BlockError::NonEmptyOmmersHash { .. })
        ));
        assert_eq!(check_ommers(0), Ok(()));
        assert_eq!(
            check_ommers(1),
            Err(BlockError::NonEmptyOmmers { count: 1 })
        );
    }

    /// La constante no se copia de memoria: es `keccak(rlp([]))`.
    #[test]
    fn the_empty_ommers_hash_is_the_keccak_of_the_empty_list() {
        assert_eq!(
            alloy_primitives::keccak256([alloy_rlp::EMPTY_LIST_CODE]),
            EMPTY_OMMERS_HASH
        );
    }

    #[test]
    fn the_parent_hash_is_the_hash_of_the_parent() {
        assert!(matches!(
            verdict(|h| h.parent_hash = B256::repeat_byte(9)),
            Err(BlockError::ParentHash { .. })
        ));
        // El hash del padre se computa: el que el hijo declara no entra.
        let parent = prague_genesis();
        let mut other_parent = parent.clone();
        other_parent.timestamp = 0;
        other_parent.extra_data = vec![0x01].into();
        let child = valid_child(&parent);
        assert!(matches!(
            validate_header(&child, &other_parent, Spec::Prague),
            Err(BlockError::ParentHash { .. })
        ));
    }

    /// La matriz de presencia por fork: cada campo del tail está desde su fork
    /// y no antes.
    #[test]
    fn every_fork_requires_exactly_its_fields() {
        let full = prague_genesis();
        assert_eq!(validate_fork_fields(&full, Spec::Prague), Ok(()));
        assert_eq!(validate_fork_fields(&full, Spec::Osaka), Ok(()));
        assert!(matches!(
            validate_fork_fields(&full, Spec::Cancun),
            Err(BlockError::UnexpectedField {
                field: HeaderField::RequestsHash,
                ..
            })
        ));

        let mut cancun = full.clone();
        cancun.requests_hash = None;
        assert_eq!(validate_fork_fields(&cancun, Spec::Cancun), Ok(()));
        assert!(matches!(
            validate_fork_fields(&cancun, Spec::Prague),
            Err(BlockError::MissingField {
                field: HeaderField::RequestsHash,
                ..
            })
        ));

        type Drop = fn(&mut Header);
        let cancun_fields: [(HeaderField, Drop); 3] = [
            (HeaderField::BlobGasUsed, |h| h.blob_gas_used = None),
            (HeaderField::ExcessBlobGas, |h| h.excess_blob_gas = None),
            (HeaderField::ParentBeaconBlockRoot, |h| {
                h.parent_beacon_block_root = None;
            }),
        ];
        for (field, drop) in cancun_fields {
            let mut missing = cancun.clone();
            drop(&mut missing);
            assert_eq!(
                validate_fork_fields(&missing, Spec::Cancun),
                Err(BlockError::MissingField {
                    field,
                    spec: Spec::Cancun
                })
            );
        }

        let mut shanghai = cancun.clone();
        shanghai.blob_gas_used = None;
        shanghai.excess_blob_gas = None;
        shanghai.parent_beacon_block_root = None;
        assert_eq!(validate_fork_fields(&shanghai, Spec::Shanghai), Ok(()));
        assert!(validate_fork_fields(&shanghai, Spec::Paris).is_err());

        let mut paris = shanghai.clone();
        paris.withdrawals_root = None;
        assert_eq!(validate_fork_fields(&paris, Spec::Paris), Ok(()));
        assert!(validate_fork_fields(&paris, Spec::Shanghai).is_err());

        let mut no_base_fee = paris.clone();
        no_base_fee.base_fee_per_gas = None;
        assert!(matches!(
            validate_fork_fields(&no_base_fee, Spec::Paris),
            Err(BlockError::MissingField {
                field: HeaderField::BaseFeePerGas,
                ..
            })
        ));

        // Un campo de un fork posterior sin los intermedios: el header de Paris
        // con `requestsHash` no se acepta en ningún fork.
        let mut gap = paris;
        gap.requests_hash = full.requests_hash;
        for spec in [Spec::Paris, Spec::Shanghai, Spec::Cancun, Spec::Prague] {
            assert!(validate_fork_fields(&gap, spec).is_err(), "{spec:?}");
        }
    }

    /// La regla de presencia corre primero en `validate_header`: un hijo
    /// válido al que le falta un campo de su fork no pasa.
    #[test]
    fn validate_header_enforces_the_fork_fields() {
        assert!(matches!(
            verdict(|h| h.requests_hash = None),
            Err(BlockError::MissingField { .. })
        ));
    }

    #[test]
    fn withdrawals_without_a_root_are_rejected() {
        let mut header = prague_genesis();
        header.withdrawals_root = None;
        let one = Withdrawal {
            index: 0,
            validator_index: 0,
            address: alloy_primitives::Address::ZERO,
            amount: 1,
        };
        assert_eq!(check_withdrawals_root(&header, &[]), Ok(()));
        assert_eq!(
            check_withdrawals_root(&header, &[one]),
            Err(BlockError::WithdrawalsWithoutRoot { count: 1 })
        );
    }

    /// El genesis del set con exactamente los campos del tail de `spec`.
    fn genesis_of(spec: Spec) -> Header {
        let mut header = prague_genesis();
        if !spec.is_enabled(Spec::Prague) {
            header.requests_hash = None;
        }
        if !spec.is_enabled(Spec::Cancun) {
            header.blob_gas_used = None;
            header.excess_blob_gas = None;
            header.parent_beacon_block_root = None;
        }
        if !spec.is_enabled(Spec::Shanghai) {
            header.withdrawals_root = None;
        }
        header
    }

    /// El primer bloque de Cancun sobre un padre Shanghai, válido.
    fn first_cancun_block() -> (Header, Header) {
        let parent = genesis_of(Spec::Shanghai);
        let mut child = valid_child(&parent);
        child.blob_gas_used = Some(0);
        child.excess_blob_gas = Some(0);
        child.parent_beacon_block_root = Some(B256::ZERO);
        (parent, child)
    }

    /// EIP-4844: en el primer bloque del fork, los campos de blob del padre se
    /// evalúan en cero. El bloque 19 426 587 de mainnet es este caso.
    #[test]
    fn the_first_cancun_block_reads_the_missing_parent_blob_fields_as_zero() {
        let (parent, child) = first_cancun_block();
        assert_eq!(validate_header(&child, &parent, Spec::Cancun), Ok(()));

        // El excedente se calcula desde cero, y cero es lo único que vale.
        let mut wrong = child;
        wrong.excess_blob_gas = Some(1);
        assert_eq!(
            validate_header(&wrong, &parent, Spec::Cancun),
            Err(BlockError::ExcessBlobGas {
                declared: 1,
                expected: 0,
                parent_excess: 0,
                parent_used: 0,
                target: repo_b_evm::blob::blob_params(Spec::Cancun).target_blob_gas(),
            })
        );
    }

    /// La regla de transición es del PRIMER fork con campos de blob: un hijo
    /// de Prague u Osaka sobre un padre sin ellos se reporta.
    #[test]
    fn only_the_first_blob_fork_reads_a_missing_parent_field_as_zero() {
        let (parent, mut child) = first_cancun_block();
        child.requests_hash = genesis_of(Spec::Prague).requests_hash;
        for spec in [Spec::Prague, Spec::Osaka] {
            assert_eq!(
                validate_header(&child, &parent, spec),
                Err(BlockError::ParentFieldMissing {
                    field: HeaderField::ExcessBlobGas
                }),
                "{spec:?}"
            );
        }
    }

    /// Y solo sobre un padre con la forma ENTERA de Shanghai: un padre Cancun
    /// al que le falta uno de los dos campos, o los dos pero que trae
    /// `parentBeaconBlockRoot`, no es un padre Shanghai.
    #[test]
    fn a_partial_cancun_parent_is_not_a_transition_parent() {
        let (_, child) = first_cancun_block();
        let cancun = genesis_of(Spec::Cancun);

        let mut no_used = cancun.clone();
        no_used.blob_gas_used = None;
        let mut no_excess = cancun.clone();
        no_excess.excess_blob_gas = None;
        let mut beacon_only = cancun;
        beacon_only.blob_gas_used = None;
        beacon_only.excess_blob_gas = None;

        let cases = [
            (no_used, HeaderField::BlobGasUsed),
            (no_excess, HeaderField::ExcessBlobGas),
            (beacon_only, HeaderField::ExcessBlobGas),
        ];
        for (parent, field) in cases {
            let mut orphan = child.clone();
            orphan.parent_hash = parent.hash();
            assert_eq!(
                validate_header(&orphan, &parent, Spec::Cancun),
                Err(BlockError::ParentFieldMissing { field }),
                "{}",
                field.name()
            );
        }
    }

    /// Un hijo válido y uno inválido por fork, los dos por `validate_header`
    /// completo. El inválido rompe la regla que distingue a ese fork.
    #[test]
    fn every_fork_in_scope_accepts_a_valid_child_and_rejects_an_invalid_one() {
        type Break = fn(&mut Header);
        type Verdict = fn(&BlockError) -> bool;
        let forks: [(Spec, Break, Verdict); 5] = [
            (
                Spec::Paris,
                |h| h.withdrawals_root = Some(B256::ZERO),
                |e| {
                    matches!(
                        e,
                        BlockError::UnexpectedField {
                            field: HeaderField::WithdrawalsRoot,
                            ..
                        }
                    )
                },
            ),
            (
                Spec::Shanghai,
                |h| h.withdrawals_root = None,
                |e| {
                    matches!(
                        e,
                        BlockError::MissingField {
                            field: HeaderField::WithdrawalsRoot,
                            ..
                        }
                    )
                },
            ),
            (
                Spec::Cancun,
                |h| h.excess_blob_gas = Some(1),
                |e| matches!(e, BlockError::ExcessBlobGas { .. }),
            ),
            (
                Spec::Prague,
                |h| h.requests_hash = None,
                |e| {
                    matches!(
                        e,
                        BlockError::MissingField {
                            field: HeaderField::RequestsHash,
                            ..
                        }
                    )
                },
            ),
            (
                Spec::Osaka,
                |h| h.base_fee_per_gas = Some(0),
                |e| matches!(e, BlockError::BaseFee { .. }),
            ),
        ];
        for (spec, breaks, expected) in forks {
            let parent = genesis_of(spec);
            let child = valid_child(&parent);
            assert_eq!(validate_header(&child, &parent, spec), Ok(()), "{spec:?}");
            let mut invalid = child;
            breaks(&mut invalid);
            match validate_header(&invalid, &parent, spec) {
                Err(e) => assert!(expected(&e), "{spec:?}: veredicto equivocado: {e}"),
                Ok(()) => panic!("{spec:?}: el hijo inválido pasó"),
            }
        }
    }

    /// El `nonce` es una cadena de 8 bytes: un 1 en cualquiera de las dos
    /// puntas lo hace distinto de cero.
    #[test]
    fn a_nonce_with_a_single_bit_at_either_end_is_rejected() {
        let first: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
        let last: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
        for nonce in [first, last] {
            assert_eq!(
                verdict(|h| h.nonce = B64::new(nonce)),
                Err(BlockError::NonZeroNonce),
                "{nonce:?}"
            );
        }
    }

    #[test]
    fn the_largest_difficulty_is_rejected() {
        assert_eq!(
            verdict(|h| h.difficulty = alloy_primitives::U256::MAX),
            Err(BlockError::NonZeroDifficulty)
        );
    }
}
