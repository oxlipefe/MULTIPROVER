//! Por qué un bloque no es válido — una variante por regla.
//!
//! Una variante por regla y no un mensaje suelto: el consumidor (el harness,
//! que agrupa fallas por clase; el guest, que solo sale con error) decide qué
//! hacer con cada una, y una regla nueva bajo la clave de otra quedaría tapada
//! por la vieja.

use core::fmt;

use alloy_primitives::B256;
use repo_b_common::spec::Spec;

/// Los campos del header que existen desde un fork en adelante. Los quince
/// primeros (Frontier) están en todo header y no tienen variante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderField {
    /// London, EIP-1559.
    BaseFeePerGas,
    /// Shanghai, EIP-4895.
    WithdrawalsRoot,
    /// Cancun, EIP-4844.
    BlobGasUsed,
    /// Cancun, EIP-4844.
    ExcessBlobGas,
    /// Cancun, EIP-4788.
    ParentBeaconBlockRoot,
    /// Prague, EIP-7685.
    RequestsHash,
}

impl HeaderField {
    /// El nombre del campo como lo publica el JSON-RPC (y el corpus de la EF).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BaseFeePerGas => "baseFeePerGas",
            Self::WithdrawalsRoot => "withdrawalsRoot",
            Self::BlobGasUsed => "blobGasUsed",
            Self::ExcessBlobGas => "excessBlobGas",
            Self::ParentBeaconBlockRoot => "parentBeaconBlockRoot",
            Self::RequestsHash => "requestsHash",
        }
    }
}

/// Un bloque inválido, o un bloque cuya validez no se puede decidir.
///
/// Las variantes `*Underivable` y [`BlockError::ParentFieldMissing`] no dicen
/// "el bloque es inválido" sino "con este padre la regla no se puede evaluar":
/// un padre ya validado nunca las produce. Que al padre le falte un campo no
/// alcanza para producirlas: el padre Shanghai del primer bloque de Cancun no
/// trae `excessBlobGas` ni `blobGasUsed`, y la regla los evalúa en cero
/// (EIP-4844). El consumidor decide si eso es un rechazo o un error propio; lo
/// que nunca es, es una aceptación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    /// El RLP del header no decodifica.
    HeaderRlp(alloy_rlp::Error),
    /// El RLP del header decodificó y sobran bytes detrás de él.
    HeaderTrailingBytes { trailing: usize },
    /// El RLP del bloque entero no decodifica (o no es canónico).
    BlockRlp(alloy_rlp::Error),
    /// El RLP del bloque es válido y el bloque tiene otra forma: ítems de
    /// más o de menos, una tx envuelta como no corresponde, la lista de
    /// withdrawals donde el fork no la tiene.
    BodyShape { reason: &'static str },
    /// El fork exige el campo y el header no lo trae.
    MissingField { field: HeaderField, spec: Spec },
    /// El header trae un campo que el fork todavía no tiene.
    UnexpectedField { field: HeaderField, spec: Spec },
    /// El padre no trae un campo que la regla del hijo necesita, fuera del
    /// único caso en que la ausencia ES la regla: los campos de blob del padre
    /// del primer bloque de Cancun.
    ParentFieldMissing { field: HeaderField },
    /// EIP-7934: el RLP del bloque excede el máximo (Osaka+).
    BlockRlpTooLarge { len: usize, max: usize },
    /// `gasLimit` por debajo del piso absoluto.
    GasLimitBelowMinimum { gas_limit: u64, minimum: u64 },
    /// `gasLimit` que se aparta del padre `parent/1024` o más.
    GasLimitOutOfBounds {
        gas_limit: u64,
        parent_gas_limit: u64,
        delta: u64,
        bound: u64,
    },
    /// EIP-1559: `baseFeePerGas` distinto del que exige la fórmula.
    BaseFee { declared: u64, expected: u64 },
    /// EIP-1559: con este padre la fórmula no se puede evaluar.
    BaseFeeUnderivable { parent_gas_limit: u64 },
    /// EIP-4844: `excessBlobGas` distinto del que exige la fórmula.
    ExcessBlobGas {
        declared: u64,
        expected: u64,
        parent_excess: u64,
        parent_used: u64,
        target: u64,
    },
    /// EIP-4844: con este padre la fórmula no se puede evaluar.
    ExcessBlobGasUnderivable,
    /// EIP-4844: `blobGasUsed` distinto de lo que suman las txs del bloque.
    BlobGasUsed { declared: u64, computed: u64 },
    /// EIP-4844: `blobGasUsed` por encima del tope del bloque.
    BlobGasAboveMax {
        declared: u64,
        max: u64,
        max_blobs: u64,
    },
    /// `gasUsed > gasLimit`.
    GasUsedAboveLimit { gas_used: u64, gas_limit: u64 },
    /// `timestamp <= parent.timestamp`.
    TimestampNotAfterParent {
        timestamp: u64,
        parent_timestamp: u64,
    },
    /// `number != parent.number + 1`.
    NumberNotParentPlusOne { number: u64, parent_number: u64 },
    /// `extraData` de más de 32 bytes.
    ExtraDataTooLong { len: usize, max: usize },
    /// Post-Merge: `difficulty != 0`.
    NonZeroDifficulty,
    /// Post-Merge: el `nonce` de PoW no es cero.
    NonZeroNonce,
    /// Post-Merge: `ommersHash` no es el de la lista vacía.
    NonEmptyOmmersHash { declared: B256 },
    /// Post-Merge: el cuerpo trae ommers.
    NonEmptyOmmers { count: usize },
    /// `parentHash` no es `keccak(rlp(padre))`.
    ParentHash { declared: B256, computed: B256 },
    /// `transactionsRoot` distinto del de las txs del cuerpo.
    TransactionsRoot { declared: B256, computed: B256 },
    /// `withdrawalsRoot` distinto del de las withdrawals del cuerpo.
    WithdrawalsRoot { declared: B256, computed: B256 },
    /// El cuerpo trae withdrawals y el header no tiene dónde comprometerlas.
    WithdrawalsWithoutRoot { count: usize },
    /// `stateRoot` distinto del post-state ejecutado.
    StateRoot { declared: B256, computed: B256 },
    /// `gasUsed` distinto del gas que consumió la ejecución.
    GasUsed { declared: u64, computed: u64 },
    /// El motor no devolvió un receipt por tx.
    ReceiptCount {
        transactions: usize,
        receipts: usize,
    },
    /// `receiptsRoot` distinto del de los receipts ejecutados.
    ReceiptsRoot { declared: B256, computed: B256 },
    /// El bloom del header no es el de los logs ejecutados. Sin los dos
    /// valores: 256 B cada uno inflarían todo `Result` de este crate.
    LogsBloom,
    /// EIP-7685: `requestsHash` distinto del de los requests del bloque.
    RequestsHash { declared: B256, computed: B256 },
    /// EIP-6110: un log del contrato de depósito con un layout que no es el
    /// canónico.
    DepositLayout { reason: &'static str },
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderRlp(e) => write!(f, "el RLP del header no decodifica: {e}"),
            Self::HeaderTrailingBytes { trailing } => {
                write!(f, "sobran {trailing} bytes detrás del RLP del header")
            }
            Self::BlockRlp(e) => write!(f, "el RLP del bloque no decodifica: {e}"),
            Self::BodyShape { reason } => write!(f, "forma del bloque: {reason}"),
            Self::MissingField { field, spec } => {
                write!(f, "header de {spec:?} sin `{}`", field.name())
            }
            Self::UnexpectedField { field, spec } => {
                write!(
                    f,
                    "header de {spec:?} con `{}`, que el fork no tiene",
                    field.name()
                )
            }
            Self::ParentFieldMissing { field } => {
                write!(f, "el padre no trae `{}`", field.name())
            }
            Self::BlockRlpTooLarge { len, max } => {
                write!(f, "RLP de {len} bytes excede el máximo de {max} (EIP-7934)")
            }
            Self::GasLimitBelowMinimum { gas_limit, minimum } => {
                write!(f, "gasLimit {gas_limit} por debajo del mínimo {minimum}")
            }
            Self::GasLimitOutOfBounds {
                gas_limit,
                parent_gas_limit,
                delta,
                bound,
            } => write!(
                f,
                "gasLimit {gas_limit} se aparta {delta} del padre {parent_gas_limit} (máximo < {bound})"
            ),
            Self::BaseFee { declared, expected } => write!(
                f,
                "baseFeePerGas declarado {declared}, la fórmula de EIP-1559 exige {expected}"
            ),
            Self::BaseFeeUnderivable { parent_gas_limit } => write!(
                f,
                "el padre declara gasLimit {parent_gas_limit}: el baseFeePerGas no se puede derivar"
            ),
            Self::ExcessBlobGas {
                declared,
                expected,
                parent_excess,
                parent_used,
                target,
            } => write!(
                f,
                "excessBlobGas declarado {declared}, la fórmula de EIP-4844 exige {expected} \
                 (padre: excess {parent_excess} + used {parent_used} − target {target})"
            ),
            Self::ExcessBlobGasUnderivable => {
                write!(f, "no se pudo calcular excessBlobGas con este padre")
            }
            Self::BlobGasUsed { declared, computed } => write!(
                f,
                "blobGasUsed declarado {declared}, las txs del bloque suman {computed}"
            ),
            Self::BlobGasAboveMax {
                declared,
                max,
                max_blobs,
            } => write!(
                f,
                "blobGasUsed {declared} por encima del máximo del bloque {max} ({max_blobs} blobs)"
            ),
            Self::GasUsedAboveLimit {
                gas_used,
                gas_limit,
            } => write!(f, "gasUsed {gas_used} por encima del gasLimit {gas_limit}"),
            Self::TimestampNotAfterParent {
                timestamp,
                parent_timestamp,
            } => write!(
                f,
                "timestamp {timestamp} no es posterior al del padre {parent_timestamp}"
            ),
            Self::NumberNotParentPlusOne {
                number,
                parent_number,
            } => write!(
                f,
                "number {number} no es el del padre ({parent_number}) + 1"
            ),
            Self::ExtraDataTooLong { len, max } => {
                write!(f, "extraData de {len} bytes (máximo {max})")
            }
            Self::NonZeroDifficulty => write!(f, "difficulty distinta de cero post-Merge"),
            Self::NonZeroNonce => write!(f, "nonce de PoW distinto de cero post-Merge"),
            Self::NonEmptyOmmersHash { declared } => write!(
                f,
                "ommersHash {declared} no es el de la lista vacía post-Merge"
            ),
            Self::NonEmptyOmmers { count } => {
                write!(f, "el cuerpo trae {count} ommers post-Merge")
            }
            Self::ParentHash { declared, computed } => write!(
                f,
                "parentHash declarado {declared}, `keccak(rlp(padre))` da {computed}"
            ),
            Self::TransactionsRoot { declared, computed } => write!(
                f,
                "transactionsRoot diverge: esperado {declared}, obtenido {computed}"
            ),
            Self::WithdrawalsRoot { declared, computed } => write!(
                f,
                "withdrawalsRoot diverge: esperado {declared}, obtenido {computed}"
            ),
            Self::WithdrawalsWithoutRoot { count } => write!(
                f,
                "el cuerpo trae {count} withdrawals y el header no tiene withdrawalsRoot"
            ),
            Self::StateRoot { declared, computed } => write!(
                f,
                "stateRoot diverge: esperado {declared}, obtenido {computed}"
            ),
            Self::GasUsed { declared, computed } => write!(
                f,
                "gasUsed diverge: esperado {declared}, obtenido {computed}"
            ),
            Self::ReceiptCount {
                transactions,
                receipts,
            } => write!(
                f,
                "{transactions} txs y {receipts} receipts: el motor no devolvió un receipt por tx"
            ),
            Self::ReceiptsRoot { declared, computed } => write!(
                f,
                "receiptsRoot diverge: esperado {declared}, obtenido {computed}"
            ),
            Self::LogsBloom => write!(f, "el bloom no coincide con el de los logs"),
            Self::RequestsHash { declared, computed } => write!(
                f,
                "requestsHash declarado {declared}, los requests del bloque dan {computed}"
            ),
            Self::DepositLayout { reason } => {
                write!(f, "layout del DepositEvent: {reason}")
            }
        }
    }
}
