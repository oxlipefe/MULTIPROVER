//! Hosts de test compartidos entre integration tests (`tests/*.rs`).
//! Subdirectorio `tests/support/`: cargo NO trata sus archivos como sus
//! propios targets de test (a diferencia de un `tests/support.rs` suelto) —
//! es el patrón idiomático para compartir código entre integration tests.
//!
//! `NoopHost` vive acá (todos los tests que no tocan storage lo importan vía
//! `mod support;`). `MockHost` vive en `support/mock.rs`, incluido aparte
//! (`#[path = "support/mock.rs"] mod mock;`) SOLO por los tests que ejercitan
//! el seam `Host` de verdad — así `cargo test`/`clippy` no marcan `MockHost`
//! como dead-code en los binarios que nunca lo usan.

use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::receipt::Log;
use repo_b_interpreter::host::{AccountLoad, BlockEnv, TxEnv};
use repo_b_interpreter::{Host, SStoreResult, StateLoad};

/// Host que no hace nada: SLOAD/TLOAD devuelven cero siempre-frío, las
/// escrituras se descartan. Para tests que no ejercitan storage — evita que
/// cada test de la Fase 1/slice 2.1 tenga que armar un `MockHost`.
#[derive(Debug, Default)]
pub struct NoopHost;

impl Host for NoopHost {
    fn sload(&mut self, _addr: Address, _key: U256) -> StateLoad<U256> {
        StateLoad {
            data: U256::ZERO,
            is_cold: true,
        }
    }

    fn sstore(&mut self, _addr: Address, _key: U256, value: U256) -> StateLoad<SStoreResult> {
        StateLoad {
            data: SStoreResult {
                original: U256::ZERO,
                current: U256::ZERO,
                new: value,
            },
            is_cold: true,
        }
    }

    fn tload(&mut self, _addr: Address, _key: U256) -> U256 {
        U256::ZERO
    }

    fn tstore(&mut self, _addr: Address, _key: U256, _value: U256) {}

    fn refund(&mut self, _delta: i64) {}

    fn env(&self) -> &BlockEnv {
        const ENV: BlockEnv = BlockEnv {
            chain_id: 0,
            number: 0,
            coinbase: Address::ZERO,
            timestamp: 0,
            gas_limit: 0,
            base_fee: 0,
            prevrandao: B256::ZERO,
            blob_base_fee: 0,
        };
        &ENV
    }

    fn tx(&self) -> &TxEnv {
        // `TxEnv` no es const-promovible (`Vec` implementa `Drop`, a
        // diferencia de `BlockEnv`): `OnceLock` en vez de un `const` local.
        static TX: std::sync::OnceLock<TxEnv> = std::sync::OnceLock::new();
        TX.get_or_init(TxEnv::default)
    }

    fn self_balance(&mut self) -> U256 {
        U256::ZERO
    }

    fn block_hash(&mut self, _number: u64) -> B256 {
        B256::ZERO
    }

    fn log(&mut self, _log: Log) {}

    fn load_account(&mut self, _addr: Address) -> StateLoad<AccountLoad> {
        StateLoad {
            data: AccountLoad {
                balance: U256::ZERO,
                code_hash: KECCAK256_EMPTY,
                is_empty: true,
            },
            is_cold: true,
        }
    }

    fn code_by_address(&mut self, _addr: Address) -> StateLoad<Bytes> {
        StateLoad {
            data: Bytes::new(),
            is_cold: true,
        }
    }
}
