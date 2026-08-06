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

use repo_b_common::primitives::{Address, U256};
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
}
