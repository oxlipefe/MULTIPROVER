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
//!
//! `dead_code` allowed por lo mismo: `logs_env`/`extcode` importan este módulo
//! por `run_frame` y nunca instancian `NoopHost`.
#![allow(dead_code)]

use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::receipt::Log;
use repo_b_interpreter::host::{AccountLoad, BlockEnv, TxEnv};
use repo_b_interpreter::{
    Host, Interpreter, InterpreterAction, InterpreterOutcome, SStoreResult, SelfDestructResult,
    StateLoad,
};

/// Corre UN frame hasta terminar. Desde el `run` puede suspender el
/// frame para abrir una sub-call; estos tests no tienen executor detrás, así
/// que una `Call` acá es un bug del test, no un resultado válido — se rompe
/// ruidosamente en vez de inventar un outcome.
#[track_caller]
pub fn run_frame(mut interpreter: Interpreter, host: &mut dyn Host) -> InterpreterOutcome {
    match interpreter.run(host) {
        InterpreterAction::Return(outcome) => outcome,
        InterpreterAction::Call(inputs) => {
            panic!("este test no espera sub-calls, pero el frame abrió {inputs:?}")
        }
        InterpreterAction::Create(inputs) => {
            panic!("este test no espera creaciones, pero el frame abrió {inputs:?}")
        }
    }
}

/// Host que no hace nada: SLOAD/TLOAD devuelven cero siempre-frío, las
/// escrituras se descartan. Para tests que no ejercitan storage — evita que
/// cada test de la Fase 1/ tenga que armar un `MockHost`.
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

    /// Sin cuentas que modelar: beneficiary frío e inexistente, cuenta sin
    /// balance. La semántica de EIP-6780 se prueba contra el `Journal` real.
    fn selfdestruct(
        &mut self,
        _addr: Address,
        _beneficiary: Address,
    ) -> StateLoad<SelfDestructResult> {
        StateLoad {
            data: SelfDestructResult {
                had_value: false,
                target_exists: false,
                previously_destroyed: false,
            },
            is_cold: true,
        }
    }

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

    fn self_balance(&mut self, _addr: Address) -> U256 {
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

    /// Sin cuentas que modelar: nada está delegado (EIP-7702). La resolución
    /// real se prueba contra el `Journal` y el set diferencial.
    fn load_delegated_account(&mut self, _addr: Address) -> Option<StateLoad<Address>> {
        None
    }
}
