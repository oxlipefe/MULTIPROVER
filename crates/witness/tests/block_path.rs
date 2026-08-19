//! El camino de BLOQUE, que el gate de fixtures no puede tocar.
//!
//! `--record-replay` corre `execute_tx`, donde el motor recibe el `&dyn State`
//! y lo usa tal cual. El lifecycle de bloque es otra cosa:
//! `begin_block` hace `BlockState::new(state.clone_state())`, o sea que **el
//! motor clona el `State` que le pasan**. Un recorder cuyo log viviera por
//! valor grabaría en la copia y devolvería un log vacío justo en el camino que
//! produce bloques — que es el que la statelessness necesita.
//!
//! Estos tests existen para que esa propiedad tenga una aserción propia, en vez
//! de depender de que alguien se acuerde.

use std::collections::BTreeMap;

use repo_b_common::primitives::{
    Address, B256, Bytes, EMPTY_ROOT_HASH, KECCAK256_EMPTY, U256, keccak256,
};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::OwnVm;
use repo_b_evm::error::StateError;
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, BlockEnv, CodeMetadata, Spec};
use repo_b_evm::vm::Vm;
use repo_b_witness::{RecordingState, StrictState};

const SENDER: Address = Address::new([0xAA; 20]);
const CONTRACT: Address = Address::new([0xBB; 20]);
const COINBASE: Address = Address::new([0xCC; 20]);
const BASE_FEE: u64 = 10;

/// `State` mínimo en memoria. Determinista y fail-closed, como el del resto de
/// los tests de integración del repo.
#[derive(Debug, Clone, Default)]
struct MemState {
    accounts: BTreeMap<Address, AccountInfo>,
    storage: BTreeMap<(Address, U256), U256>,
    code: BTreeMap<B256, Bytes>,
}

impl MemState {
    fn with_eoa(mut self, addr: Address, balance: u64) -> Self {
        self.accounts.insert(
            addr,
            AccountInfo {
                balance: U256::from(balance),
                nonce: 0,
                code_hash: KECCAK256_EMPTY,
            },
        );
        self
    }

    fn with_contract(mut self, addr: Address, code: &[u8]) -> Self {
        let bytes = Bytes::copy_from_slice(code);
        let hash = keccak256(&bytes);
        self.code.insert(hash, bytes);
        self.accounts.insert(
            addr,
            AccountInfo {
                balance: U256::ZERO,
                nonce: 1,
                code_hash: hash,
            },
        );
        self
    }

    fn with_slot(mut self, addr: Address, key: u64, value: u64) -> Self {
        self.storage
            .insert((addr, U256::from(key)), U256::from(value));
        self
    }
}

impl State for MemState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        Ok(self.accounts.get(&addr).cloned())
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        Ok(self
            .storage
            .get(&(addr, key))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn storage_root(&self, addr: Address) -> Result<B256, StateError> {
        let has_storage = self.storage.keys().any(|(a, _)| *a == addr);
        Ok(if has_storage {
            B256::new([0x5D; 32])
        } else {
            EMPTY_ROOT_HASH
        })
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        if code_hash == KECCAK256_EMPTY {
            return Ok(Bytes::new());
        }
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| StateError::Database(format!("código desconocido: {code_hash}")))
    }

    fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
        Ok(CodeMetadata::Regular)
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        Ok(B256::with_last_byte(
            u8::try_from(number % 256).unwrap_or(0),
        ))
    }
}

fn env() -> BlockEnv {
    BlockEnv {
        spec: Spec::Prague,
        chain_id: 1,
        number: 1,
        coinbase: COINBASE,
        timestamp: 1000,
        gas_limit: 30_000_000,
        base_fee: BASE_FEE,
        prevrandao: B256::ZERO,
        blob_excess_gas: Some(0),
        blob_base_fee: Some(1),
        blob_base_fee_update_fraction: None,
    }
}

fn tx(nonce: u64) -> Transaction {
    Transaction {
        tx_type: TxType::Legacy,
        sender: SENDER,
        nonce,
        to: Some(CONTRACT),
        value: U256::ZERO,
        input: Bytes::new(),
        gas_limit: 200_000,
        gas_price: Some(u128::from(BASE_FEE)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    }
}

/// Los tests del repo no usan `expect`: el lint del workspace lo trata como
/// error. Un helper con `panic!` dice lo mismo y además imprime el error.
#[track_caller]
fn must<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what} falló: {err:?}"),
    }
}

#[track_caller]
fn must_fail<T: std::fmt::Debug, E>(result: Result<T, E>, what: &str) -> E {
    match result {
        Ok(value) => panic!("{what} tenía que fallar, dio: {value:?}"),
        Err(err) => err,
    }
}

/// `SLOAD(1)` y `SSTORE(2, …)`: obliga al motor a leer del `State` de abajo.
const READS_STORAGE: &[u8] = &[
    0x60, 0x01, 0x54, // PUSH1 1 SLOAD
    0x60, 0x02, 0x55, // PUSH1 2 SSTORE (guarda lo leído)
    0x00, // STOP
];

fn base() -> MemState {
    MemState::default()
        .with_eoa(SENDER, 10_000_000_000)
        .with_contract(CONTRACT, READS_STORAGE)
        .with_slot(CONTRACT, 1, 42)
}

/// **La trampa del clon.** El motor clona el `State` al abrir el bloque; si el
/// log no se compartiera, esto saldría vacío y el witness de todo bloque sería
/// vacío.
#[test]
fn the_log_survives_the_clone_the_engine_makes_when_it_opens_a_block() {
    let recorder = RecordingState::new(Box::new(base()));
    let mut vm = OwnVm::new();
    must(vm.begin_block(&env(), &recorder), "begin_block");
    must(vm.transact_in_block(&tx(0), SENDER), "tx");
    must(vm.finish_block(), "finish_block");

    let log = recorder.log();
    assert!(
        !log.is_empty(),
        "el bloque no grabó nada: el motor clonó el recorder y el log se perdió"
    );
    assert!(
        log.storage.contains_key(&(CONTRACT, U256::from(1))),
        "el SLOAD del contrato no quedó grabado: {log:?}"
    );
    assert!(
        log.accounts.contains_key(&SENDER),
        "la cuenta del sender no quedó grabada: {log:?}"
    );
}

/// Y lo grabado alcanza para volver a producir el MISMO bloque sin el estado
/// completo: es el DoD de la fase, en chico y por el camino de bloque.
#[test]
fn a_block_replays_from_the_log_alone_and_produces_the_same_changes() {
    let recorder = RecordingState::new(Box::new(base()));
    let mut vm = OwnVm::new();
    must(vm.begin_block(&env(), &recorder), "begin_block");
    must(vm.transact_in_block(&tx(0), SENDER), "tx");
    let full = must(vm.finish_block(), "finish_block");

    let witness = StrictState::new(recorder.log());
    let mut vm = OwnVm::new();
    must(vm.begin_block(&env(), &witness), "begin_block");
    must(vm.transact_in_block(&tx(0), SENDER), "tx en replay");
    let replayed = must(vm.finish_block(), "finish_block");

    assert_eq!(
        full, replayed,
        "el bloque no se reproduce desde el log solo"
    );
}

/// Dos txs en el mismo bloque: la segunda lee lo que la primera escribió, que
/// el overlay contesta sin bajar al `State`. El log tiene que traer lo que el
/// overlay **no** puede contestar, y nada más.
#[test]
fn a_two_tx_block_replays_from_the_log_alone() {
    let recorder = RecordingState::new(Box::new(base()));
    let mut vm = OwnVm::new();
    must(vm.begin_block(&env(), &recorder), "begin_block");
    must(vm.transact_in_block(&tx(0), SENDER), "tx 0");
    must(vm.transact_in_block(&tx(1), SENDER), "tx 1");
    let full = must(vm.finish_block(), "finish_block");

    let witness = StrictState::new(recorder.log());
    let mut vm = OwnVm::new();
    must(vm.begin_block(&env(), &witness), "begin_block");
    must(vm.transact_in_block(&tx(0), SENDER), "tx 0 en replay");
    must(vm.transact_in_block(&tx(1), SENDER), "tx 1 en replay");
    let replayed = must(vm.finish_block(), "finish_block");

    assert_eq!(full, replayed, "el bloque de dos txs no se reproduce");
}

/// Fail-closed: lo que no está grabado es un error, nunca un cero.
#[test]
fn the_strict_state_refuses_what_it_did_not_record() {
    let witness = StrictState::new(repo_b_witness::AccessLog::default());
    let err = must_fail(witness.account(SENDER), "una cuenta no grabada");
    assert!(
        format!("{err:?}").contains("no grabado"),
        "el error tiene que decir qué faltó: {err:?}"
    );
    assert!(witness.storage(CONTRACT, U256::from(1)).is_err());
    assert!(witness.block_hash(1).is_err());
}
