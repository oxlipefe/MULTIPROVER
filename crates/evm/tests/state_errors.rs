//! **Un error del `State` gana sobre cualquier otro resultado.**
//!
//! El journal no puede devolver `Result` desde el `Host` (el intérprete no
//! maneja IO): registra el primer error de lectura y responde con una cuenta
//! vacía o bytes vacíos. Eso es seguro solo si TODO camino de salida mira ese
//! registro antes de devolver nada. Si alguno no lo mira, un witness
//! incompleto se lee como una cuenta vacía y el motor contesta otra cosa: un
//! rechazo de consenso (un balance "insuficiente") o, peor, un resultado sobre
//! datos que no existen.
//!
//! El `State` de estos tests falla en la N-ésima lectura (cualquier método) y
//! se barre N sobre todas las lecturas que el escenario hace. Dos modos:
//!
//! - **una sola vez**: la lectura N falla y las demás contestan. Es el caso
//!   hostil: una dirección que se leyó bien en la validación y mal después.
//! - **desde N**: toda lectura a partir de la N falla.
//!
//! Para todo N alcanzado, el único resultado aceptable es
//! `InternalError::StateAccess`. Para el N siguiente al último, el resultado
//! tiene que ser idéntico al de un estado que nunca falla.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use repo_b_common::authorization::Authorization;
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::withdrawal::Withdrawal;
use repo_b_evm::error::{InternalError, StateError, VmError};
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, CodeMetadata, Spec};
use repo_b_evm::{BEACON_ROOTS_ADDRESS, OwnVm, Vm};

use support::{BASE_FEE, CONTRACT, MemState, SENDER, env};

const OTHER: Address = Address::new([0xDD; 20]);
const AUTHORITY: Address = Address::new([0xA7; 20]);
const RECEIVER: Address = Address::new([0x5E; 20]);
const SENDER_BALANCE: u64 = 1_000_000_000_000;
const GAS_LIMIT: u64 = 1_000_000;

/// Cuándo falla el `State`.
#[derive(Debug, Clone, Copy)]
enum Fault {
    /// Solo la lectura número N (desde 1).
    Once(u64),
    /// Toda lectura a partir de la N.
    From(u64),
    Never,
}

/// Un `MemState` que cuenta sus lecturas y falla según `Fault`. El contador
/// es compartido: `begin_block` clona el `State`, y las lecturas de la copia
/// cuentan igual.
#[derive(Debug, Clone)]
struct FaultyState {
    inner: MemState,
    reads: Arc<AtomicU64>,
    fault: Fault,
}

impl FaultyState {
    fn new(inner: MemState, fault: Fault) -> Self {
        Self {
            inner,
            reads: Arc::new(AtomicU64::new(0)),
            fault,
        }
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::SeqCst)
    }

    fn read(&self) -> Result<(), StateError> {
        let n = self.reads.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let fails = match self.fault {
            Fault::Once(at) => n == at,
            Fault::From(at) => n >= at,
            Fault::Never => false,
        };
        if fails {
            return Err(StateError::Database(format!("lectura {n} indisponible")));
        }
        Ok(())
    }
}

impl State for FaultyState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        self.read()?;
        self.inner.account(addr)
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        self.read()?;
        self.inner.storage(addr, key)
    }

    fn storage_root(&self, addr: Address) -> Result<B256, StateError> {
        self.read()?;
        self.inner.storage_root(addr)
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        self.read()?;
        self.inner.code(code_hash)
    }

    fn code_metadata(&self, code_hash: B256) -> Result<CodeMetadata, StateError> {
        self.read()?;
        self.inner.code_metadata(code_hash)
    }

    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        self.read()?;
        self.inner.block_hash(number)
    }
}

// Opcodes.
const BALANCE: u8 = 0x31;
const POP: u8 = 0x50;
const SLOAD: u8 = 0x54;
const SSTORE: u8 = 0x55;
const PUSH1: u8 = 0x60;
const PUSH20: u8 = 0x73;
const CALL: u8 = 0xF1;
const EXTCODESIZE: u8 = 0x3B;
const STOP: u8 = 0x00;

fn push20(code: &mut Vec<u8>, addr: Address) {
    code.push(PUSH20);
    code.extend_from_slice(addr.as_slice());
}

/// Lee storage, el balance y el código de otra cuenta, escribe un slot y
/// llama a otra cuenta con valor: toca todos los métodos del `State` que una
/// tx alcanza.
fn busy_code() -> Vec<u8> {
    let mut code = vec![PUSH1, 0x01, SLOAD, POP];
    push20(&mut code, OTHER);
    code.extend([BALANCE, POP]);
    push20(&mut code, OTHER);
    code.extend([EXTCODESIZE, POP]);
    code.extend([PUSH1, 0x07, PUSH1, 0x02, SSTORE]);
    // CALL(gas, OTHER, 1, 0, 0, 0, 0)
    code.extend([
        PUSH1, 0x00, PUSH1, 0x00, PUSH1, 0x00, PUSH1, 0x00, PUSH1, 0x01,
    ]);
    push20(&mut code, OTHER);
    code.extend([PUSH1, 0xFF, CALL, POP, STOP]);
    code
}

fn world() -> MemState {
    MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &busy_code(), 10)
        .with_contract(OTHER, &[STOP], 3)
        .with_slot(CONTRACT, 1, 42)
        .with_eoa(AUTHORITY, 0, 0)
        .with_contract(
            BEACON_ROOTS_ADDRESS,
            &[PUSH1, 0x01, PUSH1, 0x00, SSTORE, STOP],
            0,
        )
}

fn tx(to: Option<Address>, value: u64) -> Transaction {
    Transaction {
        tx_type: TxType::Eip1559,
        sender: SENDER,
        nonce: 0,
        to,
        value: U256::from(value),
        input: Bytes::new(),
        gas_limit: GAS_LIMIT,
        gas_price: None,
        max_fee_per_gas: Some(u128::from(BASE_FEE) * 2),
        max_priority_fee_per_gas: Some(1),
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    }
}

/// Una tx tipo 4 que delega `AUTHORITY` en `CONTRACT` y la llama: el frame
/// raíz ejecuta el código delegado.
fn delegating_tx() -> Transaction {
    Transaction {
        tx_type: TxType::Eip7702,
        authorization_list: vec![Authorization {
            chain_id: U256::from(1u64),
            address: CONTRACT,
            nonce: 0,
            authority: Some(AUTHORITY),
        }],
        ..tx(Some(AUTHORITY), 0)
    }
}

/// Una tx de creación cuyo initcode escribe un slot.
fn create_tx() -> Transaction {
    Transaction {
        input: Bytes::from(vec![PUSH1, 0x01, PUSH1, 0x00, SSTORE, STOP]),
        ..tx(None, 5)
    }
}

type Scenario = fn(&dyn State) -> Result<String, VmError>;

fn single_tx(state: &dyn State, tx: &Transaction) -> Result<String, VmError> {
    let mut vm = OwnVm::new();
    vm.execute_tx(tx, &env(Spec::Prague), state)
        .map(|outcome| format!("{:?} {:?}", outcome.result, outcome.state_changes))
}

fn transfer(state: &dyn State) -> Result<String, VmError> {
    single_tx(state, &tx(Some(RECEIVER), 7))
}

fn contract_call(state: &dyn State) -> Result<String, VmError> {
    single_tx(state, &tx(Some(CONTRACT), 9))
}

fn delegation(state: &dyn State) -> Result<String, VmError> {
    single_tx(state, &delegating_tx())
}

fn creation(state: &dyn State) -> Result<String, VmError> {
    single_tx(state, &create_tx())
}

/// El lifecycle entero: withdrawals, una system call, dos txs y el cierre.
fn block(state: &dyn State) -> Result<String, VmError> {
    let mut vm = OwnVm::new();
    let withdrawals = vec![Withdrawal {
        index: 0,
        validator_index: 0,
        address: OTHER,
        amount: 1,
    }];
    vm.begin_block_with_withdrawals(&env(Spec::Prague), state, withdrawals)?;
    let system = vm.system_call_in_block(BEACON_ROOTS_ADDRESS, Bytes::from(vec![0u8; 32]))?;
    let first = vm.transact_in_block(&tx(Some(CONTRACT), 1), SENDER)?;
    let second = vm.transact_in_block(
        &Transaction {
            nonce: 1,
            ..tx(Some(RECEIVER), 2)
        },
        SENDER,
    )?;
    vm.settle_withdrawals_in_block()?;
    let has_code = vm.has_code_in_block(BEACON_ROOTS_ADDRESS)?;
    let changes = vm.finish_block()?;
    Ok(format!(
        "{:?} {:?} {:?} {has_code} {changes:?}",
        system.result, first.result, second.result
    ))
}

const SCENARIOS: &[(&str, Scenario)] = &[
    ("transferencia", transfer),
    ("llamada a contrato", contract_call),
    ("delegación 7702", delegation),
    ("creación", creation),
    ("bloque", block),
];

fn is_state_access(result: &Result<String, VmError>) -> bool {
    matches!(
        result,
        Err(VmError::Internal(InternalError::StateAccess(_)))
    )
}

/// Barre N sobre cada lectura del escenario, en los dos modos, y junta los
/// N cuyo resultado no es un error de acceso a estado.
fn sweep(name: &str, scenario: Scenario) -> Vec<String> {
    let clean = FaultyState::new(world(), Fault::Never);
    let expected = scenario(&clean);
    assert!(
        expected.is_ok(),
        "{name}: el escenario limpio falla: {expected:?}"
    );
    let total = clean.reads();
    assert!(total > 0, "{name}: el escenario no lee el estado");

    let mut wrong = Vec::new();
    for n in 1..=total {
        for fault in [Fault::Once(n), Fault::From(n)] {
            let state = FaultyState::new(world(), fault);
            let result = scenario(&state);
            if !is_state_access(&result) {
                wrong.push(format!("{name} {fault:?} de {total}: {result:?}"));
            }
        }
    }
    // Una lectura más allá de la última no se alcanza: el resultado es el del
    // estado que nunca falla.
    let past = FaultyState::new(world(), Fault::Once(total.saturating_add(1)));
    assert_eq!(
        scenario(&past).ok(),
        expected.ok(),
        "{name}: más allá del final"
    );
    wrong
}

#[test]
fn a_state_error_wins_over_every_other_result_at_every_read() {
    let wrong: Vec<String> = SCENARIOS
        .iter()
        .flat_map(|(name, scenario)| sweep(name, *scenario))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} lecturas fallidas no salieron como error de estado:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// El barrido no es vacuo: cada escenario lee el estado varias veces.
#[test]
fn every_scenario_reads_the_state_more_than_once() {
    for (name, scenario) in SCENARIOS {
        let clean = FaultyState::new(world(), Fault::Never);
        assert!(scenario(&clean).is_ok(), "{name}");
        assert!(clean.reads() > 3, "{name}: {} lecturas", clean.reads());
    }
}
