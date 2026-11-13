//! `trace_tx` (feature `tracer`) es fail-closed igual que `execute_tx`.
//!
//! El journal convierte una lectura fallida del `State` en un valor por default
//! y la guarda como error pendiente: la ejecución sigue, y el que la drena
//! decide. Una traza que no lo drena reporta como éxito una ejecución que leyó
//! ceros en lugar del estado real. Sin la feature este archivo desaparece.

#![cfg(feature = "tracer")]

mod support;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::error::{InternalError, VmError};
use repo_b_evm::execution::trace_tx;
use repo_b_evm::types::Spec;
use repo_b_interpreter::tracer::{StepRecord, StepSink};

use support::{BASE_FEE, CONTRACT, MemState, SENDER, env};

/// La cuenta cuya lectura falla (nodo ausente en el witness).
const UNREADABLE: Address = Address::new([0x77; 20]);
const GAS_LIMIT: u64 = 100_000;
const SENDER_BALANCE: u64 = 100_000_000;

const PUSH20: u8 = 0x73;
const BALANCE: u8 = 0x31;
const STOP: u8 = 0x00;

/// `BALANCE(UNREADABLE); STOP`: una sola lectura de cuenta, y el programa
/// termina bien aunque esa lectura haya fallado.
fn reads_unreadable_balance() -> Vec<u8> {
    let mut code = vec![PUSH20];
    code.extend_from_slice(UNREADABLE.as_slice());
    code.extend_from_slice(&[BALANCE, STOP]);
    code
}

fn tx() -> Transaction {
    Transaction {
        tx_type: TxType::Legacy,
        sender: SENDER,
        nonce: 0,
        to: Some(CONTRACT),
        value: U256::ZERO,
        input: Bytes::new(),
        gas_limit: GAS_LIMIT,
        gas_price: Some(u128::from(BASE_FEE)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: Vec::new(),
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: Vec::new(),
        authorization_list: Vec::new(),
    }
}

#[derive(Default)]
struct CountingSink {
    steps: usize,
}

impl StepSink for CountingSink {
    fn step(&mut self, _record: &StepRecord) {
        self.steps = self.steps.saturating_add(1);
    }
}

fn state() -> MemState {
    MemState::new()
        .with_eoa(SENDER, SENDER_BALANCE, 0)
        .with_contract(CONTRACT, &reads_unreadable_balance(), 0)
}

/// Control: con la cuenta legible, la misma tx se traza entera y termina bien.
/// Sin esto, el test de abajo podría pasar porque la tx no se traza por otra
/// razón.
#[test]
fn the_same_tx_traces_when_the_account_is_readable() {
    let mut sink = CountingSink::default();
    let traced = trace_tx(&tx(), &env(Spec::Prague), &state(), &mut sink);
    assert!(
        matches!(traced, Ok(Some(_))),
        "esperado una traza, obtenido {traced:?}"
    );
    assert_eq!(sink.steps, 3, "PUSH20, BALANCE y STOP");
}

#[test]
fn a_trace_whose_state_read_fails_is_an_error() {
    let state = state().failing_account_on(UNREADABLE);
    let mut sink = CountingSink::default();
    let traced = trace_tx(&tx(), &env(Spec::Prague), &state, &mut sink);
    match traced {
        Err(VmError::Internal(InternalError::StateAccess(_))) => {}
        otro => panic!("esperado un error de acceso al estado, obtenido {otro:?}"),
    }
    assert!(
        sink.steps >= 2,
        "la lectura fallida ocurre DENTRO de la ejecución trazada (pasos: {})",
        sink.steps
    );
}
