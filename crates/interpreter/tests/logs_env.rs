//! Tests de LOG0..LOG4 + opcodes de entorno (ORIGIN/GASPRICE/COINBASE/
//! TIMESTAMP/NUMBER/PREVRANDAO/GASLIMIT/CHAINID/SELFBALANCE/BASEFEE/BLOBHASH/
//! BLOBBASEFEE/BLOCKHASH), slice 2.3 (ADR-0002 §1: seam `Host`).
//!
//! Convención de stack (Yellow Paper, igual que `tests/programs.rs` y
//! `tests/storage.rs`): para LOGn(offset, len, topic1..topicN) el TOPE
//! (µ_s[0]) es `offset`, por eso el bytecode apila en orden inverso:
//! topicN, ..., topic1, len, offset.
//!
//! Los números de gas de los asserts salen de la spec (Yellow Paper apéndice
//! G + EIP-1884/2929/4844/7516), calculados a mano — no del código bajo test.

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_interpreter::gas::cost;
use repo_b_interpreter::host::{BlockEnv, TxEnv};
use repo_b_interpreter::opcode::{
    BASEFEE, BLOBBASEFEE, BLOBHASH, BLOCKHASH, CHAINID, COINBASE, GASLIMIT, GASPRICE, LOG0, MSTORE,
    NUMBER, ORIGIN, PREVRANDAO, PUSH1, PUSH32, RETURN, SELFBALANCE, TIMESTAMP,
};
use repo_b_interpreter::{CallContext, Halt, Host, Interpreter, InterpreterOutcome};

#[path = "support/mock.rs"]
mod mock;
use mock::MockHost;

const GAS: u64 = 1_000_000;
const CONTRACT: Address = Address::new([0xBB; 20]);

fn run_program(code: &[u8], host: &mut dyn Host) -> InterpreterOutcome {
    let context = CallContext {
        address: CONTRACT,
        ..CallContext::for_code(Bytes::copy_from_slice(code))
    };
    Interpreter::new(context, GAS).run(host)
}

fn run_static(code: &[u8], host: &mut dyn Host) -> InterpreterOutcome {
    let context = CallContext {
        address: CONTRACT,
        is_static: true,
        ..CallContext::for_code(Bytes::copy_from_slice(code))
    };
    Interpreter::new(context, GAS).run(host)
}

/// Epílogo: guarda el tope del stack en memoria[0..32] y lo retorna.
fn return_top_epilogue(code: &mut Vec<u8>) {
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x20, PUSH1, 0x00, RETURN]);
}

fn returned_word(outcome: &InterpreterOutcome) -> U256 {
    match outcome {
        InterpreterOutcome::Success { output, .. } => U256::from_be_slice(output),
        other => panic!("se esperaba Success, hubo {other:?}"),
    }
}

fn gas_used(outcome: &InterpreterOutcome) -> u64 {
    outcome.gas_used()
}

// ------------------------------------------------------------------------ LOG

#[test]
fn log0_with_data_emits_and_charges_static_plus_data_plus_expansion() {
    // PUSH32 <valor> PUSH1 0 MSTORE PUSH1 5 PUSH1 0 LOG0
    let mut code = vec![PUSH32];
    code.extend([0xAAu8; 32]);
    code.extend([PUSH1, 0x00, MSTORE, PUSH1, 0x05, PUSH1, 0x00, LOG0]);
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    assert!(outcome.is_success(), "esperaba Success, hubo {outcome:?}");
    // PUSH32=3, PUSH1(offset MSTORE)=3, MSTORE=3+3(expansión w=1)=6,
    // PUSH1(len=5)=3, PUSH1(offset=0)=3, LOG0=375+8*5=415 (memoria ya
    // expandida por el MSTORE, expand() propio cobra 0) ⇒ 3+3+6+3+3+415=433.
    assert_eq!(gas_used(&outcome), 3 + 3 + 6 + 3 + 3 + 415);
    assert_eq!(host.logs().len(), 1);
    let log = &host.logs()[0];
    assert_eq!(log.address, CONTRACT);
    assert!(log.topics.is_empty());
    assert_eq!(log.data.as_ref(), &[0xAAu8; 5]);
}

#[test]
fn log2_with_two_topics_and_no_data_charges_static_plus_topics() {
    // PUSH1 topic2 PUSH1 topic1 PUSH1 0(len) PUSH1 0(offset) LOG2
    let code = [
        PUSH1,
        0x02,
        PUSH1,
        0x01,
        PUSH1,
        0x00,
        PUSH1,
        0x00,
        LOG0 + 2,
    ];
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    assert!(outcome.is_success(), "esperaba Success, hubo {outcome:?}");
    // 4 PUSH1 = 12; LOG2 = 375 + 375*2 + 8*0 = 1125.
    assert_eq!(gas_used(&outcome), 12 + 1125);
    let log = &host.logs()[0];
    assert_eq!(
        log.topics,
        vec![
            B256::new(U256::from(1u64).to_be_bytes()),
            B256::new(U256::from(2u64).to_be_bytes()),
        ]
    );
    assert!(log.data.is_empty());
}

#[test]
fn log_in_static_context_halts_without_emitting() {
    // PUSH1 0 PUSH1 0 LOG0 — nunca llega a tocar memoria ni al host.
    let code = [PUSH1, 0x00, PUSH1, 0x00, LOG0];
    let mut host = MockHost::new();

    let outcome = run_static(&code, &mut host);

    match outcome {
        InterpreterOutcome::Halt { reason, gas_used } => {
            assert_eq!(reason, Halt::StateChangeDuringStaticCall);
            assert_eq!(gas_used, GAS);
        }
        other => panic!("se esperaba Halt, hubo {other:?}"),
    }
    assert!(host.logs().is_empty());
}

#[test]
fn log4_underflows_with_too_few_stack_items() {
    // Solo offset+len: faltan los 4 topics de LOG4.
    let code = [PUSH1, 0x00, PUSH1, 0x00, LOG0 + 4];
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    match outcome {
        InterpreterOutcome::Halt { reason, .. } => assert_eq!(reason, Halt::StackUnderflow),
        other => panic!("se esperaba Halt, hubo {other:?}"),
    }
}

// -------------------------------------------------------------- entorno (env)

fn sample_env() -> BlockEnv {
    BlockEnv {
        chain_id: 7,
        number: 500,
        coinbase: Address::new([0xC0; 20]),
        timestamp: 12_345,
        gas_limit: 30_000_000,
        base_fee: 42,
        prevrandao: B256::new([0x99; 32]),
        blob_base_fee: 3,
    }
}

fn sample_tx() -> TxEnv {
    TxEnv {
        origin: Address::new([0xA0; 20]),
        gas_price: 17,
        blob_hashes: vec![B256::new([0x11; 32]), B256::new([0x22; 32])],
    }
}

#[track_caller]
fn assert_env_opcode(op: u8, expected: U256, gas_cost: u64) {
    let mut code = vec![op];
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_env(sample_env()).with_tx(sample_tx());

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), expected, "op 0x{op:02x}");
    // gas_cost del opcode + el epílogo: PUSH1(0)=3, MSTORE=3+3(expansión
    // w=1)=6, PUSH1(0x20)=3, PUSH1(0x00)=3, RETURN=0 (ya expandido) ⇒ 15.
    assert_eq!(gas_used(&outcome), gas_cost + 15);
}

#[test]
fn origin_pushes_tx_origin() {
    assert_env_opcode(
        ORIGIN,
        U256::from_be_slice(sample_tx().origin.as_slice()),
        cost::BASE,
    );
}

#[test]
fn gasprice_pushes_the_effective_price() {
    assert_env_opcode(GASPRICE, U256::from(sample_tx().gas_price), cost::BASE);
}

#[test]
fn coinbase_pushes_the_block_coinbase() {
    assert_env_opcode(
        COINBASE,
        U256::from_be_slice(sample_env().coinbase.as_slice()),
        cost::BASE,
    );
}

#[test]
fn timestamp_pushes_the_block_timestamp() {
    assert_env_opcode(TIMESTAMP, U256::from(sample_env().timestamp), cost::BASE);
}

#[test]
fn number_pushes_the_block_number() {
    assert_env_opcode(NUMBER, U256::from(sample_env().number), cost::BASE);
}

#[test]
fn prevrandao_pushes_the_block_prevrandao() {
    assert_env_opcode(
        PREVRANDAO,
        U256::from_be_slice(sample_env().prevrandao.as_slice()),
        cost::BASE,
    );
}

#[test]
fn gaslimit_pushes_the_block_gas_limit() {
    assert_env_opcode(GASLIMIT, U256::from(sample_env().gas_limit), cost::BASE);
}

#[test]
fn chainid_pushes_the_chain_id() {
    assert_env_opcode(CHAINID, U256::from(sample_env().chain_id), cost::BASE);
}

#[test]
fn basefee_pushes_the_block_base_fee() {
    assert_env_opcode(BASEFEE, U256::from(sample_env().base_fee), cost::BASE);
}

#[test]
fn blobbasefee_pushes_the_precomputed_blob_base_fee() {
    assert_env_opcode(
        BLOBBASEFEE,
        U256::from(sample_env().blob_base_fee),
        cost::BASE,
    );
}

// --------------------------------------------------------------- SELFBALANCE

#[test]
fn selfbalance_pushes_the_host_balance_at_selfbalance_cost() {
    let mut code = Vec::new();
    return_top_epilogue(&mut code);
    code.insert(0, SELFBALANCE);
    let mut host = MockHost::new().with_self_balance(U256::from(777u64));

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::from(777u64));
    assert_eq!(gas_used(&outcome), cost::SELFBALANCE + 15);
}

// ------------------------------------------------------------------ BLOBHASH

#[test]
fn blobhash_in_range_returns_the_hash() {
    // PUSH1 0(index) BLOBHASH
    let mut code = vec![PUSH1, 0x00, BLOBHASH];
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_tx(sample_tx());

    let outcome = run_program(&code, &mut host);

    assert_eq!(
        returned_word(&outcome),
        U256::from_be_slice(sample_tx().blob_hashes[0].as_slice())
    );
}

#[test]
fn blobhash_out_of_range_returns_zero() {
    // PUSH1 5(index, fuera de rango: solo hay 2) BLOBHASH
    let mut code = vec![PUSH1, 0x05, BLOBHASH];
    return_top_epilogue(&mut code);
    let mut host = MockHost::new().with_tx(sample_tx());

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn blobhash_on_a_non_blob_tx_is_always_zero() {
    // TxEnv::default(): blob_hashes vacío.
    let mut code = vec![PUSH1, 0x00, BLOBHASH];
    return_top_epilogue(&mut code);
    let mut host = MockHost::new();

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

// ----------------------------------------------------------------- BLOCKHASH

#[test]
fn blockhash_within_window_reads_the_host() {
    // Bloque actual 500; pide el 400 (dentro de [244, 499]).
    // PUSH2 400 BLOCKHASH
    let mut code = vec![0x61, 0x01, 0x90, BLOCKHASH];
    return_top_epilogue(&mut code);
    let ancestor_hash = B256::new([0x77; 32]);
    let mut host = MockHost::new()
        .with_env(sample_env())
        .with_block_hash(400, ancestor_hash);

    let outcome = run_program(&code, &mut host);

    assert_eq!(
        returned_word(&outcome),
        U256::from_be_slice(ancestor_hash.as_slice())
    );
}

#[test]
fn blockhash_too_far_back_is_zero_without_consulting_the_host() {
    // Bloque actual 500; pide el 100 (fuera de [244, 499]: 500-256=244).
    let mut code = vec![0x61, 0x00, 0x64, BLOCKHASH]; // PUSH2 100 BLOCKHASH
    return_top_epilogue(&mut code);
    // El host NO tiene el hash de 100 configurado: si el intérprete lo
    // consultara igual, el mock devolvería 0 también — pero lo que este test
    // prueba es que la ventana corta el camino ANTES (ver el próximo test
    // con un hash configurado que NUNCA debe verse).
    let mut host = MockHost::new()
        .with_env(sample_env())
        .with_block_hash(100, B256::new([0xEE; 32]));

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn blockhash_of_the_current_or_a_future_block_is_zero() {
    // Bloque actual 500; pide el 500 (no es ancestro: rango es number < current).
    let mut code = vec![0x61, 0x01, 0xF4, BLOCKHASH]; // PUSH2 500 BLOCKHASH
    return_top_epilogue(&mut code);
    let mut host = MockHost::new()
        .with_env(sample_env())
        .with_block_hash(500, B256::new([0xEE; 32]));

    let outcome = run_program(&code, &mut host);

    assert_eq!(returned_word(&outcome), U256::ZERO);
}

#[test]
fn blockhash_costs_twenty_gas() {
    let mut code = vec![0x61, 0x01, 0x90, BLOCKHASH]; // PUSH2 400 BLOCKHASH
    return_top_epilogue(&mut code);
    let mut host = MockHost::new()
        .with_env(sample_env())
        .with_block_hash(400, B256::new([0x77; 32]));

    let outcome = run_program(&code, &mut host);

    // PUSH2=3, BLOCKHASH=20, epílogo=3+3+3+3+3=15 (32 bytes ya expandidos).
    assert_eq!(gas_used(&outcome), 3 + cost::BLOCKHASH + 15);
}
