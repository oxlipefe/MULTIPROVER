//! Unit + adversariales del `Journal` (ADR-0002 §4, task 004).
//!
//! Los números y la semántica salen de las EIPs (2929 warm/cold, 2200/3529
//! original-vs-current y refunds, 1153 transient), NO del código: testear el
//! código contra sí mismo no prueba nada de consenso.

mod support;

use repo_b_common::access_list::{AccessList, AccessListItem};
use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::receipt::Log;
use repo_b_evm::journal::Journal;
use repo_b_evm::types::Spec;
use repo_b_interpreter::host::Host;

use support::{COINBASE, CONTRACT, MemState, SENDER, env};

const EXTERNAL: Address = Address::new([0xEE; 20]);

const SLOT: u64 = 7;
const OTHER_SLOT: u64 = 9;

fn key(k: u64) -> U256 {
    U256::from(k)
}

fn val(v: u64) -> U256 {
    U256::from(v)
}

// --------------------------------------------------------------- original vs current

#[test]
fn original_is_the_pre_tx_value_and_current_follows_writes() {
    // Arrange: el slot vale 3 al empezar la tx.
    let state = MemState::new().with_slot(CONTRACT, SLOT, 3);
    let mut journal = Journal::new(&state);

    // Act: dos escrituras dentro de la MISMA tx.
    let first = journal.sstore(CONTRACT, key(SLOT), val(5));
    let second = journal.sstore(CONTRACT, key(SLOT), val(8));

    // Assert: `original` NUNCA cambia dentro de la tx (EIP-2200); `current` sí.
    assert_eq!(first.data.original, val(3));
    assert_eq!(first.data.current, val(3));
    assert_eq!(first.data.new, val(5));
    assert_eq!(second.data.original, val(3));
    assert_eq!(second.data.current, val(5));
    assert_eq!(second.data.new, val(8));
}

#[test]
fn sload_reads_through_the_state_and_then_the_overlay() {
    let state = MemState::new().with_slot(CONTRACT, SLOT, 42);
    let mut journal = Journal::new(&state);

    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, val(42));
    journal.sstore(CONTRACT, key(SLOT), val(1));
    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, val(1));
    // Un slot nunca escrito lee 0 (el State devuelve 0 por defecto).
    assert_eq!(journal.sload(CONTRACT, key(OTHER_SLOT)).data, U256::ZERO);
}

#[test]
fn storage_changes_only_lists_slots_that_really_changed() {
    let state = MemState::new().with_slot(CONTRACT, SLOT, 3);
    let mut journal = Journal::new(&state);

    // Se toca y se vuelve al valor original ⇒ NO es un cambio de estado.
    journal.sstore(CONTRACT, key(SLOT), val(5));
    journal.sstore(CONTRACT, key(SLOT), val(3));
    // Una lectura pura tampoco es un cambio.
    journal.sload(CONTRACT, key(OTHER_SLOT));
    assert!(journal.storage_changes().is_empty());

    journal.sstore(CONTRACT, key(OTHER_SLOT), val(11));
    let changes = journal.storage_changes();
    let contract = changes
        .get(&CONTRACT)
        .unwrap_or_else(|| panic!("cambios del contrato"));
    assert_eq!(contract.len(), 1);
    assert_eq!(contract.get(&key(OTHER_SLOT)), Some(&val(11)));
}

// ------------------------------------------------------------------ warm / cold

#[test]
fn first_slot_access_is_cold_and_the_second_is_warm() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    assert!(journal.sload(CONTRACT, key(SLOT)).is_cold);
    assert!(!journal.sload(CONTRACT, key(SLOT)).is_cold);
    // El warm es por (address, slot): otro slot sigue frío.
    assert!(journal.sload(CONTRACT, key(OTHER_SLOT)).is_cold);
}

#[test]
fn sstore_also_warms_the_slot_eip2929() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    assert!(journal.sstore(CONTRACT, key(SLOT), val(1)).is_cold);
    assert!(!journal.sstore(CONTRACT, key(SLOT), val(2)).is_cold);
    assert!(!journal.sload(CONTRACT, key(SLOT)).is_cold);
}

#[test]
fn tx_prewarming_marks_sender_to_and_coinbase_eip2929_eip3651() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    journal.prewarm_tx(SENDER, Some(CONTRACT), &AccessList::new(), &env(Spec::Prague));

    assert!(journal.is_address_warm(SENDER));
    assert!(journal.is_address_warm(CONTRACT));
    // EIP-3651 (Shanghai+): el coinbase entra warm.
    assert!(journal.is_address_warm(COINBASE));
    assert!(!journal.is_address_warm(Address::new([0x01; 20])));
}

#[test]
fn coinbase_is_cold_before_eip3651() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    journal.prewarm_tx(SENDER, Some(CONTRACT), &AccessList::new(), &env(Spec::Paris));

    assert!(journal.is_address_warm(SENDER));
    assert!(!journal.is_address_warm(COINBASE));
}

#[test]
fn tx_prewarming_warms_the_access_list_addresses_and_storage_keys_eip2930() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    let access_list: AccessList = vec![AccessListItem {
        address: EXTERNAL,
        storage_keys: vec![B256::new(key(SLOT).to_be_bytes())],
    }];
    journal.prewarm_tx(SENDER, Some(CONTRACT), &access_list, &env(Spec::Prague));

    assert!(journal.is_address_warm(EXTERNAL));
    // El SLOAD sobre la key declarada ya no debe cobrar el costo cold.
    assert!(!journal.sload(EXTERNAL, key(SLOT)).is_cold);
    // Una key NO declarada en la misma dirección sigue fría.
    assert!(journal.sload(EXTERNAL, key(OTHER_SLOT)).is_cold);
}

// ------------------------------------------------------------- checkpoint / revert

#[test]
fn revert_to_checkpoint_restores_storage_refund_and_logs() {
    let state = MemState::new().with_slot(CONTRACT, SLOT, 3);
    let mut journal = Journal::new(&state);
    journal.sstore(CONTRACT, key(SLOT), val(5));
    journal.refund(1000);

    let checkpoint = journal.checkpoint();
    journal.sstore(CONTRACT, key(SLOT), val(9));
    journal.sstore(CONTRACT, key(OTHER_SLOT), val(4));
    journal.refund(4800);
    journal.push_log(Log {
        address: CONTRACT,
        topics: Vec::new(),
        data: Bytes::new(),
    });
    journal.revert_to(checkpoint);

    // Lo posterior al checkpoint se deshace; lo anterior sobrevive.
    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, val(5));
    assert_eq!(journal.sload(CONTRACT, key(OTHER_SLOT)).data, U256::ZERO);
    assert_eq!(journal.refund_total(), 1000);
    assert!(journal.logs().is_empty());
}

#[test]
fn revert_marks_slots_warmed_after_the_checkpoint_as_cold_again() {
    // La sutileza que caza el diff: revm/EELS revierten los accessed sets
    // junto con el resto del frame (en EELS los sets del hijo solo se
    // mergean al padre si el hijo tiene éxito). Sin sub-calls (2.5) esto no
    // es observable todavía, pero la semántica se fija ACÁ y con test.
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    journal.sload(CONTRACT, key(SLOT)); // warm antes del checkpoint

    let checkpoint = journal.checkpoint();
    assert!(journal.sload(CONTRACT, key(OTHER_SLOT)).is_cold);
    journal.revert_to(checkpoint);

    assert!(journal.sload(CONTRACT, key(OTHER_SLOT)).is_cold);
    // El warm previo al checkpoint NO se toca.
    assert!(!journal.sload(CONTRACT, key(SLOT)).is_cold);
}

#[test]
fn commit_keeps_everything_written_after_the_checkpoint() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    let checkpoint = journal.checkpoint();
    journal.sstore(CONTRACT, key(SLOT), val(7));
    journal.refund(4800);
    journal.commit(checkpoint);

    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, val(7));
    assert_eq!(journal.refund_total(), 4800);
}

#[test]
fn nested_checkpoints_revert_independently() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    let outer = journal.checkpoint();
    journal.sstore(CONTRACT, key(SLOT), val(1));
    let inner = journal.checkpoint();
    journal.sstore(CONTRACT, key(SLOT), val(2));
    journal.revert_to(inner);
    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, val(1));

    journal.revert_to(outer);
    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, U256::ZERO);
    assert!(journal.storage_changes().is_empty());
}

// ---------------------------------------------------------------------- refunds

#[test]
fn refund_accumulates_signed_deltas_eip3529() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    journal.refund(4800);
    journal.refund(-4800);
    journal.refund(19900);
    assert_eq!(journal.refund_total(), 19900);
}

#[test]
fn refund_counter_can_go_negative_and_saturates_at_zero_when_settled() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    journal.refund(-4800);
    assert_eq!(journal.refund_total(), -4800);
    // La liquidación (EIP-3529: `min(refund, gas_used/5)` con piso 0) NO la
    // hace el journal; expone el contador crudo y satura al liquidar.
    assert_eq!(journal.settled_refund(1_000_000), 0);
}

#[test]
fn settled_refund_is_capped_at_a_fifth_of_the_gas_used_eip3529() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    journal.refund(19900);

    // gas_used = 50_000 ⇒ tope = 10_000 < 19_900.
    assert_eq!(journal.settled_refund(50_000), 10_000);
    // gas_used = 200_000 ⇒ tope = 40_000 > 19_900 ⇒ manda el contador.
    assert_eq!(journal.settled_refund(200_000), 19_900);
}

// ------------------------------------------------------------ transient (EIP-1153)

#[test]
fn transient_storage_roundtrips_and_is_isolated_from_persistent_storage() {
    let state = MemState::new().with_slot(CONTRACT, SLOT, 3);
    let mut journal = Journal::new(&state);

    assert_eq!(journal.tload(CONTRACT, key(SLOT)), U256::ZERO);
    journal.tstore(CONTRACT, key(SLOT), val(99));
    assert_eq!(journal.tload(CONTRACT, key(SLOT)), val(99));
    // No contamina el storage persistente ni el diff.
    assert_eq!(journal.sload(CONTRACT, key(SLOT)).data, val(3));
    assert!(journal.storage_changes().is_empty());
}

#[test]
fn transient_storage_reverts_with_the_checkpoint() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    journal.tstore(CONTRACT, key(SLOT), val(1));

    let checkpoint = journal.checkpoint();
    journal.tstore(CONTRACT, key(SLOT), val(2));
    journal.revert_to(checkpoint);

    assert_eq!(journal.tload(CONTRACT, key(SLOT)), val(1));
}

#[test]
fn transient_storage_starts_empty_in_every_journal_a_journal_is_one_tx() {
    let state = MemState::new();
    let mut first = Journal::new(&state);
    first.tstore(CONTRACT, key(SLOT), val(5));

    // EIP-1153: el transient storage se descarta al terminar la tx. El
    // journal VIVE una tx, así que la limpieza es por construcción.
    let mut second = Journal::new(&state);
    assert_eq!(second.tload(CONTRACT, key(SLOT)), U256::ZERO);
}

// ------------------------------------------------------------------- fail-closed

#[test]
fn a_state_error_is_captured_and_never_silently_turned_into_zero() {
    // `Host` no puede devolver Result (el intérprete no maneja errores de IO):
    // el journal registra el error y el caller lo convierte en `VmError`.
    let state = MemState::new().failing_on(CONTRACT);
    let mut journal = Journal::new(&state);

    let _ = journal.sload(CONTRACT, key(SLOT));
    assert!(journal.take_error().is_some());
    // Se consume una sola vez.
    assert!(journal.take_error().is_none());
}

// -------------------------------------------------- account access (slice 2.4)

#[test]
fn load_account_reads_through_the_state_for_an_untouched_address() {
    let state = MemState::new().with_eoa(EXTERNAL, 500, 3);
    let mut journal = Journal::new(&state);

    let load = journal.load_account(EXTERNAL);

    assert_eq!(load.data.balance, val(500));
    assert_eq!(load.data.code_hash, KECCAK256_EMPTY);
    assert!(!load.data.is_empty);
}

#[test]
fn load_account_is_cold_then_warm_on_repeated_access() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    assert!(journal.load_account(EXTERNAL).is_cold);
    assert!(!journal.load_account(EXTERNAL).is_cold);
}

#[test]
fn load_account_warms_the_address_accessed_set() {
    // El accessed-set de cuentas (BALANCE/EXTCODE*) es el MISMO que usa el
    // pre-warming de tx (`is_address_warm`), distinto del de `(addr, slot)`.
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    journal.load_account(EXTERNAL);

    assert!(journal.is_address_warm(EXTERNAL));
}

#[test]
fn load_account_sees_the_live_balance_not_the_frozen_state() {
    // El overlay vivo (gas prepagado, value de la tx, transfers de sub-calls)
    // manda sobre el balance "congelado" del `State` — la sutileza central del
    // slice 2.4, que en 2.5 pasó a ser dueño el propio journal.
    let state = MemState::new().with_eoa(SENDER, 1000, 0);
    let mut journal = Journal::new(&state);

    assert_eq!(journal.debit(SENDER, val(958)), Ok(()));

    assert_eq!(journal.load_account(SENDER).data.balance, val(42));
}

#[test]
fn load_account_of_a_nonexistent_address_is_zero_and_empty() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    let load = journal.load_account(EXTERNAL);

    assert_eq!(load.data.balance, U256::ZERO);
    assert_eq!(load.data.code_hash, KECCAK256_EMPTY);
    assert!(load.data.is_empty);
}

#[test]
fn load_account_of_a_touched_but_empty_eip161_account_is_empty() {
    let state = MemState::new().with_eoa(EXTERNAL, 0, 0);
    let mut journal = Journal::new(&state);

    assert!(journal.load_account(EXTERNAL).data.is_empty);
}

#[test]
fn load_account_with_nonzero_nonce_is_not_empty_despite_zero_balance() {
    let state = MemState::new().with_eoa(EXTERNAL, 0, 1);
    let mut journal = Journal::new(&state);

    assert!(!journal.load_account(EXTERNAL).data.is_empty);
}

#[test]
fn load_account_of_a_contract_is_not_empty_and_carries_its_code_hash() {
    let state = MemState::new().with_contract(EXTERNAL, &[0x00], 0);
    let mut journal = Journal::new(&state);

    let load = journal.load_account(EXTERNAL);

    assert!(!load.data.is_empty);
    assert_ne!(load.data.code_hash, KECCAK256_EMPTY);
}

#[test]
fn code_by_address_reads_the_bytecode_of_the_account() {
    let code = [0x60, 0x00, 0x60, 0x00];
    let state = MemState::new().with_contract(EXTERNAL, &code, 0);
    let mut journal = Journal::new(&state);

    let load = journal.code_by_address(EXTERNAL);

    assert_eq!(load.data.as_ref(), &code);
    assert!(load.is_cold);
}

#[test]
fn code_by_address_of_an_eoa_is_empty_bytes() {
    let state = MemState::new().with_eoa(EXTERNAL, 1, 0);
    let mut journal = Journal::new(&state);

    assert_eq!(journal.code_by_address(EXTERNAL).data, Bytes::new());
}

#[test]
fn code_by_address_shares_the_address_warm_set_with_load_account() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);

    journal.code_by_address(EXTERNAL);

    assert!(!journal.load_account(EXTERNAL).is_cold);
}

#[test]
fn logs_are_appended_in_order() {
    let state = MemState::new();
    let mut journal = Journal::new(&state);
    journal.push_log(Log {
        address: CONTRACT,
        topics: Vec::new(),
        data: Bytes::from_static(b"a"),
    });
    journal.push_log(Log {
        address: SENDER,
        topics: Vec::new(),
        data: Bytes::from_static(b"b"),
    });

    assert_eq!(journal.logs().len(), 2);
    assert_eq!(journal.logs().first().map(|l| l.address), Some(CONTRACT));
    assert_eq!(journal.logs().get(1).map(|l| l.address), Some(SENDER));
}
