//! El orden interno del cierre de bloque en Prague: las withdrawals se
//! acreditan ANTES de las system calls de EIP-7002/7251, que todavía forman
//! parte del bloque porque su output es la fuente de dos de los tres tipos de
//! request.
//!
//! **Lo que se prueba acá es lo que el corpus NO puede medir.** Medido: mover
//! las withdrawals al otro lado de esas dos llamadas no cambia un solo caso de
//! los 42 017 — las dos operaciones tocan estado disjunto (una acredita
//! balances arbitrarios, la otra lee y escribe el storage de su propio
//! predeploy) y por construcción ningún fixture puede separarlas. Se respeta
//! igual el orden del protocolo, y esta es la única evidencia disponible de que
//! el mecanismo que lo permite —acreditar temprano sin cerrar el bloque— no
//! acredita de más ni de menos.

mod support;

use repo_b_common::primitives::{Address, U256};
use repo_b_common::withdrawal::{GWEI_TO_WEI, Withdrawal};
use repo_b_evm::types::Spec;
use repo_b_evm::vm::Vm;
use repo_b_evm::{OwnVm, StateChanges};
use support::{MemState, env};

const BENEFICIARY: Address = Address::new([0xD1; 20]);
const AMOUNT_GWEI: u64 = 32;

fn withdrawal() -> Withdrawal {
    Withdrawal {
        index: 0,
        validator_index: 7,
        address: BENEFICIARY,
        amount: AMOUNT_GWEI,
    }
}

#[track_caller]
fn balance_of(changes: &StateChanges, addr: Address) -> Option<U256> {
    changes
        .iter()
        .find(|update| update.address == addr)
        .and_then(|update| update.balance)
}

/// Un bloque con una withdrawal, cerrado de las dos maneras: acreditando
/// temprano (el camino de Prague) y dejando que lo haga `finish_block` (el
/// camino de todo fork anterior). **El diff tiene que ser el mismo.**
///
/// Es la aserción de que el mecanismo no abre la ventana que 026 quería cerrar:
/// olvidarse de acreditar temprano produce el MISMO bloque, no uno sin
/// withdrawals.
#[test]
fn settling_early_and_letting_finish_block_do_it_produce_the_same_diff() {
    let state = MemState::new().with_eoa(BENEFICIARY, 0, 0);
    let block = env(Spec::Prague);

    let mut early = OwnVm::new();
    early
        .begin_block_with_withdrawals(&block, &state, vec![withdrawal()])
        .unwrap_or_else(|e| panic!("begin_block falló: {e}"));
    early
        .settle_withdrawals_in_block()
        .unwrap_or_else(|e| panic!("acreditar temprano falló: {e}"));
    let early = early
        .finish_block()
        .unwrap_or_else(|e| panic!("finish_block falló: {e}"));

    let mut late = OwnVm::new();
    late.begin_block_with_withdrawals(&block, &state, vec![withdrawal()])
        .unwrap_or_else(|e| panic!("begin_block falló: {e}"));
    let late = late
        .finish_block()
        .unwrap_or_else(|e| panic!("finish_block falló: {e}"));

    let expected = U256::from(AMOUNT_GWEI) * U256::from(GWEI_TO_WEI);
    assert_eq!(
        balance_of(&early, BENEFICIARY),
        Some(expected),
        "acreditar temprano tiene que dejar el crédito completo"
    );
    assert_eq!(
        balance_of(&late, BENEFICIARY),
        balance_of(&early, BENEFICIARY),
        "el crédito no puede depender de QUIÉN lo acreditó"
    );
    assert_eq!(
        early.len(),
        late.len(),
        "los dos diffs tienen el mismo largo"
    );
}

/// Acreditar dos veces sería duplicar el crédito, o sea una divergencia de
/// `stateRoot`. Fail-closed y ruidoso, nunca un no-op silencioso: un no-op
/// dejaría pasar al llamador que llama de más creyendo que acreditó.
#[test]
fn settling_the_withdrawals_twice_is_fail_closed() {
    let state = MemState::new().with_eoa(BENEFICIARY, 0, 0);
    let block = env(Spec::Prague);
    let mut vm = OwnVm::new();
    vm.begin_block_with_withdrawals(&block, &state, vec![withdrawal()])
        .unwrap_or_else(|e| panic!("begin_block falló: {e}"));

    assert!(vm.settle_withdrawals_in_block().is_ok());
    assert!(
        vm.settle_withdrawals_in_block().is_err(),
        "la segunda acreditación tiene que fallar en vez de duplicar el crédito"
    );
}

/// Sin bloque abierto no hay withdrawals que acreditar. Mismo criterio que el
/// resto del lifecycle: se dice en voz alta, no se ignora.
#[test]
fn settling_without_an_open_block_is_fail_closed() {
    assert!(OwnVm::new().settle_withdrawals_in_block().is_err());
}
