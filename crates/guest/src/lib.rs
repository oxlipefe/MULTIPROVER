//! `repo-b-guest` — lo que corre **adentro** de la zkVM.
//!
//! Es el único crate del árbol que produce un **ELF**, y esa es toda su razón
//! de existir. Hasta acá el motor se verificaba sobre `rlib`s, y un `rlib` no
//! contesta la pregunta que importa: *¿qué código llega de verdad al binario?*
//! El código no-genérico de una dependencia vive en su propio `rlib` y el
//! linker lo descarta **solo si nadie lo llama** — o sea que sobre `rlib`s
//! "esto no llega al guest" es una **inferencia sobre el descarte del linker**,
//! y sobre un ELF es un **hecho**.
//!
//! **Agnóstico de backend, a propósito.** No hay macro de entrada de ninguna
//! zkVM acá: el punto de entrada es una función de Rust y `_start` es un
//! símbolo pelado. El día que entre un backend, lo que cambia es el arranque,
//! no esto. Casarse con uno ahora sería tomar en la Fase 3 una decisión que es
//! de la Fase 4, y contra el multiproof.
//!
//! **Qué NO hace todavía, dicho acá y no escondido:**
//!
//! 1. **El input llega tipado, no serializado.** No existe codec: el
//!    `ExecutionWitness` son cuatro listas de bytes sin encoding y una tx tiene
//!    catorce campos con tres listas anidadas. Un codec adversarial de esa
//!    superficie es más grande que este crate entero, así que va aparte.
//! 2. **No devuelve el post-state root.** Y no es un olvido: **nadie en el
//!    árbol puede computarlo desde un witness**. El root que juzga los dos ejes
//!    de conformance se computa con el mapa COMPLETO de cuentas, que es
//!    exactamente lo que el guest no tiene. Desde un witness hay que
//!    **actualizar** los nodos del camino probado y re-hashear hacia arriba —
//!    un trie disperso—, y eso es una pieza propia que todavía no existe.
//!    Mientras tanto el guest devuelve el diff (`StateChanges`), que es lo que
//!    el motor sí produce.
//! 3. **Los senders vienen pre-recuperados.** Es el contrato del seam: el VM no
//!    llama a `recover_signer`. Meter ECDSA acá agrandaría el blast radius de
//!    este slice sin necesidad.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes};
use repo_b_common::transaction::Transaction;
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::types::BlockEnv;
use repo_b_evm::{OwnVm, StateChanges, Vm};
use repo_b_witness::WitnessState;

/// Lo que el guest necesita para ejecutar un bloque sin base de datos.
///
/// Tipado y no bytes: el codec es una pieza aparte. Cuando exista, decodifica a
/// esto — el punto de entrada no cambia.
pub struct GuestInput<'a> {
    /// Los pre-images: nodos de trie, códigos, claves y la cadena de headers.
    pub witness: &'a ExecutionWitness,
    /// El ancla. Toda lectura se verifica caminando el trie desde acá, así que
    /// un witness que no corresponda a este root no puede servir nada.
    pub pre_state_root: B256,
    pub env: BlockEnv,
    /// Con el sender ya recuperado adentro de cada `Transaction`.
    pub txs: &'a [Transaction],
    pub withdrawals: Vec<Withdrawal>,
    /// System calls del arranque del bloque (EIP-4788, EIP-2935), en orden.
    pub system_calls: &'a [(Address, Bytes)],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    /// El motor rechazó el bloque. Se conserva el texto porque distinguir un
    /// rechazo de protocolo de un error interno es la diferencia entre un
    /// bloque inválido y un bug.
    Vm(alloc::string::String),
}

/// Ejecuta un bloque **solo desde el witness** y devuelve el diff.
///
/// Es el camino real y completo: apertura del bloque con sus withdrawals, las
/// system calls de arranque, las txs en orden, el settle de withdrawals antes
/// de cerrar, y el cierre. Ninguna de esas llamadas se puede saltear sin
/// producir otro bloque.
///
/// # Errors
/// Devuelve `GuestError::Vm` si el motor rechaza el bloque o si el witness no
/// alcanza para una lectura — que es fail-closed a propósito: servir un dato
/// sin prueba es la única forma de que un guest mienta.
pub fn run_block(input: &GuestInput<'_>) -> Result<StateChanges, GuestError> {
    let state = WitnessState::new(input.witness, input.pre_state_root);
    let mut vm = OwnVm::new();

    let fail = |e: repo_b_evm::error::VmError| GuestError::Vm(alloc::format!("{e}"));

    vm.begin_block_with_withdrawals(&input.env, &state, input.withdrawals.clone())
        .map_err(fail)?;
    for (to, data) in input.system_calls {
        vm.system_call_in_block(*to, data.clone()).map_err(fail)?;
    }
    for tx in input.txs {
        vm.transact_in_block(tx, tx.sender).map_err(fail)?;
    }
    // Antes de cerrar: el protocolo acredita las withdrawals después de las txs.
    vm.settle_withdrawals_in_block().map_err(fail)?;
    vm.finish_block().map_err(fail)
}

/// Un digest del diff, para que el arranque bare-metal tenga algo que devolver
/// sin poder tirarlo por optimización.
///
/// **No es el post-state root** y no pretende serlo: es un resumen de lo que la
/// ejecución produjo. El root de verdad necesita el trie disperso que todavía
/// no existe.
#[must_use]
pub fn digest_of(changes: &StateChanges) -> B256 {
    use repo_b_common::primitives::keccak256;
    let mut bytes = Vec::new();
    for update in changes {
        bytes.extend_from_slice(update.address.as_slice());
        bytes.push(u8::from(update.destroyed));
        if let Some(nonce) = update.nonce {
            bytes.extend_from_slice(&nonce.to_be_bytes());
        }
        if let Some(balance) = update.balance {
            bytes.extend_from_slice(&balance.to_be_bytes::<32>());
        }
        for (key, value) in &update.storage {
            bytes.extend_from_slice(&key.to_be_bytes::<32>());
            bytes.extend_from_slice(&value.to_be_bytes::<32>());
        }
    }
    keccak256(&bytes)
}
