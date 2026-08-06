//! `Journal` — el overlay journaled sobre el seam `State` que implementa
//! `interpreter::Host` (ADR-0002 §4).
//!
//! Es el componente **más sutil de consenso** del motor: acá viven
//! `original`-vs-`current` de EIP-2200, los accessed sets de EIP-2929 (+ el
//! pre-warming de tx y EIP-3651), el contador de refund de EIP-3529, el
//! transient storage de EIP-1153 y la semántica de revert. Por eso su gate no
//! es "los tests pasan" sino el **diferencial byte-a-byte vs revm**.
//!
//! Invariantes:
//! - **Un `Journal` vive exactamente UNA tx.** El transient storage (EIP-1153)
//!   se descarta al terminar la tx: acá eso es por construcción, no por una
//!   rutina de limpieza que alguien pueda olvidarse de llamar.
//! - **El motor no muta estado:** el journal lee del `State` (read-through) y
//!   acumula un diff; `storage_changes()` es ese diff.
//! - **Fail-closed:** `Host` no puede devolver `Result`, así que un error del
//!   `State` se registra y el caller lo convierte en `VmError`. Un fallo de
//!   lectura JAMÁS se aproxima como cero.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, U256};
use repo_b_common::receipt::Log;
use repo_b_interpreter::host::{Host, SStoreResult, StateLoad};

use crate::error::StateError;
use crate::state::State;
use crate::types::{BlockEnv, Spec};

/// EIP-3529: el refund liquidable es a lo sumo `gas_used / REFUND_QUOTIENT`.
pub const REFUND_QUOTIENT: u64 = 5;

/// Un slot tocado en la tx. `original` es el valor con el que ARRANCÓ la tx
/// (lo que exige el gas de EIP-2200); `current`, el valor vigente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlotState {
    original: U256,
    current: U256,
}

/// Entradas de deshacer. Un `revert_to` las aplica en orden inverso.
#[derive(Debug, Clone, Copy)]
enum JournalEntry {
    SlotChanged {
        addr: Address,
        key: U256,
        previous: U256,
    },
    SlotWarmed {
        addr: Address,
        key: U256,
    },
    AddressWarmed {
        addr: Address,
    },
    TransientChanged {
        addr: Address,
        key: U256,
        previous: U256,
    },
    RefundChanged {
        delta: i64,
    },
    LogAdded,
}

/// Marca de un punto del journal. Opaco a propósito: solo `revert_to`/`commit`
/// del mismo journal saben interpretarlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    entries: usize,
}

/// Overlay journaled sobre `State`. Implementa el seam `Host` del intérprete.
pub struct Journal<'a> {
    state: &'a dyn State,
    storage: BTreeMap<(Address, U256), SlotState>,
    transient: BTreeMap<(Address, U256), U256>,
    warm_addresses: BTreeSet<Address>,
    warm_slots: BTreeSet<(Address, U256)>,
    logs: Vec<Log>,
    refund: i64,
    entries: Vec<JournalEntry>,
    error: Option<StateError>,
}

impl<'a> Journal<'a> {
    pub fn new(state: &'a dyn State) -> Self {
        Self {
            state,
            storage: BTreeMap::new(),
            transient: BTreeMap::new(),
            warm_addresses: BTreeSet::new(),
            warm_slots: BTreeSet::new(),
            logs: Vec::new(),
            refund: 0,
            entries: Vec::new(),
            error: None,
        }
    }

    /// Pre-warming de la tx (EIP-2929 §tx + EIP-3651). Se corre ANTES de
    /// ejecutar y fuera de todo checkpoint: estas direcciones no se enfrían
    /// con un revert de la tx.
    pub fn prewarm_tx(&mut self, sender: Address, to: Option<Address>, env: &BlockEnv) {
        self.warm_address(sender);
        if let Some(to) = to {
            self.warm_address(to);
        }
        // EIP-3651 (Shanghai+): el coinbase arranca warm.
        if env.spec.is_enabled(Spec::Shanghai) {
            self.warm_address(env.coinbase);
        }
    }

    /// Marca de deshacer. Todo lo journaled a partir de acá se revierte con
    /// `revert_to`.
    pub fn checkpoint(&mut self) -> Checkpoint {
        Checkpoint {
            entries: self.entries.len(),
        }
    }

    /// Deshace todo lo journaled después de `checkpoint`, en orden inverso.
    pub fn revert_to(&mut self, checkpoint: Checkpoint) {
        while self.entries.len() > checkpoint.entries {
            let Some(entry) = self.entries.pop() else {
                break;
            };
            self.undo(entry);
        }
    }

    /// Acepta lo hecho desde `checkpoint`. Las entradas quedan en el journal:
    /// un checkpoint EXTERIOR todavía puede deshacerlas (semántica de revm;
    /// la necesitan las sub-calls de 2.5).
    pub fn commit(&mut self, _checkpoint: Checkpoint) {}

    /// Contador crudo de refund (EIP-3529). Puede ser negativo dentro de la tx.
    pub fn refund_total(&self) -> i64 {
        self.refund
    }

    /// Refund efectivamente liquidable (EIP-3529): `min(contador, gas_used/5)`
    /// con piso 0 — un contador negativo no le cobra de más al sender.
    pub fn settled_refund(&self, gas_used: u64) -> u64 {
        let counter = u64::try_from(self.refund).unwrap_or(0);
        counter.min(gas_used / REFUND_QUOTIENT)
    }

    /// ¿La dirección está en el accessed set (EIP-2929)?
    pub fn is_address_warm(&self, addr: Address) -> bool {
        self.warm_addresses.contains(&addr)
    }

    pub fn logs(&self) -> &[Log] {
        &self.logs
    }

    /// Agrega un log journaled. (Los opcodes LOG0..4 llegan en el slice 2.3;
    /// el hogar journaled de los logs se fija acá, con su revert.)
    pub fn push_log(&mut self, log: Log) {
        self.logs.push(log);
        self.entries.push(JournalEntry::LogAdded);
    }

    /// El diff de storage de la tx: SOLO los slots cuyo valor final difiere
    /// del que tenían al arrancar (tocar y volver al original no es un cambio).
    pub fn storage_changes(&self) -> BTreeMap<Address, BTreeMap<U256, U256>> {
        let mut changes: BTreeMap<Address, BTreeMap<U256, U256>> = BTreeMap::new();
        for ((addr, key), slot) in &self.storage {
            if slot.current != slot.original {
                changes.entry(*addr).or_default().insert(*key, slot.current);
            }
        }
        changes
    }

    /// Consume el primer error del `State` ocurrido durante la ejecución.
    /// El caller DEBE chequearlo antes de aceptar el resultado (fail-closed).
    pub fn take_error(&mut self) -> Option<StateError> {
        self.error.take()
    }

    // ------------------------------------------------------------- internos

    fn undo(&mut self, entry: JournalEntry) {
        match entry {
            JournalEntry::SlotChanged {
                addr,
                key,
                previous,
            } => {
                if let Some(slot) = self.storage.get_mut(&(addr, key)) {
                    slot.current = previous;
                }
            }
            JournalEntry::SlotWarmed { addr, key } => {
                self.warm_slots.remove(&(addr, key));
            }
            JournalEntry::AddressWarmed { addr } => {
                self.warm_addresses.remove(&addr);
            }
            JournalEntry::TransientChanged {
                addr,
                key,
                previous,
            } => {
                self.transient.insert((addr, key), previous);
            }
            JournalEntry::RefundChanged { delta } => {
                self.refund = self.refund.saturating_sub(delta);
            }
            JournalEntry::LogAdded => {
                self.logs.pop();
            }
        }
    }

    fn warm_address(&mut self, addr: Address) {
        if self.warm_addresses.insert(addr) {
            self.entries.push(JournalEntry::AddressWarmed { addr });
        }
    }

    /// Mete `(addr, key)` en el accessed set y devuelve si estaba **frío**
    /// (EIP-2929: el intérprete cobra 2100 vs 100 con este flag).
    fn warm_slot(&mut self, addr: Address, key: U256) -> bool {
        let was_cold = self.warm_slots.insert((addr, key));
        if was_cold {
            self.entries.push(JournalEntry::SlotWarmed { addr, key });
        }
        was_cold
    }

    /// Slot del overlay, leyendo del `State` la primera vez (read-through).
    /// Esa primera lectura fija el `original` de la tx.
    fn slot(&mut self, addr: Address, key: U256) -> SlotState {
        if let Some(slot) = self.storage.get(&(addr, key)) {
            return *slot;
        }
        let original = match self.state.storage(addr, key) {
            Ok(value) => value,
            Err(err) => {
                self.record_error(err);
                U256::ZERO
            }
        };
        let slot = SlotState {
            original,
            current: original,
        };
        self.storage.insert((addr, key), slot);
        slot
    }

    /// Guarda el PRIMER error (el que causó la divergencia); los siguientes
    /// son ruido derivado.
    fn record_error(&mut self, err: StateError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }
}

impl Host for Journal<'_> {
    fn sload(&mut self, addr: Address, key: U256) -> StateLoad<U256> {
        let is_cold = self.warm_slot(addr, key);
        StateLoad {
            data: self.slot(addr, key).current,
            is_cold,
        }
    }

    fn sstore(&mut self, addr: Address, key: U256, value: U256) -> StateLoad<SStoreResult> {
        let is_cold = self.warm_slot(addr, key);
        let slot = self.slot(addr, key);
        self.entries.push(JournalEntry::SlotChanged {
            addr,
            key,
            previous: slot.current,
        });
        self.storage.insert(
            (addr, key),
            SlotState {
                original: slot.original,
                current: value,
            },
        );
        StateLoad {
            data: SStoreResult {
                original: slot.original,
                current: slot.current,
                new: value,
            },
            is_cold,
        }
    }

    fn tload(&mut self, addr: Address, key: U256) -> U256 {
        self.transient
            .get(&(addr, key))
            .copied()
            .unwrap_or(U256::ZERO)
    }

    fn tstore(&mut self, addr: Address, key: U256, value: U256) {
        let previous = self.tload(addr, key);
        self.entries.push(JournalEntry::TransientChanged {
            addr,
            key,
            previous,
        });
        self.transient.insert((addr, key), value);
    }

    fn refund(&mut self, delta: i64) {
        self.refund = self.refund.saturating_add(delta);
        self.entries.push(JournalEntry::RefundChanged { delta });
    }
}
