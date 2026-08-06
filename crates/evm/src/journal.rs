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

use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::receipt::Log;
use repo_b_interpreter::host::{
    AccountLoad, BlockEnv as HostBlockEnv, Host, SStoreResult, StateLoad, TxEnv as HostTxEnv,
};

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
    /// Entorno/tx proyectados para el seam `Host` (slice 2.3). Default (todo
    /// cero) hasta que `with_frame_context` los fija; los tests de storage/
    /// refund/transient de este módulo nunca los leen.
    host_env: HostBlockEnv,
    host_tx: HostTxEnv,
    self_balance: U256,
    /// Overlay de balances pre-frame (slice 2.4, `Host::load_account`):
    /// sender/`to` ya reflejan el gas prepagado y el value de la tx —
    /// `own_vm::frame_balance_overlay` es la única fuente de este cálculo.
    /// Sin sub-calls (2.5) ninguna otra cuenta puede estar en este overlay.
    balance_overlay: BTreeMap<Address, U256>,
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
            host_env: HostBlockEnv::default(),
            host_tx: HostTxEnv::default(),
            self_balance: U256::ZERO,
            balance_overlay: BTreeMap::new(),
        }
    }

    /// Fija lo que el seam `Host` expone de entorno/tx/balance propio para
    /// ESTE frame (slice 2.3: `env`/`tx`/`self_balance`/`block_hash`). Quien
    /// arma el frame (`evm::execution::build_frame`) ya calculó
    /// `self_balance` reflejando el value entrante y el gas prepagado.
    #[must_use]
    pub fn with_frame_context(mut self, self_balance: U256, env: HostBlockEnv, tx: HostTxEnv) -> Self {
        self.self_balance = self_balance;
        self.host_env = env;
        self.host_tx = tx;
        self
    }

    /// Overlay de balances pre-frame (slice 2.4): `BALANCE`/`EXTCODEHASH` de
    /// sender/`to` deben ver el débito de fees+value ANTES de correr el
    /// código (protocolo real: el prepago y el transfer ocurren antes de la
    /// call), no el balance "congelado" del `State`. Cuentas fuera del
    /// overlay leen del `State` sin más (read-through, igual que `slot`).
    #[must_use]
    pub fn with_balance_overlay(mut self, overlay: BTreeMap<Address, U256>) -> Self {
        self.balance_overlay = overlay;
        self
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

    /// Mete `addr` en el accessed set y devuelve si estaba **fría** (EIP-2929:
    /// BALANCE/EXTCODE* cobran 2600 vs 100 con este flag). Distinto del
    /// accessed set de `(addr, slot)` que usa `warm_slot`.
    fn warm_address(&mut self, addr: Address) -> bool {
        let was_cold = self.warm_addresses.insert(addr);
        if was_cold {
            self.entries.push(JournalEntry::AddressWarmed { addr });
        }
        was_cold
    }

    /// Balance/nonce/code_hash de una cuenta AJENA (slice 2.4): el balance
    /// sale del overlay pre-frame si está ahí (sender/`to` ya
    /// debitados/acreditados), si no, read-through al `State`. El nonce y el
    /// code_hash no tienen overlay propio: sin sub-calls (2.5) ni CREATE
    /// (2.6) ninguna cuenta puede tener código o nonce nuevos dentro de esta
    /// tx — leerlos del `State` es correcto incluso para sender/`to`.
    fn account_load(&mut self, addr: Address) -> AccountLoad {
        let (state_balance, nonce, code_hash, exists) = match self.state.account(addr) {
            Ok(Some(info)) => (info.balance, info.nonce, info.code_hash, true),
            Ok(None) => (U256::ZERO, 0, KECCAK256_EMPTY, false),
            Err(err) => {
                self.record_error(err);
                (U256::ZERO, 0, KECCAK256_EMPTY, false)
            }
        };
        let balance = self
            .balance_overlay
            .get(&addr)
            .copied()
            .unwrap_or(state_balance);
        // EIP-161: inexistente O (nonce=0 ∧ balance=0 ∧ code vacío).
        let is_empty = !exists || (nonce == 0 && balance.is_zero() && code_hash == KECCAK256_EMPTY);
        AccountLoad {
            balance,
            code_hash,
            is_empty,
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

    fn env(&self) -> &HostBlockEnv {
        &self.host_env
    }

    fn tx(&self) -> &HostTxEnv {
        &self.host_tx
    }

    fn self_balance(&mut self) -> U256 {
        self.self_balance
    }

    /// El intérprete ya validó la ventana `[number-256, number-1]` antes de
    /// llamar acá (`interpreter::block_hash_word`); esto es un read-through
    /// fail-closed idéntico a `slot()`: un error del `State` se registra, NUNCA
    /// se aproxima como cero silenciosamente.
    fn block_hash(&mut self, number: u64) -> B256 {
        match self.state.block_hash(number) {
            Ok(hash) => hash,
            Err(err) => {
                self.record_error(err);
                B256::ZERO
            }
        }
    }

    fn log(&mut self, log: Log) {
        self.push_log(log);
    }

    fn load_account(&mut self, addr: Address) -> StateLoad<AccountLoad> {
        let is_cold = self.warm_address(addr);
        StateLoad {
            data: self.account_load(addr),
            is_cold,
        }
    }

    /// Read-through fail-closed idéntico a `slot()`/`block_hash()`: un error
    /// del `State` se registra, NUNCA se aproxima como bytes vacíos en
    /// silencio (el caller lo convierte en `VmError` antes de aceptar nada).
    fn code_by_address(&mut self, addr: Address) -> StateLoad<Bytes> {
        let is_cold = self.warm_address(addr);
        let code_hash = self.account_load(addr).code_hash;
        let data = match self.state.code(code_hash) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.record_error(err);
                Bytes::new()
            }
        };
        StateLoad { data, is_cold }
    }
}
