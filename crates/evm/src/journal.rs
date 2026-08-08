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

use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
use repo_b_common::receipt::Log;
use repo_b_interpreter::host::{
    AccountLoad, BlockEnv as HostBlockEnv, Host, SStoreResult, SelfDestructResult, StateLoad,
    TxEnv as HostTxEnv,
};

use crate::error::StateError;
use crate::result::StateChanges;
use crate::state::State;
use crate::types::{BlockEnv, Spec};

/// EIP-3529: el refund liquidable es a lo sumo `gas_used / REFUND_QUOTIENT`.
pub const REFUND_QUOTIENT: u64 = 5;

/// Por qué un movimiento de balance no se pudo hacer. **No es un halt**: una
/// call sin fondos pushea 0 al caller y le devuelve el gas reenviado
/// (execution-specs `generic_call`); en la liquidación de la tx, en cambio, es
/// un bug de validación (el chequeo de balance debió atraparlo antes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferError {
    InsufficientBalance,
    /// Overflow de U256 en el receptor. Imposible en mainnet (el supply no
    /// llega); fail-closed igual, nunca wrapping silencioso.
    BalanceOverflow,
}

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
    BalanceChanged {
        addr: Address,
        previous: U256,
    },
    NonceChanged {
        addr: Address,
        previous: u64,
    },
    /// Código depositado por una creación (slice 2.6). Deshacer = SACAR la
    /// entrada del overlay, no restaurar una anterior: la regla de colisión
    /// (`nonce != 0` o código no vacío ⇒ la creación falla) garantiza que una
    /// dirección no puede recibir código dos veces sin un revert en el medio.
    CodeDeposited {
        addr: Address,
    },
    /// La dirección se marcó como "creada en esta tx" (EIP-6780).
    AccountCreated {
        addr: Address,
    },
    /// La cuenta ejecutó SELFDESTRUCT y se creó en esta tx (EIP-6780).
    AccountDestroyed {
        addr: Address,
    },
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
    /// Overlay de balances (slice 2.5). Read-through al `State` la primera vez;
    /// desde acá salen `BALANCE`/`SELFBALANCE`/`EXTCODEHASH` (EIP-161) y el
    /// diff final. Es el journal —no `own_vm`— quien mueve balance, porque con
    /// sub-calls el value puede terminar en CUALQUIER cuenta y hay que poder
    /// revertirlo por frame.
    balances: BTreeMap<Address, U256>,
    /// Overlay de nonces. Lo mueven el bump del sender, el bump del creador en
    /// CREATE y el `nonce = 1` del contrato nuevo (EIP-161); `is_empty` (y con
    /// él los 25000 de `G_newaccount`) lo lee: un nonce leído del `State`
    /// post-bump sería falso.
    nonces: BTreeMap<Address, u64>,
    /// Overlay de código depositado por CREATE/CREATE2 (slice 2.6). Es la
    /// ÚNICA vía por la que una cuenta estrena código dentro de una tx, así
    /// que EXTCODESIZE/EXTCODECOPY/EXTCODEHASH lo consultan ANTES del `State`.
    code: BTreeMap<Address, Bytes>,
    /// Direcciones creadas en ESTA tx (EIP-6780): es lo único que le permite a
    /// SELFDESTRUCT destruir la cuenta de verdad. Journaled: el revert de un
    /// frame de creación borra la marca.
    created: BTreeSet<Address>,
    /// Cuentas efectivamente destruidas (EIP-6780). `state_changes()` emite un
    /// `AccountUpdate { destroyed: true }` y el consumidor las borra enteras.
    destroyed: BTreeSet<Address>,
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
            balances: BTreeMap::new(),
            nonces: BTreeMap::new(),
            code: BTreeMap::new(),
            created: BTreeSet::new(),
            destroyed: BTreeSet::new(),
        }
    }

    /// Fija lo que el seam `Host` expone de entorno/tx (slice 2.3:
    /// `env`/`tx`/`block_hash`). El balance propio ya no se pasa: sale del
    /// overlay de balances, que es quien conoce el estado vivo de la tx.
    #[must_use]
    pub fn with_frame_context(mut self, env: HostBlockEnv, tx: HostTxEnv) -> Self {
        self.host_env = env;
        self.host_tx = tx;
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

    // -------------------------------------------------- balances y nonces

    /// Balance vigente de una cuenta (read-through al `State` la primera vez).
    /// **No toca el accessed set**: el gas de EIP-2929 lo decide `load_account`.
    pub fn balance(&mut self, addr: Address) -> U256 {
        if let Some(balance) = self.balances.get(&addr) {
            return *balance;
        }
        let balance = self.account_info(addr).0;
        self.balances.insert(addr, balance);
        balance
    }

    /// Nonce vigente de una cuenta (read-through al `State` la primera vez).
    pub fn nonce(&mut self, addr: Address) -> u64 {
        if let Some(nonce) = self.nonces.get(&addr) {
            return *nonce;
        }
        let nonce = self.account_info(addr).1;
        self.nonces.insert(addr, nonce);
        nonce
    }

    /// Incrementa el nonce del sender (protocolo: ANTES de ejecutar).
    pub fn bump_nonce(&mut self, addr: Address) -> Result<(), TransferError> {
        let previous = self.nonce(addr);
        let next = previous
            .checked_add(1)
            .ok_or(TransferError::BalanceOverflow)?;
        self.entries
            .push(JournalEntry::NonceChanged { addr, previous });
        self.nonces.insert(addr, next);
        Ok(())
    }

    /// Suma `amount` al balance de `addr` (journaled).
    pub fn credit(&mut self, addr: Address, amount: U256) -> Result<(), TransferError> {
        let previous = self.balance(addr);
        let next = previous
            .checked_add(amount)
            .ok_or(TransferError::BalanceOverflow)?;
        self.set_balance(addr, previous, next);
        Ok(())
    }

    /// Resta `amount` del balance de `addr` (journaled). Sin fondos ⇒ error,
    /// NUNCA wrapping.
    pub fn debit(&mut self, addr: Address, amount: U256) -> Result<(), TransferError> {
        let previous = self.balance(addr);
        let next = previous
            .checked_sub(amount)
            .ok_or(TransferError::InsufficientBalance)?;
        self.set_balance(addr, previous, next);
        Ok(())
    }

    /// Mueve `amount` de `from` a `to` (journaled, atómico: si el crédito
    /// falla, el débito no queda hecho).
    ///
    /// Semántica de revm (`transfer_loaded`), verificada en la fuente:
    /// - `from == to` ⇒ **solo** chequeo de fondos (CALLCODE con value, o una
    ///   self-call): mover a sí mismo no cambia nada.
    /// - `amount == 0` ⇒ touch del receptor sin mover balance. Acá el touch es
    ///   implícito: leer el balance mete la cuenta en el overlay, y el diff
    ///   solo emite lo que DIFIERE del `State`, así que un touch de cero no
    ///   crea una cuenta vacía (EIP-161).
    pub fn transfer(
        &mut self,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<(), TransferError> {
        if from == to {
            if amount > self.balance(from) {
                return Err(TransferError::InsufficientBalance);
            }
            return Ok(());
        }
        if amount.is_zero() {
            self.balance(to);
            return Ok(());
        }
        let from_balance = self.balance(from);
        let from_next = from_balance
            .checked_sub(amount)
            .ok_or(TransferError::InsufficientBalance)?;
        let to_balance = self.balance(to);
        let to_next = to_balance
            .checked_add(amount)
            .ok_or(TransferError::BalanceOverflow)?;
        self.set_balance(from, from_balance, from_next);
        self.set_balance(to, to_balance, to_next);
        Ok(())
    }

    fn set_balance(&mut self, addr: Address, previous: U256, next: U256) {
        self.entries
            .push(JournalEntry::BalanceChanged { addr, previous });
        self.balances.insert(addr, next);
    }

    /// Fija el nonce de una cuenta (journaled). Lo usa la creación de un
    /// contrato: EIP-161 exige que el contrato nuevo arranque en `1`, no `0`.
    pub fn set_nonce(&mut self, addr: Address, nonce: u64) {
        let previous = self.nonce(addr);
        self.entries
            .push(JournalEntry::NonceChanged { addr, previous });
        self.nonces.insert(addr, nonce);
    }

    /// Bytecode de una cuenta, para abrir un sub-frame. Fail-closed: un error
    /// del `State` se registra y el caller lo convierte en `VmError`.
    ///
    /// El overlay de código gana sobre el `State`: un contrato creado en esta
    /// misma tx todavía no existe para el `State`.
    pub fn code_of(&mut self, addr: Address) -> Bytes {
        if let Some(code) = self.code.get(&addr) {
            return code.clone();
        }
        let code_hash = self.account_info(addr).2;
        match self.state.code(code_hash) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.record_error(err);
                Bytes::new()
            }
        }
    }

    // ------------------------------------------- creación y destrucción (2.6)

    /// Deposita el código de un contrato recién creado (journaled).
    pub fn set_code(&mut self, addr: Address, code: Bytes) {
        self.entries.push(JournalEntry::CodeDeposited { addr });
        self.code.insert(addr, code);
    }

    /// Marca la dirección como creada en ESTA tx (EIP-6780). Journaled: si el
    /// frame de creación revierte, la marca se va con él.
    pub fn mark_created(&mut self, addr: Address) {
        if self.created.insert(addr) {
            self.entries.push(JournalEntry::AccountCreated { addr });
        }
    }

    /// ¿La cuenta se creó en esta tx? Es la condición ÚNICA de EIP-6780 para
    /// que SELFDESTRUCT destruya de verdad.
    pub fn is_created_in_tx(&self, addr: Address) -> bool {
        self.created.contains(&addr)
    }

    /// ¿La dirección ya está ocupada? Regla de colisión de CREATE, literal a
    /// revm (`create_account_checkpoint`): **código no vacío O `nonce != 0`**.
    /// El balance NO cuenta (se le puede mandar ETH a una dirección futura).
    pub fn is_create_collision(&mut self, addr: Address) -> bool {
        self.nonce(addr) != 0 || self.code_hash_of(addr) != KECCAK256_EMPTY
    }

    /// Mete `addr` en el accessed set (EIP-2929) y devuelve si estaba fría.
    /// Público porque el executor warmea la dirección del contrato nuevo
    /// ANTES del checkpoint de la creación (orden de revm: la dirección queda
    /// warm incluso si la creación falla).
    pub fn warm(&mut self, addr: Address) -> bool {
        self.warm_address(addr)
    }

    // ------------------------------------------------------------ el diff

    /// El diff de la tx: balances y nonces que DIFIEREN del `State`, más el
    /// storage cambiado. Orden determinista (`BTreeMap` por address).
    ///
    /// El filtro "difiere del `State`" es lo que mantiene la semántica de
    /// EIP-161: una cuenta apenas tocada (un `BALANCE`, una call de value 0)
    /// no genera update, así que no se crea una cuenta vacía en el trie.
    pub fn state_changes(&self) -> Result<StateChanges, StateError> {
        let mut updates: BTreeMap<Address, AccountUpdate> = BTreeMap::new();
        for (addr, balance) in &self.balances {
            let (state_balance, _, _) = self.state_account_info(*addr)?;
            if *balance == state_balance {
                continue;
            }
            updates
                .entry(*addr)
                .or_insert_with(|| empty_update(*addr))
                .balance = Some(*balance);
        }
        for (addr, nonce) in &self.nonces {
            let (_, state_nonce, _) = self.state_account_info(*addr)?;
            if *nonce == state_nonce {
                continue;
            }
            updates
                .entry(*addr)
                .or_insert_with(|| empty_update(*addr))
                .nonce = Some(*nonce);
        }
        for (addr, code) in &self.code {
            updates
                .entry(*addr)
                .or_insert_with(|| empty_update(*addr))
                .code = Some(code.clone());
        }
        for (addr, storage) in self.storage_changes() {
            updates
                .entry(addr)
                .or_insert_with(|| empty_update(addr))
                .storage = storage;
        }
        // EIP-6780: la cuenta destruida se borra ENTERA. El update es
        // exclusivo (el consumidor ni mira el resto de los campos), así que se
        // sobrescribe lo que hubieran puesto los overlays.
        for addr in &self.destroyed {
            updates.insert(
                *addr,
                AccountUpdate {
                    address: *addr,
                    destroyed: true,
                    ..AccountUpdate::default()
                },
            );
        }
        Ok(updates.into_values().collect())
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
            JournalEntry::BalanceChanged { addr, previous } => {
                self.balances.insert(addr, previous);
            }
            JournalEntry::NonceChanged { addr, previous } => {
                self.nonces.insert(addr, previous);
            }
            JournalEntry::CodeDeposited { addr } => {
                self.code.remove(&addr);
            }
            JournalEntry::AccountCreated { addr } => {
                self.created.remove(&addr);
            }
            JournalEntry::AccountDestroyed { addr } => {
                self.destroyed.remove(&addr);
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

    /// `(balance, nonce, code_hash)` del `State`, sin overlay. Read-through
    /// fail-closed: un error se registra y el caller lo convierte en `VmError`
    /// (jamás se aproxima como cuenta inexistente).
    fn account_info(&mut self, addr: Address) -> (U256, u64, B256) {
        match self.state_account_info(addr) {
            Ok(info) => info,
            Err(err) => {
                self.record_error(err);
                (U256::ZERO, 0, KECCAK256_EMPTY)
            }
        }
    }

    /// `code_hash` de una cuenta con el overlay de código encima: un contrato
    /// creado en esta tx no existe todavía para el `State`, y su hash real es
    /// lo que EXTCODEHASH/EIP-161 tienen que ver.
    fn code_hash_of(&mut self, addr: Address) -> B256 {
        if let Some(code) = self.code.get(&addr) {
            if code.is_empty() {
                return KECCAK256_EMPTY;
            }
            return keccak256(code);
        }
        self.account_info(addr).2
    }

    /// Igual que `account_info` pero propagando el error: lo usa el diff, que
    /// SÍ puede devolver `Result` (y no debe tragarse un `State` roto).
    fn state_account_info(&self, addr: Address) -> Result<(U256, u64, B256), StateError> {
        Ok(match self.state.account(addr)? {
            Some(info) => (info.balance, info.nonce, info.code_hash),
            None => (U256::ZERO, 0, KECCAK256_EMPTY),
        })
    }

    /// Balance/code_hash/vacuidad de una cuenta (slice 2.4, ampliado en 2.5):
    /// balance y nonce salen de los overlays vivos de la tx (transfers de
    /// sub-calls, gas prepagado, bump de nonce); el `code_hash` sale del
    /// `State` — sin CREATE (2.6) ninguna cuenta puede estrenar código dentro
    /// de la tx.
    fn account_load(&mut self, addr: Address) -> AccountLoad {
        let code_hash = self.code_hash_of(addr);
        let balance = self.balance(addr);
        let nonce = self.nonce(addr);
        // EIP-161: inexistente O (nonce=0 ∧ balance=0 ∧ code vacío). Una
        // cuenta inexistente lee (0, 0, KECCAK256_EMPTY) ⇒ el mismo predicado
        // la cubre sin una rama de `exists` aparte.
        let is_empty = nonce == 0 && balance.is_zero() && code_hash == KECCAK256_EMPTY;
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

    fn self_balance(&mut self, addr: Address) -> U256 {
        self.balance(addr)
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
        let data = self.code_of(addr);
        StateLoad { data, is_cold }
    }

    /// SELFDESTRUCT (EIP-6780), en el orden exacto de revm
    /// (`journal/inner.rs::selfdestruct`):
    /// 1. cargar (y warmear) el `beneficiary`; su vacuidad EIP-161 se mide
    ///    ANTES de recibir nada — después siempre existiría.
    /// 2. si `beneficiary != addr`, moverle TODO el balance de `addr`.
    /// 3. si `addr` se creó en esta tx: marcarla destruida y dejar su balance
    ///    en 0 (con `beneficiary == addr` eso equivale a **quemar** el saldo).
    /// 4. si NO se creó en esta tx: la cuenta **sobrevive** con su código y su
    ///    storage; solo se movió el balance. Ese es el cambio de 6780.
    fn selfdestruct(
        &mut self,
        addr: Address,
        beneficiary: Address,
    ) -> StateLoad<SelfDestructResult> {
        let is_cold = self.warm_address(beneficiary);
        let target_exists = !self.account_load(beneficiary).is_empty;
        let balance = self.balance(addr);
        let had_value = !balance.is_zero();
        let previously_destroyed = self.destroyed.contains(&addr);

        if addr != beneficiary {
            // No puede fallar: se mueve exactamente el balance que hay.
            if self.transfer(addr, beneficiary, balance).is_err() {
                self.record_error(StateError::Database(alloc::string::String::from(
                    "SELFDESTRUCT no pudo mover el balance completo (invariante rota)",
                )));
            }
        }
        if self.is_created_in_tx(addr) {
            if addr == beneficiary && self.debit(addr, balance).is_err() {
                self.record_error(StateError::Database(alloc::string::String::from(
                    "SELFDESTRUCT no pudo quemar el balance propio (invariante rota)",
                )));
            }
            if self.destroyed.insert(addr) {
                self.entries.push(JournalEntry::AccountDestroyed { addr });
            }
        }

        StateLoad {
            data: SelfDestructResult {
                had_value,
                target_exists,
                previously_destroyed,
            },
            is_cold,
        }
    }
}

/// `AccountUpdate` sin cambios: el esqueleto que rellena `state_changes`.
fn empty_update(address: Address) -> AccountUpdate {
    AccountUpdate {
        address,
        ..AccountUpdate::default()
    }
}
