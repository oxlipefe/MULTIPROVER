//! `OwnVm` — la implementación propia del seam `Vm`.
//!
//! **Slice 2.2** (task 004): `execute_tx` para transferencias puras (Fase 1,
//! intacto) **más** ejecución de contratos de un solo frame sobre el `Journal`
//! (storage, refunds, transient, revert). TODO lo demás sigue siendo `Err`
//! explícito o `Halt` — ejecutar "aproximadamente" sería divergencia
//! silenciosa de consenso. CREATE (2.6), sub-calls (2.5), precompiles (2.8) y
//! los tipos de tx 2930/4844/7702 (2.7) siguen fail-closed.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::ToString;

use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{Address, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::transaction::{Transaction, TxType};

use crate::error::{ConsensusError, InternalError, VmError};
use crate::execution::{self, FrameOutcome};
use crate::result::{ExecutionOutcome, StateChanges};
use crate::state::State;
use crate::types::{AccountInfo, BlockEnv, CallRequest, Spec, StateOverrides};
use crate::vm::Vm;

/// Costo base de toda transacción (`G_transaction`, Yellow Paper).
pub const TX_BASE_GAS: u64 = 21_000;
/// Costo por byte de calldata distinto de cero (EIP-2028).
pub const TX_DATA_NONZERO_GAS: u64 = 16;
/// Costo por byte de calldata igual a cero.
pub const TX_DATA_ZERO_GAS: u64 = 4;
/// EIP-7623 (Prague) — "tokens" de calldata: 1 por byte cero, 4 por no-cero.
pub const TX_DATA_NONZERO_TOKENS: u64 = 4;
/// EIP-7623 (Prague) — costo por token del floor de calldata.
pub const TX_TOTAL_COST_FLOOR_PER_TOKEN: u64 = 10;

/// La implementación propia del seam `Vm` de zeth (slice de Fase 1).
#[derive(Debug, Clone, Default)]
pub struct OwnVm;

impl OwnVm {
    pub fn new() -> Self {
        Self
    }
}

/// Bytes cero / no-cero de la calldata (la base de EIP-2028 y EIP-7623).
fn calldata_bytes(input: &[u8]) -> Result<(u64, u64), VmError> {
    let zero_bytes = u64::try_from(input.iter().filter(|b| **b == 0).count())
        .map_err(|_| internal("calldata irrepresentable"))?;
    let total_bytes =
        u64::try_from(input.len()).map_err(|_| internal("calldata irrepresentable"))?;
    let nonzero_bytes = total_bytes
        .checked_sub(zero_bytes)
        .ok_or_else(|| internal("conteo de calldata inconsistente"))?;
    Ok((zero_bytes, nonzero_bytes))
}

/// Gas intrínseco de una tx: base + calldata (EIP-2028).
pub fn intrinsic_gas(input: &[u8]) -> Result<u64, VmError> {
    let (zero_bytes, nonzero_bytes) = calldata_bytes(input)?;
    zero_bytes
        .checked_mul(TX_DATA_ZERO_GAS)
        .and_then(|z| {
            nonzero_bytes
                .checked_mul(TX_DATA_NONZERO_GAS)
                .map(|nz| (z, nz))
        })
        .and_then(|(z, nz)| z.checked_add(nz))
        .and_then(|data| TX_BASE_GAS.checked_add(data))
        .ok_or_else(|| internal("overflow calculando gas intrínseco"))
}

/// EIP-7623 (Prague) — floor de calldata: `21000 + 10 · tokens`, con
/// `tokens = ceros + 4 · no-ceros`.
///
/// **Scope:** el EIP completo (validación de la tx contra el floor + piso del
/// gas cobrado) es el slice 2.7. Acá se calcula SOLO para poder **rechazar
/// explícito** las txs en las que el floor mordería: aplicar medio EIP sería
/// divergencia silenciosa; no aplicarlo, también.
pub fn calldata_floor_gas(input: &[u8]) -> Result<u64, VmError> {
    let (zero_bytes, nonzero_bytes) = calldata_bytes(input)?;
    nonzero_bytes
        .checked_mul(TX_DATA_NONZERO_TOKENS)
        .and_then(|nz| zero_bytes.checked_add(nz))
        .and_then(|tokens| tokens.checked_mul(TX_TOTAL_COST_FLOOR_PER_TOKEN))
        .and_then(|floor| TX_BASE_GAS.checked_add(floor))
        .ok_or_else(|| internal("overflow calculando el floor de calldata (EIP-7623)"))
}

/// Balance de `to` al arrancar el frame de ejecución (`SELFBALANCE`,
/// `interpreter::host::Host::self_balance`, slice 2.3): ya refleja el value
/// entrante de la tx y, si `to == sender` (self-call), el gas prepagado —
/// **al precio EFECTIVO**, no el `max_fee` (EIP-1559: lo que realmente se
/// debita por adelantado es `gas_limit · effective_price`; `max_fee` es solo
/// el tope que fija ese efectivo). Compartida por `execute_tx` y `trace_tx`
/// (`execution.rs`) para que la regla tenga una sola fuente de verdad.
pub(crate) fn frame_self_balance(
    tx: &Transaction,
    to: Address,
    sender_balance: U256,
    to_balance: U256,
    effective_price: u128,
) -> Result<U256, VmError> {
    let gas_prepaid = U256::from(tx.gas_limit)
        .checked_mul(U256::from(effective_price))
        .ok_or_else(|| internal("overflow calculando el gas prepagado"))?;
    if to == tx.sender {
        sender_balance
            .checked_sub(gas_prepaid)
            .ok_or_else(|| internal("balance insuficiente para el prepago de gas (invariante rota)"))
    } else {
        to_balance
            .checked_add(tx.value)
            .ok_or_else(|| internal("overflow acreditando el value en self_balance"))
    }
}

fn internal(msg: &str) -> VmError {
    VmError::Internal(InternalError::EvmInternal(msg.to_string()))
}

fn consensus(err: ConsensusError) -> VmError {
    VmError::Consensus(err)
}

fn invalid_tx(msg: &str) -> VmError {
    consensus(ConsensusError::InvalidTransaction(msg.to_string()))
}

/// ¿La cuenta tiene código? (EIP-3607 para el sender; gate del slice para el
/// destino). `code_hash == KECCAK256_EMPTY` o cuenta inexistente = sin código.
fn has_code(account: Option<&AccountInfo>) -> bool {
    account.is_some_and(|info| info.code_hash != KECCAK256_EMPTY)
}

/// Precio efectivo del gas + tope para el chequeo de balance (fail-closed).
pub(crate) fn gas_prices(tx: &Transaction, env: &BlockEnv) -> Result<(u128, u128), VmError> {
    let base_fee = u128::from(env.base_fee);
    match tx.tx_type {
        TxType::Legacy => {
            let gas_price = tx
                .gas_price
                .ok_or_else(|| internal("tx legacy sin gas_price (malformada)"))?;
            if gas_price < base_fee {
                return Err(invalid_tx("gas_price menor que el base fee del bloque"));
            }
            Ok((gas_price, gas_price))
        }
        TxType::Eip1559 => {
            let max_fee = tx
                .max_fee_per_gas
                .ok_or_else(|| internal("tx 1559 sin max_fee_per_gas (malformada)"))?;
            let max_priority = tx
                .max_priority_fee_per_gas
                .ok_or_else(|| internal("tx 1559 sin max_priority_fee_per_gas (malformada)"))?;
            if max_fee < base_fee {
                return Err(invalid_tx(
                    "max_fee_per_gas menor que el base fee del bloque",
                ));
            }
            if max_priority > max_fee {
                return Err(invalid_tx(
                    "max_priority_fee_per_gas mayor que max_fee_per_gas",
                ));
            }
            let effective = base_fee
                .checked_add(max_priority)
                .map(|candidate| candidate.min(max_fee))
                .ok_or_else(|| internal("overflow calculando el precio efectivo de gas"))?;
            Ok((effective, max_fee))
        }
        TxType::Eip2930 | TxType::Eip4844 | TxType::Eip7702 => Err(internal(
            "tipo de tx no soportado en el slice de Fase 1 (llega en Fase 2)",
        )),
    }
}

impl Vm for OwnVm {
    /// Transferencia pura (Fase 1) o ejecución de contrato single-frame
    /// (slice 2.2). Ver ficha 02 §alcance.
    fn execute_tx(
        &mut self,
        tx: &Transaction,
        env: &BlockEnv,
        state: &dyn State,
    ) -> Result<ExecutionOutcome, VmError> {
        let sender = tx.sender;
        // --- Gates del slice (fail-closed; NO son juicios de consenso) ---
        let to = tx
            .to
            .ok_or_else(|| internal("CREATE no soportado hasta el slice 2.6"))?;
        let to_account = state.account(to)?;

        // --- Validación de consenso de la tx ---
        let sender_account = state.account(sender)?.unwrap_or(AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: KECCAK256_EMPTY,
        });
        if sender_account.code_hash != KECCAK256_EMPTY {
            return Err(invalid_tx("el sender tiene código (EIP-3607)"));
        }
        if tx.nonce != sender_account.nonce {
            return Err(consensus(ConsensusError::NonceInvalid {
                expected: sender_account.nonce,
                actual: tx.nonce,
            }));
        }
        if tx.gas_limit > env.gas_limit {
            return Err(invalid_tx("gas limit de la tx excede el del bloque"));
        }
        let required_gas = intrinsic_gas(&tx.input)?;
        if tx.gas_limit < required_gas {
            return Err(consensus(ConsensusError::IntrinsicGasTooLow {
                required: required_gas,
                available: tx.gas_limit,
            }));
        }
        let (effective_price, balance_check_price) = gas_prices(tx, env)?;
        let max_gas_cost = U256::from(tx.gas_limit)
            .checked_mul(U256::from(balance_check_price))
            .ok_or_else(|| internal("overflow en el costo máximo de gas"))?;
        let required_balance = max_gas_cost
            .checked_add(tx.value)
            .ok_or_else(|| internal("overflow en el balance requerido"))?;
        if sender_account.balance < required_balance {
            return Err(consensus(ConsensusError::InsufficientBalance {
                required: format!("{required_balance}"),
                available: format!("{}", sender_account.balance),
            }));
        }
        // EIP-7623 (Prague), mitad 1: la tx debe pagar al menos el floor.
        let floor_gas = calldata_floor_gas(&tx.input)?;
        let floor_applies = env.spec.is_enabled(Spec::Prague);
        if floor_applies && tx.gas_limit < floor_gas {
            return Err(internal(
                "EIP-7623: gas limit por debajo del floor de calldata (slice 2.7)",
            ));
        }

        // --- Ejecución ---
        let to_balance = to_account.as_ref().map_or(U256::ZERO, |info| info.balance);
        let frame = if has_code(to_account.as_ref()) {
            let code_hash = to_account
                .as_ref()
                .map_or(KECCAK256_EMPTY, |info| info.code_hash);
            let bytecode = state.code(code_hash)?;
            let self_balance = frame_self_balance(
                tx,
                to,
                sender_account.balance,
                to_balance,
                effective_price,
            )?;
            execution::execute_contract(execution::FrameRequest {
                tx,
                env,
                state,
                to,
                bytecode,
                intrinsic_gas: required_gas,
                self_balance,
                effective_price,
            })?
        } else {
            if !tx.input.is_empty() {
                return Err(internal(
                    "calldata hacia una cuenta sin código: EIP-7623 completo llega en 2.7",
                ));
            }
            FrameOutcome::pure_transfer(required_gas)
        };
        // EIP-7623 (Prague), mitad 2: si el floor mordería el gas cobrado,
        // rechazamos explícito en vez de cobrar un número que sabemos falso.
        if floor_applies && floor_gas > frame.gas_charged {
            return Err(internal(
                "EIP-7623: el floor de calldata mordería el gas cobrado (slice 2.7)",
            ));
        }

        let state_changes = settle(
            &Settlement {
                tx,
                env,
                to,
                sender_balance: sender_account.balance,
                sender_nonce: sender_account.nonce,
                to_balance,
                effective_price,
            },
            state,
            frame.gas_charged,
            frame.value_transferred,
            frame.storage_changes,
        )?;

        Ok(ExecutionOutcome {
            result: frame.result,
            state_changes,
            witness: None,
        })
    }

    fn execute_system_call(
        &mut self,
        _to: Address,
        _data: Bytes,
        _env: &BlockEnv,
        _state: &dyn State,
    ) -> Result<ExecutionOutcome, VmError> {
        Err(internal("system calls no implementadas hasta Fase 2"))
    }

    fn begin_block(&mut self, _env: &BlockEnv, _state: &dyn State) -> Result<(), VmError> {
        Err(internal("contexto de bloque no implementado hasta Fase 2"))
    }

    fn transact_in_block(
        &mut self,
        _tx: &Transaction,
        _sender: Address,
    ) -> Result<ExecutionOutcome, VmError> {
        Err(internal("contexto de bloque no implementado hasta Fase 2"))
    }

    fn system_call_in_block(
        &mut self,
        _to: Address,
        _data: Bytes,
    ) -> Result<ExecutionOutcome, VmError> {
        Err(internal("contexto de bloque no implementado hasta Fase 2"))
    }

    fn finish_block(&mut self) -> Result<StateChanges, VmError> {
        Err(internal("contexto de bloque no implementado hasta Fase 2"))
    }

    fn execute_call(
        &mut self,
        _call: &CallRequest,
        _env: &BlockEnv,
        _state: &dyn State,
        _overrides: Option<&StateOverrides>,
    ) -> Result<ExecutionOutcome, VmError> {
        Err(internal("eth_call no implementado hasta Fase 2"))
    }
}

/// Datos de la tx que necesita la liquidación de balances/fees. Agrupados en
/// un struct para no arrastrar 8 parámetros sueltos.
struct Settlement<'a> {
    tx: &'a Transaction,
    env: &'a BlockEnv,
    to: Address,
    sender_balance: U256,
    sender_nonce: u64,
    to_balance: U256,
    effective_price: u128,
}

/// Liquida la tx: fee al sender, tip al coinbase, value al destino (solo si la
/// ejecución tuvo éxito) y el diff de storage del journal. Produce los
/// `AccountUpdate` en orden determinista (`BTreeMap` por address).
fn settle(
    settlement: &Settlement<'_>,
    state: &dyn State,
    gas_charged: u64,
    value_transferred: bool,
    storage_changes: BTreeMap<Address, BTreeMap<U256, U256>>,
) -> Result<StateChanges, VmError> {
    let Settlement {
        tx,
        env,
        to,
        sender_balance,
        sender_nonce,
        to_balance,
        effective_price,
    } = *settlement;
    let sender = tx.sender;

    let fee = U256::from(gas_charged)
        .checked_mul(U256::from(effective_price))
        .ok_or_else(|| internal("overflow en el fee"))?;
    let tip = effective_price
        .checked_sub(u128::from(env.base_fee))
        .ok_or_else(|| internal("precio efectivo menor que base fee (invariante rota)"))?;
    let coinbase_reward = U256::from(gas_charged)
        .checked_mul(U256::from(tip))
        .ok_or_else(|| internal("overflow en el reward del coinbase"))?;
    let moved_value = if value_transferred {
        tx.value
    } else {
        U256::ZERO
    };

    // Balances finales sobre un mapa (maneja to == sender y orden
    // determinista de los updates).
    let mut balances: BTreeMap<Address, U256> = BTreeMap::new();
    balances.insert(sender, sender_balance);
    balances.entry(to).or_insert(to_balance);

    debit(
        &mut balances,
        sender,
        fee.checked_add(moved_value)
            .ok_or_else(|| internal("overflow en el débito del sender"))?,
    )?;
    credit(&mut balances, to, moved_value)?;
    // EIP-161 (slice): no crear el coinbase por un touch de 0 (ficha 02).
    if coinbase_reward > U256::ZERO {
        let coinbase_balance = state
            .account(env.coinbase)?
            .map_or(U256::ZERO, |info| info.balance);
        balances.entry(env.coinbase).or_insert(coinbase_balance);
        credit(&mut balances, env.coinbase, coinbase_reward)?;
    }

    let new_nonce = sender_nonce
        .checked_add(1)
        .ok_or_else(|| internal("overflow de nonce del sender"))?;

    let mut updates: BTreeMap<Address, AccountUpdate> = balances
        .into_iter()
        .map(|(address, balance)| {
            (
                address,
                AccountUpdate {
                    address,
                    balance: Some(balance),
                    nonce: (address == sender).then_some(new_nonce),
                    code: None,
                    storage: BTreeMap::new(),
                    destroyed: false,
                },
            )
        })
        .collect();
    for (address, storage) in storage_changes {
        updates
            .entry(address)
            .or_insert_with(|| AccountUpdate {
                address,
                ..AccountUpdate::default()
            })
            .storage = storage;
    }
    Ok(updates.into_values().collect())
}

fn debit(
    balances: &mut BTreeMap<Address, U256>,
    address: Address,
    amount: U256,
) -> Result<(), VmError> {
    let balance = balances
        .get_mut(&address)
        .ok_or_else(|| internal("débito sobre cuenta no cargada (bug)"))?;
    *balance = balance
        .checked_sub(amount)
        .ok_or_else(|| internal("débito con underflow (el chequeo de balance debió atraparlo)"))?;
    Ok(())
}

fn credit(
    balances: &mut BTreeMap<Address, U256>,
    address: Address,
    amount: U256,
) -> Result<(), VmError> {
    let balance = balances
        .get_mut(&address)
        .ok_or_else(|| internal("crédito sobre cuenta no cargada (bug)"))?;
    *balance = balance
        .checked_add(amount)
        .ok_or_else(|| internal("overflow de balance del receptor"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::string::ToString;
    use alloc::vec;

    use repo_b_common::primitives::B256;

    use super::*;
    use crate::error::StateError;
    use crate::result::ExecutionResult;
    use crate::types::CodeMetadata;

    /// State en memoria para tests (BTreeMap: determinista).
    #[derive(Debug, Clone, Default)]
    struct MockState {
        accounts: BTreeMap<Address, AccountInfo>,
    }

    impl State for MockState {
        fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
            Ok(self.accounts.get(&addr).cloned())
        }
        fn storage(&self, _addr: Address, _key: U256) -> Result<U256, StateError> {
            Ok(U256::ZERO)
        }
        /// Fail-closed: este mock no sirve bytecode. Una cuenta con
        /// `code_hash != KECCAK256_EMPTY` acá es código irresoluble.
        fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
            if code_hash == KECCAK256_EMPTY {
                return Ok(Bytes::new());
            }
            Err(StateError::Database(alloc::format!(
                "código desconocido: {code_hash}"
            )))
        }
        fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
            Ok(CodeMetadata::Regular)
        }
        fn block_hash(&self, _number: u64) -> Result<B256, StateError> {
            Ok(B256::ZERO)
        }
    }

    const SENDER: Address = Address::new([0xAA; 20]);
    const RECEIVER: Address = Address::new([0xBB; 20]);
    const COINBASE: Address = Address::new([0xCC; 20]);
    const BASE_FEE: u64 = 10;

    fn env() -> BlockEnv {
        BlockEnv {
            spec: Spec::Prague,
            chain_id: 1,
            number: 1,
            coinbase: COINBASE,
            timestamp: 1000,
            gas_limit: 10_000_000,
            base_fee: BASE_FEE,
            prevrandao: B256::ZERO,
            blob_excess_gas: Some(0),
            blob_base_fee: Some(1),
            blob_base_fee_update_fraction: None,
        }
    }

    fn eoa(balance: u64, nonce: u64) -> AccountInfo {
        AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash: KECCAK256_EMPTY,
        }
    }

    fn state_with_sender(balance: u64) -> MockState {
        let mut accounts = BTreeMap::new();
        accounts.insert(SENDER, eoa(balance, 0));
        MockState { accounts }
    }

    fn legacy_transfer(value: u64, gas_price: u128) -> Transaction {
        Transaction {
            tx_type: TxType::Legacy,
            sender: SENDER,
            nonce: 0,
            to: Some(RECEIVER),
            value: U256::from(value),
            input: Bytes::new(),
            gas_limit: 100_000,
            gas_price: Some(gas_price),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
        }
    }

    fn find_update(changes: &StateChanges, addr: Address) -> Option<&AccountUpdate> {
        changes.iter().find(|update| update.address == addr)
    }

    #[track_caller]
    fn must_execute(result: Result<ExecutionOutcome, VmError>) -> ExecutionOutcome {
        match result {
            Ok(outcome) => outcome,
            Err(err) => panic!("debia ejecutar, fallo con: {err}"),
        }
    }

    #[track_caller]
    fn must_fail(result: Result<ExecutionOutcome, VmError>) -> VmError {
        match result {
            Ok(_) => panic!("debia rechazar y ejecuto"),
            Err(err) => err,
        }
    }

    #[test]
    fn legacy_transfer_updates_sender_and_receiver_exactly() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        // gas_price == base_fee: tip 0.
        let outcome =
            must_execute(vm.execute_tx(&legacy_transfer(7, u128::from(BASE_FEE)), &env(), &state));
        assert!(matches!(
            outcome.result,
            ExecutionResult::Success {
                gas_used: TX_BASE_GAS,
                gas_refunded: 0,
                ..
            }
        ));
        let sender = find_update(&outcome.state_changes, SENDER)
            .unwrap_or_else(|| panic!("update del sender"));
        // 10_000_000 - 21000·10 - 7 = 9_789_993.
        assert_eq!(sender.balance, Some(U256::from(9_789_993u64)));
        assert_eq!(sender.nonce, Some(1));
        let receiver = find_update(&outcome.state_changes, RECEIVER)
            .unwrap_or_else(|| panic!("update del receiver"));
        assert_eq!(receiver.balance, Some(U256::from(7u64)));
        assert_eq!(receiver.nonce, None);
        // Tip 0: el coinbase NO se toca (EIP-161, slice).
        assert!(find_update(&outcome.state_changes, COINBASE).is_none());
    }

    #[test]
    fn eip1559_transfer_pays_tip_to_coinbase() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let tx = Transaction {
            tx_type: TxType::Eip1559,
            gas_price: None,
            max_fee_per_gas: Some(20),
            max_priority_fee_per_gas: Some(3),
            ..legacy_transfer(1, 0)
        };
        let outcome = must_execute(vm.execute_tx(&tx, &env(), &state));
        // effective = min(20, 10+3) = 13; tip = 3.
        let coinbase = find_update(&outcome.state_changes, COINBASE)
            .unwrap_or_else(|| panic!("update del coinbase"));
        assert_eq!(coinbase.balance, Some(U256::from(63_000u64))); // 21000 · tip 3
        let sender = find_update(&outcome.state_changes, SENDER)
            .unwrap_or_else(|| panic!("update del sender"));
        // 10_000_000 - 21000·13 - 1 = 9_726_999.
        assert_eq!(sender.balance, Some(U256::from(9_726_999u64)));
    }

    #[test]
    fn self_transfer_only_pays_the_fee() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let mut tx = legacy_transfer(500, u128::from(BASE_FEE));
        tx.to = Some(SENDER);
        let outcome = must_execute(vm.execute_tx(&tx, &env(), &state));
        let sender = find_update(&outcome.state_changes, SENDER)
            .unwrap_or_else(|| panic!("update del sender"));
        // Solo el fee: 10_000_000 - 210_000 = 9_790_000 (el value vuelve).
        assert_eq!(sender.balance, Some(U256::from(9_790_000u64)));
        assert_eq!(outcome.state_changes.len(), 1);
    }

    #[test]
    fn wrong_nonce_is_a_consensus_error() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000);
        let mut tx = legacy_transfer(1, u128::from(BASE_FEE));
        tx.nonce = 5;
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::NonceInvalid {
                expected: 0,
                actual: 5
            })
        ));
    }

    #[test]
    fn insufficient_balance_is_a_consensus_error() {
        let mut vm = OwnVm::new();
        // Alcanza para el value pero no para value + gas máximo.
        let state = state_with_sender(50_000);
        let err =
            must_fail(vm.execute_tx(&legacy_transfer(1, u128::from(BASE_FEE)), &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn gas_limit_below_intrinsic_is_a_consensus_error() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000);
        let mut tx = legacy_transfer(1, u128::from(BASE_FEE));
        tx.gas_limit = TX_BASE_GAS - 1;
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::IntrinsicGasTooLow {
                required: TX_BASE_GAS,
                ..
            })
        ));
    }

    #[test]
    fn gas_price_below_base_fee_is_a_consensus_error() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000);
        let err = must_fail(vm.execute_tx(
            &legacy_transfer(1, u128::from(BASE_FEE - 1)),
            &env(),
            &state,
        ));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn sender_with_code_is_rejected_eip3607() {
        let mut vm = OwnVm::new();
        let mut state = state_with_sender(1_000_000);
        if let Some(account) = state.accounts.get_mut(&SENDER) {
            account.code_hash = B256::new([0x11; 32]);
        }
        let err =
            must_fail(vm.execute_tx(&legacy_transfer(1, u128::from(BASE_FEE)), &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    /// Desde el slice 2.2 el código SÍ se ejecuta; lo que sigue fail-closed es
    /// el código **irresoluble** (el `State` no puede servir el bytecode del
    /// `code_hash`) — nunca se aproxima como "cuenta sin código".
    #[test]
    fn receiver_with_unresolvable_code_is_fail_closed_internal_error() {
        let mut vm = OwnVm::new();
        let mut state = state_with_sender(10_000_000);
        state.accounts.insert(
            RECEIVER,
            AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: B256::new([0x22; 32]),
            },
        );
        let err =
            must_fail(vm.execute_tx(&legacy_transfer(1, u128::from(BASE_FEE)), &env(), &state));
        assert!(matches!(err, VmError::Internal(_)));
    }

    #[test]
    fn create_and_calldata_are_fail_closed_internal_errors() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000);
        let mut create_tx = legacy_transfer(0, u128::from(BASE_FEE));
        create_tx.to = None;
        assert!(matches!(
            vm.execute_tx(&create_tx, &env(), &state),
            Err(VmError::Internal(_))
        ));
        let mut data_tx = legacy_transfer(0, u128::from(BASE_FEE));
        data_tx.input = Bytes::from(vec![0x01]);
        assert!(matches!(
            vm.execute_tx(&data_tx, &env(), &state),
            Err(VmError::Internal(_))
        ));
    }

    #[test]
    fn intrinsic_gas_counts_zero_and_nonzero_bytes() {
        // 2 bytes cero (4 c/u) + 3 no-cero (16 c/u) = 21000 + 8 + 48.
        let data = [0x00, 0x00, 0x01, 0xFF, 0x7A];
        assert_eq!(intrinsic_gas(&data).map_err(|e| e.to_string()), Ok(21_056));
        assert_eq!(
            intrinsic_gas(&[]).map_err(|e| e.to_string()),
            Ok(TX_BASE_GAS)
        );
    }

    #[test]
    fn state_trait_object_still_clones() {
        // El seam exige Box<dyn State>: Clone (DynCloneState). Humo mínimo.
        let boxed: Box<dyn State> = Box::new(state_with_sender(1));
        let cloned = boxed.clone();
        assert!(matches!(cloned.account(SENDER), Ok(Some(_))));
    }
}
