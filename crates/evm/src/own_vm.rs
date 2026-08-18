//! `OwnVm` — la implementación propia del seam `Vm`.
//!
//! ****: `OwnVm` valida la tx y delega la ejecución a
//! `execution::execute_tx`, que corre el árbol de frames sobre el `Journal`
//! (storage, logs, entorno, extcode, **calls anidadas**, refunds, revert).
//! Este módulo se quedó con lo que le corresponde: las reglas de consenso
//! **de la tx** (nonce, balance, EIP-3607/1559/2028/7623) y los gates
//! fail-closed del slice. TODO lo demás sigue siendo `Err` explícito o
//! `Halt` — ejecutar "aproximadamente" sería divergencia silenciosa de
//! consenso. Las precompiles y los tipos de tx 2930/4844/7702
//! siguen fail-closed.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use repo_b_common::access_list::AccessList;
use repo_b_common::account::AccountUpdate;
use repo_b_common::authorization::{AuthorizationList, delegation_target};
use repo_b_common::primitives::{Address, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::receipt::Receipt;
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::withdrawal::Withdrawal;
use repo_b_interpreter::MAX_INITCODE_SIZE;
use repo_b_interpreter::gas::cost;

use crate::block::BlockState;
use crate::error::{ConsensusError, InternalError, VmError};
use crate::execution;
use crate::result::{ExecutionOutcome, ExecutionResult, StateChanges};
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
/// EIP-2930 — costo por dirección declarada en la access list.
/// Verificado contra `revm` (`gas::ACCESS_LIST_ADDRESS`).
pub const TX_ACCESS_LIST_ADDRESS_GAS: u64 = 2_400;
/// EIP-2930 — costo por storage key declarada en la access list.
/// Verificado contra `revm` (`gas::ACCESS_LIST_STORAGE_KEY`).
pub const TX_ACCESS_LIST_STORAGE_KEY_GAS: u64 = 1_900;
/// EIP-7702 — costo intrínseco por CADA tupla de la
/// authorization list, cobrado siempre (se aplique o no la autorización).
/// Verificado contra `revm` (`primitives::eip7702::PER_EMPTY_ACCOUNT_COST` y
/// `GasParams::initial_tx_gas`, tabla PRAGUE): el cobro es el **pesimista**
/// (cuenta nueva) y el caso "la cuenta ya existía" se compensa con un refund,
/// no con un cobro menor.
pub const TX_AUTH_PER_EMPTY_ACCOUNT_GAS: u64 = 25_000;
/// EIP-7702 — costo base por tupla (`PER_AUTH_BASE_COST`). No se cobra
/// directamente: es el sustraendo del refund de abajo.
pub const TX_AUTH_BASE_GAS: u64 = 12_500;
/// EIP-7702 — refund por autorización **aplicada** sobre una cuenta que YA
/// existía (`PER_EMPTY_ACCOUNT_COST − PER_AUTH_BASE_COST`). Entra al contador
/// global de EIP-3529 (capado a `gas_used/5`) y **sobrevive a un revert o un
/// halt** del frame raíz.
pub const AUTH_EXISTING_ACCOUNT_REFUND: u64 = TX_AUTH_PER_EMPTY_ACCOUNT_GAS - TX_AUTH_BASE_GAS;
/// Bytes por palabra de la EVM (el `⌈len/32⌉` de EIP-3860).
const WORD_BYTES: u64 = 32;
/// EIP-4844 — gas por blob (2¹⁷). Verificado contra `revm`
/// (`primitives::eip4844::GAS_PER_BLOB`).
pub const GAS_PER_BLOB: u64 = 131_072;
/// EIP-4844 — primer byte válido de un blob versioned hash (KZG). Verificado
/// contra `revm` (`primitives::eip4844::VERSIONED_HASH_VERSION_KZG`). Acá se
/// valida SOLO el formato del hash — nunca se verifica el commitment KZG real
/// (precompile `0x0A`; Prohibido de este slice).
const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Lo que el motor lleva mientras un bloque está abierto.
#[derive(Debug, Clone)]
struct BlockContext {
    env: BlockEnv,
    /// El estado del bloque: el `State` de arranque más lo que las txs ya
    /// corridas cambiaron (ver `crate::block`).
    state: BlockState,
    /// EIP-4895. Se declaran al ABRIR el bloque y no antes de cerrarlo: un
    /// setter aparte deja una ventana en la que alguien se las olvida y
    /// `finish_block` produce, en silencio, un bloque sin withdrawals.
    withdrawals: Vec<Withdrawal>,
    cumulative_gas_used: u64,
}

/// La implementación propia del seam `Vm` de zeth.
#[derive(Debug, Clone, Default)]
pub struct OwnVm {
    /// `None` = no hay bloque abierto. `execute_tx` (una tx suelta, sin
    /// bloque) no lo mira: ese camino no cambió.
    block: Option<BlockContext>,
    /// Receipts del bloque en curso — o del último cerrado, porque el trait
    /// devuelve `StateChanges` en `finish_block` y no hay dónde ponerlos.
    /// `begin_block` los limpia.
    receipts: Vec<Receipt>,
}

impl OwnVm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Abre un bloque con sus withdrawals (EIP-4895).
    ///
    /// Método inherente y no del trait: el `Vm` vendoreado no las lleva en
    /// `begin_block` ni en `finish_block`, y ese contrato **no se redefine**.
    /// Meterlas en `BlockEnv` tampoco: `BlockEnv` es lo que ve el intérprete, y
    /// ningún opcode puede observar una withdrawal.
    pub fn begin_block_with_withdrawals(
        &mut self,
        env: &BlockEnv,
        state: &dyn State,
        withdrawals: Vec<Withdrawal>,
    ) -> Result<(), VmError> {
        if self.block.is_some() {
            return Err(internal("begin_block con un bloque todavía abierto"));
        }
        self.receipts.clear();
        self.block = Some(BlockContext {
            env: env.clone(),
            state: BlockState::new(state.clone_state()),
            withdrawals,
            cumulative_gas_used: 0,
        });
        Ok(())
    }

    /// Los receipts del bloque, en orden de ejecución. Válidos mientras el
    /// bloque está abierto y después de `finish_block`, hasta el próximo
    /// `begin_block`.
    #[must_use]
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }
}

/// EIP-4895: acredita las withdrawals al cerrar el bloque.
///
/// Reglas, en el orden de `execution-specs::process_withdrawal`:
/// 1. el `amount` viene en **Gwei** y se acredita en Wei;
/// 2. la cuenta se crea si no existía;
/// 3. si DESPUÉS de acreditar la cuenta queda vacía (EIP-161: nonce 0, balance
///    0, sin código) y existía, se borra. Es la interacción con EIP-161 que
///    hace que una withdrawal de monto cero no deje una cuenta vacía en el
///    trie — ni una nueva, ni una que ya estaba.
///
/// Varias withdrawals a la MISMA dirección se acumulan: cada una lee el estado
/// que dejó la anterior, porque el diff se aplica al overlay en el acto.
fn apply_withdrawals(block: &mut BlockContext) -> Result<(), VmError> {
    let BlockContext {
        withdrawals, state, ..
    } = block;
    for withdrawal in withdrawals.iter() {
        let existing = state.account(withdrawal.address)?;
        let (balance, nonce, code_hash) = existing
            .as_ref()
            .map_or((U256::ZERO, 0, KECCAK256_EMPTY), |account| {
                (account.balance, account.nonce, account.code_hash)
            });
        let credited = balance
            .checked_add(withdrawal.amount_wei())
            .ok_or_else(|| internal("overflow acreditando una withdrawal"))?;
        let stays_empty = credited.is_zero() && nonce == 0 && code_hash == KECCAK256_EMPTY;
        if stays_empty {
            if existing.is_none() {
                // No existía y sigue sin existir: no hay nada que escribir.
                continue;
            }
            state.apply(&[AccountUpdate {
                address: withdrawal.address,
                destroyed: true,
                ..AccountUpdate::default()
            }]);
            continue;
        }
        state.apply(&[AccountUpdate {
            address: withdrawal.address,
            balance: Some(credited),
            ..AccountUpdate::default()
        }]);
    }
    Ok(())
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

/// EIP-2930: costo de la access list declarada — `direcciones ·
/// 2400 + Σ(storage_keys) · 1900`, cobrado por CADA entrada tal cual viene en
/// la tx, sin dedup (una dirección repetida, o una que coincide con `to`,
/// paga las dos veces: el fee es por lo que el usuario declaró, no por lo que
/// efectivamente cambia de frío a caliente).
fn access_list_gas(access_list: &AccessList) -> Result<u64, VmError> {
    let addresses =
        u64::try_from(access_list.len()).map_err(|_| internal("access list irrepresentable"))?;
    let mut storage_keys: u64 = 0;
    for item in access_list {
        let keys = u64::try_from(item.storage_keys.len())
            .map_err(|_| internal("access list irrepresentable"))?;
        storage_keys = storage_keys
            .checked_add(keys)
            .ok_or_else(|| internal("overflow contando storage keys de la access list"))?;
    }
    addresses
        .checked_mul(TX_ACCESS_LIST_ADDRESS_GAS)
        .and_then(|addr_cost| {
            storage_keys
                .checked_mul(TX_ACCESS_LIST_STORAGE_KEY_GAS)
                .map(|key_cost| (addr_cost, key_cost))
        })
        .and_then(|(addr_cost, key_cost)| addr_cost.checked_add(key_cost))
        .ok_or_else(|| internal("overflow calculando el gas de la access list"))
}

/// EIP-7702: costo de la authorization list declarada
/// `tuplas · 25000`, cobrado por CADA tupla tal cual viene en la tx, sin
/// importar si esa autorización termina aplicándose o salteándose (mismo
/// criterio que la access list: el fee es por lo declarado).
fn authorization_list_gas(authorization_list: &AuthorizationList) -> Result<u64, VmError> {
    u64::try_from(authorization_list.len())
        .ok()
        .and_then(|count| count.checked_mul(TX_AUTH_PER_EMPTY_ACCOUNT_GAS))
        .ok_or_else(|| internal("overflow calculando el gas de la authorization list"))
}

/// Gas intrínseco de una tx: base + calldata (EIP-2028) + access list
/// (EIP-2930) + authorization list (EIP-7702) y, si es una tx de
/// **creación** (`to == None`), `G_txcreate`
/// (32000, EIP-2/Homestead) más el término por palabra de initcode de
/// EIP-3860.
///
/// Verificado contra `revm` (`GasParams::initial_tx_gas`): el término de
/// access list se suma al `base` ANTES de la rama de creación (mismo orden
/// que el source: tokens de calldata + access list + stipend, y RECIÉN
/// DESPUÉS el término de creación) — no hay orden-dependencia observable
/// porque es una suma, pero el orden de líneas sigue al oráculo. Los DOS
/// términos de creación son obligatorios (verificado en el).
pub fn intrinsic_gas(
    input: &[u8],
    is_create: bool,
    access_list: &AccessList,
    authorization_list: &AuthorizationList,
    spec: Spec,
) -> Result<u64, VmError> {
    let (zero_bytes, nonzero_bytes) = calldata_bytes(input)?;
    let calldata_cost = zero_bytes
        .checked_mul(TX_DATA_ZERO_GAS)
        .and_then(|z| {
            nonzero_bytes
                .checked_mul(TX_DATA_NONZERO_GAS)
                .map(|nz| (z, nz))
        })
        .and_then(|(z, nz)| z.checked_add(nz))
        .and_then(|data| TX_BASE_GAS.checked_add(data))
        .ok_or_else(|| internal("overflow calculando gas intrínseco"))?;
    let auth_cost = authorization_list_gas(authorization_list)?;
    let base = calldata_cost
        .checked_add(access_list_gas(access_list)?)
        .and_then(|base| base.checked_add(auth_cost))
        .ok_or_else(|| {
            internal("overflow sumando access list / authorization list al gas intrínseco")
        })?;
    if !is_create {
        return Ok(base);
    }
    let total_bytes =
        u64::try_from(input.len()).map_err(|_| internal("initcode irrepresentable"))?;
    // EIP-3860 (Shanghai): el término de initcode en el gas intrínseco tampoco
    // existe antes de Shanghai.
    let initcode_word = if spec.is_enabled(Spec::Shanghai) {
        cost::INITCODE_WORD
    } else {
        0
    };
    total_bytes
        .div_ceil(WORD_BYTES)
        .checked_mul(initcode_word)
        .and_then(|initcode| initcode.checked_add(cost::CREATE))
        .and_then(|create| base.checked_add(create))
        .ok_or_else(|| internal("overflow calculando el gas intrínseco de creación"))
}

/// EIP-7623 (Prague) — floor de calldata: `21000 + 10 · tokens`, con
/// `tokens = ceros + 4 · no-ceros`.
///
/// **No depende de la access list** (verificado contra `revm`:
/// `tx_floor_cost` solo ve `tokens_in_calldata`) ni de `is_create` (el floor
/// se computa igual para call y create). El llamador valida la tx contra
/// `max(intrinsic_gas, floor_gas)` Y
/// clampea el gas COBRADO real (`execution::settle`) — no solo el reportado.
pub fn calldata_floor_gas(input: &[u8]) -> Result<u64, VmError> {
    let (zero_bytes, nonzero_bytes) = calldata_bytes(input)?;
    nonzero_bytes
        .checked_mul(TX_DATA_NONZERO_TOKENS)
        .and_then(|nz| zero_bytes.checked_add(nz))
        .and_then(|tokens| tokens.checked_mul(TX_TOTAL_COST_FLOOR_PER_TOKEN))
        .and_then(|floor| TX_BASE_GAS.checked_add(floor))
        .ok_or_else(|| internal("overflow calculando el floor de calldata (EIP-7623)"))
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

/// Precio efectivo del gas + tope para el chequeo de balance (fail-closed).
pub(crate) fn gas_prices(tx: &Transaction, env: &BlockEnv) -> Result<(u128, u128), VmError> {
    let base_fee = u128::from(env.base_fee);
    match tx.tx_type {
        // EIP-2930 es anterior a EIP-1559: mismo camino que legacy (gas_price
        // plano, chequeo contra base_fee), sin priority fee.
        TxType::Legacy | TxType::Eip2930 => {
            let gas_price = tx
                .gas_price
                .ok_or_else(|| internal("tx legacy/2930 sin gas_price (malformada)"))?;
            if gas_price < base_fee {
                return Err(invalid_tx("gas_price menor que el base fee del bloque"));
            }
            Ok((gas_price, gas_price))
        }
        // EIP-4844: la porción de EJECUCIÓN de una tx de blob usa
        // el MISMO mecanismo 1559 (verificado contra revm:
        // `validate_priority_fee_for_tx` corre igual para Eip1559/Eip4844/
        // Eip7702). El blob gas tiene su PROPIO precio/tope (`blob_base_fee`/
        // `max_fee_per_blob_gas`, ver `validate_blob_tx`) — mercado de fees
        // separado, nunca mezclado con `effective_price` acá.
        // EIP-7702 entra en el MISMO brazo: no introduce mercado
        // de fee propio (verificado contra revm: `validate_priority_fee_for_tx`
        // corre igual para Eip1559/Eip4844/Eip7702).
        TxType::Eip1559 | TxType::Eip4844 | TxType::Eip7702 => {
            let max_fee = tx
                .max_fee_per_gas
                .ok_or_else(|| internal("tx 1559/4844/7702 sin max_fee_per_gas (malformada)"))?;
            let max_priority = tx.max_priority_fee_per_gas.ok_or_else(|| {
                internal("tx 1559/4844/7702 sin max_priority_fee_per_gas (malformada)")
            })?;
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
    }
}

/// EIP-4844: gas de blob de la tx — `blob_versioned_hashes.len
/// · GAS_PER_BLOB` (aritmética `checked_*`). Vacío en toda tx no-4844 por el
/// invariante de construcción de `Transaction::blob_versioned_hashes` ⇒ 0.
pub(crate) fn total_blob_gas(tx: &Transaction) -> Result<u64, VmError> {
    let count = u64::try_from(tx.blob_versioned_hashes.len())
        .map_err(|_| internal("blob_versioned_hashes irrepresentable"))?;
    count
        .checked_mul(GAS_PER_BLOB)
        .ok_or_else(|| internal("overflow calculando el blob gas"))
}

/// Lo que la validación de una tx de blob le deja a `execute_tx`: el gas de
/// blob ya calculado y el tope declarado por el usuario (necesario para el
/// chequeo de balance máximo, separado del precio real que se cobra).
struct BlobCharge {
    gas_used: u64,
    max_fee_per_blob_gas: u128,
}

/// EIP-4844: validación de una tx de blob — verificado contra
/// revm (`revm-handler::validate_eip4844_tx` + `Transaction::kind()`, cuya
/// doc dice "is Call for EIP-4844 and EIP-7702 transactions"). **Hallazgo del
/// oráculo** (no anticipado por el spec de este slice): revm=38.0.0 NO
/// re-chequea `to`/`kind` en runtime dentro de `validate_tx_env` — el error
/// `InvalidTransaction::BlobCreateTransaction` existe en
/// `revm-context-interface` pero está MUERTO (sin un solo `return Err` que lo
/// construya) en esta versión. Es un invariante de ENCODING: una tx 4844 real
/// (RLP-decodable) no puede representar `to == None` (mismo patrón que la AL
/// vacía de legacy ). Acá igual se valida fail-closed porque
/// `Transaction` (este crate) SÍ permite construir ese estado inválido — el
/// chequeo no diverge de revm porque revm nunca ve ese estado en absoluto.
/// Tope de blobs por tx, **por fork**. EIP-4844 (Cancun) fija el máximo del
/// bloque en `2 × target` con `target = 3` ⇒ **6**; EIP-7691 (Prague) lo sube a
/// **9**. Una tx no puede exceder el máximo del bloque, así que el tope de
/// bloque ES el tope por tx.
///
/// Verificado contra `revm-primitives::eip4844`
/// (`MAX_BLOB_NUMBER_PER_BLOCK_CANCUN = 2 * TARGET(3)`,
/// `MAX_BLOB_NUMBER_PER_BLOCK_PRAGUE = 9`). **Hardcodear uno solo pasa la mitad
/// de los casos**: los fixtures de EEST usan 7 en Cancun y 10 en Prague.
const MAX_BLOBS_PER_TX_CANCUN: usize = 6;
const MAX_BLOBS_PER_TX_PRAGUE: usize = 9;

fn max_blobs_per_tx(spec: Spec) -> usize {
    if spec.is_enabled(Spec::Prague) {
        MAX_BLOBS_PER_TX_PRAGUE
    } else {
        MAX_BLOBS_PER_TX_CANCUN
    }
}

/// EIP-2718: **un tipo de tx no existe antes de su fork**, y una tx de un tipo
/// que todavía no existe es inválida — no "se ejecuta como legacy".
///
/// Orden y reglas literales de `revm-handler::validation::validate_tx_env`:
/// `Eip4844NotSupported` si no hay Cancun, `Eip7702NotSupported` si no hay
/// Prague. Corre ANTES de los chequeos contra la cuenta del sender, igual que
/// en el oráculo.
///
/// Aceptar una tx de un tipo inexistente es **la dirección peligrosa** del
/// comparador: un cliente que ejecuta lo que el protocolo rechaza no produce un
/// test rojo, produce un fork.
fn validate_tx_type(tx: &Transaction, spec: Spec, is_create: bool) -> Result<(), VmError> {
    match tx.tx_type {
        // Berlin (2930) y London (1559) son anteriores a Paris, el piso del
        // scope de este motor, así que sus tipos existen en todos los forks que
        // conoce. Se listan explícitos —y no con `_`— para que agregar una
        // variante nueva a `TxType` no compile hasta decidir su fork.
        TxType::Legacy | TxType::Eip2930 | TxType::Eip1559 => {}
        TxType::Eip4844 => {
            if !spec.is_enabled(Spec::Cancun) {
                return Err(invalid_tx("tx tipo 3 (EIP-4844) antes de Cancun"));
            }
        }
        TxType::Eip7702 => {
            if !spec.is_enabled(Spec::Prague) {
                return Err(invalid_tx("tx tipo 4 (EIP-7702) antes de Prague"));
            }
            // EEST: `TYPE_4_TX_CONTRACT_CREATION`. revm NO lo chequea, y no es
            // un descuido: su sistema de tipos hace el caso irrepresentable.
            // `Transaction` de este crate SÍ permite construirlo, así que para
            // nosotros la regla existe — mismo razonamiento (y misma
            // resolución) que el `to = Some` de 4844.
            if is_create {
                return Err(invalid_tx(
                    "tx tipo 4 con to = None (EIP-7702 prohíbe set-code-create)",
                ));
            }
        }
    }
    Ok(())
}

fn validate_blob_tx(
    tx: &Transaction,
    env: &BlockEnv,
    is_create: bool,
) -> Result<BlobCharge, VmError> {
    if is_create {
        return Err(invalid_tx(
            "tx de blob con to = None (EIP-4844 prohíbe blob-create)",
        ));
    }
    if tx.blob_versioned_hashes.is_empty() {
        return Err(invalid_tx(
            "blob_versioned_hashes vacío: la tx debe declarar al menos 1 blob",
        ));
    }
    for hash in &tx.blob_versioned_hashes {
        if hash.0[0] != VERSIONED_HASH_VERSION_KZG {
            return Err(invalid_tx(
                "blob versioned hash con version distinta de KZG (0x01)",
            ));
        }
    }
    if tx.blob_versioned_hashes.len() > max_blobs_per_tx(env.spec) {
        return Err(invalid_tx("la tx declara más blobs que el tope del fork"));
    }
    let max_fee_per_blob_gas = tx
        .max_fee_per_blob_gas
        .ok_or_else(|| internal("tx 4844 sin max_fee_per_blob_gas (malformada)"))?;
    let block_blob_base_fee =
        u128::from(crate::blob::blob_base_fee(env.blob_excess_gas, env.spec)?);
    if max_fee_per_blob_gas < block_blob_base_fee {
        return Err(invalid_tx(
            "max_fee_per_blob_gas menor que el blob base fee del bloque",
        ));
    }
    Ok(BlobCharge {
        gas_used: total_blob_gas(tx)?,
        max_fee_per_blob_gas,
    })
}

impl Vm for OwnVm {
    /// Valida la tx (consenso) y delega la ejecución..
    fn execute_tx(
        &mut self,
        tx: &Transaction,
        env: &BlockEnv,
        state: &dyn State,
    ) -> Result<ExecutionOutcome, VmError> {
        let sender = tx.sender;
        let is_create = tx.to.is_none();
        // EIP-3860 a nivel tx: un initcode por encima del tope invalida la tx
        // ENTERA (no es un halt del frame, como sí lo es en el opcode).
        // EIP-3860 (Shanghai): antes no hay tope de initcode a nivel tx.
        if is_create && env.spec.is_enabled(Spec::Shanghai) && tx.input.len() > MAX_INITCODE_SIZE {
            return Err(invalid_tx(
                "initcode de la tx por encima de MAX_INITCODE_SIZE (EIP-3860)",
            ));
        }
        // --- Validación de consenso de la tx ---
        // Primero lo que no depende de la cuenta (orden del oráculo:
        // `validate_tx_env` corre antes que `validate_tx_against_account`).
        validate_tx_type(tx, env.spec, is_create)?;
        // EIP-2681: `nonce == u64::MAX` invalida la tx — bumpearlo desbordaría.
        // Sin esto la tx pasa la validación y revienta más adentro con un error
        // INTERNO, que es una falla de otra clase: un motor que no sabe
        // rechazar dice "estoy roto" en vez de "tu tx es inválida".
        if tx.nonce == u64::MAX {
            return Err(invalid_tx("nonce en el máximo de u64 (EIP-2681)"));
        }
        let sender_account = state.account(sender)?.unwrap_or(AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: KECCAK256_EMPTY,
        });
        // EIP-3607: un sender con código no puede originar txs — **salvo que
        // ese código sea un designator de delegación EIP-7702** (verificado
        // contra revm, `validate_account_nonce_and_code`: `!bytecode.is_empty()
        // && !bytecode.is_eip7702()`). Sin esta excepción, el caso canónico de
        // 7702 —una EOA delegada que manda una tx— se rechazaría entero.
        if sender_account.code_hash != KECCAK256_EMPTY {
            let code = state.code(sender_account.code_hash)?;
            if delegation_target(&code).is_none() {
                return Err(invalid_tx("el sender tiene código (EIP-3607)"));
            }
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
        let required_gas = intrinsic_gas(
            &tx.input,
            is_create,
            &tx.access_list,
            &tx.authorization_list,
            env.spec,
        )?;
        // EIP-7623 (Prague): la tx debe cubrir el MAYOR de intrinsic_gas y
        // floor_gas. Verificado contra revm (`validate_initial_tx_gas`): el
        // source hace DOS chequeos independientes con DOS variantes de error
        // (`CallGasCostMoreThanGasLimit`, `GasFloorMoreThanGasLimit`) — acá se
        // colapsan en un `max()` porque `a > L || b > L ⟺ max(a,b) > L`: el
        // resultado observable (tx válida o no) es idéntico, y el Rust
        // `ConsensusError` no es un campo que el diferencial compare (el
        // efecto observable es el mismo: tx inválida).
        let floor_gas = calldata_floor_gas(&tx.input)?;
        let floor_applies = env.spec.is_enabled(Spec::Prague);
        let effective_minimum = if floor_applies {
            required_gas.max(floor_gas)
        } else {
            required_gas
        };
        if tx.gas_limit < effective_minimum {
            return Err(consensus(ConsensusError::IntrinsicGasTooLow {
                required: effective_minimum,
                available: tx.gas_limit,
            }));
        }
        let (effective_price, balance_check_price) = gas_prices(tx, env)?;
        // EIP-4844: blob gas — SIEMPRE separado del gas de
        // ejecución (nunca mezclado con intrinsic_gas/gas_limit/refunds).
        // Verificado contra revm (`Transaction::max_balance_spending` suma el
        // término de blob APARTE del término de ejecución, nunca dentro de
        // `effective_gas_price`).
        let blob = if tx.tx_type == TxType::Eip4844 {
            Some(validate_blob_tx(tx, env, is_create)?)
        } else {
            None
        };
        // EIP-7702: la ÚNICA validación de runtime propia del
        // tipo 4 — lista vacía ⇒ tx inválida (verificado contra revm:
        // `InvalidTransaction::EmptyAuthorizationList`). **`to == None` NO se
        // rechaza**: revm no lo chequea (igual que 4844 ) y ejecuta un
        // CREATE normal; acá pasa exactamente lo mismo.
        if tx.tx_type == TxType::Eip7702 && tx.authorization_list.is_empty() {
            return Err(invalid_tx(
                "authorization_list vacía: una tx EIP-7702 debe declarar al menos 1 tupla",
            ));
        }
        let max_gas_cost = U256::from(tx.gas_limit)
            .checked_mul(U256::from(balance_check_price))
            .ok_or_else(|| internal("overflow en el costo máximo de gas"))?;
        let required_balance = max_gas_cost
            .checked_add(tx.value)
            .ok_or_else(|| internal("overflow en el balance requerido"))?;
        let required_balance = match &blob {
            Some(charge) => {
                let max_blob_cost = U256::from(charge.gas_used)
                    .checked_mul(U256::from(charge.max_fee_per_blob_gas))
                    .ok_or_else(|| internal("overflow en el costo máximo del blob gas"))?;
                required_balance
                    .checked_add(max_blob_cost)
                    .ok_or_else(|| internal("overflow sumando el blob gas al balance requerido"))?
            }
            None => required_balance,
        };
        if sender_account.balance < required_balance {
            return Err(consensus(ConsensusError::InsufficientBalance {
                required: format!("{required_balance}"),
                available: format!("{}", sender_account.balance),
            }));
        }
        // --- Ejecución ---
        // NO hay gate por "el destino no tiene código". Mandar calldata a una
        // cuenta sin código es una tx PERFECTAMENTE VÁLIDA del protocolo: el
        // frame raíz corre bytecode vacío, ejecuta cero opcodes y devuelve
        // `Success` con `gas_used == intrinsic`; la calldata simplemente no la
        // lee nadie. El gate que vivía acá era un resto de la Fase 1 (cuando
        // `OwnVm` solo hacía transferencias puras) y, contra el set real de
        // EEST, era el cluster `execute_error/internal error` de **907 casos**.
        // `execution::prepare` ya resuelve este camino sin ayuda:
        // `code_to_execute(to)` devuelve `Bytes::new()`.
        let outcome = execution::execute_tx(&execution::TxRequest {
            tx,
            env,
            state,
            to: tx.to,
            intrinsic_gas: required_gas,
            effective_price,
            floor_gas,
            blob_gas_used: blob.as_ref().map_or(0, |charge| charge.gas_used),
        })?;

        Ok(ExecutionOutcome {
            result: outcome.result,
            state_changes: outcome.state_changes,
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

    /// Abre el bloque SIN withdrawals. La variante con withdrawals es
    /// `OwnVm::begin_block_with_withdrawals`: el trait vendoreado no las lleva
    /// en ninguna de sus firmas y no se lo redefine.
    fn begin_block(&mut self, env: &BlockEnv, state: &dyn State) -> Result<(), VmError> {
        self.begin_block_with_withdrawals(env, state, Vec::new())
    }

    /// Ejecuta una tx dentro del bloque abierto: mismo camino de consenso que
    /// `execute_tx`, pero contra el estado que ya arrastra las txs anteriores.
    ///
    /// Acumula el gas del bloque y deja el `Receipt` en `receipts()`.
    fn transact_in_block(
        &mut self,
        tx: &Transaction,
        sender: Address,
    ) -> Result<ExecutionOutcome, VmError> {
        // El trait pasa el sender aparte porque el VM no hace recuperación
        // ECDSA. Acá `Transaction` ya lo lleva adentro, así que hay DOS fuentes
        // para el mismo dato: fail-closed si discrepan, en vez de elegir una en
        // silencio.
        if tx.sender != sender {
            return Err(internal(
                "transact_in_block con un sender distinto del de la tx",
            ));
        }
        // El contexto sale del `self` para que `execute_tx` (que pide
        // `&mut self`) pueda correr; vuelve pase lo que pase.
        let Some(mut block) = self.block.take() else {
            return Err(internal("transact_in_block sin un bloque abierto"));
        };
        let executed = self.execute_tx(tx, &block.env, &block.state);
        let outcome = match executed {
            Ok(outcome) => outcome,
            Err(err) => {
                self.block = Some(block);
                return Err(err);
            }
        };
        let settled = block
            .cumulative_gas_used
            .checked_add(outcome.result.gas_used())
            .ok_or_else(|| internal("overflow acumulando el gas del bloque"));
        let cumulative_gas_used = match settled {
            Ok(gas) => gas,
            Err(err) => {
                self.block = Some(block);
                return Err(err);
            }
        };
        block.cumulative_gas_used = cumulative_gas_used;
        block.state.apply(&outcome.state_changes);
        self.receipts.push(Receipt {
            success: outcome.result.is_success(),
            cumulative_gas_used,
            logs: match &outcome.result {
                ExecutionResult::Success { logs, .. } => logs.clone(),
                // Un revert/halt descarta sus logs con el frame.
                ExecutionResult::Revert { .. } | ExecutionResult::Halt { .. } => Vec::new(),
            },
        });
        self.block = Some(block);
        Ok(outcome)
    }

    fn system_call_in_block(
        &mut self,
        _to: Address,
        _data: Bytes,
    ) -> Result<ExecutionOutcome, VmError> {
        Err(internal("system calls no implementadas hasta 2.9c-3"))
    }

    /// Cierra el bloque: aplica las withdrawals (EIP-4895) y devuelve el diff
    /// ACUMULADO de todo el bloque.
    fn finish_block(&mut self) -> Result<StateChanges, VmError> {
        let Some(mut block) = self.block.take() else {
            return Err(internal("finish_block sin un bloque abierto"));
        };
        apply_withdrawals(&mut block)?;
        Ok(block.state.into_changes())
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

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;

    use repo_b_common::account::AccountUpdate;
    use repo_b_common::authorization::{Authorization, delegation_designator};
    use repo_b_common::primitives::B256;

    use super::*;
    use crate::error::StateError;
    use crate::result::ExecutionResult;
    use crate::types::CodeMetadata;

    /// State en memoria para tests (BTreeMap: determinista).
    #[derive(Debug, Clone, Default)]
    struct MockState {
        accounts: BTreeMap<Address, AccountInfo>,
        codes: BTreeMap<B256, Bytes>,
    }

    impl MockState {
        /// Le da código REAL a una cuenta (hasheándolo, como el `State` real).
        fn with_code(mut self, addr: Address, code: Bytes) -> Self {
            let code_hash = repo_b_common::primitives::keccak256(&code);
            let mut account = self.accounts.get(&addr).cloned().unwrap_or(AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: KECCAK256_EMPTY,
            });
            account.code_hash = code_hash;
            self.accounts.insert(addr, account);
            self.codes.insert(code_hash, code);
            self
        }
    }

    impl State for MockState {
        fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
            Ok(self.accounts.get(&addr).cloned())
        }
        fn storage(&self, _addr: Address, _key: U256) -> Result<U256, StateError> {
            Ok(U256::ZERO)
        }
        /// Sin storage: este mock solo tiene cuentas y código.
        fn storage_root(&self, _addr: Address) -> Result<B256, StateError> {
            Ok(repo_b_common::primitives::EMPTY_ROOT_HASH)
        }
        /// Fail-closed: salvo lo cargado con `with_code`, este mock no sirve
        /// bytecode. Una cuenta con `code_hash` desconocido es código
        /// irresoluble.
        fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
            if code_hash == KECCAK256_EMPTY {
                return Ok(Bytes::new());
            }
            self.codes.get(&code_hash).cloned().ok_or_else(|| {
                StateError::Database(alloc::format!("código desconocido: {code_hash}"))
            })
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
        MockState {
            accounts,
            codes: BTreeMap::new(),
        }
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
            access_list: AccessList::new(),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: alloc::vec::Vec::new(),
            authorization_list: AuthorizationList::new(),
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
        // Código real (no un designator): STOP.
        let state = state_with_sender(1_000_000).with_code(SENDER, Bytes::from(vec![0x00]));
        let err =
            must_fail(vm.execute_tx(&legacy_transfer(1, u128::from(BASE_FEE)), &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    /// EIP-7702: la EXCEPCIÓN de EIP-3607 — una EOA **delegada**
    /// sí puede originar transacciones (verificado contra revm,
    /// `validate_account_nonce_and_code`). Sin esto, el caso canónico de 7702
    /// quedaría rechazado de entrada.
    #[test]
    fn a_delegated_sender_is_not_rejected_by_eip3607() {
        let mut vm = OwnVm::new();
        let state =
            state_with_sender(10_000_000).with_code(SENDER, delegation_designator(RECEIVER));
        // El código delegado de RECEIVER es vacío ⇒ el frame raíz corre
        // bytecode vacío y la tx es un éxito trivial: lo que se prueba acá es
        // que NO se rechaza por 3607.
        let mut tx = legacy_transfer(0, u128::from(BASE_FEE));
        tx.to = Some(RECEIVER);
        let outcome = must_execute(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            outcome.result,
            ExecutionResult::Success {
                gas_used: TX_BASE_GAS,
                ..
            }
        ));
    }

    /// Desde el código SÍ se ejecuta; lo que sigue fail-closed es
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

    /// **Mandar calldata a una cuenta sin código es una tx VÁLIDA** — no un
    /// error. El frame raíz corre bytecode vacío, ejecuta cero opcodes, y la
    /// tx cuesta exactamente su gas intrínseco: nadie lee la calldata, pero se
    /// paga igual. Hasta el acá había un gate
    /// `Internal` heredado de la Fase 1 que rechazaba este camino; contra EEST
    /// era el cluster `execute_error/internal error` de **907 casos**.
    ///
    /// Gas: 21000 (`G_transaction`) + 16 (`G_txdatanonzero` × 1 byte no-cero) =
    /// 21016, pero el **floor de EIP-7623** manda: 21000 + 10 × 4 tokens =
    /// 21040. Se cobra el mayor.
    #[test]
    fn calldata_to_a_codeless_account_runs_empty_code_and_succeeds() {
        const EIP7623_FLOOR_ONE_NONZERO_BYTE: u64 = 21_040;

        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000);
        let mut data_tx = legacy_transfer(0, u128::from(BASE_FEE));
        data_tx.input = Bytes::from(vec![0x01]);
        let outcome = must_execute(vm.execute_tx(&data_tx, &env(), &state));
        assert!(
            matches!(
                outcome.result,
                ExecutionResult::Success {
                    gas_used: EIP7623_FLOOR_ONE_NONZERO_BYTE,
                    ..
                }
            ),
            "esperado Success con gas {EIP7623_FLOOR_ONE_NONZERO_BYTE}, obtenido {:?}",
            outcome.result
        );
    }

    /// Una tx de creación con initcode VACÍO es válida y despliega
    /// una cuenta sin código con `nonce = 1` (EIP-161) en `create(sender, 0)`.
    /// El gas intrínseco incluye `G_txcreate` (32000): 21000 + 32000 = 53000.
    #[test]
    fn a_create_transaction_deploys_at_the_derived_address() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let mut create_tx = legacy_transfer(0, u128::from(BASE_FEE));
        create_tx.to = None;

        let outcome = must_execute(vm.execute_tx(&create_tx, &env(), &state));

        assert!(matches!(
            outcome.result,
            ExecutionResult::Success {
                gas_used: 53_000,
                ..
            }
        ));
        let deployed = SENDER.create(0);
        let created = find_update(&outcome.state_changes, deployed)
            .unwrap_or_else(|| panic!("update del contrato creado"));
        assert_eq!(created.nonce, Some(1));
        assert_eq!(created.code, Some(Bytes::new()));
        let sender = find_update(&outcome.state_changes, SENDER)
            .unwrap_or_else(|| panic!("update del sender"));
        assert_eq!(sender.nonce, Some(1));
    }

    /// EIP-3860 a nivel tx: el initcode por encima del tope invalida la tx
    /// ENTERA (error de consenso), no es un halt del frame.
    #[test]
    fn a_create_transaction_over_the_initcode_limit_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000_000);
        let mut create_tx = legacy_transfer(0, u128::from(BASE_FEE));
        create_tx.to = None;
        create_tx.input = Bytes::from(vec![0x00; MAX_INITCODE_SIZE + 1]);
        create_tx.gas_limit = 10_000_000;
        assert!(matches!(
            vm.execute_tx(&create_tx, &env(), &state),
            Err(VmError::Consensus(ConsensusError::InvalidTransaction(_)))
        ));
    }

    #[test]
    fn intrinsic_gas_of_a_create_adds_txcreate_and_the_initcode_term() {
        // 33 bytes no-cero ⇒ 2 palabras: 21000 + 33·16 + 32000 + 2·2 = 53532.
        let initcode = [0x01u8; 33];
        assert_eq!(
            intrinsic_gas(
                &initcode,
                true,
                &AccessList::new(),
                &AuthorizationList::new(),
                Spec::Prague
            )
            .map_err(|e| e.to_string()),
            Ok(53_532)
        );
        assert_eq!(
            intrinsic_gas(
                &[],
                true,
                &AccessList::new(),
                &AuthorizationList::new(),
                Spec::Prague
            )
            .map_err(|e| e.to_string()),
            Ok(TX_BASE_GAS + cost::CREATE)
        );
    }

    #[test]
    fn intrinsic_gas_counts_zero_and_nonzero_bytes() {
        // 2 bytes cero (4 c/u) + 3 no-cero (16 c/u) = 21000 + 8 + 48.
        let data = [0x00, 0x00, 0x01, 0xFF, 0x7A];
        assert_eq!(
            intrinsic_gas(
                &data,
                false,
                &AccessList::new(),
                &AuthorizationList::new(),
                Spec::Prague
            )
            .map_err(|e| e.to_string()),
            Ok(21_056)
        );
        assert_eq!(
            intrinsic_gas(
                &[],
                false,
                &AccessList::new(),
                &AuthorizationList::new(),
                Spec::Prague
            )
            .map_err(|e| e.to_string()),
            Ok(TX_BASE_GAS)
        );
    }

    #[test]
    fn intrinsic_gas_charges_the_access_list_per_entry_without_dedup() {
        use repo_b_common::access_list::AccessListItem;

        // 2 direcciones (una repetida) + 3 storage keys: 2·2400 + 3·1900 = 10500.
        let access_list = alloc::vec![
            AccessListItem {
                address: RECEIVER,
                storage_keys: alloc::vec![B256::ZERO, B256::new([0x01; 32])],
            },
            AccessListItem {
                address: RECEIVER,
                storage_keys: alloc::vec![B256::new([0x02; 32])],
            },
        ];
        assert_eq!(
            intrinsic_gas(
                &[],
                false,
                &access_list,
                &AuthorizationList::new(),
                Spec::Prague
            )
            .map_err(|e| e.to_string()),
            Ok(TX_BASE_GAS + 10_500)
        );
    }

    #[test]
    fn state_trait_object_still_clones() {
        // El seam exige Box<dyn State>: Clone (DynCloneState). Humo mínimo.
        let boxed: Box<dyn State> = Box::new(state_with_sender(1));
        let cloned = boxed.clone();
        assert!(matches!(cloned.account(SENDER), Ok(Some(_))));
    }

    // -------------------------------------------- EIP-4844

    /// Un `B256` con el primer byte fijado (KZG version o uno inválido a
    /// propósito, según el caso), el resto derivado de `tag` para que dos
    /// hashes de un mismo test no colisionen.
    fn hash_with_version(version: u8, tag: u8) -> B256 {
        let mut bytes = [tag; 32];
        bytes[0] = version;
        B256::new(bytes)
    }

    fn kzg_hash(tag: u8) -> B256 {
        hash_with_version(VERSIONED_HASH_VERSION_KZG, tag)
    }

    /// Tx 4844 base: mismo mecanismo 1559 que la porción de ejecución
    /// (`gas_prices` trata `Eip1559`/`Eip4844` igual), gas_limit heredado del
    /// `legacy_transfer` (100_000).
    fn blob_tx(hashes: alloc::vec::Vec<B256>, max_fee_per_blob_gas: Option<u128>) -> Transaction {
        Transaction {
            tx_type: TxType::Eip4844,
            gas_price: None,
            max_fee_per_gas: Some(20),
            max_priority_fee_per_gas: Some(3),
            max_fee_per_blob_gas,
            blob_versioned_hashes: hashes,
            ..legacy_transfer(0, 0)
        }
    }

    // ------------------------------------------ validación de tx por fork

    fn env_at(spec: Spec) -> BlockEnv {
        BlockEnv { spec, ..env() }
    }

    /// Tx tipo 4 válida con `to` explícito. Reusa el `set_code_tx` de más
    /// abajo (una sola forma de armar una tx 7702 en los tests).
    fn set_code_tx_to(to: Option<Address>) -> Transaction {
        Transaction {
            to,
            ..set_code_tx(alloc::vec![authorization(0, Some(RECEIVER))])
        }
    }

    /// EIP-2718: un tipo de tx no existe antes de su fork. Aceptarla es la
    /// dirección peligrosa — un cliente que corre lo que el protocolo rechaza
    /// no da un test rojo, da un fork.
    #[test]
    fn a_blob_tx_before_cancun_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let tx = blob_tx(alloc::vec![kzg_hash(0x11)], Some(1));
        for spec in [Spec::Paris, Spec::Shanghai] {
            assert!(
                matches!(
                    vm.execute_tx(&tx, &env_at(spec), &state),
                    Err(VmError::Consensus(ConsensusError::InvalidTransaction(_)))
                ),
                "tipo 3 no existe en {spec:?}"
            );
        }
        assert!(vm.execute_tx(&tx, &env_at(Spec::Cancun), &state).is_ok());
    }

    #[test]
    fn a_set_code_tx_before_prague_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let tx = set_code_tx_to(Some(RECEIVER));
        for spec in [Spec::Paris, Spec::Shanghai, Spec::Cancun] {
            assert!(
                matches!(
                    vm.execute_tx(&tx, &env_at(spec), &state),
                    Err(VmError::Consensus(ConsensusError::InvalidTransaction(_)))
                ),
                "tipo 4 no existe en {spec:?}"
            );
        }
        assert!(vm.execute_tx(&tx, &env_at(Spec::Prague), &state).is_ok());
    }

    /// El tope de blobs por tx **cambia con el fork**: 6 en Cancun (target 3
    /// × 2, EIP-4844) y 9 en Prague (EIP-7691). Hardcodear uno solo pasa la
    /// mitad de los casos.
    #[test]
    fn more_blobs_than_the_fork_allows_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(100_000_000);
        for (spec, max) in [(Spec::Cancun, 6usize), (Spec::Prague, 9usize)] {
            let ok = blob_tx((0..max).map(|i| kzg_hash(i as u8)).collect(), Some(1));
            assert!(
                vm.execute_tx(&ok, &env_at(spec), &state).is_ok(),
                "{max} blobs es el tope exacto en {spec:?}: válida"
            );
            let too_many = blob_tx((0..=max).map(|i| kzg_hash(i as u8)).collect(), Some(1));
            assert!(
                matches!(
                    vm.execute_tx(&too_many, &env_at(spec), &state),
                    Err(VmError::Consensus(ConsensusError::InvalidTransaction(_)))
                ),
                "{} blobs pasa el tope en {spec:?}",
                max + 1
            );
        }
    }

    /// EEST: `TransactionException.TYPE_4_TX_CONTRACT_CREATION`. revm no lo
    /// chequea porque su sistema de tipos hace el caso irrepresentable —
    /// nosotros parseamos fixtures arbitrarios, así que para nosotros existe.
    /// Mismo patrón que el `to = Some` de 4844.
    #[test]
    fn a_set_code_tx_cannot_be_a_creation() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        assert!(matches!(
            vm.execute_tx(&set_code_tx_to(None), &env_at(Spec::Prague), &state),
            Err(VmError::Consensus(ConsensusError::InvalidTransaction(_)))
        ));
    }

    /// EIP-2681: `nonce == u64::MAX` invalida la tx — bumpearlo desbordaría.
    /// Hoy el motor la deja pasar y revienta adentro con un error interno cuyo
    /// propio mensaje dice "validación de la tx rota".
    #[test]
    fn a_nonce_at_the_u64_limit_is_rejected() {
        let mut vm = OwnVm::new();
        let mut accounts = BTreeMap::new();
        accounts.insert(SENDER, eoa(10_000_000, u64::MAX));
        let state = MockState {
            accounts,
            codes: BTreeMap::new(),
        };
        let tx = Transaction {
            nonce: u64::MAX,
            ..legacy_transfer(0, u128::from(BASE_FEE))
        };
        assert!(
            matches!(
                vm.execute_tx(&tx, &env(), &state),
                Err(VmError::Consensus(ConsensusError::InvalidTransaction(_)))
            ),
            "EIP-2681: se rechaza como tx inválida, NO como error interno"
        );
    }

    /// El punto de mayor riesgo del slice: el blob fee se
    /// debita del sender y NO se acredita a NADIE — ni al coinbase (a
    /// diferencia del tip de ejecución). Acá tip = 0 (max_fee_per_gas ==
    /// base_fee) para aislar el efecto del blob fee del de la ejecución.
    #[test]
    fn blob_fee_is_debited_from_sender_and_credited_to_nobody() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let tx = Transaction {
            tx_type: TxType::Eip4844,
            gas_price: None,
            max_fee_per_gas: Some(u128::from(BASE_FEE)),
            max_priority_fee_per_gas: Some(0),
            max_fee_per_blob_gas: Some(1),
            blob_versioned_hashes: alloc::vec![kzg_hash(0x11)],
            ..legacy_transfer(0, 0)
        };
        let outcome = must_execute(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            outcome.result,
            ExecutionResult::Success {
                gas_used: TX_BASE_GAS,
                ..
            }
        ));
        let sender = find_update(&outcome.state_changes, SENDER)
            .unwrap_or_else(|| panic!("update del sender"));
        // Fee de ejecución: 21000 · 10 (tip 0) = 210000.
        // Blob: 1 blob · 131072 · 1 (precio del bloque, excess=0) = 131072.
        // 10_000_000 - 210_000 - 131_072 = 9_658_928.
        assert_eq!(sender.balance, Some(U256::from(9_658_928u64)));
        // Tip 0 + blob quemado sin destinatario: el coinbase NO se toca.
        assert!(find_update(&outcome.state_changes, COINBASE).is_none());
    }

    #[test]
    fn blob_tx_with_to_none_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000_000);
        let mut tx = blob_tx(alloc::vec![kzg_hash(0x11)], Some(1));
        tx.to = None;
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn blob_tx_with_empty_hashes_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000_000);
        let tx = blob_tx(alloc::vec::Vec::new(), Some(1));
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn blob_tx_with_wrong_hash_version_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000_000);
        let bad_hash = hash_with_version(0x02, 0x11);
        let tx = blob_tx(alloc::vec![bad_hash], Some(1));
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn blob_tx_with_max_fee_per_blob_gas_below_block_price_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000_000);
        // env(): blob_excess_gas = Some(0) ⇒ blob_base_fee del bloque = 1.
        let tx = blob_tx(alloc::vec![kzg_hash(0x11)], Some(0));
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn blob_tx_without_max_fee_per_blob_gas_is_a_malformed_internal_error() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(1_000_000_000);
        let tx = blob_tx(alloc::vec![kzg_hash(0x11)], None);
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(err, VmError::Internal(_)));
    }

    /// Separa los DOS chequeos de balance: el sender
    /// alcanza para el gas de ejecución máximo (100_000 · 20 = 2_000_000) más
    /// value (0), pero NO le alcanza para sumarle encima el blob gas máximo
    /// (131072 · 100 = 13_107_200).
    #[test]
    fn blob_tx_balance_covers_execution_but_not_the_blob_fee_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(2_000_000);
        let tx = blob_tx(alloc::vec![kzg_hash(0x11)], Some(100));
        let err = must_fail(vm.execute_tx(&tx, &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn blob_gas_used_counts_hashes_times_gas_per_blob() {
        let tx = blob_tx(
            alloc::vec![kzg_hash(0x11), kzg_hash(0x22), kzg_hash(0x33)],
            Some(1),
        );
        assert_eq!(
            total_blob_gas(&tx).map_err(|e| e.to_string()),
            Ok(3 * GAS_PER_BLOB)
        );
    }

    // -------------------------------------------- EIP-7702

    fn set_code_tx(authorizations: AuthorizationList) -> Transaction {
        Transaction {
            tx_type: TxType::Eip7702,
            gas_price: None,
            max_fee_per_gas: Some(20),
            max_priority_fee_per_gas: Some(3),
            authorization_list: authorizations,
            ..legacy_transfer(0, 0)
        }
    }

    fn authorization(nonce: u64, authority: Option<Address>) -> Authorization {
        Authorization {
            chain_id: U256::from(1u64),
            address: RECEIVER,
            nonce,
            authority,
        }
    }

    /// La ÚNICA validación de runtime propia del tipo 4 (verificada contra
    /// revm: `InvalidTransaction::EmptyAuthorizationList`).
    #[test]
    fn a_set_code_tx_with_an_empty_authorization_list_is_rejected() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(10_000_000);
        let err = must_fail(vm.execute_tx(&set_code_tx(AuthorizationList::new()), &env(), &state));
        assert!(matches!(
            err,
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    /// **Corrección de un registro de 2.7c.** Aquel slice concluyó que
    /// "`to == None` en una tx tipo 4 NO se rechaza", verificándolo contra
    /// revm. La observación sobre revm era correcta —`validate_tx_env` no tiene
    /// ese chequeo— pero la conclusión estaba mal enunciada: **es una
    /// afirmación sobre el código de revm, no sobre el protocolo.** revm no lo
    /// necesita porque su sistema de tipos hace el caso irrepresentable.
    ///
    /// EEST, que es el oráculo canónico del PROTOCOLO, declara
    /// `TransactionException.TYPE_4_TX_CONTRACT_CREATION`: la tx es inválida.
    /// Nosotros parseamos fixtures arbitrarios, así que el estado inválido SÍ
    /// se puede construir y hay que rechazarlo fail-closed.
    ///
    /// Es exactamente la misma forma que el hallazgo de 2.7b
    /// (`BlobCreateTransaction` era dead code en revm y el `to = Some` de 4844
    /// se implementó igual), y la resolución es consistente con aquella.
    /// **"revm no lo chequea" ≠ "no hay que chequearlo".**
    #[test]
    fn a_set_code_tx_without_to_is_rejected_even_though_revm_has_no_such_check() {
        let mut vm = OwnVm::new();
        let state = state_with_sender(100_000_000);
        let mut tx = set_code_tx(alloc::vec![authorization(0, Some(RECEIVER))]);
        tx.to = None;
        assert!(matches!(
            must_fail(vm.execute_tx(&tx, &env(), &state)),
            VmError::Consensus(ConsensusError::InvalidTransaction(_))
        ));
    }

    /// El costo intrínseco es por tupla DECLARADA (25000 = PER_EMPTY_ACCOUNT),
    /// se aplique o no la autorización.
    #[test]
    fn intrinsic_gas_charges_every_declared_authorization() {
        let list = alloc::vec![authorization(0, Some(RECEIVER)), authorization(9, None)];
        assert_eq!(
            intrinsic_gas(&[], false, &AccessList::new(), &list, Spec::Prague)
                .map_err(|e| e.to_string()),
            Ok(TX_BASE_GAS + 2 * TX_AUTH_PER_EMPTY_ACCOUNT_GAS)
        );
        assert_eq!(AUTH_EXISTING_ACCOUNT_REFUND, 12_500);
    }

    #[test]
    fn blob_gas_used_is_zero_for_a_non_blob_tx() {
        let tx = legacy_transfer(0, u128::from(BASE_FEE));
        assert_eq!(total_blob_gas(&tx).map_err(|e| e.to_string()), Ok(0));
    }
}
