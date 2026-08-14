//! Seam `Host`: subset storage (SLOAD/SSTORE/TLOAD/TSTORE + refund),
//! entorno (`env`/`tx`), `self_balance`, `block_hash`, `log`, y acceso a
//! cuentas ajenas (`load_account`/`code_by_address`, EIP-2929/161).
//!
//! Las sub-calls **no agregan métodos**: el movimiento de balance y la
//! carga del código del sub-frame los hace el executor sobre el journal, no el
//! intérprete. Lo único que cambió es que `self_balance` recibe
//! la dirección del frame en ejecución. SELFDESTRUCT queda para su
//! slice, just-in-time — no se agrega acá especulativamente (YAGNI).
//!
//! El intérprete llama a `&mut dyn Host` para todo lo que toca el mundo; NO
//! trackea cold/warm por su cuenta (eso lo decide quien implemente `Host` —
//! el mock en 002, el journal en 004).

use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::receipt::Log;

/// Envuelve un valor con el flag de acceso frío (EIP-2929): el intérprete
/// cobra el gas correcto (cold vs warm) sin saber CÓMO se trackea.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLoad<T> {
    pub data: T,
    pub is_cold: bool,
}

/// Proyección MÍNIMA del `BlockEnv` del seam (vendoreado en `evm`;
/// prohíbe tocarlo) con solo los campos que los opcodes de entorno de este
/// slice necesitan. Vive en `interpreter::host` — no en `evm` — por la misma
/// razón que `TxEnv`: el intérprete solo depende de `common`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockEnv {
    pub chain_id: u64,
    pub number: u64,
    pub coinbase: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub prevrandao: B256,
    /// EIP-7516 (BLOBBASEFEE) / EIP-4844 `fake_exponential`: ya calculado por
    /// quien arma el frame (`evm`); el intérprete solo lo apila.
    pub blob_base_fee: u64,
}

/// Datos de la tx que ORIGIN/GASPRICE/BLOBHASH necesitan. Vive en
/// `interpreter::host` (NO en el seam `Transaction` vendeado): en el slice
/// single-frame, `origin` = sender de la tx y `gas_price` = el effective ya
/// calculado por `OwnVm` (EIP-1559). `blob_hashes` vacío hasta el tipo de tx
/// 4844.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxEnv {
    pub origin: Address,
    pub gas_price: u128,
    pub blob_hashes: Vec<B256>,
}

/// Lo que el gas de SSTORE necesita (EIP-2200): el valor del slot antes de la
/// tx (`original`), el valor actual dentro de la tx (`current`) y el que se
/// está escribiendo (`new`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SStoreResult {
    pub original: U256,
    pub current: U256,
    pub new: U256,
}

/// Lo que BALANCE/EXTCODESIZE/EXTCODECOPY/EXTCODEHASH necesitan de una
/// cuenta ajena. `is_empty` es EIP-161: inexistente O (nonce=0 ∧
/// balance=0 ∧ code vacío) — el intérprete lo usa para EXTCODEHASH (una
/// cuenta vacía o inexistente pushea 0, NUNCA `keccak("")`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountLoad {
    pub balance: U256,
    pub code_hash: B256,
    pub is_empty: bool,
}

/// Lo que el gas de SELFDESTRUCT necesita saber del efecto ya aplicado.
/// El movimiento de balance y la marca de destrucción los hace el
/// host —es estado, no aritmética de pila—; el intérprete solo cobra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfDestructResult {
    /// La cuenta que se autodestruye tenía balance `> 0` (medido ANTES de
    /// moverlo). Con `target_exists == false` dispara `G_newaccount`.
    pub had_value: bool,
    /// El `beneficiary` existía y NO estaba vacío (EIP-161), medido **antes**
    /// del transfer — después siempre existiría.
    pub target_exists: bool,
    /// La cuenta ya había ejecutado SELFDESTRUCT antes en esta tx. Sin uso de
    /// gas en Prague (el refund de 24000 murió con EIP-3529); se expone porque
    /// es lo que decide el refund en los forks viejos y no queremos que un
    /// futuro `Spec` lo tenga que recalcular.
    pub previously_destroyed: bool,
}

/// Subset storage del seam `Host`. Vive en `interpreter` (no en `evm`) para
/// no invertir la dirección de dependencias: usa solo tipos de
/// `common`.
pub trait Host {
    fn sload(&mut self, addr: Address, key: U256) -> StateLoad<U256>;
    fn sstore(&mut self, addr: Address, key: U256, value: U256) -> StateLoad<SStoreResult>;
    /// EIP-1153 — transient storage: sin cold/warm, no journaled más allá de
    /// la tx (el fin-de-tx lo maneja quien implemente `Host`).
    fn tload(&mut self, addr: Address, key: U256) -> U256;
    fn tstore(&mut self, addr: Address, key: U256, value: U256);
    /// Acumulador de refund (EIP-3529); el tope al liquidar la tx es
    /// responsabilidad de quien implemente `Host`, no del intérprete.
    fn refund(&mut self, delta: i64);

    /// Entorno del bloque (NUMBER/TIMESTAMP/COINBASE/GASLIMIT/CHAINID/
    /// BASEFEE/PREVRANDAO/BLOBBASEFEE).
    fn env(&self) -> &BlockEnv;
    /// Datos de la tx (ORIGIN/GASPRICE/BLOBHASH).
    fn tx(&self) -> &TxEnv;
    /// Balance de la cuenta en ejecución (SELFBALANCE, EIP-1884). El
    /// intérprete pasa su propio `context.address`: con sub-calls el
    /// frame en ejecución cambia, así que el host NO puede tener un
    /// "self" fijo. **No toca el accessed set** (a diferencia de
    /// `load_account`): SELFBALANCE no cobra cold/warm.
    ///
    /// El valor YA refleja los transfers de la tx y de las sub-calls y el gas
    /// prepagado — nunca el balance "congelado" del `State`.
    fn self_balance(&mut self, addr: Address) -> U256;
    /// `BLOCKHASH`: hash de un bloque ancestro. El chequeo de ventana
    /// (`[number-256, number-1]`) lo hace el intérprete ANTES de llamar acá;
    /// un `number` fuera de ventana ni siquiera llega a este método.
    fn block_hash(&mut self, number: u64) -> B256;
    /// Emite un log (LOG0..LOG4); journaled y revertido igual que storage.
    fn log(&mut self, log: Log);

    /// Balance/code_hash/empty de una cuenta AJENA (BALANCE, EXTCODEHASH;
    /// EIP-2929/161). El flag `is_cold` sale del accessed-set de
    /// DIRECCIONES (distinto del de `(addr, slot)` que usa `sload`/`sstore`).
    fn load_account(&mut self, addr: Address) -> StateLoad<AccountLoad>;
    /// Bytecode de una cuenta ajena (EXTCODESIZE, EXTCODECOPY). Cuenta sin
    /// código o inexistente ⇒ bytes vacíos. **NO resuelve delegaciones
    /// EIP-7702**: EXTCODE\* ve el designator crudo (verificado contra revm,
    /// `instructions/host.rs` usa `load_account_info`, no la variante
    /// `_delegated`).
    fn code_by_address(&mut self, addr: Address) -> StateLoad<Bytes>;

    /// EIP-7702: si el código de `addr` es un designator de
    /// delegación, devuelve la dirección DELEGADA **metiéndola en el accessed
    /// set** (EIP-2929) y reportando si estaba fría. `None` = la cuenta no
    /// está delegada.
    ///
    /// Existe como método aparte de `load_account` porque el gas de la
    /// delegación es un acceso a cuenta PROPIO, cobrado además del de
    /// `code_address` (revm: `load_account_delegated` suma `+100` siempre y
    /// `+2500` si la delegada está fría). Solo lo llaman los 4 opcodes de
    /// call: EXTCODE\*/BALANCE nunca resuelven la delegación.
    fn load_delegated_account(&mut self, addr: Address) -> Option<StateLoad<Address>>;

    /// `SELFDESTRUCT` (0xFF): mueve TODO el balance de `addr` a
    /// `beneficiary` y —solo si `addr` se creó en ESTA tx (EIP-6780)— la marca
    /// como destruida. `is_cold` es el accessed-set de DIRECCIONES aplicado al
    /// `beneficiary` (EIP-2929).
    ///
    /// Vive en el host y no en el intérprete porque es una mutación de estado
    /// journaled (revert por frame), exactamente como `sstore`.
    fn selfdestruct(
        &mut self,
        addr: Address,
        beneficiary: Address,
    ) -> StateLoad<SelfDestructResult>;
}
