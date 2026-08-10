//! Ejecución de un state test contra `OwnVm` + validación del post-state.
//!
//! El veredicto es **bit-idéntico o falla**: state root recomputado (MPT real
//! vía `alloy-trie`) == hash del fixture, y logs hash == esperado. Si el
//! fixture trae el post-state inline, además se diffea cuenta-a-cuenta para
//! diagnóstico (el root sigue siendo el juez).

use std::collections::BTreeMap;

use alloy_primitives::keccak256;
use alloy_trie::TrieAccount;
use alloy_trie::root::{state_root_unhashed, storage_root_unhashed};
use repo_b_common::account::AccountUpdate;
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::receipt::Log;
use repo_b_evm::OwnVm;
use repo_b_evm::error::StateError;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::state::State;
use repo_b_evm::types::{AccountInfo, CodeMetadata};
use repo_b_evm::vm::Vm;

use crate::fixture::{FixtureAccount, PostCase, StateTest, spec_for_fork};

/// Categoría de falla — la clave de clustering (`AGENT_LOOP.md` §5). A escala
/// de decenas de miles de casos, miles de fallas comparten causa raíz: se
/// ataca el CLUSTER, no el caso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailKind {
    /// El fixture no se pudo interpretar. **No es un skip**: si no lo
    /// entendimos, no pasó (task 018 §7, prohibido el default optimista).
    Parse,
    /// La tx del fixture no se pudo construir.
    TxInvalid,
    /// `execute_tx` devolvió `Err` (error del motor, no un revert/halt).
    ExecuteError,
    /// El post-state no se pudo aplicar al pre-state.
    PostStateApply,
    /// El juez: el root MPT recomputado no coincide.
    StateRoot,
    /// El logs hash no coincide.
    LogsHash,
}

impl FailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::TxInvalid => "tx_invalid",
            Self::ExecuteError => "execute_error",
            Self::PostStateApply => "post_state_apply",
            Self::StateRoot => "state_root",
            Self::LogsHash => "logs_hash",
        }
    }
}

/// Una falla, separada en dos ejes deliberadamente:
/// - `detail`: la sub-clave del cluster. **Acotada y sin datos únicos por
///   caso** (nunca hashes ni direcciones) — si no, cada falla es su propio
///   cluster y el clustering no sirve para nada.
/// - `message`: el diagnóstico largo de UN caso (sí lleva los valores).
#[derive(Debug, Clone)]
pub struct Failure {
    pub kind: FailKind,
    pub detail: String,
    pub message: String,
}

impl Failure {
    fn new(kind: FailKind, detail: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            message: message.into(),
        }
    }

    /// La firma de cluster: `(categoría, detalle)`.
    pub fn signature(&self) -> (FailKind, &str) {
        (self.kind, self.detail.as_str())
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}", self.kind.as_str(), self.message)
    }
}

/// Resultado de correr un caso (test × fork × index).
#[derive(Debug)]
pub enum CaseOutcome {
    Pass,
    /// Fork fuera del scope post-Merge del runner.
    SkippedFork(String),
    Fail(Failure),
}

/// State en memoria construido del pre-state del fixture (BTreeMap:
/// determinista). El código se sirve por hash, como pide el seam.
#[derive(Debug, Clone, Default)]
pub struct MemoryState {
    accounts: BTreeMap<Address, FixtureAccount>,
    code_by_hash: BTreeMap<B256, Bytes>,
    block_hashes: BTreeMap<u64, B256>,
}

impl MemoryState {
    pub fn from_pre(pre: &BTreeMap<Address, FixtureAccount>) -> Self {
        let mut code_by_hash = BTreeMap::new();
        for account in pre.values() {
            code_by_hash.insert(keccak256(&account.code), account.code.clone());
        }
        Self {
            accounts: pre.clone(),
            code_by_hash,
            block_hashes: BTreeMap::new(),
        }
    }

    /// `BLOCKHASH` (slice 2.3): extensión propia del fixture, no campo EF —
    /// ver `RawEnv::block_hashes`.
    #[must_use]
    pub fn with_block_hashes(mut self, block_hashes: BTreeMap<u64, B256>) -> Self {
        self.block_hashes = block_hashes;
        self
    }
}

impl State for MemoryState {
    fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
        Ok(self.accounts.get(&addr).map(|acc| AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce,
            code_hash: keccak256(&acc.code),
        }))
    }

    fn storage(&self, addr: Address, key: U256) -> Result<U256, StateError> {
        Ok(self
            .accounts
            .get(&addr)
            .and_then(|acc| acc.storage.get(&key).copied())
            .unwrap_or(U256::ZERO))
    }

    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        self.code_by_hash
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| StateError::Database(format!("código desconocido: {code_hash}")))
    }

    fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
        // Slice de Fase 1: sin delegaciones EIP-7702 en los fixtures corridos.
        Ok(CodeMetadata::Regular)
    }

    /// El intérprete solo llama a esto para números YA validados dentro de la
    /// ventana `[number-256, number-1]` (chequeo del opcode, ver ficha 01);
    /// uno sin hash configurado en el fixture es un fixture incompleto, no un
    /// ancestro legítimamente desconocido — fail-closed, nunca 0 aproximado.
    fn block_hash(&self, number: u64) -> Result<B256, StateError> {
        self.block_hashes.get(&number).copied().ok_or_else(|| {
            StateError::Database(format!("blockHashes del fixture sin entrada para {number}"))
        })
    }
}

/// Aplica el diff del EVM sobre el pre-state → post-state.
pub fn apply_updates(
    pre: &BTreeMap<Address, FixtureAccount>,
    changes: &[AccountUpdate],
) -> Result<BTreeMap<Address, FixtureAccount>, String> {
    let mut post = pre.clone();
    for update in changes {
        if update.destroyed {
            post.remove(&update.address);
            continue;
        }
        let entry = post
            .entry(update.address)
            .or_insert_with(|| FixtureAccount {
                balance: U256::ZERO,
                nonce: 0,
                code: Bytes::new(),
                storage: BTreeMap::new(),
            });
        if let Some(balance) = update.balance {
            entry.balance = balance;
        }
        if let Some(nonce) = update.nonce {
            entry.nonce = nonce;
        }
        if let Some(code) = &update.code {
            entry.code = code.clone();
        }
        for (key, value) in &update.storage {
            if value.is_zero() {
                entry.storage.remove(key);
            } else {
                entry.storage.insert(*key, *value);
            }
        }
    }
    Ok(post)
}

/// State root MPT real del post-state (el juez del gate).
fn compute_state_root(accounts: &BTreeMap<Address, FixtureAccount>) -> B256 {
    state_root_unhashed(accounts.iter().map(|(addr, acc)| {
        let storage_root = storage_root_unhashed(
            acc.storage
                .iter()
                .filter(|(_, value)| !value.is_zero())
                .map(|(key, value)| (B256::from(key.to_be_bytes()), *value)),
        );
        (
            *addr,
            TrieAccount {
                nonce: acc.nonce,
                balance: acc.balance,
                storage_root,
                code_hash: keccak256(&acc.code),
            },
        )
    }))
}

/// `keccak(rlp(logs))` (slice 2.3): cada log es `[address, topics, data]`
/// (`Log: RlpEncodable`, `crates/common/src/receipt.rs`); `logs` completo es
/// la lista RLP de esos logs (`Vec<Log>: Encodable` codifica como lista).
/// `encode_list` (y no `encode(&Vec<_>)`) porque `alloy_rlp` no implementa
/// `Encodable` para slices. Producen los MISMOS bytes — verificado contra el
/// set diferencial `logs-env` (9 casos con logs reales, byte a byte vs revm),
/// no asumido: esto es el logs hash, es consenso.
fn logs_hash(logs: &[Log]) -> B256 {
    let mut out = Vec::new();
    alloy_rlp::encode_list::<Log, Log>(logs, &mut out);
    keccak256(out)
}

/// Diff cuenta-a-cuenta contra el post-state inline (diagnóstico).
fn diff_expected(
    expected: &BTreeMap<Address, FixtureAccount>,
    actual: &BTreeMap<Address, FixtureAccount>,
) -> Vec<String> {
    let mut diffs = Vec::new();
    for (addr, exp) in expected {
        match actual.get(addr) {
            None => diffs.push(format!("falta la cuenta {addr}")),
            Some(act) if act != exp => diffs.push(format!(
                "cuenta {addr}: esperado balance={} nonce={}, obtenido balance={} nonce={}",
                exp.balance, exp.nonce, act.balance, act.nonce
            )),
            Some(_) => {}
        }
    }
    for addr in actual.keys() {
        if !expected.contains_key(addr) {
            diffs.push(format!("cuenta {addr} sobra en el post-state"));
        }
    }
    diffs
}

/// Corre un caso de post-state de un test. Bit-idéntico o `Fail`.
pub fn run_case(test: &StateTest, case: &PostCase) -> CaseOutcome {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return CaseOutcome::SkippedFork(case.fork.clone());
    };
    if let Err(e) = test.require_post_merge_env() {
        return CaseOutcome::Fail(Failure::new(FailKind::Parse, error_head(&e), e));
    }
    let tx = match test.transaction_for(case) {
        Ok(tx) => tx,
        Err(e) => {
            return CaseOutcome::Fail(Failure::new(
                FailKind::TxInvalid,
                error_head(&e),
                format!("tx del fixture inválida: {e}"),
            ));
        }
    };
    let env = test.block_env(spec);
    let state = MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone());

    let outcome = match OwnVm::new().execute_tx(&tx, &env, &state) {
        Ok(outcome) => outcome,
        Err(e) => {
            return CaseOutcome::Fail(Failure::new(
                FailKind::ExecuteError,
                error_head(&format!("{e}")),
                format!("execute_tx falló: {e}"),
            ));
        }
    };

    // **Un revert/halt NO es un fallo del test.** El post-state de una tx
    // revertida igual cambió (fee cobrado, nonce bumpeado) y el fixture espera
    // ESE root. Antes de 2.9a el runner hard-falleaba acá porque el subset
    // vendoreado solo traía txs de éxito — con el set de EF eso hubiera sido
    // un cluster masivo de falsos-fallos (task 018, it.2).
    //
    // Los logs se descartan en revert/halt, así que el logs hash esperado es
    // el del set vacío.
    const NO_LOGS: &[Log] = &[];
    let (logs, status) = match &outcome.result {
        ExecutionResult::Success { logs, .. } => (logs.as_slice(), "success"),
        ExecutionResult::Revert { .. } => (NO_LOGS, "revert"),
        ExecutionResult::Halt { .. } => (NO_LOGS, "halt"),
    };

    let post = match apply_updates(&test.pre, &outcome.state_changes) {
        Ok(post) => post,
        Err(e) => {
            return CaseOutcome::Fail(Failure::new(FailKind::PostStateApply, error_head(&e), e));
        }
    };

    // El juez es el root MPT byte-a-byte; el post-state inline (si viene) solo
    // enriquece el diagnóstico de un caso, no relaja el veredicto.
    let root = compute_state_root(&post);
    if root != case.state_root {
        let mut message = format!(
            "state root diverge: esperado {}, obtenido {root} (status={status})",
            case.state_root
        );
        if let Some(expected) = &case.expected_state {
            let diffs = diff_expected(expected, &post);
            if !diffs.is_empty() {
                message.push_str(&format!(" | post-state: {}", diffs.join(" | ")));
            }
        }
        // La sub-clave del cluster es el STATUS, no los hashes: agrupa
        // "divergimos con la tx en éxito" vs "…con halt", que son causas raíz
        // distintas.
        return CaseOutcome::Fail(Failure::new(FailKind::StateRoot, status, message));
    }

    let hash = logs_hash(logs);
    if hash == case.logs_hash {
        CaseOutcome::Pass
    } else {
        CaseOutcome::Fail(Failure::new(
            FailKind::LogsHash,
            status,
            format!(
                "logs hash diverge: esperado {}, obtenido {hash} (status={status})",
                case.logs_hash
            ),
        ))
    }
}

/// Recorta un mensaje de error a su cabeza estable, para que sirva de
/// sub-clave de cluster: sin valores concretos (hashes, direcciones, números)
/// que harían que cada caso fuese su propio cluster.
fn error_head(msg: &str) -> String {
    let head = msg.split([':', '(', '{']).next().unwrap_or(msg).trim();
    head.chars().take(60).collect()
}
