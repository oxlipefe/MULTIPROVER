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

/// Resultado de correr un caso (test × fork × index).
#[derive(Debug)]
pub enum CaseOutcome {
    Pass,
    /// Fork fuera del scope post-Merge del runner.
    SkippedFork(String),
    Fail(String),
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
fn logs_hash(logs: &Vec<Log>) -> B256 {
    keccak256(alloy_rlp::encode(logs))
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
    let tx = match test.transaction_for(case) {
        Ok(tx) => tx,
        Err(e) => return CaseOutcome::Fail(format!("tx del fixture inválida: {e}")),
    };
    let env = test.block_env(spec);
    let state = MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone());

    let outcome = match OwnVm::new().execute_tx(&tx, &env, &state) {
        Ok(outcome) => outcome,
        Err(e) => return CaseOutcome::Fail(format!("execute_tx falló: {e}")),
    };
    let logs = match &outcome.result {
        ExecutionResult::Success { logs, .. } => logs,
        // El subset vendoreado de este runner solo trae txs de éxito.
        other => return CaseOutcome::Fail(format!("resultado inesperado: {other:?}")),
    };

    let post = match apply_updates(&test.pre, &outcome.state_changes) {
        Ok(post) => post,
        Err(e) => return CaseOutcome::Fail(e),
    };

    // Diagnóstico fino primero (si el fixture trae el estado inline)…
    if let Some(expected) = &case.expected_state {
        let diffs = diff_expected(expected, &post);
        if !diffs.is_empty() {
            return CaseOutcome::Fail(format!("post-state diverge: {}", diffs.join(" | ")));
        }
    }
    // …y el juez: el root MPT byte-a-byte.
    let root = compute_state_root(&post);
    if root != case.state_root {
        return CaseOutcome::Fail(format!(
            "state root diverge: esperado {}, obtenido {root}",
            case.state_root
        ));
    }
    let hash = logs_hash(logs);
    if hash == case.logs_hash {
        CaseOutcome::Pass
    } else {
        CaseOutcome::Fail(format!(
            "logs hash diverge: esperado {}, obtenido {hash}",
            case.logs_hash
        ))
    }
}
