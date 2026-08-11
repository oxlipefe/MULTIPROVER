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
use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use repo_b_common::receipt::Log;
use repo_b_evm::OwnVm;
use repo_b_evm::error::{StateError, VmError};
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
    /// **La dirección peligrosa**: el fixture declara `expectException` (la tx
    /// es inválida y DEBE rechazarse) y el motor la ejecutó igual. Aceptar una
    /// tx inválida es un bug de consenso mucho peor que rechazar una válida —
    /// tiene su propia categoría para que nunca se diluya en otro cluster.
    AcceptedInvalidTx,
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
            Self::AcceptedInvalidTx => "accepted_invalid_tx",
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

    /// `KECCAK256_EMPTY` → código vacío, SIEMPRE. No es un default optimista:
    /// es la definición (`keccak("") == KECCAK256_EMPTY`), y no depende de que
    /// alguna cuenta del pre-state lo haya poblado por casualidad. Sin esto,
    /// una delegación EIP-7702 hacia una cuenta ausente del pre-state hacía
    /// fallar el motor con "código desconocido" — 6 casos del cluster
    /// `execute_error/internal error` (slice 2.9b, task 019). Cualquier OTRO
    /// hash desconocido sigue siendo fail-closed: eso sí es un fixture roto.
    fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
        if code_hash == KECCAK256_EMPTY {
            return Ok(Bytes::new());
        }
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

    // **`expectException` = el fixture declara la tx INVÁLIDA** y exige que el
    // cliente la rechace (slice 2.9b, task 019). Se chequean las DOS
    // direcciones, porque excusar el error sin más sería un comparador tuerto:
    // pasaríamos rechazando txs perfectamente válidas.
    let expect_exception = case.expect_exception.as_deref();
    let executed = match (OwnVm::new().execute_tx(&tx, &env, &state), expect_exception) {
        // Ejecutó una tx que el fixture declara inválida: la dirección
        // PELIGROSA (un bloque inválido que aceptaríamos). Categoría propia.
        (Ok(_), Some(expected)) => {
            return CaseOutcome::Fail(Failure::new(
                FailKind::AcceptedInvalidTx,
                expected,
                format!("el fixture declara `{expected}` pero la tx se ejecutó sin rechazo"),
            ));
        }
        (Ok(outcome), None) => Some(outcome),
        // Rechazo por CONSENSO con el fixture esperándolo: es el resultado
        // correcto. El post-state queda IGUAL al pre-state (la tx no entra al
        // bloque: sin fee, sin bump de nonce) — verificado sobre el set, no
        // asumido: en los 1 863 casos en scope con `expectException`,
        // `case.state == pre`. El root se sigue chequeando abajo como en
        // cualquier otro caso; esto no es un atajo al veredicto.
        //
        // Un `InternalError` NUNCA se excusa, ni con `expectException`: es un
        // bug del motor, no un juicio sobre la tx (taxonomía de
        // `crates/evm/src/error.rs`).
        (Err(VmError::Consensus(_)), Some(_)) => None,
        (Err(e), _) => {
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
    // el del set vacío. Una tx rechazada tampoco produce logs.
    const NO_LOGS: &[Log] = &[];
    const NO_CHANGES: &[AccountUpdate] = &[];
    // El halt lleva su RAZÓN en la sub-clave del cluster (slice 2.9b, task
    // 019). "halt" a secas era demasiado grueso: juntaba en un solo cluster de
    // 6 749 casos causas raíz sin nada en común (un opcode que no existe vs.
    // quedarse sin gas). Con la razón adentro, el mapa se parte en las causas
    // reales — que es la razón de ser del clustering (`AGENT_LOOP.md` §5). El
    // conjunto de razones es ACOTADO (`HaltReason`), así que no rompe la regla
    // de "sub-clave sin datos únicos por caso".
    let (logs, status) = match executed.as_ref().map(|out| &out.result) {
        Some(ExecutionResult::Success { logs, .. }) => (logs.as_slice(), "success".to_owned()),
        Some(ExecutionResult::Revert { .. }) => (NO_LOGS, "revert".to_owned()),
        Some(ExecutionResult::Halt { reason, .. }) => (NO_LOGS, format!("halt:{reason:?}")),
        None => (NO_LOGS, "rejected".to_owned()),
    };
    let status = status.as_str();
    let state_changes = executed
        .as_ref()
        .map_or(NO_CHANGES, |out| out.state_changes.as_slice());

    let post = match apply_updates(&test.pre, state_changes) {
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

/// Semántica de `expectException` (slice 2.9b, task 019). Se prueban las TRES
/// direcciones, no solo la feliz: excusar el rechazo sin chequear la recíproca
/// sería un comparador tuerto — pasaríamos rechazando txs válidas.
///
/// Los tests pasan por el PARSER real (`fixture::parse_file`), no por un
/// `PostCase` construido a mano: así cubren también que `expectException` se
/// lea del JSON.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::parse_file;

    /// `gasLimit` 20999 < 21000 intrínseco ⇒ `IntrinsicGasTooLow`
    /// (`ConsensusError`). El mismo `TransactionException.INTRINSIC_GAS_TOO_LOW`
    /// que domina el set real (1 195 de los 1 863 casos con `expectException`).
    const GAS_LIMIT_BELOW_INTRINSIC: &str = "0x5207";
    const GAS_LIMIT_VALID: &str = "0x0927c0";

    fn fixture_json(gas_limit: &str, expect_exception: Option<&str>) -> String {
        let exception = expect_exception
            .map(|e| format!(r#""expectException": "{e}","#))
            .unwrap_or_default();
        format!(
            r#"{{ "test": {{
              "config": {{ "chainid": "0x01" }},
              "env": {{
                "currentBaseFee": "0x0a",
                "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "currentGasLimit": "0x989680",
                "currentNumber": "0x01",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000020000",
                "currentTimestamp": "0x03e8",
                "currentExcessBlobGas": "0x00"
              }},
              "pre": {{
                "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {{
                  "balance": "0xe8d4a51000", "code": "0x", "nonce": "0x00", "storage": {{}}
                }},
                "0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b": {{
                  "balance": "0x64", "code": "0x", "nonce": "0x00", "storage": {{}}
                }}
              }},
              "transaction": {{
                "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                "to": "0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
                "nonce": "0x00",
                "gasPrice": "0x0a",
                "data": ["0x"],
                "gasLimit": ["{gas_limit}"],
                "value": ["0x01"]
              }},
              "post": {{ "Cancun": [ {{
                {exception}
                "indexes": {{ "data": 0, "gas": 0, "value": 0 }},
                "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "logs": "0x0000000000000000000000000000000000000000000000000000000000000000"
              }} ] }}
            }} }}"#
        )
    }

    /// Devuelve el test con el caso ya "sellado": el root esperado es el del
    /// **pre-state intacto** y el logs hash el del set vacío — que es
    /// exactamente lo que un fixture con `expectException` trae de verdad
    /// (verificado sobre el set: `case.state == pre` en los 1 863 casos).
    fn parsed(gas_limit: &str, expect_exception: Option<&str>) -> StateTest {
        let parsed = parse_file(&fixture_json(gas_limit, expect_exception));
        let Ok(mut tests) = parsed else {
            panic!("el fixture de prueba tiene que parsear: {parsed:?}");
        };
        let Some(mut test) = tests.pop() else {
            panic!("el fixture de prueba tiene que traer un test");
        };
        let pre_root = compute_state_root(&test.pre);
        let empty_logs = logs_hash(&[]);
        for case in &mut test.posts {
            case.state_root = pre_root;
            case.logs_hash = empty_logs;
        }
        test
    }

    #[test]
    fn expect_exception_is_read_from_the_json() {
        let test = parsed(GAS_LIMIT_BELOW_INTRINSIC, Some("TransactionException.FOO"));
        assert_eq!(
            test.posts[0].expect_exception.as_deref(),
            Some("TransactionException.FOO")
        );
        assert!(
            parsed(GAS_LIMIT_VALID, None).posts[0]
                .expect_exception
                .is_none()
        );
    }

    /// Dirección 1: la tx es inválida, el fixture lo declara ⇒ **PASS**, y el
    /// post-state queda idéntico al pre-state (sin fee cobrado, sin bump de
    /// nonce: la tx nunca entró al bloque).
    #[test]
    fn a_rejected_tx_the_fixture_declares_invalid_passes_with_the_pre_state_root() {
        let test = parsed(
            GAS_LIMIT_BELOW_INTRINSIC,
            Some("TransactionException.INTRINSIC_GAS_TOO_LOW"),
        );
        assert!(
            matches!(run_case(&test, &test.posts[0]), CaseOutcome::Pass),
            "un rechazo esperado con el root del pre-state tiene que pasar"
        );
    }

    /// Dirección 2: rechazamos una tx que el fixture NO declara inválida ⇒
    /// falla. Sin esto, "excusar el error" sería un cheque en blanco.
    #[test]
    fn rejecting_a_tx_the_fixture_considers_valid_still_fails() {
        let test = parsed(GAS_LIMIT_BELOW_INTRINSIC, None);
        let outcome = run_case(&test, &test.posts[0]);
        assert!(
            matches!(
                outcome,
                CaseOutcome::Fail(Failure {
                    kind: FailKind::ExecuteError,
                    ..
                })
            ),
            "esperado ExecuteError, obtenido {outcome:?}"
        );
    }

    /// Dirección 3 — **la peligrosa**: ejecutamos una tx que el fixture declara
    /// inválida. Categoría propia (`accepted_invalid_tx`) para que nunca se
    /// diluya en el cluster de `state_root`.
    #[test]
    fn executing_a_tx_the_fixture_declares_invalid_is_its_own_failure_kind() {
        let test = parsed(
            GAS_LIMIT_VALID,
            Some("TransactionException.INTRINSIC_GAS_TOO_LOW"),
        );
        let outcome = run_case(&test, &test.posts[0]);
        assert!(
            matches!(
                outcome,
                CaseOutcome::Fail(Failure {
                    kind: FailKind::AcceptedInvalidTx,
                    ..
                })
            ),
            "esperado AcceptedInvalidTx, obtenido {outcome:?}"
        );
    }

    /// `KECCAK256_EMPTY` siempre resuelve a código vacío, aunque ninguna cuenta
    /// del pre-state lo haya poblado; cualquier otro hash desconocido sigue
    /// siendo fail-closed.
    #[test]
    fn memory_state_serves_empty_code_but_stays_fail_closed_for_unknown_hashes() {
        let state = MemoryState::default();
        assert!(matches!(state.code(KECCAK256_EMPTY), Ok(code) if code.is_empty()));
        assert!(state.code(B256::new([0x22; 32])).is_err());
    }
}
