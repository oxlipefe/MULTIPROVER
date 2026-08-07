//! Bridge diferencial **bit-idéntico vs `revm`** (task 004, PHASE_2_ROADMAP
//! §2.2 / §Velocidad).
//!
//! Ejecuta la MISMA tx en `OwnVm` y en `revm` (=38.0.0, in-process: un caso
//! son microsegundos, nunca subproceso) y compara byte a byte: status,
//! `gas_used`, refund, output y **post-state completo**. Cuando divergen,
//! imprime el PRIMER paso divergente (EIP-3155 de los dos lados vía
//! `trace_diff`) — nunca "el root difiere" a secas.
//!
//! El juez es revm, no el `hash` del fixture: ver `fixtures/diff/README.md`.

use std::collections::BTreeMap;
use std::path::Path;

use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::OwnVm;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;
use revm::context::TxEnv;
use revm::context::result::{ExecutionResult as RevmExecutionResult, Output};
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::{TxKind, hardfork::SpecId};
use revm::state::{AccountInfo as RevmAccountInfo, Bytecode};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

use crate::fixture::{FixtureAccount, PostCase, StateTest, parse_file, spec_for_fork};
use crate::runner::{MemoryState, apply_updates};
use crate::trace_diff::first_divergence;

mod trace_source;

/// Post-state normalizado: la unidad de comparación.
type PostState = BTreeMap<Address, FixtureAccount>;

/// La trichotomy, reducida a lo comparable entre los dos motores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Success,
    Revert,
    Halt,
}

/// Todo lo observable de una ejecución. Dos `Summary` iguales = bit-idéntico.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Summary {
    status: Status,
    gas_used: u64,
    gas_refunded: u64,
    output: Bytes,
    post: PostState,
}

#[derive(Debug, Default)]
pub struct Report {
    pub cases: u32,
    pub diverged: u32,
    pub skipped: u32,
}

/// Corre el set diferencial de un directorio. Exit del gate = `diverged == 0`
/// **y** al menos un caso corrido (un directorio vacío no es "verde").
pub fn run_dir(dir: &Path) -> Report {
    let mut report = Report::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("[FAIL] no se pudo leer {}: {e}", dir.display());
            report.diverged = report.diverged.saturating_add(1);
            return report;
        }
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    // Orden determinista: `read_dir` no lo garantiza.
    paths.sort();

    for path in paths {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("[FAIL] {}: no se pudo leer: {e}", path.display());
                report.diverged = report.diverged.saturating_add(1);
                continue;
            }
        };
        let tests = match parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => {
                eprintln!("[FAIL] {}: {e}", path.display());
                report.diverged = report.diverged.saturating_add(1);
                continue;
            }
        };
        for test in &tests {
            for case in &test.posts {
                run_one(test, case, &mut report);
            }
        }
    }
    report
}

fn run_one(test: &StateTest, case: &PostCase, report: &mut Report) {
    let label = format!("{} [{}]", test.name, case.fork);
    let Some(spec) = spec_for_fork(&case.fork) else {
        eprintln!("[SKIP] {label}: fork fuera de scope post-Merge");
        report.skipped = report.skipped.saturating_add(1);
        return;
    };
    report.cases = report.cases.saturating_add(1);

    let ours = match ours_summary(test, case, spec) {
        Ok(summary) => summary,
        Err(e) => {
            eprintln!("[DIFF] {label}: OwnVm no pudo ejecutar: {e}");
            report.diverged = report.diverged.saturating_add(1);
            return;
        }
    };
    let oracle = match revm_summary(test, case, spec) {
        Ok(summary) => summary,
        Err(e) => {
            eprintln!("[DIFF] {label}: revm no pudo ejecutar: {e}");
            report.diverged = report.diverged.saturating_add(1);
            return;
        }
    };

    let differences = compare(&ours, &oracle);
    if differences.is_empty() {
        eprintln!("[SAME] {label}");
        return;
    }
    report.diverged = report.diverged.saturating_add(1);
    eprintln!("[DIFF] {label}");
    for difference in &differences {
        eprintln!("        {difference}");
    }
    report_first_divergent_step(test, case, spec);
}

/// Diferencias campo a campo. Vacío = bit-idéntico.
///
/// **No se debilita nunca**: el refund y el post-state entran enteros. Sacar
/// un campo para "pasar" sería mentirle al gate (Prohibido del task 004).
fn compare(ours: &Summary, oracle: &Summary) -> Vec<String> {
    let mut differences = Vec::new();
    if ours.status != oracle.status {
        differences.push(format!(
            "status: nuestro {:?} vs revm {:?}",
            ours.status, oracle.status
        ));
    }
    if ours.gas_used != oracle.gas_used {
        differences.push(format!(
            "gas_used: nuestro {} vs revm {} (delta {})",
            ours.gas_used,
            oracle.gas_used,
            i128::from(ours.gas_used) - i128::from(oracle.gas_used)
        ));
    }
    if ours.gas_refunded != oracle.gas_refunded {
        differences.push(format!(
            "refund: nuestro {} vs revm {}",
            ours.gas_refunded, oracle.gas_refunded
        ));
    }
    if ours.output != oracle.output {
        differences.push(format!(
            "output: nuestro 0x{} vs revm 0x{}",
            hex(&ours.output),
            hex(&oracle.output)
        ));
    }
    differences.extend(compare_post(&ours.post, &oracle.post));
    differences
}

fn compare_post(ours: &PostState, oracle: &PostState) -> Vec<String> {
    let mut differences = Vec::new();
    let addresses: std::collections::BTreeSet<Address> =
        ours.keys().chain(oracle.keys()).copied().collect();
    for address in addresses {
        match (ours.get(&address), oracle.get(&address)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => {
                if a.balance != b.balance {
                    differences.push(format!(
                        "{address}: balance nuestro {} vs revm {}",
                        a.balance, b.balance
                    ));
                }
                if a.nonce != b.nonce {
                    differences.push(format!(
                        "{address}: nonce nuestro {} vs revm {}",
                        a.nonce, b.nonce
                    ));
                }
                if a.code != b.code {
                    differences.push(format!("{address}: el código difiere"));
                }
                if a.storage != b.storage {
                    differences.push(format!(
                        "{address}: storage nuestro {:?} vs revm {:?}",
                        a.storage, b.storage
                    ));
                }
            }
            (Some(_), None) => differences.push(format!("{address}: sobra en nuestro post-state")),
            (None, Some(_)) => differences.push(format!("{address}: falta en nuestro post-state")),
            (None, None) => {}
        }
    }
    differences
}

// ------------------------------------------------------------------ lado propio

fn ours_summary(test: &StateTest, case: &PostCase, spec: Spec) -> Result<Summary, String> {
    let tx = test.transaction_for(case)?;
    let env = test.block_env(spec);
    let state = MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone());

    let outcome = OwnVm::new()
        .execute_tx(&tx, &env, &state)
        .map_err(|e| format!("{e}"))?;
    let post = apply_updates(&test.pre, &outcome.state_changes)?;

    let (status, gas_used, gas_refunded, output) = match &outcome.result {
        ExecutionResult::Success {
            gas_used,
            gas_refunded,
            output,
            ..
        } => (Status::Success, *gas_used, *gas_refunded, output.clone()),
        ExecutionResult::Revert { gas_used, output } => {
            (Status::Revert, *gas_used, 0, output.clone())
        }
        ExecutionResult::Halt { gas_used, .. } => (Status::Halt, *gas_used, 0, Bytes::new()),
    };
    Ok(Summary {
        status,
        gas_used,
        gas_refunded,
        output,
        post: normalize(post),
    })
}

// ------------------------------------------------------------------ lado revm

/// `Spec` (nuestro) → `SpecId` (revm). Total, sin `_`.
fn spec_id(spec: Spec) -> SpecId {
    match spec {
        Spec::Paris => SpecId::MERGE,
        Spec::Shanghai => SpecId::SHANGHAI,
        Spec::Cancun => SpecId::CANCUN,
        Spec::Prague => SpecId::PRAGUE,
    }
}

/// Pre-state del fixture → `Database` de revm (adapter del harness).
/// `block_hashes` alimenta el `BLOCKHASH` de revm con la MISMA data que
/// `MemoryState` (extensión propia del fixture, no campo EF).
fn revm_db(
    pre: &BTreeMap<Address, FixtureAccount>,
    block_hashes: &BTreeMap<u64, B256>,
) -> Result<CacheDB<EmptyDB>, String> {
    let mut db = CacheDB::new(EmptyDB::default());
    for (number, hash) in block_hashes {
        db.cache.block_hashes.insert(U256::from(*number), *hash);
    }
    for (address, account) in pre {
        let bytecode = Bytecode::new_raw(account.code.clone());
        db.insert_account_info(
            *address,
            RevmAccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: bytecode.hash_slow(),
                code: Some(bytecode),
                ..RevmAccountInfo::default()
            },
        );
        for (key, value) in &account.storage {
            db.insert_account_storage(*address, *key, *value)
                .map_err(|e| format!("storage de revm: {e:?}"))?;
        }
    }
    Ok(db)
}

/// `Transaction` (nuestra) → `TxEnv` de revm. Los precios se pasan tal cual:
/// que revm aplique SU regla de fees es justamente lo que queremos comparar.
fn revm_tx(tx: &Transaction, env: &BlockEnv) -> Result<TxEnv, String> {
    let kind = tx.to.map_or(TxKind::Create, TxKind::Call);
    let (tx_type, gas_price, priority_fee) = match tx.tx_type {
        TxType::Legacy => (0u8, tx.gas_price.ok_or("tx legacy sin gasPrice")?, None),
        TxType::Eip1559 => (
            2u8,
            tx.max_fee_per_gas.ok_or("tx 1559 sin maxFeePerGas")?,
            Some(
                tx.max_priority_fee_per_gas
                    .ok_or("tx 1559 sin maxPriorityFeePerGas")?,
            ),
        ),
        other => return Err(format!("tipo de tx {other:?} fuera del slice")),
    };
    Ok(TxEnv {
        tx_type,
        caller: tx.sender,
        gas_limit: tx.gas_limit,
        gas_price,
        gas_priority_fee: priority_fee,
        kind,
        value: tx.value,
        data: tx.input.clone(),
        nonce: tx.nonce,
        chain_id: Some(env.chain_id),
        ..TxEnv::default()
    })
}

fn revm_summary(test: &StateTest, case: &PostCase, spec: Spec) -> Result<Summary, String> {
    let tx = test.transaction_for(case)?;
    let env = test.block_env(spec);
    let db = revm_db(&test.pre, &test.env.block_hashes)?;

    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = env.chain_id;
            cfg.spec = spec_id(spec);
        })
        .modify_block_chained(|block| apply_block_env(block, &env))
        .build_mainnet();

    let outcome = evm
        .transact(revm_tx(&tx, &env)?)
        .map_err(|e| format!("{e:?}"))?;

    // revm guarda el contador crudo: `spent()` es pre-refund y `refunded()` ya
    // viene capado por su handler. El número de protocolo —el que compara el
    // gate— es `spent − refunded`, calculado acá explícitamente en vez de
    // confiar en un helper cuya semántica no vemos.
    let (status, gas, output) = match &outcome.result {
        RevmExecutionResult::Success { gas, output, .. } => {
            (Status::Success, gas, revm_output(output))
        }
        RevmExecutionResult::Revert { gas, output, .. } => (Status::Revert, gas, output.clone()),
        RevmExecutionResult::Halt { gas, .. } => (Status::Halt, gas, Bytes::new()),
    };
    let gas_refunded = gas.final_refunded();
    let gas_used = gas.total_gas_spent().saturating_sub(gas_refunded);

    let mut post = test.pre.clone();
    for (address, account) in &outcome.state {
        if !account.is_touched() {
            continue;
        }
        if account.is_selfdestructed() {
            post.remove(address);
            continue;
        }
        let entry = post.entry(*address).or_insert_with(|| FixtureAccount {
            balance: U256::ZERO,
            nonce: 0,
            code: Bytes::new(),
            storage: BTreeMap::new(),
        });
        entry.balance = account.info.balance;
        entry.nonce = account.info.nonce;
        entry.code = account
            .info
            .code
            .as_ref()
            .map(Bytecode::original_bytes)
            .unwrap_or_default();
        for (key, slot) in &account.storage {
            entry.storage.insert(*key, slot.present_value);
        }
    }

    Ok(Summary {
        status,
        gas_used,
        gas_refunded,
        output,
        post: normalize(post),
    })
}

fn revm_output(output: &Output) -> Bytes {
    match output {
        Output::Call(data) | Output::Create(data, _) => data.clone(),
    }
}

/// Normalización del post-state, idéntica en los dos lados:
/// - fuera los slots en cero (no existen en el trie),
/// - fuera las cuentas vacías (EIP-161 state clearing: `balance == 0 &&
///   nonce == 0 && sin código`).
///
/// Es válida porque los fixtures de `fixtures/diff/` no traen cuentas vacías
/// en el pre-state (ahí sí habría que distinguir "vacía y no tocada").
fn normalize(mut post: PostState) -> PostState {
    for account in post.values_mut() {
        account.storage.retain(|_, value| !value.is_zero());
    }
    post.retain(|_, account| {
        !(account.balance.is_zero() && account.nonce == 0 && account.code.is_empty())
    });
    post
}

// -------------------------------------------------- primer paso divergente

/// Traza los dos motores y reporta el primer paso donde se separan. Solo se
/// llama cuando ya hay divergencia: es diagnóstico, no veredicto.
fn report_first_divergent_step(test: &StateTest, case: &PostCase, spec: Spec) {
    let ours = match trace_source::ours(test, case, spec) {
        Ok(trace) => trace,
        Err(e) => {
            eprintln!("        (no se pudo trazar nuestro lado: {e})");
            return;
        }
    };
    let oracle = match trace_source::revm(test, case, spec) {
        Ok(trace) => trace,
        Err(e) => {
            eprintln!("        (no se pudo trazar revm: {e})");
            return;
        }
    };
    match first_divergence(&ours, &oracle) {
        Some(divergence) => eprintln!("        primer paso divergente → {divergence}"),
        None => eprintln!(
            "        las trazas de opcodes coinciden: la divergencia está en la \
             liquidación de la tx (gas intrínseco / refund / fees), no en el intérprete"
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Vuelca nuestro `BlockEnv` en el de revm. Aislado para que un cambio de
/// campos de revm rompa acá y en un solo lugar.
fn apply_block_env(block: &mut revm::context::BlockEnv, env: &BlockEnv) {
    block.number = U256::from(env.number);
    block.timestamp = U256::from(env.timestamp);
    block.beneficiary = env.coinbase;
    block.gas_limit = env.gas_limit;
    block.basefee = env.base_fee;
    block.difficulty = U256::ZERO;
    block.prevrandao = Some(env.prevrandao);
    // BLOBBASEFEE: misma fracción de actualización (`repo_b_evm::blob`) que
    // usa `OwnVm`, para que revm derive el mismo precio de la MISMA regla —
    // no un número copiado a mano en los dos lados.
    if let Some(excess_blob_gas) = env.blob_excess_gas {
        block.set_blob_excess_gas_and_price(
            excess_blob_gas,
            repo_b_evm::blob::update_fraction(env.spec),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: Address = Address::new([0xAA; 20]);

    fn account(balance: u64, nonce: u64, slots: &[(u64, u64)]) -> FixtureAccount {
        FixtureAccount {
            balance: U256::from(balance),
            nonce,
            code: Bytes::new(),
            storage: slots
                .iter()
                .map(|(k, v)| (U256::from(*k), U256::from(*v)))
                .collect(),
        }
    }

    fn summary() -> Summary {
        Summary {
            status: Status::Success,
            gas_used: 43_106,
            gas_refunded: 4_800,
            output: Bytes::from_static(b"ok"),
            post: BTreeMap::from([(ALICE, account(10, 1, &[(0, 7)]))]),
        }
    }

    #[test]
    fn identical_summaries_have_no_differences() {
        assert!(compare(&summary(), &summary()).is_empty());
    }

    /// El comparador NO se debilita: cada campo observable dispara diferencia.
    #[test]
    fn every_observable_field_is_compared() {
        let cases: Vec<(&str, Summary)> = vec![
            (
                "status",
                Summary {
                    status: Status::Revert,
                    ..summary()
                },
            ),
            (
                "gas_used",
                Summary {
                    gas_used: 43_107,
                    ..summary()
                },
            ),
            (
                "refund",
                Summary {
                    gas_refunded: 0,
                    ..summary()
                },
            ),
            (
                "output",
                Summary {
                    output: Bytes::from_static(b"no"),
                    ..summary()
                },
            ),
            (
                "balance",
                Summary {
                    post: BTreeMap::from([(ALICE, account(11, 1, &[(0, 7)]))]),
                    ..summary()
                },
            ),
            (
                "nonce",
                Summary {
                    post: BTreeMap::from([(ALICE, account(10, 2, &[(0, 7)]))]),
                    ..summary()
                },
            ),
            (
                "storage",
                Summary {
                    post: BTreeMap::from([(ALICE, account(10, 1, &[(0, 8)]))]),
                    ..summary()
                },
            ),
            ("cuenta faltante", {
                Summary {
                    post: BTreeMap::new(),
                    ..summary()
                }
            }),
        ];
        for (field, mutated) in cases {
            assert!(
                !compare(&summary(), &mutated).is_empty(),
                "una diferencia de {field} pasó desapercibida"
            );
        }
    }

    #[test]
    fn normalize_drops_zero_slots_and_empty_accounts() {
        let post = BTreeMap::from([
            (ALICE, account(0, 0, &[(1, 0)])),
            (Address::new([0xBB; 20]), account(5, 0, &[(1, 0), (2, 9)])),
        ]);

        let normalized = normalize(post);

        // La cuenta vacía (balance 0, nonce 0, sin código) desaparece: EIP-161.
        assert!(!normalized.contains_key(&ALICE));
        let kept = normalized
            .get(&Address::new([0xBB; 20]))
            .unwrap_or_else(|| panic!("la cuenta no vacía sobrevive"));
        // Los slots en cero no existen en el trie.
        assert_eq!(kept.storage.len(), 1);
        assert_eq!(kept.storage.get(&U256::from(2u64)), Some(&U256::from(9u64)));
    }
}
