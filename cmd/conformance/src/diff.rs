//! Bridge diferencial **bit-idéntico vs `revm`**.
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
use repo_b_common::receipt::Log;
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::OwnVm;
use repo_b_evm::VmError;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;
use revm::context::TxEnv;
use revm::context::either::Either;
use revm::context::result::{ExecutionResult as RevmExecutionResult, Output};
use revm::context::transaction::{
    Authorization as RevmAuthorization, RecoveredAuthority, RecoveredAuthorization,
};
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::{TxKind, hardfork::SpecId};
use revm::state::{AccountInfo as RevmAccountInfo, Bytecode};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

use crate::fixture::{FixtureAccount, PostCase, StateTest, parse_file, spec_for_fork};
use crate::oracle::{
    LogRecord, Status, Summary, VERDICT_OURS_INTERNAL, VERDICT_TX_VALIDITY, compare, normalize,
};
use crate::runner::{MemoryState, apply_updates};
use crate::trace_diff::first_divergence;

mod trace_source;

#[derive(Debug, Default)]
pub struct Report {
    pub cases: u32,
    pub diverged: u32,
    pub skipped: u32,
}

/// El veredicto de UN caso. **Es el único veredicto que existe**: el modo
/// interactivo (`run_dir`) y cualquier generador que venga después consumen
/// esta misma función, así que el juez que gatea CI y el juez que va a
/// triazar un millón de casos son literalmente el mismo código.
///
/// `run_case` es **silencioso**: no imprime nada. A escala de fuzzing, un
/// `eprintln!` por caso es el cuello de botella y además ahoga la señal; el
/// reporte a stderr vive en `run_dir`, que es el modo humano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseOutcome {
    /// Fork fuera del scope post-Merge: el caso no se corrió. **No es "pasó"**.
    SkippedFork,
    /// Los dos motores coinciden byte a byte, campos de `Summary` incluidos.
    Same,
    /// **Los dos** motores rechazan la tx por inválida. Es acuerdo, pero NO es
    /// `Same`: acá no se ejecutó un solo opcode, y contarlo junto a los casos
    /// que sí corrieron haría que "0 divergencias en N casos" dijera más de lo
    /// que dice. La razón del rechazo no se compara (punto ciego declarado en
    /// `oracle::ORACLE_BLIND_SPOTS`); el veredicto sí.
    BothRejectedTx { ours: String },
    /// Divergen. `differences` **nunca** está vacío: si lo estuviera, el caso
    /// sería `Same`. Un motor que no pudo ejecutar también cae acá — no poder
    /// correr lo que el otro corre ES una divergencia.
    Diverged { differences: Vec<String> },
}

/// Por qué nuestro lado no produjo un `Summary`. La distinción es la MISMA
/// que ya rige para los bloques inválidos (`Rejection::{Protocol,
/// Internal}`) y sale de la taxonomía de `evm::error`, no de una lista de
/// strings: **rechazar una tx inválida es un veredicto del protocolo; un error
/// interno es un bug del motor y nunca cuenta como acuerdo.**
#[derive(Debug)]
enum OursFailure {
    /// `VmError::Consensus`: el motor juzgó la tx inválida.
    Rejected(String),
    /// `VmError::Internal` o un fallo del harness. Siempre divergencia.
    Internal(String),
}

/// El caso, sin disco y sin ruido. Todo lo que hace falta para un generador:
/// `StateTest`/`PostCase` se construyen en memoria (sus campos son `pub`).
pub fn run_case(test: &StateTest, case: &PostCase) -> CaseOutcome {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return CaseOutcome::SkippedFork;
    };
    verdict(
        ours_summary(test, case, spec),
        revm_summary(test, case, spec),
    )
}

/// El veredicto, aislado de la ejecución: las cinco combinaciones posibles de
/// "cada motor produjo un `Summary` o no", en una función pura y testeable.
/// Inline adentro de `run_case`, la rama que importa —un error interno nunca
/// es acuerdo— solo se podría probar con un caso que la reprodujera, y un
/// motor correcto no produce ninguno.
fn verdict(ours: Result<Summary, OursFailure>, oracle: Result<Summary, String>) -> CaseOutcome {
    match (ours, oracle) {
        (Ok(ours), Ok(oracle)) => {
            let differences = compare(&ours, &oracle);
            if differences.is_empty() {
                CaseOutcome::Same
            } else {
                CaseOutcome::Diverged { differences }
            }
        }
        // Un error interno NUNCA es acuerdo, aunque revm también falle: es un
        // bug del motor, no un veredicto sobre la tx.
        (Err(OursFailure::Internal(e)), _) => CaseOutcome::Diverged {
            differences: vec![format!("{VERDICT_OURS_INTERNAL}: {e}")],
        },
        // **Los dos rechazan la tx ⇒ acuerdo.** No es una excusa: es el
        // veredicto correcto, y sin él toda tx inválida sería un falso
        // positivo — a escala de fuzzing, la forma más rápida de ahogar la
        // señal. La RAZÓN del rechazo no se compara, y eso es
        // un punto ciego declarado en `oracle::ORACLE_BLIND_SPOTS`.
        (Err(OursFailure::Rejected(ours)), Err(_)) => CaseOutcome::BothRejectedTx { ours },
        (Err(OursFailure::Rejected(ours)), Ok(_)) => CaseOutcome::Diverged {
            differences: vec![format!(
                "{VERDICT_TX_VALIDITY}: nuestro la RECHAZA ({ours}) y revm la ejecuta"
            )],
        },
        (Ok(_), Err(oracle)) => CaseOutcome::Diverged {
            differences: vec![format!(
                "{VERDICT_TX_VALIDITY}: nuestro la ejecuta y revm la RECHAZA ({oracle})"
            )],
        },
    }
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

/// El modo interactivo: `run_case` + el reporte a stderr. **No re-implementa
/// la comparación** — si la re-implementara, el día que las dos deriven el
/// fuzzer estaría midiendo un juez distinto del que gatea CI.
fn run_one(test: &StateTest, case: &PostCase, report: &mut Report) {
    let label = format!("{} [{}]", test.name, case.fork);
    match run_case(test, case) {
        CaseOutcome::SkippedFork => {
            eprintln!("[SKIP] {label}: fork fuera de scope post-Merge");
            report.skipped = report.skipped.saturating_add(1);
        }
        CaseOutcome::Same => {
            report.cases = report.cases.saturating_add(1);
            eprintln!("[SAME] {label}");
        }
        CaseOutcome::BothRejectedTx { ours } => {
            report.cases = report.cases.saturating_add(1);
            eprintln!("[SAME] {label}: los dos motores rechazan la tx ({ours})");
        }
        CaseOutcome::Diverged { differences } => {
            report.cases = report.cases.saturating_add(1);
            report.diverged = report.diverged.saturating_add(1);
            eprintln!("[DIFF] {label}");
            for difference in &differences {
                eprintln!("        {difference}");
            }
            // Diagnóstico, no veredicto: el fork ya se resolvió adentro de
            // `run_case`, y sin él no hay traza que pedir.
            if let Some(spec) = spec_for_fork(&case.fork) {
                report_first_divergent_step(test, case, spec);
            }
        }
    }
}

// ------------------------------------------------------------------ lado propio

fn ours_summary(test: &StateTest, case: &PostCase, spec: Spec) -> Result<Summary, OursFailure> {
    let tx = test.transaction_for(case).map_err(OursFailure::Internal)?;
    let env = test.block_env(spec);
    let state = MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone());

    let outcome = OwnVm::new()
        .execute_tx(&tx, &env, &state)
        .map_err(|e| match e {
            VmError::Consensus(_) => OursFailure::Rejected(format!("{e}")),
            VmError::Internal(_) => OursFailure::Internal(format!("{e}")),
        })?;
    let post = apply_updates(&test.pre, &outcome.state_changes).map_err(OursFailure::Internal)?;

    // Los logs solo existen en `Success`: en Revert y en Halt el frame se
    // descarta con ellos adentro, y el tipo lo refleja (no llevan el campo).
    // La lista vacía de esas dos ramas no es un default de conveniencia — es
    // la única lista representable.
    let (status, gas_used, gas_refunded, output, logs) = match &outcome.result {
        ExecutionResult::Success {
            gas_used,
            gas_refunded,
            output,
            logs,
        } => (
            Status::Success,
            *gas_used,
            *gas_refunded,
            output.clone(),
            our_logs(logs),
        ),
        // `gas_refunded` NO es cero por defecto en Revert/Halt: el refund de
        // EIP-7702 sobrevive a los dos (ver `evm::result`).
        ExecutionResult::Revert {
            gas_used,
            gas_refunded,
            output,
        } => (
            Status::Revert,
            *gas_used,
            *gas_refunded,
            output.clone(),
            Vec::new(),
        ),
        ExecutionResult::Halt {
            gas_used,
            gas_refunded,
            ..
        } => (
            Status::Halt,
            *gas_used,
            *gas_refunded,
            Bytes::new(),
            Vec::new(),
        ),
    };
    Ok(Summary {
        status,
        gas_used,
        gas_refunded,
        output,
        logs,
        post: normalize(post),
    })
}

/// Nuestro `Log` → la terna comparable.
fn our_logs(logs: &[Log]) -> Vec<LogRecord> {
    logs.iter()
        .map(|log| LogRecord {
            address: log.address,
            topics: log.topics.clone(),
            data: log.data.clone(),
        })
        .collect()
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
        let bytecode = revm_bytecode(account.code.clone());
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

/// Código del pre-state → `Bytecode` de revm, **sin paniquear**.
///
/// `Bytecode::new_raw` PANIQUEA con cualquier código que empiece con el magic
/// `0xef01` y no sea un designator de EIP-7702 válido (23 bytes, versión
/// `0x00`): su implementación es `new_raw_checked(..).expect(..)`. Un
/// pre-state con esa forma no puede existir en una cadena real —EIP-3541
/// prohíbe desplegar código que arranque con `0xEF`— pero SÍ puede escribirse
/// en un fixture, y el fuzzer lo produjo en su primera campaña real.
///
/// El fallback correcto es `new_legacy`, y no una elección de comodidad: es
/// **la misma regla que aplica nuestro motor**. `common::authorization::
/// delegation_target` devuelve `None` para todo lo que no mida exactamente 23
/// bytes con el prefijo exacto, y ese código se ejecuta literal. Tratarlo como
/// legacy de los dos lados mantiene la comparación honesta; dejar que el
/// bridge paniquee la habría cancelado.
fn revm_bytecode(code: Bytes) -> Bytecode {
    Bytecode::new_raw_checked(code.clone()).unwrap_or_else(|_| Bytecode::new_legacy(code))
}

/// `Transaction` (nuestra) → `TxEnv` de revm. Los precios se pasan tal cual:
/// que revm aplique SU regla de fees es justamente lo que queremos comparar.
fn revm_tx(tx: &Transaction, env: &BlockEnv) -> Result<TxEnv, String> {
    let kind = tx.to.map_or(TxKind::Create, TxKind::Call);
    let (tx_type, gas_price, priority_fee) = match tx.tx_type {
        TxType::Legacy => (0u8, tx.gas_price.ok_or("tx legacy sin gasPrice")?, None),
        TxType::Eip2930 => (1u8, tx.gas_price.ok_or("tx 2930 sin gasPrice")?, None),
        TxType::Eip1559 => (
            2u8,
            tx.max_fee_per_gas.ok_or("tx 1559 sin maxFeePerGas")?,
            Some(
                tx.max_priority_fee_per_gas
                    .ok_or("tx 1559 sin maxPriorityFeePerGas")?,
            ),
        ),
        TxType::Eip4844 => (
            3u8,
            tx.max_fee_per_gas.ok_or("tx 4844 sin maxFeePerGas")?,
            Some(
                tx.max_priority_fee_per_gas
                    .ok_or("tx 4844 sin maxPriorityFeePerGas")?,
            ),
        ),
        TxType::Eip7702 => (
            4u8,
            tx.max_fee_per_gas.ok_or("tx 7702 sin maxFeePerGas")?,
            Some(
                tx.max_priority_fee_per_gas
                    .ok_or("tx 7702 sin maxPriorityFeePerGas")?,
            ),
        ),
    };
    let access_list = revm::context::transaction::AccessList(
        tx.access_list
            .iter()
            .map(|item| revm::context::transaction::AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect(),
    );
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
        access_list,
        // EIP-4844: vacío/0 en toda tx no-4844 por el invariante
        // de construcción de `Transaction` — pasarlos siempre es inofensivo
        // para los demás tipos.
        blob_hashes: tx.blob_versioned_hashes.clone(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas.unwrap_or(0),
        // EIP-7702: se le inyecta a revm el authority **ya
        // recuperado** (`RecoveredAuthorization`), igual que el `sender` de la
        // tx — el diferencial no hace ECDSA de ningún lado, así que ninguno de
        // los dos motores tiene ventaja. `RecoveredAuthority::Invalid` modela
        // la firma inválida (tupla salteada sin invalidar la tx).
        authorization_list: tx
            .authorization_list
            .iter()
            .map(|auth| {
                Either::Right(RecoveredAuthorization::new_unchecked(
                    RevmAuthorization {
                        chain_id: auth.chain_id,
                        address: auth.address,
                        nonce: auth.nonce,
                    },
                    match auth.authority {
                        Some(authority) => RecoveredAuthority::Valid(authority),
                        None => RecoveredAuthority::Invalid,
                    },
                ))
            })
            .collect(),
        // Sin `..TxEnv::default()`: los campos de arriba son TODOS los que
        // `TxEnv` tiene hoy, así que el rest-pattern no rellenaba nada y
        // encima ocultaba el día en que revm agregue un campo nuevo — que es
        // exactamente el día en que hay que decidir qué le pasamos al oráculo.
        // Sin él, ese día no compila. Mismo criterio que `apply_block_env`.
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

    // revm guarda el contador crudo: `total_gas_spent()` es pre-refund y
    // `refunded()`/`final_refunded()` ya vienen capados por su handler. El
    // número de protocolo —el que compara el gate— es `max(spent − refunded,
    // floor_gas)`, calculado acá explícitamente en vez de confiar en un
    // helper cuya semántica no vemos.
    //
    // CUIDADO: `gas`
    // acá es el `ResultGas` que `post_execution` arma ANTES de aplicar el
    // clamp de EIP-7623 (`eip7623_check_gas_floor` corre DESPUÉS, mutando el
    // `Gas` interno, no este `ResultGas`) — `total_gas_spent()` NUNCA refleja
    // el floor. `final_refunded()` sí lo sabe (0 si el floor muerde), pero
    // `total_gas_spent() − final_refunded()` SOLO da el número correcto
    // cuando el floor no muerde; si muerde, subestima el gas real (puede caer
    // por debajo de `floor_gas`). El getter correcto es `tx_gas_used()` =
    // `max(total_gas_spent() − refunded_crudo(), floor_gas)` — usarlo
    // directo, no reimplementar la resta a mano.
    let (status, gas, output) = match &outcome.result {
        RevmExecutionResult::Success { gas, output, .. } => {
            (Status::Success, gas, revm_output(output))
        }
        RevmExecutionResult::Revert { gas, output, .. } => (Status::Revert, gas, output.clone()),
        RevmExecutionResult::Halt { gas, .. } => (Status::Halt, gas, Bytes::new()),
    };
    let gas_refunded = gas.final_refunded();
    let gas_used = gas.tx_gas_used();
    // revm lleva `logs` en las TRES ramas (verificado en
    // `revm-context-interface` 17.0.1 `result.rs`: `Success`/`Revert`/`Halt`
    // tienen el campo, y `output()` los toma de `journal.take_logs()`). Se
    // leen sin distinguir la rama a propósito: si revm reportara logs en un
    // revert donde nosotros no podemos reportarlos, eso es exactamente la
    // divergencia que hay que ver, no una que haya que suprimir con un
    // `match` que devuelva vacío.
    let logs = revm_logs(outcome.result.logs());

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
        logs,
        post: normalize(post),
    })
}

/// `Log` de revm (`alloy_primitives::Log<LogData>`) → la MISMA terna.
fn revm_logs(logs: &[revm::primitives::Log]) -> Vec<LogRecord> {
    logs.iter()
        .map(|log| LogRecord {
            address: log.address,
            topics: log.topics().to_vec(),
            data: log.data.data.clone(),
        })
        .collect()
}

fn revm_output(output: &Output) -> Bytes {
    match output {
        Output::Call(data) | Output::Create(data, _) => data.clone(),
    }
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
        // El trace de EIP-3155 lleva stack/memoria/gas por paso, NO los
        // logs emitidos: con `logs` adentro de `Summary`, "las trazas
        // coinciden" ya no implica que el intérprete esté limpio.
        None => eprintln!(
            "        las trazas de opcodes coinciden: la divergencia está fuera de lo \
             que el trace registra — liquidación de la tx (gas intrínseco / refund / \
             fees) o los logs emitidos, que EIP-3155 no lleva"
        ),
    }
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
    use crate::fuzz::generate::{SENDER, generate_case};
    use crate::oracle::ORACLE_BLIND_SPOTS;

    /// **Punto ciego 4 — la razón del rechazo de una tx inválida.**
    ///
    /// Demostración de comportamiento, no de prosa: una tx con nonce
    /// equivocado la rechazan LOS DOS motores, y `run_case` dictamina acuerdo
    /// **sin haber comparado el motivo**. El día que el motivo se compare,
    /// este test se pone rojo — que es el día en que la entrada del
    /// inventario deja de ser cierta.
    ///
    /// Que esto sea acuerdo y no divergencia no es una excusa: es el veredicto
    /// correcto. El comparador NO se debilitó — antes ni siquiera le
    /// preguntaba a revm, porque un error nuestro cortocircuitaba el caso.
    #[test]
    fn both_engines_rejecting_the_same_invalid_tx_is_agreement() {
        let mut case = generate_case(0x1234, 1);
        case.accounts.clear();
        case.to = Some(SENDER);
        let mut test = case.to_state_test();
        // Nonce del futuro: inválida para cualquier motor que siga el
        // protocolo, y por razones que cada uno nombra a su manera.
        test.tx.nonce = 99;
        let post = case.post_case();

        assert!(
            matches!(run_case(&test, &post), CaseOutcome::BothRejectedTx { .. }),
            "un rechazo mutuo no se distinguió de una corrida que coincide"
        );
        assert!(
            ORACLE_BLIND_SPOTS
                .iter()
                .any(|spot| spot.what.contains("tx INVÁLIDA")),
            "la ceguera al motivo del rechazo está demostrada pero no inventariada"
        );
    }

    fn empty_summary() -> Summary {
        Summary {
            status: Status::Success,
            gas_used: 21_000,
            gas_refunded: 0,
            output: Bytes::new(),
            logs: Vec::new(),
            post: BTreeMap::new(),
        }
    }

    /// Las cinco ramas del veredicto, una por una. **La que importa es la
    /// tercera**: un error interno nuestro no es acuerdo aunque revm también
    /// falle — es la misma regla que el driver de bloque fijó como TIPO (`Rejection::
    /// {Protocol, Internal}`) para los bloques inválidos. Probarla por un caso
    /// real es imposible por construcción: un motor correcto no produce
    /// ninguno, y esa es exactamente la forma de mutación muda que este repo
    /// ya catalogó (027, "estructura del corpus").
    #[test]
    fn the_five_verdict_branches_do_what_they_say() {
        // 1. Los dos ejecutan y coinciden.
        assert_eq!(
            verdict(Ok(empty_summary()), Ok(empty_summary())),
            CaseOutcome::Same
        );
        // 2. Los dos ejecutan y difieren.
        let other = Summary {
            gas_used: 21_001,
            ..empty_summary()
        };
        assert!(matches!(
            verdict(Ok(empty_summary()), Ok(other)),
            CaseOutcome::Diverged { .. }
        ));
        // 3. Error INTERNO nuestro + fallo de revm: divergencia, no acuerdo.
        match verdict(
            Err(OursFailure::Internal("bug del motor".to_owned())),
            Err("revm tambien".to_owned()),
        ) {
            CaseOutcome::Diverged { differences } => assert!(
                differences.iter().any(|d| d.contains("error interno")),
                "{differences:?}"
            ),
            other => panic!("un error interno se contó como acuerdo: {other:?}"),
        }
        // 4. Los dos RECHAZAN la tx: acuerdo, pero en su propia categoría —
        //    no se ejecutó un opcode y el reporte no puede confundirlo con un
        //    caso que sí corrió.
        assert_eq!(
            verdict(
                Err(OursFailure::Rejected("nonce".to_owned())),
                Err("nonce".to_owned())
            ),
            CaseOutcome::BothRejectedTx {
                ours: "nonce".to_owned()
            }
        );
        // 5. Rechazo de UN SOLO lado, en las dos direcciones.
        for outcome in [
            verdict(
                Err(OursFailure::Rejected("nonce".to_owned())),
                Ok(empty_summary()),
            ),
            verdict(Ok(empty_summary()), Err("nonce".to_owned())),
        ] {
            match outcome {
                CaseOutcome::Diverged { differences } => assert!(
                    differences.iter().any(|d| d.contains("validez de la tx")),
                    "{differences:?}"
                ),
                other => panic!("un rechazo unilateral pasó como acuerdo: {other:?}"),
            }
        }
    }

    /// Un `PUSH` truncado de EIP-7702 en el pre-state hacía **paniquear** el
    /// bridge (`Bytecode::new_raw` es `new_raw_checked(..).expect(..)`). Lo
    /// encontró el fuzzer en su primera campaña real.
    #[test]
    fn a_malformed_delegation_designator_does_not_panic_the_bridge() {
        // `0xef01` + longitud equivocada: no es un designator válido.
        let code = Bytes::from_static(&[0xef, 0x01, 0x00, 0xaa, 0xbb]);
        let bytecode = revm_bytecode(code.clone());
        assert_eq!(bytecode.original_bytes(), code);
    }
}
