//! `--record-replay`: el gate del grabador de accesos.
//!
//! Tres corridas del MISMO caso y dos propiedades:
//!
//! 1. **Transparencia** — envuelto en el recorder, el caso da exactamente el
//!    mismo veredicto que sin envolver. Sin esto, todo lo demás mediría un
//!    grabador que no está en el camino de ejecución real.
//! 2. **Suficiencia** — alimentado *solo* por lo grabado (`StrictState`,
//!    fail-closed), el caso vuelve a dar ese veredicto. Es "no grabó de menos".
//! 3. **Minimalidad** — quitándole al log un ítem cualquiera, el caso deja de
//!    darlo. Es "no grabó de más", y es la mitad que un replay solo no puede
//!    probar: sobrar nunca rompe un replay.
//!
//! El veredicto que se compara es el observable de consenso (root del
//! post-state, status y hash de logs), no la estructura interna del outcome: si
//! dos corridas producen el mismo root y el mismo status, produjeron el mismo
//! bloque.

use std::collections::BTreeMap;
use std::path::Path;

use repo_b_common::primitives::B256;
use repo_b_evm::OwnVm;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::state::State;
use repo_b_evm::vm::Vm;
use repo_b_witness::{AccessLog, RecordingState, StrictState};

use crate::fixture::{PostCase, StateTest, parse_file, spec_for_fork};
use crate::runner::{MemoryState, apply_updates, compute_state_root, logs_hash};

#[derive(Debug, Default)]
pub struct Report {
    pub cases: u32,
    /// Casos donde el recorder cambió el veredicto.
    pub not_transparent: u32,
    /// Casos donde el replay contra lo grabado no reprodujo el veredicto.
    pub insufficient: u32,
    /// Ítems que se pudieron quitar del log sin que la ejecución lo notara.
    pub superfluous: u32,
    /// Ítems grabados en total (denominador de la minimalidad).
    pub items: u64,
    pub skipped: u32,
}

impl Report {
    #[must_use]
    pub fn failed(&self) -> u32 {
        self.not_transparent
            .saturating_add(self.insufficient)
            .saturating_add(self.superfluous)
    }
}

/// Lo que un cliente ve de una ejecución. Dos corridas con el mismo `Verdict`
/// produjeron el mismo bloque.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    root: B256,
    status: String,
    logs: B256,
}

/// Corre el caso contra el `State` dado. `Err` es un resultado válido y
/// comparable: una tx rechazada por consenso lo es, y un acceso que el witness
/// no tiene también — por eso el mensaje entra en la comparación.
fn run_with(test: &StateTest, case: &PostCase, state: &dyn State) -> Result<Verdict, String> {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Err("fork fuera de scope".to_owned());
    };
    let tx = test.transaction_for(case)?;
    let env = test.block_env(spec);
    let outcome = match OwnVm::new().execute_tx(&tx, &env, state) {
        Ok(outcome) => Some(outcome),
        Err(e) => return Err(format!("{e}")),
    };
    let (logs, status) = match outcome.as_ref().map(|out| &out.result) {
        Some(ExecutionResult::Success { logs, .. }) => (logs.as_slice(), "success".to_owned()),
        Some(ExecutionResult::Revert { .. }) => ([].as_slice(), "revert".to_owned()),
        Some(ExecutionResult::Halt { reason, .. }) => ([].as_slice(), format!("halt:{reason:?}")),
        None => ([].as_slice(), "rejected".to_owned()),
    };
    let changes = outcome
        .as_ref()
        .map_or([].as_slice(), |out| out.state_changes.as_slice());
    let post = apply_updates(&test.pre, changes)?;
    Ok(Verdict {
        root: compute_state_root(&post),
        status,
        logs: logs_hash(logs),
    })
}

fn base_state(test: &StateTest) -> MemoryState {
    MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone())
}

/// Un caso: graba, replaya y mide la minimalidad del log.
pub fn run_one(test: &StateTest, case: &PostCase, report: &mut Report, minimality: bool) {
    if spec_for_fork(&case.fork).is_none() || test.require_post_merge_env().is_err() {
        report.skipped = report.skipped.saturating_add(1);
        return;
    }
    report.cases = report.cases.saturating_add(1);

    let base = run_with(test, case, &base_state(test));

    // 1. Transparencia.
    let recorder = RecordingState::new(Box::new(base_state(test)));
    let recorded = run_with(test, case, &recorder);
    if recorded != base {
        report.not_transparent = report.not_transparent.saturating_add(1);
        eprintln!(
            "[FAIL] {} ({}): el recorder cambió el veredicto\n  sin envolver: {base:?}\n  envuelto:     {recorded:?}",
            test.name, case.fork
        );
        return;
    }
    let log = recorder.log();
    report.items = report.items.saturating_add(log.items().len() as u64);

    // 2. Suficiencia.
    let replayed = run_with(test, case, &StrictState::new(log.clone()));
    if replayed != base {
        report.insufficient = report.insufficient.saturating_add(1);
        eprintln!(
            "[FAIL] {} ({}): el replay contra lo grabado no reprodujo el veredicto\n  completo: {base:?}\n  witness:  {replayed:?}",
            test.name, case.fork
        );
        return;
    }

    // 3. Minimalidad.
    if minimality {
        for item in log.items() {
            let recortado = log.without(&item);
            if run_with(test, case, &StrictState::new(recortado)) == base {
                report.superfluous = report.superfluous.saturating_add(1);
                eprintln!(
                    "[FAIL] {} ({}): el log grabó de más — quitar {item:?} no cambia nada",
                    test.name, case.fork
                );
            }
        }
    }
}

/// Corre un directorio de fixtures. Mismo formato que consume el diferencial.
pub fn run_dir(dir: &Path, report: &mut Report, minimality: bool) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("[FAIL] no se pudo leer {}: {e}", dir.display());
            report.insufficient = report.insufficient.saturating_add(1);
            return;
        }
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();

    for path in paths {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("[FAIL] {}: no se pudo leer: {e}", path.display());
                report.insufficient = report.insufficient.saturating_add(1);
                continue;
            }
        };
        let tests = match parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => {
                eprintln!("[FAIL] {}: {e}", path.display());
                report.insufficient = report.insufficient.saturating_add(1);
                continue;
            }
        };
        for test in &tests {
            for case in &test.posts {
                run_one(test, case, report, minimality);
            }
        }
    }
}

/// Los mismos 21 sets que gatea el diferencial, más el subset vendoreado.
/// Deliberadamente no es "todo EEST": pasar el corpus entero por el witness es
/// un paso aparte, y mezclarlos haría que un fallo de cobertura y uno de escala
/// se confundieran.
pub const SETS: &[&str] = &[
    "access-list",
    "arithmetic",
    "blake2f",
    "blob-tx",
    "bls12-381",
    "bn254",
    "calls",
    "create",
    "create-collision",
    "extcode",
    "kzg",
    "logs-env",
    "modexp",
    "opcode-fork",
    "precompile-basic",
    "precompile-fork",
    "selfdestruct-fork",
    "set-code",
    "storage",
    "tx-target",
    "tx-validation",
];

/// Devuelve el reporte de correr todos los sets del subconjunto.
#[must_use]
pub fn run_sets(root: &Path, minimality: bool) -> Report {
    let mut report = Report::default();
    for set in SETS {
        run_dir(&root.join("diff").join(set), &mut report, minimality);
    }
    report
}

/// El mapa de qué cubre el subconjunto, para que la cobertura sea auditable en
/// vez de declarada: cuántos casos tocaron cada método del seam.
#[must_use]
pub fn coverage(root: &Path) -> BTreeMap<&'static str, u32> {
    let mut hits: BTreeMap<&'static str, u32> = BTreeMap::new();
    for set in SETS {
        let dir = root.join("diff").join(set);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<_> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        paths.sort();
        for path in paths {
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(tests) = parse_file(&raw) else {
                continue;
            };
            for test in &tests {
                for case in &test.posts {
                    if spec_for_fork(&case.fork).is_none() {
                        continue;
                    }
                    let recorder = RecordingState::new(Box::new(base_state(test)));
                    let _ = run_with(test, case, &recorder);
                    tally(&recorder.log(), &mut hits);
                }
            }
        }
    }
    hits
}

fn tally(log: &AccessLog, hits: &mut BTreeMap<&'static str, u32>) {
    let mut bump = |key: &'static str, present: bool| {
        if present {
            *hits.entry(key).or_default() += 1;
        }
    };
    bump("account", !log.accounts.is_empty());
    bump(
        "account:ausente",
        log.accounts.values().any(Option::is_none),
    );
    bump("storage", !log.storage.is_empty());
    bump("storage_root", !log.storage_roots.is_empty());
    bump("code", !log.code.is_empty());
    bump("code_metadata", !log.code_metadata.is_empty());
    bump("block_hash", !log.block_hashes.is_empty());
}
