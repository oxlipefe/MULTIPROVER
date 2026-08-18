//! Harness de conformance — el GATE de existencia de Repo B (Fase 2).
//!
//! Ejes del gate:
//!   1. EF `GeneralStateTests` + blockchain tests (set de zeth: ≈32999 + 8338).
//!   2. Diferencial **bit-idéntico vs `revm`** por bloque (feature `diff-revm`).
//!
//! Desde Fase 1 corre el subset de fixtures **vendoreados** (`fixtures/`): el
//! exit code refleja ESTA corrida (una regresión del subset rompe CI) y el
//! reporte deja explícito que el gate global de Fase 2 sigue RED hasta igualar
//! el set completo de zeth.

mod blockchain;
#[cfg(feature = "diff-revm")]
mod diff;
mod eest;
mod fixture;
mod runner;
mod trace_diff;

use std::path::PathBuf;
use std::process::ExitCode;

use runner::CaseOutcome;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/GeneralStateTests")
}

/// Resuelve un path de fixtures: tal cual (relativo al CWD) o, si no existe,
/// relativo al crate. El gate se corre desde la raíz del repo con
/// `--diff fixtures/diff/storage`, pero los fixtures viven junto al harness.
#[cfg(feature = "diff-revm")]
fn resolve_fixture_path(arg: &str) -> PathBuf {
    let direct = PathBuf::from(arg);
    if direct.exists() {
        return direct;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(arg)
}

/// `--diff <dir>`: modo diferencial vs revm sobre un set de fixtures.
fn diff_target() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--diff" {
            return Some(args.next().unwrap_or_default());
        }
    }
    None
}

fn main() -> ExitCode {
    // `--eest-blockchain` se chequea ANTES que `--eest`: son dos flags
    // distintas y una comparación por prefijo las confundiría.
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "--eest-blockchain")
    {
        return run_eest_blockchain();
    }
    if std::env::args().skip(1).any(|arg| arg == "--eest") {
        return run_eest();
    }
    if let Some(target) = diff_target() {
        return run_diff(&target);
    }
    run_vendored_subset()
}

/// `--eest`: el set de execution-spec-tests pineado.
///
/// Sale 0 si el harness corrió el set y **no retrocedió** contra el baseline.
/// NO exige "todo verde": eso es el gate de FASE, no el de esta corrida.
fn run_eest() -> ExitCode {
    eprintln!("== Repo B — execution-spec-tests (state_test, Paris..Prague) ==");
    let report = match eest::run() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    eest::print_report(&report);
    match eest::check_ratchet(&report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--eest-blockchain`: el otro eje del gate de Fase 2, con baseline propio.
///
/// Mismo contrato que `--eest`: sale 0 si el harness corrió el set y no
/// retrocedió contra SU baseline. Los dos baselines son independientes para que
/// una mejora de un eje no tape una regresión del otro.
fn run_eest_blockchain() -> ExitCode {
    eprintln!("== Repo B — execution-spec-tests (blockchain_test, Paris..Cancun) ==");
    let report = match blockchain::eest::run() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    blockchain::eest::print_report(&report);
    match blockchain::eest::check_ratchet(&report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            ExitCode::FAILURE
        }
    }
}

/// Modo diferencial. Sin la feature `diff-revm` no hay oráculo: fail-closed,
/// nunca "pasar" sin comparar contra nada.
#[cfg(feature = "diff-revm")]
fn run_diff(target: &str) -> ExitCode {
    let dir = resolve_fixture_path(target);
    eprintln!("== Repo B — diferencial bit-idéntico vs revm =38.0.0 ==");
    eprintln!("set: {}", dir.display());
    eprintln!();

    let report = diff::run_dir(&dir);
    eprintln!();
    eprintln!(
        "diferencial: {} casos, {} divergencias, {} skip",
        report.cases, report.diverged, report.skipped
    );
    if report.cases == 0 {
        eprintln!("[FAIL] el set no ejecutó ningún caso: un set vacío NO es verde");
        return ExitCode::FAILURE;
    }
    if report.diverged == 0 {
        eprintln!("[OK] 0 divergencias vs revm en este set");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(feature = "diff-revm"))]
fn run_diff(_target: &str) -> ExitCode {
    eprintln!(
        "--diff requiere el oráculo: recompilá con `--features diff-revm`. \
         Sin revm no hay contra qué comparar (fail-closed)."
    );
    ExitCode::FAILURE
}

fn run_vendored_subset() -> ExitCode {
    eprintln!("== Repo B — conformance gate ==");
    eprintln!();

    let dir = fixtures_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("no se pudo leer {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    };

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("[FAIL] {}: no se pudo leer: {e}", path.display());
                failed = failed.saturating_add(1);
                continue;
            }
        };
        let tests = match fixture::parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => {
                eprintln!("[FAIL] {}: {e}", path.display());
                failed = failed.saturating_add(1);
                continue;
            }
        };
        for test in &tests {
            for case in &test.posts {
                let label = format!("{} [{}]", short_name(&test.name), case.fork);
                match runner::run_case(test, case) {
                    CaseOutcome::Pass => {
                        eprintln!("[PASS] {label}");
                        passed = passed.saturating_add(1);
                    }
                    CaseOutcome::SkippedFork(fork) => {
                        eprintln!("[SKIP] {label}: fork {fork} fuera de scope post-Merge");
                        skipped = skipped.saturating_add(1);
                    }
                    CaseOutcome::Fail(reason) => {
                        eprintln!("[FAIL] {label}: {reason}");
                        failed = failed.saturating_add(1);
                    }
                }
            }
        }
    }

    eprintln!();
    eprintln!("subset vendoreado: {passed} PASS, {failed} FAIL, {skipped} SKIP");
    #[cfg(feature = "diff-revm")]
    eprintln!("[diferencial bit-idéntico vs revm] feature ACTIVA, bridge pendiente (Fase 2).");
    #[cfg(not(feature = "diff-revm"))]
    eprintln!("[diferencial bit-idéntico vs revm] feature inactiva; se activa en Fase 2.");
    eprintln!(
        "GATE Fase 2 (existencia): RED — target: el set completo de EEST + el \
         diferencial bit-idéntico vs revm."
    );

    // Exit = resultado de ESTA corrida (subset vendoreado). El gate global
    // sigue siendo el de Fase 2, medido con `--eest`.
    if failed == 0 && passed > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// El nombre del test dentro del fixture repite el path completo; recorta.
fn short_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}
