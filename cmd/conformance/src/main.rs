//! Harness de conformance — el GATE de existencia de Repo B (Fase 2).
//!
//! Ejes del gate (fuente única de verdad: `docs/knowledge/CONFORMANCE.md`):
//!   1. EF `GeneralStateTests` + blockchain tests (set de zeth: ≈32999 + 8338).
//!   2. Diferencial **bit-idéntico vs `revm`** por bloque (feature `diff-revm`).
//!
//! Desde Fase 1 corre el subset de fixtures **vendoreados** (`fixtures/`): el
//! exit code refleja ESTA corrida (una regresión del subset rompe CI) y el
//! reporte deja explícito que el gate global de Fase 2 sigue RED hasta igualar
//! el set completo de zeth.

mod fixture;
mod runner;

use std::path::PathBuf;
use std::process::ExitCode;

use runner::CaseOutcome;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/GeneralStateTests")
}

fn main() -> ExitCode {
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
        "GATE Fase 2 (existencia): RED — target ≈32999 GeneralStateTests + 8338 blockchain \
         tests + diferencial-vs-revm. Estado: docs/knowledge/CONFORMANCE.md"
    );

    // Exit = resultado de ESTA corrida (subset vendoreado). El gate global
    // sigue siendo el de Fase 2 y se trackea en CONFORMANCE.md.
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
