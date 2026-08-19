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
mod fuzz;
mod oracle;
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
    if std::env::args().skip(1).any(|arg| arg == "--fuzz") {
        return run_fuzz();
    }
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
    eprintln!("== Repo B — execution-spec-tests (blockchain_test, Paris..Prague) ==");
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
    let verdict = if report.diverged == 0 {
        eprintln!("[OK] 0 divergencias vs revm en este set");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    // El veredicto no se publica solo: sin el inventario, "0 divergencias" se
    // lee como una afirmación más fuerte de la que es.
    oracle::print_oracle_inventory();
    verdict
}

/// `--fuzz`: la campaña de fuzzing diferencial.
///
/// Flags: `--seed <hex|dec>`, `--cases N`, `--case N` (índice de arranque),
/// `--out <dir>` (trinquete), `--stop-on-first`, y el generador:
///
/// - por defecto, la **gramática** (`--seed-corpus` la siembra desde
///   `fixtures/diff/`);
/// - `--uniform`: bytes al azar, el contraste de la gramática;
/// - `--mutate`: la **mutación de EEST**;
/// - `--mutate-passthrough` y `--mutate-bytes`: sus dos contrastes.
///
/// **La semilla NO se sortea con la hora del sistema.** Si no se pasa, se usa
/// una constante: el determinismo absoluto vale para el harness igual que para
/// el guest, y una campaña que no se puede repetir no produce
/// hallazgos, produce anécdotas.
#[cfg(feature = "diff-revm")]
fn run_fuzz() -> ExitCode {
    use fuzz::campaign::{CampaignConfig, Generator, print_report, run};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|arg| arg == flag);
    // El orden es de más específico a menos: los tres modos de mutación son
    // excluyentes entre sí y con la gramática.
    let generator = if has("--mutate-passthrough") {
        Generator::MutatePassthrough
    } else if has("--mutate-bytes") {
        Generator::MutateByteLevel
    } else if has("--mutate") {
        Generator::Mutate
    } else if has("--uniform") {
        Generator::GrammarUniform
    } else {
        Generator::Grammar
    };
    let config = CampaignConfig {
        seed: flag_value(&args, "--seed")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(DEFAULT_FUZZ_SEED),
        start_index: flag_value(&args, "--case")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(0),
        cases: flag_value(&args, "--cases")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(DEFAULT_FUZZ_CASES),
        out_dir: flag_value(&args, "--out").map(PathBuf::from),
        generator,
        seed_corpus: has("--seed-corpus"),
        stop_on_first: has("--stop-on-first"),
        seed_root: flag_value(&args, "--seed-root").map(PathBuf::from),
    };

    eprintln!("== Repo B — fuzzing diferencial vs revm =38.0.0 ==");
    // Un corpus que no está NO se degrada a una campaña vacía: sin semillas el
    // generador de mutación no genera nada y reportaría "0 divergencias" con
    // toda tranquilidad, que es el modo vacuo contra el que fail-closed existe.
    let report = match run(&config) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&config, &report);
    oracle::print_oracle_inventory();

    // Un fixture del trinquete que no reproduce es un fallo del harness, no un
    // detalle: sin eso el corpus crece con casos que no prueban nada.
    let liar = report
        .findings
        .iter()
        .any(|finding| finding.fixture_reproduces == Some(false));
    if liar {
        eprintln!("[FAIL] un fixture emitido no vuelve a divergir");
        return ExitCode::FAILURE;
    }
    if report.diverged == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Semilla por defecto de la campaña. Constante y nombrada: ver `run_fuzz`.
#[cfg(feature = "diff-revm")]
const DEFAULT_FUZZ_SEED: u64 = 0x2026_0818_29D2;
#[cfg(feature = "diff-revm")]
const DEFAULT_FUZZ_CASES: u64 = 2_000;

#[cfg(feature = "diff-revm")]
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let position = args.iter().position(|arg| arg == flag)?;
    args.get(position.saturating_add(1)).cloned()
}

/// Acepta decimal o `0x`-hex. Un valor que no parsea NO cae a un default
/// silencioso: se reporta y la campaña arranca con el default, que se imprime.
#[cfg(feature = "diff-revm")]
fn parse_u64(raw: &str) -> Option<u64> {
    let parsed = match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse::<u64>(),
    };
    match parsed {
        Ok(value) => Some(value),
        Err(e) => {
            eprintln!("[warn] no se pudo leer '{raw}': {e}; se usa el valor por defecto");
            None
        }
    }
}

#[cfg(not(feature = "diff-revm"))]
fn run_fuzz() -> ExitCode {
    eprintln!(
        "--fuzz requiere el oráculo: recompilá con `--features diff-revm`. \
         Un fuzzer sin oráculo genera casos y no juzga ninguno (fail-closed)."
    );
    ExitCode::FAILURE
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
    // Los DOS ejes de EEST cerraron sin residuo (`--eest` 39 025/39 025,
    // `--eest-blockchain` 42 017/42 017) y el diferencial va 315/315. Aun así
    // el gate de FASE sigue RED, y a propósito: falta el fuzzing diferencial, y
    // **cerrar la fase es una decisión humana**, no algo que este harness pueda
    // declararse a sí mismo.
    eprintln!(
        "GATE Fase 2 (existencia): RED — los dos ejes de EEST cerraron; falta el fuzzing \
         diferencial y el cierre de fase es una decisión humana."
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
