//! El lazo de la campaña: generar → juzgar → minimizar → trinquetear.
//!
//! Vive detrás de `diff-revm` porque el juez es revm in-process. Todo lo que
//! NO necesita al oráculo (PRNG, gramática, shrinker, emisor, triage) vive
//! fuera de la feature a propósito: así sus tests corren en
//! `cargo test --workspace` sin ella, que es la lección que dejó mudar el juez
//! a `oracle.rs`: un test que CI no corre no pinea nada.
//!
//! ## Por qué el lazo es propio y no `proptest::TestRunner`
//!
//! Se leyó la API de la versión pineada (1.11.0) antes de decidir — la lección
//! del bump de `ruint` —, y hay tres hechos que la descartan para ESTE lazo,
//! ninguno de los cuales es un defecto de `proptest`:
//!
//! 1. **No hay direccionamiento `(semilla, índice)`.** `TestRunner` avanza un
//!    solo RNG caso a caso y deriva el de cada caso con `TestRng::gen_rng`, que
//!    es `pub(crate)`. Reproducir el caso 900 000 exigiría re-generar los
//!    899 999 anteriores. La regla de determinismo pide lo contrario, y de ahí
//!    sale además que
//!    una campaña se pueda repartir por rangos de índice sin coordinación.
//! 2. **El shrinking integrado acepta cualquier fallo.** `ValueTree::simplify`
//!    se guía por un `TestCaseResult` booleano; nuestra regla es más fuerte:
//!    un paso se acepta solo si el caso reducido sigue divergiendo **por la
//!    misma diferencia**. Con el predicado booleano, un caso que empieza
//!    divergiendo en `gas_used` puede terminar minimizado a otro que diverge en
//!    `status` — el reproductor de otro bug.
//! 3. **`TestRunner::run` termina en el primer fallo.** Una campaña tiene que
//!    seguir después de un hallazgo, clasificarlo y buscar el siguiente.
//!
//! `proptest` sigue siendo la herramienta correcta donde ya se usa
//! (`crates/interpreter/tests/wrapping.rs`: una propiedad acotada dentro de
//! `cargo test`). Acá el trabajo es otro.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::diff::{CaseOutcome, run_case};
use crate::fuzz::corpus::{Corpus, default_corpus_dir};
use crate::fuzz::coverage::{Coverage, implemented_opcodes, observe};
use crate::fuzz::emit::write_fixture;
use crate::fuzz::generate::{FuzzCase, generate_case_with};
use crate::fuzz::shrink::{ShrinkStats, shrink};
use crate::fuzz::triage::{signature, signature_slug};

/// Cada cuántos casos se toma una muestra para la métrica de cobertura.
/// Trazar cuesta una ejecución extra por caso: muestrear mantiene el lazo
/// rápido y la métrica sigue siendo una medición, no una estimación de nadie.
const COVERAGE_SAMPLE_EVERY: u64 = 8;

#[derive(Debug, Clone)]
pub struct CampaignConfig {
    pub seed: u64,
    pub start_index: u64,
    pub cases: u64,
    /// Dónde se escriben los fixtures del trinquete. `None` = no escribir
    /// (el modo de medición planta un bug a propósito, y sus hallazgos NO son
    /// divergencias reales que deban entrar al corpus).
    pub out_dir: Option<PathBuf>,
    /// Generador uniforme sobre `0x00..=0xFF` en vez de la gramática. Es M5:
    /// existe para que la métrica de cobertura tenga contra qué medirse.
    pub uniform: bool,
    /// Siembra desde `fixtures/diff/`.
    pub seed_corpus: bool,
    /// Corta en el primer hallazgo. Es lo que mide "cuántos casos tardó".
    pub stop_on_first: bool,
}

/// Un hallazgo, ya minimizado y con todo lo que hace falta para reproducirlo.
#[derive(Debug, Clone)]
pub struct Finding {
    pub signature: String,
    pub seed: u64,
    pub index: u64,
    pub differences: Vec<String>,
    pub shrink: ShrinkStats,
    pub fixture: Option<PathBuf>,
    /// El fixture emitido se re-parsea y se re-corre: un trinquete que no
    /// reproduce es un trinquete mentiroso.
    pub fixture_reproduces: Option<bool>,
}

#[derive(Debug, Default)]
pub struct CampaignReport {
    pub cases_run: u64,
    pub skipped_fork: u64,
    /// Casos donde los DOS motores rechazaron la tx. Se cuentan aparte porque
    /// no ejecutaron un solo opcode: sumarlos a `cases_run` haría que
    /// "0 divergencias en N casos" dijera más de lo que dice.
    pub both_rejected: u64,
    pub diverged: u64,
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
    pub elapsed_secs: f64,
    /// Índice del PRIMER caso que divergió. Es el número de M4.
    pub first_divergent_index: Option<u64>,
    pub corpus_programs: usize,
}

/// Corre la campaña.
pub fn run(config: &CampaignConfig) -> CampaignReport {
    let mut report = CampaignReport::default();
    let corpus = if config.seed_corpus {
        let (corpus, skipped) = Corpus::load(&default_corpus_dir());
        if skipped > 0 {
            eprintln!("[warn] {skipped} fixtures del corpus de siembra no parsean");
        }
        corpus
    } else {
        Corpus::default()
    };
    report.corpus_programs = corpus.len();

    let started = Instant::now();
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();

    for offset in 0..config.cases {
        let index = config.start_index.saturating_add(offset);
        let case = build_case(config, index, &corpus);

        if index.is_multiple_of(COVERAGE_SAMPLE_EVERY) {
            observe(&mut report.coverage, &case);
        }

        let test = case.to_state_test();
        let post = case.post_case();
        match run_case(&test, &post) {
            CaseOutcome::SkippedFork => {
                report.skipped_fork = report.skipped_fork.saturating_add(1);
                continue;
            }
            CaseOutcome::Same => {
                report.cases_run = report.cases_run.saturating_add(1);
            }
            CaseOutcome::BothRejectedTx { .. } => {
                report.cases_run = report.cases_run.saturating_add(1);
                report.both_rejected = report.both_rejected.saturating_add(1);
            }
            CaseOutcome::Diverged { differences } => {
                report.cases_run = report.cases_run.saturating_add(1);
                report.diverged = report.diverged.saturating_add(1);
                if report.first_divergent_index.is_none() {
                    report.first_divergent_index = Some(index);
                }
                let signature = signature(&differences);
                let count = seen.entry(signature.clone()).or_default();
                *count = count.saturating_add(1);
                if *count == 1 {
                    report
                        .findings
                        .push(triage_finding(config, &case, &signature, differences));
                }
                if config.stop_on_first {
                    break;
                }
            }
        }
    }

    report.elapsed_secs = started.elapsed().as_secs_f64();
    report
}

fn build_case(config: &CampaignConfig, index: u64, corpus: &Corpus) -> FuzzCase {
    let mut case = generate_case_with(config.seed, index, corpus);
    if config.uniform {
        // M5: se reemplaza SOLO el programa, dejando el resto del escenario
        // igual. Así la caída de la métrica mide la gramática y no el
        // escenario.
        let mut rng = crate::fuzz::rng::Rng::for_case(config.seed ^ 0x5555_5555, index);
        for account in &mut case.accounts {
            let bytes = account.program.assemble().len().max(1);
            account.program = crate::fuzz::grammar::generate_uniform_program(&mut rng, bytes);
        }
        // El initcode de una tx de creación TAMBIÉN es código, y también sale
        // de la gramática. Dejarlo sin reemplazar filtraba un programa
        // estructurado dentro del modo de contraste: medido, con esa fuga el
        // modo "uniforme" seguía ejecutando programas largos.
        if case.to.is_none() {
            let bytes = case.calldata.len().max(1);
            case.calldata =
                crate::fuzz::grammar::generate_uniform_program(&mut rng, bytes).assemble();
        }
    }
    case
}

/// Minimiza y trinquetea un hallazgo.
fn triage_finding(
    config: &CampaignConfig,
    case: &FuzzCase,
    signature_of_finding: &str,
    differences: Vec<String>,
) -> Finding {
    // El predicado del shrinker: **la misma firma**, no "cualquier
    // divergencia". Un shrinker guiado por "diverge" te entrega el reproductor
    // de otro bug, minimizado con toda prolijidad.
    let target = signature_of_finding.to_owned();
    let (minimized, stats) = shrink(case, |candidate| {
        let test = candidate.to_state_test();
        let post = candidate.post_case();
        match run_case(&test, &post) {
            CaseOutcome::Diverged { differences } => signature(&differences) == target,
            CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => {
                false
            }
        }
    });

    let mut finding = Finding {
        signature: target.clone(),
        seed: minimized.seed,
        index: minimized.index,
        differences,
        shrink: stats,
        fixture: None,
        fixture_reproduces: None,
    };

    let Some(dir) = config.out_dir.as_ref() else {
        return finding;
    };
    let name = format!(
        "{}-{:016x}-{}",
        signature_slug(&target),
        minimized.seed,
        minimized.index
    );
    let comment = format!(
        "fuzz diferencial — divergencia [{target}] minimizada; reproducir con \
         `--fuzz --seed {:#x} --case {}`",
        minimized.seed, minimized.index
    );
    match write_fixture(dir, &name, &minimized, &comment) {
        Ok(path) => {
            finding.fixture_reproduces = Some(fixture_still_diverges(&path, &target));
            finding.fixture = Some(path);
        }
        Err(e) => eprintln!("[warn] no se pudo escribir el fixture del hallazgo: {e}"),
    }
    finding
}

/// Re-lee el fixture del disco y lo vuelve a correr. Es la mitad del contrato
/// del trinquete que solo el oráculo puede verificar.
fn fixture_still_diverges(path: &std::path::Path, expected: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(tests) = crate::fixture::parse_file(&raw) else {
        return false;
    };
    tests.iter().any(|test| {
        test.posts.iter().any(|post| match run_case(test, post) {
            CaseOutcome::Diverged { differences } => signature(&differences) == expected,
            CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => {
                false
            }
        })
    })
}

/// El reporte a stderr. La métrica de cobertura va **pegada** al veredicto,
/// por la misma razón que el inventario del oráculo va pegado al "0
/// divergencias": sin ella, "no encontré nada" se lee mucho más fuerte de lo
/// que es.
pub fn print_report(config: &CampaignConfig, report: &CampaignReport) {
    let implemented = implemented_opcodes(repo_b_evm::types::Spec::Prague);
    eprintln!();
    eprintln!(
        "campaña: semilla {:#018x}, casos {}..{}",
        config.seed,
        config.start_index,
        config.start_index.saturating_add(config.cases)
    );
    if config.uniform {
        eprintln!("generador: UNIFORME sobre 0x00..=0xFF (modo de contraste, no la gramática)");
    }
    if report.corpus_programs > 0 {
        eprintln!(
            "siembra: {} programas de fixtures/diff/",
            report.corpus_programs
        );
    }
    eprintln!(
        "corridas: {} casos, {} divergencias, {} skip, {:.1} s ⇒ {:.0} casos/s",
        report.cases_run,
        report.diverged,
        report.skipped_fork,
        report.elapsed_secs,
        rate(report.cases_run, report.elapsed_secs),
    );
    eprintln!(
        "  · de ésos, {} son txs que RECHAZAN los dos motores (acuerdo sin ejecutar \
         un opcode)",
        report.both_rejected,
    );
    eprintln!();
    eprintln!(
        "cobertura MEDIDA (muestra de {} casos):",
        report.coverage.cases
    );
    eprintln!(
        "  · opcodes ejercitados: {}/{} del set implementado ({:.1} %)",
        implemented
            .iter()
            .filter(|op| report.coverage.executed_opcodes.contains(op))
            .count(),
        implemented.len(),
        report.coverage.fraction_of_opcodes(&implemented) * 100.0,
    );
    eprintln!(
        "  · casos que pasan del primer opcode: {:.1} % ({} mueren en el primero)",
        report.coverage.fraction_past_first_opcode() * 100.0,
        report.coverage.cases_dead_at_first_opcode,
    );
    eprintln!(
        "  · casos de la muestra cuya tx no llegó a ejecutar: {}",
        report.coverage.not_executed,
    );
    eprintln!(
        "  · pasos: {} en total, traza más larga {}, {} casos llegan a 10+",
        report.coverage.total_steps,
        report.coverage.longest_trace,
        report.coverage.cases_reaching_ten_steps,
    );
    let never = report.coverage.never_executed(&implemented);
    if !never.is_empty() {
        let names: Vec<String> = never.iter().map(|op| format!("{op:#04x}")).collect();
        eprintln!(
            "  · NUNCA ejecutados ({}): {}",
            never.len(),
            names.join(" ")
        );
    }
    eprintln!();
    if report.findings.is_empty() {
        eprintln!("hallazgos: ninguno.");
        eprintln!(
            "  (leer junto a la cobertura de arriba: 'ninguno' es una afirmación sobre \
             lo que esta campaña EJECUTÓ)"
        );
    } else {
        eprintln!("hallazgos: {} firmas distintas", report.findings.len());
        for finding in &report.findings {
            eprintln!(
                "  · [{}] semilla {:#x} caso {} — minimizado {} → {} ({} pasos probados, {} aceptados)",
                finding.signature,
                finding.seed,
                finding.index,
                finding.shrink.size_before,
                finding.shrink.size_after,
                finding.shrink.steps_tried,
                finding.shrink.steps_accepted,
            );
            for difference in finding.differences.iter().take(4) {
                eprintln!("        {difference}");
            }
            match (&finding.fixture, finding.fixture_reproduces) {
                (Some(path), Some(true)) => eprintln!("        trinquete: {}", path.display()),
                (Some(path), _) => eprintln!(
                    "        [FAIL] el fixture {} NO reproduce: trinquete mentiroso",
                    path.display()
                ),
                (None, _) => {}
            }
        }
    }
    if let Some(index) = report.first_divergent_index {
        eprintln!();
        eprintln!(
            "primera divergencia en el caso {index} ({} casos corridos, {:.1} s)",
            index.saturating_sub(config.start_index).saturating_add(1),
            report.elapsed_secs
        );
    }
}

fn rate(cases: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    cases as f64 / seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cases: u64) -> CampaignConfig {
        CampaignConfig {
            seed: 0x2026_0818,
            start_index: 0,
            cases,
            out_dir: None,
            uniform: false,
            seed_corpus: false,
            stop_on_first: false,
        }
    }

    /// El lazo corre de punta a punta contra el oráculo real. No afirma "0
    /// divergencias" —eso lo decide el motor, no el test—: afirma que los
    /// casos se ejecutan y que la cobertura se mide.
    #[test]
    fn a_short_campaign_runs_and_measures_coverage() {
        let config = config(64);
        let report = run(&config);
        assert_eq!(report.cases_run.saturating_add(report.skipped_fork), 64);
        assert!(report.coverage.cases > 0, "no se midió cobertura");
        assert!(
            report.coverage.total_steps > 0,
            "la muestra no ejecutó un solo opcode"
        );
    }

    /// La campaña es determinista: la misma semilla, el mismo veredicto. Sin
    /// esto, un hallazgo no se puede volver a mirar.
    #[test]
    fn the_same_seed_gives_the_same_campaign() {
        let config = config(32);
        let first = run(&config);
        let second = run(&config);
        assert_eq!(first.diverged, second.diverged);
        assert_eq!(first.first_divergent_index, second.first_divergent_index);
        assert_eq!(
            first.coverage.executed_opcodes,
            second.coverage.executed_opcodes
        );
    }

    /// El generador uniforme ejercita MENOS opcodes que la gramática. Es M5, y
    /// es lo que prueba que la métrica de cobertura es load-bearing: si el
    /// número no se moviera, no estaría midiendo la gramática.
    #[test]
    fn the_uniform_generator_covers_less_than_the_grammar() {
        let mut grammar = config(96);
        grammar.seed = 0xFEED;
        let with_grammar = run(&grammar);
        let mut uniform = grammar.clone();
        uniform.uniform = true;
        let with_uniform = run(&uniform);
        assert!(
            with_uniform.coverage.executed_opcodes.len()
                < with_grammar.coverage.executed_opcodes.len(),
            "uniforme {} vs gramática {}",
            with_uniform.coverage.executed_opcodes.len(),
            with_grammar.coverage.executed_opcodes.len()
        );
    }
}
