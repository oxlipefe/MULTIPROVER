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
use crate::fixture::{PostCase, StateTest};
use crate::fuzz::corpus::{Corpus, default_corpus_dir};
use crate::fuzz::coverage::{Coverage, implemented_opcodes, observe};
use crate::fuzz::emit::write_fixture;
use crate::fuzz::generate::{FuzzCase, generate_case_with};
use crate::fuzz::mutate::{MutCase, mutate_case, passthrough_case};
use crate::fuzz::seeds::{SeedCorpus, default_seed_root};
use crate::fuzz::shrink::{ShrinkStats, Shrinkable, shrink};
use crate::fuzz::triage::{signature, signature_slug};

/// Cada cuántos casos se toma una muestra para la métrica de cobertura.
/// Trazar cuesta una ejecución extra por caso: muestrear mantiene el lazo
/// rápido y la métrica sigue siendo una medición, no una estimación de nadie.
const COVERAGE_SAMPLE_EVERY: u64 = 8;

/// Cuántos índices divergentes se recuerdan. Acotado y nombrado como todo
/// recurso alimentado por el generador: una campaña con un bug grosero
/// divergiría en el 100 % de los casos y la lista sería la campaña entera.
const MAX_TRACKED_DIVERGENT_INDICES: usize = 256;

/// Cuál de los dos generadores diversos corre la campaña.
///
/// El enum es explícito y no un par de booleanos: los modos de contraste
/// (`GrammarUniform`, `MutatePassthrough`, `MutateByteLevel`) existen para que
/// las métricas tengan contra qué medirse, y un booleano suelto los haría
/// combinables entre sí sin que ninguna combinación signifique nada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generator {
    /// Gramática ponderada, escenario propio.
    Grammar,
    /// Contraste de la gramática: bytes uniformes sobre `0x00..=0xFF`.
    GrammarUniform,
    /// Mutación de la vecindad de un `state_test` real de EEST.
    Mutate,
    /// Contraste de la mutación (M2): el corpus semilla SIN operadores.
    MutatePassthrough,
    /// Contraste de la mutación (M3): el bytecode se muta a nivel de **byte**
    /// en vez de instrucción.
    MutateByteLevel,
}

impl Generator {
    pub const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::Mutate | Self::MutatePassthrough | Self::MutateByteLevel
        )
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Grammar => "gramática",
            Self::GrammarUniform => "UNIFORME sobre 0x00..=0xFF (contraste de la gramática)",
            Self::Mutate => "mutación de EEST",
            Self::MutatePassthrough => {
                "PASS-THROUGH del corpus semilla (contraste, sin operadores)"
            }
            Self::MutateByteLevel => "mutación de EEST a nivel de BYTE (contraste)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CampaignConfig {
    pub seed: u64,
    pub start_index: u64,
    pub cases: u64,
    /// Dónde se escriben los fixtures del trinquete. `None` = no escribir
    /// (el modo de medición planta un bug a propósito, y sus hallazgos NO son
    /// divergencias reales que deban entrar al corpus).
    pub out_dir: Option<PathBuf>,
    pub generator: Generator,
    /// Siembra desde `fixtures/diff/` (solo la gramática).
    pub seed_corpus: bool,
    /// Corta en el primer hallazgo. Es lo que mide "cuántos casos tardó".
    pub stop_on_first: bool,
    /// De dónde sale el corpus semilla de EEST. `None` = el release pineado.
    /// Existe para que los tests puedan correr sin el cache (que son 257 MB
    /// gitignoreados y CI no tiene).
    pub seed_root: Option<PathBuf>,
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
    /// **La identidad del fixture semilla** y los operadores aplicados, cuando
    /// el generador es de mutación. Sin la identidad, un hallazgo no se
    /// reproduce: el índice del caso depende del tamaño del corpus, que cambia
    /// con el release de EEST, mientras el nombre del fixture no.
    pub origin: Option<String>,
    pub seed_index: Option<usize>,
    /// ¿La semilla **sin mutar** ya divergía con la misma firma?
    ///
    /// **Clasificar, nunca excusar**: el hallazgo se reporta y se
    /// cuenta igual, pero el lector tiene que poder ver de un vistazo que la
    /// mutación no lo creó. Medido antes de escribir el generador: 55 de los
    /// 39 025 casos de EEST ya divergen sin tocarlos, y son las dos
    /// divergencias DELIBERADAS del inventario (EIP-7610 y los invariantes de
    /// encoding de los tipos 3 y 4). Sin este campo, las primeras decenas de
    /// "hallazgos" de este generador serían eso.
    pub seed_already_diverged: Option<bool>,
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
    /// Índice del PRIMER caso que divergió. Es el número de M4/M1.
    pub first_divergent_index: Option<u64>,
    /// **Todos** los índices que divergieron, acotados.
    ///
    /// No es telemetría: comparar DOS generadores sobre el mismo bug plantado
    /// exige saber en qué caso lo encontró cada uno, y "el primero que divergió"
    /// no sirve cuando el corpus ya trae divergencias deliberadas propias
    /// (medido: 55 de los 39 025 casos de EEST divergen sin tocarlos). El índice
    /// que aparece **solo** con el bug plantado es la respuesta.
    pub divergent_indices: Vec<u64>,
    pub corpus_programs: usize,
    /// Tamaño del corpus semilla de EEST (0 si el generador no lo usa).
    pub seed_cases: usize,
    /// **Métrica de vecindad**: cuántos casos quedaron estructuralmente
    /// distintos de su semilla. En el modo pass-through tiene que dar 0, y si
    /// no da 0 la métrica no está midiendo nada (§5, M2).
    pub mutated_cases: u64,
    /// Cuántos casos se construyeron sobre semillas (denominador de la
    /// vecindad).
    pub seeded_cases: u64,
    /// **Localidad**: instrucciones del stream que cambiaron / instrucciones
    /// totales, sumadas sobre todas las mutaciones de bytecode de la campaña.
    pub stream_touched: u64,
    pub stream_total: u64,
    pub code_mutations: u64,
    /// Saltos que aterrizaban en un `JUMPDEST` antes y después de la mutación.
    pub jumps_before: u64,
    pub jumps_after: u64,
}

/// Lo que el lazo necesita de un caso, sea cual sea el generador que lo
/// produjo: cómo mirarlo como `(StateTest, PostCase)` y de dónde salió.
///
/// El trait existe para que **haya un solo lazo**. Dos lazos —uno por
/// generador— serían dos caminos hacia el mismo oráculo, con el mismo riesgo
/// que se evita poniendo `run_dir` encima de `run_case`: el día que
/// deriven, una campaña estaría midiendo un juez distinto de la otra, y los
/// números del §2 dejarían de ser comparables. Y comparar los dos generadores
/// es el entregable de este slice.
pub trait CampaignCase: Shrinkable {
    /// El caso como lo ve el juez. `with_parts` y no `-> (StateTest, PostCase)`
    /// porque un `MutCase` YA los tiene y devolverlos por valor lo obligaría a
    /// clonar un `pre` de hasta 168 cuentas por caso.
    fn with_parts<R>(&self, f: impl FnOnce(&StateTest, &PostCase) -> R) -> R;
    /// De dónde salió: el fixture semilla y los operadores, o `None` para un
    /// generador que no siembra de un caso concreto.
    fn origin(&self) -> Option<String>;
    /// ¿Quedó distinto de su semilla? `None` si la pregunta no aplica.
    fn changed_from_seed(&self) -> Option<bool>;
    /// `(instrucciones tocadas, instrucciones totales)` de las mutaciones de
    /// bytecode del caso.
    fn stream_delta(&self) -> Option<(usize, usize)>;
    /// `(saltos resueltos antes, saltos resueltos después)`.
    fn jump_delta(&self) -> Option<(usize, usize)>;
    /// El índice del caso semilla, para poder preguntarle al oráculo si ya
    /// divergía sin tocarlo.
    fn seed_index(&self) -> Option<usize>;
}

impl CampaignCase for FuzzCase {
    fn with_parts<R>(&self, f: impl FnOnce(&StateTest, &PostCase) -> R) -> R {
        f(&self.to_state_test(), &self.post_case())
    }

    fn origin(&self) -> Option<String> {
        None
    }

    fn changed_from_seed(&self) -> Option<bool> {
        None
    }

    fn seed_index(&self) -> Option<usize> {
        None
    }

    fn stream_delta(&self) -> Option<(usize, usize)> {
        None
    }

    fn jump_delta(&self) -> Option<(usize, usize)> {
        None
    }
}

impl CampaignCase for MutCase {
    fn with_parts<R>(&self, f: impl FnOnce(&StateTest, &PostCase) -> R) -> R {
        f(&self.test, &self.post)
    }

    fn origin(&self) -> Option<String> {
        Some(format!(
            "semilla `{}` (#{}) + [{}]",
            self.seed_name,
            self.seed_index,
            if self.applied.is_empty() {
                "sin mutar".to_owned()
            } else {
                self.applied.join(", ")
            }
        ))
    }

    fn changed_from_seed(&self) -> Option<bool> {
        Some(self.changed)
    }

    fn seed_index(&self) -> Option<usize> {
        Some(self.seed_index)
    }

    fn stream_delta(&self) -> Option<(usize, usize)> {
        self.stream_delta
    }

    fn jump_delta(&self) -> Option<(usize, usize)> {
        self.jump_delta
    }
}

impl CampaignReport {
    /// La fracción de casos que quedó distinta de su semilla. En el modo
    /// pass-through vale **0**, y ése es el punto del contraste.
    pub fn fraction_mutated(&self) -> f64 {
        if self.seeded_cases == 0 {
            return 0.0;
        }
        self.mutated_cases as f64 / self.seeded_cases as f64
    }

    /// La fracción del stream de instrucciones que una mutación de bytecode
    /// toca. Cerca de 0 = la mutación es LOCAL (la que se pidió); cerca de 1 =
    /// re-encuadró el programa entero.
    /// De los saltos que aterrizaban en un `JUMPDEST` antes de la mutación,
    /// cuántos siguen aterrizando después. **Es la trampa del §4.1 medida**:
    /// los saltos de la EVM son absolutos y mutar bytes corre los `JUMPDEST`.
    pub fn fraction_jumps_kept(&self) -> f64 {
        if self.jumps_before == 0 {
            return 1.0;
        }
        self.jumps_after as f64 / self.jumps_before as f64
    }

    pub fn stream_locality(&self) -> f64 {
        if self.stream_total == 0 {
            return 0.0;
        }
        self.stream_touched as f64 / self.stream_total as f64
    }
}

/// Corre la campaña. `Err` = no se pudo ni arrancar (el corpus semilla no
/// está): fail-closed, nunca un reporte vacío que diga "0 divergencias".
pub fn run(config: &CampaignConfig) -> Result<CampaignReport, String> {
    let mut report = CampaignReport::default();
    if config.generator.is_mutation() {
        let root = config.seed_root.clone().unwrap_or_else(default_seed_root);
        let corpus = SeedCorpus::load(&root)?;
        if corpus.unparsed > 0 {
            eprintln!(
                "[warn] {} archivos del corpus semilla no parsean",
                corpus.unparsed
            );
        }
        report.seed_cases = corpus.len();
        let byte_level = config.generator == Generator::MutateByteLevel;
        let passthrough = config.generator == Generator::MutatePassthrough;
        run_loop(config, &mut report, |index| {
            if passthrough {
                passthrough_case(config.seed, index, &corpus)
            } else {
                mutate_case(config.seed, index, &corpus, byte_level)
            }
        });
        classify_against_the_seed(&mut report, &corpus);
        return Ok(report);
    }

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
    run_loop(config, &mut report, |index| {
        Some(build_case(config, index, &corpus))
    });
    Ok(report)
}

/// El lazo, uno solo para los dos generadores.
fn run_loop<C: CampaignCase>(
    config: &CampaignConfig,
    report: &mut CampaignReport,
    mut build: impl FnMut(u64) -> Option<C>,
) {
    let started = Instant::now();
    let mut seen: BTreeMap<String, u64> = BTreeMap::new();

    for offset in 0..config.cases {
        let index = config.start_index.saturating_add(offset);
        let Some(case) = build(index) else {
            continue;
        };
        if let Some(changed) = case.changed_from_seed() {
            report.seeded_cases = report.seeded_cases.saturating_add(1);
            if changed {
                report.mutated_cases = report.mutated_cases.saturating_add(1);
            }
        }
        if let Some((touched, total)) = case.stream_delta() {
            report.code_mutations = report.code_mutations.saturating_add(1);
            report.stream_touched = report
                .stream_touched
                .saturating_add(u64::try_from(touched).unwrap_or(u64::MAX));
            report.stream_total = report
                .stream_total
                .saturating_add(u64::try_from(total).unwrap_or(u64::MAX));
        }
        if let Some((before, after)) = case.jump_delta() {
            report.jumps_before = report
                .jumps_before
                .saturating_add(u64::try_from(before).unwrap_or(u64::MAX));
            report.jumps_after = report
                .jumps_after
                .saturating_add(u64::try_from(after).unwrap_or(u64::MAX));
        }

        if index.is_multiple_of(COVERAGE_SAMPLE_EVERY) {
            case.with_parts(|test, post| observe(&mut report.coverage, test, post));
        }

        let outcome = case.with_parts(run_case);
        match outcome {
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
                if report.divergent_indices.len() < MAX_TRACKED_DIVERGENT_INDICES {
                    report.divergent_indices.push(index);
                }
                let signature = signature(&differences);
                let count = seen.entry(signature.clone()).or_default();
                *count = count.saturating_add(1);
                if *count == 1 {
                    report.findings.push(triage_finding(
                        config,
                        &case,
                        index,
                        &signature,
                        differences,
                    ));
                }
                if config.stop_on_first {
                    break;
                }
            }
        }
    }

    report.elapsed_secs = started.elapsed().as_secs_f64();
}

/// Le pregunta al oráculo si la semilla de cada hallazgo **ya divergía sin
/// mutar**, y lo anota. Una corrida por hallazgo, no por caso.
fn classify_against_the_seed(report: &mut CampaignReport, corpus: &SeedCorpus) {
    for finding in &mut report.findings {
        let Some(index) = finding.seed_index else {
            continue;
        };
        let Some(seed) = corpus.cases.get(index) else {
            continue;
        };
        finding.seed_already_diverged = Some(match run_case(&seed.test, &seed.post) {
            CaseOutcome::Diverged { differences } => signature(&differences) == finding.signature,
            CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => {
                false
            }
        });
    }
}

/// El caso de la gramática, con su modo de contraste.
fn build_case(config: &CampaignConfig, index: u64, corpus: &Corpus) -> FuzzCase {
    let mut case = generate_case_with(config.seed, index, corpus);
    if config.generator == Generator::GrammarUniform {
        // Se reemplaza SOLO el programa, dejando el resto del escenario igual.
        // Así la caída de la métrica mide la gramática y no el escenario.
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
fn triage_finding<C: CampaignCase>(
    config: &CampaignConfig,
    case: &C,
    index: u64,
    signature_of_finding: &str,
    differences: Vec<String>,
) -> Finding {
    // El predicado del shrinker: **la misma firma**, no "cualquier
    // divergencia". Un shrinker guiado por "diverge" te entrega el reproductor
    // de otro bug, minimizado con toda prolijidad.
    let target = signature_of_finding.to_owned();
    let (minimized, stats) = shrink(case, |candidate: &C| match candidate.with_parts(run_case) {
        CaseOutcome::Diverged { differences } => signature(&differences) == target,
        CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => false,
    });

    let mut finding = Finding {
        signature: target.clone(),
        seed: config.seed,
        index,
        differences,
        shrink: stats,
        fixture: None,
        fixture_reproduces: None,
        origin: minimized.origin(),
        seed_index: minimized.seed_index(),
        seed_already_diverged: None,
    };

    let Some(dir) = config.out_dir.as_ref() else {
        return finding;
    };
    let name = format!("{}-{:016x}-{index}", signature_slug(&target), config.seed);
    let comment = finding_comment(&target, config.seed, index, finding.origin.as_deref());
    let written =
        minimized.with_parts(|test, post| write_fixture(dir, &name, test, post, &comment));
    match written {
        Ok(path) => {
            finding.fixture_reproduces = Some(fixture_still_diverges(&path, &target));
            finding.fixture = Some(path);
        }
        Err(e) => eprintln!("[warn] no se pudo escribir el fixture del hallazgo: {e}"),
    }
    finding
}

/// El comentario que viaja DENTRO del fixture emitido.
///
/// Lleva la semilla, el índice **y la identidad del fixture semilla**: sin lo
/// tercero, un hallazgo del generador de mutación no se puede volver a mirar
/// una vez que el corpus cambie de tamaño (el índice del caso semilla depende
/// del release de EEST; el nombre del caso no). Es función pura para poder
/// exigirlo con un test en vez de con una lectura.
fn finding_comment(signature: &str, seed: u64, index: u64, origin: Option<&str>) -> String {
    let origin = origin.map_or_else(String::new, |origin| format!("; origen: {origin}"));
    format!(
        "fuzz diferencial — divergencia [{signature}] minimizada; reproducir con \
         `--fuzz --seed {seed:#x} --case {index}`{origin}"
    )
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
    eprintln!("generador: {}", config.generator.label());
    if report.corpus_programs > 0 {
        eprintln!(
            "siembra: {} programas de fixtures/diff/",
            report.corpus_programs
        );
    }
    if report.seed_cases > 0 {
        eprintln!(
            "corpus semilla: {} casos `state_test` de EEST {}",
            report.seed_cases,
            crate::fuzz::seeds::PINNED_TAG,
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
    if report.seeded_cases > 0 {
        // La métrica de VECINDAD. Va pegada al veredicto por la misma razón que
        // la cobertura: un generador de mutación con los operadores muertos
        // reportaría exactamente el mismo "0 divergencias".
        eprintln!(
            "  · vecindad: {} de {} casos quedaron distintos de su semilla ({:.1} %)",
            report.mutated_cases,
            report.seeded_cases,
            report.fraction_mutated() * 100.0,
        );
    }
    if report.code_mutations > 0 {
        eprintln!(
            "  · localidad: {} mutaciones de bytecode tocaron {} de {} instrucciones \
             del stream ({:.1} %)",
            report.code_mutations,
            report.stream_touched,
            report.stream_total,
            report.stream_locality() * 100.0,
        );
        eprintln!(
            "  · saltos que siguen cayendo en un JUMPDEST: {} de {} ({:.1} %)",
            report.jumps_after,
            report.jumps_before,
            report.fraction_jumps_kept() * 100.0,
        );
    }
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
            if let Some(origin) = finding.origin.as_ref() {
                eprintln!("        origen: {origin}");
            }
            match finding.seed_already_diverged {
                Some(true) => eprintln!(
                    "        [YA DIVERGÍA SIN MUTAR] la mutación no lo creó — clasificar \
                     contra el inventario de divergencias deliberadas"
                ),
                Some(false) => eprintln!("        la semilla sin mutar NO divergía"),
                None => {}
            }
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
    if !report.divergent_indices.is_empty() {
        let shown: Vec<String> = report
            .divergent_indices
            .iter()
            .take(32)
            .map(u64::to_string)
            .collect();
        eprintln!();
        eprintln!(
            "índices divergentes ({}{}): {}",
            report.divergent_indices.len(),
            if report.divergent_indices.len() >= MAX_TRACKED_DIVERGENT_INDICES {
                "+"
            } else {
                ""
            },
            shown.join(" ")
        );
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
            generator: Generator::Grammar,
            seed_corpus: false,
            stop_on_first: false,
            seed_root: None,
        }
    }

    fn must_run(config: &CampaignConfig) -> CampaignReport {
        match run(config) {
            Ok(report) => report,
            Err(e) => panic!("la campaña no arrancó: {e}"),
        }
    }

    /// El lazo corre de punta a punta contra el oráculo real. No afirma "0
    /// divergencias" —eso lo decide el motor, no el test—: afirma que los
    /// casos se ejecutan y que la cobertura se mide.
    #[test]
    fn a_short_campaign_runs_and_measures_coverage() {
        let config = config(64);
        let report = must_run(&config);
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
        let first = must_run(&config);
        let second = must_run(&config);
        assert_eq!(first.diverged, second.diverged);
        assert_eq!(first.first_divergent_index, second.first_divergent_index);
        assert_eq!(
            first.coverage.executed_opcodes,
            second.coverage.executed_opcodes
        );
    }

    /// El generador uniforme ejercita MENOS opcodes que la gramática. Es el
    /// contraste que prueba que la métrica de cobertura es load-bearing: si el
    /// número no se moviera, no estaría midiendo la gramática.
    #[test]
    fn the_uniform_generator_covers_less_than_the_grammar() {
        let mut grammar = config(96);
        grammar.seed = 0xFEED;
        let with_grammar = must_run(&grammar);
        let mut uniform = grammar.clone();
        uniform.generator = Generator::GrammarUniform;
        let with_uniform = must_run(&uniform);
        assert!(
            with_uniform.coverage.executed_opcodes.len()
                < with_grammar.coverage.executed_opcodes.len(),
            "uniforme {} vs gramática {}",
            with_uniform.coverage.executed_opcodes.len(),
            with_grammar.coverage.executed_opcodes.len()
        );
    }

    /// **El corpus semilla que no está NO se degrada a una campaña vacía.**
    /// Es la regla del §4.3 y la mutación M5 la mide: con el chequeo borrado,
    /// esta campaña "correría" y reportaría 0 divergencias sobre 0 casos.
    #[test]
    fn a_mutation_campaign_without_a_seed_corpus_fails_loudly() {
        let mut config = config(8);
        config.generator = Generator::Mutate;
        config.seed_root = Some(PathBuf::from("/no/existe/este/release"));
        match run(&config) {
            Ok(report) => panic!(
                "corrió en vacío: {} casos, {} divergencias",
                report.cases_run, report.diverged
            ),
            Err(e) => assert!(e.contains("fetch-eest.sh"), "{e}"),
        }
    }

    /// La campaña de mutación corre de punta a punta contra el oráculo real
    /// sobre un corpus sintético (los tests no pueden depender del cache de
    /// EEST, que son 257 MB gitignoreados), y **su métrica de vecindad se
    /// mueve**: el modo normal muta y el pass-through no.
    ///
    /// Las dos mitades van en el MISMO test a propósito: la afirmación no es
    /// "el generador muta" sino "la métrica distingue", y eso necesita los dos
    /// números.
    #[test]
    fn the_mutation_campaign_runs_and_its_neighbourhood_metric_discriminates() {
        let dir =
            std::env::temp_dir().join(format!("repo-b-fuzz-seedcorpus-{}", std::process::id()));
        write_synthetic_corpus(&dir);

        let mut mutating = config(64);
        mutating.seed = 0x2026_0819;
        mutating.generator = Generator::Mutate;
        mutating.seed_root = Some(dir.clone());
        let mutated = must_run(&mutating);

        let mut passthrough = mutating.clone();
        passthrough.generator = Generator::MutatePassthrough;
        let untouched = must_run(&passthrough);

        let _ = std::fs::remove_dir_all(&dir);

        assert!(mutated.cases_run > 0, "la campaña de mutación no corrió");
        assert!(mutated.seeded_cases > 0);
        assert!(
            mutated.fraction_mutated() > 0.5,
            "el generador apenas mutó: {:.2}",
            mutated.fraction_mutated()
        );
        assert_eq!(
            untouched.mutated_cases, 0,
            "el pass-through mutó {} casos",
            untouched.mutated_cases
        );
    }

    /// El comentario del fixture emitido lleva **la identidad del fixture
    /// semilla**. Sin ella, un hallazgo del generador de mutación deja de ser
    /// reproducible en cuanto el corpus cambie de tamaño.
    #[test]
    fn the_emitted_comment_carries_the_seed_fixture_identity() {
        let corpus = crate::fuzz::mutate::synthetic_corpus();
        let Some(case) = crate::fuzz::mutate::mutate_case(0xABC, 3, &corpus, false) else {
            panic!("sin caso");
        };
        let Some(origin) = case.origin() else {
            panic!("un caso de mutación tiene que declarar su origen");
        };
        assert!(
            origin.contains("sintetico"),
            "el origen no nombra al fixture semilla: {origin}"
        );
        let comment = finding_comment("gas_used", 0xABC, 3, Some(&origin));
        assert!(comment.contains("--seed 0xabc"), "{comment}");
        assert!(comment.contains("--case 3"), "{comment}");
        assert!(comment.contains("sintetico"), "{comment}");
    }

    /// Escribe el corpus sintético al disco en la forma que `SeedCorpus::load`
    /// espera (`<root>/fixtures/state_tests/*.json`).
    fn write_synthetic_corpus(root: &std::path::Path) {
        let dir = root.join("fixtures/state_tests");
        if std::fs::create_dir_all(&dir).is_err() {
            panic!("no se pudo preparar el corpus sintético");
        }
        let corpus = crate::fuzz::mutate::synthetic_corpus();
        let Some(case) = corpus.cases.first() else {
            panic!("corpus sintético vacío");
        };
        let json = crate::fuzz::emit::to_fixture_json(
            &case.test,
            &case.post,
            "sintetico",
            "corpus de test",
        );
        let Ok(text) = serde_json::to_string_pretty(&json) else {
            panic!("no serializa");
        };
        if std::fs::write(dir.join("sintetico.json"), text).is_err() {
            panic!("no se pudo escribir el corpus sintético");
        }
    }
}
