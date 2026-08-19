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
use crate::fuzz::coverage::observe;
use crate::fuzz::emit::write_fixture;
use crate::fuzz::finding::{CampaignReport, Finding};
use crate::fuzz::generate::{FuzzCase, generate_case_with};
use crate::fuzz::mutate::{MutCase, mutate_case, passthrough_case};
use crate::fuzz::seeds::{SeedCorpus, default_seed_root};
use crate::fuzz::shrink::{Shrinkable, shrink};
use crate::fuzz::site::site_of;
use crate::fuzz::triage::{cluster_key, signature, signature_slug};
use crate::oracle::known_cluster;

/// Cada cuántos casos se toma una muestra para la métrica de cobertura.
/// Trazar cuesta una ejecución extra por caso: muestrear mantiene el lazo
/// rápido y la métrica sigue siendo una medición, no una estimación de nadie.
const COVERAGE_SAMPLE_EVERY: u64 = 8;

/// Cuántos índices divergentes se recuerdan. Acotado y nombrado como todo
/// recurso alimentado por el generador: una campaña con un bug grosero
/// divergiría en el 100 % de los casos y la lista sería la campaña entera.
pub const MAX_TRACKED_DIVERGENT_INDICES: usize = 256;

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
    /// **No es un generador: es el barrido del corpus semilla SIN mutar**, en
    /// orden, cada caso una vez. Existe para derivar la tabla de clusters ya
    /// explicados **midiendo** en vez de escribiéndola a mano: lo que el
    /// corpus de EEST diverge sin que nadie lo toque es, por definición, lo
    /// que ya estaba ahí.
    SeedScan,
}

impl Generator {
    pub const fn is_mutation(self) -> bool {
        matches!(
            self,
            Self::Mutate | Self::MutatePassthrough | Self::MutateByteLevel | Self::SeedScan
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
            Self::SeedScan => {
                "BARRIDO del corpus semilla sin mutar (deriva los clusters conocidos)"
            }
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

/// Quien propone una causa raíz para un hallazgo.
///
/// **No puede decidir nada, y eso es estructura y no disciplina**: se lo llama
/// una sola vez, al final de `run_with`, cuando el reporte ya está cerrado y
/// los clusters ya están asignados. Lo único que puede tocar es
/// `Finding::llm_root_cause`, un campo que nadie lee para producir el
/// veredicto. Una llamada a un LLM no es determinista, así que no puede estar
/// en el camino que produce el veredicto (CLAUDE.md §5).
pub trait RootCauseAnnotator {
    fn annotate(&mut self, finding: &Finding) -> Option<String>;
}

/// Corre la campaña. `Err` = no se pudo ni arrancar (el corpus semilla no
/// está): fail-closed, nunca un reporte vacío que diga "0 divergencias".
///
/// `annotator` es `None` en el camino que gatea CI, y tiene que dar el MISMO
/// resultado que con uno puesto: es la restricción del §3.4 y va como test.
pub fn run(
    config: &CampaignConfig,
    annotator: Option<&mut dyn RootCauseAnnotator>,
) -> Result<CampaignReport, String> {
    let mut report = run_campaign(config)?;
    // La anotación va **después** del veredicto, sobre un reporte ya cerrado.
    if let Some(annotator) = annotator {
        for finding in &mut report.findings {
            finding.llm_root_cause = annotator.annotate(finding);
        }
    }
    Ok(report)
}

fn run_campaign(config: &CampaignConfig) -> Result<CampaignReport, String> {
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
        let scan = config.generator == Generator::SeedScan;
        run_loop(config, &mut report, |index| {
            if scan {
                scan_case(&corpus, index)
            } else if passthrough {
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
    // Clave de cluster → índice de su representante en `report.findings`.
    let mut clusters: BTreeMap<String, usize> = BTreeMap::new();
    let mut triage_elapsed = 0.0f64;

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
                // El triage arranca acá y se cronometra aparte: computar el
                // SITIO cuesta trazar los dos motores, y ese costo se paga por
                // divergencia, nunca por caso.
                let triage_started = Instant::now();
                let site = case.with_parts(|test, post| site_of(test, post, &differences));
                let key = cluster_key(&differences, &site);
                let sub_signature = signature(&differences);
                match clusters.get(&key).copied() {
                    Some(position) => {
                        if let Some(finding) = report.findings.get_mut(position) {
                            finding.occurrences = finding.occurrences.saturating_add(1);
                            if !finding.sub_signatures.contains(&sub_signature) {
                                finding.sub_signatures.push(sub_signature);
                            }
                        }
                    }
                    None => {
                        let finding =
                            triage_finding(config, &case, index, &key, &site, differences);
                        clusters.insert(key, report.findings.len());
                        report.findings.push(finding);
                    }
                }
                triage_elapsed += triage_started.elapsed().as_secs_f64();
                if config.stop_on_first {
                    break;
                }
            }
        }
    }

    report.elapsed_secs = started.elapsed().as_secs_f64();
    report.triage_secs = triage_elapsed;
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
            CaseOutcome::Diverged { differences } => {
                cluster_key(&differences, &site_of(&seed.test, &seed.post, &differences))
                    == finding.cluster
            }
            CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => {
                false
            }
        });
    }
}

/// El caso `index` del corpus semilla, **sin mutar y en orden**. Es el barrido
/// que deriva los clusters ya explicados: un índice fuera del corpus devuelve
/// `None` y el lazo lo saltea, así que pedir más casos que el corpus no
/// inventa ninguno.
fn scan_case(corpus: &SeedCorpus, index: u64) -> Option<MutCase> {
    let position = usize::try_from(index).ok()?;
    let seed_case = corpus.cases.get(position)?;
    Some(MutCase {
        seed_name: seed_case.name.clone(),
        seed_index: position,
        applied: Vec::new(),
        changed: false,
        stream_delta: None,
        jump_delta: None,
        test: seed_case.test.clone(),
        post: seed_case.post.clone(),
    })
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

/// Minimiza y trinquetea el representante de un cluster.
fn triage_finding<C: CampaignCase>(
    config: &CampaignConfig,
    case: &C,
    index: u64,
    cluster: &str,
    site: &str,
    differences: Vec<String>,
) -> Finding {
    // El predicado del shrinker es **el mismo CLUSTER**, no "cualquier
    // divergencia" ni "la misma sub-firma". Un shrinker guiado por "diverge" te
    // entrega el reproductor de otro bug minimizado con toda prolijidad; uno
    // guiado por la sub-firma puede terminar en otro SITIO, y entonces el
    // reproductor del cluster no reproduce el cluster.
    let target = cluster.to_owned();
    let (minimized, stats) = shrink(case, |candidate: &C| match candidate.with_parts(run_case) {
        CaseOutcome::Diverged { differences } => {
            let site = candidate.with_parts(|test, post| site_of(test, post, &differences));
            cluster_key(&differences, &site) == target
        }
        CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => false,
    });

    let signature_of_case = signature(&differences);
    let mut finding = Finding {
        cluster: target.clone(),
        site: site.to_owned(),
        occurrences: 1,
        sub_signatures: vec![signature_of_case.clone()],
        known: known_cluster(&target).map(|known| known.rule),
        llm_root_cause: None,
        signature: signature_of_case,
        seed: config.seed,
        index,
        differences,
        shrink: stats,
        fixture: None,
        fixture_reproduces: None,
        origin: minimized.origin(),
        seed_index: minimized.seed_index(),
        seed_already_diverged: None,
        reproducer: None,
    };

    let comment = finding_comment(&target, config.seed, index, finding.origin.as_deref());
    let name = format!("{}-{:016x}-{index}", signature_slug(&target), config.seed);
    // El reproductor viaja EMBEBIDO en el hallazgo, exista o no el directorio
    // del trinquete: el libro mayor no puede depender de un `--out`.
    finding.reproducer =
        Some(minimized.with_parts(|test, post| {
            crate::fuzz::emit::to_fixture_json(test, post, &name, &comment)
        }));

    let Some(dir) = config.out_dir.as_ref() else {
        return finding;
    };
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
fn finding_comment(cluster: &str, seed: u64, index: u64, origin: Option<&str>) -> String {
    let origin = origin.map_or_else(String::new, |origin| format!("; origen: {origin}"));
    format!(
        "fuzz diferencial — cluster [{cluster}] minimizado; reproducir con \
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
            CaseOutcome::Diverged { differences } => {
                cluster_key(&differences, &site_of(test, post, &differences)) == expected
            }
            CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => {
                false
            }
        })
    })
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
        match run(config, None) {
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
        match run(&config, None) {
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

    /// Un anotador **no determinista a propósito**: devuelve algo distinto en
    /// cada llamada. Si la anotación tocara el veredicto, el test de abajo
    /// fallaría de forma intermitente — que es exactamente el modo de falla que
    /// el §3.4 quiere hacer imposible.
    struct ChaoticAnnotator {
        calls: usize,
    }

    impl RootCauseAnnotator for ChaoticAnnotator {
        fn annotate(&mut self, finding: &Finding) -> Option<String> {
            self.calls = self.calls.saturating_add(1);
            Some(format!(
                "hipótesis #{} para {} (inventada, y da igual)",
                self.calls, finding.cluster
            ))
        }
    }

    /// **El determinismo del §3.4, como test.** Un LLM no es determinista, así
    /// que no puede estar en el camino que produce el veredicto: correr la misma
    /// campaña con y sin anotador tiene que dar el MISMO veredicto, los MISMOS
    /// clusters y el mismo conteo de nuevos.
    ///
    /// El test no es vacuo y eso también se afirma: el corpus sintético trae un
    /// caso que diverge de verdad, así que el anotador se llama al menos una
    /// vez. Sin esa aserción, borrar el anotador entero dejaría el test verde.
    #[test]
    fn the_verdict_does_not_depend_on_the_llm_annotation() {
        let dir = std::env::temp_dir().join(format!("repo-b-fuzz-llm-{}", std::process::id()));
        write_synthetic_corpus(&dir);

        let mut config = config(48);
        config.seed = 0x2026_0819;
        config.generator = Generator::Mutate;
        config.seed_root = Some(dir.clone());

        let plain = must_run(&config);
        let mut annotator = ChaoticAnnotator { calls: 0 };
        let annotated = match run(&config, Some(&mut annotator)) {
            Ok(report) => report,
            Err(e) => panic!("la campaña no arrancó: {e}"),
        };
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            annotator.calls > 0,
            "el anotador no se llamó: el test no probaría nada"
        );
        assert_eq!(plain.diverged, annotated.diverged);
        assert_eq!(plain.new_clusters(), annotated.new_clusters());
        let plain_keys: Vec<&str> = plain.findings.iter().map(|f| f.cluster.as_str()).collect();
        let annotated_keys: Vec<&str> = annotated
            .findings
            .iter()
            .map(|f| f.cluster.as_str())
            .collect();
        assert_eq!(plain_keys, annotated_keys, "el LLM movió los clusters");
        let plain_known: Vec<Option<&str>> = plain.findings.iter().map(|f| f.known).collect();
        let annotated_known: Vec<Option<&str>> =
            annotated.findings.iter().map(|f| f.known).collect();
        assert_eq!(
            plain_known, annotated_known,
            "el LLM movió la clasificación"
        );
        // Lo único que cambia es la columna del costado.
        assert!(plain.findings.iter().all(|f| f.llm_root_cause.is_none()));
        assert!(
            annotated
                .findings
                .iter()
                .all(|f| f.llm_root_cause.is_some())
        );
    }

    /// **Una divergencia conocida se CUENTA y se MUESTRA** (§3.2). Lo que
    /// cambia es el exit code y el titular, nunca su existencia. El corpus
    /// sintético trae un caso que cae en una divergencia deliberada del
    /// inventario, así que el test mira el caso real y no una construcción.
    #[test]
    fn a_known_divergence_is_counted_and_shown_never_suppressed() {
        let dir = std::env::temp_dir().join(format!("repo-b-fuzz-known-{}", std::process::id()));
        write_synthetic_corpus(&dir);
        let mut config = config(48);
        config.seed = 0x2026_0819;
        config.generator = Generator::Mutate;
        config.seed_root = Some(dir.clone());
        let report = must_run(&config);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(report.diverged > 0, "el corpus sintético no divergió");
        assert!(
            report.clusters_account_for_every_divergence(),
            "{} divergencias crudas contra {} repartidas en clusters",
            report.diverged,
            report.findings.iter().map(|f| f.occurrences).sum::<u64>()
        );
        let Some(known) = report.findings.iter().find(|f| f.known.is_some()) else {
            panic!("la divergencia conocida no aparece en el reporte: fue suprimida");
        };
        assert!(known.occurrences > 0);
        let rendered = crate::fuzz::report::finding_lines(known).join("\n");
        assert!(rendered.contains("CONOCIDO"), "{rendered}");
        assert!(rendered.contains(&known.cluster), "{rendered}");
        assert_eq!(report.known_clusters(), report.findings.len());
        assert_eq!(report.new_clusters(), 0);
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
        // Un caso que DIVERGE de verdad, y que cae contra una divergencia
        // deliberada del inventario: una tx tipo 4 con `to == None`, que
        // nosotros rechazamos y revm ejecuta (`revm no lo chequea` ≠ `no hay
        // que chequearlo`). Sin un caso así, los tests del triage correrían
        // sobre cero hallazgos y no probarían nada — el modo vacuo que este
        // proyecto caza desde 2.9b-3a.
        if std::fs::write(dir.join("divergente.json"), DELIBERATE_DIVERGENCE_FIXTURE).is_err() {
            panic!("no se pudo escribir el caso divergente");
        }
    }

    /// El fixture del párrafo de arriba. Va literal y no generado: lo que
    /// prueba es que el triage clasifica ESTE caso, y un generador en el medio
    /// podría dejar de producirlo sin que nadie se entere.
    const DELIBERATE_DIVERGENCE_FIXTURE: &str = r#"{
      "tipo4-sin-to": {
        "_comment": "tx tipo 4 con to = None: la rechazamos y revm la ejecuta",
        "env": {
          "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
          "currentNumber": "0x1",
          "currentTimestamp": "0x3e8",
          "currentGasLimit": "0x7270e00",
          "currentBaseFee": "0x7",
          "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000000",
          "currentExcessBlobGas": "0x0"
        },
        "config": { "chainid": "0x1" },
        "pre": {
          "0x290fe81e0c9b0d7da96b64ba5e6cbbdaf554e473": {
            "nonce": "0x0",
            "balance": "0x3635c9adc5dea00000",
            "code": "0x",
            "storage": {}
          }
        },
        "transaction": {
          "sender": "0x290fe81e0c9b0d7da96b64ba5e6cbbdaf554e473",
          "to": "",
          "nonce": "0x0",
          "maxFeePerGas": "0x7",
          "maxPriorityFeePerGas": "0x0",
          "data": ["0x"],
          "gasLimit": ["0x186a0"],
          "value": ["0x0"],
          "accessLists": [[]],
          "authorizationList": [
            {
              "chainId": "0x0",
              "address": "0x0000000000000000000000000000000000000001",
              "nonce": "0x0",
              "authority": "0x3aaee4b6bcbd0677c9ef4dcc9f76f33e37eb26e4"
            }
          ]
        },
        "post": {
          "Prague": [
            {
              "indexes": { "data": 0, "gas": 0, "value": 0 },
              "hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
              "logs": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
          ]
        }
      }
    }"#;
}
