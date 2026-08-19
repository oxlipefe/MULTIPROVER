//! **El loop de regresión**: el primero de los dos loops del red-team, y el
//! que protege el repo todos los días.
//!
//! | loop | cuándo | SLA | corpus |
//! |---|---|---|---|
//! | **regresión** (acá) | gate de merge | **minutos** | cada divergencia histórica ya cazada |
//! | profundidad (`fleet`) | nightly | horas, deadline duro | campañas largas, flota efímera |
//!
//! ## Qué siembra el corpus, y por qué no alcanza con `--diff`
//!
//! El corpus de regresión es la **unión** de tres orígenes, y ninguno de los
//! tres cubre a los otros dos:
//!
//! 1. `fixtures/diff/` — los 21 sets diferenciales, un caso por regla de
//!    consenso que alguna vez se rompió o se puso a prueba. `--diff` ya los
//!    corre, pero los corre en 21 procesos y **sin clasificar contra el
//!    inventario**;
//! 2. `fixtures/fuzz-seeds/` — el corpus dirigido, que hoy **no está
//!    en el gate por ningún camino**: solo lo toca `--fuzz --directed`;
//! 3. `fixtures/fuzz-ratchet/` — el trinquete del fuzzer, donde caen los
//!    hallazgos minimizados de una campaña. Hoy está **vacío**, y ésa es la
//!    razón correcta: ninguna campaña encontró todavía un bug real. Existe
//!    igual, versionado, porque el directorio tiene que estar ANTES del primer
//!    hallazgo o el primero se pierde por no tener dónde caer.
//!
//! ## Clasificar, nunca excusar
//!
//! El barrido no exige "cero divergencias": exige **cero divergencias NUEVAS**.
//! Una divergencia deliberada del inventario (hoy: EIP-7610, que el corpus
//! dirigido trae a propósito) se cuenta, se muestra y se etiqueta. Es la regla
//! del red-team, y 2.9c-5 le puso número: excusar en vez de clasificar dejó
//! pasar 2 545 casos con la razón equivocada.
//!
//! Que el corpus traiga **las dos clases desde el día uno** —338 casos que
//! coinciden y 1 clasificado— no es casualidad afortunada: un barrido que solo
//! tuviera casos verdes no probaría que la clasificación funciona.

use std::path::{Path, PathBuf};

use crate::fixture::spec_for_fork;
use crate::fuzz::seeds::{SeedCase, normalize_seed};

/// Los 21 sets diferenciales, enumerados a mano y **contrastados contra el
/// disco**.
///
/// Enumerarlos parece redundante con leer el directorio, y no lo es: leerlo
/// solo detecta que un set desapareció, no que uno nuevo entró sin que nadie
/// decidiera sembrarlo. Con la lista, las dos direcciones se ponen rojas. Es la
/// misma lista que enumera el gate, y por la misma razón por la que el gate la
/// enumera en vez de usar un glob: `diff::run_dir` no recursa.
pub const HISTORICAL_DIFF_SETS: &[&str] = &[
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

/// El piso de corridas del corpus de regresión: **327** del diferencial + **12**
/// del corpus dirigido, los dos medidos.
///
/// Es un piso y no una igualdad porque el trinquete solo crece. Que sea un piso
/// **medido** es lo que le da sentido: sin él, "el corpus de regresión está
/// sembrado" sería una afirmación que nadie puede falsificar, y un corpus vacío
/// pasaría el barrido en 0 s con toda tranquilidad.
pub const MIN_REGRESSION_CASES: usize = 339;

/// Un caso del corpus de regresión, con **de dónde salió**. El origen no es
/// adorno: cuando un caso vuelve a divergir, lo primero que hace falta saber es
/// qué regla protegía.
#[derive(Debug, Clone)]
pub struct RegressionCase {
    /// El set o corpus de origen (`storage`, `dirigido`, `trinquete`).
    pub source: String,
    pub case: SeedCase,
}

#[derive(Debug, Clone, Default)]
pub struct RegressionCorpus {
    pub cases: Vec<RegressionCase>,
    /// Los sets de `fixtures/diff/` que se encontraron en el disco, ordenados.
    pub diff_sets: Vec<String>,
    /// Cuántos casos aportó el trinquete. Hoy 0, y se reporta explícito para
    /// que el día que deje de ser 0 se note.
    pub ratchet_cases: usize,
}

impl RegressionCorpus {
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }
}

/// Dónde vive cada pieza del corpus. Las tres, junto al harness.
pub fn diff_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/diff")
}

pub fn directed_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/fuzz-seeds")
}

/// El trinquete: donde caen los hallazgos minimizados de una campaña
/// (`--fuzz --out`).
pub fn ratchet_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/fuzz-ratchet")
}

/// Carga el corpus de regresión completo.
///
/// **Fail-closed en tres direcciones**, y las tres producirían un loop que
/// corre y no protege nada: un directorio que falta, un archivo que no parsea,
/// y un corpus por debajo del piso medido.
pub fn load() -> Result<RegressionCorpus, String> {
    let mut corpus = RegressionCorpus::default();
    load_diff_sets(&mut corpus)?;
    load_dir(&mut corpus, &directed_root(), "dirigido")?;

    let ratchet = ratchet_root();
    if !ratchet.is_dir() {
        return Err(format!(
            "no encuentro el trinquete en {} — tiene que existir ANTES del primer \
             hallazgo, o el primero se pierde por no tener dónde caer",
            ratchet.display()
        ));
    }
    let before = corpus.len();
    load_dir(&mut corpus, &ratchet, "trinquete")?;
    corpus.ratchet_cases = corpus.len().saturating_sub(before);

    if corpus.is_empty() || corpus.len() < MIN_REGRESSION_CASES {
        return Err(format!(
            "el corpus de regresión quedó en {} corridas, por debajo del piso medido \
             de {MIN_REGRESSION_CASES}: un corpus vacío o mutilado pasa el barrido en \
             0 s y no protege nada (fail-closed)",
            corpus.len()
        ));
    }
    Ok(corpus)
}

/// Los 21 sets, contrastados contra la lista enumerada en las dos direcciones.
fn load_diff_sets(corpus: &mut RegressionCorpus) -> Result<(), String> {
    let root = diff_root();
    let mut found: Vec<String> = Vec::new();
    let entries =
        std::fs::read_dir(&root).map_err(|e| format!("leyendo {}: {e}", root.display()))?;
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in &dirs {
        let Some(name) = dir.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        found.push(name.to_owned());
        load_dir(corpus, dir, name)?;
    }
    if found != HISTORICAL_DIFF_SETS {
        return Err(format!(
            "los sets diferenciales del disco no son los enumerados: disco {found:?}, \
             enumerados {HISTORICAL_DIFF_SETS:?}. Un set nuevo se siembra a propósito, \
             no por descubrimiento"
        ));
    }
    corpus.diff_sets = found;
    Ok(())
}

/// Levanta todos los `.json` de un directorio (sin recursar: es la forma de
/// `fixtures/diff/<set>/`). Un archivo que no parsea **falla**, no se saltea:
/// éste es corpus versionado nuestro, no un cache ajeno.
fn load_dir(corpus: &mut RegressionCorpus, dir: &Path, source: &str) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("leyendo {}: {e}", dir.display()))?;
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    // El orden del sistema de archivos no es determinista y el índice del caso
    // es parte de cómo se reporta un hallazgo.
    files.sort();
    for path in &files {
        let name = path.display().to_string();
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
        let tests = crate::fixture::parse_file(&raw).map_err(|e| format!("{name}: {e}"))?;
        for test in &tests {
            for post in &test.posts {
                if spec_for_fork(&post.fork).is_none() {
                    return Err(format!(
                        "{name}: el caso `{}` declara el fork `{}`, fuera del scope \
                         (Paris, Shanghai, Cancun, Prague)",
                        test.name, post.fork
                    ));
                }
                corpus.cases.push(RegressionCase {
                    source: source.to_owned(),
                    case: normalize_seed(test, post),
                });
            }
        }
    }
    Ok(())
}

/// Lo que el barrido encontró.
#[derive(Debug, Default)]
pub struct RegressionReport {
    pub cases: usize,
    pub same: usize,
    pub both_rejected: usize,
    pub skipped_fork: usize,
    /// Divergencias que caen contra el inventario: `(origen, caso, cluster,
    /// regla)`. Se cuentan y se muestran; no se suprimen.
    pub known: Vec<(String, String, String, &'static str)>,
    /// Lo único que hace fallar el loop.
    pub new: Vec<(String, String, String)>,
    pub elapsed_secs: f64,
}

impl RegressionReport {
    pub const fn is_green(&self) -> bool {
        self.new.is_empty() && self.skipped_fork == 0
    }
}

/// El barrido. Detrás de la feature porque el juez es revm in-process.
#[cfg(feature = "diff-revm")]
pub fn sweep(corpus: &RegressionCorpus) -> RegressionReport {
    use crate::diff::{CaseOutcome, run_case};
    use crate::fuzz::site::site_of;
    use crate::fuzz::triage::cluster_key;
    use crate::oracle::known_cluster;

    let started = std::time::Instant::now();
    let mut report = RegressionReport {
        cases: corpus.len(),
        ..RegressionReport::default()
    };
    for entry in &corpus.cases {
        let case = &entry.case;
        match run_case(&case.test, &case.post) {
            CaseOutcome::Same => report.same = report.same.saturating_add(1),
            CaseOutcome::BothRejectedTx { .. } => {
                report.both_rejected = report.both_rejected.saturating_add(1);
            }
            // Un caso del corpus de regresión que no se corre no protege nada.
            // Se cuenta y **hace fallar**: es la regla de `run_dir`, un set
            // vacío no es verde.
            CaseOutcome::SkippedFork => {
                report.skipped_fork = report.skipped_fork.saturating_add(1);
            }
            CaseOutcome::Diverged { differences } => {
                let site = site_of(&case.test, &case.post, &differences);
                let key = cluster_key(&differences, &site);
                match known_cluster(&key) {
                    Some(known) => report.known.push((
                        entry.source.clone(),
                        case.name.clone(),
                        key,
                        known.rule,
                    )),
                    None => report
                        .new
                        .push((entry.source.clone(), case.name.clone(), key)),
                }
            }
        }
    }
    report.elapsed_secs = started.elapsed().as_secs_f64();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **M4 en su forma estática.** El corpus de regresión está SEMBRADO: los
    /// 21 sets históricos, el corpus dirigido y el trinquete, por encima del
    /// piso medido. Un loop de regresión con corpus vacío corre en 0 s, sale
    /// verde y deja volver a pasar cualquier bug ya cazado.
    #[test]
    fn the_regression_corpus_is_seeded_with_every_historical_source() {
        let corpus = match load() {
            Ok(corpus) => corpus,
            Err(e) => panic!("el corpus de regresión no carga: {e}"),
        };
        assert!(
            corpus.len() >= MIN_REGRESSION_CASES,
            "el corpus quedó en {} corridas",
            corpus.len()
        );
        assert_eq!(corpus.diff_sets, HISTORICAL_DIFF_SETS);
        for set in HISTORICAL_DIFF_SETS {
            assert!(
                corpus.cases.iter().any(|case| case.source == *set),
                "el set histórico `{set}` no aportó ninguna corrida"
            );
        }
        assert!(
            corpus.cases.iter().any(|case| case.source == "dirigido"),
            "el corpus dirigido no aportó ninguna corrida: hoy es el ÚNICO origen \
             del corpus de regresión que ningún otro comando del gate toca"
        );
    }

    /// El trinquete existe y hoy está vacío. Las dos mitades importan: sin el
    /// directorio, el primer hallazgo no tiene dónde caer; y que hoy sea 0 es
    /// la razón correcta, no una falla.
    #[test]
    fn the_ratchet_directory_exists_and_is_empty_for_the_right_reason() {
        assert!(ratchet_root().is_dir(), "el trinquete no existe");
        let Ok(corpus) = load() else {
            panic!("el corpus de regresión no carga");
        };
        assert_eq!(
            corpus.ratchet_cases, 0,
            "el trinquete tiene {} casos: si una campaña encontró algo, este número \
             tiene que subir Y el piso `MIN_REGRESSION_CASES` con él",
            corpus.ratchet_cases
        );
    }

    /// El orden del barrido es determinista: dos cargas dan el mismo corpus en
    /// el mismo orden. Sin esto, "el caso 17 diverge" no señalaría nada.
    #[test]
    fn loading_twice_gives_the_same_corpus_in_the_same_order() {
        let (Ok(first), Ok(second)) = (load(), load()) else {
            panic!("el corpus de regresión no carga");
        };
        let names = |corpus: &RegressionCorpus| -> Vec<(String, String)> {
            corpus
                .cases
                .iter()
                .map(|case| (case.source.clone(), case.case.name.clone()))
                .collect()
        };
        assert_eq!(names(&first), names(&second));
    }
}
