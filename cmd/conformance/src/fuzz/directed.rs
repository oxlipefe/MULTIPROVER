//! El **tercer generador** del red-team: un corpus de semillas **dirigidas**,
//! escritas contra una interacción concreta entre EIPs.
//!
//! ## Qué hace distinto a este generador, medido y no declarado
//!
//! Los otros dos tienen un blind spot que es de **estructura**, no de
//! presupuesto:
//!
//! | | gramática (2.9d-2) | mutación de EEST (2.9d-3) |
//! |---|---|---|
//! | envelope 2930/4844/7702 | **imposible**: `FuzzCase` los construye en `None` | lo **hereda** del fixture semilla |
//! | un cruce que EEST no trae | imposible | **imposible**: ningún operador crea una access list, una autorización ni un designator de 23 bytes |
//!
//! Medido sobre los 39 025 `state_test` en scope: EEST cruza access list con
//! blob tx en 932 casos y delega a una precompile en 199, pero **cruza una
//! access list con un designator ya presente en el `pre` en CERO**. Un cruce
//! con cero semillas es inalcanzable para el generador de mutación con
//! cualquier presupuesto.
//!
//! ## Las dos reglas que hacen utilizable a un corpus escrito por un LLM
//!
//! 1. **El LLM propone DÓNDE mirar, nunca dice QUÉ tiene que pasar.** El
//!    oráculo sigue siendo revm + EEST. Acá eso es **mecánico**: una semilla
//!    que declare un `hash`, un `logs`, un `state` o un `expectException`
//!    **se rechaza al cargarla**. Un valor esperado escrito por un LLM sería un
//!    tercer oráculo que miente.
//! 2. **El LLM es autor de corpus, no componente de runtime.** Las semillas se
//!    escriben offline y se versionan; desde ahí las muta, minimiza y triaza la
//!    misma maquinaria determinista que cualquier otro corpus. La campaña se
//!    reproduce del disco **sin volver a llamar a ningún LLM**, y por eso este
//!    módulo no tiene ninguna dependencia nueva ni necesita una API key.
//!
//! ## Procedencia obligatoria
//!
//! Una semilla sin justificación es ruido caro: la próxima persona no puede
//! decidir si borrarla. Cada caso declara **qué ataca** y **por qué los otros
//! dos generadores no llegan ahí**, y la carga **falla** si falta.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::fixture::{parse_file, spec_for_fork};
use crate::fuzz::seeds::{SeedCase, SeedCorpus, normalize_seed};

/// La clave del bloque de procedencia dentro de cada caso. Va **adentro** del
/// caso y no al tope del archivo porque `fixture::parse_file` trata cada clave
/// del tope como un test: una `_provenance` ahí sería un caso sin `env`.
const PROVENANCE_KEY: &str = "_provenance";

/// Los campos obligatorios de la procedencia (§5). No alcanza con "qué ataca":
/// **por qué los otros dos no llegan** es lo que justifica el costo de tener un
/// tercer generador, y es lo que M1 después mide.
const REQUIRED_PROVENANCE: &[&str] = &[
    "targets",
    "why",
    "unreachable_by_grammar",
    "unreachable_by_eest_mutation",
];

/// El hash nulo: lo único que una semilla puede declarar en `post.hash` /
/// `post.logs`. Es el mismo valor que escribe `emit::to_fixture_json`, y por la
/// misma razón — el juez del diferencial es revm, no el fixture.
const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// La procedencia de una semilla, tal cual la declara el corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Qué EIP o cruce de EIPs ataca.
    pub targets: String,
    /// Qué regla de consenso pone en juego.
    pub why: String,
    /// Por qué la gramática de 2.9d-2 no llega.
    pub unreachable_by_grammar: String,
    /// Por qué la mutación de EEST de 2.9d-3 no llega.
    pub unreachable_by_eest_mutation: String,
}

/// El corpus dirigido, con la procedencia al lado de cada caso.
#[derive(Debug, Clone, Default)]
pub struct DirectedCorpus {
    pub corpus: SeedCorpus,
    /// Paralelo a `corpus.cases`: la procedencia del caso `i`.
    pub provenance: Vec<Provenance>,
}

/// Carga el corpus dirigido desde `dir`.
///
/// **Fail-closed en las cuatro direcciones**, porque las cuatro producirían un
/// generador que corre y no prueba nada:
///
/// - el directorio no existe o quedó vacío ⇒ error (la regla de `run_dir`: un
///   set vacío NO es verde);
/// - un archivo no parsea ⇒ error, **a diferencia del corpus de EEST**, que
///   cuenta y sigue: aquél es un cache de 257 MB ajeno, éste es nuestro y está
///   versionado, así que un archivo roto es un bug del repo, no del release;
/// - falta la procedencia o alguno de sus campos ⇒ error (§5);
/// - la semilla declara un valor esperado ⇒ error (§2).
pub fn load(dir: &Path) -> Result<DirectedCorpus, String> {
    if !dir.is_dir() {
        return Err(format!(
            "no encuentro el corpus dirigido en {} — es corpus VERSIONADO del repo, \
             no un cache: si no está, el checkout está incompleto",
            dir.display()
        ));
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("leyendo {}: {e}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    // El orden del sistema de archivos no es determinista y el índice del caso
    // semilla sale de esta lista.
    files.sort();

    let mut out = DirectedCorpus::default();
    for path in &files {
        let name = path.display().to_string();
        let raw = std::fs::read_to_string(path).map_err(|e| format!("{name}: {e}"))?;
        let document: Value =
            serde_json::from_str(&raw).map_err(|e| format!("{name}: JSON inválido: {e}"))?;
        let object = document
            .as_object()
            .ok_or_else(|| format!("{name}: el archivo no es un objeto JSON"))?;
        let tests = parse_file(&raw).map_err(|e| format!("{name}: {e}"))?;

        for test in tests {
            let body = object
                .get(&test.name)
                .ok_or_else(|| format!("{name}: no encuentro el caso `{}`", test.name))?;
            let provenance = provenance_of(&name, &test.name, body)?;
            for post in &test.posts {
                reject_expected_values(&name, &test.name, body)?;
                if spec_for_fork(&post.fork).is_none() {
                    return Err(format!(
                        "{name}: el caso `{}` declara el fork `{}`, que está fuera del scope \
                         (Paris, Shanghai, Cancun, Prague)",
                        test.name, post.fork
                    ));
                }
                out.corpus.cases.push(named(normalize_seed(&test, post)));
                out.provenance.push(provenance.clone());
            }
        }
    }

    if out.corpus.cases.is_empty() {
        return Err(format!(
            "el corpus dirigido quedó VACÍO tras leer {} archivos de {} \
             (fail-closed: un corpus vacío no es un corpus chico)",
            files.len(),
            dir.display()
        ));
    }
    Ok(out)
}

/// El nombre del caso semilla viaja al hallazgo, y para una semilla dirigida
/// conviene que se lea como tal en el reporte.
fn named(mut case: SeedCase) -> SeedCase {
    case.name = format!("dirigida::{}", case.name);
    case
}

fn provenance_of(file: &str, case: &str, body: &Value) -> Result<Provenance, String> {
    let block = body.get(PROVENANCE_KEY).ok_or_else(|| {
        format!(
            "{file}: el caso `{case}` no declara `{PROVENANCE_KEY}` — una semilla sin \
             procedencia es ruido caro: nadie puede decidir después si borrarla"
        )
    })?;
    let field = |key: &str| -> Result<String, String> {
        let value = block
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if value.is_empty() {
            return Err(format!(
                "{file}: el caso `{case}` no declara `{PROVENANCE_KEY}.{key}`"
            ));
        }
        Ok(value)
    };
    let mut values = Vec::with_capacity(REQUIRED_PROVENANCE.len());
    for key in REQUIRED_PROVENANCE {
        values.push(field(key)?);
    }
    let mut values = values.into_iter();
    let mut next = || values.next().unwrap_or_default();
    Ok(Provenance {
        targets: next(),
        why: next(),
        unreachable_by_grammar: next(),
        unreachable_by_eest_mutation: next(),
    })
}

/// **La regla del §2, mecánica.** Una semilla no puede traer un valor esperado:
/// el oráculo es revm + EEST, y un número escrito por un LLM sería un tercer
/// oráculo que miente. Se mira el JSON crudo y no el `PostCase` parseado porque
/// lo que hay que prohibir es que el campo **esté escrito**, no que sobreviva
/// al parseo.
fn reject_expected_values(file: &str, case: &str, body: &Value) -> Result<(), String> {
    let Some(post) = body.get("post").and_then(Value::as_object) else {
        return Ok(());
    };
    for (fork, entries) in post {
        let Some(entries) = entries.as_array() else {
            continue;
        };
        for entry in entries {
            for key in ["hash", "logs"] {
                let declared = entry.get(key).and_then(Value::as_str).unwrap_or(ZERO_HASH);
                if declared != ZERO_HASH {
                    return Err(format!(
                        "{file}: el caso `{case}` [{fork}] declara `post.{key}` = {declared}. \
                         Una semilla dirigida NO lleva valores esperados: el oráculo es revm \
                         + EEST, y un valor escrito acá sería un tercer oráculo que miente"
                    ));
                }
            }
            for key in ["state", "expectException"] {
                if entry.get(key).is_some() {
                    return Err(format!(
                        "{file}: el caso `{case}` [{fork}] declara `post.{key}`. \
                         Una semilla dirigida NO lleva valores esperados (§2): el juez es \
                         revm, no el fixture"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Dónde vive el corpus dirigido. **Versionado en el repo**, junto a los
/// fixtures del diferencial: es la mitad del §3 que hace que la campaña se
/// reproduzca sin volver a llamar a ningún LLM.
pub fn default_directed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/fuzz-seeds")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El corpus versionado carga, no está vacío y **toda** semilla declara su
    /// procedencia completa. Es el test que M5 pone en rojo.
    #[test]
    fn the_versioned_corpus_loads_and_every_seed_declares_its_provenance() {
        let corpus = match load(&default_directed_dir()) {
            Ok(corpus) => corpus,
            Err(e) => panic!("el corpus dirigido no carga: {e}"),
        };
        assert!(
            corpus.corpus.len() >= 8,
            "el corpus dirigido quedó en {} casos",
            corpus.corpus.len()
        );
        assert_eq!(corpus.provenance.len(), corpus.corpus.len());
        for (case, provenance) in corpus.corpus.cases.iter().zip(&corpus.provenance) {
            for (label, text) in [
                ("targets", &provenance.targets),
                ("why", &provenance.why),
                ("unreachable_by_grammar", &provenance.unreachable_by_grammar),
                (
                    "unreachable_by_eest_mutation",
                    &provenance.unreachable_by_eest_mutation,
                ),
            ] {
                assert!(
                    !text.trim().is_empty(),
                    "la semilla `{}` no justifica `{label}`",
                    case.name
                );
            }
        }
    }

    /// **El trinquete de cobertura por tema.** El corpus dirigido existe por
    /// los cruces entre EIPs que los otros dos generadores no alcanzan; si un
    /// cruce desaparece —porque se borró una semilla o porque una edición la
    /// dejó sin ejercitarlo— este test lo dice. La lista está pineada: la
    /// cobertura por tema deja de ser una medición de una tarde y pasa a ser
    /// una propiedad del repo.
    #[test]
    fn the_directed_corpus_covers_the_crossings_it_claims() {
        let Ok(corpus) = load(&default_directed_dir()) else {
            panic!("el corpus dirigido no carga");
        };
        let mut covered = std::collections::BTreeSet::new();
        for case in &corpus.corpus.cases {
            covered.extend(crate::fuzz::themes::themes_of(&case.test, &case.post));
        }
        for crossing in [
            "x:access-list×designator",
            "x:7702→precompile",
            "x:4844×designator",
            "x:4844×access-list",
            "x:designator×CREATE",
            "x:designator×SELFDESTRUCT",
            "x:7702→precompile×sender-delegado",
        ] {
            assert!(
                covered.contains(crossing),
                "el corpus dirigido dejó de cubrir `{crossing}`; cubre {covered:?}"
            );
        }
    }

    /// Ninguna semilla es decorativa: cada una declara al menos un tema que no
    /// sea el fork. Una semilla que solo dijera "Prague" no ejercita nada, y
    /// un corpus con semillas así reportaría "0 divergencias" sin haber
    /// mirado — el modo vacuo que este proyecto caza desde 2.9b-3a.
    #[test]
    fn no_directed_seed_is_decorative() {
        let Ok(corpus) = load(&default_directed_dir()) else {
            panic!("el corpus dirigido no carga");
        };
        for case in &corpus.corpus.cases {
            let themes = crate::fuzz::themes::themes_of(&case.test, &case.post);
            let substantive = themes
                .iter()
                .filter(|theme| !theme.starts_with("fork:"))
                .count();
            assert!(
                substantive > 0,
                "la semilla `{}` no ejercita ningún tema",
                case.name
            );
        }
    }

    /// **El orden del corpus está PINEADO, no comparado consigo mismo.**
    ///
    /// La primera versión de este test cargaba dos veces y comparaba las dos
    /// cargas — y una mutación que reordena el corpus **no la ponía en rojo**,
    /// porque las dos cargas se reordenaban igual. Es la misma forma del
    /// hallazgo de M6 de 2.9d-3: la mutación no encontró un bug, encontró que
    /// la prueba no probaba.
    ///
    /// El índice del caso semilla es la mitad del `(semilla, índice)` que
    /// reproduce un hallazgo; si el orden se mueve, el hallazgo archivado
    /// apunta a otra semilla. Por eso lo que se pinea es el orden CONCRETO.
    #[test]
    fn the_corpus_order_is_pinned_and_not_merely_self_consistent() {
        let Ok(corpus) = load(&default_directed_dir()) else {
            panic!("el corpus dirigido no carga");
        };
        let names: Vec<&str> = corpus
            .corpus
            .cases
            .iter()
            .map(|case| case.name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(
            names.first(),
            Some(&"dirigida::al_warms_both_ends [Prague]"),
            "cambió la primera semilla del corpus: {names:?}"
        );
        assert_eq!(
            names.last(),
            Some(&"dirigida::sender_delegated_to_precompile [Prague]"),
            "cambió la última semilla del corpus: {names:?}"
        );
        assert_eq!(corpus.provenance.len(), names.len());
    }

    fn write(dir: &Path, name: &str, body: &str) {
        if std::fs::create_dir_all(dir).is_err() {
            panic!("no se pudo preparar {}", dir.display());
        }
        if std::fs::write(dir.join(name), body).is_err() {
            panic!("no se pudo escribir {name}");
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "repo-b-directed-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Una semilla mínima y válida, con los agujeros que cada test tapa.
    fn seed(provenance: &str, post_extra: &str) -> String {
        format!(
            r#"{{ "semilla": {{
              {provenance}
              "env": {{
                "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "currentNumber": "0x1", "currentTimestamp": "0x3e8",
                "currentGasLimit": "0x7270e00", "currentBaseFee": "0x7",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000042",
                "currentExcessBlobGas": "0x0"
              }},
              "pre": {{ "0x290fe81e0c9b0d7da96b64ba5e6cbbdaf554e473": {{
                "nonce": "0x0", "balance": "0x3635c9adc5dea00000", "code": "0x", "storage": {{}}
              }} }},
              "transaction": {{
                "sender": "0x290fe81e0c9b0d7da96b64ba5e6cbbdaf554e473",
                "to": "0x290fe81e0c9b0d7da96b64ba5e6cbbdaf554e473",
                "nonce": "0x0", "gasPrice": "0x7",
                "data": ["0x"], "gasLimit": ["0x186a0"], "value": ["0x0"]
              }},
              "post": {{ "Prague": [ {{ "indexes": {{ "data": 0, "gas": 0, "value": 0 }},
                "hash": "{ZERO_HASH}", "logs": "{ZERO_HASH}"{post_extra} }} ] }}
            }} }}"#
        )
    }

    const GOOD_PROVENANCE: &str = r#""_provenance": {
        "targets": "EIP-x", "why": "porque sí",
        "unreachable_by_grammar": "no hay envelope",
        "unreachable_by_eest_mutation": "no hay semilla" },"#;

    /// **M5.** Una semilla sin procedencia no se carga: se rechaza con el
    /// nombre del caso y el campo que falta.
    #[test]
    fn a_seed_without_provenance_is_rejected() {
        let dir = scratch("noprov");
        write(&dir, "a.json", &seed("", ""));
        let result = load(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(corpus) => panic!("cargó {} semillas sin procedencia", corpus.corpus.len()),
            Err(e) => assert!(e.contains("_provenance"), "{e}"),
        }
    }

    /// Una procedencia incompleta tampoco pasa: los cuatro campos son el §5, y
    /// el que falta se nombra.
    #[test]
    fn a_partial_provenance_is_rejected_naming_the_missing_field() {
        let dir = scratch("partial");
        write(
            &dir,
            "a.json",
            &seed(
                r#""_provenance": { "targets": "EIP-x", "why": "porque sí",
                    "unreachable_by_grammar": "no hay envelope" },"#,
                "",
            ),
        );
        let result = load(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(_) => panic!("cargó una semilla con la procedencia a medias"),
            Err(e) => assert!(e.contains("unreachable_by_eest_mutation"), "{e}"),
        }
    }

    /// **M2, mecánica.** Una semilla que trae un valor esperado se rechaza: el
    /// oráculo es revm + EEST y un número escrito por el LLM sería un tercer
    /// oráculo que miente.
    #[test]
    fn a_seed_that_carries_an_expected_value_is_rejected() {
        for extra in [
            r#", "hash": "0x1111111111111111111111111111111111111111111111111111111111111111""#,
            r#", "state": { "0x290fe81e0c9b0d7da96b64ba5e6cbbdaf554e473": {
                "nonce": "0x1", "balance": "0x0", "code": "0x", "storage": {} } }"#,
            r#", "expectException": "TransactionException.INTRINSIC_GAS_TOO_LOW""#,
        ] {
            let dir = scratch("expected");
            // El `hash` duplicado del primer caso es a propósito: serde_json se
            // queda con el último, que es el valor inventado.
            write(&dir, "a.json", &seed(GOOD_PROVENANCE, extra));
            let result = load(&dir);
            let _ = std::fs::remove_dir_all(&dir);
            match result {
                Ok(_) => panic!("cargó una semilla con un valor esperado: {extra}"),
                Err(e) => assert!(
                    e.contains("oráculo") || e.contains("valores esperados"),
                    "{e}"
                ),
            }
        }
    }

    /// **M4.** Una semilla malformada **falla closed y con error claro**: no
    /// paniquea, no se saltea en silencio y no deja correr el resto. A
    /// diferencia del cache de EEST —ajeno y de 257 MB—, este corpus está
    /// versionado: un archivo roto es un bug del repo.
    #[test]
    fn a_malformed_seed_fails_closed_and_never_silently_skips() {
        for (tag, body) in [
            ("nojson", "{ esto no es json"),
            (
                "noenv",
                r#"{ "semilla": { "pre": {}, "transaction": {} } }"#,
            ),
            (
                "badhex",
                &seed(GOOD_PROVENANCE, "").replace("\"0x186a0\"", "\"0xZZZZ\""),
            ),
        ] {
            let dir = scratch(tag);
            // **La semilla BUENA va al lado a propósito.** Sin ella, saltear
            // el archivo roto dejaría el corpus vacío y el `Err` vendría del
            // chequeo de vacuidad: el test pasaría con la implementación que
            // este test existe para prohibir. Lo destapó la mutación M4, que
            // salió muda en la primera versión.
            write(&dir, "z-buena.json", &seed(GOOD_PROVENANCE, ""));
            write(&dir, "a.json", body);
            let result = load(&dir);
            let _ = std::fs::remove_dir_all(&dir);
            match result {
                Ok(corpus) => panic!(
                    "la semilla `{tag}` se salteó en silencio: el corpus cargó {} casos",
                    corpus.corpus.len()
                ),
                Err(e) => assert!(
                    !e.contains("VACÍO"),
                    "falló por vacuidad y no por `{tag}`: {e}"
                ),
            }
        }
    }

    /// Un directorio ausente o vacío no es un corpus chico: es la misma regla
    /// fail-closed que aplica `run_dir` y que M5 de 2.9d-3 dejó medida.
    #[test]
    fn a_missing_or_empty_directory_is_a_loud_error() {
        match load(Path::new("/no/existe/este/corpus")) {
            Ok(_) => panic!("cargó un corpus de un directorio que no existe"),
            Err(e) => assert!(e.contains("no encuentro"), "{e}"),
        }
        let dir = scratch("empty");
        if std::fs::create_dir_all(&dir).is_err() {
            panic!("no se pudo preparar el directorio");
        }
        let result = load(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        match result {
            Ok(_) => panic!("un directorio vacío cargó semillas"),
            Err(e) => assert!(e.contains("VACÍO"), "{e}"),
        }
    }
}
