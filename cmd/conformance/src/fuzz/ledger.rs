//! El **libro mayor append-only** de los hallazgos del red-team diferencial.
//!
//! La regla que le da forma: *un hallazgo que no se puede reproducir no es un
//! hallazgo*. Por eso cada línea lleva, además del cluster, todo lo que hace
//! falta para volver a producirlo desde cero:
//!
//! - **la semilla y el índice del caso** (`(seed, index)` direcciona un caso
//!   sin re-generar los anteriores, que es por qué el lazo no usa
//!   `proptest::TestRunner`);
//! - **la identidad del fixture semilla**, porque el índice depende del tamaño
//!   del corpus y el nombre no;
//! - **el commit del motor**, marcado como sucio si el árbol tenía cambios sin
//!   commitear — un hallazgo producido sobre un árbol sucio no se reproduce
//!   desde el commit y decirlo es más barato que descubrirlo después;
//! - **la versión pineada de revm**, porque el juez es revm y un juez distinto
//!   es otro experimento;
//! - **el reproductor minimizado completo**, embebido: la línea del libro es
//!   auto-contenida y no depende de que el directorio del trinquete siga ahí.
//!
//! Formato: **JSON-lines**. Una línea por hallazgo, append. No es estético:
//! un formato que hay que re-escribir entero para agregar una línea no es
//! append-only, y con una campaña de 24/7 el archivo se lee mientras se
//! escribe.
//!
//! El `run_id` se **deriva** de la configuración y del entorno en vez de
//! sortearse: dos corridas idénticas comparten `run_id` porque son la misma
//! corrida, y un identificador con la hora del sistema adentro convertiría el
//! libro en algo que no se puede diffear.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

use repo_b_common::primitives::keccak256;
use serde_json::{Value, json};

/// La versión de revm que juzga. Pineada acá y **cruzada por un test** contra
/// el `Cargo.toml` del workspace: un bump que no toque esta constante deja el
/// libro mayor mintiendo sobre quién fue el juez, y el test lo caza.
pub const REVM_PINNED_VERSION: &str = "38.0.0";

/// Lo que identifica a una corrida entera.
#[derive(Debug, Clone)]
pub struct RunMetadata {
    pub run_id: String,
    pub seed: u64,
    pub start_index: u64,
    pub cases: u64,
    pub generator: &'static str,
    pub engine_commit: String,
    pub revm_version: &'static str,
    pub seed_corpus_tag: &'static str,
}

impl RunMetadata {
    pub fn new(
        seed: u64,
        start_index: u64,
        cases: u64,
        generator: &'static str,
        seed_corpus_tag: &'static str,
    ) -> Self {
        let engine_commit = engine_commit();
        let run_id = derive_run_id(
            seed,
            start_index,
            cases,
            generator,
            &engine_commit,
            REVM_PINNED_VERSION,
        );
        Self {
            run_id,
            seed,
            start_index,
            cases,
            generator,
            engine_commit,
            revm_version: REVM_PINNED_VERSION,
            seed_corpus_tag,
        }
    }
}

/// El `run_id`: hash de lo que hace que dos corridas sean la misma corrida.
/// Determinista a propósito (ver el doc del módulo).
fn derive_run_id(
    seed: u64,
    start_index: u64,
    cases: u64,
    generator: &str,
    engine_commit: &str,
    revm_version: &str,
) -> String {
    let material =
        format!("{seed:#x}|{start_index}|{cases}|{generator}|{engine_commit}|{revm_version}");
    let digest = keccak256(material.as_bytes());
    let mut out = String::new();
    for byte in digest.iter().take(8) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// El commit del motor, con `-sucio` pegado si el árbol tiene cambios sin
/// commitear. Sin git disponible, `desconocido` — nombrado, nunca vacío: un
/// campo vacío se lee como "no hace falta" y acá hace falta.
fn engine_commit() -> String {
    let Some(head) = git(&["rev-parse", "HEAD"]) else {
        return "desconocido".to_owned();
    };
    match git(&["status", "--porcelain"]) {
        Some(status) if !status.trim().is_empty() => format!("{head}-sucio"),
        Some(_) => head,
        None => format!("{head}-limpieza-desconocida"),
    }
}

fn git(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

/// Una línea del libro. `Value` y no un struct con `Serialize`: el libro es
/// append-only y sus lectores son humanos y `jq`, así que lo que importa es
/// que los campos estén, no que exista un tipo que los espeje.
pub fn record(meta: &RunMetadata, finding: &Value) -> Value {
    json!({
        "run_id": meta.run_id,
        "seed": format!("{:#x}", meta.seed),
        "start_index": meta.start_index,
        "cases": meta.cases,
        "generator": meta.generator,
        "engine_commit": meta.engine_commit,
        "revm_version": meta.revm_version,
        "seed_corpus": meta.seed_corpus_tag,
        "finding": finding,
    })
}

/// Lo que hace falta para volver a producir un hallazgo **en la laptop, sin la
/// flota**.
///
/// La regla: *un hallazgo de la flota tiene que reproducirse desde el libro
/// mayor*. Si no reproduce, el libro no lleva lo
/// suficiente y la flota está produciendo hallazgos que nadie puede investigar.
///
/// El tipo es la mitad barata de esa regla —extraer y exigir los campos— y el
/// test de integración es la cara: reproducir de verdad y comparar el cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproSpec {
    pub seed: u64,
    pub case_index: u64,
    pub generator: String,
    pub engine_commit: String,
    pub revm_version: String,
    pub seed_corpus: String,
    pub cluster: String,
}

impl ReproSpec {
    /// Lee una línea del libro. **Fail-closed campo por campo**: si falta uno,
    /// la línea no describe un experimento que se pueda volver a montar, y
    /// decirlo acá es más barato que descubrirlo con la flota apagada.
    pub fn from_ledger_line(line: &Value) -> Result<Self, String> {
        let text = |key: &str| -> Result<String, String> {
            line.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| missing(key))
        };
        let finding = line.get("finding").ok_or_else(|| missing("finding"))?;
        let raw_seed = text("seed")?;
        let seed = parse_hex_u64(&raw_seed)
            .ok_or_else(|| format!("`seed` = {raw_seed} no es un entero hexadecimal"))?;
        let case_index = finding
            .get("case_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| missing("finding.case_index"))?;
        let cluster = finding
            .get("cluster")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| missing("finding.cluster"))?;
        Ok(Self {
            seed,
            case_index,
            generator: text("generator")?,
            engine_commit: text("engine_commit")?,
            revm_version: text("revm_version")?,
            seed_corpus: text("seed_corpus")?,
            cluster,
        })
    }
}

fn missing(field: &str) -> String {
    format!(
        "la línea del libro mayor no trae `{field}`: sin eso el hallazgo no se puede \
         reproducir en la laptop, y un hallazgo que no se reproduce no es un hallazgo"
    )
}

fn parse_hex_u64(raw: &str) -> Option<u64> {
    let text = raw.trim();
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Agrega líneas al libro. **Append**, nunca truncar: el modo de apertura es
/// parte del contrato, no un detalle.
pub fn append(path: &Path, lines: &[Value]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("no se pudo crear {}: {e}", parent.display()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("no se pudo abrir {}: {e}", path.display()))?;
    for line in lines {
        let text = serde_json::to_string(line).map_err(|e| format!("no serializa: {e}"))?;
        writeln!(file, "{text}").map_err(|e| format!("no se pudo escribir: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La versión de revm del libro mayor **es** la que el workspace pinea.
    /// Con dos literales sueltos, un bump dejaría el libro atribuyéndole el
    /// veredicto a un juez que no corrió.
    #[test]
    fn the_pinned_revm_version_is_the_one_the_workspace_declares() {
        let manifest = include_str!("../../../../Cargo.toml");
        let expected = format!("revm = {{ version = \"={REVM_PINNED_VERSION}\"");
        assert!(
            manifest.contains(&expected),
            "el Cargo.toml del workspace no pinea revm ={REVM_PINNED_VERSION}"
        );
    }

    /// El `run_id` es una función de la corrida, no del reloj.
    #[test]
    fn the_run_id_is_derived_and_not_drawn() {
        let a = derive_run_id(7, 0, 10, "mutación", "abc", "38.0.0");
        let b = derive_run_id(7, 0, 10, "mutación", "abc", "38.0.0");
        assert_eq!(a, b);
        assert_ne!(a, derive_run_id(8, 0, 10, "mutación", "abc", "38.0.0"));
        assert_ne!(a, derive_run_id(7, 0, 10, "mutación", "abd", "38.0.0"));
        assert_ne!(a, derive_run_id(7, 0, 10, "mutación", "abc", "39.0.0"));
    }

    /// **La reproducibilidad de un hallazgo es un contrato del libro, no una
    /// costumbre.** Sin el commit del motor y la versión de revm, la línea
    /// describe un experimento que nadie puede volver a montar. Es la
    /// mutación M7 del §5.
    #[test]
    fn a_ledger_line_carries_everything_a_finding_needs_to_be_reproduced() {
        let meta = RunMetadata::new(0x1234, 0, 64, "mutación de EEST", "v5.4.0");
        let line = record(&meta, &json!({"cluster": "gas_used@op:ADD"}));
        for field in [
            "run_id",
            "seed",
            "generator",
            "engine_commit",
            "revm_version",
            "seed_corpus",
            "finding",
        ] {
            assert!(line.get(field).is_some(), "falta el campo {field}");
        }
        assert!(
            !meta.engine_commit.is_empty(),
            "el commit del motor no puede ir vacío"
        );
        assert_eq!(line["revm_version"], REVM_PINNED_VERSION);
    }

    /// **M3.** La línea del libro trae todo lo que hace falta para reproducir
    /// en la laptop, y **sacar cualquiera de esos campos la rompe**. Un test
    /// que solo mirara el camino feliz se conformaría con la peor
    /// implementación posible: una que devuelve un spec con ceros.
    #[test]
    fn a_ledger_line_that_lost_a_field_stops_being_reproducible() {
        let meta = RunMetadata::new(0x2026_0819, 4_096, 512, "gramática", "v5.4.0");
        let line = record(
            &meta,
            &json!({"cluster": "gas_used@op:ADD", "case_index": 4_231}),
        );
        let Ok(spec) = ReproSpec::from_ledger_line(&line) else {
            panic!("una línea completa tiene que reproducirse");
        };
        assert_eq!(spec.seed, 0x2026_0819);
        assert_eq!(spec.case_index, 4_231);
        assert_eq!(spec.cluster, "gas_used@op:ADD");
        assert_eq!(spec.revm_version, REVM_PINNED_VERSION);

        for field in [
            "seed",
            "generator",
            "engine_commit",
            "revm_version",
            "seed_corpus",
        ] {
            let mut mutilated = line.clone();
            let Some(object) = mutilated.as_object_mut() else {
                panic!("la línea no es un objeto");
            };
            object.remove(field);
            assert!(
                ReproSpec::from_ledger_line(&mutilated).is_err(),
                "sin `{field}` la línea igual se dio por reproducible"
            );
        }
        for field in ["case_index", "cluster"] {
            let mut mutilated = line.clone();
            if let Some(finding) = mutilated.get_mut("finding").and_then(Value::as_object_mut) {
                finding.remove(field);
            }
            assert!(
                ReproSpec::from_ledger_line(&mutilated).is_err(),
                "sin `finding.{field}` la línea igual se dio por reproducible"
            );
        }
    }

    /// Append-only: escribir dos veces suma, nunca reemplaza.
    #[test]
    fn the_ledger_only_grows() {
        let path = std::env::temp_dir().join(format!(
            "repo-b-fuzz-ledger-{}-{:?}.jsonl",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        let meta = RunMetadata::new(1, 0, 1, "gramática", "v5.4.0");
        let Ok(()) = append(&path, &[record(&meta, &json!({"cluster": "a"}))]) else {
            panic!("no se pudo escribir el libro");
        };
        let Ok(()) = append(&path, &[record(&meta, &json!({"cluster": "b"}))]) else {
            panic!("no se pudo escribir el libro");
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            panic!("no se pudo leer el libro");
        };
        let _ = std::fs::remove_file(&path);
        assert_eq!(text.lines().count(), 2, "el libro no es append-only");
        assert!(text.contains("\"cluster\":\"a\""));
        assert!(text.contains("\"cluster\":\"b\""));
    }
}
