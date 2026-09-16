//! Modo `--eest`: corre el set de `execution-spec-tests` (EEST) pineado.
//!
//! El artefacto NO se vendorea: lo baja y lo verifica por `sha256`
//! `scripts/fetch-eest.sh` (content-addressing).
//!
//! **Este modo NO exige "todo verde"** — ese es el gate de FASE. Acá el
//! entregable es el **número honesto + el mapa de causas raíz**: sin clustering,
//! 39 025 fallas son 39 025 iteraciones.
//!
//! El exit code implementa el **trinquete**: falla si el
//! harness crashea o si el número de casos pasando **retrocede** contra el
//! baseline versionado. Nunca sale 0 por "no encontré fixtures" (fail-closed).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::fixture::{self, spec_for_fork};
use crate::runner::{self, CaseOutcome, FailKind};

/// Forks en scope de Repo B (post-Merge).
///
/// `tests@v20.0.2` trae de Frontier a Osaka: lo de abajo de Paris se saltea
/// explícitamente, y **Osaka entra** — mainnet corre ahí desde el
/// 2025-12-03 y medir un fork atrás es afirmar "Type-1-exacto" sobre una red
/// que ya no existe.
///
/// **Los forks de transición quedan fuera**, como los `*AtTime15k` anteriores:
/// `PragueToOsakaAtTime15k`, `OsakaToBPO1AtTime15k`, `BPO1ToBPO2AtTime15k`,
/// `BPO2ToBPO3AtTime15k`, `BPO3ToBPO4AtTime15k`. Todos son `blockchain_test` y
/// ninguno tiene fork puro `BPO*` en el índice, así que entrar a medirlos sería
/// abrir el gating por timestamp sin un fork base que lo sostenga.
pub(crate) const IN_SCOPE: [&str; 5] = ["Paris", "Shanghai", "Cancun", "Prague", "Osaka"];

/// Cuántos clusters se listan en el reporte. El reporte tiene que **caber en
/// una pantalla**: el objetivo es decidir qué atacar, no leer 39 025 líneas.
const TOP_CLUSTERS: usize = 25;

pub(crate) fn cache_root() -> PathBuf {
    std::env::var("EEST_CACHE_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.eest-cache"),
        PathBuf::from,
    )
}

/// El tag pineado — debe coincidir con `scripts/fetch-eest.sh`, y lo pinea un
/// test (`pin_tests`). Desde `tests@v20.0.2` el release ya no sale de
/// `ethereum/execution-spec-tests` (archivado) sino de `ethereum/execution-specs`.
pub(crate) const PINNED_TAG: &str = "tests@v20.0.2";
pub(crate) const PINNED_SHA256: &str =
    "1280540950a4c3470a421416b6f35458a9b635827265c29e5aef1ae839ae1788";

#[derive(Debug, Default)]
pub struct Cluster {
    pub count: u32,
    /// Un caso representativo, para reproducir el cluster con un comando.
    pub example_case: String,
    pub example_message: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub passing: u32,
    pub failing: u32,
    /// Casos con fork fuera de scope (pre-Merge): saltados a propósito.
    pub out_of_scope: u32,
    pub files_seen: u32,
    /// Archivos que no se pudieron leer/parsear. **No son skips**: cuentan
    /// como falla de categoría `parse`.
    pub files_unparsed: u32,
    pub clusters: BTreeMap<(FailKind, String), Cluster>,
}

impl Report {
    fn record(&mut self, sig: (FailKind, String), case: &str, message: &str) {
        let entry = self.clusters.entry(sig).or_default();
        entry.count = entry.count.saturating_add(1);
        if entry.example_case.is_empty() {
            entry.example_case = case.to_owned();
            entry.example_message = message.chars().take(240).collect();
        }
    }

    pub fn in_scope_total(&self) -> u32 {
        self.passing.saturating_add(self.failing)
    }
}

/// Recorre `dir` juntando los `.json` (recursivo, orden determinista).
pub(crate) fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_json(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

/// Cuenta, desde `.meta/index.json`, los `state_test` en scope — el
/// **cross-check independiente** del número que produce la corrida. Que dos
/// fuentes distintas den el mismo total es evidencia; que difieran es un
/// hallazgo (no confiar en una sola señal).
pub(crate) fn index_expected_count(root: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(root.join("fixtures/.meta/index.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let cases = value.get("test_cases")?.as_array()?;
    let count = cases
        .iter()
        .filter(|c| {
            c.get("format").and_then(serde_json::Value::as_str) == Some("state_test")
                && c.get("fork")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|f| IN_SCOPE.contains(&f))
        })
        .count();
    u32::try_from(count).ok()
}

/// Corre el set completo. `Err` = el harness no pudo correr (fail-closed).
pub fn run() -> Result<Report, String> {
    let root = cache_root().join(PINNED_TAG);
    let state_tests = root.join("fixtures/state_tests");
    if !state_tests.is_dir() {
        return Err(format!(
            "no encuentro {} — corré `bash scripts/fetch-eest.sh` primero",
            state_tests.display()
        ));
    }

    let mut files = Vec::new();
    collect_json(&state_tests, &mut files).map_err(|e| format!("recorriendo fixtures: {e}"))?;
    if files.is_empty() {
        return Err("0 fixtures encontrados (fail-closed)".to_owned());
    }

    let mut report = Report::default();
    for path in &files {
        report.files_seen = report.files_seen.saturating_add(1);
        let label = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();

        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) => {
                report.files_unparsed = report.files_unparsed.saturating_add(1);
                report.failing = report.failing.saturating_add(1);
                report.record(
                    (FailKind::Parse, "io".to_owned()),
                    &label,
                    &format!("no se pudo leer: {e}"),
                );
                continue;
            }
        };
        let tests = match fixture::parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => {
                report.files_unparsed = report.files_unparsed.saturating_add(1);
                report.failing = report.failing.saturating_add(1);
                report.record((FailKind::Parse, head(&e)), &label, &e);
                continue;
            }
        };

        for test in &tests {
            for case in &test.posts {
                // Filtro por el CAMPO fork del caso, NUNCA por el path: un
                // test bajo `tests/osaka/` puede estar parametrizado a
                // Cancun/Prague.
                if spec_for_fork(&case.fork).is_none() {
                    report.out_of_scope = report.out_of_scope.saturating_add(1);
                    continue;
                }
                let case_label = format!("{label}::{} [{}]", short(&test.name), case.fork);
                match runner::run_case(test, case) {
                    CaseOutcome::Pass => report.passing = report.passing.saturating_add(1),
                    CaseOutcome::SkippedFork(_) => {
                        report.out_of_scope = report.out_of_scope.saturating_add(1);
                    }
                    CaseOutcome::Fail(failure) => {
                        report.failing = report.failing.saturating_add(1);
                        let (kind, detail) = failure.signature();
                        report.record((kind, detail.to_owned()), &case_label, &failure.message);
                    }
                }
            }
        }
    }

    // Cross-check independiente contra el índice del release.
    if let Some(expected) = index_expected_count(&root) {
        let actual = report.in_scope_total();
        if expected != actual {
            eprintln!(
                "[AVISO] el índice declara {expected} `state_test` en scope y la corrida vio \
                 {actual}. Diferencia = {}. No es un fallo del gate, pero ES un hallazgo: \
                 investigar antes de confiar en el número.",
                i64::from(expected) - i64::from(actual)
            );
        } else {
            eprintln!("[cross-check] índice y corrida coinciden: {expected} casos en scope.");
        }
    }

    Ok(report)
}

pub fn print_report(report: &Report) {
    eprintln!();
    eprintln!("== EEST {PINNED_TAG} (sha256 {}…) ==", &PINNED_SHA256[..16]);
    eprintln!(
        "archivos: {} ({} no parseables) | casos en scope: {}",
        report.files_seen,
        report.files_unparsed,
        report.in_scope_total()
    );
    eprintln!(
        "PASS {} | FAIL {} | fuera de scope (pre-Merge) {}",
        report.passing, report.failing, report.out_of_scope
    );

    if report.clusters.is_empty() {
        return;
    }

    // Orden determinista: por conteo desc, después por firma.
    let mut clusters: Vec<_> = report.clusters.iter().collect();
    clusters.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));

    eprintln!();
    eprintln!(
        "== causas raíz: {} clusters (top {}) ==",
        clusters.len(),
        TOP_CLUSTERS.min(clusters.len())
    );
    for ((kind, detail), cluster) in clusters.iter().take(TOP_CLUSTERS) {
        eprintln!(
            "{:>7}  {:<16} {}",
            cluster.count,
            kind.as_str(),
            if detail.is_empty() { "—" } else { detail }
        );
        eprintln!("         ej: {}", cluster.example_case);
        eprintln!("         └─ {}", cluster.example_message);
    }
    if clusters.len() > TOP_CLUSTERS {
        let rest: u32 = clusters
            .iter()
            .skip(TOP_CLUSTERS)
            .map(|(_, c)| c.count)
            .sum();
        eprintln!(
            "  … y {} clusters más ({} casos).",
            clusters.len() - TOP_CLUSTERS,
            rest
        );
    }
}

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eest-baseline.json")
}

/// El trinquete: el piso nunca baja.
///
/// - Sin baseline: se **establece** y se avisa que hay que commitearlo. No es
///   "subir el baseline", es fijarlo por primera vez.
/// - Con baseline: retroceder es **falla dura**. Mejorar NO actualiza el
///   archivo solo — subirlo es un acto explícito y commiteado,
///   porque si no, una regresión posterior se mediría contra un piso que se
///   movió sin que nadie lo revisara.
pub fn check_ratchet(report: &Report) -> Result<(), String> {
    let path = baseline_path();
    let current = report.passing;

    let previous = match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| v.get("passing").and_then(serde_json::Value::as_u64))
            .and_then(|n| u32::try_from(n).ok()),
        Err(_) => None,
    };

    let Some(previous) = previous else {
        let body = serde_json::json!({
            "_comment": "Trinquete: el piso de casos EEST pasando. \
                         Subirlo es un acto EXPLÍCITO y commiteado.",
            "tag": PINNED_TAG,
            "sha256": PINNED_SHA256,
            "in_scope": report.in_scope_total(),
            "passing": current,
        });
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&body).unwrap_or_default()
        );
        std::fs::write(&path, rendered)
            .map_err(|e| format!("no pude escribir el baseline {}: {e}", path.display()))?;
        eprintln!();
        eprintln!(
            "[baseline] establecido en {current} casos pasando → {}",
            path.display()
        );
        eprintln!("[baseline] COMMITEALO: a partir de acá, retroceder rompe el gate.");
        return Ok(());
    };

    eprintln!();
    if current < previous {
        return Err(format!(
            "REGRESIÓN: {current} casos pasando, el baseline es {previous} (−{}). \
             El trinquete no permite retroceder.",
            previous - current
        ));
    }
    if current > previous {
        eprintln!(
            "[baseline] {current} pasando vs baseline {previous} (+{}). \
             Subí el baseline en un commit explícito.",
            current - previous
        );
    } else {
        eprintln!("[baseline] {current} pasando, sin cambio.");
    }
    Ok(())
}

pub(crate) fn short(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

pub(crate) fn head(msg: &str) -> String {
    msg.split(':')
        .next()
        .unwrap_or(msg)
        .trim()
        .chars()
        .take(60)
        .collect()
}

/// El release se pinea en **cinco** lugares: el script que lo baja y cuatro
/// constantes de Rust. Cuatro de ellos son inertes —nadie verifica nada con
/// ellos, solo arman un path— así que un pin desactualizado no rompe nada:
/// simplemente hace que un eje mida un corpus y el otro mida otro, o que el
/// harness busque un directorio que el script nunca creó. Estos tests hacen
/// del acuerdo una propiedad chequeada y no una convención recordada.
#[cfg(test)]
mod pin_tests {
    use super::PINNED_SHA256;
    use super::PINNED_TAG;

    /// Extrae `NOMBRE="valor"` de un script de shell, exigiendo la asignación
    /// al principio de la línea (así `TAG_URL=` no se confunde con `TAG=`).
    fn shell_var(script: &str, name: &str) -> Option<String> {
        let prefix = format!("{name}=\"");
        script.lines().find_map(|line| {
            let rest = line.strip_prefix(&prefix)?;
            rest.strip_suffix('"').map(str::to_owned)
        })
    }

    fn fetch_script() -> String {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/fetch-eest.sh");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("no pude leer {}: {e}", path.display()))
    }

    #[test]
    fn the_script_and_the_code_pin_the_same_release() {
        let script = fetch_script();
        assert_eq!(
            shell_var(&script, "TAG").as_deref(),
            Some(PINNED_TAG),
            "`TAG` de scripts/fetch-eest.sh y `PINNED_TAG` de eest.rs discrepan"
        );
        assert_eq!(
            shell_var(&script, "SHA256").as_deref(),
            Some(PINNED_SHA256),
            "`SHA256` de scripts/fetch-eest.sh y `PINNED_SHA256` de eest.rs discrepan"
        );
    }

    /// El `@` del tag no es representable tal cual en una URL de GitHub: va
    /// percent-encodeado. Que las dos formas nombren el mismo tag es lo que
    /// impide bajar un release y buscarlo en el directorio de otro.
    #[test]
    fn the_url_form_of_the_tag_is_the_percent_encoded_tag() {
        let script = fetch_script();
        let tag_url = shell_var(&script, "TAG_URL").unwrap_or_default();
        assert_eq!(
            tag_url.replace("%40", "@"),
            PINNED_TAG,
            "`TAG_URL` no es `TAG` percent-encodeado"
        );
    }

    /// Los **baselines** declaran contra qué release se midieron, y ese campo
    /// no puede quedar viejo.
    ///
    /// Un trinquete es un número contra un corpus: `39 025 pasando` no quiere
    /// decir nada sin decir *de cuántos y de cuáles*. Si el `tag` del baseline
    /// se queda en el release anterior mientras el código consume otro, el piso
    /// se sigue comparando —sale verde— pero está midiendo un corpus que ya no
    /// existe. Sin este test, rebajar un baseline a mano es un acto sin
    /// testigos.
    #[test]
    fn every_baseline_declares_the_release_it_was_measured_against() {
        for file in [
            "eest-baseline.json",
            "eest-blockchain-baseline.json",
            "witness-eest-baseline.json",
        ] {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("no pude leer {}: {e}", path.display()));
            let value: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{file} no es JSON válido: {e}"));
            let field = |k: &str| {
                value
                    .get(k)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            assert_eq!(
                field("tag").as_deref(),
                Some(PINNED_TAG),
                "{file} declara otro `tag` que el release pineado"
            );
            assert_eq!(
                field("sha256").as_deref(),
                Some(PINNED_SHA256),
                "{file} declara otro `sha256` que el release pineado"
            );
            assert!(
                field("_comment").is_some_and(|c| !c.trim().is_empty()),
                "{file} sin `_comment`: un piso sin motivo escrito no se puede auditar"
            );
        }
    }

    /// Los otros tres pines de Rust apuntan al mismo release.
    #[test]
    fn every_rust_pin_names_the_same_release() {
        assert_eq!(
            crate::blockchain::eest::PINNED_TAG,
            PINNED_TAG,
            "el eje `blockchain_test` pinea otro release que el eje `state_test`"
        );
        assert_eq!(
            crate::fuzz::seeds::PINNED_TAG,
            PINNED_TAG,
            "el corpus semilla del fuzzer pinea otro release que el gate"
        );
    }
}
