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

/// Forks en scope de Repo B (post-Merge). El release está construido con
/// `--until=Prague`, así que lo de más arriba no existe; lo de más abajo
/// (Frontier..London) sí, y se saltea explícitamente.
const IN_SCOPE: [&str; 4] = ["Paris", "Shanghai", "Cancun", "Prague"];

/// Cuántos clusters se listan en el reporte. El reporte tiene que **caber en
/// una pantalla**: el objetivo es decidir qué atacar, no leer 39 025 líneas.
const TOP_CLUSTERS: usize = 25;

fn cache_root() -> PathBuf {
    std::env::var("EEST_CACHE_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.eest-cache"),
        PathBuf::from,
    )
}

/// El tag pineado — debe coincidir con `scripts/fetch-eest.sh`.
const PINNED_TAG: &str = "v5.4.0";
const PINNED_SHA256: &str = "92cf1b47ad12fb27163261fc3c1cea5df72439cab507983d06b56c94f8741909";

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
fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
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
fn index_expected_count(root: &Path) -> Option<u32> {
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

fn short(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

fn head(msg: &str) -> String {
    msg.split(':')
        .next()
        .unwrap_or(msg)
        .trim()
        .chars()
        .take(60)
        .collect()
}
