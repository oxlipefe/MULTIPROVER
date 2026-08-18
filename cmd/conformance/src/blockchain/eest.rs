//! Modo `--eest-blockchain`: el gemelo del `--eest` de `state_test`, para el
//! otro eje del gate de Fase 2.
//!
//! Mismo contrato que su gemelo: **no exige "todo verde"** (eso es el gate de
//! FASE), el entregable es el número honesto más el mapa de causas raíz, y el
//! exit code implementa el **trinquete** contra un baseline propio. Sin
//! clustering desde la primera corrida, 42 017 fallas son 42 017 iteraciones.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::driver::{self, CaseOutcome, FailKind};
use super::fixture;

/// El scope acumulado del eje. 2.9c-1/2.9c-2 cerraron Paris+Shanghai, 2.9c-3
/// sumó Cancun y 2.9c-4 suma **Prague** (EIP-2935 + EIP-7685). Con Prague el
/// eje queda COMPLETO: no hay fork posterior en el release pineado.
const IN_SCOPE: [&str; 5] = ["Paris", "Merge", "Shanghai", "Cancun", "Prague"];

const TOP_CLUSTERS: usize = 25;

/// El tag pineado — el mismo release que consume `--eest`.
const PINNED_TAG: &str = "v5.4.0";

fn cache_root() -> PathBuf {
    std::env::var("EEST_CACHE_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.eest-cache"),
        PathBuf::from,
    )
}

#[derive(Debug, Default)]
pub struct Cluster {
    pub count: u32,
    pub example_case: String,
    pub example_message: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub passing: u32,
    pub failing: u32,
    /// Casos con `network` fuera del scope de este sub-slice.
    pub out_of_scope: u32,
    pub files_seen: u32,
    pub files_unparsed: u32,
    pub clusters: BTreeMap<(FailKind, String), Cluster>,
    /// Cuántos bloques inválidos se rechazaron, por clase declarada del
    /// fixture y por la razón real del rechazo. El gate **no** exige que
    /// calcen: atar el string de EEST a un error interno sería acoplamiento a
    /// la nomenclatura del generador, no consenso. Se registra porque es lo
    /// único capaz de delatar un rechazo producido por la razón equivocada.
    pub rejected: BTreeMap<(String, FailKind), u32>,
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

/// Cuenta, desde `.meta/index.json`, los `blockchain_test` del scope — el
/// cross-check independiente del número de la corrida. Que dos fuentes
/// distintas coincidan es evidencia; que difieran es un hallazgo (en 2.9a esa
/// misma comparación destapó 6 622 casos invisibles).
fn index_expected_count(root: &Path) -> Option<u32> {
    let raw = std::fs::read_to_string(root.join("fixtures/.meta/index.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let cases = value.get("test_cases")?.as_array()?;
    let count = cases
        .iter()
        .filter(|c| {
            c.get("format").and_then(serde_json::Value::as_str) == Some("blockchain_test")
                && c.get("fork")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|f| IN_SCOPE.contains(&f))
        })
        .count();
    u32::try_from(count).ok()
}

pub fn run() -> Result<Report, String> {
    let root = cache_root().join(PINNED_TAG);
    let blockchain_tests = root.join("fixtures/blockchain_tests");
    if !blockchain_tests.is_dir() {
        return Err(format!(
            "no encuentro {} — corré `bash scripts/fetch-eest.sh` primero",
            blockchain_tests.display()
        ));
    }

    let mut files = Vec::new();
    collect_json(&blockchain_tests, &mut files)
        .map_err(|e| format!("recorriendo fixtures: {e}"))?;
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
            // Filtro por el CAMPO `network`, NUNCA por el path.
            if !IN_SCOPE.contains(&test.network.as_str()) {
                report.out_of_scope = report.out_of_scope.saturating_add(1);
                continue;
            }
            let case_label = format!("{label}::{} [{}]", short(&test.name), test.network);
            match driver::run_case(test) {
                CaseOutcome::Pass(rejected) => {
                    report.passing = report.passing.saturating_add(1);
                    for block in rejected {
                        let entry = report
                            .rejected
                            .entry((block.expectation, block.reason))
                            .or_default();
                        *entry = entry.saturating_add(1);
                    }
                }
                CaseOutcome::Fail(failure) => {
                    report.failing = report.failing.saturating_add(1);
                    let (kind, detail) = failure.signature();
                    report.record((kind, detail.to_owned()), &case_label, &failure.message);
                }
            }
        }
    }

    if let Some(expected) = index_expected_count(&root) {
        let actual = report.in_scope_total();
        if expected == actual {
            eprintln!("[cross-check] índice y corrida coinciden: {expected} casos en scope.");
        } else {
            eprintln!(
                "[AVISO] el índice declara {expected} `blockchain_test` en scope y la corrida vio \
                 {actual}. Diferencia = {}. No es un fallo del gate, pero ES un hallazgo.",
                i64::from(expected) - i64::from(actual)
            );
        }
    }

    Ok(report)
}

pub fn print_report(report: &Report) {
    eprintln!();
    eprintln!("== EEST {PINNED_TAG} — blockchain_test (Paris..Prague, 2.9c-4) ==");
    eprintln!(
        "archivos: {} ({} no parseables) | casos en scope: {}",
        report.files_seen,
        report.files_unparsed,
        report.in_scope_total()
    );
    eprintln!(
        "PASS {} | FAIL {} | fuera del scope de 2.9c-4 {}",
        report.passing, report.failing, report.out_of_scope
    );

    if !report.rejected.is_empty() {
        let total: u32 = report.rejected.values().copied().sum();
        eprintln!();
        eprintln!("== bloques inválidos rechazados: {total} ==");
        let mut rows: Vec<_> = report.rejected.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for ((expectation, reason), count) in rows {
            eprintln!("{count:>7}  {expectation}  ⇒  {}", reason.as_str());
        }
    }

    if report.clusters.is_empty() {
        return;
    }

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
            "{:>7}  {:<18} {}",
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eest-blockchain-baseline.json")
}

/// El trinquete del eje `blockchain_test`. Baseline PROPIO: mezclarlo con el de
/// `state_test` dejaría que una mejora de un eje tape una regresión del otro.
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
            "_comment": "Trinquete del eje blockchain_test (scope 2.9c-4: Paris..Prague). \
                         Subirlo es un acto EXPLÍCITO y commiteado.",
            "tag": PINNED_TAG,
            "scope": "Paris..Prague",
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

/// El scope de este sub-slice y el del runner de `state_test` tienen que
/// coincidir en lo que consideran un fork conocido: si `spec_for_fork` dejara
/// de resolver uno de los tres, el filtro de arriba mandaría a ejecutar un caso
/// que el motor no sabe correr.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::spec_for_fork;

    #[test]
    fn every_fork_in_scope_resolves_to_a_spec() {
        for fork in IN_SCOPE {
            assert!(
                spec_for_fork(fork).is_some(),
                "{fork} está en scope y `spec_for_fork` no lo resuelve"
            );
        }
    }
}
