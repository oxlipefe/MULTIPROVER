//! Modo `--witness-eest`: el eje `state_test` de EEST **por el witness**.
//!
//! No hay que construir un corpus para juzgar el camino stateless: hay que
//! **re-apuntar** el que ya está en verde. Cada uno de los 39 025 casos se graba, se le arma el witness
//! de lo que tocó, y se vuelve a ejecutar **solo desde él**, verificando cada
//! lectura contra el pre-state root.
//!
//! Tres diferencias con `--witness` (el mismo camino sobre el subset
//! vendoreado), y las tres son consecuencia de la escala:
//!
//! 1. **El residuo es un mapa, no una lista.** Un `eprintln` por falla
//!    funciona con 327 casos hechos a mano; con 39 025 serían 39 025 líneas
//!    que nadie lee. Acá se clusteriza por firma.
//! 2. **Los diferidos se declaran por CONTEO trinquetado**, no por nombre.
//!    Siguen siendo un resultado de primera clase, pero una lista de nombres
//!    no escala. El trinquete es **bidireccional**: que el
//!    conteo suba rompe el gate igual que si bajara el de ejecutados, porque
//!    una deuda que puede crecer sin que nadie la firme no está declarada.
//! 3. **El peso se mide con su distribución, no con un promedio.** Un promedio
//!    no ve la cola, y la cola es lo que la Fase 4 va a pagar.
//!
//! El camino en sí NO se reimplementa: es `record::witness_outcome`, el mismo
//! que corre el gate del subset. Dos implementaciones del mismo camino pueden
//! discrepar, y entonces ninguna de las dos prueba nada.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::eest::{
    PINNED_SHA256, PINNED_TAG, cache_root, collect_json, head, index_expected_count, short,
};
use crate::fixture::{self, spec_for_fork};
use crate::record::{WitnessOutcome, WitnessRun, witness_outcome};

/// Cuántos clusters se listan. El reporte tiene que **caber en una pantalla**.
const TOP_CLUSTERS: usize = 25;

/// Las categorías de falla del camino de witness. Separadas porque responden
/// preguntas distintas: la primera dice que el grabador no es transparente (y
/// entonces nada de lo que siga mide el camino real), la segunda que el log ya
/// era insuficiente (bug del grabador) y la tercera que el log alcanzaba y el
/// witness no (bug del witness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailKind {
    NotTransparent,
    LogInsufficient,
    WitnessMismatch,
    /// El caso ejecutó desde el witness, pero el post-state root recomputado
    /// solo desde él no coincide. Categoría propia: sin ella, la regla nueva
    /// queda tapada por las viejas.
    PostRoot,
    /// El input del guest no sobrevivió el viaje por bytes.
    Codec,
    Parse,
}

impl FailKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotTransparent => "no-transparente",
            Self::LogInsufficient => "log-insuficiente",
            Self::WitnessMismatch => "witness-mismatch",
            Self::PostRoot => "post-root",
            Self::Codec => "codec",
            Self::Parse => "parse",
        }
    }
}

#[derive(Debug, Default)]
pub struct Cluster {
    pub count: u32,
    pub example_case: String,
    pub example_message: String,
}

#[derive(Debug, Default)]
pub struct Report {
    /// Casos que ejecutaron **solo desde el witness** reproduciendo el
    /// veredicto.
    pub executed: u32,
    /// De esos, los que además **corrieron la tx**. Un caso cuya tx se rechaza
    /// antes de tocar estado pasa trivialmente, y contarlo junto a los otros
    /// inflaría el número sin evidencia detrás.
    pub executed_tx: u32,
    /// De los ejecutados, en cuántos el post-root recomputado desde el witness
    /// coincidió. Es la mitad del DoD que el harness venía contestando.
    pub root_ok: u32,
    /// Casos cuyo input pasó por bytes y produjo lo mismo.
    pub codec_ok: u32,
    /// Casos que pidieron una pieza que el witness todavía no lleva. Deuda con
    /// razón y conteo, no casos restados del denominador.
    pub deferred: u32,
    pub failing: u32,
    pub out_of_scope: u32,
    pub files_seen: u32,
    pub files_unparsed: u32,
    pub clusters: BTreeMap<(FailKind, String), Cluster>,
    /// Bytes de witness por caso ejecutado. Se guardan **todos** porque la
    /// distribución es el entregable: un promedio no ve la cola.
    pub weights: Vec<u64>,
    pub nodes_total: u64,
    /// El caso más pesado, con nombre. Sin nombre, un p99 no se puede ir a ver.
    pub heaviest: (u64, String),
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

    fn tally(&mut self, run: &WitnessRun, case_label: &str) {
        self.executed = self.executed.saturating_add(1);
        if run.executed_tx {
            self.executed_tx = self.executed_tx.saturating_add(1);
        }
        if run.root.is_ok() {
            self.root_ok = self.root_ok.saturating_add(1);
        }
        if run.codec.is_ok() {
            self.codec_ok = self.codec_ok.saturating_add(1);
        }
        self.weights.push(run.bytes);
        self.nodes_total = self.nodes_total.saturating_add(run.nodes);
        if run.bytes > self.heaviest.0 {
            self.heaviest = (run.bytes, case_label.to_owned());
        }
    }

    /// El denominador: todo caso en scope cae en exactamente una de las tres.
    pub fn in_scope_total(&self) -> u32 {
        self.executed
            .saturating_add(self.deferred)
            .saturating_add(self.failing)
    }
}

/// Corre el eje entero. `Err` = el harness no pudo correr (fail-closed).
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
                // Filtro por el CAMPO fork, NUNCA por el path: un test bajo
                // `tests/osaka/` puede estar parametrizado a Cancun/Prague.
                if spec_for_fork(&case.fork).is_none() {
                    report.out_of_scope = report.out_of_scope.saturating_add(1);
                    continue;
                }
                let case_label = format!("{label}::{} [{}]", short(&test.name), case.fork);
                match witness_outcome(test, case) {
                    // Un caso que ejecuta desde el witness pero no puede
                    // cerrar el root NO es una falla: es la deuda declarada de
                    // §post-root, con su conteo trinquetado. Se clusteriza para
                    // que se vea la causa, y no suma a `failing`.
                    WitnessOutcome::Executed(run) => {
                        if let Err(e) = &run.root {
                            report.record((FailKind::PostRoot, head(e)), &case_label, e);
                        }
                        if let Err(e) = &run.codec {
                            report.record((FailKind::Codec, head(e)), &case_label, e);
                        }
                        report.tally(&run, &case_label);
                    }
                    WitnessOutcome::NeedsBlockHash => {
                        report.deferred = report.deferred.saturating_add(1);
                    }
                    // Un caso en scope que el camino declara fuera de scope no
                    // se saltea en silencio: es una falla con cluster propio.
                    // Saltearlo sería mover el denominador sin que nadie lo vea.
                    WitnessOutcome::OutOfScope(e) => {
                        report.failing = report.failing.saturating_add(1);
                        report.record((FailKind::Parse, head(&e)), &case_label, &e);
                    }
                    WitnessOutcome::NotTransparent { base, wrapped } => {
                        report.failing = report.failing.saturating_add(1);
                        let msg = format!("sin envolver: {base} | envuelto: {wrapped}");
                        report.record(
                            (FailKind::NotTransparent, head(&wrapped)),
                            &case_label,
                            &msg,
                        );
                    }
                    WitnessOutcome::Mismatch {
                        base,
                        witness,
                        log_sufficient,
                    } => {
                        report.failing = report.failing.saturating_add(1);
                        let kind = if log_sufficient {
                            FailKind::WitnessMismatch
                        } else {
                            FailKind::LogInsufficient
                        };
                        let msg = format!("completo: {base} | witness: {witness}");
                        report.record((kind, head(&witness)), &case_label, &msg);
                    }
                }
            }
        }
    }

    // Cross-check independiente contra el índice del release: que dos fuentes
    // distintas den el mismo total es evidencia; que difieran es un hallazgo.
    if let Some(expected) = index_expected_count(&root) {
        let actual = report.in_scope_total();
        if expected == actual {
            eprintln!("[cross-check] índice y corrida coinciden: {expected} casos en scope.");
        } else {
            eprintln!(
                "[AVISO] el índice declara {expected} `state_test` en scope y la corrida vio \
                 {actual}. Diferencia = {}. Investigar antes de confiar en el número.",
                i64::from(expected) - i64::from(actual)
            );
        }
    }

    Ok(report)
}

/// El percentil `p` (0..=100) de una lista **ya ordenada**, por el método del
/// índice más cercano. Sin floats: la regla dura del guest no aplica al
/// harness, pero un percentil con `f64` no aporta nada y sí una dependencia
/// más de redondeo.
fn percentile(sorted: &[u64], p: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len().saturating_sub(1) * usize::try_from(p).unwrap_or(0)) / 100;
    sorted.get(idx).copied().unwrap_or(0)
}

pub fn print_report(report: &Report) {
    eprintln!();
    eprintln!(
        "== EEST {PINNED_TAG} (sha256 {}…) — el eje `state_test` por el witness ==",
        &PINNED_SHA256[..16]
    );
    eprintln!(
        "archivos: {} ({} no parseables) | casos en scope: {}",
        report.files_seen,
        report.files_unparsed,
        report.in_scope_total()
    );
    eprintln!(
        "DESDE EL WITNESS {} | diferidos {} | FAIL {} | fuera de scope (pre-Merge) {}",
        report.executed, report.deferred, report.failing, report.out_of_scope
    );
    // La deuda se imprime SIEMPRE y con su razón: una deuda que no se lee en
    // cada corrida deja de existir a las dos semanas.
    if report.deferred > 0 {
        eprintln!(
            "  diferido ({}): {}",
            report.deferred, DEFERRED_REASON_BLOCK_HASH
        );
    }
    // La auditoría, en el reporte y no escondida en el total: un caso cuya tx
    // se rechaza antes de tocar estado pasa por el witness trivialmente.
    eprintln!(
        "  de los {} que ejecutan desde el witness, {} corrieron la tx y {} la tuvieron rechazada antes de tocar estado",
        report.executed,
        report.executed_tx,
        report.executed.saturating_sub(report.executed_tx),
    );

    eprintln!(
        "  post-state root recomputado SOLO desde el witness: {} de {}",
        report.root_ok, report.executed,
    );
    let deuda = report.executed.saturating_sub(report.root_ok);
    if deuda > 0 {
        eprintln!("  deuda de post-root ({deuda}): {DEUDA_POST_ROOT}");
    }

    eprintln!(
        "  input del guest por bytes (encode → decode → ejecutar): {} de {}",
        report.codec_ok, report.executed,
    );

    {
        use core::sync::atomic::Ordering;
        eprintln!(
            "    cobertura del codec: access-list {} · blob-hashes {} · authorization-list {} casos | {} bytes de input de promedio",
            crate::record::CON_ACCESS_LIST.load(Ordering::Relaxed),
            crate::record::CON_BLOBS.load(Ordering::Relaxed),
            crate::record::CON_AUTH.load(Ordering::Relaxed),
            crate::record::CODEC_BYTES
                .load(Ordering::Relaxed)
                .checked_div(u64::from(report.executed))
                .unwrap_or(0),
        );
    }

    print_weights(report);

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
            "{:>7}  {:<17} {}",
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

/// El peso del witness con su **distribución**. Un promedio no ve la cola, y
/// la cola es lo que se paga cuando esto se pruebe.
fn print_weights(report: &Report) {
    if report.weights.is_empty() {
        return;
    }
    let mut sorted = report.weights.clone();
    sorted.sort_unstable();
    let total: u64 = sorted.iter().copied().sum();
    let n = u64::try_from(sorted.len()).unwrap_or(1);
    eprintln!();
    eprintln!(
        "== peso del witness ({} casos, {} nodos, {} KiB en total) ==",
        sorted.len(),
        report.nodes_total,
        total / 1024,
    );
    eprintln!(
        "  promedio {} B | p50 {} B | p90 {} B | p99 {} B | máx {} B",
        total / n,
        percentile(&sorted, 50),
        percentile(&sorted, 90),
        percentile(&sorted, 99),
        sorted.last().copied().unwrap_or(0),
    );
    eprintln!("  el más pesado: {}", report.heaviest.1);
}

/// La razón del diferido, escrita una sola vez.
///
/// En un `state_test` **no hay headers**: el fixture publica un mapa
/// número→hash sin preimagen, así que no existe un header cuyo
/// `keccak(rlp(·))` dé ese valor. No es deuda de implementación, es el formato
/// del corpus — y la regla está probada en el otro eje, donde 46 052 bloques
/// se reproducen desde su witness con la cadena contigua de headers.
pub const DEFERRED_REASON_BLOCK_HASH: &str = "BLOCKHASH necesita la cadena contigua de headers, y un `state_test` no tiene headers \
     (el fixture inventa el mapa número→hash). Lo prueba el eje de bloques.";

/// El trinquete del post-root: piso, y nunca retrocede.
fn compare_root(actual: u32, previo: u32) -> Result<(), String> {
    if actual < previo {
        return Err(format!(
            "REGRESIÓN en el post-state root: {actual} casos lo cierran desde el witness, el \
             baseline es {previo} (−{}).",
            previo.saturating_sub(actual)
        ));
    }
    Ok(())
}

/// La razón de la deuda del post-root, escrita una sola vez.
///
/// El witness alcanza para **leer** y no siempre para **escribir**, y el
/// recómputo falla **cerrado** en vez de inventar un nodo.
///
/// De las dos causas conocidas, una está resuelta y la otra no. El **colapso**
/// —un branch que al borrar queda con un solo hijo y hay que fundir con el
/// hermano— se cierra pidiendo los hermanos de las claves borradas. Lo que
/// queda **no pasa por ahí**, y su causa está medida pero no explicada.
pub const DEUDA_POST_ROOT: &str = "el colapso de un branch al borrar necesita el hermano intacto, que el witness de los \
     caminos tocados no lleva";

/// La comparación del trinquete, pura y sin IO — para que la regla se pueda
/// probar sin tocar el baseline del repo.
fn compare(current: (u32, u32), previous: (u32, u32)) -> Result<(), String> {
    let ((executed, deferred), (prev_executed, prev_deferred)) = (current, previous);
    if executed < prev_executed {
        return Err(format!(
            "REGRESIÓN: {executed} ejecutan desde el witness, el baseline es {prev_executed} \
             (−{}). El trinquete no permite retroceder.",
            prev_executed.saturating_sub(executed)
        ));
    }
    if deferred > prev_deferred {
        return Err(format!(
            "DEUDA NUEVA SIN FIRMAR: {deferred} diferidos, el baseline declara {prev_deferred} \
             (+{}). Un diferido nuevo se declara con su razón, no se descubre en una corrida.",
            deferred.saturating_sub(prev_deferred)
        ));
    }
    Ok(())
}

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("witness-eest-baseline.json")
}

/// El trinquete, **bidireccional**.
///
/// - `executed` es un piso: retroceder es falla dura.
/// - `deferred` es un **techo**: que la deuda crezca es falla dura también. Un
///   diferido nuevo hay que firmarlo, igual que en el subset vendoreado hay que
///   escribirle el nombre. Sin esto, "N ejecutan" taparía al próximo caso que
///   deje de ejecutar por un motivo nuevo.
/// - Mejorar NO actualiza el archivo solo: subirlo es un acto explícito y
///   commiteado, porque si no una regresión posterior se mediría contra un piso
///   que se movió sin que nadie lo revisara.
pub fn check_ratchet(report: &Report) -> Result<(), String> {
    let path = baseline_path();

    let previous = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|v| {
            let get = |k: &str| {
                v.get(k)
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
            };
            Some((get("executed")?, get("deferred")?, get("root_ok")?))
        });

    let Some((prev_executed, prev_deferred, prev_root_ok)) = previous else {
        let body = serde_json::json!({
            "_comment": "Trinquete BIDIRECCIONAL del eje `state_test` por el witness: \
                         `executed` es un piso y `deferred` un techo. Moverlos es un acto \
                         EXPLÍCITO y commiteado.",
            "tag": PINNED_TAG,
            "sha256": PINNED_SHA256,
            "in_scope": report.in_scope_total(),
            "executed": report.executed,
            "deferred": report.deferred,
            "root_ok": report.root_ok,
            "root_deuda": report.executed.saturating_sub(report.root_ok),
            "root_deuda_razon": DEUDA_POST_ROOT,
            "deferred_reason": DEFERRED_REASON_BLOCK_HASH,
        });
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&body).unwrap_or_default()
        );
        std::fs::write(&path, rendered)
            .map_err(|e| format!("no pude escribir el baseline {}: {e}", path.display()))?;
        eprintln!();
        eprintln!(
            "[baseline] establecido en {} ejecutando desde el witness y {} diferidos → {}",
            report.executed,
            report.deferred,
            path.display()
        );
        eprintln!("[baseline] COMMITEALO: a partir de acá, retroceder rompe el gate.");
        return Ok(());
    };

    eprintln!();
    compare(
        (report.executed, report.deferred),
        (prev_executed, prev_deferred),
    )?;
    compare_root(report.root_ok, prev_root_ok)?;
    if report.executed > prev_executed
        || report.deferred < prev_deferred
        || report.root_ok > prev_root_ok
    {
        eprintln!(
            "[baseline] {} ejecutando (baseline {prev_executed}) y {} diferidos \
             (baseline {prev_deferred}). Subí el baseline en un commit explícito.",
            report.executed, report.deferred
        );
    } else {
        eprintln!(
            "[baseline] {} ejecutando desde el witness y {} diferidos, sin cambio.",
            report.executed, report.deferred
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(executed: u32, deferred: u32) -> Report {
        Report {
            executed,
            deferred,
            ..Report::default()
        }
    }

    /// El percentil de una lista de un solo elemento es ese elemento, y el de
    /// una vacía es 0 — no un panic por indexar fuera de rango.
    #[test]
    fn percentiles_have_no_implicit_panic_at_the_edges() {
        assert_eq!(percentile(&[], 99), 0);
        assert_eq!(percentile(&[7], 0), 7);
        assert_eq!(percentile(&[7], 100), 7);
    }

    #[test]
    fn the_percentile_picks_the_nearest_index() {
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 50), 50);
        assert_eq!(percentile(&sorted, 99), 99);
        assert_eq!(percentile(&sorted, 100), 100);
    }

    /// La cola es lo que el promedio no ve: 99 casos de 100 bytes y uno de un
    /// millón dan un promedio de ~10 KB y un p50 de 100.
    #[test]
    fn the_average_hides_the_tail_and_the_percentiles_do_not() {
        let mut weights = vec![100_u64; 99];
        weights.push(1_000_000);
        weights.sort_unstable();
        let total: u64 = weights.iter().sum();
        assert_eq!(percentile(&weights, 50), 100);
        assert!(total / 100 > 10_000);
        assert_eq!(weights.last().copied(), Some(1_000_000));
    }

    /// El denominador es la suma de las tres poblaciones: ningún caso en scope
    /// puede desaparecer del total.
    #[test]
    fn every_in_scope_case_lands_in_exactly_one_population() {
        let mut r = report(10, 2);
        r.failing = 3;
        assert_eq!(r.in_scope_total(), 15);
    }

    /// Un caso cuya tx fue rechazada antes de ejecutar cuenta como ejecutado
    /// desde el witness, pero **no** como "corrió la tx".
    #[test]
    fn a_rejected_tx_counts_as_executed_but_not_as_having_run() {
        let mut r = Report::default();
        r.tally(
            &WitnessRun {
                bytes: 10,
                nodes: 1,
                root: Ok(()),
                codec: Ok(()),
                executed_tx: false,
            },
            "caso",
        );
        assert_eq!(r.executed, 1);
        assert_eq!(r.executed_tx, 0);
    }

    /// El caso más pesado se registra CON NOMBRE: un p99 que no se puede ir a
    /// ver no sirve de nada.
    #[test]
    fn the_heaviest_case_keeps_its_name() {
        let mut r = Report::default();
        for (bytes, name) in [(10_u64, "chico"), (900, "grande"), (20, "mediano")] {
            r.tally(
                &WitnessRun {
                    bytes,
                    nodes: 1,
                    root: Ok(()),
                    codec: Ok(()),
                    executed_tx: true,
                },
                name,
            );
        }
        assert_eq!(r.heaviest, (900, "grande".to_owned()));
    }

    /// Perder un caso que ejecutaba rompe el gate.
    #[test]
    fn the_ratchet_rejects_losing_an_executed_case() {
        let Err(e) = compare((99, 2), (100, 2)) else {
            panic!("perder un caso que ejecutaba tiene que romper el trinquete");
        };
        assert!(e.contains("REGRESIÓN"), "{e}");
        assert!(e.contains("−1"), "{e}");
    }

    /// Y **también** rompe que la deuda crezca: es la mitad que un trinquete de
    /// una sola dirección deja pasar. Sin esto, un caso que deja de ejecutar y
    /// se auto-declara diferido saldría verde.
    #[test]
    fn the_ratchet_rejects_new_unsigned_debt() {
        let Err(e) = compare((100, 3), (100, 2)) else {
            panic!("una deuda nueva sin firmar tiene que romper el trinquete");
        };
        assert!(e.contains("DEUDA NUEVA SIN FIRMAR"), "{e}");
    }

    /// El caso que un trinquete tuerto dejaría pasar: mismo total, un caso que
    /// pasó de ejecutar a diferido.
    #[test]
    fn a_case_moving_from_executed_to_deferred_is_caught() {
        assert!(compare((99, 3), (100, 2)).is_err());
    }

    /// Mejorar no rompe nada: más ejecutados y menos deuda es verde.
    #[test]
    fn improving_in_both_directions_is_green() {
        assert!(compare((101, 1), (100, 2)).is_ok());
        assert!(compare((100, 2), (100, 2)).is_ok());
    }
}
