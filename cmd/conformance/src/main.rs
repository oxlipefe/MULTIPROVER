//! Harness de conformance — el GATE de existencia de Repo B (Fase 2).
//!
//! Ejes del gate:
//!   1. EF `GeneralStateTests` + blockchain tests (set de zeth: ≈32999 + 8338).
//!   2. Diferencial **bit-idéntico vs `revm`** por bloque (feature `diff-revm`).
//!
//! Desde Fase 1 corre el subset de fixtures **vendoreados** (`fixtures/`): el
//! exit code refleja ESTA corrida (una regresión del subset rompe CI) y el
//! reporte deja explícito que el gate global de Fase 2 sigue RED hasta igualar
//! el set completo de zeth.

mod blockchain;
#[cfg(feature = "diff-revm")]
mod diff;
mod eest;
mod fixture;
mod fuzz;
mod oracle;
mod record;
mod runner;
mod trace_diff;
mod witness_build;
mod witness_eest;

use std::path::PathBuf;
use std::process::ExitCode;

use runner::CaseOutcome;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/GeneralStateTests")
}

/// Resuelve un path de fixtures: tal cual (relativo al CWD) o, si no existe,
/// relativo al crate. El gate se corre desde la raíz del repo con
/// `--diff fixtures/diff/storage`, pero los fixtures viven junto al harness.
#[cfg(feature = "diff-revm")]
fn resolve_fixture_path(arg: &str) -> PathBuf {
    let direct = PathBuf::from(arg);
    if direct.exists() {
        return direct;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(arg)
}

/// `--diff <dir>`: modo diferencial vs revm sobre un set de fixtures.
fn diff_target() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--diff" {
            return Some(args.next().unwrap_or_default());
        }
    }
    None
}

fn main() -> ExitCode {
    if std::env::args().skip(1).any(|arg| arg == "--fuzz") {
        return run_fuzz();
    }
    // `--eest-blockchain` se chequea ANTES que `--eest`: son dos flags
    // distintas y una comparación por prefijo las confundiría.
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "--eest-blockchain")
    {
        return run_eest_blockchain();
    }
    if std::env::args().skip(1).any(|arg| arg == "--eest") {
        return run_eest();
    }
    if let Some(target) = diff_target() {
        return run_diff(&target);
    }
    // `--witness-blocks` va antes que `--witness`: son dos flags y una
    // comparación por prefijo las confundiría.
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "--witness-blocks")
    {
        return run_witness_blocks();
    }
    // `--witness-eest` va antes que `--witness`, por el mismo motivo que
    // `--witness-blocks`: son flags distintas y el orden evita que una
    // comparación por prefijo las confunda.
    if std::env::args().skip(1).any(|arg| arg == "--witness-eest") {
        return run_witness_eest();
    }
    // `--witness` va ANTES de `--record-replay`: son dos flags distintas y el
    // orden evita que una comparación por prefijo las confunda.
    if std::env::args().skip(1).any(|arg| arg == "--witness") {
        return run_witness();
    }
    // `--record-replay`: el gate del grabador de accesos.
    if std::env::args().skip(1).any(|arg| arg == "--record-replay") {
        return run_record_replay();
    }
    run_vendored_subset()
}

/// `--witness-blocks`: el eje de bloques, con cada bloque ejecutado **dos
/// veces** — la normal y otra alimentada solo por el witness de lo que la
/// primera tocó, incluida la cadena contigua de headers que prueba sus
/// `BLOCKHASH`. Un bloque que no se reproduce es una falla con categoría propia
/// (`witness`), no un rechazo del protocolo.
fn run_witness_blocks() -> ExitCode {
    use blockchain::driver::{
        ROUNDTRIP_BLOCKS, ROUNDTRIP_BYTES, ROUNDTRIP_CLOSING, ROUNDTRIP_CLOSING_NONEMPTY,
        ROUNDTRIP_SIZES, ROUNDTRIP_SKIP, WITNESS_BLOCKS, WITNESS_BYTES, WITNESS_CHAIN_MAX,
        WITNESS_HEADER_BYTES, WITNESS_HEADERS, WITNESS_ROOTS, WITNESS_ROOTS_TRIVIALES,
        WITNESS_WITH_BLOCKHASH,
    };
    use std::sync::atomic::Ordering;

    eprintln!("== Repo B — el eje de bloques, cada bloque también desde su witness ==");
    let report = match blockchain::eest::run_with(true) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    blockchain::eest::print_report(&report);
    let bloques = WITNESS_BLOCKS.load(Ordering::Relaxed);
    let bytes = WITNESS_BYTES.load(Ordering::Relaxed);
    eprintln!(
        "bloques reproducidos desde su witness: {bloques} | con `BLOCKHASH`: {} | cadena más larga: {} headers | {} bytes de witness de promedio",
        WITNESS_WITH_BLOCKHASH.load(Ordering::Relaxed),
        WITNESS_CHAIN_MAX.load(Ordering::Relaxed),
        bytes.checked_div(bloques).unwrap_or(0),
    );
    let roots = WITNESS_ROOTS.load(Ordering::Relaxed);
    let triviales = WITNESS_ROOTS_TRIVIALES.load(Ordering::Relaxed);
    eprintln!(
        "post-state root recomputado SOLO desde el witness: {roots} bloques ({} sin un solo cambio de estado, que pasan trivialmente)",
        triviales,
    );
    let rt = ROUNDTRIP_BLOCKS.load(Ordering::Relaxed);
    eprintln!(
        "el guest EJECUTÓ desde el input por bytes: {rt} bloques ({} con system calls de cierre, de los cuales {} con output NO vacío; {} salteados) | {} bytes de promedio",
        ROUNDTRIP_CLOSING.load(Ordering::Relaxed),
        ROUNDTRIP_CLOSING_NONEMPTY.load(Ordering::Relaxed),
        ROUNDTRIP_SKIP.load(Ordering::Relaxed),
        ROUNDTRIP_BYTES
            .load(Ordering::Relaxed)
            .checked_div(rt)
            .unwrap_or(0),
    );
    if let Ok(sizes) = ROUNDTRIP_SIZES.lock() {
        let mut sorted = sizes.clone();
        sorted.sort_unstable();
        eprintln!(
            "  distribución del input: p50 {} B | p90 {} B | p99 {} B | máx {} B",
            crate::witness_eest::percentile(&sorted, 50),
            crate::witness_eest::percentile(&sorted, 90),
            crate::witness_eest::percentile(&sorted, 99),
            sorted.last().copied().unwrap_or(0),
        );
    }
    eprintln!(
        "cadena de headers: {} headers en total, {} KiB",
        WITNESS_HEADERS.load(Ordering::Relaxed),
        WITNESS_HEADER_BYTES.load(Ordering::Relaxed) / 1024,
    );
    match blockchain::eest::check_ratchet(&report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--witness-eest`: el eje `state_test` **entero** por el witness. No se
/// construye un corpus para juzgar el camino stateless: se re-apunta el que ya
/// está en verde.
///
/// El exit code exige que **todo caso en scope caiga en una de dos
/// poblaciones** —ejecutó desde el witness, o es deuda declarada— y que el
/// trinquete bidireccional no se mueva sin firma.
fn run_witness_eest() -> ExitCode {
    eprintln!("== Repo B — el eje `state_test` de EEST, cada caso solo desde su witness ==");
    let report = match witness_eest::run() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    witness_eest::print_report(&report);
    if let Err(e) = witness_eest::check_ratchet(&report) {
        eprintln!("[FAIL] {e}");
        return ExitCode::FAILURE;
    }
    if report.failing == 0 {
        eprintln!(
            "[OK] {} casos ejecutan solo desde el witness, {} son deuda declarada, 0 fallan",
            report.executed, report.deferred
        );
        return ExitCode::SUCCESS;
    }
    ExitCode::FAILURE
}

/// `--witness`: cada caso se ejecuta **solo desde el witness** — nodos de trie
/// de lo que se tocó, y cada lectura verificada contra el pre-state root. Es el
/// DoD de la fase, en el subconjunto que ya está en verde.
fn run_witness() -> ExitCode {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    eprintln!("== Repo B — ejecución solo desde el witness ==");
    let report = record::run_sets_witness(&root);
    let kb = report.witness_bytes / 1024;
    let ejecutados = report
        .cases
        .saturating_sub(u32::try_from(report.deferred.len()).unwrap_or(u32::MAX));
    eprintln!(
        "casos={} | desde el witness={} diferidos={} | otro veredicto={} no-transparentes={}",
        report.cases,
        ejecutados,
        report.deferred.len(),
        report.witness_mismatch,
        report.not_transparent,
    );
    eprintln!(
        "witness: {} nodos, {kb} KiB en total, {} bytes de promedio",
        report.witness_nodes,
        report
            .witness_bytes
            .checked_div(u64::from(ejecutados))
            .unwrap_or(0),
    );
    // Los diferidos se imprimen SIEMPRE y con su razón: una deuda que no se lee
    // en cada corrida deja de existir a las dos semanas.
    for (name, razon) in record::DEFERRED {
        eprintln!("  diferido: {name} — {razon}");
    }
    if !report.deferred_matches_declared() {
        eprintln!(
            "[FAIL] los diferidos observados no son los declarados: {:?} vs {:?}",
            report.deferred,
            record::DEFERRED
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
        );
        return ExitCode::FAILURE;
    }
    if report.failed() == 0 {
        eprintln!("[OK] los {ejecutados} casos ejecutan solo desde el witness");
        return ExitCode::SUCCESS;
    }
    ExitCode::FAILURE
}

/// `--record-replay`: graba los accesos de cada caso, lo re-ejecuta contra un
/// `State` que sirve SOLO lo grabado, y le quita ítems de a uno para ver si
/// alguno sobraba. Sale 0 solo si las tres propiedades se cumplen en todos los
/// casos del subconjunto.
fn run_record_replay() -> ExitCode {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    eprintln!("== Repo B — grabador de accesos: transparencia + suficiencia + minimalidad ==");
    let report = record::run_sets(&root, true);
    eprintln!(
        "casos={} items grabados={} | no-transparentes={} insuficientes={} items de más={} (skip {})",
        report.cases,
        report.items,
        report.not_transparent,
        report.insufficient,
        report.superfluous,
        report.skipped,
    );
    // La cobertura se imprime SIEMPRE: un gate verde sobre un subconjunto que
    // no toca un método del seam es un gate que no lo probó, y eso tiene que
    // ser legible sin leer el código.
    eprintln!("-- qué método del seam tocó cada caso --");
    for (metodo, casos) in record::coverage(&root) {
        eprintln!("  {metodo:24} {casos}");
    }
    if report.failed() == 0 {
        eprintln!(
            "[OK] el log es suficiente y mínimo en los {} casos",
            report.cases
        );
        return ExitCode::SUCCESS;
    }
    ExitCode::FAILURE
}

/// `--eest`: el set de execution-spec-tests pineado.
///
/// Sale 0 si el harness corrió el set y **no retrocedió** contra el baseline.
/// NO exige "todo verde": eso es el gate de FASE, no el de esta corrida.
fn run_eest() -> ExitCode {
    eprintln!("== Repo B — execution-spec-tests (state_test, Paris..Prague) ==");
    let report = match eest::run() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    eest::print_report(&report);
    match eest::check_ratchet(&report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--eest-blockchain`: el otro eje del gate de Fase 2, con baseline propio.
///
/// Mismo contrato que `--eest`: sale 0 si el harness corrió el set y no
/// retrocedió contra SU baseline. Los dos baselines son independientes para que
/// una mejora de un eje no tape una regresión del otro.
fn run_eest_blockchain() -> ExitCode {
    eprintln!("== Repo B — execution-spec-tests (blockchain_test, Paris..Prague) ==");
    let report = match blockchain::eest::run() {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    blockchain::eest::print_report(&report);
    match blockchain::eest::check_ratchet(&report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            ExitCode::FAILURE
        }
    }
}

/// Modo diferencial. Sin la feature `diff-revm` no hay oráculo: fail-closed,
/// nunca "pasar" sin comparar contra nada.
#[cfg(feature = "diff-revm")]
fn run_diff(target: &str) -> ExitCode {
    let dir = resolve_fixture_path(target);
    eprintln!("== Repo B — diferencial bit-idéntico vs revm =38.0.0 ==");
    eprintln!("set: {}", dir.display());
    eprintln!();

    let report = diff::run_dir(&dir);
    eprintln!();
    eprintln!(
        "diferencial: {} casos, {} divergencias, {} skip",
        report.cases, report.diverged, report.skipped
    );
    if report.cases == 0 {
        eprintln!("[FAIL] el set no ejecutó ningún caso: un set vacío NO es verde");
        return ExitCode::FAILURE;
    }
    let verdict = if report.diverged == 0 {
        eprintln!("[OK] 0 divergencias vs revm en este set");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    // El veredicto no se publica solo: sin el inventario, "0 divergencias" se
    // lee como una afirmación más fuerte de la que es.
    oracle::print_oracle_inventory();
    verdict
}

/// `--fuzz`: la campaña de fuzzing diferencial.
///
/// Flags: `--seed <hex|dec>`, `--cases N`, `--case N` (índice de arranque),
/// `--out <dir>` (trinquete), `--stop-on-first`, y el generador:
///
/// - por defecto, la **gramática** (`--seed-corpus` la siembra desde
///   `fixtures/diff/`);
/// - `--uniform`: bytes al azar, el contraste de la gramática;
/// - `--mutate`: la **mutación de EEST**;
/// - `--mutate-passthrough` y `--mutate-bytes`: sus dos contrastes;
/// - `--directed`: el **corpus dirigido** (semillas escritas contra una
///   interacción entre EIPs), y `--directed-passthrough` su contraste;
/// - `--seed-scan`: el barrido del corpus semilla SIN mutar, que deriva los
///   clusters ya explicados.
///
/// Y dos flags del triage: `--ledger <archivo>` (el libro mayor append-only) y
/// `--llm <comando>` (la anotación de causa raíz, opt-in y fuera del camino
/// del veredicto).
///
/// **La semilla NO se sortea con la hora del sistema.** Si no se pasa, se usa
/// una constante: el determinismo absoluto vale para el harness igual que para
/// el guest, y una campaña que no se puede repetir no produce
/// hallazgos, produce anécdotas.
#[cfg(feature = "diff-revm")]
fn run_fuzz() -> ExitCode {
    use fuzz::campaign::{CampaignConfig, Generator, RootCauseAnnotator, run};
    use fuzz::report::print_report;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|arg| arg == flag);
    // **El loop de REGRESIÓN** sale primero: es el que corre en el gate de
    // merge y no genera nada, así que no comparte una sola flag con los
    // generadores.
    if has("--regression") {
        return run_regression();
    }
    // El botón de pánico va antes que cualquier otra cosa: si alguien lo tipea,
    // es porque hay algo encendido.
    if has("--fleet-destroy-all") {
        return run_fleet_destroy_all(&args);
    }
    // El orden es de más específico a menos: los tres modos de mutación son
    // excluyentes entre sí y con la gramática.
    let generator = if has("--seed-scan") {
        Generator::SeedScan
    } else if has("--directed-passthrough") {
        Generator::DirectedPassthrough
    } else if has("--directed") {
        Generator::Directed
    } else if has("--mutate-passthrough") {
        Generator::MutatePassthrough
    } else if has("--mutate-bytes") {
        Generator::MutateByteLevel
    } else if has("--mutate") {
        Generator::Mutate
    } else if has("--uniform") {
        Generator::GrammarUniform
    } else {
        Generator::Grammar
    };
    let config = CampaignConfig {
        seed: flag_value(&args, "--seed")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(DEFAULT_FUZZ_SEED),
        start_index: flag_value(&args, "--case")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(0),
        cases: flag_value(&args, "--cases")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(DEFAULT_FUZZ_CASES),
        out_dir: flag_value(&args, "--out").map(PathBuf::from),
        generator,
        seed_corpus: has("--seed-corpus"),
        stop_on_first: has("--stop-on-first"),
        seed_root: flag_value(&args, "--seed-root").map(PathBuf::from),
    };

    if has("--fleet") {
        return run_fleet_campaign(&args, generator);
    }

    eprintln!("== Repo B — fuzzing diferencial vs revm =38.0.0 ==");
    // El anotador de causa raíz es **opt-in y está fuera del camino del
    // veredicto**: sin `--llm`, la campaña produce exactamente el mismo
    // veredicto, los mismos clusters y el mismo exit code. Va como test.
    let mut annotator = flag_value(&args, "--llm").map(|command| CommandAnnotator { command });
    let annotator: Option<&mut dyn RootCauseAnnotator> = match annotator.as_mut() {
        Some(annotator) => Some(annotator),
        None => None,
    };
    // Un corpus que no está NO se degrada a una campaña vacía: sin semillas el
    // generador de mutación no genera nada y reportaría "0 divergencias" con
    // toda tranquilidad, que es el modo vacuo contra el que fail-closed existe.
    let report = match run(&config, annotator) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&config, &report);
    oracle::print_oracle_inventory();

    if let Some(path) = flag_value(&args, "--ledger") {
        let meta = fuzz::ledger::RunMetadata::new(
            config.seed,
            config.start_index,
            config.cases,
            config.generator.label(),
            fuzz::seeds::PINNED_TAG,
        );
        let lines: Vec<serde_json::Value> = report
            .findings
            .iter()
            .map(|finding| fuzz::ledger::record(&meta, &finding.to_ledger_value()))
            .collect();
        match fuzz::ledger::append(&PathBuf::from(&path), &lines) {
            Ok(()) => eprintln!(
                "\nlibro mayor: {} hallazgos agregados a {path} (run_id {})",
                lines.len(),
                meta.run_id
            ),
            // Un libro que no se pudo escribir no puede degradarse a silencio:
            // un hallazgo que no queda registrado no es reproducible.
            Err(e) => {
                eprintln!("[FAIL] no se pudo escribir el libro mayor: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // **Ninguna divergencia se suprime.** Si la suma de las ocurrencias de los
    // clusters no da el total crudo, alguien se guardó hallazgos en el bolsillo
    // y el reporte estaría mintiendo por omisión.
    if !report.clusters_account_for_every_divergence() {
        eprintln!(
            "\n[FAIL] los clusters no dan cuenta de las {} divergencias crudas: \
             hay hallazgos suprimidos",
            report.diverged
        );
        return ExitCode::FAILURE;
    }

    // Un fixture del trinquete que no reproduce es un fallo del harness, no un
    // detalle: sin eso el corpus crece con casos que no prueban nada.
    let liar = report
        .findings
        .iter()
        .any(|finding| finding.fixture_reproduces == Some(false));
    if liar {
        eprintln!("[FAIL] un fixture emitido no vuelve a divergir");
        return ExitCode::FAILURE;
    }
    // **El veredicto es sobre lo NUEVO.** Las divergencias ya explicadas se
    // cuentan y se muestran (arriba), no se suprimen; lo que cambia es esto.
    let new_clusters = report.new_clusters();
    if new_clusters == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!("\n[FAIL] {new_clusters} cluster(s) NUEVO(s): ninguno cae contra el inventario");
        ExitCode::FAILURE
    }
}

/// `--fuzz --regression`: **el loop de regresión**, el que corre en el gate de
/// merge.
///
/// Barre el corpus sembrado con cada divergencia histórica ya cazada —los 21
/// sets diferenciales, el corpus dirigido y el trinquete— y exige **cero
/// clusters NUEVOS**. Las divergencias deliberadas se cuentan, se muestran y se
/// etiquetan: clasificar, nunca excusar.
///
/// Su SLA se **mide**, no se declara: el reporte imprime el tiempo, y si algún
/// día deja de ser segundos hay que decir por qué antes de sacarlo del gate.
#[cfg(feature = "diff-revm")]
fn run_regression() -> ExitCode {
    use fuzz::regression::{load, sweep};

    eprintln!("== Repo B — loop de REGRESIÓN (gate de merge) ==");
    let corpus = match load() {
        Ok(corpus) => corpus,
        Err(e) => {
            eprintln!("[FAIL] {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "corpus sembrado: {} corridas ({} sets diferenciales + corpus dirigido + \
         {} del trinquete)",
        corpus.len(),
        corpus.diff_sets.len(),
        corpus.ratchet_cases
    );
    let report = sweep(&corpus);
    eprintln!(
        "barrido: {} corridas en {:.2} s — {} coinciden, {} con la tx rechazada por los dos",
        report.cases, report.elapsed_secs, report.same, report.both_rejected
    );
    if report.skipped_fork > 0 {
        eprintln!(
            "[FAIL] {} corridas no se corrieron por fork fuera de scope: un caso del \
             corpus de regresión que no se corre no protege nada",
            report.skipped_fork
        );
        return ExitCode::FAILURE;
    }
    if report.known.is_empty() {
        eprintln!(
            "[warn] ninguna divergencia conocida en el barrido: el corpus dejó de \
             ejercitar el camino de clasificación"
        );
    }
    for (source, case, cluster, rule) in &report.known {
        eprintln!("  · [{source}] {case} — [{cluster}] CONOCIDO: {rule}");
    }
    if report.is_green() {
        eprintln!("\nOK — 0 clusters NUEVOS. Cada divergencia cazada una vez sigue cazada.");
        return ExitCode::SUCCESS;
    }
    for (source, case, cluster) in &report.new {
        eprintln!("  · [{source}] {case} — [{cluster}] **NUEVO**");
    }
    eprintln!(
        "\n[FAIL] {} cluster(s) NUEVO(s) en el corpus de regresión: una regla que ya \
         estaba protegida se rompió",
        report.new.len()
    );
    ExitCode::FAILURE
}

/// `--fuzz --fleet`: **el loop de profundidad**.
///
/// Flags propias, y las dos primeras **no tienen default**:
/// `--fleet-budget <USD>`, `--fleet-deadline <segundos>`,
/// `--fleet-shard-cases N`, `--fleet-wall <segundos>` (el techo de reloj que se
/// cobra), `--fleet-plan <ccx…>`, `--fleet-commit <sha>`, y `--fleet-dry-run`
/// para correr la campaña entera contra el proveedor **falso**, sin nube y sin
/// gastar un centavo.
#[cfg(feature = "diff-revm")]
fn run_fleet_campaign(args: &[String], generator: fuzz::campaign::Generator) -> ExitCode {
    use fuzz::budget::usd_to_micros;
    use fuzz::fleet::{FleetConfig, SystemClock, fake, hetzner, print_fleet_report, run_fleet};

    let has = |flag: &str| args.iter().any(|arg| arg == flag);
    let number = |flag: &str| flag_value(args, flag).and_then(|raw| parse_u64(&raw));
    let budget_micros = match flag_value(args, "--fleet-budget").map(|raw| usd_to_micros(&raw)) {
        Some(Ok(micros)) => Some(micros),
        Some(Err(e)) => {
            eprintln!("[FAIL] --fleet-budget: {e}");
            return ExitCode::FAILURE;
        }
        None => None,
    };
    let config = FleetConfig {
        seed: flag_value(args, "--seed")
            .and_then(|raw| parse_u64(&raw))
            .unwrap_or(DEFAULT_FUZZ_SEED),
        generator: generator.label(),
        total_cases: number("--cases").unwrap_or(DEFAULT_FUZZ_CASES),
        shard_cases: number("--fleet-shard-cases").unwrap_or(DEFAULT_SHARD_CASES),
        budget_micros,
        harvest_deadline_secs: number("--fleet-deadline"),
        seed_corpus_tag: fuzz::seeds::PINNED_TAG,
        ledger: flag_value(args, "--ledger").map(PathBuf::from),
    };
    let wall_secs = number("--fleet-wall").unwrap_or(DEFAULT_RUNNER_WALL_SECS);

    eprintln!("== Repo B — flota efímera (loop de PROFUNDIDAD) ==");
    let clock = SystemClock::default();
    let report = if has("--fleet-dry-run") {
        eprintln!("proveedor: FALSO (in-memory) — sin nube, sin credenciales, sin costo");
        // Los ensayos de falla se piden por flag: colgar un runner o hacerlo
        // fallar en la nube cuesta plata y paciencia; acá es gratis y es la
        // forma de practicar el deadline y la campaña parcial antes de encender
        // nada.
        let mut provider = fake::FakeProvider::synthetic()
            .used_percent(number("--fleet-dry-run-used").unwrap_or(50));
        if let Some(start) = number("--fleet-dry-run-hang") {
            provider = provider.hang_shard(start);
        }
        if let Some(start) = number("--fleet-dry-run-fail") {
            provider = provider.fail_shard(start);
        }
        if let Some(alert) = flag_value(args, "--fleet-dry-run-alert") {
            provider = provider.with_alert(&alert);
        }
        run_fleet(
            &config,
            &mut provider,
            &fake::FakeClock::default(),
            wall_secs,
        )
    } else {
        let plan =
            flag_value(args, "--fleet-plan").unwrap_or_else(|| hetzner::DEFAULT_PLAN.to_owned());
        let commit = flag_value(args, "--fleet-commit").unwrap_or_else(|| "HEAD".to_owned());
        let repo = flag_value(args, "--fleet-repo")
            .unwrap_or_else(|| "https://github.com/oxlipefe/MULTIPROVER".to_owned());
        let vcpus = hetzner::plan_by_name(&plan).map_or(0, |plan| plan.vcpus);
        eprintln!(
            "proveedor: Hetzner Cloud, plan {plan} ({vcpus} vCPU DEDICADAS), commit {commit}"
        );
        let mut provider =
            match hetzner::HetznerFleet::new(&plan, "ubuntu-24.04", "nbg1", &repo, &commit) {
                Ok(provider) => provider,
                Err(e) => {
                    eprintln!("[FAIL] {e}");
                    return ExitCode::FAILURE;
                }
            };
        run_fleet(&config, &mut provider, &clock, wall_secs)
    };
    match report {
        Ok(report) => {
            print_fleet_report(&report);
            // Una campaña PARCIAL es un resultado válido; lo que no lo es es
            // haberse pasado del tope o haber dejado algo encendido.
            if report.is_sound() {
                ExitCode::SUCCESS
            } else {
                eprintln!("[FAIL] la campaña se pasó del tope o dejó runners vivos");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("[FAIL] {e}");
            ExitCode::FAILURE
        }
    }
}

/// `--fuzz --fleet-destroy-all`: el botón de pánico, sin pensar en nada más.
#[cfg(feature = "diff-revm")]
fn run_fleet_destroy_all(args: &[String]) -> ExitCode {
    use fuzz::fleet::{FleetProvider, hetzner};

    let plan = flag_value(args, "--fleet-plan").unwrap_or_else(|| hetzner::DEFAULT_PLAN.to_owned());
    let Ok(mut provider) = hetzner::HetznerFleet::new(&plan, "ubuntu-24.04", "nbg1", "", "") else {
        eprintln!("[FAIL] plan desconocido: {plan}");
        return ExitCode::FAILURE;
    };
    let destroyed = provider.destroy_all();
    eprintln!(
        "destruidos {destroyed} servidor(es) con label fleet={}",
        hetzner::FLEET_LABEL
    );
    ExitCode::SUCCESS
}

/// Cuántos casos lleva un shard por defecto.
///
/// El número sale de medir, no de dividir, y el que manda no es el
/// throughput sino el **costo fijo de arranque**: un runner nace vacío y tiene
/// que instalar toolchain y compilar el workspace, del orden de **15 minutos de
/// máquina**. Con el techo de reloj de una hora eso deja ~45 min de fuzzing
/// útil, que a los ~4 400 casos/s medidos del generador de mutación son ~12 M de
/// casos. Un shard de 250 000 —el número que uno escribiría de memoria— gastaría
/// el 97 % del runner arrancándolo.
///
/// Shards más chicos = más máquinas = más plata, y encima menos trabajo hecho.
#[cfg(feature = "diff-revm")]
const DEFAULT_SHARD_CASES: u64 = 10_000_000;

/// El techo de reloj de un runner, en segundos: una hora. Es lo que se COBRA
/// por adelantado, no lo que se espera que tarde.
#[cfg(feature = "diff-revm")]
const DEFAULT_RUNNER_WALL_SECS: u64 = 3_600;

/// El anotador de causa raíz que shellea un comando.
///
/// Recibe el hallazgo por stdin como JSON y devuelve su stdout como
/// hipótesis. Que sea un comando externo y no una integración es a propósito:
/// el binario del harness no puede depender de una red ni de una API, y el
/// LLM que se use es del operador, no del gate.
#[cfg(feature = "diff-revm")]
struct CommandAnnotator {
    command: String,
}

#[cfg(feature = "diff-revm")]
impl fuzz::campaign::RootCauseAnnotator for CommandAnnotator {
    fn annotate(&mut self, finding: &fuzz::finding::Finding) -> Option<String> {
        use std::io::Write;
        let payload = serde_json::to_string(&finding.to_ledger_value()).ok()?;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(&self.command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .ok()?;
        child.stdin.as_mut()?.write_all(payload.as_bytes()).ok()?;
        let output = child.wait_with_output().ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
        if text.is_empty() { None } else { Some(text) }
    }
}

/// Semilla por defecto de la campaña. Constante y nombrada: ver `run_fuzz`.
#[cfg(feature = "diff-revm")]
const DEFAULT_FUZZ_SEED: u64 = 0x2026_0818_29D2;
#[cfg(feature = "diff-revm")]
const DEFAULT_FUZZ_CASES: u64 = 2_000;

#[cfg(feature = "diff-revm")]
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let position = args.iter().position(|arg| arg == flag)?;
    args.get(position.saturating_add(1)).cloned()
}

/// Acepta decimal o `0x`-hex. Un valor que no parsea NO cae a un default
/// silencioso: se reporta y la campaña arranca con el default, que se imprime.
#[cfg(feature = "diff-revm")]
fn parse_u64(raw: &str) -> Option<u64> {
    let parsed = match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse::<u64>(),
    };
    match parsed {
        Ok(value) => Some(value),
        Err(e) => {
            eprintln!("[warn] no se pudo leer '{raw}': {e}; se usa el valor por defecto");
            None
        }
    }
}

#[cfg(not(feature = "diff-revm"))]
fn run_fuzz() -> ExitCode {
    eprintln!(
        "--fuzz requiere el oráculo: recompilá con `--features diff-revm`. \
         Un fuzzer sin oráculo genera casos y no juzga ninguno (fail-closed)."
    );
    ExitCode::FAILURE
}

#[cfg(not(feature = "diff-revm"))]
fn run_diff(_target: &str) -> ExitCode {
    eprintln!(
        "--diff requiere el oráculo: recompilá con `--features diff-revm`. \
         Sin revm no hay contra qué comparar (fail-closed)."
    );
    ExitCode::FAILURE
}

fn run_vendored_subset() -> ExitCode {
    eprintln!("== Repo B — conformance gate ==");
    eprintln!();

    let dir = fixtures_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("no se pudo leer {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    };

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut skipped = 0u32;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("[FAIL] {}: no se pudo leer: {e}", path.display());
                failed = failed.saturating_add(1);
                continue;
            }
        };
        let tests = match fixture::parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => {
                eprintln!("[FAIL] {}: {e}", path.display());
                failed = failed.saturating_add(1);
                continue;
            }
        };
        for test in &tests {
            for case in &test.posts {
                let label = format!("{} [{}]", short_name(&test.name), case.fork);
                match runner::run_case(test, case) {
                    CaseOutcome::Pass => {
                        eprintln!("[PASS] {label}");
                        passed = passed.saturating_add(1);
                    }
                    CaseOutcome::SkippedFork(fork) => {
                        eprintln!("[SKIP] {label}: fork {fork} fuera de scope post-Merge");
                        skipped = skipped.saturating_add(1);
                    }
                    CaseOutcome::Fail(reason) => {
                        eprintln!("[FAIL] {label}: {reason}");
                        failed = failed.saturating_add(1);
                    }
                }
            }
        }
    }

    eprintln!();
    eprintln!("subset vendoreado: {passed} PASS, {failed} FAIL, {skipped} SKIP");
    #[cfg(feature = "diff-revm")]
    eprintln!("[diferencial bit-idéntico vs revm] feature ACTIVA, bridge pendiente (Fase 2).");
    #[cfg(not(feature = "diff-revm"))]
    eprintln!("[diferencial bit-idéntico vs revm] feature inactiva; se activa en Fase 2.");
    // Los DOS ejes de EEST cerraron sin residuo (`--eest` 39 025/39 025,
    // `--eest-blockchain` 42 017/42 017) y el diferencial va 315/315. Aun así
    // el gate de FASE sigue RED, y a propósito: falta el fuzzing diferencial, y
    // **cerrar la fase es una decisión humana**, no algo que este harness pueda
    // declararse a sí mismo.
    eprintln!(
        "GATE Fase 2 (existencia): RED — los dos ejes de EEST cerraron; falta el fuzzing \
         diferencial y el cierre de fase es una decisión humana."
    );

    // Exit = resultado de ESTA corrida (subset vendoreado). El gate global
    // sigue siendo el de Fase 2, medido con `--eest`.
    if failed == 0 && passed > 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// El nombre del test dentro del fixture repite el path completo; recorta.
fn short_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}
