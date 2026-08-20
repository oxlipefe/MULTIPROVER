//! `--record-replay`: el gate del grabador de accesos.
//!
//! Tres corridas del MISMO caso y dos propiedades:
//!
//! 1. **Transparencia** — envuelto en el recorder, el caso da exactamente el
//!    mismo veredicto que sin envolver. Sin esto, todo lo demás mediría un
//!    grabador que no está en el camino de ejecución real.
//! 2. **Suficiencia** — alimentado *solo* por lo grabado (`StrictState`,
//!    fail-closed), el caso vuelve a dar ese veredicto. Es "no grabó de menos".
//! 3. **Minimalidad** — quitándole al log un ítem cualquiera, el caso deja de
//!    darlo. Es "no grabó de más", y es la mitad que un replay solo no puede
//!    probar: sobrar nunca rompe un replay.
//!
//! El veredicto que se compara es el observable de consenso (root del
//! post-state, status y hash de logs), no la estructura interna del outcome: si
//! dos corridas producen el mismo root y el mismo status, produjeron el mismo
//! bloque.

use std::collections::BTreeMap;
use std::path::Path;

use repo_b_common::primitives::B256;
use repo_b_evm::OwnVm;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::state::State;
use repo_b_evm::vm::Vm;
use repo_b_witness::{AccessLog, RecordingState, StrictState, WitnessState};

use crate::fixture::{PostCase, StateTest, parse_file, spec_for_fork};
use crate::runner::{MemoryState, apply_updates, compute_state_root, logs_hash};

#[derive(Debug, Default)]
pub struct Report {
    pub cases: u32,
    /// Casos donde el recorder cambió el veredicto.
    pub not_transparent: u32,
    /// Casos donde el replay contra lo grabado no reprodujo el veredicto.
    pub insufficient: u32,
    /// Ítems que se pudieron quitar del log sin que la ejecución lo notara.
    pub superfluous: u32,
    /// Ítems grabados en total (denominador de la minimalidad).
    pub items: u64,
    pub skipped: u32,
    /// Casos donde ejecutar SOLO desde el witness dio otro veredicto.
    pub witness_mismatch: u32,
    /// Peso total de los witness generados, en bytes. Es lo que se paga por
    /// bloque cuando esto se pruebe, así que se mide desde el día uno.
    pub witness_bytes: u64,
    /// Nodos de trie totales, para separar el peso de los nodos del de códigos.
    pub witness_nodes: u64,
    /// Casos que **todavía no pueden** ejecutarse desde el witness, por una
    /// pieza que el witness no lleva. No son fallas y no son éxitos: son
    /// deuda con nombre.
    pub deferred: Vec<&'static str>,
}

impl Report {
    #[must_use]
    pub fn failed(&self) -> u32 {
        self.not_transparent
            .saturating_add(self.insufficient)
            .saturating_add(self.superfluous)
            .saturating_add(self.witness_mismatch)
    }

    /// Los diferidos observados coinciden **exactamente** con los declarados.
    ///
    /// Es un trinquete y no una tolerancia: un caso diferido nuevo hay que
    /// declararlo a mano, con su razón. Sin esto, "326 de 327" sería un número
    /// pelado capaz de tapar al próximo caso que falle por otro motivo.
    #[must_use]
    pub fn deferred_matches_declared(&self) -> bool {
        let mut observados = self.deferred.clone();
        observados.sort_unstable();
        let mut declarados: Vec<&str> = DEFERRED.iter().map(|(name, _)| *name).collect();
        declarados.sort_unstable();
        observados == declarados
    }
}

/// **Lo que el witness todavía no puede alimentar, con nombre y razón.**
///
/// La cadena contigua de headers no está en el witness: un `BLOCKHASH` no se
/// puede probar con un hash suelto, hace falta encadenar `parent_hash` hacia
/// atrás. Y en un `state_test` no hay headers que encadenar — el fixture
/// inventa el mapa número→hash —, así que el corpus que puede juzgar esa regla
/// es el de bloques, no éste.
pub const DEFERRED: &[(&str, &str)] = &[(
    "blockhash_within_and_outside_window",
    "BLOCKHASH necesita la cadena contigua de headers, que el witness todavía no lleva",
)];

/// Lo que un cliente ve de una ejecución. Dos corridas con el mismo `Verdict`
/// produjeron el mismo bloque.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    root: B256,
    status: String,
    logs: B256,
}

/// Corre el caso contra el `State` dado. `Err` es un resultado válido y
/// comparable: una tx rechazada por consenso lo es, y un acceso que el witness
/// no tiene también — por eso el mensaje entra en la comparación.
fn run_with(test: &StateTest, case: &PostCase, state: &dyn State) -> Result<Verdict, String> {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Err("fork fuera de scope".to_owned());
    };
    let tx = test.transaction_for(case)?;
    let env = test.block_env(spec);
    let outcome = match OwnVm::new().execute_tx(&tx, &env, state) {
        Ok(outcome) => Some(outcome),
        Err(e) => return Err(format!("{e}")),
    };
    let (logs, status) = match outcome.as_ref().map(|out| &out.result) {
        Some(ExecutionResult::Success { logs, .. }) => (logs.as_slice(), "success".to_owned()),
        Some(ExecutionResult::Revert { .. }) => ([].as_slice(), "revert".to_owned()),
        Some(ExecutionResult::Halt { reason, .. }) => ([].as_slice(), format!("halt:{reason:?}")),
        None => ([].as_slice(), "rejected".to_owned()),
    };
    let changes = outcome
        .as_ref()
        .map_or([].as_slice(), |out| out.state_changes.as_slice());
    let post = apply_updates(&test.pre, changes)?;
    Ok(Verdict {
        root: compute_state_root(&post),
        status,
        logs: logs_hash(logs),
    })
}

fn base_state(test: &StateTest) -> MemoryState {
    MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone())
}

/// Un caso: graba, replaya y mide la minimalidad del log.
pub fn run_one(test: &StateTest, case: &PostCase, report: &mut Report, minimality: bool) {
    if spec_for_fork(&case.fork).is_none() || test.require_post_merge_env().is_err() {
        report.skipped = report.skipped.saturating_add(1);
        return;
    }
    report.cases = report.cases.saturating_add(1);

    let base = run_with(test, case, &base_state(test));

    // 1. Transparencia.
    let recorder = RecordingState::new(Box::new(base_state(test)));
    let recorded = run_with(test, case, &recorder);
    if recorded != base {
        report.not_transparent = report.not_transparent.saturating_add(1);
        eprintln!(
            "[FAIL] {} ({}): el recorder cambió el veredicto\n  sin envolver: {base:?}\n  envuelto:     {recorded:?}",
            test.name, case.fork
        );
        return;
    }
    let log = recorder.log();
    report.items = report.items.saturating_add(log.items().len() as u64);

    // 2. Suficiencia.
    let replayed = run_with(test, case, &StrictState::new(log.clone()));
    if replayed != base {
        report.insufficient = report.insufficient.saturating_add(1);
        eprintln!(
            "[FAIL] {} ({}): el replay contra lo grabado no reprodujo el veredicto\n  completo: {base:?}\n  witness:  {replayed:?}",
            test.name, case.fork
        );
        return;
    }

    // 3. Minimalidad.
    if minimality {
        for item in log.items() {
            let recortado = log.without(&item);
            if run_with(test, case, &StrictState::new(recortado)) == base {
                report.superfluous = report.superfluous.saturating_add(1);
                eprintln!(
                    "[FAIL] {} ({}): el log grabó de más — quitar {item:?} no cambia nada",
                    test.name, case.fork
                );
            }
        }
    }
}

/// Lo que pasó al intentar ejecutar un caso **solo desde el witness**.
///
/// Es un resultado estructurado y no un contador más un `eprintln` porque el
/// MISMO camino lo consumen dos gates con políticas distintas: el subset
/// vendoreado declara sus diferidos **por nombre** (327 casos hechos a mano) y
/// el eje de EEST los declara **por conteo trinquetado** (39 025 no caben en
/// una lista). Escribir un segundo camino para el segundo gate es exactamente
/// evitar: dos implementaciones del mismo camino pueden discrepar.
#[derive(Debug)]
pub enum WitnessOutcome {
    /// Ejecutó solo desde el witness y reprodujo el veredicto.
    Executed(WitnessRun),
    /// El recorder cambió el veredicto: nada de lo que siga mediría el camino
    /// de ejecución real.
    NotTransparent { base: String, wrapped: String },
    /// El motor **pidió** una pieza que el witness todavía no lleva. La
    /// clasificación es estructural —qué pidió—, nunca por el texto del error.
    NeedsBlockHash,
    /// Ejecutar desde el witness dio otro veredicto.
    ///
    /// `log_sufficient` separa las dos causas posibles, y se calcula **solo
    /// acá** (en el camino feliz no cuesta nada): si el replay contra lo
    /// grabado ya fallaba, el problema es del **grabador**; si el log
    /// alcanzaba y el witness no, el problema es del **witness**.
    Mismatch {
        base: String,
        witness: String,
        log_sufficient: bool,
    },
    /// El caso no se corre acá (fork fuera de scope, env sin campos
    /// post-merge). No es éxito ni falla.
    OutOfScope(String),
}

/// Lo que un caso que sí ejecutó desde el witness deja medido.
#[derive(Debug, Clone)]
pub struct WitnessRun {
    pub bytes: u64,
    pub nodes: u64,
    /// El input pasó por bytes —codificado del lado del host, decodificado del
    /// lado del guest— y la ejecución desde lo decodificado dio lo mismo.
    pub codec: Result<(), String>,
    /// El post-state root recomputado **solo desde el witness** coincidió con
    /// el que el harness computa desde el estado completo. `Err` lleva la razón
    /// para que el residuo se pueda clusterizar en vez de contarse.
    pub root: Result<(), String>,
    /// `false` cuando la tx fue **rechazada** antes de ejecutar. Un caso así
    /// pasa por el witness trivialmente, y contarlo junto a los que corrieron
    /// código inflaría el número sin evidencia detrás.
    pub executed_tx: bool,
}

/// Un caso, ejecutado **solo desde el witness**: se graba, se arma el witness
/// con los nodos de trie de lo tocado, y se vuelve a ejecutar contra un `State`
/// que no tiene más que eso y verifica cada lectura contra el pre-state root.
#[must_use]
pub fn witness_outcome(test: &StateTest, case: &PostCase) -> WitnessOutcome {
    if spec_for_fork(&case.fork).is_none() {
        return WitnessOutcome::OutOfScope("fork fuera de scope".to_owned());
    }
    if let Err(e) = test.require_post_merge_env() {
        return WitnessOutcome::OutOfScope(e);
    }

    let base = run_with(test, case, &base_state(test));

    let recorder = RecordingState::new(Box::new(base_state(test)));
    let recorded = run_with(test, case, &recorder);
    if recorded != base {
        return WitnessOutcome::NotTransparent {
            base: format!("{base:?}"),
            wrapped: format!("{recorded:?}"),
        };
    }
    let log = recorder.log();

    // **La clasificación es estructural, no por el texto del error.** El log
    // dice qué pidió el motor: si pidió un `block_hash`, este caso necesita una
    // pieza que el witness todavía no lleva, y eso se sabe ANTES de ejecutar.
    // Clasificar por el mensaje sería un cheque en blanco: cualquier `Err`
    // futuro entraría en la excusa.
    if !log.block_hashes.is_empty() {
        return WitnessOutcome::NeedsBlockHash;
    }

    // Los borrados del diff, que son lo único que necesita hermanos. Se conocen
    // porque el witness se arma DESPUÉS de ejecutar — igual que en un cliente
    // real, que ejecuta y después publica.
    let shape = changes_of(test, case)
        .as_deref()
        .map(|c| crate::witness_build::ShapeChanges::of(c, &test.pre))
        .unwrap_or_default();
    let witness = crate::witness_build::build_with(&test.pre, &log, &shape);
    // El root contra el que se verifica es el del pre-state, computado con la
    // MISMA función que juzga el post-state en los dos ejes de EEST — o sea que
    // no es un root de casa: está pineado por 39 025 + 42 017 casos.
    let root = compute_state_root(&test.pre);
    let from_witness = run_with(test, case, &WitnessState::new(&witness, root));
    if from_witness != base {
        let log_sufficient = run_with(test, case, &StrictState::new(log)) == base;
        return WitnessOutcome::Mismatch {
            base: format!("{base:?}"),
            witness: format!("{from_witness:?}"),
            log_sufficient,
        };
    }
    WitnessOutcome::Executed(WitnessRun {
        bytes: witness.size_in_bytes() as u64,
        nodes: witness.state.len() as u64,
        root: post_root_matches(test, case, &witness, root),
        codec: codec_roundtrip(test, case, &witness, root),
        executed_tx: base.is_ok(),
    })
}

/// Cobertura del round-trip: cuántos casos ejercitan cada lista anidada.
pub static CON_ACCESS_LIST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static CON_BLOBS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static CON_AUTH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static CODEC_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// **El input del guest, ida y vuelta por bytes, y ejecutado desde lo que
/// vuelve.**
///
/// Es lo que ata las dos mitades del codec: el encoder vive en el host y el
/// decoder en el guest, y un round-trip que solo se compare consigo mismo daría
/// verde aunque los dos compartieran el mismo error. Acá el resultado contra el
/// que se compara —el veredicto y el root del camino tipado— **no sale del
/// codec**.
fn codec_roundtrip(
    test: &StateTest,
    case: &PostCase,
    witness: &repo_b_common::witness::ExecutionWitness,
    pre_root: B256,
) -> Result<(), String> {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Err("fork fuera de scope".to_owned());
    };
    let Ok(tx) = test.transaction_for(case) else {
        return Ok(()); // tx que ni siquiera se puede armar: no hay input que probar
    };
    let input = repo_b_guest::codec::OwnedInput {
        witness: witness.clone(),
        pre_state_root: pre_root,
        env: test.block_env(spec),
        txs: alloc_vec(tx),
        withdrawals: Vec::new(),
        system_calls: Vec::new(),
    };
    // **La auditoría del round-trip**: un verde sobre 39 025 casos no prueba las
    // ramas anidadas si el corpus casi no las tiene. Se cuentan para que el
    // número diga qué cubrió y qué no.
    if let Some(t) = input.txs.first() {
        if !t.access_list.is_empty() {
            CON_ACCESS_LIST.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        if !t.blob_versioned_hashes.is_empty() {
            CON_BLOBS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        if !t.authorization_list.is_empty() {
            CON_AUTH.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    CODEC_BYTES.fetch_add(
        repo_b_guest::codec::encode(&input).len() as u64,
        core::sync::atomic::Ordering::Relaxed,
    );
    let bytes = repo_b_guest::codec::encode(&input);
    let vuelto = repo_b_guest::codec::decode(&bytes)
        .map_err(|e| format!("el input no decodifica: {e:?}"))?;

    // 1. El input tiene que volver idéntico.
    if vuelto.witness != input.witness
        || vuelto.pre_state_root != input.pre_state_root
        || vuelto.env != input.env
        || vuelto.txs != input.txs
    {
        return Err("el input no sobrevivió el round-trip".to_owned());
    }

    // 2. Y ejecutar desde lo decodificado tiene que dar lo mismo que desde el
    //    witness tipado. Sin esto, el punto 1 solo prueba que el codec se
    //    entiende a sí mismo.
    let Some(tx) = vuelto.txs.first() else {
        return Err("el round-trip perdió la tx".to_owned());
    };
    let state = WitnessState::new(&vuelto.witness, vuelto.pre_state_root);
    let desde_bytes = OwnVm::new().execute_tx(tx, &vuelto.env, &state);
    let tipado = OwnVm::new().execute_tx(
        &input.txs[0],
        &input.env,
        &WitnessState::new(witness, pre_root),
    );
    match (desde_bytes, tipado) {
        (Ok(a), Ok(b)) if a.state_changes == b.state_changes && a.result == b.result => Ok(()),
        (Err(a), Err(b)) if format!("{a}") == format!("{b}") => Ok(()),
        _ => Err("ejecutar desde el input decodificado dio otro resultado".to_owned()),
    }
}

fn alloc_vec(
    tx: repo_b_common::transaction::Transaction,
) -> Vec<repo_b_common::transaction::Transaction> {
    vec![tx]
}

/// El diff que el caso produce contra el estado completo, para saber qué se
/// borra antes de armar el witness.
fn changes_of(
    test: &StateTest,
    case: &PostCase,
) -> Option<Vec<repo_b_common::account::AccountUpdate>> {
    let spec = spec_for_fork(&case.fork)?;
    let tx = test.transaction_for(case).ok()?;
    let env = test.block_env(spec);
    let state = base_state(test);
    OwnVm::new()
        .execute_tx(&tx, &env, &state)
        .ok()
        .map(|out| out.state_changes)
}

/// ¿El post-state root recomputado SOLO desde el witness es el mismo que el
/// que el harness computa desde el estado completo?
///
/// Es la mitad del DoD de la fase que hasta acá contestaba el harness con datos
/// que el guest no tiene.
fn post_root_matches(
    test: &StateTest,
    case: &PostCase,
    witness: &repo_b_common::witness::ExecutionWitness,
    pre_root: B256,
) -> Result<(), String> {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Err("fork fuera de scope".to_owned());
    };
    let Ok(tx) = test.transaction_for(case) else {
        return Ok(()); // tx inválida: no hay cambios, el root no se mueve
    };
    let env = test.block_env(spec);
    let state = WitnessState::new(witness, pre_root);
    let Ok(outcome) = OwnVm::new().execute_tx(&tx, &env, &state) else {
        return Ok(()); // rechazada: idem
    };
    let post = apply_updates(&test.pre, &outcome.state_changes)
        .map_err(|e| format!("no se pudo armar el post-state: {e}"))?;
    let esperado = compute_state_root(&post);
    match state.post_state_root(&outcome.state_changes) {
        Ok(r) if r == esperado => Ok(()),
        Ok(r) => Err(format!("root distinto: {r} vs {esperado}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// El gate del subset vendoreado sobre `witness_outcome`: acá los diferidos se
/// declaran **por nombre**, porque son 327 casos escritos a mano y una deuda
/// con nombre es la que se lee en cada corrida.
pub fn run_one_witness(test: &StateTest, case: &PostCase, report: &mut Report) {
    match witness_outcome(test, case) {
        WitnessOutcome::OutOfScope(_) => report.skipped = report.skipped.saturating_add(1),
        WitnessOutcome::Executed(run) => {
            report.cases = report.cases.saturating_add(1);
            report.witness_bytes = report.witness_bytes.saturating_add(run.bytes);
            report.witness_nodes = report.witness_nodes.saturating_add(run.nodes);
        }
        WitnessOutcome::NotTransparent { .. } => {
            report.cases = report.cases.saturating_add(1);
            report.not_transparent = report.not_transparent.saturating_add(1);
        }
        WitnessOutcome::NeedsBlockHash => {
            report.cases = report.cases.saturating_add(1);
            match DEFERRED.iter().find(|(name, _)| *name == test.name) {
                Some((name, _)) => report.deferred.push(name),
                // Un caso que necesita la pieza pendiente y NO está declarado
                // es una falla: la deuda se declara, no se descubre en una
                // corrida.
                None => {
                    report.witness_mismatch = report.witness_mismatch.saturating_add(1);
                    eprintln!(
                        "[FAIL] {} ({}): necesita `block_hash` y no está en la lista de diferidos",
                        test.name, case.fork
                    );
                }
            }
        }
        WitnessOutcome::Mismatch { base, witness, .. } => {
            report.cases = report.cases.saturating_add(1);
            report.witness_mismatch = report.witness_mismatch.saturating_add(1);
            eprintln!(
                "[FAIL] {} ({}): ejecutar desde el witness dio otro veredicto\n  completo: {base}\n  witness:  {witness}",
                test.name, case.fork
            );
        }
    }
}

/// Corre un directorio de fixtures. Mismo formato que consume el diferencial.
pub fn run_dir(dir: &Path, report: &mut Report, minimality: bool) {
    run_dir_with(dir, report, &mut |test, case, report| {
        run_one(test, case, report, minimality);
    });
}

/// Igual que `run_dir` pero cada caso se ejecuta **solo desde el witness**.
pub fn run_dir_witness(dir: &Path, report: &mut Report) {
    run_dir_with(dir, report, &mut run_one_witness);
}

fn run_dir_with(
    dir: &Path,
    report: &mut Report,
    each: &mut dyn FnMut(&StateTest, &PostCase, &mut Report),
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("[FAIL] no se pudo leer {}: {e}", dir.display());
            report.insufficient = report.insufficient.saturating_add(1);
            return;
        }
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();

    for path in paths {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("[FAIL] {}: no se pudo leer: {e}", path.display());
                report.insufficient = report.insufficient.saturating_add(1);
                continue;
            }
        };
        let tests = match parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => {
                eprintln!("[FAIL] {}: {e}", path.display());
                report.insufficient = report.insufficient.saturating_add(1);
                continue;
            }
        };
        for test in &tests {
            for case in &test.posts {
                each(test, case, report);
            }
        }
    }
}

/// Los mismos 21 sets que gatea el diferencial, más el subset vendoreado.
/// Deliberadamente no es "todo EEST": pasar el corpus entero por el witness es
/// un paso aparte, y mezclarlos haría que un fallo de cobertura y uno de escala
/// se confundieran.
pub const SETS: &[&str] = &[
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

/// Devuelve el reporte de correr todos los sets del subconjunto.
#[must_use]
pub fn run_sets(root: &Path, minimality: bool) -> Report {
    let mut report = Report::default();
    for set in SETS {
        run_dir(&root.join("diff").join(set), &mut report, minimality);
    }
    report
}

/// Los mismos sets, ejecutados solo desde el witness.
#[must_use]
pub fn run_sets_witness(root: &Path) -> Report {
    let mut report = Report::default();
    for set in SETS {
        run_dir_witness(&root.join("diff").join(set), &mut report);
    }
    report
}

/// El mapa de qué cubre el subconjunto, para que la cobertura sea auditable en
/// vez de declarada: cuántos casos tocaron cada método del seam.
#[must_use]
pub fn coverage(root: &Path) -> BTreeMap<&'static str, u32> {
    let mut hits: BTreeMap<&'static str, u32> = BTreeMap::new();
    for set in SETS {
        let dir = root.join("diff").join(set);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<_> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        paths.sort();
        for path in paths {
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(tests) = parse_file(&raw) else {
                continue;
            };
            for test in &tests {
                for case in &test.posts {
                    if spec_for_fork(&case.fork).is_none() {
                        continue;
                    }
                    let recorder = RecordingState::new(Box::new(base_state(test)));
                    let _ = run_with(test, case, &recorder);
                    tally(&recorder.log(), &mut hits);
                }
            }
        }
    }
    hits
}

fn tally(log: &AccessLog, hits: &mut BTreeMap<&'static str, u32>) {
    let mut bump = |key: &'static str, present: bool| {
        if present {
            *hits.entry(key).or_default() += 1;
        }
    };
    bump("account", !log.accounts.is_empty());
    bump(
        "account:ausente",
        log.accounts.values().any(Option::is_none),
    );
    bump("storage", !log.storage.is_empty());
    bump("storage_root", !log.storage_roots.is_empty());
    bump("code", !log.code.is_empty());
    bump("code_metadata", !log.code_metadata.is_empty());
    bump("block_hash", !log.block_hashes.is_empty());
}
