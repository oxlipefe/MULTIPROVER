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

/// El `State` de arranque del caso. Lleva la convención de `BLOCKHASH` de los
/// `state_test` por el mismo motivo que `runner::run_case`: el veredicto base
/// contra el que se contrasta el witness tiene que ser el MISMO que el del eje
/// `--eest`, o los dos caminos estarían juzgando cosas distintas.
fn base_state(test: &StateTest) -> MemoryState {
    MemoryState::from_pre(&test.pre)
        .with_block_hashes(test.env.block_hashes.clone())
        .with_state_test_block_hashes()
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
    /// **El sender derivado de la firma es el que el fixture declara** (y los
    /// `authority` de EIP-7702, los que declara su `signer`).
    ///
    /// Campo aparte de `codec` **y con dientes propios**: el round-trip del
    /// codec es deuda tolerada —se clusteriza y no suma a `failing`—, y bajo esa
    /// clave una divergencia de sender saldría en el reporte sin poner el eje en
    /// rojo. Un chequeo sin dientes es exactamente lo que este repo viene
    /// cazando desde 2.9c-5.
    pub sender: Result<(), String>,
    /// **El input del guest, encodeado**: los mismos bytes que entran al zkVM.
    ///
    /// Sale de acá y no de un segundo armador porque un segundo armador es un
    /// segundo lugar donde el input puede salir distinto — y entonces el nivel
    /// 3 estaría contrastando dos cosas que no son el mismo caso. `None`
    /// cuando el caso no tiene envelope construible (sin `secretKey`).
    pub input: Option<Vec<u8>>,
    /// **El guest en `Mode::StateTest`, juzgado por el fixture**: el input del
    /// caso (con el `txbytes` del fixture) por `run_bytes`, y el `post_state_root` que publica contra el
    /// `stateRoot` del fixture (o un rechazo, si el fixture declara la tx
    /// inválida). Es el único juez externo de ese modo: el round-trip de
    /// `codec` ejecuta con `execute_tx`, no con el lifecycle del guest.
    /// Con dientes; `Unjudged` se cuenta y tiene techo.
    pub guest: Result<GuestJudgement, String>,
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
    let (codec, input) = match codec_roundtrip(test, case, &witness, root) {
        Ok(bytes) => (Ok(()), bytes),
        Err(e) => (Err(e), None),
    };
    let guest = guest_state_test(test, case, &witness, root);
    WitnessOutcome::Executed(WitnessRun {
        bytes: witness.size_in_bytes() as u64,
        nodes: witness.state.len() as u64,
        root: post_root_matches(test, case, &witness, root),
        codec,
        input,
        guest,
        sender: sender_contrast(test, case),
        executed_tx: base.is_ok(),
    })
}

/// Qué dijo el juez de `Mode::StateTest` sobre un caso. Ver
/// [`guest_state_test`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestJudgement {
    /// El guest publicó el `stateRoot` del fixture.
    Matched,
    /// El fixture declara la tx inválida y el guest la rechazó **por una razón
    /// que el `expectException` nombra** (o por consenso, como el runner).
    Rejected,
    /// No hay envelope que darle al guest: ni `txbytes` ni una firma que el
    /// harness pueda construir. Lleva la razón; se cuenta y se reporta.
    Unjudged(String),
}

/// De dónde salió el envelope que corrió el guest, y los rechazos tempranos.
pub static GUEST_FROM_TXBYTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static GUEST_FROM_SIGNATURE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// `txbytes` que no decodifica, rechazado antes de llegar al guest (y que el
/// `expectException` explica). Va dentro de `Rejected`.
pub static GUEST_TXBYTES_UNDECODABLE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// **El guest en `Mode::StateTest`, por el mismo camino de bytes que el
/// zkVM**, contra lo que el fixture dice. Ver `WitnessRun::guest`.
///
/// **La tx es la del fixture, no la que firma el harness.** Con `txbytes`, el
/// envelope es ése: el harness firma con el `chainId` del bloque, y una tx que
/// el fixture declara inválida por su `chainId` saldría válida re-firmada. Solo
/// sin `txbytes` se usa la firma del harness, y sin ninguno de los dos el caso
/// queda `Unjudged` con su razón.
///
/// **El rechazo tiene que ser el que el fixture espera**, con el criterio del
/// runner: un `txbytes` que no decodifica tiene que estar explicado por una
/// excepción de envelope, una firma que no recupera por una de firma, y un
/// rechazo del motor tiene que ser de consenso (un error interno nunca se
/// excusa). Cualquier otro es un rechazo por otra razón, y falla.
///
/// # Errors
/// Si el journal no es el de este caso o el veredicto no es el del fixture.
pub fn guest_state_test(
    test: &StateTest,
    case: &PostCase,
    witness: &repo_b_common::witness::ExecutionWitness,
    pre_root: B256,
) -> Result<GuestJudgement, String> {
    use crate::runner::{FailKind, signature_path_explains};
    use repo_b_guest::journal::Mode;
    use repo_b_guest::{GuestError, codec};
    let relaxed = core::sync::atomic::Ordering::Relaxed;
    let expected = case.expect_exception.as_deref();
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Err("fork fuera de scope".to_owned());
    };
    let env = test.block_env(spec);
    let tx = match &case.tx_bytes {
        Some(raw) => match repo_b_guest::signature::decode_2718(raw) {
            Ok(tx) => {
                GUEST_FROM_TXBYTES.fetch_add(1, relaxed);
                tx
            }
            Err(e) => {
                return match expected {
                    Some(x) if signature_path_explains(FailKind::Envelope, x) => {
                        GUEST_TXBYTES_UNDECODABLE.fetch_add(1, relaxed);
                        Ok(GuestJudgement::Rejected)
                    }
                    Some(x) => Err(format!(
                        "rechazo por otra razón: el txbytes no decodifica ({}) y el fixture espera `{x}`",
                        e.0
                    )),
                    None => Err(format!(
                        "el txbytes de una tx válida no decodifica: {}",
                        e.0
                    )),
                };
            }
        },
        None => match crate::fixture::signed_transaction_for(test, case, env.chain_id) {
            Ok(tx) => {
                GUEST_FROM_SIGNATURE.fetch_add(1, relaxed);
                tx
            }
            Err(e) => return Ok(GuestJudgement::Unjudged(e)),
        },
    };
    let input = codec::TxInput {
        witness: repo_b_common::witness::ExecutionWitness {
            keys: Vec::new(),
            headers: Vec::new(),
            ..witness.clone()
        },
        pre_state_root: pre_root,
        env,
        txs: vec![tx],
    };
    let bytes =
        codec::encode_tx_input(&input).map_err(|e| format!("el input no encodea: {e:?}"))?;
    let mut raw = Vec::with_capacity(bytes.len().saturating_add(1));
    raw.push(Mode::StateTest.as_byte());
    raw.extend_from_slice(&bytes);
    let j = match (repo_b_guest::run_bytes(&raw), expected) {
        (Ok(j), None) => j,
        (Ok(j), Some(x)) => {
            return Err(format!(
                "el guest aceptó una tx que el fixture declara inválida ({x}): {j:?}"
            ));
        }
        (Err(e), None) => return Err(format!("el guest rechazó una tx válida: {}", e.0)),
        (Err(_), Some(x)) => {
            // `run_bytes` solo devuelve la razón corta; el error tipado sale
            // del MISMO camino (decode + `run_tx_input`) sin el byte de modo.
            let tipado = codec::decode_tx_input(&bytes)
                .map_err(|e| format!("el input no decodifica: {e:?}"))
                .and_then(|i| match repo_b_guest::run_tx_input(&i) {
                    Ok(j) => Err(format!(
                        "el camino tipado aceptó lo que run_bytes rechazó: {j:?}"
                    )),
                    Err(e) => Ok(e),
                })?;
            let explica = match &tipado {
                GuestError::Signature(_) => signature_path_explains(FailKind::Signature, x),
                // El texto es el `Display` de `VmError`: `consensus error: …`
                // o `internal error: …`. Un interno nunca es un rechazo válido.
                GuestError::Vm { message, .. } => message.starts_with("consensus error:"),
                _ => false,
            };
            if !explica {
                return Err(format!(
                    "rechazo por otra razón: el guest dio {tipado:?} y el fixture espera `{x}`"
                ));
            }
            return Ok(GuestJudgement::Rejected);
        }
    };
    if j.mode != Mode::StateTest || j.pre_state_root != pre_root {
        return Err(format!(
            "el guest publicó otro modo o otro pre-state: {j:?}"
        ));
    }
    if j.block_hash != B256::ZERO || j.parent_hash != B256::ZERO {
        return Err(format!("un journal de StateTest nombra un bloque: {j:?}"));
    }
    if j.post_state_root != case.state_root {
        return Err(format!(
            "el guest publicó post_state_root {} y el fixture dice {}",
            j.post_state_root, case.state_root
        ));
    }
    Ok(GuestJudgement::Matched)
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
) -> Result<Option<Vec<u8>>, String> {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Err("fork fuera de scope".to_owned());
    };
    let Ok(tx) = test.transaction_for(case) else {
        return Ok(None); // tx que ni siquiera se puede armar: no hay input que probar
    };
    let env = test.block_env(spec);
    // **Sin `secretKey` no hay envelope que construir.** Se saltea y se cuenta:
    // un salteo silencioso convertiría el gate en un espejo. Ver
    // `SIN_FIRMA` y el reporte de `--witness`.
    let Ok(firmada) = crate::fixture::signed_transaction_for(test, case, env.chain_id) else {
        // El contador vive en `sender_contrast`, que corre para el mismo caso.
        return Ok(None);
    };
    // Un `state_test` es una tx suelta: no hay cadena de headers que anclar
    // (los casos que piden un `BLOCKHASH` se difieren antes de llegar acá), ni
    // system calls ni withdrawals. Va por el formato de `Mode::StateTest`, que
    // no afirma nada sobre un bloque. Las `keys` del witness no viajan.
    let input = repo_b_guest::codec::TxInput {
        witness: repo_b_common::witness::ExecutionWitness {
            keys: Vec::new(),
            headers: Vec::new(),
            ..witness.clone()
        },
        pre_state_root: pre_root,
        env,
        txs: vec![firmada],
    };
    // **La auditoría del round-trip**: un verde sobre 39 025 casos no prueba las
    // ramas anidadas si el corpus casi no las tiene. Se cuentan para que el
    // número diga qué cubrió y qué no.
    if let Some(t) = input
        .txs
        .first()
        .map(repo_b_guest::signature::SignedTransaction::payload)
    {
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
    let bytes = repo_b_guest::codec::encode_tx_input(&input)
        .map_err(|e| format!("el input no encodea: {e:?}"))?;
    CODEC_BYTES.fetch_add(bytes.len() as u64, core::sync::atomic::Ordering::Relaxed);
    let vuelto = repo_b_guest::codec::decode_tx_input(&bytes)
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
    //    entiende a sí mismo. **El sender del lado de los bytes sale de la
    //    firma**; el del lado tipado, del fixture.
    let Some(firmada) = vuelto.txs.first() else {
        return Err("el round-trip perdió la tx".to_owned());
    };
    let desde_firma = firmada
        .recover(vuelto.env.chain_id)
        .map_err(|e| format!("la firma decodificada no recupera: {}", e.0))?;
    let state = WitnessState::new(&vuelto.witness, vuelto.pre_state_root);
    let desde_bytes = OwnVm::new().execute_tx(&desde_firma, &vuelto.env, &state);
    let tipado = OwnVm::new().execute_tx(&tx, &input.env, &WitnessState::new(witness, pre_root));
    match (desde_bytes, tipado) {
        (Ok(a), Ok(b)) if a.state_changes == b.state_changes && a.result == b.result => {
            Ok(Some(bytes))
        }
        (Err(a), Err(b)) if format!("{a}") == format!("{b}") => Ok(Some(bytes)),
        _ => Err("ejecutar desde el input decodificado dio otro resultado".to_owned()),
    }
}

/// **El sender derivado de la firma contra el que el fixture declara.**
///
/// Un `state_test` no publica `v`/`r`/`s`: publica `secretKey`, así que **el
/// firmante somos nosotros**. Lo que salva el test de ser un espejo es el
/// oráculo: el `sender` declarado NO sale de nuestra firma. Firmar es nuestro;
/// el contraste, no.
///
/// Los `authority` de EIP-7702 van por el mismo camino: los del fixture salen
/// de su campo `signer` y los nuestros de la firma de la tupla.
///
/// # Errors
/// Si lo derivado no es lo declarado. **No** es error que el caso no se pueda
/// firmar: eso se saltea y se cuenta (`SIN_FIRMA`).
fn sender_contrast(test: &StateTest, case: &PostCase) -> Result<(), String> {
    let Some(spec) = spec_for_fork(&case.fork) else {
        return Ok(());
    };
    let Ok(tx) = test.transaction_for(case) else {
        return Ok(());
    };
    let env = test.block_env(spec);
    let Ok(firmada) = crate::fixture::signed_transaction_for(test, case, env.chain_id) else {
        SIN_FIRMA.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return Ok(());
    };
    let recuperada = firmada
        .recover(env.chain_id)
        .map_err(|e| format!("la firma no recupera: {}", e.0))?;
    if recuperada.sender != tx.sender {
        return Err(format!(
            "la firma produce {} y el fixture declara {}",
            recuperada.sender, tx.sender
        ));
    }
    let declarados: Vec<_> = tx.authorization_list.iter().map(|a| a.authority).collect();
    let derivados: Vec<_> = recuperada
        .authorization_list
        .iter()
        .map(|a| a.authority)
        .collect();
    if declarados != derivados {
        return Err(format!(
            "los authority derivados {derivados:?} no son los declarados {declarados:?}"
        ));
    }
    SENDERS_DERIVADOS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    AUTHORITIES_DERIVADAS.fetch_add(
        declarados.len() as u64,
        core::sync::atomic::Ordering::Relaxed,
    );
    Ok(())
}

/// Casos que **no pueden** llevar envelope firmado porque el fixture no publica
/// con qué firmar. Se cuenta y se imprime: los 327 del diferencial no son
/// evidencia sobre derivación de sender, y eso tiene que leerse en la corrida.
pub static SIN_FIRMA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Casos donde el sender derivado de la firma **coincidió** con el declarado.
/// Sin este número, "0 fallas" podría ser cierto por vacuidad.
pub static SENDERS_DERIVADOS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Tuplas de EIP-7702 cuyo `authority` se contrastó contra el `signer` del
/// fixture.
pub static AUTHORITIES_DERIVADAS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

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

/// Los mismos 22 sets que gatea el diferencial, más el subset vendoreado.
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

#[cfg(test)]
mod tests {
    use super::{GuestJudgement, WitnessOutcome, guest_state_test, witness_outcome};
    use crate::fixture::parse_file;
    use repo_b_common::primitives::B256;

    /// El `state_test` de la EF vendoreado: un `CALL` con valor, en Cancun y
    /// en Prague, con su `secretKey` y el `stateRoot` que publicó la EF.
    fn vendoreado() -> Vec<crate::fixture::StateTest> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "fixtures/GeneralStateTests/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json",
        );
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => panic!("no se pudo leer {}: {e}", path.display()),
        };
        match parse_file(&raw) {
            Ok(tests) => tests,
            Err(e) => panic!("el fixture vendoreado tiene que parsear: {e}"),
        }
    }

    /// El witness del caso, tal como lo arma `witness_outcome`: sale del input
    /// que publicó (el guest lo vuelve a armar sin `keys` ni headers).
    fn caso(
        test: &crate::fixture::StateTest,
        case: &crate::fixture::PostCase,
    ) -> (repo_b_common::witness::ExecutionWitness, B256) {
        let WitnessOutcome::Executed(run) = witness_outcome(test, case) else {
            panic!(
                "{} [{}] tiene que ejecutar desde el witness",
                test.name, case.fork
            );
        };
        let Some(input) = run.input.as_deref() else {
            panic!("el caso trae secretKey: hay input");
        };
        let Ok(decodificado) = repo_b_guest::codec::decode_tx_input(input) else {
            panic!("el input del caso decodifica");
        };
        (decodificado.witness, decodificado.pre_state_root)
    }

    /// **`Mode::StateTest` contra un juez externo**: el guest, por `run_bytes`,
    /// publica el `stateRoot` que la EF publicó para cada fork del caso. Y la
    /// recíproca, con la razón exacta: con otro root esperado es un root
    /// distinto, y con el fixture declarando la tx inválida es una aceptación
    /// indebida.
    #[test]
    fn the_state_test_mode_publishes_the_root_the_ef_published() {
        let mut juzgados = 0usize;
        for test in vendoreado() {
            for case in &test.posts {
                let WitnessOutcome::Executed(run) = witness_outcome(&test, case) else {
                    panic!("{} [{}] tiene que ejecutar", test.name, case.fork);
                };
                assert_eq!(
                    run.guest,
                    Ok(GuestJudgement::Matched),
                    "{} [{}]",
                    test.name,
                    case.fork
                );
                let (witness, root) = caso(&test, case);
                let mut otro = case.clone();
                otro.state_root = B256::repeat_byte(0x42);
                let Err(e) = guest_state_test(&test, &otro, &witness, root) else {
                    panic!("otro root esperado tiene que fallar");
                };
                assert!(
                    e.starts_with("el guest publicó post_state_root ")
                        && e.ends_with(&format!("y el fixture dice {}", otro.state_root)),
                    "{e}"
                );
                let mut invalida = case.clone();
                invalida.expect_exception = Some("TransactionException.X".to_owned());
                let Err(e) = guest_state_test(&test, &invalida, &witness, root) else {
                    panic!("una tx declarada inválida y aceptada tiene que fallar");
                };
                assert!(
                    e.starts_with(
                        "el guest aceptó una tx que el fixture declara inválida (TransactionException.X)"
                    ),
                    "{e}"
                );
                juzgados = juzgados.saturating_add(1);
            }
        }
        assert!(juzgados >= 2, "Cancun y Prague: {juzgados}");
    }

    /// **Un `txbytes` firmado para otra cadena**: el guest lo rechaza en la
    /// firma, y eso es un rechazo como el fixture solo si el `expectException`
    /// nombra una razón de firma. Con otra razón, o sin `expectException`,
    /// falla.
    #[test]
    fn a_txbytes_with_another_chain_id_is_rejected_for_its_reason() {
        let Some(test) = vendoreado().into_iter().next() else {
            panic!("el fixture trae un test");
        };
        let Some(case) = test.posts.first() else {
            panic!("el test trae casos");
        };
        let (witness, root) = caso(&test, case);
        let ajena = match crate::fixture::signed_transaction_for(
            &test,
            case,
            test.chain_id.saturating_add(1),
        )
        .map(|t| t.encode_2718())
        {
            Ok(Ok(bytes)) => bytes,
            otro => panic!("la tx se firma para otra cadena: {otro:?}"),
        };
        let con = |expect: Option<&str>| {
            let mut c = case.clone();
            c.tx_bytes = Some(ajena.clone().into());
            c.expect_exception = expect.map(str::to_owned);
            guest_state_test(&test, &c, &witness, root)
        };
        assert_eq!(
            con(Some("TransactionException.INVALID_CHAINID")),
            Ok(GuestJudgement::Rejected)
        );
        let Err(e) = con(Some("TransactionException.INTRINSIC_GAS_TOO_LOW")) else {
            panic!("otra razón no explica un rechazo de firma");
        };
        assert!(
            e.starts_with("rechazo por otra razón: el guest dio Signature("),
            "{e}"
        );
        let Err(e) = con(None) else {
            panic!("sin expectException es una tx válida rechazada");
        };
        assert!(e.starts_with("el guest rechazó una tx válida: "), "{e}");
    }

    /// **Un `txbytes` que no decodifica** se rechaza antes del guest, y cuenta
    /// como el rechazo del fixture solo si el `expectException` nombra una
    /// razón de envelope.
    #[test]
    fn an_undecodable_txbytes_is_rejected_for_its_reason() {
        let Some(test) = vendoreado().into_iter().next() else {
            panic!("el fixture trae un test");
        };
        let Some(case) = test.posts.first() else {
            panic!("el test trae casos");
        };
        let (witness, root) = caso(&test, case);
        let con = |expect: Option<&str>| {
            let mut c = case.clone();
            // `0x7f` no es un tipo de tx ni la cabecera de una lista.
            c.tx_bytes = Some(vec![0x7fu8, 0x00].into());
            c.expect_exception = expect.map(str::to_owned);
            guest_state_test(&test, &c, &witness, root)
        };
        assert_eq!(
            con(Some("TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW")),
            Ok(GuestJudgement::Rejected)
        );
        assert_eq!(
            con(Some("TransactionException.INVALID_CHAINID")),
            Err(
                "rechazo por otra razón: el txbytes no decodifica (byte de tipo de tx desconocido) \
                 y el fixture espera `TransactionException.INVALID_CHAINID`"
                    .to_owned()
            )
        );
        assert_eq!(
            con(None),
            Err(
                "el txbytes de una tx válida no decodifica: byte de tipo de tx desconocido"
                    .to_owned()
            )
        );
    }
}

#[cfg(test)]
mod tests_interno {
    use super::guest_state_test;

    /// **Un error interno nunca es el rechazo del fixture.** Sin nodos de
    /// estado en el witness, el guest no puede leer al remitente: eso es un
    /// witness insuficiente, no una tx inválida, aunque el fixture declare una.
    #[test]
    fn an_internal_error_is_never_the_rejection_the_fixture_expects() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "fixtures/GeneralStateTests/NonZeroValue_TransactionCALL_ToNonNonZeroBalance.json",
        );
        let Ok(raw) = std::fs::read_to_string(&path) else {
            panic!("no se pudo leer {}", path.display());
        };
        let Ok(tests) = crate::fixture::parse_file(&raw) else {
            panic!("el fixture vendoreado tiene que parsear");
        };
        let Some(test) = tests.first() else {
            panic!("el fixture trae un test");
        };
        let Some(case) = test.posts.first() else {
            panic!("el test trae casos");
        };
        let mut c = case.clone();
        c.expect_exception = Some("TransactionException.INTRINSIC_GAS_TOO_LOW".to_owned());
        let vacio = repo_b_common::witness::ExecutionWitness::default();
        let root = crate::runner::compute_state_root(&test.pre);
        let Err(e) = guest_state_test(test, &c, &vacio, root) else {
            panic!("un witness vacío no es el rechazo del fixture");
        };
        assert!(
            e.starts_with("rechazo por otra razón: el guest dio Vm { message: \"internal error: "),
            "{e}"
        );
    }
}
