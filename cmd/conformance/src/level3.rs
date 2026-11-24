//! Modo `--level3`: el corpus de criptografía pesada **adentro del emulador**.
//!
//! # Por qué existe, y qué es lo único que puede contestar
//!
//! El nivel 2 del gate escalonado corre **nativo**, y ahí la librería
//! parcheada de un backend **cae al algoritmo genérico**: la instrucción que le
//! pide al circuito resolver la operación por hardware se emite **solo adentro
//! del zkVM**. Un verde de nivel 2 dice *"cambiar de librería no cambió la
//! semántica"* y **nada** sobre el camino que efectivamente se prueba. Ningún
//! gate nativo puede decir más — no por descuido, sino por construcción.
//!
//! Este eje es el único escalón que ve ese camino: arma el input de guest de
//! cada caso del corte, lo pasa por el `execute` del backend y contrasta el
//! journal publicado contra el del **mismo caso corrido nativo**.
//!
//! # El oráculo es la corrida nativa, no `revm`
//!
//! La pregunta es *"¿el camino acelerado calcula lo mismo que el genérico?"*,
//! así que cada caso es su propio oráculo: los mismos bytes de entrada, el
//! mismo código, dos lugares donde correrlo. Meter a `revm` acá contestaría
//! otra pregunta (la semántica del EVM), que es la que ya contestan los dos
//! ejes de EEST y el diferencial.
//!
//! # El corte es una REGLA sobre lo que el caso EJECUTA
//!
//! *"Entra todo caso cuya ejecución toca una precompile criptográfica."* No es
//! una lista escrita a mano ni una búsqueda de la dirección en el JSON del
//! caso: una dirección puede aparecer en el pre-state y no llamarse nunca, y un
//! caso puede llamar a una precompile desde bytecode que ningún grep ve. Quien
//! contesta es el motor, por el chokepoint de `precompiles::precompile_for`
//! (ver `repo_b_evm::precompiles::observe`).
//!
//! # Lo que un verde de acá NO dice
//!
//! Prueba **una** configuración en **un** backend, sobre **este** corpus. No
//! prueba la matriz de N configuraciones y no prueba que el circuito sea
//! correcto en general.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use repo_b_evm::precompiles::observe;
use repo_b_guest::journal::{Journal, Mode};

use crate::eest::{PINNED_TAG, cache_root, collect_json, head, short};
use crate::fixture::{self, spec_for_fork};
use crate::record::{WitnessOutcome, witness_outcome};

/// `IDENTITY` (`0x04`) **no entra al corte**: copia bytes, no es criptografía.
/// Dicho acá y no dejado implícito en una máscara escrita a mano — es la única
/// exclusión de la regla y por eso lleva su nombre.
pub const IDENTITY: u8 = 0x04;

/// Los `id` de precompile con su nombre, para el desglose. Es la misma tabla
/// que despacha el motor: `0x01..=0x11` sin huecos, más el `id` `0x12` de
/// `P256VERIFY`, cuya DIRECCIÓN (`0x0100`) rompe la contigüidad que estos `id`
/// conservan.
pub const PRECOMPILES: &[(u8, &str)] = &[
    (0x01, "ECRECOVER"),
    (0x02, "SHA256"),
    (0x03, "RIPEMD160"),
    (IDENTITY, "IDENTITY (no es cripto)"),
    (0x05, "MODEXP"),
    (0x06, "BN254_ADD"),
    (0x07, "BN254_MUL"),
    (0x08, "BN254_PAIRING"),
    (0x09, "BLAKE2F"),
    (0x0a, "KZG_POINT_EVALUATION"),
    (0x0b, "BLS12_G1_ADD"),
    (0x0c, "BLS12_G1_MSM"),
    (0x0d, "BLS12_G2_ADD"),
    (0x0e, "BLS12_G2_MSM"),
    (0x0f, "BLS12_PAIRING"),
    (0x10, "BLS12_MAP_FP_TO_G1"),
    (0x11, "BLS12_MAP_FP2_TO_G2"),
    // El `id` interno, NO la dirección: `P256VERIFY` vive en `0x0100` y el
    // motor la despacha por `0x12`. El corte se arma con `id`, así que lo que
    // va acá es el `id`.
    (0x12, "P256VERIFY"),
];

/// La máscara de la regla: **todo precompile menos `IDENTITY`**.
///
/// Se deriva de la tabla en vez de escribirse a mano para que agregar un
/// precompile no exija acordarse de este archivo: la regla es *"cripto"*, y la
/// única excepción se nombra.
#[must_use]
pub fn mascara_cripto(incluir_identity: bool) -> u32 {
    let mut m = 0u32;
    for (id, _) in PRECOMPILES {
        if *id == IDENTITY && !incluir_identity {
            continue;
        }
        if let Some(bit) = 1u32.checked_shl(u32::from(*id)) {
            m |= bit;
        }
    }
    m
}

/// El modo con el que se ejecuta cada caso. Un caso del corte es un `state_test`
/// —una tx sobre un pre-state, sin bloque—, así que va por `StateTest`: ejecuta la
/// tx entera y recomputa el root, sin afirmar nada sobre un bloque.
pub const MODO: Mode = Mode::StateTest;

/// Un caso del corte, con todo lo que hace falta para contrastarlo.
pub struct CasoDelCorte {
    pub label: String,
    /// El input del guest tal cual entra al zkVM.
    pub input: Vec<u8>,
    /// El journal de la corrida **nativa**: el oráculo.
    pub nativo: Journal,
    /// Qué precompiles resolvió el motor (bitmask por `id`).
    pub tocadas: u32,
}

/// Las direcciones de precompile criptográfico **tal como aparecen escritas en
/// el JSON de un fixture**. Existen para una sola cosa: medir cuánto se
/// equivoca la detección textual, que es la que el §3.2 rechaza.
#[must_use]
pub fn direcciones_textuales() -> Vec<String> {
    PRECOMPILES
        .iter()
        .filter(|(id, _)| *id != IDENTITY)
        .map(|(id, _)| format!("0x{:0>38}{id:02x}", ""))
        .collect()
}

/// Lo que el corte dejó medido.
#[derive(Default)]
pub struct Corte {
    pub casos: Vec<CasoDelCorte>,
    /// Cuántos casos del corte tocaron cada `id`.
    pub por_precompile: BTreeMap<u8, u32>,
    pub en_scope: u32,
    /// Casos que tocaron cripto pero de los que **no** se pudo armar un input
    /// de guest. No se saltean en silencio: se cuentan y se clusterizan.
    pub sin_input: u32,
    /// Casos que tocaron cripto y cuyo camino nativo **no produjo un journal**.
    /// Sin journal no hay oráculo, así que no se pueden contrastar — y por eso
    /// se cuentan aparte en vez de desaparecer del denominador.
    pub sin_oraculo: u32,
    pub clusters: BTreeMap<String, (u32, String)>,
    /// La tabla 2×2 contra la detección **textual**, indexada por
    /// `(!menciona) + 2·(!ejecuta)`: `[ambas, solo ejecutada, solo textual,
    /// ninguna]`. Solo se llena con `--comparar-textual`.
    pub textual: Option<[u32; 4]>,
}

impl Corte {
    fn anotar(&mut self, firma: String, ejemplo: &str) {
        let e = self.clusters.entry(firma).or_insert((0, String::new()));
        e.0 = e.0.saturating_add(1);
        if e.1.is_empty() {
            e.1 = ejemplo.to_owned();
        }
    }
}

/// Camina el corpus de `state_test` y arma el corte.
///
/// **El camino de ejecución no se reimplementa**: es `record::witness_outcome`,
/// el mismo que corren `--witness` y `--witness-eest`. Lo único propio de acá
/// es preguntarle al motor qué tocó y quedarse con los bytes del input, que ese
/// camino ya produce.
///
/// # Errors
/// Si el cache de EEST no está (fail-closed).
pub fn corte(mascara: u32, limite: Option<usize>, comparar_textual: bool) -> Result<Corte, String> {
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

    let mut corte = Corte::default();
    if comparar_textual {
        corte.textual = Some([0; 4]);
    }
    let direcciones = direcciones_textuales();
    for path in &files {
        let label = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(tests) = fixture::parse_file(&raw) else {
            continue;
        };
        // La detección textual es **de archivo**: es lo que puede ver un grep,
        // que no sabe qué caso de adentro llama a qué.
        let menciona = comparar_textual && direcciones.iter().any(|a| raw.contains(a.as_str()));
        for test in &tests {
            for case in &test.posts {
                if spec_for_fork(&case.fork).is_none() {
                    continue;
                }
                corte.en_scope = corte.en_scope.saturating_add(1);
                let case_label = format!("{label}::{} [{}]", short(&test.name), case.fork);

                // Vaciar antes: lo anotado por el caso anterior no puede
                // atribuirse a éste. `tomar` lee **y** vacía, justamente para
                // que no exista la forma de leer sin vaciar.
                let _ = observe::tomar();
                let outcome = witness_outcome(test, case);
                let tocadas = observe::tomar();
                let ejecuta = tocadas & mascara != 0;
                if let Some(t) = corte.textual.as_mut() {
                    t[usize::from(!menciona) + 2 * usize::from(!ejecuta)] += 1;
                }
                if !ejecuta {
                    continue;
                }
                for (id, _) in PRECOMPILES {
                    if tocadas & mascara & (1u32 << id) != 0 {
                        *corte.por_precompile.entry(*id).or_default() += 1;
                    }
                }

                let WitnessOutcome::Executed(run) = outcome else {
                    corte.sin_input = corte.sin_input.saturating_add(1);
                    corte.anotar(format!("sin input: {}", clase(&outcome)), &case_label);
                    continue;
                };
                let Some(input) = run.input else {
                    corte.sin_input = corte.sin_input.saturating_add(1);
                    corte.anotar(
                        "sin input: sin envelope construible".to_owned(),
                        &case_label,
                    );
                    continue;
                };

                let mut buf = Vec::with_capacity(input.len() + 1);
                buf.push(MODO.as_byte());
                buf.extend_from_slice(&input);
                match repo_b_guest::run_bytes(&buf) {
                    Ok(nativo) => corte.casos.push(CasoDelCorte {
                        label: case_label,
                        input: buf,
                        nativo,
                        tocadas,
                    }),
                    Err(e) => {
                        corte.sin_oraculo = corte.sin_oraculo.saturating_add(1);
                        corte.anotar(format!("sin oráculo: {}", head(e.0)), &case_label);
                    }
                }
                if let Some(n) = limite
                    && corte.casos.len() >= n
                {
                    return Ok(corte);
                }
            }
        }
    }
    Ok(corte)
}

/// Los nombres de los precompiles anotados en un bitmask. Una divergencia sin
/// esto sería un caso sin sospechoso.
#[must_use]
pub fn nombres(tocadas: u32) -> String {
    let mut v = Vec::new();
    for (id, nombre) in PRECOMPILES {
        if tocadas & (1u32 << id) != 0 {
            v.push(*nombre);
        }
    }
    v.join("+")
}

fn clase(outcome: &WitnessOutcome) -> &'static str {
    match outcome {
        WitnessOutcome::Executed(_) => "ejecutado",
        WitnessOutcome::NotTransparent { .. } => "no-transparente",
        WitnessOutcome::NeedsBlockHash => "necesita BLOCKHASH",
        WitnessOutcome::Mismatch { .. } => "otro veredicto desde el witness",
        WitnessOutcome::OutOfScope(_) => "fuera de scope",
    }
}

pub fn imprimir_corte(corte: &Corte) {
    eprintln!();
    eprintln!("== el corte: los casos que EJECUTAN una precompile criptográfica ==");
    eprintln!(
        "casos en scope {} | del corte {} | sin input {} | sin oráculo nativo {}",
        corte.en_scope,
        corte.casos.len(),
        corte.sin_input,
        corte.sin_oraculo
    );
    eprintln!("desglose por precompile (un caso puede tocar varias):");
    for (id, nombre) in PRECOMPILES {
        let n = corte.por_precompile.get(id).copied().unwrap_or(0);
        eprintln!("  0x{id:02x} {nombre:<24} {n:>7}");
    }
    if let Some([ambas, solo_ejec, solo_texto, ninguna]) = corte.textual {
        eprintln!();
        eprintln!("== la regla EJECUTADA contra la detección TEXTUAL ==");
        eprintln!("  las dos                       {ambas:>7}");
        eprintln!("  SOLO la ejecutada             {solo_ejec:>7}  (el JSON no la menciona)");
        eprintln!("  SOLO la textual               {solo_texto:>7}  (menciona y nunca la llama)");
        eprintln!("  ninguna                       {ninguna:>7}");
    }
    if corte.clusters.is_empty() {
        return;
    }
    eprintln!("casos del corte que no se pueden contrastar:");
    for (firma, (n, ej)) in &corte.clusters {
        eprintln!("  {n:>7}  {firma}");
        eprintln!("           ej: {ej}");
    }
}

/// El tamaño del ELF **con** el patch de `k256`/`sha2`.
///
/// Se afirma y no se supone: si el emulador corriera el ELF de antes del patch,
/// el nivel 3 mediría el camino genérico contra sí mismo y saldría verde sin
/// haber visto nunca el camino acelerado — que es exactamente lo que este
/// escalón existe para ver.
/// Cambió cuando el motor pasó a hablar por el seam `Crypto`: el ELF se
/// movió de 1 317 160 a 1 354 480 B. El patch sigue siendo el mismo y sigue
/// aplicando —redirige el crate en todo el grafo, sin importar quién lo
/// depende—, lo que cambió es el código del guest.
///
/// Y se movió otra vez a **1 393 184 B** con `P256VERIFY`: el motor suma el
/// precompile y el crate `p256` (que el guest de SP1 además parchea, así que
/// son **tres** los redirigidos), y el KAT suma dos casos de P-256. La
/// aserción se ganó su lugar en esa corrida: el ELF que estaba en `target/`
/// era de **otra rama** y no tenía Osaka adentro, así que los 3 135 casos de
/// Osaka del corte salían con `exit code 1` — un número que sin esta guarda se
/// habría leído como un problema del slice.
///
/// Y a **1 386 128 B** con `ere` 0.20.0 (SP1 v6.9.0): el runtime nuevo del
/// backend entra al ELF por `ere-platform-sp1` y `libzkevm`, y el patch es el
/// mismo (los tres tags y sus commits, verificados contra el `Cargo.lock` de
/// SP1).
///
/// **Y lo que este número separa es más chico de lo que su nombre sugiere.**
/// Un pin de TAMAÑO distingue este ELF del de antes del patch, que mide otra
/// cosa; **no** distingue dos ELFs del mismo guest compilados con dos versiones
/// del runtime del backend. Está medido: subir el runtime de `ere` 0.16.2 a
/// 0.18.0 cambió el `sha256` del ELF de SP1 y lo dejó en exactamente el mismo
/// tamaño, sin que una sola función cambiara de tamaño. O sea que esta
/// aserción afirma "no es el ELF sin patch" y no "es este ELF".
///
/// Y a **1 524 224 B** con el input v2 (el bloque validado contra su padre), el
/// journal v2 de 171 B y los forks hasta BPO2, compilado en una caja x86_64 nativa.
pub const ELF_CON_PATCH_BYTES: u64 = 1_524_224;

/// El `sha256` del ELF **con** el patch, el que el nivel 3 tiene que correr.
///
/// Existe porque el tamaño no alcanza: dos ELFs del mismo guest compilados
/// contra dos runtimes del backend midieron exactamente lo mismo y tenían otro
/// hash. Este pin sí afirma "es este ELF". Se mueve cuando cambia el guest, el
/// patch o el runtime del backend, y solo con el valor medido del ELF que
/// compiló el backend (`zkvm compile --backend sp1`).
pub const ELF_CON_PATCH_SHA256: &str =
    "946b1d8e5db242c6d2be3742ae3624b632077aa989b554898dcfc2e5ed576f12";

/// El tamaño y el `sha256` del ELF de OpenVM que corre el nivel 3. El guest de
/// OpenVM no parchea ningún crate: corre la criptografía de referencia, así que
/// lo que su nivel 3 contesta no es "el camino acelerado calcula lo mismo" sino
/// "este zkVM ejecuta el mismo programa que la corrida nativa" —la pregunta que
/// caza una miscompilación del backend—.
pub const ELF_OPENVM_BYTES: u64 = 8_320_016;
/// Ver [`ELF_OPENVM_BYTES`].
pub const ELF_OPENVM_SHA256: &str =
    "eb1f9641d314a9bacdde0e2dff4650898bcd6be89162e1e0c390c7ff363a168e";

/// El tamaño y el `sha256` del ELF de ZisK que corre el nivel 3. Como el de
/// OpenVM, sin patch: ver [`ELF_OPENVM_BYTES`].
pub const ELF_ZISK_BYTES: u64 = 1_417_408;
/// Ver [`ELF_ZISK_BYTES`].
pub const ELF_ZISK_SHA256: &str =
    "9c3aff6cc38b5d5687428d2877c49281c6348ddecc628a5012e720f12fa8810b";

/// El tamaño y el `sha256` del ELF de Pico que corre el nivel 3. Como el de
/// OpenVM, sin patch: ver [`ELF_OPENVM_BYTES`]. Sale del compilador Docker de
/// `ere`, que monta el árbol en una ruta fija: compilado desde otra ruta el
/// binario cambia (las dependencias por ruta entran en `-C metadata`).
pub const ELF_PICO_BYTES: u64 = 1_444_848;
/// Ver [`ELF_PICO_BYTES`].
pub const ELF_PICO_SHA256: &str =
    "134129922ff0e743b6e5c5b4b463c900aa65a55aa12f18fb59b2f0a6275db61c";

/// El backend que corre el corte. **Fail-closed**: un nombre desconocido no
/// cae en el default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sp1,
    OpenVm,
    Zisk,
    Pico,
}

impl Backend {
    #[must_use]
    pub fn parse(nombre: &str) -> Option<Self> {
        match nombre {
            "sp1" => Some(Self::Sp1),
            "openvm" => Some(Self::OpenVm),
            "zisk" => Some(Self::Zisk),
            "pico" => Some(Self::Pico),
            _ => None,
        }
    }

    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Self::Sp1 => "sp1",
            Self::OpenVm => "openvm",
            Self::Zisk => "zisk",
            Self::Pico => "pico",
        }
    }

    /// El tamaño y el `sha256` pineados del ELF de este backend.
    #[must_use]
    pub const fn pin(self) -> (u64, &'static str) {
        match self {
            Self::Sp1 => (ELF_CON_PATCH_BYTES, ELF_CON_PATCH_SHA256),
            Self::OpenVm => (ELF_OPENVM_BYTES, ELF_OPENVM_SHA256),
            Self::Zisk => (ELF_ZISK_BYTES, ELF_ZISK_SHA256),
            Self::Pico => (ELF_PICO_BYTES, ELF_PICO_SHA256),
        }
    }

    /// Qué camino criptográfico lleva el ELF, para el reporte.
    #[must_use]
    pub const fn que_corre(self) -> &'static str {
        match self {
            Self::Sp1 => "el ELF CON el patch de `k256`/`p256`/`sha2`",
            Self::OpenVm | Self::Zisk | Self::Pico => {
                "el guest con la criptografía de referencia, sin patch"
            }
        }
    }

    /// Dónde vive el ELF de este backend por default.
    #[must_use]
    pub fn elf_por_default(self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../target/guest-{}.elf", self.nombre()))
    }
}

/// El `sha256` de unos bytes, en hex minúscula.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            // Escribir en un `String` no falla.
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Verifica que el ELF que se le va a dar al emulador sea el parcheado: el
/// tamaño Y el `sha256`.
///
/// # Errors
/// Si el tamaño o el hash no son los medidos. `esperado` y `sha_esperado`
/// permiten correr a propósito con otro ELF (la mutación M1), que es la única
/// razón por la que este chequeo se puede mover — nunca para que el gate pase.
pub fn verificar_elf(path: &Path, esperado: u64, sha_esperado: &str) -> Result<u64, String> {
    if sha_esperado.is_empty() {
        return Err(format!(
            "no hay pin para {}: un ELF sin pinear no se corre",
            path.display()
        ));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("no puedo leer {}: {e}", path.display()))?;
    let n = u64::try_from(bytes.len())
        .map_err(|_| format!("el ELF {} no entra en un u64", path.display()))?;
    if n != esperado {
        return Err(format!(
            "el ELF {} mide {n} B y el esperado es {esperado} B — si es el de antes del patch, \
             el nivel 3 estaría midiendo el camino genérico contra sí mismo",
            path.display()
        ));
    }
    let sha = sha256_hex(&bytes);
    if !sha.eq_ignore_ascii_case(sha_esperado) {
        return Err(format!(
            "el ELF {} mide lo esperado pero su sha256 es {sha} y el pineado es {sha_esperado} \
             — mismo tamaño no es mismo ELF",
            path.display()
        ));
    }
    Ok(n)
}

/// **Las fuentes del guest son las de los ELF pineados.** El pin dice "es ESTE
/// binario"; esto dice que ese binario sigue saliendo del árbol. Lo decide
/// `scripts/guest-sources-digest.sh --check` —una sola implementación del
/// digest para el nivel 3 y la receta del nivel 4—, contra el digest que se
/// registró al pinear.
///
/// # Errors
/// Si las fuentes cambiaron después del pin (con el reporte del script), o si
/// el script no se puede correr.
pub fn fuentes_del_guest_al_dia() -> Result<String, String> {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/guest-sources-digest.sh");
    let salida = std::process::Command::new("bash")
        .arg(&script)
        .arg("--check")
        .output()
        .map_err(|e| format!("no pude correr {}: {e}", script.display()))?;
    let texto = String::from_utf8_lossy(&salida.stdout).into_owned();
    if salida.status.success() {
        Ok(texto)
    } else {
        Err(format!(
            "{texto}{}",
            String::from_utf8_lossy(&salida.stderr)
        ))
    }
}

/// El resultado de la corrida entera.
#[derive(Default)]
pub struct Resultado {
    pub coinciden: u32,
    pub divergen: u32,
    pub no_corrieron: u32,
    /// Cada divergencia con nombre: son pocas por definición y cada una es un
    /// hallazgo sobre el backend, no una línea de un cluster.
    pub detalle: Vec<(String, String)>,
}

impl Resultado {
    #[must_use]
    pub fn fallando(&self) -> u32 {
        self.divergen.saturating_add(self.no_corrieron)
    }
}

/// Corre el corte por el emulador y contrasta cada journal.
///
/// El backend se levanta **una sola vez** para todo el corte: el arranque
/// cuesta ~40-70 s y una instancia por caso volvería el eje inviable.
pub fn contrastar<E: repo_b_prover::Execute + ?Sized>(zkvm: &E, corte: &Corte) -> Resultado {
    let mut r = Resultado::default();
    let t0 = Instant::now();
    for (i, caso) in corte.casos.iter().enumerate() {
        match zkvm.execute_raw(&repo_b_prover::Input::new().with_stdin(caso.input.clone())) {
            // **Este eje no mide costo, y llamar al estimador sería otra
            // corrida por caso.** Su gate es el journal: que lo que el zkVM
            // publica sea lo mismo que la corrida nativa publicó. Un número de
            // costo acá nunca fue gate, y pagarlo 7 346 veces por una columna
            // que nadie mira es trabajo sin evidencia.
            Ok((pv, _duracion)) => match Journal::decode(pv.as_ref()) {
                Some(adentro) if adentro == caso.nativo => {
                    r.coinciden = r.coinciden.saturating_add(1);
                }
                Some(adentro) => {
                    r.divergen = r.divergen.saturating_add(1);
                    r.detalle.push((
                        caso.label.clone(),
                        format!(
                            "[{}] adentro {adentro:?} | nativo {:?}",
                            nombres(caso.tocadas),
                            caso.nativo
                        ),
                    ));
                }
                None => {
                    r.no_corrieron = r.no_corrieron.saturating_add(1);
                    r.detalle.push((
                        caso.label.clone(),
                        format!("publicó {} bytes que no son un journal", pv.as_ref().len()),
                    ));
                }
            },
            Err(e) => {
                // **Con dientes**: un caso que no se pudo correr suma a
                // `fallando`. Clusterizarlo sin sumar sería un eje que sale
                // verde habiendo ejecutado menos de lo que dice. El error va
                // ENTERO: la causa suele estar después del primer `:`, y un
                // KNOWN sin su causa a la vista no se puede juzgar.
                r.no_corrieron = r.no_corrieron.saturating_add(1);
                r.detalle
                    .push((caso.label.clone(), format!("no ejecutó: {e}")));
            }
        }
        if i % 100 == 99 {
            eprintln!(
                "  [{}/{}] {} coinciden, {} divergen, {} no corrieron — {:?}",
                i + 1,
                corte.casos.len(),
                r.coinciden,
                r.divergen,
                r.no_corrieron,
                t0.elapsed()
            );
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::{IDENTITY, PRECOMPILES, mascara_cripto};

    /// **`IDENTITY` no entra al corte, y eso se afirma.** Es la única excepción
    /// de la regla; si entrara, el corte mediría casos que no tienen nada de
    /// criptográfico y el número diría de más.
    #[test]
    fn identity_is_not_part_of_the_crypto_cut() {
        let m = mascara_cripto(false);
        assert_eq!(m & (1 << IDENTITY), 0);
        assert_ne!(m & (1 << 0x01), 0, "ECRECOVER sí es cripto");
        assert_ne!(m & (1 << 0x11), 0, "la última BLS también");
    }

    /// La máscara sale de la tabla: todos los precompiles menos uno.
    #[test]
    fn the_mask_covers_every_precompile_but_one() {
        assert_eq!(PRECOMPILES.len(), 18);
        assert_eq!(mascara_cripto(false).count_ones(), 17);
        assert_eq!(mascara_cripto(true).count_ones(), 18);
    }

    /// El hash se calcula bien: vector conocido de FIPS 180-2.
    #[test]
    fn sha256_hex_matches_the_known_vector() {
        assert_eq!(
            super::sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// **Mismo tamaño no es mismo ELF.** Un archivo del tamaño pineado pero con
    /// otro contenido tiene que fallar por el hash, y el mensaje lo dice.
    #[test]
    fn same_size_other_bytes_fails_on_the_hash() {
        let dir = std::env::temp_dir().join(format!("l3-elf-{}", std::process::id()));
        assert!(std::fs::create_dir_all(&dir).is_ok());
        let path = dir.join("elf.bin");
        let bytes = b"abc";
        assert!(std::fs::write(&path, bytes).is_ok());
        let ok = super::verificar_elf(&path, 3, &super::sha256_hex(bytes));
        assert_eq!(ok, Ok(3));
        let otro = super::verificar_elf(&path, 3, super::ELF_CON_PATCH_SHA256);
        assert!(
            otro.as_ref().is_err_and(|e| e.contains("sha256")),
            "{otro:?}"
        );
        let tam = super::verificar_elf(&path, 4, &super::sha256_hex(bytes));
        assert!(
            tam.as_ref().is_err_and(|e| e.contains("mide 3 B")),
            "{tam:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **El chequeo de las fuentes del guest corre y da un veredicto con
    /// nombre**: al día o desactualizados. Cualquier otra salida (el script o
    /// el registro rotos) es un chequeo que no está midiendo. No exige "al
    /// día": eso lo exigen el nivel 3 y la receta, que son los que corren un
    /// ELF pineado.
    #[test]
    fn the_guest_sources_check_names_its_verdict() {
        match super::fuentes_del_guest_al_dia() {
            Ok(r) => assert!(r.contains("pines al día"), "{r}"),
            Err(r) => assert!(r.contains("PINES DESACTUALIZADOS"), "{r}"),
        }
    }

    /// El valor de `NOMBRE=valor` en la receta.
    fn valor_de(texto: &str, nombre: &str) -> Option<String> {
        texto
            .lines()
            .find_map(|l| l.strip_prefix(nombre).and_then(|r| r.strip_prefix('=')))
            .map(|v| v.trim().to_owned())
    }

    /// **Los pins de la receta y los del nivel 3 son los mismos.** Viven en dos
    /// archivos porque los lee un script de bash y un binario; si se separaran,
    /// uno de los dos estaría asertando un ELF que el otro ya no corre.
    #[test]
    fn the_recipe_pins_are_the_level3_pins() {
        let ruta =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/prove-block.sh");
        let texto = std::fs::read_to_string(&ruta).unwrap_or_default();
        assert!(!texto.is_empty(), "no pude leer {}", ruta.display());
        for (b, bytes, sha) in [
            (
                super::Backend::Sp1,
                "ELF_BYTES_ESPERADOS",
                "ELF_SHA256_ESPERADO",
            ),
            (
                super::Backend::OpenVm,
                "ELF_OPENVM_BYTES_ESPERADOS",
                "ELF_OPENVM_SHA256_ESPERADO",
            ),
            (
                super::Backend::Zisk,
                "ELF_ZISK_BYTES_ESPERADOS",
                "ELF_ZISK_SHA256_ESPERADO",
            ),
            (
                super::Backend::Pico,
                "ELF_PICO_BYTES_ESPERADOS",
                "ELF_PICO_SHA256_ESPERADO",
            ),
        ] {
            let (pin_bytes, pin_sha) = b.pin();
            assert_eq!(
                valor_de(&texto, bytes),
                Some(pin_bytes.to_string()),
                "{}: tamaño",
                b.nombre()
            );
            assert_eq!(
                valor_de(&texto, sha),
                Some(pin_sha.to_string()),
                "{}: sha256",
                b.nombre()
            );
        }
    }

    /// Un backend desconocido no cae en el default, y cada uno tiene su ELF.
    #[test]
    fn the_backend_is_parsed_fail_closed() {
        for b in [
            super::Backend::Sp1,
            super::Backend::OpenVm,
            super::Backend::Zisk,
            super::Backend::Pico,
        ] {
            assert_eq!(super::Backend::parse(b.nombre()), Some(b));
            assert!(
                b.elf_por_default()
                    .ends_with(format!("guest-{}.elf", b.nombre()))
            );
        }
        assert_eq!(super::Backend::parse("SP1"), None);
        assert_eq!(super::Backend::parse("risc0"), None);
    }
}
