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
/// que despacha el motor (`0x01..=0x11`, sin huecos desde 2.8f).
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

/// El modo con el que se ejecuta cada caso. `Full` y no un peldaño ablacionado:
/// lo que se contrasta es el bloque entero, root incluido.
pub const MODO: Mode = Mode::Full;

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
/// movió de 1 317 160 a 1 354 480 B. El patch de `k256`/`sha2` sigue siendo el
/// mismo y sigue aplicando —redirige el crate en todo el grafo, sin importar
/// quién lo depende—, lo que cambió es el código del guest.
pub const ELF_CON_PATCH_BYTES: u64 = 1_354_480;

/// Verifica que el ELF que se le va a dar al emulador sea el parcheado.
///
/// # Errors
/// Si el tamaño no es el medido. `esperado` permite correr a propósito con otro
/// ELF (la mutación M1), que es la única razón por la que este chequeo se puede
/// mover — nunca para que el gate pase.
pub fn verificar_elf(path: &Path, esperado: u64) -> Result<u64, String> {
    let n = std::fs::metadata(path)
        .map_err(|e| format!("no puedo leer {}: {e}", path.display()))?
        .len();
    if n == esperado {
        Ok(n)
    } else {
        Err(format!(
            "el ELF {} mide {n} B y el esperado es {esperado} B — si es el de antes del patch, \
             el nivel 3 estaría midiendo el camino genérico contra sí mismo",
            path.display()
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
    pub ciclos_totales: u64,
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
            Ok((pv, reporte)) => {
                r.ciclos_totales = r.ciclos_totales.saturating_add(reporte.total_num_cycles);
                match Journal::decode(pv.as_ref()) {
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
                }
            }
            Err(e) => {
                // **Con dientes**: un caso que no se pudo correr suma a
                // `fallando`. Clusterizarlo sin sumar sería un eje que sale
                // verde habiendo ejecutado menos de lo que dice.
                r.no_corrieron = r.no_corrieron.saturating_add(1);
                r.detalle
                    .push((caso.label.clone(), format!("no ejecutó: {}", head(&e))));
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

/// Dónde vive el ELF por default.
#[must_use]
pub fn elf_por_default() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/guest-sp1.elf")
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

    /// La máscara sale de la tabla: 16 de los 17 precompiles.
    #[test]
    fn the_mask_covers_every_precompile_but_one() {
        assert_eq!(PRECOMPILES.len(), 17);
        assert_eq!(mascara_cripto(false).count_ones(), 16);
        assert_eq!(mascara_cripto(true).count_ones(), 17);
    }
}
