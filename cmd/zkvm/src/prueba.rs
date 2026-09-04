//! Correr **un** backend de punta a punta y contrastarlo contra su oráculo.
//!
//! # Por qué esto vive aparte de la línea de comandos
//!
//! Hay dos consumidores del mismo trabajo: `prove`, que corre un backend y
//! reporta; y `multiproof`, que corre dos y además los cruza. Si cada uno
//! escribiera su propio contraste, el día que uno se afloje el otro seguiría
//! verde y nadie sabría cuál de los dos es el que vale. Acá vive **una sola**
//! implementación del contraste, y los dos caminos la llaman.
//!
//! # Qué es una falla y qué es no-poder-correr
//!
//! La distinción no es cosmética, es la que hace que el cruce entre backends
//! signifique algo:
//!
//! * **`Err`** — este backend no produjo nada que se pueda cruzar: no arrancó,
//!   no ejecutó, no probó, o su prueba no verificó. No hay journal *probado*.
//! * **`fallas`** — hay journal probado, y algo de lo que afirma no coincide
//!   con el oráculo. Se acumulan y **no cortan**: el cruce se hace igual, y el
//!   exit code agrega al final.
//!
//! Cruzar el journal de una corrida que solo *ejecutó* sería una afirmación
//! más débil disfrazada de la misma: lo que se quiere contrastar es lo que cada
//! backend **probó**.
//!
//! # Los contrastes se evalúan TODOS antes de fallar
//!
//! La primera versión cortaba en el primer desacuerdo. El KAT ya mostró por qué
//! eso es defectuoso: un chequeo que solo corre cuando el otro pasa no está
//! probado por la corrida que encuentra el bug.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ere_dockerized::{DockerizedzkVM, EncodedProof};
use repo_b_common::primitives::B256;
use repo_b_prover::{Elf, Journal, Mode, ProverResource};

use crate::{Backend, CASO, MODO_QUE_ENTRA, TECHO_MEDIDO, config_backend, leer_journal_esperado};

/// Lo que produjo `prove` y `verify` de un backend.
#[derive(Debug, Clone)]
pub(crate) struct Prueba {
    pub bytes: usize,
    pub prove: Duration,
    pub verify: Duration,
    /// Dónde quedó la prueba en disco, si se pidió guardarla.
    pub archivo: Option<PathBuf>,
}

/// Una corrida completa de un backend.
#[derive(Debug, Clone)]
pub(crate) struct Corrida {
    /// Lo que `ere` dice que levantó. No se hardcodea: la evidencia tiene que
    /// decir qué SDK produjo el resultado, no cuál creíamos.
    pub sdk: String,
    pub modo: Mode,
    /// **El journal PROBADO** (o el ejecutado, si se corrió sin prueba).
    pub journal: Journal,
    /// Cuántos bytes públicos publicó el backend. **No es el largo del
    /// journal**: OpenVM rellena con ceros hasta 256 y SP1 no rellena.
    pub publicos: usize,
    pub ciclos: u64,
    pub execute: Duration,
    pub prueba: Option<Prueba>,
    /// Si `execute`, `prove` y `verify` publicaron los mismos bytes. `None`
    /// cuando no se probó. **Campo y no una inferencia sobre `fallas`**: leerlo
    /// de la lista de errores ataría la evidencia al texto de un mensaje.
    pub tres_puntas: Option<bool>,
    /// Desacuerdos con el oráculo. Vacío = verde.
    pub fallas: Vec<String>,
}

/// Qué se le pide a una corrida.
pub(crate) struct Opciones<'a> {
    /// `false` ⇒ solo `execute`. El cruce entre backends se puede hacer igual
    /// y sale en segundos en vez de horas — lo que se pierde es que lo que se
    /// cruza sea lo *probado*, y por eso se dice en el reporte.
    pub probar: bool,
    /// Los public values de OTRA corrida en el lugar de los de `verify`. Si la
    /// aserción de las tres puntas fuera decorativa, esto pasaría igual.
    pub mutar_public_values: bool,
    /// Dónde escribir la prueba. `None` ⇒ no se escribe.
    pub guardar_prueba: Option<PathBuf>,
    /// **Verificar una prueba AJENA en vez de la propia.** Una prueba de otro
    /// sistema no tiene por qué verificar acá; si verificara, `verify` no
    /// estaría atado al programa que se probó.
    pub verificar_ajena: Option<(&'a str, &'a EncodedProof)>,
}

/// El KAT nativo, que es el oráculo del modo `Kat`.
///
/// # Errors
/// Si el KAT falla nativamente el defecto es del KAT y no del backend; y un
/// digest en cero sería un oráculo trivial —dos backends que publicaran cero
/// coincidirían sin haber computado nada—, así que también se rechaza.
pub(crate) fn kat_nativo() -> Result<repo_b_guest::kat::Resultado, Box<dyn std::error::Error>> {
    let nativo = repo_b_guest::kat::run();
    if !nativo.paso() {
        return Err(format!(
            "el KAT falla NATIVAMENTE (bitmask {:#x}): el defecto es del KAT, no del backend",
            nativo.fallas
        )
        .into());
    }
    if nativo.digest == B256::ZERO {
        return Err(
            "el digest del KAT nativo es CERO: sería un oráculo que dos backends pueden \
             satisfacer sin computar nada"
                .into(),
        );
    }
    Ok(nativo)
}

/// El journal que **este modo debe producir**, sea cual sea el backend.
///
/// Un oráculo y dos pruebas: el modo decide de dónde sale el valor esperado
/// —la corrida nativa del KAT, o el caso congelado que el harness computó
/// afuera del zkVM—, y no el backend. Un oráculo por backend haría que
/// "coinciden" quisiera decir dos cosas distintas.
///
/// # Errors
/// Si el oráculo no se puede construir (el KAT falla nativo, el fixture no se
/// lee).
pub(crate) fn journal_debido(
    mode: Mode,
    root: &Path,
) -> Result<Journal, Box<dyn std::error::Error>> {
    if mode == Mode::Kat {
        let nativo = kat_nativo()?;
        return Ok(Journal {
            mode,
            pre_state_root: repo_b_guest::kat::KAT_MAGIC,
            // El KAT publica su digest acá y su bitmask de fallas en el campo
            // de abajo: cero es "los CASOS pasaron".
            post_state_root: nativo.digest,
            output_digest: B256::ZERO,
        });
    }

    let esperado = leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), None)?;
    // Un modo ablacionado publica ceros en lo que no computó. Contrastar los
    // tres campos siempre daría un FAIL que no significa nada; no contrastar
    // ninguno sería el `verify` decorativo que esto existe para evitar.
    Ok(match mode {
        Mode::Full => Journal { mode, ..esperado },
        Mode::NoRoot | Mode::NoTxs => Journal {
            mode,
            pre_state_root: esperado.pre_state_root,
            post_state_root: B256::ZERO,
            output_digest: esperado.output_digest,
        },
        _ => Journal::empty(mode),
    })
}

/// El buffer que se le da al guest en este modo.
///
/// El KAT **no mira el cuerpo del input**: su razón de ser es contestar si la
/// aritmética de este ELF es correcta, y atarlo a decodificar un bloque lo
/// haría depender de una pieza que puede estar rota por lo mismo que se
/// investiga.
fn bloque_del_modo(mode: Mode, root: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if mode == Mode::Kat {
        return Ok(Vec::new());
    }
    Ok(std::fs::read(root.join(CASO).join("block-input.bin"))?)
}

/// Corre un backend de punta a punta y contrasta lo que publicó.
///
/// # La aserción, y por qué son TRES puntas y no dos
///
/// `execute` dice qué publica el guest cuando corre. `prove` dice qué publica
/// la prueba. `verify` dice qué acepta el verificador. Si solo se contrastaran
/// las dos últimas, una prueba de otro input pasaría siempre que fuera
/// internamente consistente; con `execute` adentro, lo que se afirma es que la
/// prueba es de ESTA corrida.
///
/// # Errors
/// Ver el doc del módulo: `Err` es "no hay journal que cruzar".
pub(crate) fn correr_backend(
    backend: Backend,
    elf_path: &Path,
    mode: Mode,
    opciones: &Opciones<'_>,
) -> Result<Corrida, Box<dyn std::error::Error>> {
    let root = crate::repo_root();
    let elf = Elf(std::fs::read(elf_path)?);
    let bloque = bloque_del_modo(mode, &root)?;
    let debido = journal_debido(mode, &root)?;

    eprintln!("[zkvm] levantando el zkVM…");
    let t = Instant::now();
    let zkvm = DockerizedzkVM::new(backend.kind(), elf, ProverResource::Cpu, config_backend())?;
    let sdk = format!("{} {}", zkvm.name(), zkvm.sdk_version());
    eprintln!("[zkvm] arriba en {:?} — {sdk}", t.elapsed());

    let input = repo_b_prover::zkvm_input(mode, &bloque);
    let mut fallas: Vec<String> = Vec::new();

    println!("\n=== execute ===");
    let t = Instant::now();
    let (pv_execute, reporte) = zkvm.execute(&input)?;
    let execute = t.elapsed();
    println!(
        "modo {mode:?}: {} ciclos en {execute:?} — {} bytes públicos",
        reporte.total_num_cycles,
        pv_execute.as_ref().len()
    );

    // --- el camino sin prueba ------------------------------------------------
    if !opciones.probar {
        let journal = decodificar(pv_execute.as_ref())?;
        contrastar_journal(&journal, &debido, mode, &mut fallas);
        return Ok(Corrida {
            sdk,
            modo: mode,
            journal,
            publicos: pv_execute.as_ref().len(),
            ciclos: reporte.total_num_cycles,
            execute,
            prueba: None,
            tres_puntas: None,
            fallas,
        });
    }

    println!("\n=== prove ===");
    let t = Instant::now();
    let (pv_prove, prueba, reporte_prueba) = match zkvm.prove(&input) {
        Ok(x) => x,
        Err(e) => {
            // El techo va en el error, no en un panic críptico: quien corra
            // esto tiene que enterarse de POR QUÉ no entra y de que no hay un
            // flag que lo arregle.
            eprintln!(
                "\n[zkvm] `prove` falló en el modo {mode:?} ({} ciclos).",
                reporte.total_num_cycles
            );
            if backend == Backend::Sp1 {
                eprintln!("{TECHO_MEDIDO}");
            } else {
                eprintln!(
                    "El techo de memoria de abajo se midió con SP1 y NO vale acá: nadie\n\
                     midió el de este backend. Citarlo sería heredar un número de otra\n\
                     máquina virtual.\n{TECHO_MEDIDO}"
                );
            }
            return Err(format!("prove falló: {e:#}").into());
        }
    };
    let prove = t.elapsed();
    println!(
        "prueba en {prove:?} (backend: {:?}) — {} bytes de prueba, {} bytes públicos",
        reporte_prueba.proving_time,
        prueba.as_ref().len(),
        pv_prove.as_ref().len()
    );

    let archivo = match &opciones.guardar_prueba {
        None => None,
        Some(p) => {
            if let Some(dir) = p.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(p, prueba.as_ref())?;
            println!("prueba escrita en {}", p.display());
            Some(p.clone())
        }
    };

    println!("\n=== verify ===");
    let (que_prueba, de_quien) = match opciones.verificar_ajena {
        Some((nombre, ajena)) => {
            eprintln!(
                "[zkvm] MUTACIÓN --mutar-verificador-cruzado: se le da al verificador de {} \
                 la prueba de {nombre}",
                backend.nombre()
            );
            (ajena, nombre)
        }
        None => (&prueba, backend.nombre()),
    };
    let t = Instant::now();
    let pv_verify = match zkvm.verify(que_prueba) {
        Ok(pv) => pv,
        Err(e) => {
            return Err(format!(
                "verify falló con la prueba de {de_quien}: {e:#}\n\
                 Sin un journal verificado no hay nada que cruzar contra el otro backend."
            )
            .into());
        }
    };
    let verify = t.elapsed();
    println!(
        "verificada en {verify:?} — {} bytes públicos",
        pv_verify.as_ref().len()
    );

    let pv_verify = if opciones.mutar_public_values {
        let otro = if mode == Mode::Nop {
            Mode::DecodeOnly
        } else {
            Mode::Nop
        };
        eprintln!(
            "[M4] sustituyendo los public values de `verify` por los de una corrida en {otro:?}"
        );
        let (pv_otro, _) = zkvm.execute(&repo_b_prover::zkvm_input(otro, &bloque))?;
        pv_otro
    } else {
        pv_verify
    };

    println!("\n=== execute == prove == verify ===");
    let e = pv_execute.as_ref();
    let p = pv_prove.as_ref();
    let v = pv_verify.as_ref();
    let mut tres_puntas = true;
    for (a, b, nombre) in [(e, p, "execute vs prove"), (p, v, "prove vs verify")] {
        if a == b {
            println!("  ok   {nombre}: los mismos {} bytes", a.len());
        } else {
            println!("  FAIL {nombre}: {} bytes vs {} bytes", a.len(), b.len());
            println!("       {}", hex(a));
            println!("       {}", hex(b));
            fallas.push(format!("{nombre}: no son los mismos bytes"));
            tres_puntas = false;
        }
    }

    println!("\n=== y esos bytes son el journal que el harness esperaba ===");
    let journal = decodificar(v)?;
    contrastar_journal(&journal, &debido, mode, &mut fallas);

    Ok(Corrida {
        sdk,
        modo: mode,
        journal,
        publicos: v.len(),
        ciclos: reporte.total_num_cycles,
        execute,
        prueba: Some(Prueba {
            bytes: prueba.as_ref().len(),
            prove,
            verify,
            archivo,
        }),
        tres_puntas: Some(tres_puntas),
        fallas,
    })
}

fn decodificar(bytes: &[u8]) -> Result<Journal, Box<dyn std::error::Error>> {
    Journal::decode(bytes)
        .ok_or_else(|| format!("los {} bytes publicados no son un journal", bytes.len()).into())
}

/// Los cuatro campos contra el oráculo del modo. **Se evalúan los cuatro**
/// antes de decidir: ver el doc del módulo.
fn contrastar_journal(publicado: &Journal, debido: &Journal, mode: Mode, fallas: &mut Vec<String>) {
    if publicado.mode == mode {
        println!("  ok   modo {:?} (el pedido)", publicado.mode);
    } else {
        println!("  FAIL modo {:?} — se pidió {mode:?}", publicado.mode);
        fallas.push(format!(
            "se pidió el modo {mode:?} y el journal dice {:?}",
            publicado.mode
        ));
    }
    for (campo, a, b) in [
        (
            "pre_state_root",
            publicado.pre_state_root,
            debido.pre_state_root,
        ),
        (
            "post_state_root",
            publicado.post_state_root,
            debido.post_state_root,
        ),
        (
            "output_digest",
            publicado.output_digest,
            debido.output_digest,
        ),
    ] {
        contrastar(campo, a, b);
        if a != b {
            fallas.push(format!("{campo}: {a} en vez de {b}"));
        }
    }
    if mode != Mode::Full {
        println!(
            "  (modo ablacionado: los campos que este modo no computa se afirman en CERO, no se saltean)"
        );
    }
}

/// Prueba el caso congelado con **un** backend y verifica la prueba.
///
/// # Errors
/// Cualquier desacuerdo con el oráculo, o un backend que no pudo correr.
pub(crate) fn probar(
    backend: Backend,
    elf_path: &Path,
    modo: Option<u8>,
    mutar_pv: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = match modo {
        Some(m) => Mode::from_byte(m).ok_or("modo desconocido")?,
        None => MODO_QUE_ENTRA,
    };
    let corrida = correr_backend(
        backend,
        elf_path,
        mode,
        &Opciones {
            probar: true,
            mutar_public_values: mutar_pv,
            guardar_prueba: None,
            verificar_ajena: None,
        },
    )?;
    if !corrida.fallas.is_empty() {
        return Err(corrida.fallas.join(" | ").into());
    }
    println!("\nuna prueba de este guest VERIFICA, y afirma lo que el harness computó afuera.");
    Ok(())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn contrastar(campo: &str, publicado: B256, esperado: B256) {
    let marca = if publicado == esperado {
        "ok  "
    } else {
        "FAIL"
    };
    println!("  {marca} {campo:<16} {publicado}");
    if publicado != esperado {
        println!("       esperado         {esperado}");
    }
}
