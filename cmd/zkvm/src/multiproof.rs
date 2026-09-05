//! **El journal de un backend contra el journal del otro.**
//!
//! # Qué chequeo es éste, y por qué no lo hace ningún otro
//!
//! Hasta acá cada backend se contrastaba contra su corrida nativa y contra el
//! caso congelado. Los dos oráculos viven **afuera** del zkVM, y por eso hay
//! una clase de defecto que ninguno de los dos ve: el que un backend introduce
//! adentro. Ya pasó — una miscompilación de la división de enteros grandes es
//! exactamente eso, silenciosa y dependiente del valor.
//!
//! El contraste entre backends es el único chequeo del sistema que ve esa
//! clase: dos implementaciones independientes que ejecutan el MISMO programa
//! tienen que publicar el MISMO journal, y si difieren, al menos una computó
//! mal sin importar qué diga su propio oráculo.
//!
//! # Se cruzan los 97 bytes del journal, no los bytes públicos
//!
//! No es lo mismo. OpenVM rellena su output público con ceros hasta 256 bytes
//! y SP1 no rellena: comparar los bytes crudos compararía una convención de
//! cada backend, no lo que cada uno afirma. Lo que se cruza es el journal
//! decodificado y vuelto a encodear — los 97 bytes que los dos definen igual.
//!
//! # El cruce corre aunque un backend falle su propio contraste
//!
//! Deliberado, y es la lección del KAT: *un chequeo que solo corre cuando el
//! otro pasa no está probado por la corrida que caza el bug*. Los dos backends
//! se corren y se reportan completos, los errores se acumulan, y el exit code
//! agrega al final.
//!
//! Lo único que sí impide cruzar es que un backend no haya producido un journal
//! **probado**: sin arranque, sin ejecución, sin prueba o sin verificación no
//! hay nada de ese lado. Cruzar contra un journal que solo se ejecutó sería una
//! afirmación más débil disfrazada de la misma.

use std::path::{Path, PathBuf};

use repo_b_prover::{Journal, Mode};

use crate::Backend;
use crate::prueba::{Corrida, Opciones, correr_backend, hex, que_lleva};

/// Cuánto del journal mira el cruce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alcance {
    /// Los 97 bytes.
    Completo,
    /// **Mutación**: solo el byte de modo. Existe para medir que el cruce es
    /// por bytes y no por una etiqueta — con esto puesto, un byte cambiado en
    /// un root deja de verse.
    SoloModo,
}

/// Los flags que alteran la corrida a propósito.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Mutaciones {
    /// Cambiar un byte del journal de este backend **después** de `verify` y
    /// **antes** del cruce.
    pub journal_de: Option<Backend>,
    /// Correr OpenVM en otro modo que SP1: dos inputs distintos.
    pub modo_openvm: Option<Mode>,
    /// Ver [`Alcance::SoloModo`].
    pub cruce_solo_modo: bool,
    /// Darle al verificador del segundo backend la prueba del primero.
    pub verificador_cruzado: bool,
    /// Correr este backend contra un oráculo corrido en un byte. Ver
    /// [`Opciones::mutar_oraculo`].
    pub oraculo_de: Option<Backend>,
}

/// El orden en que se levantan los backends. **Uno por vez**: dos servidores de
/// zkVM a la vez en la misma caja compiten por la memoria, y el número que
/// saliera de ahí mediría la contención y no el backend.
const ORDEN: [Backend; 2] = [Backend::Sp1, Backend::OpenVm];

/// Corre los dos backends y cruza lo que publicaron.
///
/// # Errors
/// Si cualquiera de los dos falló su contraste, si alguno no pudo correr, o si
/// el cruce no coincide.
pub(crate) fn multiproof(
    elf_sp1: &Path,
    elf_openvm: &Path,
    modo: u8,
    probar: bool,
    mutaciones: Mutaciones,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = Mode::from_byte(modo).ok_or("modo desconocido")?;
    if let Some(b) = mutaciones.journal_de {
        eprintln!(
            "[zkvm] MUTACIÓN --mutar-journal-de {}: se cambia un byte del journal antes del cruce",
            b.nombre()
        );
    }
    if mutaciones.cruce_solo_modo {
        eprintln!("[zkvm] MUTACIÓN --mutar-cruce-solo-modo: el cruce mira solo el byte de modo");
    }

    let mut resultados: Vec<(Backend, Result<Corrida, String>)> = Vec::new();
    // La prueba del backend anterior, para la mutación del verificador cruzado.
    // Se guarda como bytes porque el servidor del backend que la produjo ya no
    // existe cuando le toca al siguiente — es el precio de correr en secuencia,
    // y es barato.
    let mut prueba_previa: Option<(&'static str, ere_dockerized::EncodedProof)> = None;

    for backend in ORDEN {
        let elf = match backend {
            Backend::Sp1 => elf_sp1,
            Backend::OpenVm => elf_openvm,
        };
        // La mutación de inputs distintos: OpenVM corre otro modo. El cruce
        // tiene que verlo, y el chequeo de modo también.
        let mode_backend = match (backend, mutaciones.modo_openvm) {
            (Backend::OpenVm, Some(m)) => {
                eprintln!(
                    "[zkvm] MUTACIÓN --mutar-modo-openvm: openvm corre {m:?} y sp1 corre {mode:?}"
                );
                m
            }
            _ => mode,
        };

        println!("\n════════════════════════════════════════════════════════════════");
        println!(
            "  BACKEND {} — {} — modo {mode_backend:?}",
            backend.nombre(),
            elf.display()
        );
        println!("════════════════════════════════════════════════════════════════");

        // El bloque acota el préstamo de `prueba_previa`: las opciones lo
        // toman prestado y más abajo hay que escribirlo.
        let resultado = {
            let ajena = match (&prueba_previa, mutaciones.verificador_cruzado) {
                (Some((nombre, p)), true) => Some((*nombre, p)),
                _ => None,
            };
            let opciones = Opciones {
                probar,
                mutar_public_values: false,
                guardar_prueba: probar.then(|| archivo_de_prueba(backend, mode_backend)),
                verificar_ajena: ajena,
                mutar_oraculo: mutaciones.oraculo_de == Some(backend),
            };
            correr_backend(backend, elf, mode_backend, &opciones)
        };

        match resultado {
            Ok(corrida) => {
                // La prueba del primero se guarda para el verificador del
                // segundo. Se lee del archivo y no se retiene en memoria porque
                // el archivo es parte del entregable; y se lee con `?` porque
                // una lectura que falla en silencio degradaría la mutación a
                // una corrida normal con cara de mutación.
                if mutaciones.verificador_cruzado
                    && prueba_previa.is_none()
                    && let Some(archivo) = corrida.prueba.as_ref().and_then(|p| p.archivo.as_ref())
                {
                    prueba_previa = Some((
                        backend.nombre(),
                        ere_dockerized::EncodedProof(std::fs::read(archivo)?),
                    ));
                }
                resultados.push((backend, Ok(corrida)));
            }
            Err(e) => {
                println!("\n[{}] NO PRODUJO UN JOURNAL: {e}", backend.nombre());
                resultados.push((backend, Err(format!("{e}"))));
            }
        }
    }

    reportar(&resultados, probar);
    cerrar(resultados, mutaciones)
}

/// Dónde queda la prueba de cada corrida. **Uno por backend y por modo**: con
/// un nombre compartido, la segunda prueba pisaría a la primera y una
/// comparación de tamaños mediría dos veces la misma.
fn archivo_de_prueba(backend: Backend, mode: Mode) -> PathBuf {
    PathBuf::from(format!(
        "target/proof-{}-mode{}.bin",
        backend.nombre(),
        mode.as_byte()
    ))
}

/// La tabla por backend. Se imprime **antes** del cruce y para los dos, falle
/// quien falle.
fn reportar(resultados: &[(Backend, Result<Corrida, String>)], probar: bool) {
    println!("\n════════════════════════════════════════════════════════════════");
    println!("  LOS DOS BACKENDS, LADO A LADO");
    println!("════════════════════════════════════════════════════════════════");
    for (backend, r) in resultados {
        match r {
            Err(e) => {
                println!("\n{:<8} NO CORRIÓ", backend.nombre());
                println!("         {}", e.lines().next().unwrap_or(e));
            }
            Ok(c) => {
                println!("\n{:<8} {}", backend.nombre(), c.sdk);
                println!("         modo             {:?}", c.modo);
                println!(
                    "         execute          {:?}  ({} ciclos, {} bytes públicos)",
                    c.execute, c.ciclos, c.publicos
                );
                match &c.prueba {
                    None => println!(
                        "         prove/verify     no se corrieron (--sin-prueba: se cruza lo EJECUTADO, no lo probado)"
                    ),
                    Some(p) => {
                        println!(
                            "         prove            {:?}  ({} bytes de prueba)",
                            p.prove, p.bytes
                        );
                        println!("         verify           {:?}", p.verify);
                        if let Some(a) = &p.archivo {
                            println!("         prueba en        {}", a.display());
                        }
                    }
                }
                println!("         journal (97 B)   {}", hex(&c.journal.encode()));
                // **El relleno no se ignora, se afirma.** Un backend puede
                // publicar más bytes que el journal (OpenVM rellena hasta su
                // techo), y lo que se cruza son los 97 semánticos. Que lo de
                // más sea todo ceros no es una cortesía del backend: el decoder
                // lo exige, así que un byte no-cero ahí no llega hasta acá — se
                // rechaza antes y este backend no aporta journal. Se imprime
                // para que el lector no tenga que deducirlo del decoder.
                if c.publicos > repo_b_prover::JOURNAL_BYTES {
                    println!(
                        "         relleno          {} bytes más allá del journal, TODOS en cero (si no, no decodifica)",
                        c.publicos.saturating_sub(repo_b_prover::JOURNAL_BYTES)
                    );
                }
                if c.fallas.is_empty() {
                    println!("         vs su oráculo    ok");
                } else {
                    for f in &c.fallas {
                        println!("         vs su oráculo    FAIL {f}");
                    }
                }
            }
        }
    }
    if !probar {
        println!(
            "\n(--sin-prueba: esto contrasta lo que los dos EJECUTAN. Que los dos PRUEBEN\n\
             el mismo journal es una afirmación más fuerte y necesita la corrida entera.)"
        );
    }

    // **Una línea compacta por backend, para que la receta no parsee la tabla.**
    // La tabla de arriba está para leerla; ésta para extraerla. Mezclar las dos
    // cosas hace que un cambio de formato rompa el gate en silencio.
    println!();
    for (backend, r) in resultados {
        let Ok(c) = r else {
            println!(
                "resumen|{}|—|—|—|—|—|—|—|NO CORRIÓ|NO CORRIÓ|—",
                backend.nombre()
            );
            continue;
        };
        let (prove, bytes, verify) = match &c.prueba {
            None => (
                "no se corrió (--sin-prueba)".to_string(),
                String::new(),
                "no se corrió (--sin-prueba)".to_string(),
            ),
            Some(p) => (
                format!("{:?}", p.prove),
                format!("{} bytes de prueba", p.bytes),
                format!("{:?}", p.verify),
            ),
        };
        let prove = if bytes.is_empty() {
            prove
        } else {
            format!("{prove} · {bytes}")
        };
        println!(
            "resumen|{}|{}|{:?}|{:?}|{}|{}|{}|{}|{}|{}|{}",
            backend.nombre(),
            c.sdk,
            c.modo,
            c.execute,
            c.ciclos,
            c.publicos,
            prove,
            verify,
            match c.tres_puntas {
                None => "no se corrieron (--sin-prueba)".to_string(),
                Some(true) => "ok — los mismos bytes en las tres puntas".to_string(),
                Some(false) => "FAIL — las tres puntas NO publican lo mismo".to_string(),
            },
            if c.fallas.is_empty() {
                "ok — el journal es el que este modo debe producir".to_string()
            } else {
                format!("FAIL — {}", c.fallas.join("; "))
            },
            hex(&c.journal.encode()),
        );
    }
}

/// El cruce y el exit code.
fn cerrar(
    resultados: Vec<(Backend, Result<Corrida, String>)>,
    mutaciones: Mutaciones,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut problemas: Vec<String> = Vec::new();
    let mut journals: Vec<(Backend, Journal)> = Vec::new();
    for (backend, r) in resultados {
        match r {
            Err(e) => problemas.push(format!("{}: no produjo journal ({e})", backend.nombre())),
            Ok(c) => {
                for f in &c.fallas {
                    problemas.push(format!("{}: {f}", backend.nombre()));
                }
                let journal = if mutaciones.journal_de == Some(backend) {
                    mutar_un_byte(&c.journal)
                } else {
                    c.journal
                };
                journals.push((backend, journal));
            }
        }
    }

    println!("\n════════════════════════════════════════════════════════════════");
    println!("  EL CRUCE — el journal de un backend contra el del otro");
    println!("════════════════════════════════════════════════════════════════");

    let cruce = match journals.as_slice() {
        [(a, ja), (b, jb)] => {
            println!("  {} vs {}", a.nombre(), b.nombre());
            cruzar(ja, jb, alcance(mutaciones))
        }
        _ => {
            let faltan: Vec<&str> = ORDEN
                .iter()
                .filter(|b| !journals.iter().any(|(x, _)| x == *b))
                .map(|b| b.nombre())
                .collect();
            println!(
                "  no se pudo cruzar: falta el journal de {} — el cruce necesita los DOS",
                faltan.join(" y ")
            );
            Err("no se pudo cruzar".into())
        }
    };
    if let Err(e) = cruce {
        problemas.push(format!("cruce: {e}"));
    }

    println!("\n=== RESUMEN ===");
    if problemas.is_empty() {
        println!("cruce ok");
        println!("\nlos dos backends corrieron el MISMO programa y publicaron el MISMO journal.");
        return Ok(());
    }
    println!("cruce FAIL");
    for p in &problemas {
        println!("  - {p}");
    }
    Err(problemas.join(" | ").into())
}

const fn alcance(m: Mutaciones) -> Alcance {
    if m.cruce_solo_modo {
        Alcance::SoloModo
    } else {
        Alcance::Completo
    }
}

/// **Cambia un byte del journal.** El byte 33 es el primero del
/// `post_state_root`: lo elige a propósito porque es el campo que un modo
/// ablacionado deja en cero, o sea el lugar donde una diferencia es más fácil
/// de pasar por alto.
fn mutar_un_byte(j: &Journal) -> Journal {
    let mut bytes = j.encode();
    bytes[33] ^= 0x01;
    // El byte de modo queda intacto, así que esto siempre vuelve a decodificar:
    // la mutación produce un journal VÁLIDO y distinto, que es la única forma
    // de preguntarle al cruce si mira más que la etiqueta.
    Journal::decode(&bytes).unwrap_or(*j)
}

/// **El chequeo nuevo.** Los 97 bytes de un backend contra los del otro, y los
/// cuatro campos para decir dónde.
///
/// # Errors
/// El nombre de lo que no coincide.
pub(crate) fn cruzar(a: &Journal, b: &Journal, alcance: Alcance) -> Result<(), String> {
    let mut mal: Vec<&str> = Vec::new();

    // El byte de modo primero: dos backends que corrieron programas distintos
    // no tienen por qué publicar lo mismo, y decirlo así evita leer una
    // diferencia de roots como una divergencia de cómputo.
    marcar("mode", a.mode == b.mode, &format!("{:?}", a.mode));
    if a.mode != b.mode {
        mal.push("mode");
        println!("       el otro          {:?}", b.mode);
    }

    if alcance == Alcance::SoloModo {
        println!(
            "  (--mutar-cruce-solo-modo: los tres roots NO se miraron. Un cruce así\n   \
             acepta dos journals que difieren en todo menos la etiqueta.)"
        );
        return if mal.is_empty() {
            Ok(())
        } else {
            Err(format!("difieren en {}", mal.join(", ")))
        };
    }

    // **No se reusa el contraste contra el oráculo, y la razón es una palabra.**
    // Aquél imprime `esperado` debajo del valor que no coincide, porque de un
    // lado hay una verdad y del otro un candidato. Acá los dos lados son
    // candidatos: llamar `esperado` a uno de los dos backends invitaría a leerlo
    // como el oráculo del otro, que es exactamente lo que este chequeo NO hace.
    // **Los nombres de los campos son los del camino real, y este peldaño puede
    // estar usándolos para otra cosa.** El anexo dice qué lleva cada uno; sin
    // él, el campo llamado `output_digest` aparece en cero al lado de la
    // afirmación de que el digest del oráculo no lo es. Solo se anexa cuando
    // los dos lados corrieron el mismo modo: con modos distintos no hay una
    // lectura común de los campos, y ponerle una sería inventarla.
    let mismo_modo = a.mode == b.mode;
    for (campo, x, y) in [
        ("pre_state_root", a.pre_state_root, b.pre_state_root),
        ("post_state_root", a.post_state_root, b.post_state_root),
        ("output_digest", a.output_digest, b.output_digest),
    ] {
        let lleva = if mismo_modo {
            que_lleva(a.mode, campo)
        } else {
            ""
        };
        marcar(campo, x == y, &format!("{x}{lleva}"));
        if x != y {
            println!("       el otro          {y}");
            mal.push(campo);
        }
    }

    // Los bytes, que son la afirmación. Va DESPUÉS de los campos porque los
    // campos dicen dónde y esto dice qué: si alguna vez el encoding creciera y
    // los campos no lo cubrieran, este chequeo lo vería igual.
    let (ba, bb) = (a.encode(), b.encode());
    if ba == bb {
        println!(
            "  ok   {:<16} los mismos {} bytes",
            "los 97 bytes",
            ba.len()
        );
    } else {
        println!("  FAIL {:<16} NO son los mismos bytes", "los 97 bytes");
        println!("       {}", hex(&ba));
        println!("       {}", hex(&bb));
        mal.push("los 97 bytes");
    }

    if mal.is_empty() {
        Ok(())
    } else {
        Err(format!("difieren en {}", mal.join(", ")))
    }
}

fn marcar(campo: &str, ok: bool, valor: &str) {
    println!("  {} {campo:<16} {valor}", if ok { "ok  " } else { "FAIL" });
}

#[cfg(test)]
mod tests {
    use super::{Alcance, Mutaciones, alcance, cerrar, cruzar, mutar_un_byte, reportar};
    use crate::Backend;
    use crate::prueba::Corrida;
    use repo_b_common::primitives::B256;
    use repo_b_prover::{Journal, Mode};

    fn j() -> Journal {
        Journal {
            mode: Mode::Kat,
            pre_state_root: B256::repeat_byte(0x11),
            post_state_root: B256::repeat_byte(0x22),
            output_digest: B256::repeat_byte(0x33),
        }
    }

    #[test]
    fn two_identical_journals_cross() {
        assert_eq!(cruzar(&j(), &j(), Alcance::Completo), Ok(()));
    }

    /// **Cada uno de los cuatro campos se mira, y el error dice cuál.** Sin
    /// esto, un cruce que solo comparara tres campos saldría verde con el
    /// cuarto distinto.
    #[test]
    fn every_field_of_the_journal_is_crossed_by_name() {
        for (nombre, otro) in [
            (
                "mode",
                Journal {
                    mode: Mode::Nop,
                    ..j()
                },
            ),
            (
                "pre_state_root",
                Journal {
                    pre_state_root: B256::repeat_byte(0xaa),
                    ..j()
                },
            ),
            (
                "post_state_root",
                Journal {
                    post_state_root: B256::repeat_byte(0xaa),
                    ..j()
                },
            ),
            (
                "output_digest",
                Journal {
                    output_digest: B256::repeat_byte(0xaa),
                    ..j()
                },
            ),
        ] {
            let e = cruzar(&j(), &otro, Alcance::Completo)
                .err()
                .unwrap_or_default();
            assert!(
                e.contains(nombre),
                "el error de un {nombre} distinto no lo nombra: {e}"
            );
        }
    }

    /// Un campo distinto **también** rompe la comparación de bytes: la
    /// afirmación no depende de que alguien se acuerde de enumerar el campo.
    #[test]
    fn a_different_field_also_breaks_the_byte_comparison() {
        let otro = Journal {
            output_digest: B256::repeat_byte(0xaa),
            ..j()
        };
        let e = cruzar(&j(), &otro, Alcance::Completo)
            .err()
            .unwrap_or_default();
        assert!(e.contains("los 97 bytes"), "{e}");
    }

    /// **M4.** Un cruce que solo mira el modo acepta dos journals que difieren
    /// en un root. Es la mutación que prueba que el cruce de verdad es por
    /// bytes: si esto fallara igual, el alcance no significaría nada.
    #[test]
    fn the_mode_only_cross_does_not_see_a_different_root() {
        let mutado = mutar_un_byte(&j());
        assert_ne!(mutado, j(), "la mutación tiene que cambiar el journal");
        assert!(cruzar(&j(), &mutado, Alcance::Completo).is_err());
        assert_eq!(cruzar(&j(), &mutado, Alcance::SoloModo), Ok(()));
    }

    /// Y sigue viendo un modo distinto: el alcance recortado no es "no
    /// chequear nada".
    #[test]
    fn the_mode_only_cross_still_sees_a_different_mode() {
        let otro = Journal {
            mode: Mode::Nop,
            ..j()
        };
        assert!(cruzar(&j(), &otro, Alcance::SoloModo).is_err());
    }

    /// La mutación de un byte produce un journal **válido**: si rompiera el
    /// decode, el cruce fallaría por otra razón y la mutación mediría otra cosa.
    #[test]
    fn the_one_byte_mutation_yields_a_valid_journal() {
        let m = mutar_un_byte(&j());
        assert_eq!(m.mode, j().mode);
        assert_eq!(Journal::decode(&m.encode()), Some(m));
        assert_eq!(m.pre_state_root, j().pre_state_root);
        assert_eq!(m.output_digest, j().output_digest);
        assert_ne!(m.post_state_root, j().post_state_root);
    }

    fn corrida(j: Journal, fallas: &[&str]) -> Corrida {
        Corrida {
            sdk: "prueba".into(),
            modo: j.mode,
            journal: j,
            publicos: 97,
            ciclos: 1,
            execute: std::time::Duration::from_millis(1),
            prueba: None,
            tres_puntas: None,
            fallas: fallas.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// **§ del cruce que corre aunque un backend falle.** Un backend que no
    /// coincide con su propio oráculo no impide que el otro se reporte ni que
    /// el cruce se haga: los errores se acumulan y el exit code agrega.
    #[test]
    fn a_backend_that_fails_its_oracle_does_not_stop_the_cross() {
        let r = vec![
            (
                Backend::Sp1,
                Ok(corrida(j(), &["post_state_root: 0x1 en vez de 0x2"])),
            ),
            (Backend::OpenVm, Ok(corrida(j(), &[]))),
        ];
        reportar(&r, false);
        let e = cerrar(r, Mutaciones::default())
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        // El desacuerdo del primero está en el reporte…
        assert!(e.contains("sp1: post_state_root"), "{e}");
        // …y el cruce igual corrió, y salió verde: si hubiera cortado antes, el
        // error diría que no se pudo cruzar.
        assert!(!e.contains("no se pudo cruzar"), "{e}");
    }

    /// Y al revés: un backend que **no corrió** deja el cruce sin un lado, y
    /// eso se dice con esas palabras en vez de saltearse.
    #[test]
    fn a_backend_that_could_not_run_is_reported_and_blocks_only_the_cross() {
        let r = vec![
            (Backend::Sp1, Err("docker no arrancó".to_string())),
            (Backend::OpenVm, Ok(corrida(j(), &[]))),
        ];
        reportar(&r, true);
        let e = cerrar(r, Mutaciones::default())
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("sp1: no produjo journal"), "{e}");
        assert!(e.contains("no se pudo cruzar"), "{e}");
    }

    /// **M1.** Cambiar un byte del journal de un backend después de `verify`
    /// lo ve el cruce, y **solo** el cruce: los contrastes por backend siguen
    /// verdes porque ya corrieron.
    #[test]
    fn mutating_one_backends_journal_is_seen_only_by_the_cross() {
        let r = vec![
            (Backend::Sp1, Ok(corrida(j(), &[]))),
            (Backend::OpenVm, Ok(corrida(j(), &[]))),
        ];
        let e = cerrar(
            r,
            Mutaciones {
                journal_de: Some(Backend::OpenVm),
                ..Mutaciones::default()
            },
        )
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(e.starts_with("cruce: difieren en"), "{e}");
        assert!(e.contains("post_state_root"), "{e}");
    }

    /// **M4 de punta a punta**: con el alcance recortado, M1 deja de verse.
    #[test]
    fn m4_makes_m1_invisible() {
        let r = vec![
            (Backend::Sp1, Ok(corrida(j(), &[]))),
            (Backend::OpenVm, Ok(corrida(j(), &[]))),
        ];
        assert!(
            cerrar(
                r,
                Mutaciones {
                    journal_de: Some(Backend::OpenVm),
                    cruce_solo_modo: true,
                    ..Mutaciones::default()
                }
            )
            .is_ok(),
            "el cruce por etiqueta tendría que dejar pasar un root distinto"
        );
    }

    #[test]
    fn the_scope_defaults_to_the_whole_journal() {
        assert_eq!(alcance(Mutaciones::default()), Alcance::Completo);
        assert_eq!(
            alcance(Mutaciones {
                cruce_solo_modo: true,
                ..Mutaciones::default()
            }),
            Alcance::SoloModo
        );
    }
}
