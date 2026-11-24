//! **Los KNOWN del nivel 3, con trinquete.**
//!
//! Un caso del corte que un backend no puede correr —por un límite del
//! backend, no por una divergencia del camino acelerado— no puede quedar como
//! "8 casos fallan" en un log: así el eje sale rojo para siempre, deja de dar
//! señal, y un noveno fallo nuevo se esconde detrás de los ocho viejos.
//!
//! La lista es explícita: un archivo con una línea por caso, `backend|caso|motivo`.
//! El juicio es en las dos direcciones:
//!
//! - un fallo que **no** está en la lista es rojo (lo nuevo no se esconde);
//! - un KNOWN que **pasa** es rojo también (lo arreglado se saca de la lista,
//!   o la lista miente);
//! - un KNOWN que no está en el corte es rojo (la lista apunta a algo que ya
//!   no existe, y nadie lo sabría).
//!
//! Sin el flag rige la lista versionada del repo (`LISTA_VERSIONADA`), embebida
//! al compilar; `--known <archivo>` la reemplaza entera.

use std::collections::BTreeSet;

use crate::level3::Backend;

/// Dónde vive la lista versionada, relativo a la raíz del repo.
pub const RUTA_LISTA_VERSIONADA: &str = "cmd/conformance/level3-known.txt";

/// La lista versionada, embebida al compilar: es la que rige sin `--known`.
pub const LISTA_VERSIONADA: &str = include_str!("../level3-known.txt");

/// Un caso que se sabe que no corre en un backend, y por qué.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub backend: Backend,
    pub caso: String,
    pub motivo: String,
}

/// La lista que rige: la de `archivo` si se nombró uno, y si no la versionada.
/// Devuelve también de dónde salió, para que el log lo diga.
///
/// # Errors
/// El archivo no se lee, o la lista no se entiende (ver [`parse`]).
pub fn cargar(archivo: Option<&str>) -> Result<(Vec<Known>, String), String> {
    match archivo {
        None => parse(LISTA_VERSIONADA)
            .map(|l| (l, format!("la lista versionada ({RUTA_LISTA_VERSIONADA})")))
            .map_err(|e| format!("{RUTA_LISTA_VERSIONADA}: {e}")),
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| format!("{p}: {e}"))
            .and_then(|t| parse(&t).map_err(|e| format!("{p}: {e}")))
            .map(|l| (l, format!("la lista de {p}"))),
    }
}

/// La lista que rige según los argumentos de la línea de comando: sin
/// `--known`, la versionada; `--known <archivo>`, la de ese archivo; `--known`
/// sin archivo es un error, no un "sin lista".
///
/// # Errors
/// `--known` sin archivo, o lo que devuelva [`cargar`].
pub fn desde_args(args: &[String]) -> Result<(Vec<Known>, String), String> {
    let pos = args.iter().position(|a| a == "--known");
    let archivo = match pos {
        None => None,
        Some(i) => match i.checked_add(1).and_then(|j| args.get(j)) {
            Some(p) => Some(p.as_str()),
            None => return Err("`--known` necesita un archivo `backend|caso|motivo`.".into()),
        },
    };
    cargar(archivo)
}

/// Lee la lista. Líneas vacías y las que empiezan con `#` se ignoran.
///
/// # Errors
/// Una línea sin los tres campos, un backend desconocido, un campo vacío o un
/// par (backend, caso) repetido: la lista es un contrato, y una línea que no se
/// entiende no se saltea.
pub fn parse(texto: &str) -> Result<Vec<Known>, String> {
    let mut lista: Vec<Known> = Vec::new();
    for (i, linea) in texto.lines().enumerate() {
        let n = i.saturating_add(1);
        let linea = linea.trim();
        if linea.is_empty() || linea.starts_with('#') {
            continue;
        }
        let mut campos = linea.splitn(3, '|').map(str::trim);
        let (Some(b), Some(caso), Some(motivo)) = (campos.next(), campos.next(), campos.next())
        else {
            return Err(format!(
                "línea {n}: se esperan tres campos `backend|caso|motivo`"
            ));
        };
        let backend =
            Backend::parse(b).ok_or_else(|| format!("línea {n}: `{b}` no es un backend"))?;
        if caso.is_empty() || motivo.is_empty() {
            return Err(format!(
                "línea {n}: el caso y el motivo no pueden estar vacíos"
            ));
        }
        if lista.iter().any(|k| k.backend == backend && k.caso == caso) {
            return Err(format!("línea {n}: `{caso}` ya está en la lista de {b}"));
        }
        lista.push(Known {
            backend,
            caso: caso.to_string(),
            motivo: motivo.to_string(),
        });
    }
    Ok(lista)
}

/// El veredicto del eje con la lista aplicada.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Juicio {
    /// Fallos fuera de la lista: (caso, detalle).
    pub inesperados: Vec<(String, String)>,
    /// Fallos de la lista: (caso, motivo, detalle).
    pub conocidos: Vec<(String, String, String)>,
    /// KNOWN que corrieron y coincidieron.
    pub conocidos_que_pasan: Vec<String>,
    /// KNOWN que no están en el corte de esta corrida.
    pub conocidos_ausentes: Vec<String>,
}

impl Juicio {
    #[must_use]
    pub fn verde(&self) -> bool {
        self.inesperados.is_empty()
            && self.conocidos_que_pasan.is_empty()
            && self.conocidos_ausentes.is_empty()
    }
}

/// Aplica la lista de `backend` a una corrida: `corte` son los casos que se
/// corrieron, `fallos` los que no coincidieron (caso, detalle).
#[must_use]
pub fn juzgar(
    backend: Backend,
    corte: &[String],
    fallos: &[(String, String)],
    lista: &[Known],
) -> Juicio {
    let de_este: Vec<&Known> = lista.iter().filter(|k| k.backend == backend).collect();
    let en_corte: BTreeSet<&str> = corte.iter().map(String::as_str).collect();
    let fallaron: BTreeSet<&str> = fallos.iter().map(|(c, _)| c.as_str()).collect();
    let mut j = Juicio::default();
    for (caso, detalle) in fallos {
        match de_este.iter().find(|k| k.caso == *caso) {
            Some(k) => j
                .conocidos
                .push((caso.clone(), k.motivo.clone(), detalle.clone())),
            None => j.inesperados.push((caso.clone(), detalle.clone())),
        }
    }
    for k in de_este {
        if !en_corte.contains(k.caso.as_str()) {
            j.conocidos_ausentes.push(k.caso.clone());
        } else if !fallaron.contains(k.caso.as_str()) {
            j.conocidos_que_pasan.push(k.caso.clone());
        }
    }
    j
}

#[cfg(test)]
mod tests {
    use super::{
        Known, LISTA_VERSIONADA, RUTA_LISTA_VERSIONADA, cargar, desde_args, juzgar, parse,
    };
    use crate::level3::Backend;

    fn s(x: &str) -> String {
        x.to_string()
    }

    const LISTA: &str = "# comentario\n\nzisk|caso-a|el motivo\nopenvm|caso-a|otro motivo\n";

    #[test]
    fn the_list_is_parsed_per_backend() {
        let l = parse(LISTA);
        assert_eq!(
            l,
            Ok(vec![
                Known {
                    backend: Backend::Zisk,
                    caso: s("caso-a"),
                    motivo: s("el motivo")
                },
                Known {
                    backend: Backend::OpenVm,
                    caso: s("caso-a"),
                    motivo: s("otro motivo")
                },
            ])
        );
    }

    #[test]
    fn a_malformed_list_is_an_error() {
        assert!(parse("zisk|caso").is_err(), "sin motivo");
        assert!(parse("zisk|caso| ").is_err(), "motivo vacío");
        assert!(parse("risc0|caso|m").is_err(), "backend desconocido");
        assert!(parse("zisk|c|m\nzisk|c|m2").is_err(), "repetido");
        assert!(parse("zisk||m").is_err(), "caso vacío");
    }

    /// Todo lo que falla está en la lista y todo lo de la lista falla: verde.
    #[test]
    fn known_failures_that_still_fail_are_green() {
        let l = parse(LISTA).unwrap_or_default();
        let j = juzgar(
            Backend::Zisk,
            &[s("caso-a"), s("caso-b")],
            &[(s("caso-a"), s("no ejecutó: x"))],
            &l,
        );
        assert!(j.verde(), "{j:?}");
        assert_eq!(j.conocidos.len(), 1);
    }

    /// Un fallo nuevo no se esconde detrás de los viejos.
    #[test]
    fn a_failure_outside_the_list_is_red() {
        let l = parse(LISTA).unwrap_or_default();
        let j = juzgar(
            Backend::Zisk,
            &[s("caso-a"), s("caso-b")],
            &[(s("caso-a"), s("x")), (s("caso-b"), s("y"))],
            &l,
        );
        assert!(!j.verde());
        assert_eq!(j.inesperados, vec![(s("caso-b"), s("y"))]);
    }

    /// Un KNOWN arreglado obliga a sacarlo de la lista.
    #[test]
    fn a_known_case_that_passes_is_red() {
        let l = parse(LISTA).unwrap_or_default();
        let j = juzgar(Backend::Zisk, &[s("caso-a")], &[], &l);
        assert!(!j.verde());
        assert_eq!(j.conocidos_que_pasan, vec![s("caso-a")]);
    }

    /// Un KNOWN que no está en el corte es una lista que apunta a la nada.
    #[test]
    fn a_known_case_outside_the_cut_is_red() {
        let l = parse(LISTA).unwrap_or_default();
        let j = juzgar(Backend::Zisk, &[s("caso-b")], &[], &l);
        assert!(!j.verde());
        assert_eq!(j.conocidos_ausentes, vec![s("caso-a")]);
    }

    /// La lista de un backend no perdona fallos de otro.
    #[test]
    fn the_list_of_one_backend_does_not_excuse_another() {
        let l = parse("zisk|caso-a|m").unwrap_or_default();
        let j = juzgar(Backend::Sp1, &[s("caso-a")], &[(s("caso-a"), s("x"))], &l);
        assert!(!j.verde());
        assert_eq!(j.inesperados.len(), 1);
    }

    /// **La lista versionada se entiende y dice lo que se midió**: ocho casos
    /// de OpenVM, los mismos ocho de ZisK y de Pico, ninguno de SP1. Si alguien
    /// agrega o saca una línea sin medir, esto lo ve.
    #[test]
    fn the_versioned_list_parses_and_matches_the_measured_cases() {
        let texto = LISTA_VERSIONADA;
        let l = parse(texto);
        let Ok(l) = l else {
            panic!("la lista versionada no se entiende: {l:?}");
        };
        let de = |b: Backend| -> Vec<&str> {
            l.iter()
                .filter(|k| k.backend == b)
                .map(|k| k.caso.as_str())
                .collect()
        };
        assert_eq!(de(Backend::OpenVm).len(), 8);
        assert_eq!(de(Backend::OpenVm), de(Backend::Zisk));
        assert_eq!(de(Backend::OpenVm), de(Backend::Pico));
        assert!(de(Backend::Sp1).is_empty());
        assert!(
            de(Backend::Zisk)
                .iter()
                .all(|c| c.contains("static_call50000_ecrec")
                    || c.contains("static_call50000_rip160"))
        );
    }

    /// **Sin `--known` rige la lista versionada, no una vacía.** Con la vacía,
    /// OpenVM, ZisK y Pico salen rojos por los 8 de siempre y el eje deja de dar
    /// señal; con ninguna, nadie se acuerda del flag y el trinquete no corre.
    #[test]
    fn without_a_file_the_versioned_list_rules() {
        let Ok((l, origen)) = cargar(None) else {
            panic!("la lista versionada tiene que cargarse sin archivo");
        };
        assert_eq!(l.len(), 24);
        assert!(origen.contains(RUTA_LISTA_VERSIONADA), "{origen}");
        assert!(cargar(Some("/no/existe/level3-known.txt")).is_err());
    }

    /// **La rama del binario:** los argumentos de una corrida de nivel 3 sin
    /// `--known` cargan la versionada (no una vacía); `--known` al final, sin
    /// archivo, es un error; un archivo que no existe, también.
    #[test]
    fn the_command_line_without_known_uses_the_versioned_list() {
        let args = |xs: &[&str]| xs.iter().map(|x| s(x)).collect::<Vec<_>>();
        let Ok((l, origen)) = desde_args(&args(&["--level3", "--backend", "zisk"])) else {
            panic!("sin `--known` rige la versionada");
        };
        let Ok(versionada) = parse(LISTA_VERSIONADA) else {
            panic!("la lista versionada se entiende");
        };
        assert_eq!(l, versionada);
        assert!(!l.is_empty());
        assert!(origen.contains(RUTA_LISTA_VERSIONADA), "{origen}");
        assert!(desde_args(&args(&["--level3", "--known"])).is_err());
        assert!(desde_args(&args(&["--level3", "--known", "/no/existe/known.txt"])).is_err());
    }

    /// La ruta que el log nombra es la del archivo embebido: si alguien mueve
    /// el archivo y no la constante, el log apuntaría a otro lado.
    #[test]
    fn the_named_path_is_the_embedded_file() {
        let ruta = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(RUTA_LISTA_VERSIONADA);
        let en_disco = match std::fs::read_to_string(&ruta) {
            Ok(t) => t,
            Err(e) => panic!("{}: {e}", ruta.display()),
        };
        assert_eq!(en_disco, LISTA_VERSIONADA);
        let Ok((desde_archivo, _)) = cargar(ruta.to_str()) else {
            panic!("la lista versionada se lee también por ruta");
        };
        let Ok(embebida) = parse(LISTA_VERSIONADA) else {
            panic!("la lista versionada se entiende");
        };
        assert_eq!(desde_archivo, embebida);
    }
}
