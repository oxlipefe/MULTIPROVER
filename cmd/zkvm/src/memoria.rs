//! **El pico de memoria de un backend, leído del kernel y no muestreado.**
//!
//! # Por qué no un muestreador
//!
//! Un muestreador periódico (`docker stats` cada N segundos) da **cota
//! inferior**, nunca el pico: el consumo de un prover sube y baja entre dos
//! muestras sin que nadie lo vea, y ya se midió un pico angosto que un muestreo
//! de 2 s no veía. El número que no miente es el que lleva el kernel: el
//! `memory.peak` del cgroup del contenedor, que registra el máximo de memoria
//! cargada al cgroup en todo instante, sin muestreo.
//!
//! # Por fase, con el reinicio por descriptor
//!
//! `memory.peak` es un máximo histórico. Para separar `execute`, `prove` y
//! `verify` —que corren en el MISMO contenedor— el kernel (≥ 6.12) acepta una
//! escritura que reinicia el máximo **para las lecturas por ese mismo
//! descriptor**. Por eso el archivo se abre una vez y se mantiene abierto: se
//! escribe antes de la fase y se lee, por el mismo descriptor, después.
//!
//! Si el reinicio no se puede —kernel viejo, o sin permiso de escritura sobre
//! el cgroup—, cada lectura es el máximo **desde que nació el contenedor**, y
//! así se reporta: un pico acumulado no se publica como el de una fase. El
//! arranque es SIEMPRE acumulado: su fase empezó antes que el cgroup.
//!
//! # Qué cuenta el número, y qué no
//!
//! Todo lo cargado al cgroup del contenedor: memoria anónima, `shmem` (el
//! `/dev/shm` que SP1 y ZisK usan) y page cache de archivos que el contenedor
//! leyó o escribió. Es el pico de lo que el cgroup **tuvo cargado**, no el piso
//! con el que la corrida todavía termina —eso lo mide una bisección con límite—,
//! y no incluye al proceso del driver, que vive afuera del contenedor.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Backend;

/// El nombre del contenedor que `ere` le da al servidor de un backend.
fn contenedor(backend: Backend) -> String {
    format!("ere-server-{}", backend.kind().as_str())
}

/// Qué cuenta un pico de `memory.peak`. Va pegado a CADA fila: un número de
/// memoria sin esto se lee como RSS del prover, y no lo es.
pub(crate) const QUE_CUENTA: &str = "incluye anónima, shmem y page cache";

/// Desde cuándo es el máximo que se leyó.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ventana {
    /// Desde el reinicio antes de la fase hasta la lectura después.
    DeLaFase,
    /// Desde que nació el contenedor: el arranque siempre (su fase empezó
    /// antes de que existiera el cgroup), y cualquier fase cuando el kernel
    /// no admitió el reinicio.
    DesdeQueNacioElContenedor,
}

impl Ventana {
    pub(crate) const fn texto(self) -> &'static str {
        match self {
            Self::DeLaFase => "de la fase",
            Self::DesdeQueNacioElContenedor => "acumulado desde que nació el contenedor",
        }
    }
}

/// Lo que se midió en una fase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fase {
    pub nombre: &'static str,
    /// El máximo de memoria cargada al cgroup en la ventana, en bytes.
    pub pico: u64,
    /// Lo que el cgroup tenía cargado al empezar la fase. Sin esto, un pico
    /// no dice cuánto de él puso la fase y cuánto ya estaba.
    pub base: u64,
    pub ventana: Ventana,
}

impl Fase {
    /// La línea compacta que la receta extrae. Un campo por columna, sin
    /// unidades mezcladas: los bytes van crudos y la receta los convierte.
    pub(crate) fn linea(&self, backend: Backend) -> String {
        format!(
            "memoria|{}|{}|{}|{}|{}|{QUE_CUENTA}",
            backend.nombre(),
            self.nombre,
            self.pico,
            self.base,
            self.ventana.texto()
        )
    }
}

/// El `memory.peak` del contenedor de un backend, abierto una vez.
pub(crate) struct Medidor {
    backend: Backend,
    pico: File,
    actual: PathBuf,
    /// Si el descriptor admite el reinicio por escritura.
    reinicia: bool,
    /// El `memory.peak` leído por el descriptor recién abierto, ANTES del
    /// primer reinicio: el máximo desde que nació el contenedor.
    desde_que_nacio: Result<u64, String>,
    pub fases: Vec<Fase>,
}

impl Medidor {
    /// Abre el cgroup del contenedor del backend, que tiene que estar vivo.
    ///
    /// # Errors
    /// Si el contenedor no existe, si su cgroup no es v2 o si `memory.peak`
    /// no está (kernel < 5.19): no hay pico que leer, y se dice.
    pub(crate) fn abrir(backend: Backend) -> Result<Self, String> {
        Self::abrir_en(backend, &cgroup_del_contenedor(&contenedor(backend))?)
    }

    /// [`Self::abrir`] sobre un directorio de cgroup dado.
    ///
    /// **El pico del arranque se lee ANTES de probar el reinicio.** La
    /// escritura de prueba deja el máximo de este descriptor en lo cargado en
    /// ese instante; leerlo después daría la memoria actual con el rótulo del
    /// arranque.
    fn abrir_en(backend: Backend, dir: &Path) -> Result<Self, String> {
        let ruta = dir.join("memory.peak");
        let (pico, reinicia) = match OpenOptions::new().read(true).write(true).open(&ruta) {
            Ok(f) => (f, true),
            Err(_) => (
                File::open(&ruta).map_err(|e| format!("no puedo abrir {}: {e}", ruta.display()))?,
                false,
            ),
        };
        let mut m = Self {
            backend,
            pico,
            actual: dir.join("memory.current"),
            reinicia,
            desde_que_nacio: Err(String::new()),
            fases: Vec::new(),
        };
        m.desde_que_nacio = m.leer_pico();
        // La escritura se prueba ahora: un kernel sin reinicio devuelve error
        // a la escritura, y descubrirlo en la fase de `prove` sería tarde.
        m.reinicia = m.reinicia && m.reiniciar().is_ok();
        Ok(m)
    }

    fn reiniciar(&mut self) -> Result<(), String> {
        self.pico
            .write_all(b"reset\n")
            .map_err(|e| format!("el kernel no reinició memory.peak: {e}"))
    }

    fn leer_pico(&mut self) -> Result<u64, String> {
        self.pico
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("memory.peak: {e}"))?;
        let mut s = String::new();
        self.pico
            .read_to_string(&mut s)
            .map_err(|e| format!("memory.peak: {e}"))?;
        bytes_de(&s)
    }

    fn leer_actual(&self) -> Result<u64, String> {
        let s = std::fs::read_to_string(&self.actual)
            .map_err(|e| format!("{}: {e}", self.actual.display()))?;
        bytes_de(&s)
    }

    /// El arranque: el pico desde que nació el contenedor hasta que se abrió
    /// el medidor. No es "de la fase" —la fase empezó antes de que existiera
    /// el cgroup, así que no hay reinicio posible— y la fila lo dice.
    ///
    /// # Errors
    /// Si el cgroup no se pudo leer al abrir.
    pub(crate) fn arranque(&mut self) -> Result<(), String> {
        let pico = self.desde_que_nacio.clone()?;
        self.registrar(Fase {
            nombre: "arranque",
            pico,
            base: 0,
            ventana: Ventana::DesdeQueNacioElContenedor,
        });
        Ok(())
    }

    /// Corre `f` como una fase medida.
    ///
    /// # Errors
    /// Los de `f`, tal cual. Una falla de LECTURA del cgroup no se convierte
    /// en una falla de la corrida: se dice que no se midió.
    pub(crate) fn fase<T, E>(
        &mut self,
        nombre: &'static str,
        f: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let base = self.leer_actual().ok();
        let ventana = if self.reinicia && self.reiniciar().is_ok() {
            Ventana::DeLaFase
        } else {
            Ventana::DesdeQueNacioElContenedor
        };
        let r = f();
        match (base, self.leer_pico()) {
            (Some(base), Ok(pico)) => self.registrar(Fase {
                nombre,
                pico,
                base,
                ventana,
            }),
            (_, Err(e)) => println!("memoria|{}|{nombre}|no medido: {e}", self.backend.nombre()),
            (None, Ok(_)) => println!(
                "memoria|{}|{nombre}|no medido: no se pudo leer memory.current",
                self.backend.nombre()
            ),
        }
        r
    }

    fn registrar(&mut self, f: Fase) {
        println!("{}", f.linea(self.backend));
        self.fases.push(f);
    }
}

fn bytes_de(s: &str) -> Result<u64, String> {
    s.trim()
        .parse::<u64>()
        .map_err(|e| format!("`{}` no es un número de bytes: {e}", s.trim()))
}

/// El directorio del cgroup v2 de un contenedor, por el pid de su proceso
/// inicial. **No se arma la ruta a mano** (`system.slice/docker-<id>.scope`):
/// depende del driver de cgroups de Docker, y `/proc/<pid>/cgroup` la dice.
fn cgroup_del_contenedor(nombre: &str) -> Result<PathBuf, String> {
    let salida = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Pid}}", nombre])
        .output()
        .map_err(|e| format!("docker inspect: {e}"))?;
    if !salida.status.success() {
        return Err(format!("docker inspect {nombre} falló"));
    }
    let pid = String::from_utf8_lossy(&salida.stdout).trim().to_owned();
    if pid.is_empty() || pid == "0" {
        return Err(format!("{nombre} no tiene un proceso vivo"));
    }
    let texto = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|e| format!("/proc/{pid}/cgroup: {e}"))?;
    cgroup_v2_de(&texto, Path::new("/sys/fs/cgroup"))
}

/// La ruta del cgroup v2 en el contenido de `/proc/<pid>/cgroup`.
fn cgroup_v2_de(texto: &str, raiz: &Path) -> Result<PathBuf, String> {
    let rel = texto
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or("el proceso no está en un cgroup v2 (falta la línea `0::`)")?;
    Ok(raiz.join(rel.trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::{Fase, Medidor, Ventana, bytes_de, cgroup_v2_de, contenedor};
    use crate::Backend;
    use std::path::Path;

    #[test]
    fn the_container_name_is_the_one_ere_gives() {
        assert_eq!(contenedor(Backend::Sp1), "ere-server-sp1");
        assert_eq!(contenedor(Backend::OpenVm), "ere-server-openvm");
        assert_eq!(contenedor(Backend::Zisk), "ere-server-zisk");
    }

    #[test]
    fn the_cgroup_path_comes_from_the_v2_line() {
        let t = "0::/system.slice/docker-abc.scope\n";
        assert_eq!(
            cgroup_v2_de(t, Path::new("/sys/fs/cgroup")),
            Ok(Path::new("/sys/fs/cgroup/system.slice/docker-abc.scope").to_path_buf())
        );
        // Un cgroup v1 no tiene `memory.peak`: se rechaza en vez de adivinar.
        assert!(cgroup_v2_de("4:memory:/docker/abc\n", Path::new("/x")).is_err());
    }

    #[test]
    fn a_peak_that_is_not_a_number_is_an_error() {
        assert_eq!(bytes_de("123\n"), Ok(123));
        assert!(bytes_de("max\n").is_err());
        assert!(bytes_de("").is_err());
    }

    /// Un pico acumulado no se publica como el de una fase, y cada fila dice
    /// qué cuenta el número.
    #[test]
    fn the_line_says_the_window_and_what_the_peak_counts() {
        let f = Fase {
            nombre: "prove",
            pico: 10,
            base: 2,
            ventana: Ventana::DesdeQueNacioElContenedor,
        };
        assert_eq!(
            f.linea(Backend::Zisk),
            "memoria|zisk|prove|10|2|acumulado desde que nació el contenedor|incluye anónima, shmem y page cache"
        );
        let g = Fase {
            ventana: Ventana::DeLaFase,
            ..f
        };
        assert_eq!(
            g.linea(Backend::Sp1),
            "memoria|sp1|prove|10|2|de la fase|incluye anónima, shmem y page cache"
        );
    }

    /// **El arranque es acumulado desde que nació el contenedor, y se lee
    /// antes del reinicio de prueba.** Con un archivo común en lugar del
    /// cgroup, la escritura de `reset` agrega texto: si el pico se leyera
    /// después, no sería un número y el arranque fallaría.
    #[test]
    fn the_startup_peak_is_read_before_the_reset_and_labelled_cumulative() {
        let dir = std::env::temp_dir().join(format!("memoria-arranque-{}", std::process::id()));
        assert!(std::fs::create_dir_all(&dir).is_ok());
        assert!(std::fs::write(dir.join("memory.peak"), "6947000000\n").is_ok());
        assert!(std::fs::write(dir.join("memory.current"), "100\n").is_ok());
        let m = Medidor::abrir_en(Backend::Sp1, &dir);
        let Ok(mut m) = m else {
            panic!("tendría que abrir: {:?}", m.err());
        };
        assert_eq!(m.arranque(), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            m.fases,
            vec![Fase {
                nombre: "arranque",
                pico: 6_947_000_000,
                base: 0,
                ventana: Ventana::DesdeQueNacioElContenedor,
            }]
        );
    }
}
