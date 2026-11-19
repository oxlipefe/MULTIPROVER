//! Congela **un** bloque real del corpus como caso de zkVM.
//!
//! # Por qué existe
//!
//! Ejecutar el guest adentro de un backend cuesta una compilación de decenas de
//! minutos y una imagen de Docker de varios GB. Volver a moler los 42 017
//! bloques de EEST cada vez que se quiere correr ese camino sería absurdo — y
//! además el corpus de EEST no está vendoreado (son 515 MB con cache aparte),
//! así que un caso congelado es lo único que hace **reproducible** la corrida
//! del zkVM en un clon limpio.
//!
//! # Qué se congela, y qué NO
//!
//! Se congela el **input** (los bytes que entran al guest) y el **journal
//! esperado** (lo que el guest tiene que publicar). El journal esperado lo
//! computa el driver **con el estado completo**, que es exactamente lo que el
//! guest no tiene: si saliera del mismo camino que el guest recorre, compararlo
//! sería compararlo consigo mismo — el `[SAME]` que no prueba nada.
//!
//! # Cómo se repuebla
//!
//! ```sh
//! REPO_B_GUEST_DUMP_DIR=cmd/conformance/fixtures/guest \
//!   cargo run --release -p conformance -- --witness-blocks
//! ```
//!
//! **El caso se elige por su etiqueta**, `<nombre del test> #<número de
//! bloque>`: [`FROZEN_CASE`] por default, o la que diga
//! `REPO_B_GUEST_DUMP_CASE`. No se elige "el primero que califique": el driver
//! recorre el corpus en serie y ordenado, así que el primero sería
//! determinista, pero un cambio de tag de EEST que agregara un archivo antes
//! movería el caso **en silencio**. Con la etiqueta, un tag que ya no trae el
//! test hace fallar la corrida en vez de congelar otro bloque.
//!
//! La etiqueta tiene que nombrar un bloque VÁLIDO, de Prague en adelante, con
//! transacciones y system calls de arranque y de cierre — el lifecycle
//! completo, no un bloque vacío que pasaría por vacuidad. Un bloque que no
//! califica no se congela aunque la etiqueta lo nombre.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use repo_b_guest::journal::{JOURNAL_VERSION, Journal};

/// El caso congelado: Osaka, bloque 1, dos txs, las dos system calls de
/// arranque y las dos de cierre.
pub const FROZEN_CASE: &str = "tests/amsterdam/eip8037_state_creation_gas_cost_increase/test_block_2d_gas_accounting.py::test_tx_inclusion_at_execution_gas_block_limit_small[fork_Osaka-blockchain_test-exactly_fits] #1";

/// A dónde escribir, si es que hay que escribir. `None` = el modo está apagado,
/// que es el default de toda corrida del gate.
fn dump_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var_os("REPO_B_GUEST_DUMP_DIR").map(PathBuf::from))
        .as_ref()
}

/// La etiqueta del caso a congelar: la del entorno o [`FROZEN_CASE`].
fn wanted() -> &'static str {
    static CASE: OnceLock<String> = OnceLock::new();
    CASE.get_or_init(|| {
        std::env::var("REPO_B_GUEST_DUMP_CASE").unwrap_or_else(|_| FROZEN_CASE.to_owned())
    })
}

/// La etiqueta de un bloque: el nombre completo del test y su número.
#[must_use]
pub fn label(test: &str, number: u64) -> String {
    format!("{test} #{number}")
}

static YA: AtomicBool = AtomicBool::new(false);

/// El nombre del caso congelado. Un solo par de archivos: el camino del zkVM se
/// corre sobre UN bloque, no sobre un set.
pub const CASE_INPUT: &str = "block-input.bin";
pub const CASE_JOURNAL: &str = "block-journal.txt";

/// Escribe el caso si el modo está prendido y este bloque es el pedido. No
/// devuelve error: es instrumentación, no un veredicto — pero si no llega a
/// escribir, [`report`] lo dice y la corrida falla.
///
/// El journal se escribe **campo por campo**, una línea por campo y con el
/// valor como segundo token: es lo que leen `cmd/zkvm` y la receta, sin
/// depender del layout binario.
pub fn offer(etiqueta: &str, bytes: &[u8], journal: &Journal, identidad: &str) {
    let Some(dir) = dump_dir() else { return };
    if etiqueta != wanted() {
        return;
    }
    // El directorio ANTES de marcar el caso como escrito: si no se puede
    // crear, el caso no quedó congelado y `report` lo tiene que decir.
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("[dump] no se pudo crear {}: {e}", dir.display());
        return;
    }
    // `swap` y no `load`+`store`: si el mismo bloque se ofreciera dos veces,
    // el par de archivos se escribe una sola.
    if YA.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut texto = format!(
        "# El bloque real que el guest ejecuta adentro del zkVM.\n\
         # Lo escribió `--witness-blocks` con REPO_B_GUEST_DUMP_DIR; el journal\n\
         # esperado lo computó el driver CON EL ESTADO COMPLETO, no por el\n\
         # camino del witness que el guest recorre.\n\
         case {identidad}\n\
         input_bytes {}\n\
         version {JOURNAL_VERSION}\n\
         mode {}\n",
        bytes.len(),
        journal.mode.as_byte(),
    );
    texto.push_str(&journal_lines(journal));
    let escrito = std::fs::write(dir.join(CASE_INPUT), bytes)
        .and_then(|()| std::fs::write(dir.join(CASE_JOURNAL), texto));
    if let Err(e) = escrito {
        eprintln!(
            "[dump] no se pudo escribir el caso en {}: {e}",
            dir.display()
        );
        // No quedó congelado: que `report` lo diga.
        YA.store(false, Ordering::SeqCst);
        return;
    }
    eprintln!(
        "[dump] caso congelado en {} — {} ({} bytes de input)",
        dir.display(),
        identidad,
        bytes.len()
    );
}

/// Al final de la corrida: si se pidió congelar un caso, ¿se congeló? `false`
/// es un fallo de la corrida — una etiqueta que el corpus ya no trae no
/// congela otro bloque en su lugar.
#[must_use]
pub fn report() -> bool {
    let Some(dir) = dump_dir() else { return true };
    if YA.load(Ordering::SeqCst) {
        eprintln!("[dump] caso congelado: {}", wanted());
        return true;
    }
    eprintln!(
        "[dump] FAIL: el caso `{}` no se congeló en {} (el corpus no lo trae, no califica o no se pudo escribir)",
        wanted(),
        dir.display()
    );
    false
}

/// ¿Vale la pena congelar este bloque? Ver el doc del módulo: un bloque sin
/// transacciones ni system calls de cierre pasaría por vacuidad.
#[must_use]
pub fn califica(txs: usize, closing: usize, opening: usize) -> bool {
    dump_dir().is_some() && txs > 0 && closing > 0 && opening > 0
}

/// Los campos del journal, uno por línea y con el valor como segundo token.
/// El fork lleva además su nombre entre paréntesis.
#[must_use]
pub fn journal_lines(journal: &Journal) -> String {
    let mut texto = String::new();
    for (campo, valor) in journal.fields() {
        let nombre = match (campo, journal.fork) {
            ("fork", Some(spec)) => format!(" ({spec:?})"),
            _ => String::new(),
        };
        texto.push_str(&format!("{campo} {valor}{nombre}\n"));
    }
    texto
}
