//! Congela **un** bloque real del corpus como caso de zkVM.
//!
//! # Por qué existe
//!
//! Ejecutar el guest adentro de un backend cuesta una compilación de decenas de
//! minutos y una imagen de Docker de varios GB. Volver a moler los 42 017
//! bloques de EEST cada vez que se quiere correr ese camino sería absurdo — y
//! además el corpus de EEST no está vendoreado (son 257 MB con cache aparte),
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
//! Se queda con el **primer** bloque de Prague que tenga transacciones y system
//! calls de cierre — o sea el lifecycle completo, no un bloque vacío que
//! pasaría por vacuidad.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use repo_b_common::primitives::B256;
use repo_b_guest::journal::{Journal, Mode};

/// A dónde escribir, si es que hay que escribir. `None` = el modo está apagado,
/// que es el default de toda corrida del gate.
fn dump_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var_os("REPO_B_GUEST_DUMP_DIR").map(PathBuf::from))
        .as_ref()
}

static YA: AtomicBool = AtomicBool::new(false);

/// El nombre del caso congelado. Un solo par de archivos: el camino del zkVM se
/// corre sobre UN bloque, no sobre un set.
pub const CASE_INPUT: &str = "block-input.bin";
pub const CASE_JOURNAL: &str = "block-journal.txt";

/// Escribe el caso si el modo está prendido y este bloque es el primero que
/// califica. No devuelve error: es instrumentación, no un veredicto.
pub fn offer(bytes: &[u8], journal: &Journal, identidad: &str) {
    let Some(dir) = dump_dir() else { return };
    // `swap` y no `load`+`store`: el driver es paralelo y dos bloques podrían
    // pasar el chequeo a la vez, dejando el par de archivos cruzado.
    if YA.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("[dump] no se pudo crear {}: {e}", dir.display());
        return;
    }
    let _ = std::fs::write(dir.join(CASE_INPUT), bytes);
    let _ = std::fs::write(
        dir.join(CASE_JOURNAL),
        format!(
            "# El bloque real que el guest ejecuta adentro del zkVM.\n\
             # Lo escribió `--witness-blocks` con REPO_B_GUEST_DUMP_DIR; el journal\n\
             # esperado lo computó el driver CON EL ESTADO COMPLETO, no por el\n\
             # camino del witness que el guest recorre.\n\
             case {identidad}\n\
             input_bytes {}\n\
             pre_state_root {}\n\
             post_state_root {}\n\
             output_digest {}\n",
            bytes.len(),
            journal.pre_state_root,
            journal.post_state_root,
            journal.output_digest,
        ),
    );
    eprintln!(
        "[dump] caso congelado en {} — {} ({} bytes de input)",
        dir.display(),
        identidad,
        bytes.len()
    );
}

/// ¿Vale la pena congelar este bloque? Ver el doc del módulo: un bloque sin
/// transacciones ni system calls de cierre pasaría por vacuidad.
#[must_use]
pub fn califica(txs: usize, closing: usize, opening: usize) -> bool {
    dump_dir().is_some() && txs > 0 && closing > 0 && opening > 0
}

/// El journal que el guest tiene que publicar para este bloque.
#[must_use]
pub fn journal_esperado(
    pre_state_root: B256,
    post_state_root: B256,
    output_digest: B256,
) -> Journal {
    Journal {
        mode: Mode::Full,
        pre_state_root,
        post_state_root,
        output_digest,
    }
}
