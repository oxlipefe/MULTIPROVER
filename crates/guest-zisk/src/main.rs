//! El ELF del guest para ZisK.
//!
//! **Tres líneas a propósito**, igual que los de SP1 y OpenVM. Todo lo que hace
//! es instanciar `repo_b_guest::entry` con la `Platform` de ZisK: leer el input
//! por `read_input`, ejecutar el bloque y publicar el journal por
//! `write_output`. Si este archivo creciera, sería señal de que algo específico
//! del backend se está colando adentro de la lógica del guest.
//!
//! El exit code es parte del contrato: `ziskos::entrypoint!` devuelve `0` en
//! `a0` cuando `main` retorna, y ZisK solo prueba una ejecución que termina
//! así. Un rechazo del bloque es un panic, que con `panic = "abort"` termina en
//! trap: una ejecución que el backend marca como fallida y no prueba.
#![no_main]

use ere_platform_zisk::{ZiskPlatform, ziskos};

ziskos::entrypoint!(main);

pub fn main() {
    repo_b_guest::entry::<ZiskPlatform>();
}
