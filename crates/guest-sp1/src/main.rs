//! El ELF del guest para SP1.
//!
//! **Tres líneas a propósito.** Todo lo que hace es instanciar
//! `repo_b_guest::entry` con la `Platform` de SP1: leer el input por
//! `read_input`, ejecutar el bloque y publicar el journal por `write_output`.
//! Si este archivo creciera, sería señal de que algo específico del backend se
//! está colando adentro de la lógica del guest.
#![no_main]

use ere_platform_sp1::{SP1Platform, sp1_zkvm};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    repo_b_guest::entry::<SP1Platform>();
}
