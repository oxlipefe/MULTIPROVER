//! El ELF del guest para OpenVM.
//!
//! **Tres líneas a propósito**, igual que el de SP1. Todo lo que hace es
//! instanciar `repo_b_guest::entry` con la `Platform` de OpenVM: leer el input
//! por `read_input`, ejecutar el bloque y publicar el journal por
//! `write_output`. Si este archivo creciera, sería señal de que algo específico
//! del backend se está colando adentro de la lógica del guest.
//!
//! No hay macro de entrada visible: con la feature `std` de OpenVM el
//! entrypoint se linkea solo y el punto de entrada del guest es un `main`
//! normal.

use ere_platform_openvm::OpenVMPlatform;

fn main() {
    repo_b_guest::entry::<OpenVMPlatform>();
}
