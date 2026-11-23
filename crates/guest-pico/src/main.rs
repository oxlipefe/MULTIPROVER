//! El ELF del guest para Pico.
//!
//! **Tres líneas a propósito**, igual que los de SP1, OpenVM y ZisK. Todo lo
//! que hace es instanciar `repo_b_guest::entry` con la `Platform` de Pico: leer
//! el input por `read_input`, ejecutar el bloque y publicar el journal por
//! `write_output`. Si este archivo creciera, sería señal de que algo específico
//! del backend se está colando adentro de la lógica del guest.
//!
//! Un rechazo del bloque es un panic, que con `panic = "abort"` termina la
//! ejecución con un código distinto de cero: Pico no la prueba.
//!
//! La única excepción es el módulo `medir`, que solo existe con la feature
//! `medir-heap` y produce otro binario (ver el `Cargo.toml`).
#![no_main]

use ere_platform_pico::{PicoPlatform, pico_sdk};

pico_sdk::entrypoint!(main);

pub fn main() {
    #[cfg(feature = "medir-heap")]
    let antes = medir::posicion();
    repo_b_guest::entry::<PicoPlatform>();
    #[cfg(feature = "medir-heap")]
    medir::publicar(antes);
}

/// **El puntero bump, leído sin `unsafe`.** El allocator de Pico entrega cada
/// asignación en su puntero actual alineado y avanza; una asignación de 1 byte
/// con alineación 1 cae exactamente en la posición del puntero. Como no hay
/// `dealloc`, la diferencia entre la posición después y antes del bloque es el
/// heap ACUMULADO que consumió `entry` (input incluido), y la posición final
/// contra el fin del heap es el margen que quedó.
#[cfg(feature = "medir-heap")]
mod medir {
    extern crate alloc;
    use alloc::boxed::Box;

    pub fn posicion() -> u64 {
        // `black_box`: sin él, la asignación se puede elidir y la dirección
        // dejaría de ser la del puntero bump.
        let caja = core::hint::black_box(Box::new(0u8));
        let direccion = core::ptr::from_ref::<u8>(&caja) as usize;
        u64::try_from(direccion).unwrap_or(u64::MAX)
    }

    /// 16 bytes LE detrás del journal: posición antes y después.
    pub fn publicar(antes: u64) {
        let despues = posicion();
        let mut salida = antes.to_le_bytes().to_vec();
        salida.extend_from_slice(&despues.to_le_bytes());
        super::pico_sdk::io::commit_bytes(&salida);
    }
}
