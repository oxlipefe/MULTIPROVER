//! El arranque bare-metal del guest: allocator, panic handler y `_start`.
//!
//! **Todo lo específico del metal está acá y en ningún otro lado.** La lógica
//! vive en `lib.rs`, que es `no_std` pero se testea en el host; este archivo es
//! la cáscara mínima que convierte esa lógica en un ELF.
//!
//! En el host (`cargo build --workspace`) compila como un binario normal que no
//! hace nada: sin esto, un `cargo test` en la máquina de desarrollo intentaría
//! linkear un binario sin `main` y fallaría. El shell real está detrás de
//! `target_os = "none"`.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
fn main() {
    // En el host este binario no tiene rol: el ELF del guest se construye con
    // `--target riscv64imac-unknown-none-elf`.
}

#[cfg(target_os = "none")]
mod bare {
    extern crate alloc;

    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use repo_b_common::primitives::B256;
    use repo_b_guest::codec::decode;
    use repo_b_guest::{digest_of, reservar, run_block};

    /// El buffer del input. Hoy vacío: el host lo llena, y cuando entre un
    /// backend de proving lo reemplaza su región de stdin. Lo que importa acá es
    /// que **el decoder esté en el camino**, porque un decoder que el linker
    /// descarta no es un decoder que corra en el guest.
    static ENTRADA: [u8; 0] = [];

    /// Arena del allocator. Va en `.bss` (arranca en cero), así que **no**
    /// engorda el ELF: son 64 MiB de direcciones, no de archivo.
    const ARENA_BYTES: usize = 64 * 1024 * 1024;

    /// **Bump allocator que nunca libera**, y es deliberado, no una simplificación
    /// que haya que arreglar después.
    ///
    /// Adentro de una zkVM cada instrucción se paga en el costo de la prueba, y
    /// una free-list cuesta instrucciones en cada `dealloc` para recuperar
    /// memoria que un guest —que corre una vez y muere— no vuelve a necesitar.
    /// Un bump es además **determinista por construcción**: la misma ejecución
    /// devuelve exactamente las mismas direcciones, que es condición de una
    /// prueba reproducible. No hay fragmentación porque no hay reuso.
    ///
    /// Es también la pieza más reemplazable del árbol: cuando entre un backend,
    /// su SDK trae el suyo y esto se borra.
    struct Bump;

    #[repr(C, align(16))]
    struct Arena(UnsafeCell<[u8; ARENA_BYTES]>);

    // SAFETY (excepción 1 de 2, declarada en Cargo.toml): el guest es de un
    // solo hilo — no hay `spawn` ni scheduler adentro de una zkVM — así que el
    // acceso a la arena no puede solaparse. El offset igual se lleva en un
    // atómico, de modo que la corrección no depende de esa premisa.
    #[allow(unsafe_code)]
    unsafe impl Sync for Arena {}

    static ARENA: Arena = Arena(UnsafeCell::new([0; ARENA_BYTES]));
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    // SAFETY (excepción 2 de 2): `GlobalAlloc` es un trait `unsafe` — no hay
    // forma de registrar un allocator en Rust seguro. El contrato que hay que
    // cumplir es devolver o bien un bloque alineado y no solapado de al menos
    // `layout.size()` bytes, o bien null; las dos ramas están abajo, y toda la
    // aritmética es `checked_*` para que un `Layout` hostil no envuelva.
    #[allow(unsafe_code)]
    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let base = ARENA.0.get().cast::<u8>();
            let mut asignado: usize = 0;
            // Toda la aritmética vive en `reservar`, que se prueba en el host.
            // Acá adentro queda solo la entrega del puntero.
            let resultado = NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |actual| {
                let (offset, fin) = reservar(actual, layout.align(), layout.size(), ARENA_BYTES)?;
                asignado = offset;
                Some(fin)
            });
            if resultado.is_err() {
                // Arena agotada o aritmética desbordada: null es "no pude", que
                // es lo que el contrato pide. Nunca devolver un puntero dudoso.
                return core::ptr::null_mut();
            }
            base.wrapping_add(asignado)
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
            // Un bump no libera. Ver el doc-comment de `Bump`.
        }
    }

    #[global_allocator]
    static ALLOCATOR: Bump = Bump;

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        // Adentro de la zkVM un panic no es un error que se reporte: es una
        // ejecución que no se puede probar. Fail-closed y se acabó.
        //
        // `spin_loop` y no `loop {}` pelado: el hint existe y no cuesta nada.
        // El halt de verdad lo trae el backend, y hasta entonces no hay forma
        // segura de emitirlo.
        loop {
            core::hint::spin_loop();
        }
    }

    /// El punto de entrada del ELF.
    ///
    /// Corre el camino real con un input **opaco al optimizador**: sin
    /// `black_box` el compilador podría plegar la ejecución entera y el binario
    /// quedaría vacío — que es exactamente el ELF de cascarón que este slice no
    /// puede aceptar.
    ///
    /// El input es un arranque en seco: hasta que exista el codec, el bloque
    /// real entra tipado desde el host. Lo que este `_start` garantiza es que
    /// **el camino de ejecución está adentro del binario**, que es lo que el
    /// chequeo de floats necesita para medir algo.
    #[allow(unsafe_code)] // `no_mangle` es `unsafe` en la edición 2024.
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        // **El input entra por BYTES**, que es lo único que entra a una zkVM.
        // El buffer es opaco al optimizador: sin `black_box` el compilador
        // podría plegar la decodificación entera y el decoder no llegaría al
        // binario — que es exactamente lo que pasaba cuando `_start` armaba el
        // input tipado.
        let bytes: &[u8] = core::hint::black_box(&ENTRADA);
        let salida = match decode(bytes) {
            Ok(input) => match run_block(&input.as_input()) {
                Ok(changes) => digest_of(&changes),
                Err(_) => B256::ZERO,
            },
            // Un input que no decodifica es un rechazo, nunca una ejecución a
            // medias.
            Err(_) => B256::ZERO,
        };
        core::hint::black_box(salida);
        loop {
            core::hint::spin_loop();
        }
    }
}
