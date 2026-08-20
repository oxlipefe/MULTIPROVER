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
    use repo_b_common::witness::ExecutionWitness;
    use repo_b_evm::types::{BlockEnv, Spec};
    use repo_b_guest::{GuestInput, digest_of, run_block};

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
            let resultado = NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |actual| {
                // Alinear hacia arriba sin desbordar: `align` es potencia de 2
                // por contrato de `Layout`, pero el `+ align - 1` sí puede
                // envolver con un tamaño hostil.
                let align = layout.align();
                let alineado = actual.checked_add(align.saturating_sub(1))? & !(align - 1);
                let fin = alineado.checked_add(layout.size())?;
                if fin > ARENA_BYTES {
                    return None;
                }
                asignado = alineado;
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
        let witness = core::hint::black_box(ExecutionWitness::default());
        let root = core::hint::black_box(B256::ZERO);
        // `BlockEnv` no tiene `Default` a propósito: un fork por descarte es
        // cómo se contesta la regla equivocada en silencio. Se escribe entero.
        let env = core::hint::black_box(BlockEnv {
            spec: Spec::Prague,
            chain_id: 1,
            number: 1,
            coinbase: repo_b_common::primitives::Address::ZERO,
            timestamp: 0,
            gas_limit: 30_000_000,
            base_fee: 0,
            prevrandao: B256::ZERO,
            blob_excess_gas: None,
            blob_base_fee: None,
            blob_base_fee_update_fraction: None,
        });
        let input = GuestInput {
            witness: &witness,
            pre_state_root: root,
            env,
            txs: &[],
            withdrawals: alloc::vec::Vec::new(),
            system_calls: &[],
        };
        let salida = match run_block(&input) {
            Ok(changes) => digest_of(&changes),
            Err(_) => B256::ZERO,
        };
        core::hint::black_box(salida);
        loop {
            core::hint::spin_loop();
        }
    }
}
