//! **Cuánto heap consume el guest adentro de Pico, medido sobre OTRO ELF.**
//!
//! # Por qué hace falta
//!
//! El allocator de Pico es un bump sin `dealloc` y su heap es fijo (no se
//! configura). Lo que el guest asigna se acumula hasta el final, input
//! incluido, y un bloque que no entra no falla con un error de la EVM: el guest
//! aborta y Pico no prueba. El margen se mide; no se supone.
//!
//! # Qué mide y qué NO
//!
//! El ELF pineado no publica nada además del journal, y alterarlo para medir
//! movería el pin. Por eso la medición corre sobre un ELF **aparte**: la hoja
//! compilada con la feature `medir-heap`, que publica detrás del journal la
//! posición del puntero bump antes y después del bloque. Ese binario difiere
//! del pineado en esas líneas, así que el número es el heap de ESE binario: la
//! diferencia es una asignación de un byte antes y otra después, no el código
//! que corre el bloque. No reemplaza a una medición sobre el ELF pineado
//! (leerle la memoria al emulador), que no existe hoy.
//!
//! Para que el ELF de medición no termine en el lugar del pineado, `compile`
//! exige un nombre de archivo que lo diga.

use std::path::Path;
use std::time::Instant;

use ere_dockerized::DockerizedzkVM;
use repo_b_prover::{Elf, Journal, Mode, ProverResource};

use crate::Backend;
use crate::prueba::hex;

/// La feature de la hoja de Pico que produce el ELF de medición.
pub(crate) const FEATURE: &str = "medir-heap";

/// El ELF de medición se nombra así o no se escribe.
const MARCA_EN_EL_NOMBRE: &str = "medir-heap";

/// El fin del heap de Pico v3.1.5 (`_heap_end` del linker script de
/// `pico-sdk`). Es fijo: el guest no lo elige.
pub(crate) const FIN_DEL_HEAP: u64 = 0x777f_0000;

/// Lo que publica el ELF de medición detrás del journal: dos `u64` LE.
const BYTES_DE_MEDICION: usize = 16;

/// `compile --medir-heap`: solo para Pico, y nunca sobre un ELF que se pinea.
///
/// # Errors
/// Otro backend, o un archivo de salida cuyo nombre no dice que es de medición.
pub(crate) fn validar_salida(backend: Backend, salida: &Path) -> Result<(), String> {
    if backend != Backend::Pico {
        return Err(format!(
            "--medir-heap es una feature de la hoja de Pico; {} no la tiene",
            backend.nombre()
        ));
    }
    let nombre = salida
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if !nombre.contains(MARCA_EN_EL_NOMBRE) {
        return Err(format!(
            "el ELF de medición no es el pineado: su nombre tiene que decir `{MARCA_EN_EL_NOMBRE}` \
             (p. ej. target/guest-pico-medir-heap.elf), y `{}` no lo dice",
            salida.display()
        ));
    }
    Ok(())
}

/// La lectura del ELF de medición.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Heap {
    pub journal: Vec<u8>,
    pub antes: u64,
    pub despues: u64,
}

impl Heap {
    /// Lo que consumió el bloque (input incluido), en bytes.
    pub(crate) fn usado(&self) -> Option<u64> {
        self.despues.checked_sub(self.antes)
    }

    /// Lo que quedó libre al terminar.
    pub(crate) fn margen(&self) -> Option<u64> {
        FIN_DEL_HEAP.checked_sub(self.despues)
    }
}

fn u64_le(bytes: &[u8]) -> Option<u64> {
    bytes.try_into().ok().map(u64::from_le_bytes)
}

/// Separa el journal de las dos posiciones. **Fail-closed**: otro largo, un
/// journal que no decodifica, un puntero que retrocede o que pasa el fin del
/// heap no son una medición.
///
/// # Errors
/// Cualquiera de esos casos.
pub(crate) fn leer(publicos: &[u8]) -> Result<Heap, String> {
    let esperado = repo_b_prover::JOURNAL_BYTES
        .checked_add(BYTES_DE_MEDICION)
        .ok_or("desborde del largo esperado")?;
    if publicos.len() != esperado {
        return Err(format!(
            "el ELF de medición publica {esperado} bytes (journal + 16) y llegaron {}: \
             ¿es el ELF pineado en vez del de medición?",
            publicos.len()
        ));
    }
    let (journal, cola) = publicos.split_at(repo_b_prover::JOURNAL_BYTES);
    if Journal::decode(journal).is_none() {
        return Err("los primeros bytes no son un journal".into());
    }
    let (a, d) = cola.split_at(BYTES_DE_MEDICION / 2);
    let (antes, despues) = (u64_le(a), u64_le(d));
    let (Some(antes), Some(despues)) = (antes, despues) else {
        return Err("las posiciones no son dos u64".into());
    };
    if despues < antes || despues > FIN_DEL_HEAP {
        return Err(format!(
            "posiciones imposibles: antes {antes:#x}, después {despues:#x}, fin {FIN_DEL_HEAP:#x}"
        ));
    }
    Ok(Heap {
        journal: journal.to_vec(),
        antes,
        despues,
    })
}

/// `zkvm heap --backend pico --elf <medición> --mode N`: ejecuta (no prueba) y
/// reporta el heap. En `Full` el journal además pasa la política del bloque.
///
/// # Errors
/// Otro backend, el ELF pineado en vez del de medición, o una ejecución que falla.
pub(crate) fn medir(
    backend: Backend,
    elf_path: &Path,
    modo: u8,
    root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if backend != Backend::Pico {
        return Err("`heap` mide el allocator de Pico; con otro backend no mide nada".into());
    }
    let mode = Mode::from_byte(modo).ok_or("modo desconocido")?;
    let elf = Elf(std::fs::read(elf_path)?);
    let bloque = crate::entrada::bytes(root)?;
    let zkvm = DockerizedzkVM::new(
        backend.kind(),
        elf,
        ProverResource::Cpu,
        crate::config_backend(),
    )?;
    let t = Instant::now();
    let zkvm = crate::Dockerizado(zkvm, backend);
    let (publicos, _) =
        repo_b_prover::Execute::execute_raw(&zkvm, &repo_b_prover::zkvm_input(mode, &bloque))?;
    let h = leer(publicos.as_ref())?;
    println!(
        "modo {mode:?}: ejecutado en {:?} (ELF de medición, NO el pineado)",
        t.elapsed()
    );
    println!("journal hex ({} B) {}", h.journal.len(), hex(&h.journal));
    println!("heap antes del bloque   {:#x}", h.antes);
    println!("heap después del bloque {:#x}", h.despues);
    println!(
        "heap usado por el bloque {} B (acumulado: el bump no libera)",
        h.usado().unwrap_or(0)
    );
    println!(
        "margen hasta el fin     {} B (fin {FIN_DEL_HEAP:#x})",
        h.margen().unwrap_or(0)
    );
    if mode == Mode::Full
        && let Some(falla) = crate::politica_de_bloque(&h.journal, root)?
    {
        return Err(falla.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FIN_DEL_HEAP, leer, validar_salida};
    use crate::Backend;
    use std::path::Path;

    fn publicos(antes: u64, despues: u64) -> Vec<u8> {
        let mut j = repo_b_prover::Journal::empty(repo_b_prover::Mode::Nop)
            .encode()
            .to_vec();
        j.extend_from_slice(&antes.to_le_bytes());
        j.extend_from_slice(&despues.to_le_bytes());
        j
    }

    #[test]
    fn a_measurement_is_read_after_the_journal() {
        let h = leer(&publicos(0x1000, 0x3000));
        assert_eq!(h.as_ref().ok().and_then(super::Heap::usado), Some(0x2000));
        assert_eq!(
            h.as_ref().ok().and_then(super::Heap::margen),
            Some(FIN_DEL_HEAP - 0x3000)
        );
    }

    #[test]
    fn the_pinned_elf_output_is_not_a_measurement() {
        let solo_journal = repo_b_prover::Journal::empty(repo_b_prover::Mode::Nop).encode();
        let e = leer(&solo_journal).err().unwrap_or_default();
        assert!(e.contains("¿es el ELF pineado"), "{e}");
        let mut sobra = publicos(0x1000, 0x3000);
        sobra.push(0);
        assert!(
            leer(&sobra).is_err(),
            "un byte de más tampoco es la medición"
        );
    }

    #[test]
    fn impossible_positions_are_refused() {
        assert!(leer(&publicos(0x3000, 0x1000)).is_err(), "retrocede");
        assert!(
            leer(&publicos(0x1000, FIN_DEL_HEAP + 1)).is_err(),
            "pasa el fin"
        );
    }

    #[test]
    fn the_measurement_elf_never_takes_a_pinned_name() {
        let ok = Path::new("target/guest-pico-medir-heap.elf");
        assert!(validar_salida(Backend::Pico, ok).is_ok());
        assert!(validar_salida(Backend::Pico, Path::new("target/guest-pico.elf")).is_err());
        assert!(validar_salida(Backend::Zisk, ok).is_err());
    }
}
