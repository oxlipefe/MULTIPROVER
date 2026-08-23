//! El desglose de ciclos **por diferencia**, que es la única vía portable.
//!
//! # Por qué no salió del backend
//!
//! `ere` expone `ProgramExecutionReport::region_cycles`, y el `Platform` de SP1
//! **sí** emite los marcadores de región. Pero el adapter de SP1 de `ere`
//! construye el reporte con `..Default::default()` sobre `MinimalExecutorEnum`
//! —el ejecutor mínimo, que no corre el cycle tracker— y nadie parsea los
//! marcadores: **el campo no se puebla nunca**. Medido, no inferido.
//!
//! Las salidas eran cuatro: parsear el stdout del guest, usar el SDK de SP1
//! directo, contribuir upstream, o **medir por diferencia**. Las tres primeras
//! miden **SP1**; la cuarta mide cualquier backend que reporte
//! `total_num_cycles`, que es lo que los tres reportan. Como este proyecto va a
//! comparar backends, la portabilidad no es una preferencia: es el requisito.
//!
//! # Cómo funciona
//!
//! El guest acepta un byte de modo, y cada modo ejecuta un prefijo del camino
//! real. La resta entre dos modos consecutivos es lo que cuesta la pieza que
//! los separa. Es **mutation testing aplicado a ciclos**: la misma forma de
//! evidencia que el resto del repo, con el número en vez del veredicto.
//!
//! # Lo que la escalera SÍ separa y lo que NO
//!
//! `StateOnly − DecodeOnly` da la parte de la verificación del witness que es
//! **de arranque**: hashear cada nodo y cada bytecode para indexarlos por su
//! propio hash, más encadenar los headers. La otra mitad de la verificación —
//! **caminar el trie en cada lectura**— ocurre adentro de la ejecución y no se
//! puede separar sin construir un `WitnessState` que sirva valores sin
//! probarlos, o sea sin meter en el árbol un modo que miente. No se hizo, y por
//! eso el número de "verificación" que esta escalera reporta es un **piso**, no
//! el total. Decirlo es parte del dato.

use crate::{Execute, Journal, Mode, Run, RunError, execute_block};

/// Los modos, del más completo al más chico. **El orden es el de la escalera**:
/// cada uno saca una pieza más que el anterior.
pub const LADDER: [Mode; 7] = [
    Mode::Full,
    Mode::NoRoot,
    Mode::NoTxs,
    Mode::StateOnly,
    Mode::Recover,
    Mode::DecodeOnly,
    Mode::Nop,
];

/// Una pieza del guest y lo que cuesta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    pub name: &'static str,
    pub cycles: u64,
}

/// El desglose completo de una corrida.
#[derive(Debug, Clone)]
pub struct Breakdown {
    /// Los ciclos del camino real (`Mode::Full`).
    pub total: u64,
    /// El journal que el camino real publicó — el que hay que contrastar
    /// contra lo que el harness computó afuera del zkVM.
    pub journal: Journal,
    /// Cuánto tardó el `execute` del camino real. Es tiempo de pared del
    /// backend, no una propiedad del programa: depende del camino de Docker y
    /// de la máquina, al revés que los ciclos.
    pub full_duration: core::time::Duration,
    /// Cada modo con sus ciclos, en el orden de la escalera.
    pub rungs: Vec<(Mode, u64)>,
    /// Las piezas, ya restadas.
    pub pieces: Vec<Piece>,
}

/// El nombre de la pieza que separa a `arriba` de `abajo`.
const fn piece_name(arriba: Mode, abajo: Mode) -> &'static str {
    match (arriba, abajo) {
        (Mode::Full, Mode::NoRoot) => "recomputación del post-state root",
        (Mode::NoRoot, Mode::NoTxs) => "ejecución de las transacciones",
        (Mode::NoTxs, Mode::StateOnly) => "lifecycle del bloque (system calls + withdrawals)",
        (Mode::StateOnly, Mode::Recover) => "verificación del witness (indexado + cadena)",
        (Mode::Recover, Mode::DecodeOnly) => "recuperación ECDSA de los remitentes",
        (Mode::DecodeOnly, Mode::Nop) => "decodificación del input",
        _ => "pieza sin nombre",
    }
}

/// Corre la escalera entera y devuelve el desglose.
///
/// # Errors
/// El primer modo que no ejecute corta: un desglose con un peldaño faltante
/// daría restas sin sentido, y publicar un número que no se midió es
/// exactamente lo que no se puede hacer acá.
pub fn breakdown<E: Execute + ?Sized>(zkvm: &E, block: &[u8]) -> Result<Breakdown, RunError> {
    let mut rungs: Vec<(Mode, Run)> = Vec::with_capacity(LADDER.len());
    for mode in LADDER {
        rungs.push((mode, execute_block(zkvm, mode, block)?));
    }
    let total = rungs[0].1.cycles;
    let journal = rungs[0].1.journal;
    let full_duration = rungs[0].1.duration;
    let pieces = rungs
        .windows(2)
        .map(|par| Piece {
            name: piece_name(par[0].0, par[1].0),
            // `saturating_sub`: un peldaño de abajo más caro que el de arriba
            // sería un hallazgo, no un número negativo. Se ve igual en la
            // tabla de peldaños, que va cruda.
            cycles: par[0].1.cycles.saturating_sub(par[1].1.cycles),
        })
        .collect();
    Ok(Breakdown {
        total,
        journal,
        full_duration,
        rungs: rungs.iter().map(|(m, r)| (*m, r.cycles)).collect(),
        pieces,
    })
}

#[cfg(test)]
mod tests {
    use super::{LADDER, piece_name};
    use crate::Mode;

    /// **La escalera cubre todos los modos y no repite ninguno.** Un modo
    /// suelto sería una pieza que nadie mide; uno repetido, una resta en cero
    /// con cara de dato.
    #[test]
    fn the_ladder_covers_every_mode_exactly_once() {
        let todos = [
            Mode::Full,
            Mode::NoRoot,
            Mode::NoTxs,
            Mode::StateOnly,
            Mode::Recover,
            Mode::DecodeOnly,
            Mode::Nop,
        ];
        assert_eq!(LADDER.len(), todos.len());
        for m in todos {
            assert_eq!(
                LADDER.iter().filter(|x| **x == m).count(),
                1,
                "{m:?} no aparece exactamente una vez en la escalera"
            );
        }
    }

    /// Cada par consecutivo tiene una pieza con nombre: un `"pieza sin nombre"`
    /// en la tabla sería una resta que nadie sabe qué mide.
    #[test]
    fn every_step_of_the_ladder_names_its_piece() {
        for par in LADDER.windows(2) {
            assert_ne!(
                piece_name(par[0], par[1]),
                "pieza sin nombre",
                "{:?} -> {:?} no tiene nombre",
                par[0],
                par[1]
            );
        }
    }
}
