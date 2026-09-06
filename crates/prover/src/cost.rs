//! El desglose del costo **por diferencia**, que es la única vía portable.
//!
//! # Por qué no salió del backend
//!
//! El backend estima el costo de una corrida, pero lo desglosa por **sus**
//! tablas —`opcode`, `syscall`, `system` en uno; `rv64`, `precompile`, `system`
//! en otro—, que son piezas del circuito y no piezas de nuestro guest. Ninguno
//! contesta qué cuesta decodificar el input o recomputar el post-state root.
//!
//! Las salidas eran cuatro: parsear el stdout del guest, usar el SDK de un
//! backend directo, contribuir upstream, o **medir por diferencia**. Las tres
//! primeras miden **un** backend; la cuarta mide cualquiera que estime costo,
//! que es lo que hacen los tres. Como este proyecto va a comparar backends, la
//! portabilidad no es una preferencia: es el requisito.
//!
//! # La unidad viaja con el número
//!
//! Lo que se resta acá **no son ciclos**, y no es la misma unidad en dos
//! backends: cada uno define la suya. Restar dos peldaños del MISMO backend es
//! legítimo —la unidad se cancela—; leer el resultado sin decir en qué está
//! medido, o compararlo contra el de otro backend, no lo es. Por eso el
//! desglose publica la unidad al lado del total, y el que la declara es el
//! implementador del seam.
//!
//! # Cómo funciona
//!
//! El guest acepta un byte de modo, y cada modo ejecuta un prefijo del camino
//! real. La resta entre dos modos consecutivos es lo que cuesta la pieza que
//! los separa. Es **mutation testing aplicado al costo**: la misma forma de
//! evidencia que el resto del repo, con el número en vez del veredicto.
//!
//! # La escalera se verifica, no se cree
//!
//! Un peldaño que ejecuta un prefijo más largo no puede costar menos que el
//! anterior, y el camino real tiene que costar **estrictamente** más que el
//! peldaño que no hace nada. Sin esa segunda mitad, un estimador que devuelve
//! todo en cero satisface la primera y la tabla sale con cara de dato sin haber
//! medido nada. Ver `monotonia`.
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

use std::collections::BTreeMap;

use crate::{Cost, EstimateCost, Journal, Mode, RunError, execute_block_cost};

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

/// Una pieza del guest y lo que cuesta, en la unidad del desglose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    pub name: &'static str,
    pub cost: u64,
}

/// El desglose completo de una corrida.
#[derive(Debug, Clone)]
pub struct Breakdown {
    /// El costo del camino real (`Mode::Full`).
    pub total: u64,
    /// **En qué está medido todo lo de acá.** Un total, unos peldaños y unas
    /// piezas sin esto son números que no se pueden leer.
    pub unit: &'static str,
    /// El journal que el camino real publicó — el que hay que contrastar
    /// contra lo que el harness computó afuera del zkVM.
    pub journal: Journal,
    /// El desglose por tablas que da el backend para el camino real. **No es**
    /// el desglose por pieza: nombra el circuito, no nuestro código.
    pub components: BTreeMap<String, u64>,
    /// Lo que el estimador vio de heap en el camino real. `None` cuando no lo
    /// puede leer, que no es cero.
    pub peak_heap_bytes: Option<u64>,
    /// Cada modo con su costo, en el orden de la escalera.
    pub rungs: Vec<(Mode, u64)>,
    /// Las piezas, ya restadas.
    pub pieces: Vec<Piece>,
}

impl Breakdown {
    /// Si la escalera se comporta como una escalera. Ver `monotonia`.
    ///
    /// # Errors
    /// Un peldaño más barato que el de abajo, o un camino real que no cuesta
    /// más que el peldaño que no hace nada.
    pub fn monotonia(&self) -> Result<(), Vec<String>> {
        monotonia(&self.rungs)
    }
}

/// **La escalera tiene que comportarse como una escalera.**
///
/// Dos reglas, y hacen falta las dos:
///
/// 1. Cada peldaño cuesta **≥** el de abajo. Ejecuta un prefijo más largo del
///    mismo camino, así que costar menos sería un hallazgo sobre el estimador o
///    sobre el guest.
/// 2. El camino real cuesta **estrictamente más** que el peldaño que no hace
///    nada. Sin esto, un estimador que devuelve todo en cero pasa la regla 1
///    —cero es ≥ cero— y el desglose entero sale en cero con cara de medición.
///
/// # Errors
/// Una entrada por violación, para no reportar solo la primera.
pub fn monotonia(rungs: &[(Mode, u64)]) -> Result<(), Vec<String>> {
    let mut fallas = Vec::new();
    for par in rungs.windows(2) {
        let ((arriba, ca), (abajo, cb)) = (par[0], par[1]);
        if ca < cb {
            fallas.push(format!(
                "{arriba:?} ({ca}) cuesta MENOS que {abajo:?} ({cb}), y ejecuta un prefijo más largo"
            ));
        }
    }
    match (rungs.first(), rungs.last()) {
        (Some((arriba, ca)), Some((abajo, cb))) if arriba != abajo && ca <= cb => {
            fallas.push(format!(
                "{arriba:?} ({ca}) no cuesta MÁS que {abajo:?} ({cb}): sin un salto estricto entre \
                 las puntas, un estimador que devuelve cero satisface la escalera entera"
            ));
        }
        _ => {}
    }
    if fallas.is_empty() {
        Ok(())
    } else {
        Err(fallas)
    }
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
pub fn breakdown<E: EstimateCost + ?Sized>(zkvm: &E, block: &[u8]) -> Result<Breakdown, RunError> {
    let mut peldanos: Vec<(Mode, Journal, Cost)> = Vec::with_capacity(LADDER.len());
    for mode in LADDER {
        let r = execute_block_cost(zkvm, mode, block)?;
        peldanos.push((mode, r.journal, r.cost));
    }
    let (_, journal, full) = &peldanos[0];
    let rungs: Vec<(Mode, u64)> = peldanos.iter().map(|(m, _, c)| (*m, c.total)).collect();
    let pieces = rungs
        .windows(2)
        .map(|par| Piece {
            name: piece_name(par[0].0, par[1].0),
            // `saturating_sub`: un peldaño de abajo más caro que el de arriba
            // sería un hallazgo, no un número negativo. Se ve igual en la
            // tabla de peldaños, que va cruda, y `monotonia` lo nombra.
            cost: par[0].1.saturating_sub(par[1].1),
        })
        .collect();
    Ok(Breakdown {
        total: full.total,
        unit: full.unit,
        journal: *journal,
        components: full.components.clone(),
        peak_heap_bytes: full.peak_heap_bytes,
        rungs,
        pieces,
    })
}

#[cfg(test)]
mod tests {
    use super::{LADDER, monotonia, piece_name};
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

    /// **Una escalera de ceros NO es monótona.** Es la regla que separa "cada
    /// peldaño cuesta ≥ el de abajo" de "acá se midió algo": un estimador que
    /// no se llama, o que devuelve cero, satisface la primera y falla ésta.
    #[test]
    fn a_ladder_of_zeros_is_refused() {
        let ceros: Vec<(Mode, u64)> = LADDER.iter().map(|m| (*m, 0)).collect();
        let Err(e) = monotonia(&ceros) else {
            panic!("una escalera de ceros no puede pasar por medición");
        };
        assert_eq!(e.len(), 1, "una sola violación: la de las puntas — {e:?}");
        assert!(e.join(" ").contains("Nop"), "{e:?}");
    }

    /// Una escalera que baja se rechaza, y se nombra el peldaño.
    #[test]
    fn a_rung_cheaper_than_the_one_below_is_named() {
        let rungs = vec![(Mode::Full, 10), (Mode::NoRoot, 20), (Mode::Nop, 1)];
        let Err(e) = monotonia(&rungs) else {
            panic!("un peldaño más barato que el de abajo no puede pasar");
        };
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e.join(" ").contains("NoRoot"), "{e:?}");
    }

    /// Y una escalera que sube pasa: sin esto, las dos de arriba podrían pasar
    /// por un chequeo que rechaza todo.
    #[test]
    fn a_ladder_that_climbs_is_accepted() {
        let rungs = vec![(Mode::Full, 30), (Mode::NoRoot, 20), (Mode::Nop, 10)];
        assert!(monotonia(&rungs).is_ok());
    }
}
