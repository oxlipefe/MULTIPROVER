//! `repo-b-prover` — el seam `Prover`: el backend de proving, intercambiable.
//!
//! # Qué se ADOPTA y qué se envuelve, con la razón
//!
//! El plan original era **diseñar** este seam. Medirlo lo corrigió a
//! **adoptar**: `ere` (eth-act, la misma org que mantiene el
//! estándar de target de zkVM y que usa el proyecto zkEVM de la EF) ya define
//! exactamente el contrato que había que escribir —`zkVMProver` con
//! `execute`/`prove`/`verify`, `Compiler` con `compile`— y trae **tres**
//! implementadores. Calcar la firma nos dejaría con el trait y sin los
//! implementadores, que es el trabajo entero.
//!
//! **Lo que se reexporta** (sin envolver): `zkVMProver`, `Compiler`, `Input`,
//! `PublicValues`, `ProgramExecutionReport`, `ProverResource`. Envolverlos
//! crearía un seam sobre un seam: una capa nuestra que no agrega ninguna regla
//! y que habría que mantener alineada con la de arriba cada vez que `ere` mueva
//! una firma.
//!
//! **Lo que es NUESTRO** y no está en `ere`:
//!
//! 1. **El techo del output y el formato de lo que el guest publica**
//!    (`journal`). `ere` no opina sobre qué afirma una prueba; nosotros sí, y
//!    la restricción de 256 bytes de OpenVM/ZisK obliga a decidirlo una sola
//!    vez para los tres backends.
//! 2. **El protocolo de medición por diferencia** (`cycles`). `ere` expone
//!    `region_cycles`, pero su adapter de SP1 **no lo puebla nunca** —construye
//!    el reporte con `..Default::default()` sobre un ejecutor mínimo que no
//!    corre el cycle tracker—, así que el desglose por operación hay que
//!    producirlo. Restar `total_num_cycles` entre corridas ablacionadas es la
//!    única vía **portable a los tres backends**: parsear el stdout de SP1
//!    mediría SP1 y habría que rehacerlo con cada backend nuevo.
//!
//! # El input viaja por BYTES
//!
//! La primera versión de este trait tomaba `&ExecutionWitness`. Eso no sobrevive
//! al contacto con un zkVM: lo único que entra a un guest es un buffer. El
//! tipado se recupera del otro lado, con el decoder del guest, que es input
//! externo y se valida como tal.
//!
//! # Cuarentena
//!
//! Ningún crate del motor (`interpreter`, `evm`, `witness`, `common`) depende
//! de éste, y éste no depende del SDK de ningún backend: los backends entran
//! por `ere`, y el que los instancia es el driver (`cmd/zkvm`). El guest
//! concreto de cada backend vive fuera del workspace, así que el SDK de SP1 no
//! está ni en el grafo de dependencias del motor.

pub mod cycles;

/// El contrato de lo que el guest publica y el techo que tiene. Vive en el
/// crate del guest porque las dos puntas lo necesitan y aquélla es `no_std`.
pub use repo_b_guest::journal;
pub use repo_b_guest::journal::{JOURNAL_BYTES, Journal, MAX_PUBLIC_OUTPUT_BYTES, Mode};

pub use ere_compiler_core::{Compiler, Elf};
pub use ere_prover_core::{
    CommonError, Input, ProgramExecutionReport, ProgramProvingReport, ProverResource, PublicValues,
    zkVMProver,
};

/// **El adaptador mínimo, y por qué hace falta uno.**
///
/// Adoptar `ere` no salió gratis del todo: su tipo `DockerizedzkVM` —el que
/// levanta el backend adentro de una imagen— **no implementa `zkVMProver`, el
/// trait del propio `ere`**. Tiene `execute`/`prove` como métodos inherentes,
/// porque es dinámico sobre el backend y el trait tiene tipos asociados. O sea
/// que un seam escrito directo contra `zkVMProver` no puede recibir el único
/// backend que se puede correr sin instalar un SDK.
///
/// Este trait es esa junta y **nada más**: un método. No envuelve `prove` ni
/// `verify` —eso sería el seam sobre el seam que el doc de arriba rechaza—,
/// solo el modo que hoy se ejerce.
pub trait Execute {
    /// # Errors
    /// El texto del error del backend, sin interpretar.
    fn execute_raw(&self, input: &Input) -> Result<(PublicValues, ProgramExecutionReport), String>;
}

/// El adaptador para cualquier implementador de `zkVMProver` de `ere`.
///
/// No es un blanket impl a propósito: un blanket dejaría sin lugar al
/// adaptador del `DockerizedzkVM`, que es un tipo ajeno y no puede recibir un
/// trait ajeno del lado de abajo.
pub struct ViaProver<Z>(pub Z);

impl<Z: zkVMProver> Execute for ViaProver<Z> {
    fn execute_raw(&self, input: &Input) -> Result<(PublicValues, ProgramExecutionReport), String> {
        self.0.execute(input).map_err(|e| format!("{e}"))
    }
}

/// Arma el buffer que entra al guest: **el byte de modo y después el bloque**.
///
/// El modo va afuera del formato del bloque a propósito — el codec describe un
/// bloque de Ethereum, y qué hace el guest con él no es parte de ese bloque.
/// Mezclarlos obligaría a tocar un formato de consenso para poder medir.
#[must_use]
pub fn zkvm_input(mode: Mode, block: &[u8]) -> Input {
    let mut stdin = Vec::with_capacity(block.len() + 1);
    stdin.push(mode.as_byte());
    stdin.extend_from_slice(block);
    Input::new().with_stdin(stdin)
}

/// Por qué una corrida no produjo un journal utilizable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// El backend devolvió error: el guest no pudo ejecutar. **Esto es lo que
    /// pasa cuando el input no alcanza**, y es el modo de falla correcto: un
    /// guest que no puede ejecutar no publica un journal en ceros.
    Backend(String),
    /// El backend ejecutó pero lo que publicó no es un journal.
    OutputNoEsJournal(usize),
    /// Publicó un journal de otro modo que el pedido.
    ModoEquivocado { pedido: Mode, publicado: Mode },
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "el backend no pudo ejecutar el guest: {e}"),
            Self::OutputNoEsJournal(n) => {
                write!(f, "el guest publicó {n} bytes que no son un journal")
            }
            Self::ModoEquivocado { pedido, publicado } => write!(
                f,
                "se pidió el modo {pedido:?} y el guest publicó {publicado:?}"
            ),
        }
    }
}

impl core::error::Error for RunError {}

/// Una corrida del guest: el journal que publicó y cuánto costó.
#[derive(Debug, Clone)]
pub struct Run {
    pub journal: Journal,
    pub cycles: u64,
    pub duration: core::time::Duration,
}

/// Ejecuta el guest sobre un bloque, en el modo pedido.
///
/// **El modo publicado se contrasta contra el pedido.** Sin eso, el modo
/// adentro del journal sería decoración: lo que lo vuelve una garantía es que
/// alguien lo mire.
///
/// # Errors
/// Ver `RunError`.
pub fn execute_block<E: Execute + ?Sized>(
    zkvm: &E,
    mode: Mode,
    block: &[u8],
) -> Result<Run, RunError> {
    let (public_values, report) = zkvm
        .execute_raw(&zkvm_input(mode, block))
        .map_err(RunError::Backend)?;
    let bytes = public_values.as_ref();
    let journal = Journal::decode(bytes).ok_or(RunError::OutputNoEsJournal(bytes.len()))?;
    if journal.mode != mode {
        return Err(RunError::ModoEquivocado {
            pedido: mode,
            publicado: journal.mode,
        });
    }
    Ok(Run {
        journal,
        cycles: report.total_num_cycles,
        duration: report.execution_duration,
    })
}

#[cfg(test)]
mod tests {
    use super::{Journal, Mode, zkvm_input};

    /// El byte de modo va **primero** y el bloque intacto atrás: si se
    /// invirtieran, el guest leería el primer byte del RLP como modo.
    #[test]
    fn the_mode_byte_leads_the_buffer() {
        let input = zkvm_input(Mode::StateOnly, &[0xc0, 0x42]);
        assert_eq!(input.stdin(), &[3, 0xc0, 0x42]);
    }

    /// El journal del seam y el del guest son EL MISMO tipo: el techo se decide
    /// una sola vez.
    #[test]
    fn the_seam_and_the_guest_share_one_journal() {
        let j = Journal::empty(Mode::Nop);
        assert_eq!(Journal::decode(&j.encode()), Some(j));
    }
}
