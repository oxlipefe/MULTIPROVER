//! **Dónde** se originó una divergencia: la mitad de la clave de cluster que
//! dice *por qué*, no *qué*.
//!
//! La firma vieja (`triage::signature`) dice qué campos difieren. Eso alcanza
//! para contar y no alcanza para deduplicar: dos bugs sin relación que muevan
//! el gas caen en el mismo balde, y **el mismo** bug produce conjuntos
//! distintos según cuánto arrastre cada caso. Medido: una sola causa
//! (EIP-7610) generó 12 conjuntos distintos en la campaña de 033.
//!
//! ## El sitio es el ÚLTIMO paso COMÚN, no el primero divergente
//!
//! `trace_diff::first_divergence` reporta el paso donde las trazas **ya** se
//! separaron, o sea el siguiente al culpable — y en la mitad de los casos ese
//! paso solo existe del lado del oráculo. Medido sobre los 13 hallazgos de
//! 033: el primer paso divergente nombraba `PUSH1`, `STOP`, `ADDRESS` y
//! `UNKNOWN` para una **única** causa. El opcode después de cuya ejecución las
//! trazas se separan sí la nombra.
//!
//! ## Cuando nuestro lado no ejecutó un solo opcode
//!
//! No hay último paso común, y ahí el sitio lo da **nuestro propio veredicto**
//! (halt, revert, rechazo de la tx). Comparar esa taxonomía contra la de revm
//! es un punto ciego declarado del oráculo y sigue siéndolo: acá no se compara
//! nada, se lee **un solo lado** para nombrar el lugar. Un nombre no es un
//! veredicto.
//!
//! ## Costo
//!
//! Trazar cuesta dos ejecuciones extra, y se paga **por divergencia**, no por
//! caso: en una campaña sana es ruido y en una campaña con un bug plantado es
//! el precio de saber qué se plantó. Las trazas van acotadas
//! (`MAX_TRACE_STEPS`) porque el corpus de EEST trae casos de 1 650 028 pasos
//! y una traza sin tope es memoria alimentada por el generador.

use repo_b_evm::OwnVm;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::Spec;
use repo_b_evm::vm::Vm;

use crate::diff::trace_source;
use crate::fixture::{PostCase, StateTest, spec_for_fork};
use crate::runner::MemoryState;
use crate::trace_diff::{Culprit, culprit as first_divergence_culprit};

/// Tope de pasos que se guardan de cada traza. Acotado y nombrado como todo
/// recurso alimentado por input externo: la traza más larga del corpus semilla
/// mide 1 650 028 pasos, y guardar dos de ésas por divergencia es memoria que
/// el generador controla. Un sitio que no se resolvió dentro del tope se
/// **nombra** (`traza-truncada`), no se inventa.
pub const MAX_TRACE_STEPS: usize = 100_000;

/// El sitio, ya renderizado. `String` y no un enum: se usa como clave, se
/// imprime y se persiste, y no hay lógica que despache sobre él.
///
/// `Err` no existe a propósito: un sitio que no se pudo computar es un sitio
/// **nombrado** (`sin-traza`), porque un hallazgo sin cluster se caería del
/// reporte y eso es exactamente lo que el triage tiene que impedir.
pub fn site_of(test: &StateTest, case: &PostCase, differences: &[String]) -> String {
    // Una divergencia de VEREDICTO no tiene sitio en la traza: uno de los dos
    // motores no debería estar ejecutando. Se resuelve del veredicto, y de paso
    // sale gratis — no traza nada.
    if let Some(site) = crate::fuzz::triage::verdict_site(differences) {
        return site;
    }
    let Some(spec) = spec_for_fork(&case.fork) else {
        // Un caso fuera de scope no diverge: nunca se corrió.
        return "fork-fuera-de-scope".to_owned();
    };
    let ours = match trace_source::ours_capped(test, case, spec, MAX_TRACE_STEPS) {
        Ok(steps) => steps,
        // Nuestro lado ni siquiera pudo trazar: el sitio es nuestro veredicto.
        Err(_) => return our_verdict_label(test, case, spec),
    };
    let Ok(oracle) = trace_source::revm_capped(test, case, spec, MAX_TRACE_STEPS) else {
        return "oráculo-sin-traza".to_owned();
    };

    match first_divergence_culprit(&ours, &oracle) {
        Culprit::Identical => {
            if ours.len() >= MAX_TRACE_STEPS {
                return "traza-truncada".to_owned();
            }
            // Las trazas coinciden paso a paso: la divergencia está fuera de lo
            // que EIP-3155 registra — liquidación de la tx (gas intrínseco,
            // refund, fees) o los logs emitidos.
            "fuera-de-traza".to_owned()
        }
        // Nuestro lado no ejecutó un solo opcode: el sitio es nuestro veredicto.
        Culprit::OursEmpty => format!("sin-pasos:{}", our_verdict_label(test, case, spec)),
        Culprit::OracleEmpty => "oráculo-sin-pasos".to_owned(),
        // Los dos ejecutan y ya difieren en el PRIMER opcode: la divergencia es
        // anterior a la ejecución (gas intrínseco, el estado de arranque, la
        // resolución del código a correr).
        Culprit::AtStart => "arranque".to_owned(),
        Culprit::Step(step) => match ours.get(step) {
            Some(step) => format!("op:{}", step.op_name),
            None => "sin-paso-culpable".to_owned(),
        },
    }
}

/// Cómo terminó **nuestro** motor, en una palabra y sin valores.
///
/// Se lee de un solo lado a propósito (ver el doc del módulo). El `Debug` del
/// `HaltReason` es el nombre del variante y nada más: un enum cerrado, sin
/// campos, así que no puede colar un valor en la clave — que es lo que M4
/// prohíbe.
fn our_verdict_label(test: &StateTest, case: &PostCase, spec: Spec) -> String {
    let Ok(tx) = test.transaction_for(case) else {
        return "caso-no-construible".to_owned();
    };
    let env = test.block_env(spec);
    let state = MemoryState::from_pre(&test.pre).with_block_hashes(test.env.block_hashes.clone());
    match OwnVm::new().execute_tx(&tx, &env, &state) {
        Ok(outcome) => match outcome.result {
            ExecutionResult::Success { .. } => "Success".to_owned(),
            ExecutionResult::Revert { .. } => "Revert".to_owned(),
            ExecutionResult::Halt { reason, .. } => format!("{reason:?}"),
        },
        Err(repo_b_evm::VmError::Consensus(_)) => "tx-rechazada".to_owned(),
        Err(repo_b_evm::VmError::Internal(_)) => "error-interno".to_owned(),
    }
}
