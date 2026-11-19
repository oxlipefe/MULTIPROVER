//! El guest como segundo juez de los bloques que el driver rechaza.
//!
//! El driver rechaza un bloque por su header o su cuerpo (antes de ejecutar) o
//! a mitad de la ejecución (antes de `finish_block`). En los dos casos el guest
//! recibe el mismo bloque por bytes y tiene que rechazarlo por la misma regla:
//! aceptarlo es un bloque inválido probado como válido, y rechazarlo por otra
//! regla es que los dos no aplicaron la misma.

use std::collections::BTreeMap;

use core::sync::atomic::{AtomicU64, Ordering};
use repo_b_common::primitives::Bytes;
use repo_b_evm::types::Spec;
use repo_b_guest::journal::Mode;

use super::driver::{FailKind, Failure, RunBlock};
use super::fixture::{BlockHeader, BlockchainTest, TestBlock};

/// Qué hizo el guest con un bloque que el driver rechazó durante la ejecución.
/// Qué hizo el guest con un bloque que el driver rechazó durante la ejecución.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuestVerdict {
    /// Lo rechazó por la clase de regla equivalente a la del driver.
    Attributed,
    /// Lo rechazó porque el witness parcial no le alcanzó: NO es un acierto de
    /// la regla, y se cuenta aparte.
    Unattributed,
    /// Lo rechazó por otra clase de regla: falla el caso, igual que aceptarlo,
    /// porque la regla que el driver aplicó no es la que el guest aplicó.
    OtherClass,
    /// Lo ACEPTÓ. Es un bloque inválido probado como válido.
    Accepted,
}

impl GuestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attributed => "atribuido",
            Self::Unattributed => "no atribuido (witness)",
            Self::OtherClass => "otra clase",
            Self::Accepted => "ACEPTADO",
        }
    }
}

/// Cómo empieza el texto de un `VmError` que es el protocolo juzgando la tx, y
/// el de uno que es el estado que no pudo contestar. El guest conserva el
/// error del motor como texto (`GuestError::Vm`), así que la taxonomía de
/// `evm::error` se lee de su `Display`.
const VM_CONSENSUS_PREFIX: &str = "consensus error";
const VM_STATE_ACCESS_PREFIX: &str = "internal error: state access";

/// La equivalencia entre la clase de rechazo del driver y el error del guest.
///
/// Un `Vm` del guest solo es la regla si es un error de consenso; si es el
/// estado que no contestó, es el witness parcial que no alcanzó (no atribuido);
/// cualquier otro error interno es otra clase.
pub fn classify_guest_rejection<T>(
    kind: FailKind,
    guest: &Result<T, repo_b_guest::GuestError>,
) -> GuestVerdict {
    use repo_b_guest::GuestError as G;
    let Err(error) = guest else {
        return GuestVerdict::Accepted;
    };
    let attributed = match (kind, error) {
        (_, G::Witness(_)) => return GuestVerdict::Unattributed,
        (_, G::Vm(msg)) if msg.starts_with(VM_STATE_ACCESS_PREFIX) => {
            return GuestVerdict::Unattributed;
        }
        (FailKind::ExecuteError, G::Vm(msg)) => msg.starts_with(VM_CONSENSUS_PREFIX),
        (FailKind::Signature, G::Signature(_))
        | (FailKind::Envelope, G::Signature(_) | G::Block(_))
        | (FailKind::SystemCall | FailKind::SystemContractEmpty, G::SystemCall(_))
        | (FailKind::Requests | FailKind::DepositLayout, G::Block(_)) => true,
        _ => false,
    };
    if attributed {
        GuestVerdict::Attributed
    } else {
        GuestVerdict::OtherClass
    }
}

/// ¿Una clase de rechazo sale del lifecycle (antes de `finish_block`) y no de
/// las reglas de header o cuerpo? Son las que juzga
/// [`guest_rejects_execution`]; el reporte de `--witness-blocks` exige que el
/// guest haya visto exactamente esa cantidad de bloques.
pub fn is_mid_execution(kind: FailKind) -> bool {
    matches!(
        kind,
        FailKind::ExecuteError
            | FailKind::Signature
            | FailKind::Envelope
            | FailKind::SystemCall
            | FailKind::SystemContractEmpty
            | FailKind::Requests
            | FailKind::DepositLayout
    )
}

/// Veredictos del guest sobre los rechazos a mitad de ejecución, por clase del
/// driver.
pub static GUEST_EXEC_VERDICTS: std::sync::Mutex<BTreeMap<(&'static str, GuestVerdict), u64>> =
    std::sync::Mutex::new(BTreeMap::new());

/// **Un bloque que el driver rechaza durante la ejecución, el guest también.**
///
/// El witness sale del log del grabador hasta el punto de falla: es todo lo
/// que la ejecución del driver leyó, y el guest corre el mismo lifecycle, así
/// que debería alcanzarle para llegar a la misma regla. Contrato duro: el guest
/// NO acepta el bloque y, si lo rechaza por una regla, es la de la misma clase
/// que el driver. Un rechazo por witness insuficiente no se exige ni se cuenta
/// como acierto: va aparte, con su número.
pub(super) fn guest_rejects_execution(
    args: &RunBlock<'_>,
    log: &repo_b_witness::AccessLog,
    failure: &Failure,
) -> Option<Failure> {
    let number = args.header.fields.number;
    let witness = crate::witness_build::build_block(
        args.pre,
        log,
        args.chain,
        number,
        &crate::witness_build::ShapeChanges::default(),
    );
    let input = guest_input_of(args, &witness);
    let bytes = repo_b_guest::codec::encode_block_input(&input);
    let guest = repo_b_guest::codec::decode_block_input(&bytes)
        .map_err(|_| repo_b_guest::GuestError::Input("el input no decodifica"))
        .and_then(|decoded| repo_b_guest::run_block_input(Mode::Full, &decoded));
    let verdict = classify_guest_rejection(failure.kind, &guest);
    if let Ok(mut verdicts) = GUEST_EXEC_VERDICTS.lock() {
        let entry = verdicts
            .entry((failure.kind.as_str(), verdict))
            .or_default();
        *entry = entry.saturating_add(1);
    }
    let hard = match verdict {
        GuestVerdict::Attributed | GuestVerdict::Unattributed => None,
        GuestVerdict::OtherClass => Some("lo rechazó por otra clase de regla"),
        GuestVerdict::Accepted => Some("lo ACEPTÓ"),
    };
    hard.map(|what| {
        Failure::new(
            FailKind::Witness,
            args.shape,
            format!(
                "bloque {number}: el driver lo rechaza por `{}` ({}) y el guest {what}: {guest:?}",
                failure.kind.as_str(),
                failure.message
            ),
        )
    })
}

/// El input del guest para este bloque: el bloque **tal como viaja** (el `rlp`
/// del fixture, que es lo que un cliente recibe y lo que mide EIP-7934), el
/// fork, el `chain_id` y el witness sin `keys`. Nada más: el `env`, el
/// `pre_state_root` y las system calls los deriva el guest.
pub(super) fn guest_input_of(
    args: &RunBlock<'_>,
    witness: &repo_b_common::witness::ExecutionWitness,
) -> repo_b_guest::codec::BlockInput {
    repo_b_guest::codec::BlockInput {
        fork: args.spec,
        chain_id: args.test.chain_id,
        block: args.block.rlp.clone(),
        witness: repo_b_common::witness::ExecutionWitness {
            keys: Vec::new(),
            ..witness.clone()
        },
    }
}

/// **Un bloque que el driver rechaza por su header o su cuerpo, el guest
/// también.** El witness es solo el padre: la validación del guest corre antes
/// de tocar el estado, así que un rechazo tiene que llegar antes de que falte
/// un nodo — y por eso se exige que sea un rechazo de validación
/// (`GuestError::Block`), no cualquier error.
pub(super) fn guest_rejects_header(
    spec: Spec,
    test: &BlockchainTest,
    block: &TestBlock,
    head: &BlockHeader,
    shape: &'static str,
) -> Option<Failure> {
    let input = repo_b_guest::codec::BlockInput {
        fork: spec,
        chain_id: test.chain_id,
        block: block.rlp.clone(),
        witness: repo_b_common::witness::ExecutionWitness {
            headers: vec![Bytes::from(head.fields.rlp())],
            ..Default::default()
        },
    };
    let bytes = repo_b_guest::codec::encode_block_input(&input);
    let decoded = repo_b_guest::codec::decode_block_input(&bytes).ok()?;
    match repo_b_guest::run_block_input(Mode::Full, &decoded) {
        Err(repo_b_guest::GuestError::Block(_)) => {
            GUEST_HEADER_REJECTED.fetch_add(1, Ordering::Relaxed);
            None
        }
        otro => Some(Failure::new(
            FailKind::Witness,
            shape,
            format!(
                "el hijo del bloque {}: el driver lo rechaza por su header o su cuerpo y el guest dio {otro:?}",
                head.fields.number
            ),
        )),
    }
}

/// Bloques que el driver rechaza por su header o su cuerpo y el guest rechazó
/// con un error de validación.
pub static GUEST_HEADER_REJECTED: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use repo_b_evm::error::{ConsensusError, InternalError, VmError};

    use super::*;

    /// La atribución del veredicto del guest sobre un rechazo a mitad de
    /// ejecución: un rechazo por witness insuficiente NUNCA es un acierto de la
    /// regla, y un `Ok` es un bloque inválido aceptado.
    #[test]
    fn a_guest_rejection_for_witness_is_never_attributed() {
        use repo_b_guest::GuestError as G;
        let witness: Result<(), G> = Err(G::Witness("falta un nodo".to_owned()));
        for kind in [
            FailKind::ExecuteError,
            FailKind::Signature,
            FailKind::SystemCall,
            FailKind::SystemContractEmpty,
            FailKind::Requests,
        ] {
            assert_eq!(
                classify_guest_rejection(kind, &witness),
                GuestVerdict::Unattributed,
                "{kind:?}"
            );
            assert_eq!(
                classify_guest_rejection(kind, &Ok::<(), G>(())),
                GuestVerdict::Accepted,
                "{kind:?}"
            );
        }
        // Los textos salen del `Display` real del motor, no de un literal.
        let consensus = VmError::Consensus(ConsensusError::NonceInvalid {
            expected: 1,
            actual: 0,
        });
        let state_access = VmError::Internal(InternalError::StateAccess(
            repo_b_evm::error::StateError::Database("falta un nodo".to_owned()),
        ));
        let engine_bug = VmError::Internal(InternalError::EvmInternal("bug".to_owned()));
        let vm: Result<(), G> = Err(G::Vm(format!("{consensus}")));
        let missing: Result<(), G> = Err(G::Vm(format!("{state_access}")));
        let bug: Result<(), G> = Err(G::Vm(format!("{engine_bug}")));
        assert_eq!(
            classify_guest_rejection(FailKind::ExecuteError, &missing),
            GuestVerdict::Unattributed
        );
        assert_eq!(
            classify_guest_rejection(FailKind::ExecuteError, &bug),
            GuestVerdict::OtherClass
        );
        let system_call: Result<(), G> = Err(G::SystemCall("revierte".to_owned()));
        assert_eq!(
            classify_guest_rejection(FailKind::ExecuteError, &vm),
            GuestVerdict::Attributed
        );
        assert_eq!(
            classify_guest_rejection(FailKind::SystemContractEmpty, &system_call),
            GuestVerdict::Attributed
        );
        assert_eq!(
            classify_guest_rejection(FailKind::SystemCall, &vm),
            GuestVerdict::OtherClass
        );
    }
}
