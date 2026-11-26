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
use repo_b_guest::GuestError;
use repo_b_guest::journal::Mode;

use super::driver::{FailKind, Failure, RunBlock};
use super::fixture::{BlockHeader, BlockchainTest, TestBlock};

/// Qué hizo el guest con un bloque que el driver rechazó durante la ejecución.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuestVerdict {
    /// Lo rechazó por la clase de regla equivalente a la del driver.
    Attributed,
    /// Lo rechazó porque el witness parcial no le alcanzó. NO es un acierto de
    /// la regla y **falla el caso**: el witness sale de todo lo que el driver
    /// leyó hasta el rechazo, así que tiene que alcanzarle. Aceptarlo como
    /// neutro dejaría pasar un guest (o un input) que no juzga nada.
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

    /// Qué hizo mal el guest, si algo: todo veredicto que no sea atribuido
    /// falla el caso.
    #[must_use]
    pub fn failure(self) -> Option<&'static str> {
        match self {
            Self::Attributed => None,
            Self::Unattributed => Some("no lo pudo juzgar: el witness no le alcanzó"),
            Self::OtherClass => Some("lo rechazó por otra regla"),
            Self::Accepted => Some("lo ACEPTÓ"),
        }
    }
}

/// Cómo empieza el texto de un `VmError` que es el estado que no pudo contestar.
/// El guest conserva el error del motor como texto (`GuestError::Vm`), así que
/// la taxonomía de `evm::error` se lee de su `Display`.
const VM_STATE_ACCESS_PREFIX: &str = "internal error: state access";

/// Qué error tiene que devolver el guest para que su rechazo sea la MISMA
/// regla que la del driver. Lo arma el driver en el punto del rechazo, con el
/// error que tiene en la mano: no se deduce después de la clase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestRule {
    /// Exactamente este error: el guest corre el mismo crate de bloque y la
    /// misma política de system calls sobre el mismo bloque, así que el error
    /// es comparable campo por campo.
    Exact(GuestError),
    /// Un rechazo de la ruta de firma de la tx `index`. El texto del motivo es
    /// del decoder del guest, que el driver no corre (arma la tx desde el JSON
    /// del fixture): se exige la clase y el índice.
    SignatureOf(usize),
    /// El RLP crudo del bloque no decodifica.
    Undecodable,
}

impl GuestRule {
    #[must_use]
    pub fn matches(&self, error: &GuestError) -> bool {
        use repo_b_block::BlockError as B;
        match self {
            Self::Exact(expected) => error == expected,
            Self::SignatureOf(index) => matches!(
                error,
                GuestError::Signature(msg) if msg.starts_with(&format!("tx {index}: "))
            ),
            Self::Undecodable => matches!(
                error,
                GuestError::Block(B::BlockRlp(_) | B::HeaderRlp(_) | B::HeaderTrailingBytes { .. })
            ),
        }
    }
}

/// ¿El guest no pudo juzgar el bloque porque el witness no le alcanzó? Es un
/// error de witness o una lectura de estado que el motor no pudo hacer.
fn is_witness_shortfall(error: &GuestError) -> bool {
    match error {
        GuestError::Witness(_) => true,
        GuestError::Vm { message, .. } => message.starts_with(VM_STATE_ACCESS_PREFIX),
        _ => false,
    }
}

/// El veredicto del guest contra la regla que el driver aplicó.
///
/// Un witness insuficiente se separa antes de mirar la regla: no es la regla
/// que falla, es el guest que no llegó a evaluarla. Sin regla (un rechazo que
/// el driver no supo describir) nada es atribuible: fail-closed.
pub fn classify_guest_rejection<T>(
    rule: Option<&GuestRule>,
    guest: &Result<T, GuestError>,
) -> GuestVerdict {
    let Err(error) = guest else {
        return GuestVerdict::Accepted;
    };
    if is_witness_shortfall(error) {
        return GuestVerdict::Unattributed;
    }
    match rule {
        Some(rule) if rule.matches(error) => GuestVerdict::Attributed,
        _ => GuestVerdict::OtherClass,
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
/// rechaza el bloque por la misma regla que el driver. Aceptarlo, rechazarlo
/// por otra regla o no poder juzgarlo (witness insuficiente) falla el caso.
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
    let verdict = classify_guest_rejection(failure.guest_rule.as_deref(), &guest);
    if let Ok(mut verdicts) = GUEST_EXEC_VERDICTS.lock() {
        let entry = verdicts
            .entry((failure.kind.as_str(), verdict))
            .or_default();
        *entry = entry.saturating_add(1);
    }
    verdict.failure().map(|what| {
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
/// también, por la misma regla.** El witness es solo el padre: la validación
/// del guest corre antes de tocar el estado, así que el rechazo tiene que
/// llegar antes de que falte un nodo. Se exige el error que el driver produjo
/// ([`GuestRule`]): el mismo `BlockError`, o un error de decodificación si el
/// driver no pudo decodificar el header. Un input que no se puede armar falla
/// el caso: no juzgar no es pasar.
pub(super) fn guest_rejects_header(
    spec: Spec,
    test: &BlockchainTest,
    block: &TestBlock,
    head: &BlockHeader,
    failure: &Failure,
) -> Option<Failure> {
    let shape = failure.detail.as_str();
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
    let guest = repo_b_guest::codec::decode_block_input(&bytes)
        .map_err(|_| GuestError::Input("el input no decodifica"))
        .and_then(|decoded| repo_b_guest::run_block_input(Mode::Full, &decoded));
    let verdict = classify_guest_rejection(failure.guest_rule.as_deref(), &guest);
    let Some(what) = verdict.failure() else {
        GUEST_HEADER_REJECTED.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    Some(Failure::new(
        FailKind::Witness,
        shape,
        format!(
            "el hijo del bloque {}: el driver lo rechaza por `{}` ({}) y el guest {what}: {guest:?}",
            head.fields.number,
            failure.kind.as_str(),
            failure.message
        ),
    ))
}

/// Bloques que el driver rechaza por su header o su cuerpo y el guest rechazó
/// por la misma regla.
pub static GUEST_HEADER_REJECTED: AtomicU64 = AtomicU64::new(0);

/// El baseline del eje: cuántos rechazos juzgó el guest, por clase y
/// veredicto, y cuántos por su header o su cuerpo. Pineado EXACTO en los dos
/// sentidos: que bajen los atribuidos es una regresión, y que suban (o
/// aparezca una clase) es un cambio que se firma en un commit explícito. Sin
/// esto, "el guest vio todo lo que el eje registró" pasaría con 0 de 0.
fn baseline_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("witness-blocks-baseline.json")
}

/// La clave de un veredicto en el baseline: `<clase> ⇒ <veredicto>`.
fn verdict_key(kind: &str, verdict: GuestVerdict) -> String {
    format!("{kind} ⇒ {}", verdict.as_str())
}

/// Contrasta lo medido contra el baseline pineado. Sin baseline legible es un
/// error: el trinquete no se inventa.
///
/// # Errors
/// El baseline falta o no parsea, o algún conteo difiere.
pub fn check_ratchet(
    verdicts: &BTreeMap<(&'static str, GuestVerdict), u64>,
    header_rejected: u64,
) -> Result<(), String> {
    let path = baseline_path();
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("no pude leer el baseline {}: {e}", path.display()))?;
    let baseline: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("el baseline {} no parsea: {e}", path.display()))?;
    let pinned: BTreeMap<String, u64> = baseline
        .get("guest_mid_execution")
        .and_then(serde_json::Value::as_object)
        .ok_or("el baseline no trae `guest_mid_execution`")?
        .iter()
        .map(|(key, value)| {
            value
                .as_u64()
                .map(|count| (key.clone(), count))
                .ok_or_else(|| format!("`{key}` no es un conteo"))
        })
        .collect::<Result<_, String>>()?;
    let pinned_header = baseline
        .get("guest_header_rejected")
        .and_then(serde_json::Value::as_u64)
        .ok_or("el baseline no trae `guest_header_rejected`")?;
    let measured: BTreeMap<String, u64> = verdicts
        .iter()
        .map(|((kind, verdict), count)| (verdict_key(kind, *verdict), *count))
        .collect();
    ratchet_diff(&pinned, &measured, pinned_header, header_rejected)
}

/// Las diferencias entre lo pineado y lo medido, en los dos sentidos.
fn ratchet_diff(
    pinned: &BTreeMap<String, u64>,
    measured: &BTreeMap<String, u64>,
    pinned_header: u64,
    header_rejected: u64,
) -> Result<(), String> {
    let mut diffs = Vec::new();
    for key in pinned
        .keys()
        .chain(measured.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let (want, got) = (
            pinned.get(key).copied().unwrap_or(0),
            measured.get(key).copied().unwrap_or(0),
        );
        if want != got {
            diffs.push(format!("`{key}`: baseline {want}, medido {got}"));
        }
    }
    if pinned_header != header_rejected {
        diffs.push(format!(
            "rechazos por header o cuerpo: baseline {pinned_header}, medido {header_rejected}"
        ));
    }
    if diffs.is_empty() {
        return Ok(());
    }
    Err(format!(
        "el juicio del guest se movió contra su baseline ({}): {}. Si es un cambio \
         deliberado, se firma moviendo el baseline en un commit explícito.",
        baseline_path().display(),
        diffs.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use repo_b_evm::error::{ConsensusError, InternalError, VmError};

    use super::*;

    /// Solo un veredicto atribuido pasa: no poder juzgar el bloque por falta de
    /// witness falla igual que aceptarlo.
    #[test]
    fn only_an_attributed_verdict_passes_the_case() {
        assert_eq!(GuestVerdict::Attributed.failure(), None);
        for verdict in [
            GuestVerdict::Unattributed,
            GuestVerdict::OtherClass,
            GuestVerdict::Accepted,
        ] {
            assert!(verdict.failure().is_some(), "{verdict:?}");
        }
    }

    fn verdict(rule: &GuestRule, guest: GuestError) -> GuestVerdict {
        classify_guest_rejection(Some(rule), &Err::<(), _>(guest))
    }

    /// Un rechazo por witness insuficiente NUNCA es un acierto de la regla, y
    /// un `Ok` es un bloque inválido aceptado, sea cual sea la regla.
    #[test]
    fn a_witness_shortfall_is_never_attributed_and_ok_is_accepted() {
        let state_access = VmError::Internal(InternalError::StateAccess(
            repo_b_evm::error::StateError::Database("falta un nodo".to_owned()),
        ));
        for rule in [
            GuestRule::Exact(GuestError::Vm {
                message: "consensus error: nonce invalid: expected 1, got 0".to_owned(),
                tx: Some(0),
            }),
            GuestRule::Undecodable,
            GuestRule::SignatureOf(0),
            GuestRule::Exact(GuestError::Witness("falta un nodo".to_owned())),
        ] {
            assert_eq!(
                verdict(&rule, GuestError::Witness("falta un nodo".to_owned())),
                GuestVerdict::Unattributed,
                "{rule:?}"
            );
            assert_eq!(
                verdict(&rule, GuestError::vm(&state_access, Some(0))),
                GuestVerdict::Unattributed,
                "{rule:?}"
            );
            assert_eq!(
                classify_guest_rejection(Some(&rule), &Ok::<(), GuestError>(())),
                GuestVerdict::Accepted,
                "{rule:?}"
            );
        }
    }

    /// Sin regla no hay atribución posible: un rechazo que el driver no supo
    /// describir no lo puede confirmar el guest.
    #[test]
    fn without_a_rule_nothing_is_attributed() {
        let any = Err::<(), _>(GuestError::Signature("tx 0: r = 0".to_owned()));
        assert_eq!(
            classify_guest_rejection(None, &any),
            GuestVerdict::OtherClass
        );
    }

    /// Los errores de bloque y de system call se comparan por VARIANTE CONCRETA,
    /// no por la familia del `GuestError`: un rechazo de header no confirma
    /// uno de requests, y "sin código" no confirma "falló".
    #[test]
    fn block_and_system_call_errors_are_compared_by_their_concrete_variant() {
        use repo_b_block::BlockError as B;
        use repo_b_common::primitives::{Address, B256};
        let requests = B::RequestsHash {
            declared: B256::ZERO,
            computed: B256::repeat_byte(1),
        };
        let rule = GuestRule::Exact(GuestError::Block(requests.clone()));
        assert_eq!(
            verdict(&rule, GuestError::Block(requests)),
            GuestVerdict::Attributed
        );
        for other in [
            B::NonZeroDifficulty,
            B::DepositLayout { reason: "x" },
            B::WithdrawalsRoot {
                declared: B256::ZERO,
                computed: B256::ZERO,
            },
            B::RequestsHash {
                declared: B256::ZERO,
                computed: B256::repeat_byte(2),
            },
        ] {
            assert_eq!(
                verdict(&rule, GuestError::Block(other.clone())),
                GuestVerdict::OtherClass,
                "{other:?}"
            );
        }

        let address = Address::repeat_byte(0x70);
        let empty = GuestRule::Exact(GuestError::SystemContractEmpty(address));
        let failed = repo_b_evm::result::ExecutionResult::Revert {
            gas_used: 1,
            gas_refunded: 0,
            output: Bytes::new(),
        };
        let failed = GuestError::SystemCall {
            address,
            result: failed,
        };
        assert_eq!(
            verdict(&empty, GuestError::SystemContractEmpty(address)),
            GuestVerdict::Attributed
        );
        assert_eq!(verdict(&empty, failed.clone()), GuestVerdict::OtherClass);
        assert_eq!(
            verdict(&empty, GuestError::SystemContractEmpty(Address::ZERO)),
            GuestVerdict::OtherClass
        );
        assert_eq!(
            verdict(
                &GuestRule::Exact(failed.clone()),
                GuestError::SystemContractEmpty(address)
            ),
            GuestVerdict::OtherClass
        );
        assert_eq!(
            verdict(&GuestRule::Exact(failed.clone()), failed),
            GuestVerdict::Attributed
        );
    }

    /// La firma se exige con su índice; el decode del header, como error de
    /// decodificación y no como otra regla de bloque.
    #[test]
    fn signature_and_undecodable_rules_name_their_index_and_their_class() {
        use repo_b_block::BlockError as B;
        let sig = GuestRule::SignatureOf(2);
        assert_eq!(
            verdict(&sig, GuestError::Signature("tx 2: s alto".to_owned())),
            GuestVerdict::Attributed
        );
        for other in [
            GuestError::Signature("tx 1: s alto".to_owned()),
            GuestError::Signature("tx 21: s alto".to_owned()),
            GuestError::Block(B::NonZeroNonce),
        ] {
            assert_eq!(
                verdict(&sig, other.clone()),
                GuestVerdict::OtherClass,
                "{other:?}"
            );
        }
        let undecodable = GuestRule::Undecodable;
        assert_eq!(
            verdict(
                &undecodable,
                GuestError::Block(B::HeaderTrailingBytes { trailing: 1 })
            ),
            GuestVerdict::Attributed
        );
        assert_eq!(
            verdict(&undecodable, GuestError::Block(B::NonZeroDifficulty)),
            GuestVerdict::OtherClass
        );
    }

    /// Un rechazo del motor solo lo confirma EL MISMO error de consenso: otra
    /// variante, otros valores o un error interno que no es de estado son otra
    /// regla. Los textos salen del `Display` real del motor, no de un literal.
    #[test]
    fn an_engine_rejection_is_confirmed_only_by_the_same_consensus_error() {
        let nonce = |expected, actual| {
            GuestError::vm(
                &VmError::Consensus(ConsensusError::NonceInvalid { expected, actual }),
                Some(3),
            )
        };
        let rule = GuestRule::Exact(nonce(1, 0));
        assert_eq!(verdict(&rule, nonce(1, 0)), GuestVerdict::Attributed);
        let balance = VmError::Consensus(ConsensusError::InsufficientBalance {
            required: "1".to_owned(),
            available: "0".to_owned(),
        });
        let engine_bug = VmError::Internal(InternalError::EvmInternal("bug".to_owned()));
        for other in [
            nonce(2, 0),
            GuestError::vm(&balance, Some(3)),
            GuestError::vm(&engine_bug, Some(3)),
        ] {
            assert_eq!(
                verdict(&rule, other.clone()),
                GuestVerdict::OtherClass,
                "{other:?}"
            );
        }
    }

    /// El mismo error de consenso en OTRA tx no es el mismo rechazo: el driver
    /// rechazó la tx 3 y un guest que rechaza la tx 1 (o fuera de una tx) por
    /// el mismo texto no aplicó la regla en el mismo lugar.
    #[test]
    fn an_engine_rejection_in_another_tx_is_not_attributed() {
        let nonce = VmError::Consensus(ConsensusError::NonceInvalid {
            expected: 1,
            actual: 0,
        });
        let rule = GuestRule::Exact(GuestError::vm(&nonce, Some(3)));
        assert_eq!(
            verdict(&rule, GuestError::vm(&nonce, Some(3))),
            GuestVerdict::Attributed
        );
        for tx in [Some(1), Some(4), None] {
            assert_eq!(
                verdict(&rule, GuestError::vm(&nonce, tx)),
                GuestVerdict::OtherClass,
                "{tx:?}"
            );
        }
    }

    /// El trinquete exige igualdad en los dos sentidos: un atribuido de menos
    /// rompe, uno de más también, y 0 contra 0 en una clase pineada no pasa.
    #[test]
    fn the_ratchet_pins_every_count_both_ways() {
        let pinned = BTreeMap::from([("requests ⇒ atribuido".to_owned(), 2)]);
        let same = pinned.clone();
        assert!(ratchet_diff(&pinned, &same, 5, 5).is_ok());
        let fewer = BTreeMap::from([("requests ⇒ atribuido".to_owned(), 1)]);
        assert!(ratchet_diff(&pinned, &fewer, 5, 5).is_err());
        let more = BTreeMap::from([("requests ⇒ atribuido".to_owned(), 3)]);
        assert!(ratchet_diff(&pinned, &more, 5, 5).is_err());
        assert!(ratchet_diff(&pinned, &BTreeMap::new(), 5, 5).is_err());
        let new_class = BTreeMap::from([
            ("requests ⇒ atribuido".to_owned(), 2),
            ("requests ⇒ no atribuido (witness)".to_owned(), 1),
        ]);
        assert!(ratchet_diff(&pinned, &new_class, 5, 5).is_err());
        assert!(ratchet_diff(&pinned, &same, 5, 4).is_err());
    }

    /// El baseline commiteado parsea y no pinea un solo veredicto que no sea
    /// atribuido.
    #[test]
    fn the_committed_baseline_only_pins_attributed_verdicts() {
        let Ok(raw) = std::fs::read_to_string(baseline_path()) else {
            panic!("el baseline no se puede leer");
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            panic!("el baseline no parsea");
        };
        let Some(pinned) = value
            .get("guest_mid_execution")
            .and_then(serde_json::Value::as_object)
        else {
            panic!("el baseline no trae guest_mid_execution");
        };
        assert!(!pinned.is_empty());
        for (key, count) in pinned {
            assert!(key.ends_with("⇒ atribuido"), "{key}");
            assert!(count.as_u64().is_some_and(|n| n > 0), "{key}");
        }
    }
}
