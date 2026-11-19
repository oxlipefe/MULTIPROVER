//! El driver de bloque: genesis → por cada bloque, `begin_block`, las txs,
//! `finish_block` → contraste contra el header.
//!
//! El estado se encadena entre bloques: el post-state de uno es el pre-state
//! del siguiente. Dentro de un bloque lo encadena el motor (`BlockState`); entre
//! bloques lo encadena el driver, que es quien tiene el MPT.

use std::collections::BTreeMap;

use core::sync::atomic::{AtomicU64, Ordering};
use repo_b_common::primitives::{Address, B256, Bytes};
use repo_b_common::receipt::Receipt;
use repo_b_common::transaction::Transaction;
use repo_b_evm::OwnVm;

use repo_b_evm::error::VmError;
use repo_b_evm::state::State;
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;

use super::fixture::{BlockHeader, BlockchainTest, FixtureTx, TestBlock};
use super::guest_verdict::{
    GuestRule, guest_input_of, guest_rejects_execution, guest_rejects_header,
};
use super::network;
use crate::fixture::FixtureAccount;
use crate::runner::{MemoryState, apply_updates, compute_state_root, diff_expected};
use repo_b_block::{BlockError, HeaderField, PostExecution, requests as block_requests, roots};
use repo_b_guest::journal::{Journal, Mode};

/// Categoría de falla — la clave de clustering del eje `blockchain_test`.
/// Enum propio y no el de `runner`: los ejes tienen causas raíz distintas y
/// mezclarlas haría ilegible el mapa de los dos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailKind {
    /// El fixture no se pudo interpretar. **No es un skip**: si no lo
    /// entendimos, no pasó.
    Parse,
    /// **La dirección peligrosa**: el fixture declara el bloque INVÁLIDO y el
    /// cliente lo aceptó. Categoría propia porque excusar el rechazo sin la
    /// recíproca es un comparador tuerto.
    AcceptedInvalidBlock,
    /// El bloque se rechazó, pero por un `internal error` del motor. **Nunca
    /// cuenta como rechazo válido**: es el motor roto, no el protocolo
    /// hablando.
    InternalError,
    /// La tabla de blobs del motor no coincide con el `config.blobSchedule`
    /// que el fixture declara para un fork del caso.
    BlobSchedule,
    /// El pre-state del fixture no produce el `stateRoot` del genesis: o el
    /// parseo o el MPT del harness están mal, y todo lo de abajo sería ruido.
    GenesisRoot,
    /// El motor rechazó una tx de un bloque que el fixture declara VÁLIDO.
    ExecuteError,
    /// El diff no se pudo aplicar al pre-state.
    PostStateApply,
    /// **Una tx del bloque no tiene un remitente válido**: su firma no
    /// recupera (EIP-2, rango de `r`/`s`, `v`/`yParity`) o fue firmada para
    /// otro `chainId`. Es un rechazo de protocolo: el bloque que la lleva es
    /// inválido.
    ///
    /// Categoría propia y no `ExecuteError`: es una regla que se aplica antes
    /// de que el motor vea la tx, y bajo la clave del motor un rechazo por la
    /// firma no se distinguiría de uno por nonce o balance.
    Signature,
    /// **La tx no es representable como el envelope que lee el guest** (un
    /// precio de gas de más de 128 bits, un `chainId` de más de 64): el guest
    /// no la puede decodificar, así que el bloque que la lleva se rechaza.
    /// Categoría propia y no `Signature`: no dice nada de la firma.
    Envelope,
    /// **El bloque se rechazó por la ruta de firma, pero el `expectException`
    /// no nombra esa razón.** Sin esta clase, un rechazo por la firma
    /// satisfaría cualquier excepción esperada.
    WrongRejectionReason,
    /// **El sender que la firma produce no es el que el fixture declara.**
    ///
    /// Categoría propia y no `Witness`, por la misma razón que separó
    /// `DepositLayout` de `Requests`: la regla es nueva (4.1c) y bajo la clave
    /// vieja quedaría tapada — un bug de la recuperación se leería como un
    /// bloque que no se reproduce desde su witness, que es otra cosa.
    Sender,
    /// El bloque no se pudo reproducir ejecutándolo **solo desde el witness**.
    /// Categoría propia: sin ella, una falla del witness se leería como una del
    /// motor o del protocolo, que es justo lo que no es.
    Witness,
    /// El juez: el root MPT del post-state del bloque no coincide.
    StateRoot,
    GasUsed,
    TransactionsTrie,
    ReceiptTrie,
    Bloom,
    WithdrawalsRoot,
    /// EIP-1559: el `gasLimit` declarado no es admisible dado el del padre.
    GasLimit,
    /// EIP-1559: el `baseFeePerGas` declarado no es el que la fórmula exige.
    BaseFee,
    /// EIP-7934: el RLP crudo del bloque excede 8 MiB en Osaka+.
    BlockRlpSize,
    /// EIP-4844: `excessBlobGas` / `blobGasUsed` del header no cierran.
    BlobGas,
    /// La system call de un contrato de sistema no terminó en éxito, o el
    /// header no trae el dato que necesita como calldata.
    SystemCall,
    /// EIP-7002/7251: el predeploy de una system call *checked* no tiene código
    /// en el estado del bloque. Categoría propia y no `SystemCall`: las dos
    /// reglas rechazan el mismo bloque de cierre y, bajo la misma clave, el
    /// desglose por clase no podría delatar un rechazo por la razón equivocada.
    SystemContractEmpty,
    /// EIP-7685: el `requestsHash` del header no es el de los requests que el
    /// bloque produjo.
    Requests,
    /// EIP-6110: un log del contrato de depósito con un layout que no es el
    /// canónico.
    ///
    /// **Categoría propia y no `Requests`, y eso lo decidió una mutación:**
    /// borrar la validación de layout sale en CERO contra el corpus, porque un
    /// layout roto produce bytes distintos y el `requestsHash` lo caza igual.
    /// Con las dos reglas bajo la misma clave, el desglose por clase tampoco
    /// podía delatar el rechazo producido por la razón equivocada — que es
    /// justo lo único para lo que ese desglose existe.
    DepositLayout,
    /// El bloque se publica SOLO como `rlp` crudo, sin cuerpo decodificado:
    /// EEST omite el `rlp_decoded` justamente cuando el bloque no decodifica.
    UndecodableBlock,
    /// El header no hashea al `hash` que declara: `keccak(rlp(header))` no da el
    /// valor publicado.
    ///
    /// **Categoría propia y no `StateRoot` ni `LastBlockHash`**, por la misma
    /// razón que separó `Requests` de `DepositLayout`: sin granularidad propia la
    /// regla nueva queda tapada por la vieja, y el desglose por clase —lo único
    /// que delata un rechazo producido por la razón equivocada— no la ve. Es
    /// exactamente lo que pasaba con los 9 `INVALID_BLOCK_HASH` del set, que se
    /// rechazaban por su `withdrawalsRoot`.
    BlockHash,
    /// El RLP crudo del bloque no trae el header que el fixture publica
    /// decodificado: `decode(rlp)` no da los campos del JSON, o re-encodearlos
    /// no da los mismos bytes. Aserción del harness, como `BlockHash`: es el
    /// juez del decoder del crate de bloque y no se excusa nunca.
    HeaderRlp,
    /// Un campo del header que el fork exige y falta, o uno que el fork todavía
    /// no tiene.
    ForkFields,
    /// `gasUsed > gasLimit`.
    GasUsedAboveLimit,
    /// `timestamp` no posterior al del padre.
    Timestamp,
    /// `number` distinto de `padre + 1`.
    BlockNumber,
    /// `extraData` de más de 32 bytes.
    ExtraData,
    /// Post-Merge: `difficulty` distinta de cero.
    Difficulty,
    /// Post-Merge: el `nonce` de PoW distinto de cero.
    PowNonce,
    /// Post-Merge: `ommersHash` distinto del de la lista vacía.
    OmmersHash,
    /// Post-Merge: el cuerpo trae ommers.
    Ommers,
    /// `parentHash` distinto de `keccak(rlp(padre))`.
    ParentHash,
    /// El head de la cadena no quedó donde el fixture dice (`lastblockhash`).
    LastBlockHash,
    /// Se rechazó el bloque y aun así el estado avanzó.
    ChainAdvanced,
}

impl FailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::AcceptedInvalidBlock => "accepted_invalid_block",
            Self::InternalError => "internal_error",
            Self::BlobSchedule => "blob_schedule",
            Self::GenesisRoot => "genesis_root",
            Self::ExecuteError => "execute_error",
            Self::PostStateApply => "post_state_apply",
            Self::StateRoot => "state_root",
            Self::GasUsed => "gas_used",
            Self::TransactionsTrie => "transactions_trie",
            Self::ReceiptTrie => "receipt_trie",
            Self::Bloom => "bloom",
            Self::WithdrawalsRoot => "withdrawals_root",
            Self::GasLimit => "gas_limit_bounds",
            Self::BaseFee => "base_fee",
            Self::BlockRlpSize => "block_rlp_size",
            Self::BlobGas => "blob_gas",
            Self::SystemCall => "system_call",
            Self::SystemContractEmpty => "system_contract_empty",
            Self::Requests => "requests",
            Self::DepositLayout => "deposit_layout",
            Self::UndecodableBlock => "undecodable_block",
            Self::BlockHash => "block_hash",
            Self::HeaderRlp => "header_rlp",
            Self::ForkFields => "fork_fields",
            Self::GasUsedAboveLimit => "gas_used_above_limit",
            Self::Timestamp => "timestamp",
            Self::BlockNumber => "block_number",
            Self::ExtraData => "extra_data",
            Self::Difficulty => "difficulty",
            Self::PowNonce => "pow_nonce",
            Self::OmmersHash => "ommers_hash",
            Self::Ommers => "ommers",
            Self::ParentHash => "parent_hash",
            Self::Sender => "sender",
            Self::Signature => "signature",
            Self::Envelope => "envelope",
            Self::WrongRejectionReason => "wrong_rejection_reason",
            Self::Witness => "witness",
            Self::LastBlockHash => "last_block_hash",
            Self::ChainAdvanced => "chain_advanced",
        }
    }
}

/// Una falla. `detail` es la sub-clave del cluster (acotada, sin datos únicos
/// por caso); `message`, el diagnóstico largo de UN caso.
#[derive(Debug, Clone)]
pub struct Failure {
    pub kind: FailKind,
    pub detail: String,
    pub message: String,
    /// En un rechazo de protocolo que el guest también juzga: qué error tiene
    /// que devolver el guest para que sea la MISMA regla. `None` en todo lo
    /// demás; un rechazo que el guest juzga sin regla falla el caso.
    pub guest_rule: Option<Box<GuestRule>>,
}

impl Failure {
    pub(super) fn new(
        kind: FailKind,
        detail: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            detail: detail.into(),
            message: message.into(),
            guest_rule: None,
        }
    }

    /// El error con el que el guest tiene que rechazar el mismo bloque.
    #[must_use]
    pub(super) fn judged_by(self, rule: GuestRule) -> Self {
        Self {
            guest_rule: Some(Box::new(rule)),
            ..self
        }
    }

    pub fn signature(&self) -> (FailKind, &str) {
        (self.kind, self.detail.as_str())
    }
}

/// Un bloque que el fixture declaraba inválido y el driver rechazó, con la
/// razón POR LA QUE lo rechazó.
///
/// El gate es que se rechace, no que la razón calce con el string de EEST
/// (atar el nombre del generador a un error interno es acoplamiento, no
/// consenso). Pero el desglose se registra igual: si el día de mañana un
/// rechazo se produce por la razón equivocada, esto es lo único que lo delata.
#[derive(Debug, Clone)]
pub struct RejectedBlock {
    pub expectation: String,
    pub reason: FailKind,
}

/// Por qué un bloque no entró a la cadena. La distinción ES la regla: un
/// `internal error` es el motor roto y **nunca** cuenta como rechazo válido.
#[derive(Debug)]
enum Rejection {
    Protocol(Failure),
    Internal(Failure),
}

impl Rejection {
    /// Un error del seam `Vm`, clasificado por su propia taxonomía
    /// (`ConsensusError` = juicio determinista sobre la tx; `InternalError` =
    /// bug del motor). No se re-inventa acá: ya está fijada en `evm::error`.
    ///
    /// `tx` es la posición en el bloque de la tx rechazada, o `None` si el
    /// error no salió de una tx: el guest tiene que rechazar en el mismo lugar.
    fn from_vm(err: &VmError, tx: Option<usize>, context: &str) -> Self {
        let rendered = format!("{err}");
        let detail = error_head(&rendered);
        match err {
            VmError::Consensus(_) => Self::Protocol(
                Failure::new(
                    FailKind::ExecuteError,
                    detail,
                    format!("{context}: {rendered}"),
                )
                // Harness y guest corren el mismo `OwnVm` sobre el mismo bloque:
                // el guest tiene que rechazar con EL MISMO error de consenso
                // (variante y valores), no con cualquiera.
                .judged_by(GuestRule::Exact(repo_b_guest::GuestError::vm(err, tx))),
            ),
            VmError::Internal(_) => Self::Internal(Failure::new(
                FailKind::InternalError,
                detail,
                format!("{context}: {rendered}"),
            )),
        }
    }
}

#[derive(Debug)]
pub enum CaseOutcome {
    /// Pasó. Lleva los bloques que se rechazaron por el camino, para el
    /// desglose del reporte.
    Pass(Vec<RejectedBlock>),
    Fail(Failure),
}

/// La forma del bloque, como sub-clave de cluster: distingue "el motor está mal"
/// de "esto es multi-tx / multi-bloque y va a 2.9c-5". Acotada a propósito.
fn shape(test: &BlockchainTest, block: &TestBlock) -> &'static str {
    if test.blocks.len() > 1 {
        return "multi-bloque";
    }
    if block.transactions.len() > 1 {
        return "multi-tx";
    }
    "1 bloque, ≤1 tx"
}

/// Corre un `blockchain_test` completo. Bit-idéntico o `Fail`.
/// Con `witness = true` cada bloque se ejecuta **dos veces**: la normal, y otra
/// alimentada solo por el witness de lo que la primera tocó. Si las dos no
/// producen el mismo bloque, el caso falla con categoría propia.
pub fn run_case_with(test: &BlockchainTest, witness: bool) -> CaseOutcome {
    // El scope lo filtra el llamador por el campo `network`. Que una red llegue
    // hasta acá sin resolver sería un desacuerdo entre el filtro y el runner: se
    // dice en voz alta, no se saltea en silencio. El fork de cada bloque sale de
    // su timestamp (las redes de transición cambian de fork dentro del caso).
    let Some(forks) = network::resolve(&test.network) else {
        return CaseOutcome::Fail(Failure::new(
            FailKind::Parse,
            "fork sin Spec",
            format!("el fork `{}` llegó al driver sin resolver", test.network),
        ));
    };

    if let Some(failure) = check_blob_schedule(&test.blob_schedule, &forks) {
        return CaseOutcome::Fail(failure);
    }

    let mut post = test.pre.clone();
    // El `pre` de un `blockchain_test` ES el estado del genesis. Contrastarlo
    // contra el `stateRoot` que el genesis declara es gratis y no es
    // tautológico: si el parseo o el MPT del harness estuvieran mal, todo lo
    // que viene abajo mediría otra cosa.
    let genesis_root = compute_state_root(&post);
    if genesis_root != test.genesis.fields.state_root {
        return CaseOutcome::Fail(Failure::new(
            FailKind::GenesisRoot,
            "",
            format!(
                "el pre-state no produce el stateRoot del genesis: esperado {}, obtenido {genesis_root}",
                test.genesis.fields.state_root
            ),
        ));
    }

    // El hash del genesis se COMPUTA como el de cualquier otro header, y por la
    // misma razón por la que su `stateRoot` se contrasta: si el header del
    // genesis no hashea a lo que declara, el `BLOCKHASH` de todo bloque de abajo
    // y el `lastblockhash` de las cadenas que no avanzan medirían otra cosa. Un
    // genesis NO se "rechaza" —no hay bloque que sacar de la cadena—, así que
    // esto es una falla del caso y no un `Rejection`.
    let genesis_hash = test.genesis.fields.hash();
    if genesis_hash != test.genesis.hash {
        return CaseOutcome::Fail(Failure::new(
            FailKind::BlockHash,
            "genesis",
            format!(
                "el header del genesis declara {} y `keccak(rlp(header))` da {genesis_hash}",
                test.genesis.hash
            ),
        ));
    }

    // `BLOCKHASH` se alimenta de los hashes COMPUTADOS, nunca de los publicados:
    // tomar el del fixture volvería tautológico todo lo que dependa de ellos.
    let mut block_hashes = BTreeMap::from([(test.genesis.fields.number, genesis_hash)]);
    // Los headers crudos de la cadena, para el witness: `BLOCKHASH` no se puede
    // probar con un hash suelto, hace falta la secuencia contigua hacia atrás
    // para encadenar `parent_hash`.
    let mut chain: BTreeMap<u64, Bytes> = BTreeMap::from([(
        test.genesis.fields.number,
        Bytes::from(test.genesis.fields.rlp()),
    )]);
    // El head de la cadena: arranca en el genesis y solo lo mueve un bloque
    // ACEPTADO. Es también el padre del bloque siguiente — un bloque rechazado
    // no puede ser padre de nada.
    let mut head = &test.genesis;
    // El hash computado del head. Va al lado de `head` y no adentro de
    // `BlockHeader` porque el header es lo que el fixture DECLARA y esto es lo
    // que el harness DERIVA: juntarlos invitaría a leer el publicado sin darse
    // cuenta.
    let mut head_hash = genesis_hash;
    let mut rejected = Vec::new();

    for (index, block) in test.blocks.iter().enumerate() {
        let shape = shape(test, block);
        // El header se valida ANTES de ejecutar: un bloque cuyo `gasLimit` o
        // `baseFeePerGas` no cierran es inválido por lo que declara, sin que
        // haga falta correr una sola tx.
        let attempt = match &block.header {
            None => {
                UNDECODABLE_WITHOUT_HEADER.fetch_add(1, Ordering::Relaxed);
                Err(undecodable_block(block, shape))
            }
            // Antes de la aserción de identidad, que sobre un header no
            // representable no tiene qué afirmar.
            Some(header) if tail_has_gap(&header.fields) => {
                match gapped_header(header, head, test, &forks, block, shape, witness) {
                    Ok(rejection) => Err(rejection),
                    Err(failure) => return CaseOutcome::Fail(failure),
                }
            }
            Some(header) => {
                // La identidad del bloque se afirma para TODO bloque —válido o
                // declarado inválido— y antes que cualquier otra regla: un
                // header cuyo contenido no hashea al valor que declara no es el
                // bloque que dice ser, y ningún otro campo suyo significa nada.
                // Que sea una falla del caso y no un `Rejection` excusable es
                // deliberado; el porqué está en `check_block_hash`.
                let hash = header.fields.hash();
                if let Some(failure) = check_block_hash(header, hash) {
                    return CaseOutcome::Fail(failure);
                }
                // El decoder del crate de bloque contra el header que el
                // fixture publica decodificado: la misma clase de aserción que
                // el hash, y tampoco se excusa en un bloque inválido.
                if let Some(failure) = check_header_rlp(header, &block.rlp) {
                    return CaseOutcome::Fail(failure);
                }
                let Some(spec) = forks.spec_at(header.fields.timestamp) else {
                    return CaseOutcome::Fail(Failure::new(
                        FailKind::Parse,
                        "fork sin Spec",
                        format!(
                            "la red `{}` no resuelve un fork en el timestamp {}",
                            test.network, header.fields.timestamp
                        ),
                    ));
                };
                let validated = validate_header(spec, header, head, block, shape);
                // Con el witness prendido, el guest también tiene que rechazar
                // lo que el driver rechaza antes de ejecutar.
                if witness
                    && let Err(Rejection::Protocol(rejected)) = &validated
                    && let Some(failure) = guest_rejects_header(spec, test, block, head, rejected)
                {
                    return CaseOutcome::Fail(failure);
                }
                validated
                    .and_then(|()| {
                        run_block(&RunBlock {
                            spec,
                            test,
                            block,
                            header,
                            parent_hash: head_hash,
                            pre: &post,
                            block_hashes: &block_hashes,
                            chain: &chain,
                            from_witness: None,
                            witness,
                            shape,
                        })
                    })
                    .map(|executed| (header, hash, executed))
            }
        };

        match attempt {
            Ok((header, hash, executed)) => {
                // La dirección peligrosa: aceptar lo que el protocolo rechaza.
                // Se contrasta ANTES de mirar el post-state, porque un
                // bloque inválido igual puede producir el root que su propio
                // header declara.
                if let Some(exception) = &block.expect_exception {
                    return CaseOutcome::Fail(Failure::new(
                        FailKind::AcceptedInvalidBlock,
                        shape,
                        format!(
                            "el fixture declara el bloque inválido (`{exception}`) y el driver \
                             lo ACEPTÓ"
                        ),
                    ));
                }
                // El `postState` inline solo enriquece el diagnóstico del
                // ÚLTIMO bloque: es el estado final de la cadena, no el de cada
                // bloque intermedio.
                let is_last = index + 1 == test.blocks.len();
                let expected_state = is_last.then_some(test.post_state.as_ref()).flatten();
                if let Some(failure) = contrast(header, block, &executed, shape, expected_state) {
                    return CaseOutcome::Fail(failure);
                }
                block_hashes.insert(header.fields.number, hash);
                chain.insert(header.fields.number, Bytes::from(header.fields.rlp()));
                post = executed.post;
                head = header;
                head_hash = hash;
            }
            // El motor roto no es el protocolo hablando: no excusa nada, ni
            // siquiera en un bloque que el fixture declara inválido.
            Err(Rejection::Internal(failure)) => return CaseOutcome::Fail(failure),
            Err(Rejection::Protocol(failure)) => {
                let Some(exception) = &block.expect_exception else {
                    return CaseOutcome::Fail(failure);
                };
                // Ciertas clases de rechazo solo cuentan si la excepción
                // esperada nombra esa razón: si no, un bloque inválido por otra
                // cosa pasaría por accidente.
                let explica = rejection_explained(failure.kind, exception);
                if explica == Some(false) {
                    return CaseOutcome::Fail(Failure::new(
                        FailKind::WrongRejectionReason,
                        shape,
                        format!(
                            "el bloque se rechazó por `{}` ({}) y el fixture espera \
                             `{exception}`, que no nombra esa razón",
                            failure.kind.as_str(),
                            failure.message
                        ),
                    ));
                }
                // La cadena no avanzó: ni el head (no se toca `head`) ni el
                // estado. Lo segundo se afirma, no se supone.
                let root = compute_state_root(&post);
                if root != head.fields.state_root {
                    return CaseOutcome::Fail(Failure::new(
                        FailKind::ChainAdvanced,
                        shape,
                        format!(
                            "un bloque se rechazó sobre el head {} y el estado avanzó igual: \
                             esperado {}, obtenido {root}",
                            head.fields.number, head.fields.state_root
                        ),
                    ));
                }
                rejected.push(RejectedBlock {
                    expectation: exception.clone(),
                    reason: failure.kind,
                });
            }
        }
    }

    // La recíproca de las dos direcciones anteriores, y la única que mide el
    // head: el fixture publica dónde tiene que terminar la cadena.
    //
    // Se contrasta contra el hash **computado** del head. Con el publicado el
    // chequeo sería vacuo para toda cadena válida —los dos valores saldrían del
    // mismo fixture y serían iguales por construcción— y solo haría trabajo real
    // sobre los bloques rechazados, que es menos de lo que su nombre promete.
    if head_hash != test.last_block_hash {
        return CaseOutcome::Fail(Failure::new(
            FailKind::LastBlockHash,
            "",
            format!(
                "el head quedó en {head_hash} y el fixture declara {}",
                test.last_block_hash
            ),
        ));
    }

    CaseOutcome::Pass(rejected)
}

/// Un bloque que el fixture publica SOLO como `rlp` crudo.
///
/// EEST omite el `rlp_decoded` exactamente cuando el bloque **no decodifica**
/// (el caso medido: una tx tipo 3 con `to = None`, que no es RLP-representable,
/// ver §4.3). Un bloque que no decodifica es inválido, y por eso esto es un
/// rechazo de protocolo y no un "no lo entendimos". La recíproca se conserva:
/// sin `expectException` sigue siendo una falla de parseo, porque **un bloque
/// válido siempre trae su `blockHeader`**.
fn undecodable_block(block: &TestBlock, shape: &'static str) -> Rejection {
    let failure = Failure::new(
        FailKind::UndecodableBlock,
        shape,
        "el bloque se publica solo como `rlp` crudo, sin `blockHeader` ni \
         `rlp_decoded.blockHeader`: no decodifica"
            .to_owned(),
    );
    if block.expect_exception.is_some() {
        Rejection::Protocol(failure)
    } else {
        Rejection::Internal(Failure::new(
            FailKind::Parse,
            "bloque sin header",
            "el bloque no trae `blockHeader` ni `rlp_decoded.blockHeader` y el fixture NO lo \
             declara inválido"
                .to_owned(),
        ))
    }
}

/// ¿El tail opcional del header tiene un HUECO: un campo presente después de
/// uno ausente (p. ej. `excessBlobGas` sin `blobGasUsed`)?
///
/// El RLP del header es posicional, así que un header así no es representable:
/// sus bytes corren los campos de lugar, y lo que un cliente lee de ellos no
/// son los campos que el fixture publica decodificados.
fn tail_has_gap(fields: &repo_b_block::Header) -> bool {
    let present = [
        fields.base_fee_per_gas.is_some(),
        fields.withdrawals_root.is_some(),
        fields.blob_gas_used.is_some(),
        fields.excess_blob_gas.is_some(),
        fields.parent_beacon_block_root.is_some(),
        fields.requests_hash.is_some(),
    ];
    present.windows(2).any(|pair| matches!(pair, [false, true]))
}

/// Los nombres de `expectException` que explican un bloque cuyo header
/// publicado tiene un hueco en el tail. Medido sobre `tests@v20.0.2`: todos los
/// casos que pasan por ese camino declaran `INCORRECT_BLOCK_FORMAT`.
const GAPPED_HEADER_EXCEPTIONS: &[&str] = &["INCORRECT_BLOCK_FORMAT"];

/// Bloques cuyo header publicado tiene un hueco en el tail. Estadística del
/// eje, como los contadores del witness: dice cuántos casos juzga este camino.
pub static GAPPED_HEADERS: AtomicU64 = AtomicU64::new(0);

/// Bloques publicados SOLO como RLP crudo, sin header decodificado. El guest
/// no los ve: su input lleva el fork, y sin header no hay timestamp del que
/// derivarlo.
pub static UNDECODABLE_WITHOUT_HEADER: AtomicU64 = AtomicU64::new(0);

/// Un bloque cuyo header publicado tiene un hueco en el tail ([`tail_has_gap`]).
///
/// Los campos publicados no tienen encoding que reproducir, así que el bloque
/// se juzga como lo juzga un cliente: por el RLP crudo, que es lo único que
/// recibe.
///
/// - Si el decoder del crate de bloque lo rechaza, el bloque no decodifica y es
///   un rechazo de protocolo, con la misma recíproca que [`undecodable_block`].
/// - Si lo acepta, lee OTRO header (los campos corridos de lugar), y ése es el
///   bloque: su identidad se afirma contra el hash publicado y se le corren las
///   reglas de header contra el padre. Un header así que pasa todas las reglas
///   es un fixture que no entendemos, nunca un bloque aceptado: no tiene cuerpo
///   ejecutable que el fixture describa.
///
/// Dos exigencias más que las del camino normal, porque acá los campos corridos
/// hacen que cualquier regla de header pueda disparar (un `baseFeePerGas` que
/// en realidad es otro campo): el rechazo solo cuenta si la expectativa nombra
/// un error de formato ([`GAPPED_HEADER_EXCEPTIONS`]), y con el witness
/// prendido el guest, que lee el mismo RLP crudo, también tiene que rechazarlo.
fn gapped_header(
    header: &BlockHeader,
    parent: &BlockHeader,
    test: &BlockchainTest,
    forks: &network::NetworkForks,
    block: &TestBlock,
    shape: &'static str,
    witness: bool,
) -> Result<Rejection, Failure> {
    GAPPED_HEADERS.fetch_add(1, Ordering::Relaxed);
    let number = header.fields.number;
    let Some(exception) = &block.expect_exception else {
        return Ok(Rejection::Internal(Failure::new(
            FailKind::Parse,
            "header con hueco",
            format!(
                "bloque {number}: el header tiene un hueco en el tail y el fixture NO lo declara \
                 inválido"
            ),
        )));
    };
    let (spec_ts, rejection) = match decode_raw_header(&block.rlp) {
        Err(reason) => (
            header.fields.timestamp,
            Rejection::Protocol(
                Failure::new(
                    FailKind::UndecodableBlock,
                    shape,
                    format!(
                        "bloque {number}: header con un hueco en el tail, no decodifica: {reason}"
                    ),
                )
                .judged_by(GuestRule::Undecodable),
            ),
        ),
        Ok((decoded, encoded)) => {
            let computed = repo_b_common::primitives::keccak256(encoded);
            if computed != header.hash || encoded != decoded.rlp().as_slice() {
                return Err(Failure::new(
                    FailKind::BlockHash,
                    "",
                    format!(
                        "bloque {number}: el header con hueco declara el hash {} y sus bytes dan \
                         {computed} (o no son el encoding canónico de lo que decodifican)",
                        header.hash
                    ),
                ));
            }
            let timestamp = decoded.timestamp;
            let Some(spec) = forks.spec_at(timestamp) else {
                return Err(fork_without_spec(number, timestamp));
            };
            let as_read = BlockHeader {
                hash: header.hash,
                fields: decoded,
            };
            match validate_header(spec, &as_read, parent, block, shape) {
                Err(rejection) => (timestamp, rejection),
                Ok(()) => {
                    return Err(Failure::new(
                        FailKind::Parse,
                        "header con hueco",
                        format!(
                            "bloque {number}: el header publicado tiene un hueco en el tail y lo \
                             que el RLP crudo decodifica pasa las reglas de header"
                        ),
                    ));
                }
            }
        }
    };
    let Rejection::Protocol(failure) = rejection else {
        return Ok(rejection);
    };
    if !crate::runner::names_any(exception, GAPPED_HEADER_EXCEPTIONS) {
        return Err(Failure::new(
            FailKind::WrongRejectionReason,
            shape,
            format!(
                "bloque {number}: header con hueco rechazado por `{}` ({}) y el fixture espera \
                 `{exception}`, que no nombra un error de formato",
                failure.kind.as_str(),
                failure.message
            ),
        ));
    }
    if witness {
        let Some(spec) = forks.spec_at(spec_ts) else {
            return Err(fork_without_spec(number, spec_ts));
        };
        if let Some(guest) = guest_rejects_header(spec, test, block, parent, &failure) {
            return Err(guest);
        }
    }
    Ok(Rejection::Protocol(failure))
}

fn fork_without_spec(number: u64, timestamp: u64) -> Failure {
    Failure::new(
        FailKind::Parse,
        "fork sin Spec",
        format!("bloque {number}: el timestamp {timestamp} no resuelve un fork"),
    )
}

/// La identidad del bloque: el contenido del header tiene que hashear al valor
/// que el propio header declara.
///
/// **Es una aserción del harness, no un rechazo de protocolo, y eso lo decidió
/// la medición.** Un cliente real deriva el hash del RLP que recibe, así que
/// para él la discrepancia no existe: no hay regla de consenso que chequear. Acá
/// el driver consume el header ya decodificado *más* el hash que EEST derivó al
/// lado, y una discrepancia significa que uno de los dos encoders está mal — en
/// la práctica, el nuestro.
///
/// Modelarlo como `Rejection::Protocol` sería un comparador tuerto: en los
/// **3 024** bloques que el fixture declara inválidos el rechazo se excusa, así
/// que un bug del encoder que solo tocara a esos bloques pasaría invisible. Como
/// aserción no se excusa nunca, y eso es lo que hace que corromper un campo del
/// header tire los 42 017 casos y no solo los válidos.
///
/// **Y `BlockException.INVALID_BLOCK_HASH` de EEST no es lo que su nombre sugiere.**
/// Los 9 fixtures que lo declaran **no** tienen el hash inconsistente: EEST
/// corrompe el `withdrawalsRoot` y **recomputa** el hash sobre el header
/// corrompido (medido — los 9 pasan esta aserción). La etiqueta describe la
/// *consecuencia* —el bloque no hashea a lo que hashearía el bloque correcto— y no
/// una regla que un cliente pueda chequear por separado. Por eso siguen
/// rechazándose por su `withdrawalsRoot`, y no hay orden de reglas que lo cambie.
fn check_block_hash(header: &BlockHeader, computed: B256) -> Option<Failure> {
    if computed == header.hash {
        return None;
    }
    Some(Failure::new(
        FailKind::BlockHash,
        "",
        format!(
            "bloque {}: el header declara el hash {} y `keccak(rlp(header))` da {computed}",
            header.fields.number, header.hash
        ),
    ))
}

/// El header que el RLP crudo del bloque trae, contra el que el fixture publica
/// decodificado.
///
/// El bloque es `rlp([header, txs, ommers, …])`; el primer ítem se decodifica
/// con el decoder del crate de bloque —el que el guest usa para leer el header
/// que prueba— y tiene que dar **los mismos campos** que el JSON y, re-encodeado,
/// **los mismos bytes**. Lo segundo es lo que garantiza que el decoder acepta
/// solo el encoding canónico: dos RLP distintos del mismo header tendrían el
/// mismo contenido y distinto hash.
fn check_header_rlp(header: &BlockHeader, block_rlp: &[u8]) -> Option<Failure> {
    let number = header.fields.number;
    let fail = |message: String| Some(Failure::new(FailKind::HeaderRlp, "", message));
    let (decoded, encoded) = match decode_raw_header(block_rlp) {
        Ok(found) => found,
        Err(reason) => return fail(format!("bloque {number}: {reason}")),
    };
    if decoded != header.fields {
        return fail(format!(
            "bloque {number}: el header del RLP no es el que el fixture publica"
        ));
    }
    if encoded != decoded.rlp().as_slice() {
        return fail(format!(
            "bloque {number}: el header del RLP no es el encoding canónico de sus campos"
        ));
    }
    None
}

/// El primer ítem del RLP de un bloque, decodificado con el decoder del crate
/// de bloque, junto a los bytes de los que salió.
fn decode_raw_header(block_rlp: &[u8]) -> Result<(repo_b_block::Header, &[u8]), String> {
    let mut cursor = block_rlp;
    let outer = match alloy_rlp::Header::decode(&mut cursor) {
        Ok(outer) if outer.list => outer,
        Ok(_) => return Err("el RLP del bloque no es una lista".to_owned()),
        Err(e) => return Err(format!("el RLP del bloque no decodifica: {e}")),
    };
    let Some(payload) = cursor.get(..outer.payload_length) else {
        return Err("el RLP del bloque está truncado".to_owned());
    };
    let mut items = payload;
    let decoded = <repo_b_block::Header as alloy_rlp::Decodable>::decode(&mut items)
        .map_err(|e| format!("el header del RLP no decodifica: {e}"))?;
    let consumed = payload.len().saturating_sub(items.len());
    let encoded = payload
        .get(..consumed)
        .ok_or_else(|| "el header del RLP excede el bloque".to_owned())?;
    Ok((decoded, encoded))
}

/// Las reglas que hacen inválido a un bloque por lo que DECLARA, antes de
/// ejecutar nada. Corren sobre todo bloque, válido o no: excusar el rechazo sin
/// la recíproca sería un comparador tuerto.
///
/// Las reglas son las del crate de bloque; acá solo se arman sus entradas
/// desde el fixture y se clasifica el veredicto.
fn validate_header(
    spec: Spec,
    header: &BlockHeader,
    parent: &BlockHeader,
    block: &TestBlock,
    shape: &'static str,
) -> Result<(), Rejection> {
    let number = header.fields.number;
    let reject = |err: BlockError| header_rejection(&err, number, shape);

    repo_b_block::check_block_rlp_size(spec, block.rlp.len()).map_err(reject)?;
    repo_b_block::validate_header(&header.fields, &parent.fields, spec).map_err(reject)?;

    // Post-Merge el cuerpo no trae ommers.
    let ommers = block.ommers.ok_or_else(|| {
        Rejection::Internal(Failure::new(
            FailKind::Parse,
            "bloque sin uncleHeaders",
            format!("el bloque {number} trae header y no trae `uncleHeaders`"),
        ))
    })?;
    repo_b_block::check_ommers(ommers).map_err(reject)?;

    // EIP-4844, del lado del cuerpo: lo que el header declara contra lo que
    // las txs del bloque llevan. Solo Cancun+ — antes los campos no existen.
    if spec.is_enabled(Spec::Cancun) {
        let computed_used = block_blob_gas(block).ok_or_else(|| {
            Rejection::Internal(Failure::new(
                FailKind::Parse,
                "overflow contando blobs",
                format!("overflow sumando el blob gas de las txs del bloque {number}"),
            ))
        })?;
        repo_b_block::check_blob_gas_used(&header.fields, computed_used, spec).map_err(reject)?;
    }

    // EIP-4895. Es header y no ejecución: el `withdrawalsRoot` se contrasta
    // contra las withdrawals que el propio bloque trae.
    repo_b_block::check_withdrawals_root(
        &header.fields,
        block.withdrawals.as_deref().unwrap_or_default(),
    )
    .map_err(reject)?;

    Ok(())
}

/// ¿El `expectException` de un bloque explica un rechazo de clase `kind`?
/// `None`: la clase no exige que la excepción la nombre.
///
/// Un rechazo de la ruta de firma solo cuenta si la excepción nombra esa razón.
/// Lo mismo un predeploy de cierre sin código y una llamada de cierre que
/// falla: el mismo bloque de cierre se rechaza por cualquiera de las dos, y son
/// dos razones con dos nombres (`SYSTEM_CONTRACT_EMPTY`,
/// `SYSTEM_CONTRACT_CALL_FAILED`).
/// Un header sin un campo que su fork exige (o con uno que no tiene) no
/// decodifica en ese fork, y EEST lo nombra `INCORRECT_BLOCK_FORMAT`: es lo
/// único que excusa esa clase. Medido en la red `ShanghaiToCancunAtTime15k`,
/// donde un header de Shanghai con campos de blob se publica decodificado y
/// con ese nombre; cualquier otro nombre (uno de RLP, uno de firma) no la
/// explica.
fn rejection_explained(kind: FailKind, exception: &str) -> Option<bool> {
    match kind {
        FailKind::Signature => Some(crate::runner::names_any(
            exception,
            crate::runner::SIGNATURE_EXCEPTIONS,
        )),
        FailKind::Envelope => Some(crate::runner::names_any(
            exception,
            crate::runner::ENVELOPE_EXCEPTIONS,
        )),
        FailKind::SystemCall => Some(crate::runner::names_any(
            exception,
            &["SYSTEM_CONTRACT_CALL_FAILED"],
        )),
        FailKind::SystemContractEmpty => Some(crate::runner::names_any(
            exception,
            &["SYSTEM_CONTRACT_EMPTY"],
        )),
        FailKind::ForkFields => Some(crate::runner::names_any(
            exception,
            &["INCORRECT_BLOCK_FORMAT"],
        )),
        _ => None,
    }
}
/// Un veredicto del crate de bloque, clasificado en la taxonomía del eje.
///
/// La distinción `Protocol`/`Internal` ES la regla: lo que dice "este bloque es
/// inválido" es un rechazo; lo que dice "con este padre la regla no se puede
/// evaluar" (un padre sin un campo, una fórmula que no se puede derivar) es un
/// fixture que no entendimos, y eso nunca cuenta como rechazo válido.
fn header_rejection(err: &BlockError, number: u64, shape: &'static str) -> Rejection {
    let message = format!("bloque {number}: {err}");
    // El guest corre el mismo crate de bloque sobre el mismo header: tiene que
    // rechazarlo con EL MISMO error, no con cualquier error de validación.
    let protocol =
        |kind: FailKind| {
            Rejection::Protocol(Failure::new(kind, shape, message.clone()).judged_by(
                GuestRule::Exact(repo_b_guest::GuestError::Block(err.clone())),
            ))
        };
    let internal = |detail: &'static str| {
        Rejection::Internal(Failure::new(FailKind::Parse, detail, message.clone()))
    };
    match err {
        BlockError::BlockRlpTooLarge { .. } => protocol(FailKind::BlockRlpSize),
        // Un header sin un campo que su fork exige, o con uno que su fork no
        // tiene, no decodifica en ese fork: es inválido, no un header con el
        // campo en cero.
        BlockError::MissingField { .. } | BlockError::UnexpectedField { .. } => {
            protocol(FailKind::ForkFields)
        }
        BlockError::GasLimitBelowMinimum { .. } | BlockError::GasLimitOutOfBounds { .. } => {
            protocol(FailKind::GasLimit)
        }
        BlockError::BaseFee { .. } => protocol(FailKind::BaseFee),
        BlockError::ParentFieldMissing {
            field: HeaderField::BaseFeePerGas,
        } => internal("padre sin baseFeePerGas"),
        BlockError::BaseFeeUnderivable { .. } => internal("padre sin gasTarget"),
        BlockError::ExcessBlobGas { .. }
        | BlockError::ExcessBlobGasUnderivable
        | BlockError::BlobGasUsed { .. }
        | BlockError::BlobGasAboveMax { .. } => protocol(FailKind::BlobGas),
        // El padre sin campos de blob fuera del primer bloque de Cancun (que
        // el crate evalúa en cero) es un fixture que no entendimos: nunca un
        // rechazo.
        BlockError::ParentFieldMissing { .. } => internal("padre sin campos de blob"),
        BlockError::GasUsedAboveLimit { .. } => protocol(FailKind::GasUsedAboveLimit),
        BlockError::TimestampNotAfterParent { .. } => protocol(FailKind::Timestamp),
        BlockError::NumberNotParentPlusOne { .. } => protocol(FailKind::BlockNumber),
        BlockError::ExtraDataTooLong { .. } => protocol(FailKind::ExtraData),
        BlockError::NonZeroDifficulty => protocol(FailKind::Difficulty),
        BlockError::NonZeroNonce => protocol(FailKind::PowNonce),
        BlockError::NonEmptyOmmersHash { .. } => protocol(FailKind::OmmersHash),
        BlockError::NonEmptyOmmers { .. } => protocol(FailKind::Ommers),
        BlockError::ParentHash { .. } => protocol(FailKind::ParentHash),
        BlockError::WithdrawalsRoot { .. } | BlockError::WithdrawalsWithoutRoot { .. } => {
            protocol(FailKind::WithdrawalsRoot)
        }
        // Ninguna otra regla corre antes de ejecutar: llegar acá es un
        // desacuerdo entre el harness y el crate, no un bloque inválido.
        _ => internal("veredicto de header no clasificado"),
    }
}

/// `GAS_PER_BLOB ×` los blobs que suman las txs del bloque. `GAS_PER_BLOB`
/// sale del motor: dos copias del número serían dos fuentes de verdad.
fn block_blob_gas(block: &TestBlock) -> Option<u64> {
    let blobs = block.transactions.iter().try_fold(0usize, |acc, tx| {
        acc.checked_add(tx.blob_versioned_hashes.len())
    })?;
    u64::try_from(blobs)
        .ok()?
        .checked_mul(repo_b_evm::blob::GAS_PER_BLOB)
}

/// Lo que produjo un bloque, antes de contrastarlo contra su header.
#[derive(PartialEq, Eq)]
struct ExecutedBlock {
    post: BTreeMap<Address, FixtureAccount>,
    receipts: Vec<Receipt>,
    gas_used: u64,
    /// El diff del bloque **entero**, no de cada tx. Lo necesita el recómputo
    /// del root desde el witness: el trie se actualiza una vez por bloque.
    changes: repo_b_evm::StateChanges,
    /// Los outputs crudos de las system calls de CIERRE (EIP-7002/7251), en
    /// orden. Vacío fuera de Prague. Entra al `ExecutedBlock` —y por lo tanto a
    /// la comparación de la segunda corrida— porque es el dato del que salen dos
    /// de los tres tipos de request: un bloque que produce el mismo estado y
    /// otros outputs no es el mismo bloque.
    closing_outputs: Vec<Bytes>,
}

/// Los argumentos de `run_block`. Struct y no una lista de parámetros sueltos:
/// son siete, y varios comparten tipo — cruzarlos no lo vería el compilador.
pub(super) struct RunBlock<'a> {
    pub(super) spec: Spec,
    pub(super) test: &'a BlockchainTest,
    pub(super) block: &'a TestBlock,
    pub(super) header: &'a BlockHeader,
    /// El hash **computado** del padre REAL de la cadena (el head), no el
    /// `parentHash` que el bloque declara ni el `hash` que su header publica: es
    /// la calldata de la system call de EIP-2935. Viaja como `B256` suelto y no
    /// como `&BlockHeader` para que el hash publicado no esté al alcance.
    pub(super) parent_hash: B256,
    pub(super) pre: &'a BTreeMap<Address, FixtureAccount>,
    pub(super) block_hashes: &'a BTreeMap<u64, B256>,
    /// Los headers RLP de los ancestros, por número. Es lo que el witness
    /// necesita para probar un `BLOCKHASH`: la cadena contigua, no el hash.
    pub(super) chain: &'a BTreeMap<u64, Bytes>,
    /// Si está, el bloque se ejecuta contra ESTE `State` en vez de contra el
    /// pre-state completo. Es lo que permite correr el mismo bloque, con el
    /// mismo código, alimentado solo por un witness — sin una segunda copia del
    /// lifecycle que pudiera divergir de la primera.
    pub(super) from_witness: Option<&'a dyn State>,
    /// Modo de verificación por witness (`--witness-blocks`).
    pub(super) witness: bool,
    pub(super) shape: &'static str,
}

/// Corre el lifecycle del bloque con el grabador en el camino y, si el bloque
/// se rechaza a MITAD de la ejecución, le pasa el mismo bloque al guest.
fn run_block(args: &RunBlock<'_>) -> Result<ExecutedBlock, Rejection> {
    let base = MemoryState::from_pre(args.pre).with_block_hashes(args.block_hashes.clone());
    // El grabador queda SIEMPRE en el camino: es transparente por construcción
    // (lo gatea `--record-replay`) y tenerlo puesto es lo que permite armar el
    // witness del bloque sin ejecutarlo dos veces para descubrir qué tocó.
    let recorder = repo_b_witness::RecordingState::new(Box::new(base));
    let result = execute_block(args, &recorder);
    // Un rechazo de protocolo que sale de acá cortó el lifecycle antes de
    // `finish_block` (una tx que el motor rechaza, una firma, una system call,
    // los requests): `verify_from_witness` nunca lo ve, así que el guest se
    // juzga aparte, con el witness de lo que el bloque alcanzó a tocar.
    if let Err(Rejection::Protocol(failure)) = &result
        && args.witness
        && args.from_witness.is_none()
        && let Some(guest) = guest_rejects_execution(args, &recorder.log(), failure)
    {
        return Err(Rejection::Internal(guest));
    }
    result
}

fn execute_block(
    args: &RunBlock<'_>,
    recorder: &repo_b_witness::RecordingState,
) -> Result<ExecutedBlock, Rejection> {
    let &RunBlock {
        spec,
        test,
        block,
        header,
        // La calldata de 2935 sale del header validado (ver abajo); el hash
        // computado del padre lo consume `verify_from_witness` desde `args`.
        parent_hash: _,
        pre,
        block_hashes: _,
        // `chain` y `pre` los consume `verify_from_witness` desde `args`.
        chain: _,
        from_witness,
        witness,
        shape,
    } = args;
    // `validate_header` ya garantizó que está: llegar acá sin él sería un
    // desacuerdo entre las dos funciones, no un fixture raro.
    let Some(base_fee) = header.fields.base_fee_per_gas else {
        return Err(Rejection::Internal(Failure::new(
            FailKind::Parse,
            "header sin baseFeePerGas",
            "el header no trae `baseFeePerGas` y el fork es post-Merge".to_owned(),
        )));
    };
    let env = BlockEnv {
        spec,
        chain_id: test.chain_id,
        number: header.fields.number,
        coinbase: header.fields.beneficiary,
        timestamp: header.fields.timestamp,
        gas_limit: header.fields.gas_limit,
        base_fee,
        prevrandao: header.fields.mix_hash,
        blob_excess_gas: header.fields.excess_blob_gas,
        blob_base_fee: None,
        blob_base_fee_update_fraction: None,
    };

    // El mismo lifecycle, alimentado por uno u otro `State`.
    let state: &dyn State = from_witness.unwrap_or(recorder);
    let mut vm = OwnVm::new();
    let withdrawals = block.withdrawals.clone().unwrap_or_default();
    vm.begin_block_with_withdrawals(&env, state, withdrawals)
        .map_err(|e| Rejection::from_vm(&e, None, "begin_block falló"))?;

    // Las system calls de arranque (EIP-4788 desde Cancun, EIP-2935 desde
    // Prague) corren ANTES de la primera tx y sus escrituras entran al
    // `stateRoot` del bloque.
    //
    // Las ORQUESTA el cliente y no `begin_block`, porque el seam `Vm` está
    // vendoreado y `begin_block(env, state)` no lleva el beacon root: el trait
    // expone `system_call_in_block` justamente para que el cliente —el que lee
    // el header— dispare la llamada. Cuáles, con qué calldata y cuáles
    // invalidan el bloque lo decide `repo_b_block::system_calls`, la MISMA
    // política que corre el guest: las de arranque son *unchecked* en Cancun,
    // Prague y Osaka (`execution-specs`, `process_unchecked_system_transaction`).
    //
    // La calldata de 2935 es el `parentHash` del header, que a esta altura ya
    // encadena con el hash computado del padre real (`validate_header`).
    let calls = repo_b_block::system_calls(&header.fields, spec).map_err(|e| {
        Rejection::Protocol(
            Failure::new(
                FailKind::SystemCall,
                shape,
                format!("bloque {}: {e}", header.fields.number),
            )
            .judged_by(GuestRule::Exact(repo_b_guest::GuestError::Block(e))),
        )
    })?;
    repo_b_block::run_system_calls(&mut vm, &calls.opening)
        .map_err(|e| system_call_rejection(e, header, shape))?;

    // Un bloque NO puede llevar una tx que el protocolo rechaza. A diferencia
    // de un `state_test` —donde la tx inválida simplemente no se ejecuta—, acá
    // el bloque es inválido PORQUE la contiene.
    for (i, tx) in block.transactions.iter().enumerate() {
        let transaction = recovered_transaction(tx, env.chain_id, header.fields.number, i, shape)?;
        vm.transact_in_block(&transaction, transaction.sender)
            .map_err(|e| {
                Rejection::from_vm(&e, Some(i), "el bloque lleva una tx que el motor rechaza")
            })?;
    }

    let receipts = vm.receipts().to_vec();
    let gas_used = receipts
        .last()
        .map_or(0, |receipt| receipt.cumulative_gas_used);

    // EIP-7685: los requests se derivan DESPUÉS de las withdrawals, que por eso
    // se acreditan acá y no en `finish_block` — las dos system calls de abajo
    // todavía son parte del bloque y tienen que ver el estado que dejaron.
    let mut closing_outputs = Vec::new();
    if spec.is_enabled(Spec::Prague) {
        vm.settle_withdrawals_in_block()
            .map_err(|e| Rejection::from_vm(&e, None, "acreditando las withdrawals"))?;
        let (requests_hash, outputs) =
            block_requests_hash(&mut vm, &receipts, &calls.closing, header, shape)?;
        closing_outputs = outputs;
        // Post-Prague el campo es parte del header: un bloque sin él es
        // inválido, no un bloque sin requests.
        repo_b_block::check_requests_hash(&header.fields, requests_hash, spec).map_err(|e| {
            Rejection::Protocol(
                Failure::new(
                    FailKind::Requests,
                    shape,
                    format!("bloque {}: {e}", header.fields.number),
                )
                .judged_by(GuestRule::Exact(repo_b_guest::GuestError::Block(e))),
            )
        })?;
    }

    let changes = vm
        .finish_block()
        .map_err(|e| Rejection::from_vm(&e, None, "finish_block falló"))?;
    let post = apply_updates(pre, &changes)
        .map_err(|e| Rejection::Internal(Failure::new(FailKind::PostStateApply, shape, e)))?;

    let executed = ExecutedBlock {
        post,
        receipts,
        gas_used,
        changes,
        closing_outputs,
    };

    // La segunda corrida: el MISMO bloque, por el MISMO lifecycle, alimentado
    // solo por el witness de lo que la primera tocó. Solo en el modo, y solo en
    // la corrida de arriba — la de adentro ya viene con `from_witness`.
    if witness && from_witness.is_none() {
        verify_from_witness(args, &recorder.log(), &executed)?;
    }
    Ok(executed)
}

/// Arma el witness de lo que el bloque tocó y lo vuelve a ejecutar contra él.
///
/// Que el resultado tenga que ser **idéntico** es la definición de
/// statelessness: si el bloque se puede reproducir sin la base de datos, el
/// witness alcanza; si además falla al quitarle algo, es porque no sobra.
fn verify_from_witness(
    args: &RunBlock<'_>,
    log: &repo_b_witness::AccessLog,
    completo: &ExecutedBlock,
) -> Result<(), Rejection> {
    // Las claves cuyo cambio altera la forma del trie, juntadas del bloque
    // ENTERO: un bloque tiene varias txs y un solo witness, así que agruparlas
    // por tx dejaría afuera lo que una tx borra y otra vuelve a tocar.
    let shape = crate::witness_build::ShapeChanges::of(&completo.changes, args.pre);
    let witness = crate::witness_build::build_block(
        args.pre,
        log,
        args.chain,
        args.header.fields.number,
        &shape,
    );
    let root = compute_state_root(args.pre);
    let state = repo_b_witness::WitnessState::new(&witness, root)
        .with_chain(
            &witness,
            args.parent_hash,
            args.header.fields.number.saturating_sub(1),
        )
        .map_err(|e| {
            Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: la cadena de headers no verifica: {e}",
                    args.header.fields.number
                ),
            ))
        })?;
    let repetido = run_block(&RunBlock {
        from_witness: Some(&state),
        ..*args
    })
    .map_err(|rejection| match rejection {
        // Un bloque que el pre-state completo aceptó y el witness rechaza es
        // una falla del witness, no del protocolo: se re-etiqueta para que no
        // se confunda con un rechazo legítimo.
        Rejection::Protocol(failure) | Rejection::Internal(failure) => {
            Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: no se pudo ejecutar solo desde el witness: {}",
                    args.header.fields.number, failure.detail
                ),
            ))
        }
    })?;
    if repetido != *completo {
        return Err(Rejection::Internal(Failure::new(
            FailKind::Witness,
            args.shape,
            format!(
                "bloque {}: ejecutado solo desde el witness produjo otro bloque",
                args.header.fields.number
            ),
        )));
    }
    // **El post-state root, recomputado SOLO desde el witness.** Es la mitad
    // del DoD que el harness venía contestando con el estado completo — que es
    // exactamente lo que un guest no tiene.
    let esperado = compute_state_root(&completo.post);
    // **El bloque, por el punto de entrada del guest.** El input se codifica
    // del lado del host, se decodifica del lado del guest, y el guest valida y
    // ejecuta. Su veredicto y su journal se contrastan contra los del driver,
    // que no salen del guest. Si el modo de congelado está prendido, este
    // bloque puede ser además el caso que el guest ejecuta adentro del zkVM.
    verify_roundtrip(args, &witness, root, esperado, completo)?;
    match state.post_state_root(&completo.changes) {
        Ok(r) if r == esperado => WITNESS_ROOTS.fetch_add(1, Ordering::Relaxed),
        Ok(r) => {
            return Err(Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: el root recomputado desde el witness es {r} y no {esperado}",
                    args.header.fields.number
                ),
            )));
        }
        Err(e) => {
            return Err(Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: no se pudo recomputar el root desde el witness: {e}",
                    args.header.fields.number
                ),
            )));
        }
    };
    // Auditoría: un bloque sin cambios de estado pasa trivialmente, y contarlo
    // junto a los demás inflaría el número sin evidencia detrás.
    if completo.changes.is_empty() {
        WITNESS_ROOTS_TRIVIALES.fetch_add(1, Ordering::Relaxed);
    }
    WITNESS_BLOCKS.fetch_add(1, Ordering::Relaxed);
    WITNESS_BYTES.fetch_add(witness.size_in_bytes() as u64, Ordering::Relaxed);
    if !log.block_hashes.is_empty() {
        WITNESS_WITH_BLOCKHASH.fetch_add(1, Ordering::Relaxed);
        WITNESS_CHAIN_MAX.fetch_max(witness.headers.len() as u64, Ordering::Relaxed);
        // Los headers se cuentan aparte del peso total: son el 0,4 % de los
        // bloques, así que en el promedio global su costo desaparece. Una
        // métrica que no puede ver el cambio que mide no sirve de gate.
        WITNESS_HEADERS.fetch_add(witness.headers.len() as u64, Ordering::Relaxed);
        WITNESS_HEADER_BYTES.fetch_add(
            witness.headers.iter().map(|h| h.len() as u64).sum::<u64>(),
            Ordering::Relaxed,
        );
    }
    Ok(())
}

/// El journal que el guest tiene que publicar para este bloque, **computado por
/// el driver**: el hash del header que el harness verificó contra el fixture,
/// el hash del head real de la cadena, el root del pre-state completo, el del
/// post-state completo y el digest del diff que produjo el driver. Nada de esto
/// sale del guest ni de su witness.
fn journal_esperado(
    args: &RunBlock<'_>,
    root: B256,
    esperado: B256,
    completo: &ExecutedBlock,
) -> Journal {
    let salida = repo_b_guest::BlockOutput {
        changes: completo.changes.clone(),
        closing_outputs: completo.closing_outputs.clone(),
        receipts: completo.receipts.clone(),
    };
    Journal {
        mode: Mode::Full,
        chain_id: args.test.chain_id,
        fork: Some(args.spec),
        block_hash: args.header.fields.hash(),
        parent_hash: args.parent_hash,
        pre_state_root: root,
        post_state_root: esperado,
        output_digest: repo_b_guest::digest_of(&salida),
    }
}

/// **El sender de cada tx, derivado de su firma, contra el que el fixture
/// declara** — un oráculo independiente: no sale de nuestro encoder ni de
/// nuestra recuperación. Va aparte de la ejecución porque un bloque cuyo diff
/// no dependa del sender pasaría igual, y entonces la aserción no existiría.
///
/// Devuelve `false` si alguna tx no se puede armar como envelope desde el
/// fixture: no hay sender que contrastar, y se cuenta aparte.
fn contrast_senders(args: &RunBlock<'_>) -> Result<bool, Rejection> {
    for (i, tx) in args.block.transactions.iter().enumerate() {
        let Ok(firmada) = super::fixture::signed_transaction(tx) else {
            return Ok(false);
        };
        let derivado = firmada.recover(args.test.chain_id).map_err(|e| {
            Rejection::Internal(Failure::new(
                FailKind::Sender,
                args.shape,
                format!(
                    "bloque {}: la firma de la tx {i} no recupera: {}",
                    args.header.fields.number, e.0
                ),
            ))
        })?;
        if derivado.sender != tx.sender {
            return Err(Rejection::Internal(Failure::new(
                FailKind::Sender,
                args.shape,
                format!(
                    "bloque {}: la tx {i} firma como {} y el fixture declara {}",
                    args.header.fields.number, derivado.sender, tx.sender
                ),
            )));
        }
        SENDERS_DERIVADOS.fetch_add(1, Ordering::Relaxed);
        for auth in &derivado.authorization_list {
            if auth.authority.is_some() {
                AUTHORITIES_DERIVADAS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(true)
}

/// El bloque por el camino del guest: input por bytes, ida y vuelta, y el
/// **veredicto** del guest contra el del driver.
///
/// - Un bloque que el driver acepta, el guest lo tiene que aceptar con
///   **exactamente** el journal que el driver computó (`journal_esperado`).
/// - Un bloque que el driver rechaza por lo ejecutado (`contrast`: roots,
///   bloom, gas, txs), el guest lo tiene que rechazar. Llegan acá porque el
///   witness se arma antes de que el driver contraste.
fn verify_roundtrip(
    args: &RunBlock<'_>,
    witness: &repo_b_common::witness::ExecutionWitness,
    root: B256,
    esperado: B256,
    completo: &ExecutedBlock,
) -> Result<(), Rejection> {
    let fail =
        |detalle: String| Rejection::Internal(Failure::new(FailKind::Witness, args.shape, detalle));
    let number = args.header.fields.number;
    if !contrast_senders(args)? {
        ROUNDTRIP_SKIP.fetch_add(1, Ordering::Relaxed);
    }
    let input = guest_input_of(args, witness);
    let bytes = repo_b_guest::codec::encode_block_input(&input);
    ROUNDTRIP_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    if let Ok(mut sizes) = ROUNDTRIP_SIZES.lock() {
        sizes.push(bytes.len() as u64);
    }
    let vuelto = repo_b_guest::codec::decode_block_input(&bytes).map_err(|e| {
        fail(format!(
            "bloque {number}: el input del guest no decodifica: {e:?}"
        ))
    })?;
    // El round-trip **no se tira**: prueba que ningún campo se pierde en el
    // viaje, incluidos los que este bloque no ejercita.
    if vuelto != input {
        return Err(fail(format!(
            "bloque {number}: el input no sobrevivió el round-trip"
        )));
    }
    let veredicto = contrast(args.header, args.block, completo, args.shape, None);
    let guest = repo_b_guest::run_block_input(Mode::Full, &vuelto);
    match (veredicto, guest) {
        (None, Ok(journal)) => {
            let debido = journal_esperado(args, root, esperado, completo);
            if journal != debido {
                return Err(fail(format!(
                    "bloque {number}: el guest publicó {journal:?} y el driver computó {debido:?}"
                )));
            }
            if !completo.closing_outputs.is_empty() {
                ROUNDTRIP_CLOSING.fetch_add(1, Ordering::Relaxed);
                // **La auditoría del contraste**: un predeploy que siempre
                // devuelve vacío haría que el digest coincidiera por vacuidad.
                if completo.closing_outputs.iter().any(|o| !o.is_empty()) {
                    ROUNDTRIP_CLOSING_NONEMPTY.fetch_add(1, Ordering::Relaxed);
                }
            }
            ROUNDTRIP_BLOCKS.fetch_add(1, Ordering::Relaxed);
            congelar_caso(args, &bytes, &debido);
            crate::blockchain::rpc_export::offer(
                &crate::blockchain::dump::label(&args.test.name, number),
                &args.block.rlp,
                witness,
                &debido,
            );
            Ok(())
        }
        (Some(_), Err(_)) => {
            ROUNDTRIP_REJECTED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        (None, Err(e)) => Err(fail(format!(
            "bloque {number}: el guest rechazó un bloque que el driver acepta: {e:?}"
        ))),
        (Some(rechazo), Ok(journal)) => Err(fail(format!(
            "bloque {number}: el guest aceptó un bloque que el driver rechaza por `{}`: {journal:?}",
            rechazo.kind.as_str()
        ))),
    }
}

/// Congela este bloque como el caso que el guest ejecuta adentro del zkVM.
///
/// **No-op salvo que `REPO_B_GUEST_DUMP_DIR` esté puesto**, que es el default
/// de toda corrida del gate: esto no mueve ningún eje ni cuesta nada cuando
/// está apagado. Solo se ofrecen bloques que el driver aceptó, con el journal
/// que el driver computó (`journal_esperado`).
fn congelar_caso(args: &RunBlock<'_>, bytes: &[u8], journal: &Journal) {
    let opening = usize::from(args.spec.is_enabled(Spec::Cancun))
        .saturating_add(usize::from(args.spec.is_enabled(Spec::Prague)));
    let closing = if args.spec.is_enabled(Spec::Prague) {
        2
    } else {
        0
    };
    let txs = args.block.transactions.len();
    if !crate::blockchain::dump::califica(txs, closing, opening) {
        return;
    }
    crate::blockchain::dump::offer(
        &crate::blockchain::dump::label(&args.test.name, args.header.fields.number),
        bytes,
        journal,
        &format!(
            "{:?} bloque {} · {txs} txs · {} withdrawals · {closing} system calls de cierre",
            args.spec,
            args.header.fields.number,
            args.block.withdrawals.as_ref().map_or(0, Vec::len),
        ),
    );
}

/// Contadores del modo `--witness-blocks`. Son estadística del harness (no
/// entran en ningún veredicto), y por eso pueden vivir sueltos: el veredicto de
/// cada bloque ya viaja por el `Result`.
pub static WITNESS_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// Bloques cuyo post-state root se recomputó **solo desde el witness**.
pub static WITNESS_ROOTS: AtomicU64 = AtomicU64::new(0);
/// Bloques que el guest **ejecutó** desde el input por bytes, con el mismo
/// resultado que el driver.
pub static ROUNDTRIP_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// De esos, los que además corrieron system calls de CIERRE. Se cuentan aparte
/// porque son la pieza que este eje agrega: un total que las incluya no diría
/// cuántos bloques la ejercitan de verdad.
pub static ROUNDTRIP_CLOSING: AtomicU64 = AtomicU64::new(0);
/// De esos, los que produjeron un output **no vacío**. Sin este número,
/// "los outputs coinciden" podría ser cierto por vacuidad.
pub static ROUNDTRIP_CLOSING_NONEMPTY: AtomicU64 = AtomicU64::new(0);
/// Bloques que el driver rechaza por lo ejecutado y el guest también rechazó,
/// por el mismo camino de bytes. Sin este número, "el guest no aceptó ningún
/// bloque inválido" podría ser cierto porque no vio ninguno.
pub static ROUNDTRIP_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static ROUNDTRIP_BYTES: AtomicU64 = AtomicU64::new(0);
/// El tamaño del input de CADA bloque. La distribución es el entregable: un
/// promedio no ve la cola, y su p99 sí.
pub static ROUNDTRIP_SIZES: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
/// Bloques cuyo input no se pudo armar. Se cuentan aparte: un salteo silencioso
/// convertiría el gate en un espejo.
pub static ROUNDTRIP_SKIP: AtomicU64 = AtomicU64::new(0);
/// **Cuántos senders se derivaron de una firma y coincidieron con el declarado.**
/// Sin este número, "0 fallas de `Sender`" podría ser cierto por vacuidad.
pub static SENDERS_DERIVADOS: AtomicU64 = AtomicU64::new(0);
/// De esos, cuántos `authority` de EIP-7702 recuperaron. Se cuenta aparte
/// porque es la mitad del §2.4 que el corpus casi no ejercita.
pub static AUTHORITIES_DERIVADAS: AtomicU64 = AtomicU64::new(0);
/// De esos, los que no tenían un solo cambio de estado: pasan trivialmente.
pub static WITNESS_ROOTS_TRIVIALES: AtomicU64 = AtomicU64::new(0);
pub static WITNESS_BYTES: AtomicU64 = AtomicU64::new(0);
pub static WITNESS_WITH_BLOCKHASH: AtomicU64 = AtomicU64::new(0);
pub static WITNESS_CHAIN_MAX: AtomicU64 = AtomicU64::new(0);
pub static WITNESS_HEADERS: AtomicU64 = AtomicU64::new(0);
pub static WITNESS_HEADER_BYTES: AtomicU64 = AtomicU64::new(0);

/// EIP-7685: dispara las dos system calls de cierre de bloque y devuelve el
/// commitment de los tres tipos de request.
///
/// A diferencia de 4788 y 2935, estas dos son **checked**: un predeploy sin
/// código, o un revert, un halt o un OOG de la llamada, invalida el bloque
/// (`execution-specs`: `process_checked_system_transaction`). El corpus SÍ lo
/// ejercita: los vectores de `SYSTEM_CONTRACT_CALL_FAILED` del set son de 7002
/// y 7251, y los de `SYSTEM_CONTRACT_EMPTY` vienen de las redes de transición
/// a Prague (`test_system_contract_deployment`).
fn block_requests_hash(
    vm: &mut OwnVm,
    receipts: &[Receipt],
    closing: &[repo_b_block::SystemCall],
    header: &BlockHeader,
    shape: &'static str,
) -> Result<(B256, Vec<Bytes>), Rejection> {
    let outputs = repo_b_block::run_system_calls(vm, closing)
        .map_err(|e| system_call_rejection(e, header, shape))?;
    let [withdrawal, consolidation] = outputs.as_slice() else {
        return Err(Rejection::Internal(Failure::new(
            FailKind::SystemCall,
            shape,
            format!(
                "bloque {}: un bloque de Prague sin las dos system calls de cierre",
                header.fields.number
            ),
        )));
    };
    // El layout del evento de depósito es consenso: un log mal formado del
    // contrato de depósito invalida el bloque, no se saltea.
    let collected =
        block_requests::collect_requests(receipts, withdrawal, consolidation).map_err(|e| {
            Rejection::Protocol(
                Failure::new(
                    FailKind::DepositLayout,
                    shape,
                    format!("bloque {}: {e}", header.fields.number),
                )
                .judged_by(GuestRule::Exact(repo_b_guest::GuestError::Block(e))),
            )
        })?;
    Ok((block_requests::requests_hash(&collected), outputs))
}

/// Un error de la política de system calls, en el vocabulario del harness:
/// una *checked* sin código o que falla invalida el bloque; un error del motor
/// se clasifica como cualquier otro.
fn system_call_rejection(
    e: repo_b_block::SystemCallError,
    header: &BlockHeader,
    shape: &'static str,
) -> Rejection {
    use repo_b_guest::GuestError as G;
    let number = header.fields.number;
    match e {
        repo_b_block::SystemCallError::Vm(e) => {
            Rejection::from_vm(&e, None, "una system call falló")
        }
        repo_b_block::SystemCallError::EmptyCode { address } => Rejection::Protocol(
            Failure::new(
                FailKind::SystemContractEmpty,
                shape,
                format!("bloque {number}: la system call checked a {address} no tiene código"),
            )
            .judged_by(GuestRule::Exact(G::SystemContractEmpty(address))),
        ),
        repo_b_block::SystemCallError::Failed { address, result } => Rejection::Protocol(
            Failure::new(
                FailKind::SystemCall,
                shape,
                format!(
                    "bloque {number}: la system call a {address} no terminó en éxito: {result:?}"
                ),
            )
            .judged_by(GuestRule::Exact(G::SystemCall { address, result })),
        ),
    }
}

/// Contrasta TODO lo que el harness computó contra el campo del header.
///
/// Las reglas son las del crate de bloque: primero el `stateRoot`, que es la
/// transición de estado (lo que el motor decide), y después la maquinaria de
/// encoding. Así un bug del motor no se esconde detrás de un bug del encoder
/// ni al revés. El `transactionsRoot` va al final porque no depende de la
/// ejecución.
fn contrast(
    header: &BlockHeader,
    block: &TestBlock,
    executed: &ExecutedBlock,
    shape: &'static str,
    expected_state: Option<&BTreeMap<Address, FixtureAccount>>,
) -> Option<Failure> {
    let number = header.fields.number;
    let tx_types = block
        .transactions
        .iter()
        .map(|tx| tx.tx_type)
        .collect::<Vec<_>>();
    let receipts_root = match roots::receipts_root(&tx_types, &executed.receipts) {
        Ok(root) => root,
        Err(e) => {
            return Some(Failure::new(
                FailKind::ReceiptTrie,
                error_head(&e.to_string()),
                format!("bloque {number}: no se pudo armar el receiptTrie: {e}"),
            ));
        }
    };
    let computed = PostExecution {
        state_root: compute_state_root(&executed.post),
        gas_used: executed.gas_used,
        receipts_root,
        logs_bloom: roots::block_logs_bloom(&executed.receipts),
    };
    if let Err(e) = repo_b_block::validate_post_execution(&header.fields, &computed) {
        let mut message = format!("bloque {number}: {e}");
        let kind = match e {
            BlockError::StateRoot { .. } => {
                // El juez es el root; el `postState` inline solo dice DÓNDE
                // divergió.
                if let Some(expected) = expected_state {
                    let diffs = diff_expected(expected, &executed.post);
                    if !diffs.is_empty() {
                        message.push_str(&format!(" | post-state: {}", diffs.join(" | ")));
                    }
                }
                FailKind::StateRoot
            }
            BlockError::GasUsed { .. } => FailKind::GasUsed,
            BlockError::ReceiptsRoot { .. } => FailKind::ReceiptTrie,
            BlockError::LogsBloom => FailKind::Bloom,
            _ => FailKind::InternalError,
        };
        return Some(Failure::new(kind, shape, message));
    }
    let encoded = match encoded_transactions(&block.transactions) {
        Ok(encoded) => encoded,
        Err(e) => {
            return Some(Failure::new(
                FailKind::TransactionsTrie,
                error_head(&e),
                format!("no se pudo encodear una tx: {e}"),
            ));
        }
    };
    if let Err(e) = repo_b_block::check_transactions_root(&header.fields, &encoded) {
        return Some(Failure::new(
            FailKind::TransactionsTrie,
            shape,
            format!("bloque {number}: {e}"),
        ));
    }
    // El `withdrawalsRoot` NO se contrasta acá: es una regla de header y vive
    // en `validate_header`, que corre antes de ejecutar. Un bloque cuyo
    // `withdrawalsRoot` no cierra es inválido, no un bloque válido que da mal.
    None
}

/// Las txs del bloque en su encoding de consenso (EIP-2718). **El encoder es el
/// del guest, no uno de acá**: uno solo arma el envelope del trie y el payload
/// que se firma, y el contraste del `transactionsRoot` de cada bloque contra su
/// header es lo que lo gatea.
fn encoded_transactions(txs: &[FixtureTx]) -> Result<Vec<Vec<u8>>, String> {
    txs.iter()
        .map(|tx| {
            super::fixture::signed_transaction(tx)?
                .encode_2718()
                .map_err(|e| format!("la tx no es representable como envelope: {}", e.0))
        })
        .collect()
}

/// `FixtureTx` → la `Transaction` que ejecuta el motor, con el remitente
/// **derivado de la firma**.
///
/// El envelope se arma sin el `sender` declarado y lo recupera la misma ruta
/// que corre el guest (`SignedTransaction::recover`): low-s de EIP-2, `r, s` en
/// `[1, n)`, `v` legacy/EIP-155, `yParity` y el `chainId` del bloque. Una firma
/// que no recupera es una tx inválida, y un bloque que la lleva es inválido
/// (fail-closed).
///
/// El `sender` del fixture queda como **contraste**: si la firma recupera otra
/// dirección, el harness y el generador del fixture no están hablando del
/// mismo envelope, y eso nunca cuenta como un rechazo válido.
fn recovered_transaction(
    tx: &FixtureTx,
    chain_id: u64,
    number: u64,
    index: usize,
    shape: &'static str,
) -> Result<Transaction, Rejection> {
    // El guest decodifica el mismo envelope de los bytes del bloque y lo
    // recupera con la misma función: tiene que rechazar ESTA tx.
    let rechazo = |kind: FailKind, motivo: String, rule: GuestRule| {
        Rejection::Protocol(
            Failure::new(
                kind,
                shape,
                format!("bloque {number}: la tx {index} no tiene un remitente válido: {motivo}"),
            )
            .judged_by(rule),
        )
    };
    // Precio de gas de más de 128 bits: el envelope no es representable en el
    // formato del guest (ver `FixtureTx::fee_exceeds_u128`).
    if tx.fee_exceeds_u128 {
        return Err(rechazo(
            FailKind::Envelope,
            "un precio de gas no entra en 128 bits".to_owned(),
            GuestRule::SignatureOf(index),
        ));
    }
    // Un `chainId` de más de 64 bits no puede ser el del bloque: es la regla de
    // chain-id, no un envelope roto.
    if tx
        .chain_id
        .is_some_and(|chain| u64::try_from(chain).is_err())
    {
        return Err(rechazo(
            FailKind::Signature,
            "el chainId de la tx no entra en 64 bits".to_owned(),
            GuestRule::SignatureOf(index),
        ));
    }
    // Lo que quede es un fixture que el harness no sabe armar (tuplas sin
    // parear, una tipada sin `chainId`): problema nuestro, nunca un rechazo.
    let firmada = super::fixture::signed_transaction(tx).map_err(|motivo| {
        Rejection::Internal(Failure::new(
            FailKind::Parse,
            shape,
            format!("bloque {number}: la tx {index} no se puede armar como envelope: {motivo}"),
        ))
    })?;
    let recuperada = firmada.recover(chain_id).map_err(|e| {
        let rule = GuestRule::Exact(repo_b_guest::GuestError::Signature(format!(
            "tx {index}: {}",
            e.0
        )));
        rechazo(FailKind::Signature, e.0.to_owned(), rule)
    })?;
    if recuperada.sender != tx.sender {
        return Err(Rejection::Internal(Failure::new(
            FailKind::Sender,
            shape,
            format!(
                "bloque {number}: la tx {index} firma como {} y el fixture declara {}",
                recuperada.sender, tx.sender
            ),
        )));
    }
    Ok(recuperada)
}

/// Recorta un mensaje a su cabeza estable para que sirva de sub-clave de
/// cluster: sin valores concretos que harían de cada caso su propio cluster.
fn error_head(msg: &str) -> String {
    let head = msg.split([':', '(', '{']).next().unwrap_or(msg).trim();
    head.chars().take(60).collect()
}

/// **La tabla de blobs del motor contra la que el fixture declara.**
///
/// El diferencial no puede juzgar los números de blob: revm recibe la fracción
/// de `blob::update_fraction`, la misma que usa el motor. El único juez externo
/// de esos números es el corpus, así que se contrastan acá, fila por fila:
///
/// - todo fork con blobs que el caso alcanza (el base y el de CADA activación
///   de la red, sin suponer cuántas son) **tiene que** estar en el
///   `blobSchedule`;
/// - toda fila del `blobSchedule` tiene que ser un fork conocido y coincidir
///   con `blob_params`. Una fila desconocida no se ignora: es una red que el
///   motor no sabe describir.
///
/// Los fixtures anteriores a Cancun no traen el campo y no alcanzan ningún
/// fork con blobs, así que no hay nada que contrastar.
fn check_blob_schedule(
    schedule: &BTreeMap<String, super::fixture::BlobScheduleEntry>,
    forks: &network::NetworkForks,
) -> Option<Failure> {
    for spec in forks.reached() {
        let name = crate::fuzz::generate::fork_name(spec);
        if spec.is_enabled(Spec::Cancun) && !schedule.contains_key(name) {
            return Some(Failure::new(
                FailKind::BlobSchedule,
                "fila faltante",
                format!("el caso alcanza {name} y su `blobSchedule` no lo declara"),
            ));
        }
    }
    for (name, declared) in schedule {
        let Some(spec) = crate::fixture::spec_for_fork(name) else {
            return Some(Failure::new(
                FailKind::BlobSchedule,
                "fork desconocido",
                format!("`blobSchedule` declara `{name}`, que el motor no conoce"),
            ));
        };
        let ours = repo_b_evm::blob::blob_params(spec);
        let engine = super::fixture::BlobScheduleEntry {
            target: ours.target_blobs,
            max: ours.max_blobs,
            update_fraction: ours.update_fraction,
        };
        if engine != *declared {
            return Some(Failure::new(
                FailKind::BlobSchedule,
                "fila distinta",
                format!("{name}: el fixture declara {declared:?} y el motor usa {engine:?}"),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use repo_b_common::primitives::U256;
    use repo_b_evm::error::{ConsensusError, InternalError};

    use super::*;

    fn shanghai_header() -> repo_b_block::Header {
        repo_b_block::Header {
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Default::default(),
            difficulty: U256::ZERO,
            number: 1,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: Default::default(),
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(B256::ZERO),
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    /// Un hueco es un campo presente DESPUÉS de uno ausente; un tail corto o
    /// completo no lo es.
    #[test]
    fn a_gap_is_a_present_field_after_a_missing_one() {
        let shanghai = shanghai_header();
        assert!(!tail_has_gap(&shanghai));
        let cancun = repo_b_block::Header {
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            ..shanghai.clone()
        };
        assert!(!tail_has_gap(&cancun));
        let paris = repo_b_block::Header {
            withdrawals_root: None,
            ..shanghai.clone()
        };
        assert!(!tail_has_gap(&paris));
        // `excessBlobGas` sin `blobGasUsed`: el caso medido en el corpus.
        let excess_only = repo_b_block::Header {
            excess_blob_gas: Some(0),
            ..shanghai.clone()
        };
        assert!(tail_has_gap(&excess_only));
        let beacon_without_blob_fields = repo_b_block::Header {
            parent_beacon_block_root: Some(B256::ZERO),
            ..shanghai.clone()
        };
        assert!(tail_has_gap(&beacon_without_blob_fields));
        let requests_without_withdrawals = repo_b_block::Header {
            withdrawals_root: None,
            requests_hash: Some(B256::ZERO),
            ..cancun
        };
        assert!(tail_has_gap(&requests_without_withdrawals));
    }

    fn schedule_row(name: &str, spec: Spec) -> (String, super::super::fixture::BlobScheduleEntry) {
        let p = repo_b_evm::blob::blob_params(spec);
        (
            name.to_owned(),
            super::super::fixture::BlobScheduleEntry {
                target: p.target_blobs,
                max: p.max_blobs,
                update_fraction: p.update_fraction,
            },
        )
    }

    fn blob_schedule_verdict(
        network: &str,
        rows: Vec<(String, super::super::fixture::BlobScheduleEntry)>,
    ) -> Option<String> {
        let Some(forks) = network::resolve(network) else {
            panic!("{network} resuelve");
        };
        let schedule: BTreeMap<_, _> = rows.into_iter().collect();
        check_blob_schedule(&schedule, &forks).map(|f| {
            let (kind, detail) = f.signature();
            format!("{}:{detail}", kind.as_str())
        })
    }

    /// El `blobSchedule` se contrasta para CADA fork que la red alcanza, y
    /// cada forma de no coincidir tiene su razón nombrada.
    #[test]
    fn the_blob_schedule_is_checked_for_every_reached_fork_fail_closed() {
        let osaka = || schedule_row("Osaka", Spec::Osaka);
        let bpo1 = || schedule_row("BPO1", Spec::Bpo1);
        assert_eq!(
            blob_schedule_verdict("OsakaToBPO1AtTime15k", vec![osaka(), bpo1()]),
            None
        );
        // Falta la fila del fork de DESPUÉS de la activación.
        assert_eq!(
            blob_schedule_verdict("OsakaToBPO1AtTime15k", vec![osaka()]),
            Some("blob_schedule:fila faltante".to_owned())
        );
        // Falta la del fork base.
        assert_eq!(
            blob_schedule_verdict("OsakaToBPO1AtTime15k", vec![bpo1()]),
            Some("blob_schedule:fila faltante".to_owned())
        );
        // Una fila que no coincide con la tabla del motor.
        let mut wrong = bpo1();
        wrong.1.max = 16;
        assert_eq!(
            blob_schedule_verdict("OsakaToBPO1AtTime15k", vec![osaka(), wrong]),
            Some("blob_schedule:fila distinta".to_owned())
        );
        // Una fila de un fork que el motor no conoce.
        let mut unknown = bpo1();
        unknown.0 = "BPO3".to_owned();
        assert_eq!(
            blob_schedule_verdict("OsakaToBPO1AtTime15k", vec![osaka(), bpo1(), unknown]),
            Some("blob_schedule:fork desconocido".to_owned())
        );
        // Una red sin blobs no exige filas.
        assert_eq!(blob_schedule_verdict("Shanghai", vec![]), None);
    }

    /// La presencia de campos por fork solo la excusa
    /// `INCORRECT_BLOCK_FORMAT`; la ruta de firma, el predeploy sin código y la
    /// llamada de cierre que falla, solo su nombre propio; el resto no exige nombre.
    #[test]
    fn fork_fields_system_calls_and_the_signature_path_only_by_name() {
        assert_eq!(
            rejection_explained(
                FailKind::ForkFields,
                "BlockException.INCORRECT_BLOCK_FORMAT"
            ),
            Some(true)
        );
        for exception in [
            "BlockException.RLP_STRUCTURES_ENCODING",
            "BlockException.INVALID_BLOCK_HASH",
            "TransactionException.INVALID_SIGNATURE_VRS",
        ] {
            assert_eq!(
                rejection_explained(FailKind::ForkFields, exception),
                Some(false),
                "{exception}"
            );
        }
        assert_eq!(
            rejection_explained(
                FailKind::SystemContractEmpty,
                "BlockException.SYSTEM_CONTRACT_EMPTY"
            ),
            Some(true)
        );
        assert_eq!(
            rejection_explained(
                FailKind::SystemContractEmpty,
                "BlockException.SYSTEM_CONTRACT_CALL_FAILED"
            ),
            Some(false)
        );
        assert_eq!(
            rejection_explained(
                FailKind::SystemCall,
                "BlockException.SYSTEM_CONTRACT_CALL_FAILED"
            ),
            Some(true)
        );
        assert_eq!(
            rejection_explained(FailKind::SystemCall, "BlockException.SYSTEM_CONTRACT_EMPTY"),
            Some(false)
        );
        assert_eq!(
            rejection_explained(
                FailKind::Signature,
                "TransactionException.INVALID_SIGNATURE_VRS"
            ),
            Some(true)
        );
        assert_eq!(
            rejection_explained(FailKind::Signature, "BlockException.INVALID_GASLIMIT"),
            Some(false)
        );
        assert_eq!(
            rejection_explained(FailKind::GasLimit, "BlockException.INVALID_GASLIMIT"),
            None
        );
    }

    /// La regla —*un `internal error` nunca cuenta como rechazo válido*— **no
    /// la puede discriminar EEST**, y no por un hueco del set:
    /// un fixture describe qué tiene que hacer un cliente correcto, así que un
    /// bug del motor no es un input que el corpus pueda contener. La mutación
    /// que la ataca sale en cero por construcción. La pinea esto.
    #[test]
    fn a_consensus_error_rejects_the_block_and_an_internal_one_never_does() {
        let consensus = VmError::Consensus(ConsensusError::IntrinsicGasTooLow {
            required: 21_000,
            available: 20_999,
        });
        assert!(matches!(
            Rejection::from_vm(&consensus, None, "test"),
            Rejection::Protocol(_)
        ));

        let internal = VmError::Internal(InternalError::EvmInternal("motor roto".into()));
        assert!(matches!(
            Rejection::from_vm(&internal, None, "test"),
            Rejection::Internal(_)
        ));
    }

    /// La clave clásica de los fixtures (`0xa94f…0b`).
    const SECRET: [u8; 32] = [
        0x45, 0xa9, 0x15, 0xe4, 0xd0, 0x60, 0x14, 0x9e, 0xb4, 0x36, 0x59, 0x60, 0xe6, 0xa7, 0xa4,
        0x5f, 0x33, 0x43, 0x93, 0x09, 0x30, 0x61, 0x11, 0x6b, 0x19, 0x7e, 0x32, 0x40, 0x06, 0x5f,
        0xf2, 0xd8,
    ];
    const CHAIN: u64 = 1;
    /// `chainId·2 + 35`: la base del `v` de una legacy EIP-155.
    const EIP155_V_BASE: u64 = 35;

    /// Una legacy EIP-155 firmada de verdad para `signed_for`, con el `sender`
    /// declarado igual a la dirección de la clave.
    fn signed_legacy(signed_for: u64) -> FixtureTx {
        let Ok(key) = k256::ecdsa::SigningKey::from_slice(&SECRET) else {
            panic!("la clave de prueba es una clave de secp256k1");
        };
        let mut tx = FixtureTx {
            tx_type: repo_b_common::transaction::TxType::Legacy,
            chain_id: None,
            nonce: 0,
            gas_price: Some(10),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_limit: 21_000,
            to: Some(Address::new([0xb9; 20])),
            value: U256::from(1u8),
            data: Bytes::new(),
            access_list: Vec::new(),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: Vec::new(),
            authorization_list: Vec::new(),
            authorization_tuples: Vec::new(),
            sender: Address::ZERO,
            v: U256::from(signed_for.saturating_mul(2).saturating_add(EIP155_V_BASE)),
            r: U256::from(1u8),
            s: U256::from(1u8),
            fee_exceeds_u128: false,
        };
        let hash = match super::super::fixture::signed_transaction(&tx)
            .and_then(|f| f.signing_hash(signed_for).map_err(|e| e.0.to_owned()))
        {
            Ok(hash) => hash,
            Err(e) => panic!("la tx de prueba es representable: {e}"),
        };
        let Ok((firma, recid)) = key.sign_prehash_recoverable(hash.as_slice()) else {
            panic!("k256 firma un prehash de 32 bytes");
        };
        tx.v = tx.v.saturating_add(U256::from(recid.to_byte() & 1));
        tx.r = U256::from_be_slice(&firma.r().to_bytes());
        tx.s = U256::from_be_slice(&firma.s().to_bytes());
        let punto = key.verifying_key().to_encoded_point(false);
        let Some(crudo) = punto.as_bytes().get(1..) else {
            panic!("un punto sin comprimir trae 65 bytes");
        };
        let hash = repo_b_common::primitives::keccak256(crudo);
        let Some(addr) = hash.as_slice().get(12..) else {
            panic!("un keccak trae 32 bytes");
        };
        tx.sender = Address::from_slice(addr);
        tx
    }

    fn kind_of(result: &Result<Transaction, Rejection>) -> Option<(bool, FailKind)> {
        match result {
            Ok(_) => None,
            Err(Rejection::Protocol(f)) => Some((true, f.kind)),
            Err(Rejection::Internal(f)) => Some((false, f.kind)),
        }
    }

    #[test]
    fn the_executed_sender_is_the_one_the_signature_recovers() {
        let tx = signed_legacy(CHAIN);
        let Ok(recuperada) = recovered_transaction(&tx, CHAIN, 1, 0, "t") else {
            panic!("una firma válida para esta cadena recupera");
        };
        assert_eq!(recuperada.sender, tx.sender);
    }

    /// EIP-2: `s > n/2` invalida la tx, y el bloque se rechaza por la firma.
    #[test]
    fn a_high_s_signature_rejects_the_block() {
        let mut tx = signed_legacy(CHAIN);
        tx.s = repo_b_guest::signature::SECP256K1N_HALF.saturating_add(U256::from(1u8));
        assert_eq!(
            kind_of(&recovered_transaction(&tx, CHAIN, 1, 0, "t")),
            Some((true, FailKind::Signature))
        );
    }

    /// `r = 0` no es una firma: rechazo de protocolo, no un panic ni un error
    /// interno.
    #[test]
    fn a_zero_r_rejects_the_block() {
        let mut tx = signed_legacy(CHAIN);
        tx.r = U256::ZERO;
        assert_eq!(
            kind_of(&recovered_transaction(&tx, CHAIN, 1, 0, "t")),
            Some((true, FailKind::Signature))
        );
    }

    /// EIP-155: firmada para otra cadena ⇒ el bloque de ESTA cadena es inválido.
    #[test]
    fn a_signature_for_another_chain_rejects_the_block() {
        let tx = signed_legacy(CHAIN.saturating_add(1));
        assert_eq!(
            kind_of(&recovered_transaction(&tx, CHAIN, 1, 0, "t")),
            Some((true, FailKind::Signature))
        );
    }

    /// El `sender` declarado es contraste: si la firma recupera otro, es falla
    /// interna y nunca un rechazo válido.
    #[test]
    fn a_declared_sender_the_signature_does_not_produce_is_never_a_valid_rejection() {
        let mut tx = signed_legacy(CHAIN);
        tx.sender = Address::new([0xa9; 20]);
        assert_eq!(
            kind_of(&recovered_transaction(&tx, CHAIN, 1, 0, "t")),
            Some((false, FailKind::Sender))
        );
    }

    /// Un precio de gas que no entra en 128 bits deja un envelope que el guest
    /// no puede leer: rechazo de protocolo por `envelope`, no un sender
    /// recuperado de un envelope reconstruido con el valor saturado.
    #[test]
    fn a_fee_wider_than_128_bits_rejects_the_block_as_unrepresentable() {
        let mut tx = signed_legacy(CHAIN);
        tx.fee_exceeds_u128 = true;
        assert_eq!(
            kind_of(&recovered_transaction(&tx, CHAIN, 1, 0, "t")),
            Some((true, FailKind::Envelope))
        );
    }

    /// Un `chainId` de más de 64 bits es la regla de chain-id (`signature`), no
    /// un envelope roto ni un error del harness.
    #[test]
    fn a_chain_id_wider_than_64_bits_is_a_chain_id_rejection() {
        let mut tx = signed_legacy(CHAIN);
        tx.tx_type = repo_b_common::transaction::TxType::Eip2930;
        tx.chain_id = Some(U256::from(u64::MAX).saturating_add(U256::from(1u8)));
        assert_eq!(
            kind_of(&recovered_transaction(&tx, CHAIN, 1, 0, "t")),
            Some((true, FailKind::Signature))
        );
    }
}
