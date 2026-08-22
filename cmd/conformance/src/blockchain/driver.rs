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
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::state::State;
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;

use super::block_hash;
use super::encode;
use super::fixture::{BlockHeader, BlockchainTest, FixtureTx, TestBlock};
use super::header;
use super::requests;
use crate::fixture::{FixtureAccount, spec_for_fork};
use crate::runner::{MemoryState, apply_updates, compute_state_root, diff_expected};

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
    /// El pre-state del fixture no produce el `stateRoot` del genesis: o el
    /// parseo o el MPT del harness están mal, y todo lo de abajo sería ruido.
    GenesisRoot,
    /// El motor rechazó una tx de un bloque que el fixture declara VÁLIDO.
    ExecuteError,
    /// El diff no se pudo aplicar al pre-state.
    PostStateApply,
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
    /// EIP-4844: `excessBlobGas` / `blobGasUsed` del header no cierran.
    BlobGas,
    /// La system call de un contrato de sistema no terminó en éxito, o el
    /// header no trae el dato que necesita como calldata.
    SystemCall,
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
            Self::BlobGas => "blob_gas",
            Self::SystemCall => "system_call",
            Self::Requests => "requests",
            Self::DepositLayout => "deposit_layout",
            Self::UndecodableBlock => "undecodable_block",
            Self::BlockHash => "block_hash",
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
}

impl Failure {
    fn new(kind: FailKind, detail: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            message: message.into(),
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
    fn from_vm(err: &VmError, context: &str) -> Self {
        let rendered = format!("{err}");
        let detail = error_head(&rendered);
        match err {
            VmError::Consensus(_) => Self::Protocol(Failure::new(
                FailKind::ExecuteError,
                detail,
                format!("{context}: {rendered}"),
            )),
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
    // El scope lo filtra el llamador por el campo `network`. Que un fork llegue
    // hasta acá sin resolver a un `Spec` sería un desacuerdo entre el filtro y
    // el runner: se dice en voz alta, no se saltea en silencio.
    let Some(spec) = spec_for_fork(&test.network) else {
        return CaseOutcome::Fail(Failure::new(
            FailKind::Parse,
            "fork sin Spec",
            format!("el fork `{}` llegó al driver sin resolver", test.network),
        ));
    };

    let mut post = test.pre.clone();
    // El `pre` de un `blockchain_test` ES el estado del genesis. Contrastarlo
    // contra el `stateRoot` que el genesis declara es gratis y no es
    // tautológico: si el parseo o el MPT del harness estuvieran mal, todo lo
    // que viene abajo mediría otra cosa.
    let genesis_root = compute_state_root(&post);
    if genesis_root != test.genesis.state_root {
        return CaseOutcome::Fail(Failure::new(
            FailKind::GenesisRoot,
            "",
            format!(
                "el pre-state no produce el stateRoot del genesis: esperado {}, obtenido {genesis_root}",
                test.genesis.state_root
            ),
        ));
    }

    // El hash del genesis se COMPUTA como el de cualquier otro header, y por la
    // misma razón por la que su `stateRoot` se contrasta: si el header del
    // genesis no hashea a lo que declara, el `BLOCKHASH` de todo bloque de abajo
    // y el `lastblockhash` de las cadenas que no avanzan medirían otra cosa. Un
    // genesis NO se "rechaza" —no hay bloque que sacar de la cadena—, así que
    // esto es una falla del caso y no un `Rejection`.
    let genesis_hash = block_hash::block_hash(&test.genesis);
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
    let mut block_hashes = BTreeMap::from([(test.genesis.number, genesis_hash)]);
    // Los headers crudos de la cadena, para el witness: `BLOCKHASH` no se puede
    // probar con un hash suelto, hace falta la secuencia contigua hacia atrás
    // para encadenar `parent_hash`.
    let mut chain: BTreeMap<u64, Bytes> = BTreeMap::from([(
        test.genesis.number,
        Bytes::from(block_hash::rlp(&test.genesis)),
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
            None => Err(undecodable_block(block, shape)),
            Some(header) => {
                // La identidad del bloque se afirma para TODO bloque —válido o
                // declarado inválido— y antes que cualquier otra regla: un
                // header cuyo contenido no hashea al valor que declara no es el
                // bloque que dice ser, y ningún otro campo suyo significa nada.
                // Que sea una falla del caso y no un `Rejection` excusable es
                // deliberado; el porqué está en `check_block_hash`.
                let hash = block_hash::block_hash(header);
                if let Some(failure) = check_block_hash(header, hash) {
                    return CaseOutcome::Fail(failure);
                }
                validate_header(spec, header, head, block, shape)
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
                block_hashes.insert(header.number, hash);
                chain.insert(header.number, Bytes::from(block_hash::rlp(header)));
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
                // La cadena no avanzó: ni el head (no se toca `head`) ni el
                // estado. Lo segundo se afirma, no se supone.
                let root = compute_state_root(&post);
                if root != head.state_root {
                    return CaseOutcome::Fail(Failure::new(
                        FailKind::ChainAdvanced,
                        shape,
                        format!(
                            "un bloque se rechazó sobre el head {} y el estado avanzó igual: \
                             esperado {}, obtenido {root}",
                            head.number, head.state_root
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
            header.number, header.hash
        ),
    ))
}

/// Las reglas que hacen inválido a un bloque por lo que DECLARA, antes de
/// ejecutar nada. Corren sobre todo bloque, válido o no: excusar el rechazo sin
/// la recíproca sería un comparador tuerto.
fn validate_header(
    spec: Spec,
    header: &BlockHeader,
    parent: &BlockHeader,
    block: &TestBlock,
    shape: &'static str,
) -> Result<(), Rejection> {
    if let Err(e) = header::check_gas_limit(parent.gas_limit, header.gas_limit) {
        return Err(Rejection::Protocol(Failure::new(
            FailKind::GasLimit,
            shape,
            format!("bloque {}: {e}", header.number),
        )));
    }

    // Post-London el `baseFeePerGas` es obligatorio, y todo fork en scope acá
    // es post-Merge: un header sin él es un fixture que no entendimos, no un
    // bloque con base fee cero — y "no lo entendimos" nunca es un rechazo.
    let (Some(base_fee), Some(parent_base_fee)) = (header.base_fee, parent.base_fee) else {
        return Err(Rejection::Internal(Failure::new(
            FailKind::Parse,
            "header sin baseFeePerGas",
            "el header o su padre no traen `baseFeePerGas` y el fork es post-Merge".to_owned(),
        )));
    };
    match header::expected_base_fee(parent.gas_limit, parent.gas_used, parent_base_fee) {
        Ok(expected) if expected == base_fee => {}
        Ok(expected) => {
            return Err(Rejection::Protocol(Failure::new(
                FailKind::BaseFee,
                shape,
                format!(
                    "bloque {}: baseFeePerGas declarado {base_fee}, la fórmula de EIP-1559 exige \
                     {expected}",
                    header.number
                ),
            )));
        }
        Err(e) => {
            return Err(Rejection::Internal(Failure::new(
                FailKind::Parse,
                "padre sin gasTarget",
                e,
            )));
        }
    }

    // EIP-4844: los tres chequeos de blob gas del header. Solo Cancun+ — antes
    // los campos no existen y exigirlos rechazaría todo Paris/Shanghai.
    if spec.is_enabled(Spec::Cancun) {
        match blob_gas_of(header, parent, block) {
            Ok(blob) => {
                if let Err(e) = header::check_blob_gas(blob, spec) {
                    return Err(Rejection::Protocol(Failure::new(
                        FailKind::BlobGas,
                        shape,
                        format!("bloque {}: {e}", header.number),
                    )));
                }
            }
            Err(BlobFieldsMissing::Header) => {
                // Post-Cancun el header DEBE traer los dos campos: un bloque
                // que no los declara es inválido, no un bloque con blob gas
                // cero.
                return Err(Rejection::Protocol(Failure::new(
                    FailKind::BlobGas,
                    shape,
                    format!(
                        "bloque {}: header post-Cancun sin `excessBlobGas` y/o `blobGasUsed`",
                        header.number
                    ),
                )));
            }
            Err(BlobFieldsMissing::Parent) => {
                // El padre sin campos de blob es un fixture que no entendimos
                // (o un bloque de transición, fuera de scope): nunca un
                // rechazo.
                return Err(Rejection::Internal(Failure::new(
                    FailKind::Parse,
                    "padre sin campos de blob",
                    format!(
                        "el padre del bloque {} no trae `excessBlobGas`/`blobGasUsed` y el fork \
                         es post-Cancun",
                        header.number
                    ),
                )));
            }
            Err(BlobFieldsMissing::Overflow) => {
                return Err(Rejection::Internal(Failure::new(
                    FailKind::Parse,
                    "overflow contando blobs",
                    format!(
                        "overflow sumando el blob gas de las txs del bloque {}",
                        header.number
                    ),
                )));
            }
        }
    }

    // EIP-4895. Es header y no ejecución: el `withdrawalsRoot` se contrasta
    // contra las withdrawals que el propio bloque trae.
    if let Some(expected) = header.withdrawals_root {
        let root = encode::withdrawals_root(&block.withdrawals.clone().unwrap_or_default());
        if root != expected {
            return Err(Rejection::Protocol(Failure::new(
                FailKind::WithdrawalsRoot,
                shape,
                format!("withdrawalsRoot diverge: esperado {expected}, obtenido {root}"),
            )));
        }
    }

    Ok(())
}

/// Por qué no se pudo armar el cuadro de blob gas. Las tres razones tienen
/// consecuencias DISTINTAS —una es un rechazo, las otras dos son el harness
/// diciendo que no entendió— y por eso son un enum y no un `Option`.
enum BlobFieldsMissing {
    Header,
    Parent,
    Overflow,
}

/// Junta lo que el header declara con lo que las txs del bloque realmente
/// llevan. `GAS_PER_BLOB` sale del motor: dos copias del número serían dos
/// fuentes de verdad.
fn blob_gas_of(
    header: &BlockHeader,
    parent: &BlockHeader,
    block: &TestBlock,
) -> Result<header::BlobGas, BlobFieldsMissing> {
    let (Some(declared_excess), Some(declared_used)) =
        (header.excess_blob_gas, header.blob_gas_used)
    else {
        return Err(BlobFieldsMissing::Header);
    };
    let (Some(parent_excess), Some(parent_used)) = (parent.excess_blob_gas, parent.blob_gas_used)
    else {
        return Err(BlobFieldsMissing::Parent);
    };
    let blobs = u64::try_from(
        block
            .transactions
            .iter()
            .map(|tx| tx.blob_versioned_hashes.len())
            .sum::<usize>(),
    )
    .map_err(|_| BlobFieldsMissing::Overflow)?;
    let computed_used = blobs
        .checked_mul(repo_b_evm::blob::GAS_PER_BLOB)
        .ok_or(BlobFieldsMissing::Overflow)?;
    Ok(header::BlobGas {
        parent_excess,
        parent_used,
        declared_excess,
        declared_used,
        computed_used,
    })
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
struct RunBlock<'a> {
    spec: Spec,
    test: &'a BlockchainTest,
    block: &'a TestBlock,
    header: &'a BlockHeader,
    /// El hash **computado** del padre REAL de la cadena (el head), no el
    /// `parentHash` que el bloque declara ni el `hash` que su header publica: es
    /// la calldata de la system call de EIP-2935. Viaja como `B256` suelto y no
    /// como `&BlockHeader` para que el hash publicado no esté al alcance.
    parent_hash: B256,
    pre: &'a BTreeMap<Address, FixtureAccount>,
    block_hashes: &'a BTreeMap<u64, B256>,
    /// Los headers RLP de los ancestros, por número. Es lo que el witness
    /// necesita para probar un `BLOCKHASH`: la cadena contigua, no el hash.
    chain: &'a BTreeMap<u64, Bytes>,
    /// Si está, el bloque se ejecuta contra ESTE `State` en vez de contra el
    /// pre-state completo. Es lo que permite correr el mismo bloque, con el
    /// mismo código, alimentado solo por un witness — sin una segunda copia del
    /// lifecycle que pudiera divergir de la primera.
    from_witness: Option<&'a dyn State>,
    /// Modo de verificación por witness (`--witness-blocks`).
    witness: bool,
    shape: &'static str,
}

fn run_block(args: &RunBlock<'_>) -> Result<ExecutedBlock, Rejection> {
    let &RunBlock {
        spec,
        test,
        block,
        header,
        parent_hash,
        pre,
        block_hashes,
        // `chain` y `pre` los consume `verify_from_witness` desde `args`.
        chain: _,
        from_witness,
        witness,
        shape,
    } = args;
    // `validate_header` ya garantizó que está: llegar acá sin él sería un
    // desacuerdo entre las dos funciones, no un fixture raro.
    let Some(base_fee) = header.base_fee else {
        return Err(Rejection::Internal(Failure::new(
            FailKind::Parse,
            "header sin baseFeePerGas",
            "el header no trae `baseFeePerGas` y el fork es post-Merge".to_owned(),
        )));
    };
    let env = BlockEnv {
        spec,
        chain_id: test.chain_id,
        number: header.number,
        coinbase: header.coinbase,
        timestamp: header.timestamp,
        gas_limit: header.gas_limit,
        base_fee,
        prevrandao: header.mix_hash,
        blob_excess_gas: header.excess_blob_gas,
        blob_base_fee: None,
        blob_base_fee_update_fraction: None,
    };

    let base = MemoryState::from_pre(pre).with_block_hashes(block_hashes.clone());
    // El grabador queda SIEMPRE en el camino: es transparente por construcción
    // (lo gatea `--record-replay`) y tenerlo puesto es lo que permite armar el
    // witness del bloque sin ejecutarlo dos veces para descubrir qué tocó.
    let recorder = repo_b_witness::RecordingState::new(Box::new(base));
    // El mismo lifecycle, alimentado por uno u otro `State`.
    let state: &dyn State = from_witness.unwrap_or(&recorder);
    let mut vm = OwnVm::new();
    let withdrawals = block.withdrawals.clone().unwrap_or_default();
    vm.begin_block_with_withdrawals(&env, state, withdrawals)
        .map_err(|e| Rejection::from_vm(&e, "begin_block falló"))?;

    // EIP-4788: la system call del beacon root corre ANTES de la primera tx y
    // sus escrituras entran al `stateRoot` del bloque.
    //
    // La ORQUESTA el driver y no `begin_block`, porque el seam `Vm` está
    // vendoreado y `begin_block(env, state)` no lleva el beacon root: el trait
    // expone `system_call_in_block` justamente para que el cliente —el que lee
    // el header— dispare la llamada. El motor ejecuta; el cliente decide
    // cuándo, que es el mismo reparto que hace un cliente stateless real.
    if spec.is_enabled(Spec::Cancun) {
        let Some(beacon_root) = header.parent_beacon_block_root else {
            // Post-Cancun el campo es parte del header: un bloque sin él es
            // inválido, no un bloque con la raíz en cero.
            return Err(Rejection::Protocol(Failure::new(
                FailKind::SystemCall,
                shape,
                format!(
                    "bloque {}: header post-Cancun sin `parentBeaconBlockRoot`",
                    header.number
                ),
            )));
        };
        let outcome = vm
            .system_call_in_block(
                repo_b_evm::BEACON_ROOTS_ADDRESS,
                Bytes::from(beacon_root.0.to_vec()),
            )
            .map_err(|e| Rejection::from_vm(&e, "la system call de EIP-4788 falló"))?;
        // EIP-4788: *"the call must execute to completion"*. En Cancun el
        // corpus no lo ejercita (`SYSTEM_CONTRACT_CALL_FAILED` solo aparece en
        // fixtures de Prague), pero el texto del EIP es explícito y un bloque
        // cuyo system call falla no puede entrar a la cadena.
        if !outcome.result.is_success() {
            return Err(Rejection::Protocol(Failure::new(
                FailKind::SystemCall,
                shape,
                format!(
                    "bloque {}: la system call de EIP-4788 no terminó en éxito: {:?}",
                    header.number, outcome.result
                ),
            )));
        }
    }

    // EIP-2935: el hash del PADRE entra al ring buffer del history contract,
    // también antes de la primera tx. La calldata es el hash COMPUTADO del padre
    // real de la cadena, no el `parentHash` que el bloque declara: un bloque cuyo
    // `parentHash` miente no encadena, y validar eso es otra regla.
    //
    // **A diferencia de 4788, un fallo NO invalida el bloque**: EIP-2935 no
    // trae la cláusula *"must execute to completion"* y `execution-specs` la
    // corre como `process_unchecked_system_transaction`. El corpus no lo
    // discrimina (no hay `SYSTEM_CONTRACT_CALL_FAILED` para 2935), así que la
    // asimetría se sigue del texto de los dos EIPs y se deja escrita.
    if spec.is_enabled(Spec::Prague) {
        vm.system_call_in_block(
            repo_b_evm::HISTORY_STORAGE_ADDRESS,
            Bytes::from(parent_hash.0.to_vec()),
        )
        .map_err(|e| Rejection::from_vm(&e, "la system call de EIP-2935 falló"))?;
    }

    // Un bloque NO puede llevar una tx que el protocolo rechaza. A diferencia
    // de un `state_test` —donde la tx inválida simplemente no se ejecuta—, acá
    // el bloque es inválido PORQUE la contiene.
    for tx in &block.transactions {
        let transaction = build_transaction(tx);
        vm.transact_in_block(&transaction, tx.sender)
            .map_err(|e| Rejection::from_vm(&e, "el bloque lleva una tx que el motor rechaza"))?;
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
            .map_err(|e| Rejection::from_vm(&e, "acreditando las withdrawals"))?;
        let (requests_hash, outputs) = block_requests_hash(&mut vm, &receipts, header, shape)?;
        closing_outputs = outputs;
        // Post-Prague el campo es parte del header: un bloque sin él es
        // inválido, no un bloque sin requests.
        let Some(declared) = header.requests_hash else {
            return Err(Rejection::Protocol(Failure::new(
                FailKind::Requests,
                shape,
                format!(
                    "bloque {}: header post-Prague sin `requestsHash`",
                    header.number
                ),
            )));
        };
        if requests_hash != declared {
            return Err(Rejection::Protocol(Failure::new(
                FailKind::Requests,
                shape,
                format!(
                    "bloque {}: requestsHash declarado {declared}, los requests del bloque dan \
                     {requests_hash}",
                    header.number
                ),
            )));
        }
    }

    let changes = vm
        .finish_block()
        .map_err(|e| Rejection::from_vm(&e, "finish_block falló"))?;
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
        verify_from_witness(args, &env, &recorder.log(), &executed)?;
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
    env: &BlockEnv,
    log: &repo_b_witness::AccessLog,
    completo: &ExecutedBlock,
) -> Result<(), Rejection> {
    // Las claves cuyo cambio altera la forma del trie, juntadas del bloque
    // ENTERO: un bloque tiene varias txs y un solo witness, así que agruparlas
    // por tx dejaría afuera lo que una tx borra y otra vuelve a tocar.
    let shape = crate::witness_build::ShapeChanges::of(&completo.changes, args.pre);
    let witness =
        crate::witness_build::build_block(args.pre, log, args.chain, args.header.number, &shape);
    let root = compute_state_root(args.pre);
    let state = repo_b_witness::WitnessState::new(&witness, root)
        .with_chain(
            &witness,
            args.parent_hash,
            args.header.number.saturating_sub(1),
        )
        .map_err(|e| {
            Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: la cadena de headers no verifica: {e}",
                    args.header.number
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
                    args.header.number, failure.detail
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
                args.header.number
            ),
        )));
    }
    // **El input del guest, por bytes.** Se codifica del lado del host, se
    // decodifica del lado del guest y se ejecuta con SU punto de entrada. Que el
    // resultado tenga que coincidir con el del driver es lo que ata las dos
    // implementaciones del codec: el resultado contra el que se compara **no
    // sale del codec**.
    verify_roundtrip(args, env, &witness, root, completo)?;

    // **El post-state root, recomputado SOLO desde el witness.** Es la mitad
    // del DoD que el harness venía contestando con el estado completo — que es
    // exactamente lo que un guest no tiene.
    let esperado = compute_state_root(&completo.post);
    match state.post_state_root(&completo.changes) {
        Ok(r) if r == esperado => WITNESS_ROOTS.fetch_add(1, Ordering::Relaxed),
        Ok(r) => {
            return Err(Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: el root recomputado desde el witness es {r} y no {esperado}",
                    args.header.number
                ),
            )));
        }
        Err(e) => {
            return Err(Rejection::Internal(Failure::new(
                FailKind::Witness,
                args.shape,
                format!(
                    "bloque {}: no se pudo recomputar el root desde el witness: {e}",
                    args.header.number
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

/// El input del bloque, ida y vuelta por bytes.
fn verify_roundtrip(
    args: &RunBlock<'_>,
    env: &BlockEnv,
    witness: &repo_b_common::witness::ExecutionWitness,
    root: B256,
    completo: &ExecutedBlock,
) -> Result<(), Rejection> {
    let fail =
        |detalle: String| Rejection::Internal(Failure::new(FailKind::Witness, args.shape, detalle));
    let Some(input) = guest_input_of(args, env, witness, root) else {
        // Un bloque cuyo input no se puede armar (tx sin sender recuperable) no
        // es una falla del codec: se saltea y se cuenta aparte.
        ROUNDTRIP_SKIP.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    };
    let bytes = repo_b_guest::codec::encode(&input);
    ROUNDTRIP_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    if let Ok(mut sizes) = ROUNDTRIP_SIZES.lock() {
        sizes.push(bytes.len() as u64);
    }
    let vuelto = repo_b_guest::codec::decode(&bytes).map_err(|e| {
        fail(format!(
            "bloque {}: el input del guest no decodifica: {e:?}",
            args.header.number
        ))
    })?;
    // El round-trip **no se tira**: sigue siendo el gate del codec, y prueba
    // algo que la ejecución no prueba —que ningún campo se pierde en el viaje,
    // incluidos los que este bloque no ejercita.
    if !mismo_input(&input, &vuelto) {
        return Err(fail(format!(
            "bloque {}: el input no sobrevivió el round-trip",
            args.header.number
        )));
    }
    // **Y ahora se EJECUTA desde lo decodificado, por el punto de entrada del
    // guest.** Hasta acá este eje comparaba el input consigo mismo, porque el
    // guest no cubría el lifecycle completo de Prague; ahora sí, y lo que se
    // contrasta es lo que el bloque produjo — el diff **y** los outputs de las
    // system calls de cierre, que son la fuente de dos de los tres tipos de
    // request. El resultado contra el que se compara **no sale del guest**: lo
    // computó el driver con su propio lifecycle.
    let salida = repo_b_guest::run_block(&vuelto.as_input()).map_err(|e| {
        fail(format!(
            "bloque {}: el punto de entrada del guest no pudo ejecutar el bloque: {e:?}",
            args.header.number
        ))
    })?;
    if salida.changes != completo.changes {
        return Err(fail(format!(
            "bloque {}: el guest produjo otro diff que el driver",
            args.header.number
        )));
    }
    if salida.closing_outputs != completo.closing_outputs {
        return Err(fail(format!(
            "bloque {}: el guest produjo otros outputs de system call de cierre: {:?} vs {:?}",
            args.header.number, salida.closing_outputs, completo.closing_outputs
        )));
    }
    if !salida.closing_outputs.is_empty() {
        ROUNDTRIP_CLOSING.fetch_add(1, Ordering::Relaxed);
        // **La auditoría del contraste**: un predeploy que siempre devuelve
        // vacío haría que comparar los outputs pasara por vacuidad. Se cuenta
        // aparte cuántos bloques producen bytes de verdad.
        if salida.closing_outputs.iter().any(|o| !o.is_empty()) {
            ROUNDTRIP_CLOSING_NONEMPTY.fetch_add(1, Ordering::Relaxed);
        }
    }
    ROUNDTRIP_BLOCKS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Arma el input del guest tal como el bloque lo ejecutó.
///
/// **Las system calls van completas y separadas en dos listas**: las de arranque
/// (EIP-4788 desde Cancun, EIP-2935 desde Prague) y las de cierre (EIP-7002 y
/// EIP-7251, desde Prague). El gating por fork es el MISMO que el de la corrida
/// de arriba — si divergiera, el guest ejecutaría otro bloque y la comparación
/// lo diría.
fn guest_input_of(
    args: &RunBlock<'_>,
    env: &BlockEnv,
    witness: &repo_b_common::witness::ExecutionWitness,
    root: B256,
) -> Option<repo_b_guest::codec::OwnedInput> {
    let mut opening_system_calls = Vec::new();
    if args.spec.is_enabled(Spec::Cancun) {
        // Llegar acá sin el campo sería un desacuerdo con `run_block`, que ya
        // rechazó el bloque si faltaba. Se saltea y se cuenta, en vez de
        // inventar una raíz en cero.
        let beacon_root = args.header.parent_beacon_block_root?;
        opening_system_calls.push((
            repo_b_evm::BEACON_ROOTS_ADDRESS,
            Bytes::from(beacon_root.0.to_vec()),
        ));
    }
    if args.spec.is_enabled(Spec::Prague) {
        opening_system_calls.push((
            repo_b_evm::HISTORY_STORAGE_ADDRESS,
            Bytes::from(args.parent_hash.0.to_vec()),
        ));
    }
    let closing_system_calls = if args.spec.is_enabled(Spec::Prague) {
        vec![
            (repo_b_evm::WITHDRAWAL_REQUESTS_ADDRESS, Bytes::new()),
            (repo_b_evm::CONSOLIDATION_REQUESTS_ADDRESS, Bytes::new()),
        ]
    } else {
        Vec::new()
    };
    Some(repo_b_guest::codec::OwnedInput {
        witness: witness.clone(),
        pre_state_root: root,
        parent_hash: args.parent_hash,
        env: env.clone(),
        txs: args
            .block
            .transactions
            .iter()
            .map(build_transaction)
            .collect(),
        withdrawals: args.block.withdrawals.clone().unwrap_or_default(),
        opening_system_calls,
        closing_system_calls,
    })
}

fn mismo_input(a: &repo_b_guest::codec::OwnedInput, b: &repo_b_guest::codec::OwnedInput) -> bool {
    a.witness == b.witness
        && a.pre_state_root == b.pre_state_root
        && a.env == b.env
        && a.txs == b.txs
        && a.withdrawals == b.withdrawals
        && a.parent_hash == b.parent_hash
        && a.opening_system_calls == b.opening_system_calls
        && a.closing_system_calls == b.closing_system_calls
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
pub static ROUNDTRIP_BYTES: AtomicU64 = AtomicU64::new(0);
/// El tamaño del input de CADA bloque. La distribución es el entregable: un
/// promedio no ve la cola, y su p99 sí.
pub static ROUNDTRIP_SIZES: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
/// Bloques cuyo input no se pudo armar. Se cuentan aparte: un salteo silencioso
/// convertiría el gate en un espejo.
pub static ROUNDTRIP_SKIP: AtomicU64 = AtomicU64::new(0);
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
/// A diferencia de 4788 y 2935, estas dos son **checked**: un revert, un halt o
/// un OOG del predeploy invalida el bloque (`execution-specs`:
/// `process_checked_system_transaction`). El corpus SÍ lo ejercita — los tres
/// vectores de `SYSTEM_CONTRACT_CALL_FAILED` del set son de 7002 y 7251.
///
/// **KNOWN.** `execution-specs` además invalida el bloque si el predeploy no
/// tiene código, y eso acá no se distingue: el seam fija que una system call a
/// una cuenta sin código es un success no-op, y redefinirlo está fuera de este
/// slice. Los fixtures que lo ejercitan (`test_system_contract_deployment`) son
/// de forks de transición y quedan fuera del scope.
fn block_requests_hash(
    vm: &mut OwnVm,
    receipts: &[Receipt],
    header: &BlockHeader,
    shape: &'static str,
) -> Result<(B256, Vec<Bytes>), Rejection> {
    let withdrawal =
        checked_system_call(vm, repo_b_evm::WITHDRAWAL_REQUESTS_ADDRESS, header, shape)?;
    let consolidation = checked_system_call(
        vm,
        repo_b_evm::CONSOLIDATION_REQUESTS_ADDRESS,
        header,
        shape,
    )?;
    // El layout del evento de depósito es consenso: un log mal formado del
    // contrato de depósito invalida el bloque, no se saltea.
    let collected = requests::collect(receipts, &withdrawal, &consolidation).map_err(|e| {
        Rejection::Protocol(Failure::new(
            FailKind::DepositLayout,
            shape,
            format!("bloque {}: {e}", header.number),
        ))
    })?;
    Ok((
        requests::requests_hash(&collected),
        vec![withdrawal, consolidation],
    ))
}

/// Una system call cuyo fallo invalida el bloque, y cuyo **output es el dato**.
fn checked_system_call(
    vm: &mut OwnVm,
    to: Address,
    header: &BlockHeader,
    shape: &'static str,
) -> Result<Bytes, Rejection> {
    let outcome = vm
        .system_call_in_block(to, Bytes::new())
        .map_err(|e| Rejection::from_vm(&e, "una system call de EIP-7685 falló"))?;
    match &outcome.result {
        ExecutionResult::Success { output, .. } => Ok(output.clone()),
        other => Err(Rejection::Protocol(Failure::new(
            FailKind::SystemCall,
            shape,
            format!(
                "bloque {}: la system call a {to} no terminó en éxito: {other:?}",
                header.number
            ),
        ))),
    }
}

/// Contrasta TODO lo que el harness computó contra el campo del header.
///
/// El orden importa para el clustering: primero el `stateRoot`, que es la
/// transición de estado (lo que el motor decide), y recién después la
/// maquinaria de encoding del propio harness. Así un bug del motor no se
/// esconde detrás de un bug del encoder ni al revés.
fn contrast(
    header: &BlockHeader,
    block: &TestBlock,
    executed: &ExecutedBlock,
    shape: &'static str,
    expected_state: Option<&BTreeMap<Address, FixtureAccount>>,
) -> Option<Failure> {
    let state_root = compute_state_root(&executed.post);
    if state_root != header.state_root {
        let mut message = format!(
            "state root diverge en el bloque {}: esperado {}, obtenido {state_root}",
            header.number, header.state_root
        );
        // El juez es el root; el `postState` inline solo dice DÓNDE divergió.
        if let Some(expected) = expected_state {
            let diffs = diff_expected(expected, &executed.post);
            if !diffs.is_empty() {
                message.push_str(&format!(" | post-state: {}", diffs.join(" | ")));
            }
        }
        return Some(Failure::new(FailKind::StateRoot, shape, message));
    }
    if executed.gas_used != header.gas_used {
        return Some(Failure::new(
            FailKind::GasUsed,
            shape,
            format!(
                "gasUsed diverge en el bloque {}: esperado {}, obtenido {}",
                header.number, header.gas_used, executed.gas_used
            ),
        ));
    }
    match encode::transactions_root(&block.transactions) {
        Ok(root) if root == header.transactions_trie => {}
        Ok(root) => {
            return Some(Failure::new(
                FailKind::TransactionsTrie,
                shape,
                format!(
                    "transactionsTrie diverge: esperado {}, obtenido {root}",
                    header.transactions_trie
                ),
            ));
        }
        Err(e) => {
            return Some(Failure::new(
                FailKind::TransactionsTrie,
                error_head(&e),
                format!("no se pudo encodear una tx: {e}"),
            ));
        }
    }
    match encode::receipts_root(&block.transactions, &executed.receipts) {
        Ok(root) if root == header.receipt_trie => {}
        Ok(root) => {
            return Some(Failure::new(
                FailKind::ReceiptTrie,
                shape,
                format!(
                    "receiptTrie diverge: esperado {}, obtenido {root}",
                    header.receipt_trie
                ),
            ));
        }
        Err(e) => {
            return Some(Failure::new(
                FailKind::ReceiptTrie,
                error_head(&e),
                format!("no se pudo armar el receiptTrie: {e}"),
            ));
        }
    }
    let bloom = encode::block_bloom(&executed.receipts);
    if bloom != header.bloom {
        return Some(Failure::new(
            FailKind::Bloom,
            shape,
            format!(
                "el bloom del bloque {} no coincide con el header",
                header.number
            ),
        ));
    }
    // El `withdrawalsRoot` NO se contrasta acá: es una regla de header y vive
    // en `validate_header`, que corre antes de ejecutar. Un bloque cuyo
    // `withdrawalsRoot` no cierra es inválido, no un bloque válido que da mal.
    None
}

/// `FixtureTx` → la `Transaction` del motor. El sender ya viene recuperado y
/// la firma se queda afuera: el EVM no la mira (seam de 2.7c).
fn build_transaction(tx: &FixtureTx) -> Transaction {
    Transaction {
        tx_type: tx.tx_type,
        sender: tx.sender,
        nonce: tx.nonce,
        to: tx.to,
        value: tx.value,
        input: tx.data.clone(),
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        access_list: tx.access_list.clone(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas,
        blob_versioned_hashes: tx.blob_versioned_hashes.clone(),
        authorization_list: tx.authorization_list.clone(),
    }
}

/// Recorta un mensaje a su cabeza estable para que sirva de sub-clave de
/// cluster: sin valores concretos que harían de cada caso su propio cluster.
fn error_head(msg: &str) -> String {
    let head = msg.split([':', '(', '{']).next().unwrap_or(msg).trim();
    head.chars().take(60).collect()
}

#[cfg(test)]
mod tests {
    use repo_b_evm::error::{ConsensusError, InternalError};

    use super::*;

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
            Rejection::from_vm(&consensus, "test"),
            Rejection::Protocol(_)
        ));

        let internal = VmError::Internal(InternalError::EvmInternal("motor roto".into()));
        assert!(matches!(
            Rejection::from_vm(&internal, "test"),
            Rejection::Internal(_)
        ));
    }
}
