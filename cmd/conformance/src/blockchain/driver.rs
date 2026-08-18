//! El driver de bloque: genesis → por cada bloque, `begin_block`, las txs,
//! `finish_block` → contraste contra el header.
//!
//! El estado se encadena entre bloques: el post-state de uno es el pre-state
//! del siguiente. Dentro de un bloque lo encadena el motor (`BlockState`); entre
//! bloques lo encadena el driver, que es quien tiene el MPT.

use std::collections::BTreeMap;

use repo_b_common::primitives::{Address, B256};
use repo_b_common::receipt::Receipt;
use repo_b_common::transaction::Transaction;
use repo_b_evm::OwnVm;
use repo_b_evm::error::VmError;
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;

use super::encode;
use super::fixture::{BlockHeader, BlockchainTest, FixtureTx, TestBlock};
use super::header;
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
pub fn run_case(test: &BlockchainTest) -> CaseOutcome {
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

    // `BLOCKHASH` se alimenta de los hashes que el fixture publica en cada
    // header. Recomputarlos desde el RLP del header es 2.9c-5.
    let mut block_hashes = BTreeMap::from([(test.genesis.number, test.genesis.hash)]);
    // El head de la cadena: arranca en el genesis y solo lo mueve un bloque
    // ACEPTADO. Es también el padre del bloque siguiente — un bloque rechazado
    // no puede ser padre de nada.
    let mut head = &test.genesis;
    let mut rejected = Vec::new();

    for (index, block) in test.blocks.iter().enumerate() {
        let shape = shape(test, block);
        let Some(header) = &block.header else {
            return CaseOutcome::Fail(Failure::new(
                FailKind::Parse,
                "bloque sin header",
                "el bloque no trae `blockHeader` ni `rlp_decoded.blockHeader`".to_owned(),
            ));
        };
        // El header se valida ANTES de ejecutar: un bloque cuyo `gasLimit` o
        // `baseFeePerGas` no cierran es inválido por lo que declara, sin que
        // haga falta correr una sola tx.
        let attempt = validate_header(header, head, block, shape)
            .and_then(|()| run_block(spec, test, block, header, &post, &block_hashes, shape));

        match attempt {
            Ok(executed) => {
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
                block_hashes.insert(header.number, header.hash);
                post = executed.post;
                head = header;
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
                            "el bloque {} se rechazó y el estado avanzó igual: esperado {}, \
                             obtenido {root}",
                            header.number, head.state_root
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
    if head.hash != test.last_block_hash {
        return CaseOutcome::Fail(Failure::new(
            FailKind::LastBlockHash,
            "",
            format!(
                "el head quedó en {} y el fixture declara {}",
                head.hash, test.last_block_hash
            ),
        ));
    }

    CaseOutcome::Pass(rejected)
}

/// Las reglas que hacen inválido a un bloque por lo que DECLARA, antes de
/// ejecutar nada. Corren sobre todo bloque, válido o no: excusar el rechazo sin
/// la recíproca sería un comparador tuerto.
fn validate_header(
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

/// Lo que produjo un bloque, antes de contrastarlo contra su header.
struct ExecutedBlock {
    post: BTreeMap<Address, FixtureAccount>,
    receipts: Vec<Receipt>,
    gas_used: u64,
}

#[allow(clippy::too_many_arguments)]
fn run_block(
    spec: Spec,
    test: &BlockchainTest,
    block: &TestBlock,
    header: &BlockHeader,
    pre: &BTreeMap<Address, FixtureAccount>,
    block_hashes: &BTreeMap<u64, B256>,
    shape: &'static str,
) -> Result<ExecutedBlock, Rejection> {
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

    let state = MemoryState::from_pre(pre).with_block_hashes(block_hashes.clone());
    let mut vm = OwnVm::new();
    let withdrawals = block.withdrawals.clone().unwrap_or_default();
    vm.begin_block_with_withdrawals(&env, &state, withdrawals)
        .map_err(|e| Rejection::from_vm(&e, "begin_block falló"))?;

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
    let changes = vm
        .finish_block()
        .map_err(|e| Rejection::from_vm(&e, "finish_block falló"))?;
    let post = apply_updates(pre, &changes)
        .map_err(|e| Rejection::Internal(Failure::new(FailKind::PostStateApply, shape, e)))?;

    Ok(ExecutedBlock {
        post,
        receipts,
        gas_used,
    })
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
