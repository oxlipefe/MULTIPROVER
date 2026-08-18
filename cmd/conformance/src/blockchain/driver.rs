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
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_evm::vm::Vm;

use super::encode;
use super::fixture::{BlockHeader, BlockchainTest, FixtureTx, TestBlock};
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
    /// El fixture declara el bloque INVÁLIDO y exige que el cliente lo
    /// rechace. Es el scope de 2.9c-2: hoy no hay validación de bloque, así que
    /// no se ejecuta y se cuenta como falla — excusarlo sería inventar
    /// cobertura.
    InvalidBlock,
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
}

impl FailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::InvalidBlock => "invalid_block",
            Self::GenesisRoot => "genesis_root",
            Self::ExecuteError => "execute_error",
            Self::PostStateApply => "post_state_apply",
            Self::StateRoot => "state_root",
            Self::GasUsed => "gas_used",
            Self::TransactionsTrie => "transactions_trie",
            Self::ReceiptTrie => "receipt_trie",
            Self::Bloom => "bloom",
            Self::WithdrawalsRoot => "withdrawals_root",
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

#[derive(Debug)]
pub enum CaseOutcome {
    Pass,
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
    let last_number = test
        .blocks
        .last()
        .and_then(|block| block.header.as_ref())
        .map_or(test.genesis.number, |header| header.number);

    for block in &test.blocks {
        let shape = shape(test, block);
        if let Some(exception) = &block.expect_exception {
            return CaseOutcome::Fail(Failure::new(
                FailKind::InvalidBlock,
                shape,
                format!(
                    "el fixture declara el bloque inválido (`{exception}`) y todavía no hay \
                     validación de bloque: 2.9c-2"
                ),
            ));
        }
        let Some(header) = &block.header else {
            return CaseOutcome::Fail(Failure::new(
                FailKind::Parse,
                "bloque sin header",
                "el bloque no trae `blockHeader` ni `expectException`".to_owned(),
            ));
        };
        match run_block(spec, test, block, header, &post, &block_hashes) {
            Ok(executed) => {
                block_hashes.insert(header.number, header.hash);
                // El `postState` inline solo enriquece el diagnóstico del
                // ÚLTIMO bloque: es el estado final de la cadena, no el de cada
                // bloque intermedio.
                let is_last = header.number == last_number;
                let expected_state = is_last.then_some(test.post_state.as_ref()).flatten();
                if let Some(failure) = contrast(header, block, &executed, shape, expected_state) {
                    return CaseOutcome::Fail(failure);
                }
                post = executed.post;
            }
            Err(failure) => return CaseOutcome::Fail(failure),
        }
    }

    CaseOutcome::Pass
}

/// Lo que produjo un bloque, antes de contrastarlo contra su header.
struct ExecutedBlock {
    post: BTreeMap<Address, FixtureAccount>,
    receipts: Vec<Receipt>,
    gas_used: u64,
}

fn run_block(
    spec: Spec,
    test: &BlockchainTest,
    block: &TestBlock,
    header: &BlockHeader,
    pre: &BTreeMap<Address, FixtureAccount>,
    block_hashes: &BTreeMap<u64, B256>,
) -> Result<ExecutedBlock, Failure> {
    let shape = shape(test, block);
    // Post-London el `baseFeePerGas` es obligatorio, y todo fork en scope acá
    // es post-Merge: un header sin él es un fixture que no entendimos, no un
    // bloque con base fee cero.
    let Some(base_fee) = header.base_fee else {
        return Err(Failure::new(
            FailKind::Parse,
            "header sin baseFeePerGas",
            "el header no trae `baseFeePerGas` y el fork es post-Merge".to_owned(),
        ));
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
        .map_err(|e| {
            Failure::new(
                FailKind::ExecuteError,
                error_head(&format!("{e}")),
                format!("begin_block falló: {e}"),
            )
        })?;

    for tx in &block.transactions {
        let transaction = build_transaction(tx);
        vm.transact_in_block(&transaction, tx.sender).map_err(|e| {
            Failure::new(
                FailKind::ExecuteError,
                error_head(&format!("{e}")),
                format!("el bloque es válido para el fixture y el motor rechazó una tx: {e}"),
            )
        })?;
    }

    let receipts = vm.receipts().to_vec();
    let gas_used = receipts
        .last()
        .map_or(0, |receipt| receipt.cumulative_gas_used);
    let changes = vm.finish_block().map_err(|e| {
        Failure::new(
            FailKind::ExecuteError,
            error_head(&format!("{e}")),
            format!("finish_block falló: {e}"),
        )
    })?;
    let post = apply_updates(pre, &changes)
        .map_err(|e| Failure::new(FailKind::PostStateApply, shape, e))?;

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
    if let Some(expected) = header.withdrawals_root {
        let root = encode::withdrawals_root(&block.withdrawals.clone().unwrap_or_default());
        if root != expected {
            return Some(Failure::new(
                FailKind::WithdrawalsRoot,
                shape,
                format!("withdrawalsRoot diverge: esperado {expected}, obtenido {root}"),
            ));
        }
    }
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
