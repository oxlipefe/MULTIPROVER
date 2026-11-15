//! `repo-b-guest` — lo que corre **adentro** de la zkVM.
//!
//! Es el único crate del árbol que produce un **ELF**, y esa es toda su razón
//! de existir. Hasta acá el motor se verificaba sobre `rlib`s, y un `rlib` no
//! contesta la pregunta que importa: *¿qué código llega de verdad al binario?*
//! El código no-genérico de una dependencia vive en su propio `rlib` y el
//! linker lo descarta **solo si nadie lo llama** — o sea que sobre `rlib`s
//! "esto no llega al guest" es una **inferencia sobre el descarte del linker**,
//! y sobre un ELF es un **hecho**.
//!
//! **Agnóstico de backend, a propósito.** No hay macro de entrada de ninguna
//! zkVM acá: el punto de entrada es una función de Rust y `_start` es un
//! símbolo pelado. Lo que cambia por backend es el arranque, no esto.
//!
//! # El guest es el cliente que valida
//!
//! El input de un bloque es el bloque **tal como viaja** más su witness
//! (`codec::BlockInput`). Antes de ejecutar, el guest valida el header contra
//! su padre —que es `headers[0]` del witness, obligatorio— y el cuerpo contra
//! el header (`transactionsRoot`, `withdrawalsRoot`, ommers, blob gas, el tope
//! de EIP-7934). Después de ejecutar, todo lo ejecutado contra el header
//! (`stateRoot`, `gasUsed`, `receiptsRoot`, bloom, `requestsHash`). Las reglas
//! son las de `repo-b-block`, el MISMO crate que el harness corre contra el
//! corpus de la EF: no hay una segunda implementación acá.
//!
//! Lo que antes viajaba en el input y no estaba atado a nada ahora se
//! **deriva**: el `env` del header, el `pre_state_root` del padre, y las system
//! calls de las constantes del fork y de campos del header. Un bloque inválido
//! no produce journal, y sin journal no hay prueba.
//!
//! **Qué NO hace, dicho acá y no escondido:**
//!
//! 1. **No conoce el reloj de activación de los forks.** El fork viaja en el
//!    input y en el journal, y el guest exige que el header tenga los campos de
//!    ese fork; que el `timestamp` del bloque corresponda a ese fork lo
//!    contrasta quien consume la prueba.
//! 2. **No enforcea el *"must execute to completion"* de EIP-4788.** Las
//!    llamadas de arranque se corren *unchecked*, que es lo que
//!    `execution-specs` hace con 2935 y con el system call en general; el texto
//!    de EIP-4788 pide además que la suya no falle.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod codec;
pub mod journal;
pub mod kat;
pub mod signature;

use alloc::vec::Vec;

use repo_b_block::requests::{collect_requests, requests_hash};
use repo_b_block::roots::{block_logs_bloom, receipts_root};
use repo_b_block::{PostExecution, validate_post_execution};
use repo_b_common::primitives::{Address, B256, Bytes};
use repo_b_common::receipt::Receipt;
use repo_b_common::spec::Spec;
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_common::withdrawal::Withdrawal;
use repo_b_common::witness::ExecutionWitness;
use repo_b_evm::result::ExecutionResult;
use repo_b_evm::types::BlockEnv;
use repo_b_evm::{OwnVm, StateChanges, Vm};
use repo_b_witness::WitnessState;

pub use ere_platform_core::Platform;
pub use repo_b_block::{self as block, BlockError, Header};

use crate::codec::{BlockInput, TxInput};
use crate::journal::{Journal, Mode};
use crate::signature::SignedTransaction;

/// El lifecycle de un bloque sobre un witness, **ya resuelto**: qué `env`, qué
/// system calls, qué txs.
///
/// **No es el input del guest.** El input es `codec::BlockInput`, del que esto
/// se deriva después de validar el bloque ([`CheckedBlock::lifecycle`]); acá
/// llega armado por el propio guest, nunca por bytes externos. Existe como tipo
/// aparte porque el lifecycle se prueba solo, con un pre-state armado a mano.
pub struct GuestInput<'a> {
    /// Los pre-images: nodos de trie, códigos y la cadena de headers.
    pub witness: &'a ExecutionWitness,
    /// El ancla. Toda lectura se verifica caminando el trie desde acá, así que
    /// un witness que no corresponda a este root no puede servir nada.
    pub pre_state_root: B256,
    /// El `parentHash` del bloque que se ejecuta: el ancla de la cadena de
    /// headers que prueba los `BLOCKHASH`.
    ///
    /// **Sin esto los headers del witness no se pueden verificar.** Lo que
    /// prueba un header es encadenar cada uno con el `parent_hash` del anterior
    /// desde un ancla externa.
    pub parent_hash: B256,
    pub env: BlockEnv,
    /// **Los envelopes firmados**, sin sender: quién firmó sale de la firma.
    pub txs: &'a [SignedTransaction],
    pub withdrawals: Vec<Withdrawal>,
    /// System calls del **arranque** del bloque (EIP-4788, EIP-2935), en orden.
    pub opening_system_calls: &'a [(Address, Bytes)],
    /// System calls del **cierre** del bloque (EIP-7002, EIP-7251), en orden.
    ///
    /// Campo aparte y no un flag adentro de la lista de arriba: dos campos
    /// hacen irrepresentable pedir que una llamada de cierre corra al arrancar.
    ///
    /// Corren **después** del settle de withdrawals y antes de cerrar, porque
    /// su output es la fuente de dos de los tres tipos de request de EIP-7685 y
    /// esos requests se derivan del estado que las withdrawals ya dejaron.
    pub closing_system_calls: &'a [(Address, Bytes)],
}

/// Lo que la ejecución de un bloque produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOutput {
    pub changes: StateChanges,
    /// Los outputs crudos de `closing_system_calls`, **en el mismo orden**. Son
    /// la fuente de dos de los tres tipos de request de EIP-7685.
    pub closing_outputs: Vec<Bytes>,
    /// Un receipt por tx ejecutada: de acá salen `gasUsed`, `receiptsRoot`, el
    /// bloom y los depósitos de EIP-6110.
    pub receipts: Vec<Receipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestError {
    /// El input decodifica y le falta algo que el guest exige (el padre).
    Input(&'static str),
    /// El bloque viola una regla de validez: del header contra el padre, del
    /// cuerpo contra el header o de lo ejecutado contra el header.
    Block(BlockError),
    /// El motor rechazó el bloque. Se conserva el texto porque distinguir un
    /// rechazo de protocolo de un error interno es la diferencia entre un
    /// bloque inválido y un bug.
    Vm(alloc::string::String),
    /// La cadena de headers del witness no encadena desde el `parent_hash`.
    /// Fail-closed: sin cadena verificada no se sirve un `BLOCKHASH`.
    Chain(alloc::string::String),
    /// El witness no alcanza para recomputar el post-state root.
    Witness(alloc::string::String),
    /// Una system call de **cierre** no terminó en éxito ⇒ el bloque es
    /// inválido (`execution-specs::process_checked_system_transaction`).
    ClosingSystemCall(alloc::string::String),
    /// Un envelope no decodifica o su firma no produce un remitente.
    /// **Invalida el bloque**: ejecutarlo con cualquier otro sender sería
    /// exactamente la mentira que este camino existe para impedir.
    Signature(alloc::string::String),
}

/// Un bloque decodificado de sus bytes y **validado antes de ejecutar**: el
/// header contra el padre y el cuerpo contra el header. Es lo único de lo que
/// se puede derivar un lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedBlock {
    pub spec: Spec,
    pub chain_id: u64,
    pub header: Header,
    /// `keccak(rlp(header))`, computado acá.
    pub block_hash: B256,
    /// `headers[0]` del witness, decodificado. Su hash es `header.parent_hash`
    /// (lo exige `validate_header`).
    pub parent: Header,
    pub txs: Vec<SignedTransaction>,
    pub withdrawals: Vec<Withdrawal>,
}

/// Las system calls de un bloque, **derivadas** del fork y del header.
pub struct SystemCalls {
    pub opening: Vec<(Address, Bytes)>,
    pub closing: Vec<(Address, Bytes)>,
}

impl CheckedBlock {
    /// El `env` que el motor ve, sacado del header. El `blob_base_fee` lo
    /// deriva el motor del `excessBlobGas`.
    ///
    /// # Errors
    /// Si el header no trae `baseFeePerGas`. Inalcanzable sobre un bloque
    /// validado (todo fork en scope lo exige), y por eso un error y no un cero.
    pub fn env(&self) -> Result<BlockEnv, GuestError> {
        let base_fee = self
            .header
            .base_fee_per_gas
            .ok_or(GuestError::Input("un header validado sin baseFeePerGas"))?;
        Ok(BlockEnv {
            spec: self.spec,
            chain_id: self.chain_id,
            number: self.header.number,
            coinbase: self.header.beneficiary,
            timestamp: self.header.timestamp,
            gas_limit: self.header.gas_limit,
            base_fee,
            prevrandao: self.header.mix_hash,
            blob_excess_gas: self.header.excess_blob_gas,
            blob_base_fee: None,
            blob_base_fee_update_fraction: None,
        })
    }

    /// Las system calls del bloque. **Las direcciones son constantes del fork
    /// y la calldata sale del header**: EIP-4788 (desde Cancun) con el
    /// `parentBeaconBlockRoot`, EIP-2935 (desde Prague) con el `parentHash`, y
    /// las de cierre de EIP-7002 y EIP-7251 (desde Prague), sin calldata.
    ///
    /// # Errors
    /// Un header de Cancun+ sin `parentBeaconBlockRoot`. Inalcanzable sobre un
    /// bloque validado; una raíz en cero sería inventarla.
    pub fn system_calls(&self) -> Result<SystemCalls, GuestError> {
        let mut opening = Vec::new();
        if self.spec.is_enabled(Spec::Cancun) {
            let beacon_root = self
                .header
                .parent_beacon_block_root
                .ok_or(GuestError::Input(
                    "un header validado de Cancun sin parentBeaconBlockRoot",
                ))?;
            opening.push((
                repo_b_evm::BEACON_ROOTS_ADDRESS,
                Bytes::copy_from_slice(beacon_root.as_slice()),
            ));
        }
        let mut closing = Vec::new();
        if self.spec.is_enabled(Spec::Prague) {
            opening.push((
                repo_b_evm::HISTORY_STORAGE_ADDRESS,
                Bytes::copy_from_slice(self.header.parent_hash.as_slice()),
            ));
            closing.push((repo_b_evm::WITHDRAWAL_REQUESTS_ADDRESS, Bytes::new()));
            closing.push((repo_b_evm::CONSOLIDATION_REQUESTS_ADDRESS, Bytes::new()));
        }
        Ok(SystemCalls { opening, closing })
    }

    /// El lifecycle del bloque sobre su witness. El `pre_state_root` es el
    /// `stateRoot` del padre, y la cadena de headers se ancla en el
    /// `parentHash` del header validado.
    ///
    /// # Errors
    /// Ver [`CheckedBlock::env`].
    pub fn lifecycle<'a>(
        &'a self,
        witness: &'a ExecutionWitness,
        calls: &'a SystemCalls,
    ) -> Result<GuestInput<'a>, GuestError> {
        Ok(GuestInput {
            witness,
            pre_state_root: self.parent.state_root,
            parent_hash: self.header.parent_hash,
            env: self.env()?,
            txs: &self.txs,
            withdrawals: self.withdrawals.clone(),
            opening_system_calls: &calls.opening,
            closing_system_calls: &calls.closing,
        })
    }

    /// El journal de lo que este bloque afirma **sin ejecutarlo**: quién es,
    /// sobre qué padre, en qué cadena y fork, y desde qué estado.
    #[must_use]
    pub const fn identity(&self, mode: Mode) -> Journal {
        Journal {
            mode,
            chain_id: self.chain_id,
            fork: Some(self.spec),
            block_hash: self.block_hash,
            parent_hash: self.header.parent_hash,
            pre_state_root: self.parent.state_root,
            post_state_root: B256::ZERO,
            output_digest: B256::ZERO,
        }
    }
}

/// `GAS_PER_BLOB ×` los blobs que suman las txs. `None` si desborda.
fn blob_gas_of(txs: &[SignedTransaction]) -> Option<u64> {
    let blobs = txs.iter().try_fold(0usize, |acc, tx| {
        acc.checked_add(tx.payload().blob_versioned_hashes.len())
    })?;
    u64::try_from(blobs)
        .ok()?
        .checked_mul(repo_b_evm::blob::GAS_PER_BLOB)
}

/// **Decodifica el bloque y lo valida antes de ejecutarlo.**
///
/// El orden es el del harness, para que un bloque que viola dos reglas se
/// rechace por la misma: el tope de EIP-7934, el header contra el padre (que
/// empieza por los campos del fork), la forma del cuerpo, los ommers, el blob
/// gas, el `withdrawalsRoot` y el `transactionsRoot`. Los envelopes se
/// decodifican después de validar el header y antes del blob gas, que los
/// necesita.
///
/// # Errors
/// `GuestError::Block` si una regla falla; `GuestError::Input` si el witness
/// no trae el padre; `GuestError::Signature` si un envelope no decodifica.
pub fn check_block(input: &BlockInput) -> Result<CheckedBlock, GuestError> {
    let spec = input.fork;
    let block = repo_b_block::decode_block(&input.block).map_err(GuestError::Block)?;
    repo_b_block::check_block_rlp_size(spec, input.block.len()).map_err(GuestError::Block)?;
    let parent_raw = input
        .witness
        .headers
        .first()
        .ok_or(GuestError::Input("el witness no trae el header del padre"))?;
    let parent = Header::decode_exact(parent_raw).map_err(GuestError::Block)?;
    let header = block.header.clone();
    repo_b_block::validate_header(&header, &parent, spec).map_err(GuestError::Block)?;
    repo_b_block::check_body_fields(&block, spec).map_err(GuestError::Block)?;
    repo_b_block::check_ommers(block.ommers).map_err(GuestError::Block)?;

    let mut txs = Vec::with_capacity(block.transactions.len());
    for (i, raw) in block.transactions.iter().enumerate() {
        txs.push(
            signature::decode_2718(raw)
                .map_err(|e| GuestError::Signature(alloc::format!("tx {i}: {}", e.0)))?,
        );
    }
    if spec.is_enabled(Spec::Cancun) {
        let used = blob_gas_of(&txs).ok_or(GuestError::Input("overflow sumando el blob gas"))?;
        repo_b_block::check_blob_gas_used(&header, used, spec).map_err(GuestError::Block)?;
    }
    let withdrawals = block.withdrawals.clone().unwrap_or_default();
    repo_b_block::check_withdrawals_root(&header, &withdrawals).map_err(GuestError::Block)?;
    repo_b_block::check_transactions_root(&header, &block.transactions)
        .map_err(GuestError::Block)?;

    Ok(CheckedBlock {
        spec,
        chain_id: input.chain_id,
        block_hash: header.hash(),
        header,
        parent,
        txs,
        withdrawals,
    })
}

/// **Lo ejecutado contra el header**: el `requestsHash` (Prague+), y después
/// `stateRoot`, `gasUsed`, `receiptsRoot` y bloom. Devuelve el post-state root,
/// que a esta altura es el `stateRoot` del header.
fn check_post(
    checked: &CheckedBlock,
    state: &WitnessState,
    txs: &[Transaction],
    salida: &BlockOutput,
) -> Result<B256, GuestError> {
    let spec = checked.spec;
    if spec.is_enabled(Spec::Prague) {
        let [withdrawal, consolidation] = salida.closing_outputs.as_slice() else {
            return Err(GuestError::Input(
                "un bloque de Prague sin las dos system calls de cierre",
            ));
        };
        let requests = collect_requests(&salida.receipts, withdrawal, consolidation)
            .map_err(GuestError::Block)?;
        repo_b_block::check_requests_hash(&checked.header, requests_hash(&requests), spec)
            .map_err(GuestError::Block)?;
    }
    let state_root = state
        .post_state_root(&salida.changes)
        .map_err(|e| GuestError::Witness(alloc::format!("{e}")))?;
    let tx_types: Vec<TxType> = txs.iter().map(|tx| tx.tx_type).collect();
    let executed = PostExecution {
        state_root,
        gas_used: salida
            .receipts
            .last()
            .map_or(0, |receipt| receipt.cumulative_gas_used),
        receipts_root: receipts_root(&tx_types, &salida.receipts).map_err(GuestError::Block)?,
        logs_bloom: block_logs_bloom(&salida.receipts),
    };
    validate_post_execution(&checked.header, &executed).map_err(GuestError::Block)?;
    Ok(state_root)
}

/// **El camino de un bloque, por modo**: valida, recupera, construye el
/// estado, ejecuta y valida lo ejecutado. Cada modo ablacionado corta en un
/// prefijo de esto; ver `journal::Mode`.
///
/// # Errors
/// El primer rechazo, tipado. Un modo que no es de bloque es
/// `GuestError::Input`.
pub fn run_block_input(mode: Mode, input: &BlockInput) -> Result<Journal, GuestError> {
    if matches!(mode, Mode::Kat | Mode::Nop | Mode::StateTest) {
        return Err(GuestError::Input("el modo no ejecuta un bloque"));
    }
    let checked = check_block(input)?;
    let identity = checked.identity(mode);
    if mode == Mode::DecodeOnly {
        return Ok(identity);
    }
    let calls = checked.system_calls()?;
    let lifecycle = checked.lifecycle(&input.witness, &calls)?;
    // **La recuperación va acá, antes de todo lo demás.** El peldaño propio la
    // aísla: `Recover − DecodeOnly` es lo que cuesta la criptografía de firma.
    let txs = recover_senders(&lifecycle)?;
    if mode == Mode::Recover {
        core::hint::black_box(&txs);
        return Ok(identity);
    }
    let state = build_state(&lifecycle)?;
    if mode == Mode::StateOnly {
        core::hint::black_box(&state);
        return Ok(identity);
    }
    let salida = run_on(&state, &lifecycle, &txs, mode.runs_txs())?;
    let output_digest = digest_of(&salida);
    if mode != Mode::Full {
        return Ok(Journal {
            output_digest,
            ..identity
        });
    }
    let post_state_root = check_post(&checked, &state, &txs, &salida)?;
    Ok(Journal {
        post_state_root,
        output_digest,
        ..identity
    })
}

/// **Txs sueltas sobre un pre-state declarado** (`Mode::StateTest`). Sin
/// header, sin padre, sin system calls ni withdrawals: el lifecycle de un
/// `state_test`. El journal no nombra ningún bloque.
///
/// # Errors
/// El primer rechazo, tipado.
pub fn run_tx_input(input: &TxInput) -> Result<Journal, GuestError> {
    let lifecycle = GuestInput {
        witness: &input.witness,
        pre_state_root: input.pre_state_root,
        parent_hash: B256::ZERO,
        env: input.env.clone(),
        txs: &input.txs,
        withdrawals: Vec::new(),
        opening_system_calls: &[],
        closing_system_calls: &[],
    };
    let txs = recover_senders(&lifecycle)?;
    let state = build_state(&lifecycle)?;
    let salida = run_on(&state, &lifecycle, &txs, true)?;
    let post_state_root = state
        .post_state_root(&salida.changes)
        .map_err(|e| GuestError::Witness(alloc::format!("{e}")))?;
    Ok(Journal {
        mode: Mode::StateTest,
        chain_id: input.env.chain_id,
        fork: Some(input.env.spec),
        block_hash: B256::ZERO,
        parent_hash: B256::ZERO,
        pre_state_root: input.pre_state_root,
        post_state_root,
        output_digest: digest_of(&salida),
    })
}

/// Ejecuta el lifecycle **solo desde el witness** y devuelve lo que produjo.
///
/// Es el lifecycle completo: apertura del bloque con sus withdrawals, las
/// system calls de arranque, las txs en orden, el settle de withdrawals, las
/// system calls de cierre —cuyo output es el dato— y el cierre. **No valida el
/// bloque**: eso es [`run_block_input`], que deriva este input de un bloque
/// validado.
///
/// **La asimetría entre arranque y cierre la fija el texto de cada EIP**, no una
/// preferencia: 4788 y 2935 se corren *unchecked* (`execution-specs`), mientras
/// que 7002 y 7251 son *checked* y un revert, un halt o un OOG del predeploy
/// **invalida el bloque**.
///
/// # Errors
/// `GuestError::Vm` si el motor rechaza el bloque o si el witness no alcanza
/// para una lectura — fail-closed a propósito. `GuestError::Chain` si la cadena
/// de headers no verifica, y `GuestError::ClosingSystemCall` si una llamada de
/// cierre no terminó en éxito.
pub fn run_block(input: &GuestInput<'_>) -> Result<BlockOutput, GuestError> {
    let state = build_state(input)?;
    let txs = recover_senders(input)?;
    run_on(&state, input, &txs, true)
}

/// **Deriva el remitente de cada tx del bloque.** Es el paso que convierte un
/// envelope firmado en una tx ejecutable, y el único lugar del guest donde
/// aparece una dirección de remitente.
///
/// # Errors
/// `GuestError::Signature` si alguna firma no recupera. Fail-closed: no hay
/// "sender por defecto".
pub fn recover_senders(input: &GuestInput<'_>) -> Result<Vec<Transaction>, GuestError> {
    let mut out = Vec::with_capacity(input.txs.len());
    for (i, tx) in input.txs.iter().enumerate() {
        out.push(
            tx.recover(input.env.chain_id)
                .map_err(|e| GuestError::Signature(alloc::format!("tx {i}: {}", e.0)))?,
        );
    }
    Ok(out)
}

/// Construye el `WitnessState` del bloque: indexa los nodos del witness por su
/// propio hash y verifica la cadena de headers contra el ancla.
///
/// **Es una pieza aparte porque es una pieza MEDIBLE**: el desglose de ciclos
/// se produce restando corridas con piezas ablacionadas.
fn build_state(input: &GuestInput<'_>) -> Result<WitnessState, GuestError> {
    WitnessState::new(input.witness, input.pre_state_root)
        // El número del padre NO se lee de los headers: si la cadena encadena
        // desde el ancla, la posición `i` **es** el bloque `number - 1 - i`.
        .with_chain(
            input.witness,
            input.parent_hash,
            input.env.number.saturating_sub(1),
        )
        .map_err(|e| GuestError::Chain(alloc::format!("{e}")))
}

/// El lifecycle del bloque sobre un estado ya construido.
///
/// `run_txs` existe **solo** para la medición por diferencia: con `false` corre
/// el mismo lifecycle sin las transacciones. El resultado de una corrida así
/// **no es el bloque** —produce otro diff— y por eso el modo viaja adentro del
/// journal público: ver `journal::Mode`.
fn run_on(
    state: &WitnessState,
    input: &GuestInput<'_>,
    txs: &[Transaction],
    run_txs: bool,
) -> Result<BlockOutput, GuestError> {
    let mut vm = OwnVm::new();

    let fail = |e: repo_b_evm::error::VmError| GuestError::Vm(alloc::format!("{e}"));

    vm.begin_block_with_withdrawals(&input.env, state, input.withdrawals.clone())
        .map_err(fail)?;
    for (to, data) in input.opening_system_calls {
        // *Unchecked*: el resultado no se mira. Ver el doc de `run_block`.
        vm.system_call_in_block(*to, data.clone()).map_err(fail)?;
    }
    if run_txs {
        for tx in txs {
            vm.transact_in_block(tx, tx.sender).map_err(fail)?;
        }
    }
    let receipts = vm.receipts().to_vec();
    // Antes de las de cierre: el protocolo acredita las withdrawals después de
    // las txs, y las system calls de EIP-7685 tienen que ver ese estado.
    vm.settle_withdrawals_in_block().map_err(fail)?;

    let mut closing_outputs = Vec::with_capacity(input.closing_system_calls.len());
    for (to, data) in input.closing_system_calls {
        let outcome = vm.system_call_in_block(*to, data.clone()).map_err(fail)?;
        match outcome.result {
            ExecutionResult::Success { output, .. } => closing_outputs.push(output),
            otro => {
                return Err(GuestError::ClosingSystemCall(alloc::format!(
                    "la system call de cierre a {to} no terminó en éxito: {otro:?}"
                )));
            }
        }
    }

    let changes = vm.finish_block().map_err(fail)?;
    Ok(BlockOutput {
        changes,
        closing_outputs,
        receipts,
    })
}

/// **La aritmética del bump allocator, fuera del `unsafe` y testeable.**
///
/// Vivía adentro del `unsafe impl GlobalAlloc`, que está detrás de
/// `cfg(target_os = "none")` — o sea que el único código `unsafe` del repo
/// tenía además cero tests y era imposible escribirlos. Acá es una función pura
/// que el host prueba, y del otro lado queda solo la entrega del puntero.
///
/// Devuelve `(offset, siguiente)` o `None` si no entra. `align` es potencia de
/// dos por contrato de `Layout`, pero el redondeo hacia arriba igual puede
/// desbordar con un tamaño hostil, así que va con `checked_*`.
#[must_use]
pub fn reservar(actual: usize, align: usize, size: usize, arena: usize) -> Option<(usize, usize)> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }
    let alineado = actual.checked_add(align.saturating_sub(1))? & !(align.saturating_sub(1));
    let fin = alineado.checked_add(size)?;
    if fin > arena {
        return None;
    }
    Some((alineado, fin))
}

/// El digest de lo que la ejecución produjo: el diff y los outputs de las
/// system calls de cierre, **sin los receipts** (los compromete el header).
///
/// **No es el post-state root**: es un resumen del diff que no pasa por el
/// trie. En `Full` está implicado por el `block_hash` —el guest validó el
/// `stateRoot` y el `requestsHash` del header— y se publica igual porque el
/// host lo computa del diff que produjo con el estado completo, que es un
/// contraste que no comparte el trie con el guest; y porque es lo único que
/// publican los peldaños ablacionados que ejecutan sin validar.
///
/// El largo de cada output entra al digest: sin él, dos outputs concatenados
/// distintos darían los mismos bytes.
#[must_use]
pub fn digest_of(output: &BlockOutput) -> B256 {
    use repo_b_common::primitives::keccak256;
    let mut bytes = Vec::new();
    for update in &output.changes {
        bytes.extend_from_slice(update.address.as_slice());
        bytes.push(u8::from(update.destroyed));
        if let Some(nonce) = update.nonce {
            bytes.extend_from_slice(&nonce.to_be_bytes());
        }
        if let Some(balance) = update.balance {
            bytes.extend_from_slice(&balance.to_be_bytes::<32>());
        }
        for (key, value) in &update.storage {
            bytes.extend_from_slice(&key.to_be_bytes::<32>());
            bytes.extend_from_slice(&value.to_be_bytes::<32>());
        }
    }
    for output in &output.closing_outputs {
        // El largo entra al digest: sin él, dos outputs concatenados distintos
        // darían los mismos bytes.
        bytes.extend_from_slice(&(output.len() as u64).to_be_bytes());
        bytes.extend_from_slice(output.as_ref());
    }
    keccak256(&bytes)
}

/// El punto de entrada genérico: **lo que corre adentro de cualquier zkVM**.
///
/// # Por qué genérico sobre `Platform`
///
/// No hay un ELF para todos los backends: el guest concreto **nombra** el suyo
/// (`ere-platform-sp1` exige `sp1_zkvm::entrypoint!`). Lo agnóstico es la
/// lógica, y esta función es esa lógica. Cada backend es un crate hoja de tres
/// líneas que instancia esto con su `Platform`; el ELF sin backend —el del ABI
/// estándar de `zkvm-standards`, que sostiene la cadena de evidencia de floats
/// e ISA— es una plataforma más y no un camino aparte.
///
/// # El input entra por `Platform::read_input`, y su primer byte es el modo
///
/// El byte de modo va **afuera** del formato del bloque a propósito: el codec
/// describe un bloque de Ethereum y el modo describe qué hace el guest con él.
/// Mezclarlos obligaría a tocar el formato de consenso para poder medir.
///
/// # Fail-closed, y ruidoso
///
/// Cualquier error —input vacío, modo desconocido, witness insuficiente, el
/// motor rechazando el bloque— **panickea**. Adentro de una zkVM un panic es
/// una ejecución que no se puede probar, que es exactamente lo que corresponde:
/// lo peligroso sería publicar un journal en ceros, porque eso es una
/// afirmación bien formada sobre un bloque que nunca se ejecutó.
///
/// # Panics
///
/// Ver arriba: es el modo de falla elegido, no un descuido.
pub fn entry<P: Platform>() {
    let raw = P::read_input();
    let journal = run_bytes(&raw).unwrap_or_else(|e| panic!("{}", e.0));
    publish::<P>(&journal.encode());
}
/// Del buffer crudo al journal. Separado de `entry` porque **se testea en el
/// host**: `entry` necesita una `Platform` y esto no.
///
/// # Errors
/// Devuelve el motivo del rechazo. Nunca un journal a medio llenar.
pub fn run_bytes(raw: &[u8]) -> Result<Journal, EntryError> {
    let Some((modo, cuerpo)) = raw.split_first() else {
        return Err(EntryError("el input está vacío: no hay ni byte de modo"));
    };
    let Some(mode) = Mode::from_byte(*modo) else {
        return Err(EntryError("byte de modo desconocido"));
    };
    match mode {
        Mode::Kat => {
            // **Antes que nada, y sin tocar el cuerpo.** El KAT contesta si la
            // aritmética de este ELF es correcta; hacerlo depender de
            // decodificar un input lo ataría a una pieza que puede estar rota.
            let r = kat::run();
            Ok(Journal {
                pre_state_root: kat::KAT_MAGIC,
                post_state_root: B256::from(r.digest),
                output_digest: B256::new(r.fallas.to_be_bytes()),
                ..Journal::empty(mode)
            })
        }
        // La línea de base de la medición: leer el input y publicar. El cuerpo
        // no se toca — es lo que hace que la resta atribuya el decode al
        // decoder y no al I/O.
        Mode::Nop => Ok(Journal::empty(mode)),
        Mode::StateTest => {
            let input = codec::decode_tx_input(cuerpo).map_err(|e| EntryError(e.0))?;
            run_tx_input(&input).map_err(|e| EntryError(e.reason()))
        }
        _ => {
            let input = codec::decode_block_input(cuerpo).map_err(|e| EntryError(e.0))?;
            run_block_input(mode, &input).map_err(|e| EntryError(e.reason()))
        }
    }
}

impl GuestError {
    /// El motivo, sin el detalle: lo único que el arranque bare-metal puede
    /// reportar.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Input(reason) => reason,
            Self::Block(_) => "el bloque no es válido",
            Self::Vm(_) => "el bloque no ejecuta",
            Self::Chain(_) => "el witness no verifica",
            Self::Witness(_) => "el post-state root no se puede computar desde el witness",
            Self::ClosingSystemCall(_) => "una system call de cierre no terminó en éxito",
            Self::Signature(_) => "una firma no recupera",
        }
    }
}

/// Por qué el guest no pudo producir un journal. Un solo camino de salida: no
/// hay a quién reportarle un error parcial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryError(pub &'static str);

/// Publica el output, **haciendo cumplir el techo de los tres backends**.
///
/// El techo no se chequea "por las dudas": OpenVM y ZisK truncan o rellenan a
/// 256 bytes, así que un guest que publicara de más produciría una prueba de
/// otra cosa **en silencio**. Acá es un halt.
///
/// # Panics
/// Si el output excede `journal::MAX_PUBLIC_OUTPUT_BYTES`.
pub fn publish<P: Platform>(bytes: &[u8]) {
    assert!(
        bytes.len() <= journal::MAX_PUBLIC_OUTPUT_BYTES,
        "el output del guest excede el techo de 256 bytes de OpenVM/ZisK"
    );
    P::write_output(bytes);
}

/// La plataforma del **ABI estándar sin backend**: la que produce el ELF cuya
/// ISA y ausencia de floats gatea `scripts/check-guest-isa.sh`.
///
/// **Sobrescribe los dos métodos en vez de usar el default de `ere`.** El
/// default llama a los símbolos `read_input`/`write_output` del ABI C de
/// `zkvm-standards`, que **exporta el runtime del zkVM** — y acá no hay
/// runtime: el ELF es un binario estático que arranca en `_start`. Usar el
/// default dejaría dos símbolos indefinidos y el link fallaría; definirlos
/// nosotros exigiría dos `#[unsafe(no_mangle)]` más, o sea agrandar la única
/// excepción de `unsafe` del repo para un binario que nadie ejecuta.
pub struct StdAbiPlatform;

/// El buffer del ELF sin backend. Vacío **porque no hay host que lo llene**:
/// este ELF existe para que la ISA y los símbolos se puedan auditar sin
/// instalar ningún backend. El input de verdad entra por la `Platform` del
/// backend, por `Platform::read_input`.
static ENTRADA: [u8; 0] = [];

impl Platform for StdAbiPlatform {
    fn read_input() -> impl core::ops::Deref<Target = [u8]> {
        // **Opaco al optimizador.** Sin esto el compilador sabe que el buffer
        // está vacío, pliega el rechazo y el motor entero deja de ser
        // alcanzable: el ELF quedaría en un cascarón que pasa todas las
        // aserciones de ISA sin contener nada.
        core::hint::black_box(&ENTRADA[..])
    }

    fn write_output(output: &[u8]) {
        core::hint::black_box(output);
    }
}

#[cfg(test)]
mod tests {
    use super::reservar;
    use super::{EntryError, StdAbiPlatform, journal, publish, run_bytes};

    /// **El techo de 256 bytes es un halt, no un comentario.** OpenVM y ZisK
    /// truncan o rellenan; un guest que publicara de más produciría una prueba
    /// de otra cosa en silencio.
    #[test]
    #[should_panic(expected = "excede el techo")]
    fn publishing_over_the_ceiling_halts() {
        publish::<StdAbiPlatform>(&[0u8; journal::MAX_PUBLIC_OUTPUT_BYTES + 1]);
    }

    /// El borde exacto SÍ entra: 256 es el techo, no el primer valor prohibido.
    #[test]
    fn publishing_exactly_at_the_ceiling_is_allowed() {
        publish::<StdAbiPlatform>(&[0u8; journal::MAX_PUBLIC_OUTPUT_BYTES]);
    }

    /// **Un input vacío es un rechazo, nunca un journal en ceros.** Es la
    /// diferencia entre "no pude ejecutar" y "ejecuté un bloque vacío", y la
    /// segunda es una afirmación bien formada sobre algo que no pasó.
    #[test]
    fn an_empty_input_is_refused_instead_of_producing_a_zero_journal() {
        assert_eq!(
            run_bytes(&[]),
            Err(EntryError("el input está vacío: no hay ni byte de modo"))
        );
    }

    /// Un byte de modo desconocido tampoco cae en `Full` por default.
    #[test]
    fn an_unknown_mode_byte_is_refused() {
        assert_eq!(
            run_bytes(&[99]),
            Err(EntryError("byte de modo desconocido"))
        );
    }

    /// El modo de línea de base no toca el cuerpo: es lo que hace que la resta
    /// de la escalera le atribuya el decode al decoder y no al I/O.
    #[test]
    fn the_baseline_mode_does_not_look_at_the_body() {
        assert_eq!(
            run_bytes(&[journal::Mode::Nop.as_byte(), 0xff, 0xff]),
            Ok(journal::Journal::empty(journal::Mode::Nop))
        );
    }

    const ARENA: usize = 1024;

    /// Lo básico: la primera reserva arranca en cero y avanza su tamaño.
    #[test]
    fn the_first_allocation_starts_at_zero() {
        assert_eq!(reservar(0, 8, 16, ARENA), Some((0, 16)));
    }

    /// **La alineación se redondea hacia arriba**, y el hueco queda perdido:
    /// un bump no lo reusa, y eso es exactamente lo que lo hace determinista.
    #[test]
    fn the_offset_is_rounded_up_to_the_alignment() {
        assert_eq!(reservar(1, 8, 4, ARENA), Some((8, 12)));
        assert_eq!(reservar(8, 8, 4, ARENA), Some((8, 12)));
        assert_eq!(reservar(9, 16, 1, ARENA), Some((16, 17)));
    }

    /// Que entre justo NO es que no entre: el borde exacto es válido.
    #[test]
    fn filling_the_arena_exactly_is_allowed() {
        assert_eq!(reservar(0, 1, ARENA, ARENA), Some((0, ARENA)));
    }

    /// Un byte más que la arena es `None`, no un puntero fuera de rango.
    #[test]
    fn one_byte_past_the_arena_is_refused() {
        assert_eq!(reservar(0, 1, ARENA + 1, ARENA), None);
        assert_eq!(reservar(ARENA, 1, 1, ARENA), None);
    }

    /// **Un `Layout` hostil no puede envolver la aritmética.** Es la razón por
    /// la que todo va con `checked_*`: sin eso, un tamaño cerca de `usize::MAX`
    /// daría un offset chico y un puntero adentro de la arena.
    #[test]
    fn a_hostile_layout_cannot_wrap_the_arithmetic() {
        assert_eq!(reservar(1, 1, usize::MAX, ARENA), None);
        assert_eq!(reservar(usize::MAX, 8, 1, ARENA), None);
        assert_eq!(reservar(usize::MAX - 1, 1, 1, ARENA), None);
    }

    /// Una alineación que no es potencia de dos viola el contrato de `Layout`:
    /// se rechaza en vez de producir una máscara sin sentido.
    #[test]
    fn a_non_power_of_two_alignment_is_refused() {
        assert_eq!(reservar(0, 0, 1, ARENA), None);
        assert_eq!(reservar(0, 3, 1, ARENA), None);
        assert_eq!(reservar(0, 6, 1, ARENA), None);
    }

    /// Dos reservas seguidas **nunca se solapan**: es la propiedad que hace
    /// sound al allocator, y la que el `unsafe impl` da por sentada.
    #[test]
    fn two_allocations_never_overlap() {
        let Some((o1, n1)) = reservar(0, 8, 20, ARENA) else {
            panic!("la primera reserva tiene que entrar");
        };
        let Some((o2, _)) = reservar(n1, 8, 20, ARENA) else {
            panic!("la segunda reserva tiene que entrar");
        };
        assert!(o2 >= o1 + 20, "se solapan: {o1}+20 > {o2}");
    }
}
