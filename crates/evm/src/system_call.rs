//! El *system call*: una ejecución de EVM que dispara el protocolo, no una tx
//! firmada (EIP-4788 hoy; EIP-2935/7002/7251 después).
//!
//! **La semántica no se decide acá: la fija el doc-comment del trait `Vm`**
//! (seam vendoreado). Caller = `SYSTEM_ADDRESS`, sin checks de firma/nonce/
//! balance, **no descuenta gas del bloque**, y si el contrato no existe
//! devuelve un success no-op. Este módulo la ejecuta.
//!
//! Qué NO hace, y por qué cada omisión es la regla y no un atajo:
//!
//! - **No pre-warmea el destino** (`execution-specs`: el mensaje de sistema arranca
//!   con `accessed_addresses=set()`). No hay sender que calentar, no aplica
//!   EIP-3651 al coinbase y no hay access list.
//! - **No bumpea el nonce de `SYSTEM_ADDRESS`** ni le cobra nada: el nonce lo
//!   bumpea `process_transaction`, no `process_message_call`. `SYSTEM_ADDRESS`
//!   no se toca en absoluto, así que el diff no puede emitirlo — y una cuenta
//!   vacía de más en el trie sería una divergencia de `stateRoot` en TODOS los
//!   bloques post-Cancun.
//! - **No transfiere value** (`should_transfer_value=False`) ni liquida fees:
//!   no hay prepago, ni devolución, ni tip al coinbase.
//! - **No emite receipt ni acumula `gasUsed`**: el gas que consume no entra al
//!   presupuesto del bloque (`Vm::system_call_in_block`, que es quien decide
//!   eso, tampoco lo suma).

use alloc::vec::Vec;

use repo_b_common::primitives::{Address, Bytes, U256};
use repo_b_interpreter::context::CallContext;
use repo_b_interpreter::host::TxEnv as HostTxEnv;
use repo_b_interpreter::interpreter::Interpreter;
use repo_b_interpreter::result::InterpreterOutcome;

use crate::error::{InternalError, VmError};
use crate::execution::{TxOutcome, halt_reason, host_env};
use crate::frames::{self, Frame, PlainRunner};
use crate::journal::Journal;
use crate::result::ExecutionResult;
use crate::state::State;
use crate::types::{BlockEnv, SYSTEM_ADDRESS, SYSTEM_CALL_GAS_LIMIT};

/// EIP-4788 — el contrato de beacon roots. Vive acá (motor) y no en el harness:
/// es una constante de consenso, igual que las direcciones de las precompiles.
/// Quién decide *cuándo* dispararla es el cliente, que es el que lee el header.
/// (`0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`, en minúsculas acá porque el
/// checksum EIP-55 no es parte del valor.)
pub const BEACON_ROOTS_ADDRESS: Address = Address::new([
    0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22,
    0xd0, 0xbe, 0xac, 0x02,
]);

/// EIP-2935 — el contrato de history. Guarda el hash del bloque padre en un
/// ring buffer de `HISTORY_SERVE_WINDOW` slots. Se dispara al arrancar el
/// bloque, con el hash del padre como calldata.
/// (`0x0000F90827F1C53a10cb7A02335B175320002935`.)
pub const HISTORY_STORAGE_ADDRESS: Address = Address::new([
    0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53,
    0x20, 0x00, 0x29, 0x35,
]);

/// EIP-7002 — el predeploy de withdrawal requests. A diferencia de 4788/2935,
/// se dispara al CERRAR el bloque y **su output es el dato**: la lista de
/// requests de tipo 1, ya serializada por el propio contrato.
/// (`0x00000961Ef480Eb55e80D19ad83579A64c007002`.)
pub const WITHDRAWAL_REQUESTS_ADDRESS: Address = Address::new([
    0x00, 0x00, 0x09, 0x61, 0xef, 0x48, 0x0e, 0xb5, 0x5e, 0x80, 0xd1, 0x9a, 0xd8, 0x35, 0x79, 0xa6,
    0x4c, 0x00, 0x70, 0x02,
]);

/// EIP-7251 — el predeploy de consolidation requests. Misma forma que el de
/// 7002: system call al cerrar el bloque, output = requests de tipo 2.
/// (`0x0000BBdDc7CE488642fb579F8B00f3a590007251`.)
pub const CONSOLIDATION_REQUESTS_ADDRESS: Address = Address::new([
    0x00, 0x00, 0xbb, 0xdd, 0xc7, 0xce, 0x48, 0x86, 0x42, 0xfb, 0x57, 0x9f, 0x8b, 0x00, 0xf3, 0xa5,
    0x90, 0x00, 0x72, 0x51,
]);

/// Corre un system call contra `state` y devuelve su resultado + el diff.
pub(crate) fn execute_system_call(
    env: &BlockEnv,
    state: &dyn State,
    to: Address,
    data: Bytes,
) -> Result<TxOutcome, VmError> {
    let mut journal = Journal::new(state)
        .with_frame_context(
            host_env(env)?,
            HostTxEnv {
                // `ORIGIN` dentro de un system call ES `SYSTEM_ADDRESS`: el
                // mensaje no tiene otro originante. `GASPRICE` es 0 (no se
                // cobra gas) y no hay blob hashes que exponer.
                origin: SYSTEM_ADDRESS,
                gas_price: 0,
                blob_hashes: Vec::new(),
            },
        )
        .with_spec(env.spec);

    // Dos lecturas distintas del mismo destino, cada una con su regla:
    //
    // - el chequeo de "sin código" mira el código CRUDO de la cuenta: un
    //   designador de EIP-7702 son 23 bytes, o sea código;
    // - lo que se EJECUTA resuelve la delegación UN nivel, como el frame raíz
    //   de una tx (`execution-specs`, `process_message_call`): si el código
    //   crudo es un designador, corre el código del delegado, en el contexto
    //   del destino. Las precompiles no se despachan en este frame: delegar a
    //   una precompile ejecuta el código de su cuenta (vacío) y termina en
    //   éxito sin efecto. Si el delegado también es un designador, sus 23
    //   bytes se ejecutan crudos y haltean.
    let bytecode = journal.code_of(to);
    // `code_of` no devuelve el error: lo registra y responde con bytes vacíos.
    // Tiene que drenarse ACÁ, antes del cortocircuito de abajo: una lectura
    // fallida (nodo de cuenta ausente, bytecode que no está bajo su hash) no es
    // "la cuenta no tiene código", y confundirlas convertiría un witness
    // incompleto o alterado en un no-op exitoso de la system call.
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }
    if bytecode.is_empty() {
        // El trait lo fija: si el contrato no existe, success no-op. Para las
        // llamadas *unchecked* (4788, 2935) es la regla del protocolo, y la
        // juzga el corpus en las redes de transición a Cancun y a Prague
        // (`no_beacon_root_contract_at_transition`, el despliegue de 2935). Para
        // las *checked* (7002, 7251) la falta de código invalida el bloque, y
        // eso lo decide la política de system calls ANTES de llegar acá.
        return Ok(TxOutcome {
            result: ExecutionResult::Success {
                gas_used: 0,
                gas_refunded: 0,
                logs: Vec::new(),
                output: Bytes::new(),
            },
            state_changes: Vec::new(),
        });
    }

    // El accessed set arranca vacío: el destino queda FRÍO. El delegado, en
    // cambio, entra caliente (`message.accessed_addresses.add(delegated)`).
    if let Some(delegated) = journal.delegation_of(to) {
        journal.warm(delegated);
    }
    let bytecode = journal.code_to_execute(to);
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }

    let context = CallContext {
        address: to,
        caller: SYSTEM_ADDRESS,
        value: U256::ZERO,
        calldata: data,
        bytecode,
        is_static: false,
        depth: 0,
    };
    // El checkpoint es el mismo contrato que el del frame raíz de una tx:
    // `frames::run` commitea si el frame termina en éxito y revierte si no.
    let checkpoint = journal.checkpoint();
    let outcome = frames::run(
        &mut journal,
        &mut PlainRunner,
        Frame::call(
            Interpreter::new(context, SYSTEM_CALL_GAS_LIMIT, env.spec),
            SYSTEM_CALL_GAS_LIMIT,
            checkpoint,
        ),
        env.spec,
    )?;

    // Fail-closed, igual que en una tx: un fallo de lectura del `State` no se
    // aproxima como cero.
    if let Some(err) = journal.take_error() {
        return Err(VmError::Internal(InternalError::StateAccess(err)));
    }

    // El refund acumulado se descarta: no hay gas que devolver a nadie.
    let result = match outcome {
        InterpreterOutcome::Success { output, gas_used } => ExecutionResult::Success {
            gas_used,
            gas_refunded: 0,
            logs: journal.logs().to_vec(),
            output,
        },
        InterpreterOutcome::Revert { output, gas_used } => ExecutionResult::Revert {
            gas_used,
            gas_refunded: 0,
            output,
        },
        InterpreterOutcome::Halt { reason, gas_used } => ExecutionResult::Halt {
            reason: halt_reason(reason),
            gas_used,
            gas_refunded: 0,
        },
    };
    let state_changes = journal.state_changes()?;
    Ok(TxOutcome {
        result,
        state_changes,
    })
}
