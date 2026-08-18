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
//! - **No pre-warmea nada** (`execution-specs`: el mensaje de sistema arranca
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

    // El código sale de la CUENTA, sin resolver delegaciones de EIP-7702
    // (`execution-specs` toma `get_account(state, target).code` crudo). Un
    // contrato de sistema delegado correría el código de otro, que no es lo que
    // el protocolo dice.
    let bytecode = journal.code_of(to);
    if bytecode.is_empty() {
        // El trait lo fija: si el contrato no existe, success no-op. **Sin
        // cobertura del corpus de Cancun** — el único fixture que borra el
        // contrato de beacon roots es de un fork de transición, fuera de scope.
        // La pinea un unit test.
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
