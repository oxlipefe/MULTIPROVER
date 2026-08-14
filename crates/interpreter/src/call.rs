//! Sub-calls: la acción que el intérprete devuelve y los inputs del
//! sub-frame.
//!
//! El intérprete **no recursa**: cuando un CALL abre un frame nuevo, devuelve
//! `InterpreterAction::Call` y queda SUSPENDIDO (stack/memory/pc/gas intactos).
//! Un executor con pila explícita (`repo-b-evm`) abre el sub-frame y lo
//! reanuda con `Interpreter::resume`. Condición del guest RISC-V: una cadena
//! de 1024 calls no puede reventar el stack nativo.
//!
//! Toda la semántica de contexto de la tabla EIP-7/EIP-214 (quién es
//! `ADDRESS`, quién `CALLER`, qué `CALLVALUE` se ve, de quién es el storage)
//! se resuelve **acá**, en el opcode, que es el único que conoce el frame
//! actual. El executor queda mecánico: transferir, cargar código, empujar.

use alloc::boxed::Box;

use repo_b_common::primitives::{Address, Bytes, U256};

use crate::result::InterpreterOutcome;

/// Los cuatro sabores de call del set actual (CREATE/CREATE2 va aparte, en
/// `CreateKind`: su resultado es una dirección, no un bit de status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// `CALL` (0xF1): contexto y storage del target, value explícito.
    Call,
    /// `CALLCODE` (0xF2): código del target sobre el storage PROPIO.
    CallCode,
    /// `DELEGATECALL` (0xF4): código del target sobre el storage propio,
    /// heredando `CALLER` y `CALLVALUE` del frame actual.
    DelegateCall,
    /// `STATICCALL` (0xFA, EIP-214): como CALL con value 0 y `is_static`.
    StaticCall,
}

impl CallKind {
    /// ¿El opcode toma un argumento `value` del stack? (CALL y CALLCODE.)
    pub fn takes_value_argument(self) -> bool {
        matches!(self, Self::Call | Self::CallCode)
    }

    /// ¿Mueve balance? DELEGATECALL **no transfiere nada** (ni siquiera un
    /// touch de cero): su value es aparente, heredado del frame padre.
    pub fn transfers_balance(self) -> bool {
        !matches!(self, Self::DelegateCall)
    }
}

/// Todo lo que el executor necesita para abrir un sub-frame. Los costos fijos
/// (access, `G_callvalue`, `G_newaccount`, expansión de memoria) y el 63/64 de
/// EIP-150 YA están cobrados al frame padre cuando esto se emite; `gas_limit`
/// es el gas del sub-frame **con el stipend ya sumado**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallInputs {
    pub kind: CallKind,
    /// Cuenta cuyo **código** se ejecuta (el argumento del opcode).
    pub code_address: Address,
    /// Cuenta **en ejecución** del sub-frame: `ADDRESS` y dueña del storage.
    /// Igual a `code_address` en CALL/STATICCALL; la propia en CALLCODE/
    /// DELEGATECALL.
    pub target: Address,
    /// `CALLER` del sub-frame. En DELEGATECALL es el caller HEREDADO.
    pub caller: Address,
    /// Value que se **transfiere** de `caller` a `target`. Cero en
    /// STATICCALL (sigue siendo un touch) y sin sentido en DELEGATECALL
    /// (ver `CallKind::transfers_balance`).
    pub transfer_value: U256,
    /// `CALLVALUE` que **ve** el sub-frame. En DELEGATECALL es el heredado.
    pub value: U256,
    /// Calldata del sub-frame (copia de la ventana de memoria del caller).
    pub input: Bytes,
    /// Gas del sub-frame: `min(pedido, 63/64)` + stipend.
    pub gas_limit: u64,
    /// EIP-214: `true` en STATICCALL y heredado de un frame ya estático.
    pub is_static: bool,
}

/// Lo que el executor le devuelve al frame suspendido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubcallOutcome {
    /// `true` solo si el sub-frame terminó en `Success` (Revert y Halt
    /// pushean 0, igual que una call que ni siquiera se ejecutó).
    pub success: bool,
    /// Output del sub-frame: buffer de RETURNDATA* y fuente de la ventana de
    /// retorno. Vacío en Halt y en una call no ejecutada.
    pub output: Bytes,
    /// Gas que vuelve al caller. Halt ⇒ 0 (el sub-frame consumió todo);
    /// depth excedido o balance insuficiente ⇒ el `gas_limit` completo.
    pub gas_remaining: u64,
}

impl SubcallOutcome {
    /// La call **no se ejecutó** (depth excedido o balance insuficiente):
    /// push 0, sin returndata, y el gas reenviado vuelve ENTERO — no es un
    /// halt (EIP-150 / execution-specs `generic_call`).
    pub fn not_executed(gas_limit: u64) -> Self {
        Self {
            success: false,
            output: Bytes::new(),
            gas_remaining: gas_limit,
        }
    }
}

/// Cómo se deriva la dirección del contrato nuevo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateKind {
    /// `CREATE` (0xF0): `keccak256(rlp([creador, nonce_pre_bump]))[12..]`.
    Create,
    /// `CREATE2` (0xF5, EIP-1014):
    /// `keccak256(0xff ++ creador ++ salt ++ keccak256(init_code))[12..]`.
    Create2 { salt: U256 },
}

/// Todo lo que el executor necesita para abrir un frame de creación. Igual que
/// `CallInputs`, el gas ya viene con el 63/64 de EIP-150 aplicado y cobrado al
/// padre — pero **sin stipend**: CREATE no tiene equivalente al 2300 de CALL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInputs {
    /// Quien ejecuta CREATE/CREATE2: dueño del nonce que deriva la dirección,
    /// `CALLER` del frame nuevo y origen del `value`.
    pub creator: Address,
    pub kind: CreateKind,
    /// Value transferido al contrato nuevo ANTES de correr el initcode.
    pub value: U256,
    /// Initcode: se ejecuta como CÓDIGO del frame nuevo (no como calldata).
    pub init_code: Bytes,
    pub gas_limit: u64,
    /// Heredado. CREATE/CREATE2 en contexto estático haltea ANTES de emitir
    /// esta acción, así que acá siempre es `false` — se propaga igual para que
    /// el frame nuevo no dependa de esa invariante.
    pub is_static: bool,
}

/// Lo que el executor le devuelve al frame suspendido tras un CREATE/CREATE2.
///
/// A diferencia de `SubcallOutcome`, lo que se pushea NO es un bit de status
/// sino la **dirección** del contrato nuevo (0 en cualquier fallo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOutcome {
    /// `Some` solo si la creación terminó en éxito y el código se depositó.
    pub address: Option<Address>,
    /// EIP-211: buffer de RETURNDATA del caller. **Solo** la razón de revert
    /// de un `REVERT` del initcode; vacío en éxito (el output es código
    /// desplegado, no data) y en cualquier halt.
    pub output: Bytes,
    /// Gas que vuelve al caller. Halt/colisión ⇒ 0; depth excedido, balance
    /// insuficiente u overflow de nonce ⇒ el `gas_limit` completo.
    pub gas_remaining: u64,
}

impl CreateOutcome {
    /// La creación **no se ejecutó** (depth excedido, balance insuficiente o
    /// nonce en `u64::MAX`): push 0, sin returndata, y el gas reenviado vuelve
    /// ENTERO — igual que una call no ejecutada (revm los clasifica
    /// `is_ok_or_revert`, no como halt).
    pub fn not_executed(gas_limit: u64) -> Self {
        Self {
            address: None,
            output: Bytes::new(),
            gas_remaining: gas_limit,
        }
    }
}

/// Qué hacer con el frame cuando `Interpreter::run` devuelve el control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpreterAction {
    /// El frame terminó (Success/Revert/Halt).
    Return(InterpreterOutcome),
    /// El frame queda suspendido: abrir el sub-frame y `resume`.
    Call(Box<CallInputs>),
    /// El frame queda suspendido: crear el contrato y `resume_create`.
    Create(Box<CreateInputs>),
}
