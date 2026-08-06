//! `CallContext` — los inputs **inmutables** de un frame de ejecución (ADR-0002).
//!
//! No es world-state (eso lo da el seam `Host`, slice 2.2): son los datos del
//! frame que alimentan ADDRESS/CALLER/CALLVALUE/CALLDATA*/CODE* y, más adelante,
//! el gate `is_static` de las escrituras y el bound de profundidad de call.

use repo_b_common::primitives::{Address, Bytes, U256};

/// Inmutables de un frame. Un CALL/CREATE abre un frame nuevo con su contexto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContext {
    /// Cuenta en ejecución (`ADDRESS`). En DELEGATECALL es la del caller.
    pub address: Address,
    /// Quién invocó este frame (`CALLER`).
    pub caller: Address,
    /// Wei enviados con la llamada (`CALLVALUE`).
    pub value: U256,
    /// Datos de entrada (`CALLDATALOAD`/`CALLDATASIZE`/`CALLDATACOPY`).
    pub calldata: Bytes,
    /// Código que corre este frame (`CODESIZE`/`CODECOPY`).
    pub bytecode: Bytes,
    /// Contexto estático (STATICCALL): prohíbe escrituras de estado. Slice 2.2+.
    pub is_static: bool,
    /// Profundidad de la pila de calls (bound `CALL_DEPTH_LIMIT`). Slice 2.5+.
    pub depth: usize,
}

impl CallContext {
    /// Frame "desnudo" para tests de opcodes puros / uso sin contexto de tx:
    /// todo en cero salvo el código a ejecutar.
    pub fn for_code(bytecode: Bytes) -> Self {
        Self {
            address: Address::ZERO,
            caller: Address::ZERO,
            value: U256::ZERO,
            calldata: Bytes::new(),
            bytecode,
            is_static: false,
            depth: 0,
        }
    }
}
