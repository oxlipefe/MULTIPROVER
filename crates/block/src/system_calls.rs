//! Las system calls de un bloque: **cuáles, con qué calldata y qué pasa si
//! fallan**. Una sola política, que corren el harness y el guest.
//!
//! # Qué dice `execution-specs` (Cancun, Prague, Osaka)
//!
//! - **Arranque, *unchecked*** (`process_unchecked_system_transaction`):
//!   EIP-4788 desde Cancun, con el `parentBeaconBlockRoot` del header, y
//!   EIP-2935 desde Prague, con el hash del padre (`block_hashes[-1]`, que es el
//!   `parentHash` del header una vez que el header encadena). El resultado no
//!   se mira: un revert, un halt o un contrato sin código **no** invalidan el
//!   bloque. EIP-4788 dice en su texto que la llamada *"must execute to
//!   completion"*, pero la especificación ejecutable no lo enforcea, y el
//!   veredicto que manda es el de la especificación ejecutable.
//! - **Cierre, *checked*** (`process_checked_system_transaction`): EIP-7002 y
//!   EIP-7251 desde Prague, sin calldata, **después** de las withdrawals. Un
//!   error de la llamada invalida el bloque, y su output es el dato de los
//!   requests de tipo 1 y 2 de EIP-7685.
//!
//! # KNOWN: un predeploy de cierre sin código
//!
//! `process_checked_system_transaction` también invalida el bloque si el
//! predeploy **no tiene código**. Acá no se detecta: el motor resuelve una
//! system call a una cuenta sin código como un éxito no-op (la semántica del
//! seam `Vm`), y el resultado no distingue "sin código" de "código que termina
//! sin hacer nada". Un bloque de Prague+ cuyo pre-state no trae el código de
//! 7002 o 7251 se acepta acá y la especificación lo rechaza. En mainnet y en
//! todo fixture del corpus en scope los dos predeploys tienen código; el caso
//! solo aparece en una cadena que active Prague sin desplegarlos.

use alloc::vec::Vec;

use alloy_primitives::{Address, Bytes};
use repo_b_common::spec::Spec;
use repo_b_evm::{ExecutionResult, Vm, VmError};

use crate::error::{BlockError, HeaderField};
use crate::header::Header;

/// Qué pasa si la llamada no termina en éxito.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// El resultado no se mira.
    Unchecked,
    /// Un revert o un halt invalida el bloque.
    Checked,
}

/// Una system call, **derivada** del fork y del header: ningún byte del input
/// la nombra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemCall {
    pub address: Address,
    pub calldata: Bytes,
    pub check: Check,
}

/// Las system calls de un bloque, por fase y en orden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemCalls {
    /// Antes de la primera tx.
    pub opening: Vec<SystemCall>,
    /// Después de las txs y del settle de withdrawals.
    pub closing: Vec<SystemCall>,
}

/// Las system calls que el fork exige, con la calldata sacada del header.
///
/// # Errors
/// `MissingField` si el header de Cancun+ no trae `parentBeaconBlockRoot`:
/// una raíz en cero sería inventarla. Sobre un header ya validado contra su
/// fork es inalcanzable.
pub fn system_calls(header: &Header, spec: Spec) -> Result<SystemCalls, BlockError> {
    let mut opening = Vec::new();
    let mut closing = Vec::new();
    if spec.is_enabled(Spec::Cancun) {
        let beacon_root = header
            .parent_beacon_block_root
            .ok_or(BlockError::MissingField {
                field: HeaderField::ParentBeaconBlockRoot,
                spec,
            })?;
        opening.push(SystemCall {
            address: repo_b_evm::BEACON_ROOTS_ADDRESS,
            calldata: Bytes::copy_from_slice(beacon_root.as_slice()),
            check: Check::Unchecked,
        });
    }
    if spec.is_enabled(Spec::Prague) {
        opening.push(SystemCall {
            address: repo_b_evm::HISTORY_STORAGE_ADDRESS,
            calldata: Bytes::copy_from_slice(header.parent_hash.as_slice()),
            check: Check::Unchecked,
        });
        for address in [
            repo_b_evm::WITHDRAWAL_REQUESTS_ADDRESS,
            repo_b_evm::CONSOLIDATION_REQUESTS_ADDRESS,
        ] {
            closing.push(SystemCall {
                address,
                calldata: Bytes::new(),
                check: Check::Checked,
            });
        }
    }
    Ok(SystemCalls { opening, closing })
}

/// Por qué una tanda de system calls no terminó.
#[derive(Debug)]
pub enum SystemCallError {
    /// El motor no pudo ejecutar la llamada (witness insuficiente, error
    /// interno). No es un veredicto sobre el bloque.
    Vm(VmError),
    /// Una llamada *checked* no terminó en éxito: el bloque es inválido.
    Failed {
        address: Address,
        result: ExecutionResult,
    },
}

/// Corre las llamadas en orden y devuelve **un output por llamada**.
///
/// El output de una *unchecked* que no terminó en éxito es vacío: la
/// especificación no lo usa para nada, y devolver lo que revirtió lo haría
/// pasar por dato.
///
/// # Errors
/// El primer error del motor o la primera *checked* que falla.
pub fn run_system_calls<V: Vm + ?Sized>(
    vm: &mut V,
    calls: &[SystemCall],
) -> Result<Vec<Bytes>, SystemCallError> {
    let mut outputs = Vec::with_capacity(calls.len());
    for call in calls {
        let outcome = vm
            .system_call_in_block(call.address, call.calldata.clone())
            .map_err(SystemCallError::Vm)?;
        match (outcome.result, call.check) {
            (ExecutionResult::Success { output, .. }, _) => outputs.push(output),
            (_, Check::Unchecked) => outputs.push(Bytes::new()),
            (result, Check::Checked) => {
                return Err(SystemCallError::Failed {
                    address: call.address,
                    result,
                });
            }
        }
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Check, SystemCall, system_calls};
    use crate::error::{BlockError, HeaderField};
    use crate::header::Header;
    use alloy_primitives::{B256, Bytes};
    use repo_b_common::spec::Spec;

    fn header() -> Header {
        Header {
            parent_hash: B256::repeat_byte(0x11),
            parent_beacon_block_root: Some(B256::repeat_byte(0x22)),
            ..crate::header::tests::prague_genesis()
        }
    }

    fn unchecked(address: alloy_primitives::Address, calldata: B256) -> SystemCall {
        SystemCall {
            address,
            calldata: Bytes::copy_from_slice(calldata.as_slice()),
            check: Check::Unchecked,
        }
    }

    /// Por fork: qué llamadas, con qué calldata y cuáles son *checked*. Las de
    /// arranque son *unchecked* en los tres forks; las de cierre, *checked*.
    #[test]
    fn the_policy_per_fork() {
        let h = header();
        for spec in [Spec::Paris, Spec::Shanghai] {
            let calls = system_calls(&h, spec);
            assert_eq!(calls.as_ref().map(|c| c.opening.len()), Ok(0), "{spec:?}");
            assert_eq!(calls.map(|c| c.closing.len()), Ok(0), "{spec:?}");
        }
        let beacon = unchecked(repo_b_evm::BEACON_ROOTS_ADDRESS, B256::repeat_byte(0x22));
        let Ok(cancun) = system_calls(&h, Spec::Cancun) else {
            panic!("un header de Cancun con su raíz");
        };
        assert_eq!(cancun.opening, vec![beacon.clone()]);
        assert!(cancun.closing.is_empty());
        for spec in [Spec::Prague, Spec::Osaka] {
            let Ok(calls) = system_calls(&h, spec) else {
                panic!("un header de {spec:?} con su raíz");
            };
            assert_eq!(
                calls.opening,
                vec![
                    beacon.clone(),
                    unchecked(repo_b_evm::HISTORY_STORAGE_ADDRESS, B256::repeat_byte(0x11)),
                ],
                "{spec:?}"
            );
            let checked = |address| SystemCall {
                address,
                calldata: Bytes::new(),
                check: Check::Checked,
            };
            assert_eq!(
                calls.closing,
                vec![
                    checked(repo_b_evm::WITHDRAWAL_REQUESTS_ADDRESS),
                    checked(repo_b_evm::CONSOLIDATION_REQUESTS_ADDRESS),
                ],
                "{spec:?}"
            );
        }
    }

    #[test]
    fn a_cancun_header_without_its_beacon_root_is_refused() {
        let h = Header {
            parent_beacon_block_root: None,
            ..header()
        };
        assert_eq!(
            system_calls(&h, Spec::Cancun),
            Err(BlockError::MissingField {
                field: HeaderField::ParentBeaconBlockRoot,
                spec: Spec::Cancun
            })
        );
    }
}
