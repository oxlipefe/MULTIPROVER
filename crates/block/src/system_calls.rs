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
//!   EIP-7251 desde Prague, sin calldata, **después** de las withdrawals. Dos
//!   cosas invalidan el bloque, en este orden:
//!   1. que el predeploy **no tenga código** en el estado del bloque a esa
//!      altura (una tx anterior del mismo bloque puede haberlo desplegado). Una
//!      cuenta inexistente y una cuenta con código vacío son el mismo caso: la
//!      especificación solo mira `len(code) == 0`. Los dos EIPs lo dicen igual:
//!      *"If there is no code at `…_PREDEPLOY_ADDRESS`, the corresponding block
//!      MUST be marked invalid"*;
//!   2. que la llamada no termine en éxito (revert, halt, OOG).
//!
//!   Su output es el dato de los requests de tipo 1 y 2 de EIP-7685.
//!
//! El chequeo de código vive acá y no en el motor porque el seam `Vm` fija que
//! una system call a una cuenta sin código es un éxito no-op: el resultado de
//! la llamada no distingue "sin código" de "código que termina sin hacer nada".
//! La pregunta se le hace al motor aparte ([`SystemCallHost`]).

use alloc::vec::Vec;

use alloy_primitives::{Address, Bytes};
use repo_b_common::spec::Spec;
use repo_b_evm::{ExecutionResult, OwnVm, Vm, VmError};

use crate::error::{BlockError, HeaderField};
use crate::header::Header;

/// Lo que la política le pide al motor además del seam `Vm`, que está
/// vendoreado y no se redefine.
pub trait SystemCallHost: Vm {
    /// ¿`address` tiene código en el estado del bloque abierto, con lo que el
    /// bloque ya cambió? Una cuenta inexistente no tiene código.
    ///
    /// # Errors
    /// Si el estado no puede contestar. Nunca se lee como "sin código".
    fn has_code_in_block(&self, address: Address) -> Result<bool, VmError>;
}

impl SystemCallHost for OwnVm {
    fn has_code_in_block(&self, address: Address) -> Result<bool, VmError> {
        OwnVm::has_code_in_block(self, address)
    }
}

/// Qué invalida el bloque además de un error del motor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Nada: ni la falta de código ni el resultado se miran.
    Unchecked,
    /// Un predeploy sin código, o un revert o un halt de la llamada.
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
    /// Una llamada *checked* contra una dirección sin código: el bloque es
    /// inválido y la llamada no se corre.
    EmptyCode { address: Address },
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
/// El primer error del motor, o la primera *checked* sin código o que falla.
pub fn run_system_calls<V: SystemCallHost + ?Sized>(
    vm: &mut V,
    calls: &[SystemCall],
) -> Result<Vec<Bytes>, SystemCallError> {
    let mut outputs = Vec::with_capacity(calls.len());
    for call in calls {
        // Antes de correrla, como `process_checked_system_transaction`: sin
        // código la llamada ni se ejecuta.
        if call.check == Check::Checked
            && !vm
                .has_code_in_block(call.address)
                .map_err(SystemCallError::Vm)?
        {
            return Err(SystemCallError::EmptyCode {
                address: call.address,
            });
        }
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

/// La política de [`run_system_calls`] contra el motor real, sobre un estado en
/// memoria: qué invalida el bloque y qué no.
#[cfg(test)]
mod run_tests {
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
    use repo_b_common::spec::Spec;
    use repo_b_evm::state::State;
    use repo_b_evm::types::{AccountInfo, BlockEnv, CodeMetadata};
    use repo_b_evm::{
        BEACON_ROOTS_ADDRESS, CONSOLIDATION_REQUESTS_ADDRESS, ExecutionResult,
        HISTORY_STORAGE_ADDRESS, HaltReason, OwnVm, StateError, Vm, WITHDRAWAL_REQUESTS_ADDRESS,
    };

    use super::{Check, SystemCall, SystemCallError, run_system_calls};

    /// `STOP`: termina en éxito sin output.
    const STOPS: &[u8] = &[0x00];
    /// `PUSH0 PUSH0 REVERT`.
    const REVERTS: &[u8] = &[0x5f, 0x5f, 0xfd];

    #[derive(Debug, Clone, Default)]
    struct Mem {
        accounts: BTreeMap<Address, AccountInfo>,
        code: BTreeMap<B256, Bytes>,
        unreadable: Option<Address>,
    }

    impl Mem {
        fn with_code(mut self, address: Address, code: &[u8]) -> Self {
            let hash = keccak256(code);
            self.code.insert(hash, Bytes::copy_from_slice(code));
            self.accounts.insert(
                address,
                AccountInfo {
                    balance: U256::ZERO,
                    nonce: 1,
                    code_hash: hash,
                },
            );
            self
        }

        /// Una cuenta que EXISTE (tiene balance) y no tiene código.
        fn with_codeless_account(mut self, address: Address) -> Self {
            self.accounts.insert(
                address,
                AccountInfo {
                    balance: U256::from(1u8),
                    nonce: 0,
                    code_hash: KECCAK256_EMPTY,
                },
            );
            self
        }

        fn unreadable(mut self, address: Address) -> Self {
            self.unreadable = Some(address);
            self
        }
    }

    impl State for Mem {
        fn account(&self, addr: Address) -> Result<Option<AccountInfo>, StateError> {
            if self.unreadable == Some(addr) {
                return Err(StateError::Database(
                    "cuenta fuera del witness (test)".to_string(),
                ));
            }
            Ok(self.accounts.get(&addr).cloned())
        }
        fn storage(&self, _addr: Address, _key: U256) -> Result<U256, StateError> {
            Ok(U256::ZERO)
        }
        fn storage_root(&self, _addr: Address) -> Result<B256, StateError> {
            Ok(alloy_trie::EMPTY_ROOT_HASH)
        }
        fn code(&self, code_hash: B256) -> Result<Bytes, StateError> {
            Ok(self.code.get(&code_hash).cloned().unwrap_or_default())
        }
        fn code_metadata(&self, _code_hash: B256) -> Result<CodeMetadata, StateError> {
            Ok(CodeMetadata::Regular)
        }
        fn block_hash(&self, _number: u64) -> Result<B256, StateError> {
            Ok(B256::ZERO)
        }
    }

    fn env() -> BlockEnv {
        BlockEnv {
            spec: Spec::Prague,
            chain_id: 1,
            number: 1,
            coinbase: Address::ZERO,
            timestamp: 1000,
            gas_limit: 30_000_000,
            base_fee: 7,
            prevrandao: B256::ZERO,
            blob_excess_gas: Some(0),
            blob_base_fee: Some(1),
            blob_base_fee_update_fraction: None,
        }
    }

    fn call(address: Address, check: Check) -> SystemCall {
        SystemCall {
            address,
            calldata: Bytes::new(),
            check,
        }
    }

    fn closing() -> Vec<SystemCall> {
        vec![
            call(WITHDRAWAL_REQUESTS_ADDRESS, Check::Checked),
            call(CONSOLIDATION_REQUESTS_ADDRESS, Check::Checked),
        ]
    }

    fn run(state: &Mem, calls: &[SystemCall]) -> Result<Vec<Bytes>, SystemCallError> {
        let mut vm = OwnVm::new();
        let opened = vm.begin_block(&env(), state);
        assert!(opened.is_ok(), "begin_block: {opened:?}");
        run_system_calls(&mut vm, calls)
    }

    fn both_predeploys() -> Mem {
        Mem::default()
            .with_code(WITHDRAWAL_REQUESTS_ADDRESS, STOPS)
            .with_code(CONSOLIDATION_REQUESTS_ADDRESS, STOPS)
    }

    #[test]
    fn closing_calls_with_code_that_succeeds_return_one_output_each() {
        let outputs = run(&both_predeploys(), &closing());
        assert!(
            matches!(&outputs, Ok(o) if o == &vec![Bytes::new(), Bytes::new()]),
            "{outputs:?}"
        );
    }

    /// EIP-7002 y EIP-7251: *"If there is no code at `…_PREDEPLOY_ADDRESS`, the
    /// corresponding block MUST be marked invalid"*. Una cuenta inexistente y
    /// una que existe con código vacío son el mismo caso.
    #[test]
    fn a_closing_predeploy_without_code_invalidates_the_block() {
        for (empty, other) in [
            (WITHDRAWAL_REQUESTS_ADDRESS, CONSOLIDATION_REQUESTS_ADDRESS),
            (CONSOLIDATION_REQUESTS_ADDRESS, WITHDRAWAL_REQUESTS_ADDRESS),
        ] {
            let absent = Mem::default().with_code(other, STOPS);
            let codeless = absent.clone().with_codeless_account(empty);
            for state in [absent, codeless] {
                let result = run(&state, &closing());
                assert!(
                    matches!(result, Err(SystemCallError::EmptyCode { address }) if address == empty),
                    "{empty}: {result:?}"
                );
            }
        }
    }

    /// EIP-4788 y EIP-2935 corren *unchecked*: sin código, la llamada es un
    /// no-op y el bloque sigue.
    #[test]
    fn an_opening_call_without_code_is_a_no_op() {
        let opening = [
            call(BEACON_ROOTS_ADDRESS, Check::Unchecked),
            call(HISTORY_STORAGE_ADDRESS, Check::Unchecked),
        ];
        let absent = Mem::default();
        let codeless = Mem::default()
            .with_codeless_account(BEACON_ROOTS_ADDRESS)
            .with_codeless_account(HISTORY_STORAGE_ADDRESS);
        for state in [absent, codeless] {
            let outputs = run(&state, &opening);
            assert!(
                matches!(&outputs, Ok(o) if o == &vec![Bytes::new(), Bytes::new()]),
                "{outputs:?}"
            );
        }
    }

    #[test]
    fn a_checked_call_that_reverts_invalidates_the_block() {
        let state = both_predeploys().with_code(CONSOLIDATION_REQUESTS_ADDRESS, REVERTS);
        let result = run(&state, &closing());
        assert!(
            matches!(
                &result,
                Err(SystemCallError::Failed { address, result: ExecutionResult::Revert { .. } })
                    if *address == CONSOLIDATION_REQUESTS_ADDRESS
            ),
            "{result:?}"
        );
    }

    /// Un halt (opcode inválido) y un OOG de una *checked* invalidan el bloque
    /// igual que un revert, y por `Failed`: el predeploy tiene código.
    #[test]
    fn a_checked_call_that_halts_or_runs_out_of_gas_invalidates_the_block() {
        // `INVALID`.
        const HALTS: &[u8] = &[0xfe];
        // `JUMPDEST PUSH0 JUMP`: un loop que agota el gas de la system call.
        const LOOPS: &[u8] = &[0x5b, 0x5f, 0x56];
        for (code, expected) in [
            (HALTS, HaltReason::InvalidFEOpcode),
            (LOOPS, HaltReason::OutOfGas),
        ] {
            let state = both_predeploys().with_code(WITHDRAWAL_REQUESTS_ADDRESS, code);
            let result = run(&state, &closing());
            assert!(
                matches!(
                    &result,
                    Err(SystemCallError::Failed {
                        address,
                        result: ExecutionResult::Halt { reason, .. },
                    }) if *address == WITHDRAWAL_REQUESTS_ADDRESS && *reason == expected
                ),
                "{expected:?}: {result:?}"
            );
        }
    }

    /// La recíproca de la de arriba: un revert de una *unchecked* no invalida.
    #[test]
    fn an_unchecked_call_that_reverts_is_ignored() {
        let state = Mem::default().with_code(HISTORY_STORAGE_ADDRESS, REVERTS);
        let outputs = run(&state, &[call(HISTORY_STORAGE_ADDRESS, Check::Unchecked)]);
        assert!(
            matches!(&outputs, Ok(o) if o == &vec![Bytes::new()]),
            "{outputs:?}"
        );
    }

    /// Fail-closed: un estado que no puede contestar no es "sin código" (eso
    /// convertiría un witness incompleto en un veredicto sobre el bloque).
    #[test]
    fn a_state_that_cannot_answer_is_an_engine_error_not_empty_code() {
        let state = both_predeploys().unreadable(WITHDRAWAL_REQUESTS_ADDRESS);
        let result = run(&state, &closing());
        assert!(matches!(result, Err(SystemCallError::Vm(_))), "{result:?}");
    }
}
