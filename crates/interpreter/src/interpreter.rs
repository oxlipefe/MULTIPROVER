//! El loop de ejecución: dispatch por `match` exhaustivo sobre el byte del
//! opcode (decisión de Fase 1: legibilidad/verificabilidad > perf; ficha 01).
//!
//! Semántica de consenso implementada acá:
//! - Caer del final del código = STOP implícito.
//! - Wrapping U256 **de protocolo** explícito (ADD/MUL/SUB); overflow **de
//!   implementación** (gas/offsets) = `Halt`, fail-closed.
//! - Trichotomy: `Halt` consume TODO el gas; `Revert`/`Success` devuelven el
//!   restante al caller (reflejado en `gas_used`).

use alloc::boxed::Box;
use alloc::vec::Vec;

use repo_b_common::primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256};
use repo_b_common::receipt::Log;

use crate::bytecode::Bytecode;
use crate::call::{
    CallInputs, CallKind, CreateInputs, CreateKind, CreateOutcome, InterpreterAction,
    SubcallOutcome,
};
use crate::context::CallContext;
use crate::gas::{Gas, MAX_INITCODE_SIZE, cost, max_forwardable, refund};
use crate::host::{AccountLoad, Host, SStoreResult, SelfDestructResult};
use crate::memory::Memory;
use crate::opcode;
use crate::result::{Halt, InterpreterOutcome};
use crate::stack::Stack;

/// `BLOCKHASH` (EIP-2935 aparte): ancestros válidos = `[number-256, number-1]`.
const BLOCKHASH_WINDOW: u64 = 256;

/// Palabra de stack que el `resume` de una sub-call exitosa pushea.
const CALL_SUCCESS: u64 = 1;

/// Control de flujo interno de un paso del intérprete.
enum Control {
    /// Avanzar el pc `n` bytes (1 + inmediatos).
    Advance(usize),
    /// Salto validado a un `JUMPDEST`.
    Jump(usize),
    /// STOP (explícito o implícito).
    Stop,
    /// RETURN con `[offset, offset+len)` de memoria como output.
    Return { offset: u64, len: u64 },
    /// REVERT con output; devuelve el gas restante.
    Revert { offset: u64, len: u64 },
    /// Abrir un sub-frame: el pc avanza (la call ya se ejecutó desde la
    /// perspectiva de este frame) y el frame queda suspendido.
    Call(Box<CallInputs>),
    /// Abrir un frame de creación (CREATE/CREATE2): mismo tratamiento del pc
    /// que `Call`, pero el `resume` pushea una dirección, no un status.
    Create(Box<CreateInputs>),
}

/// Resultado de aplicar un `Control`: seguir el loop, suspender el frame o
/// terminar la ejecución. Factoreado de `run`/`run_traced` (misma lógica, dos
/// loops distintos por el hook de tracing opt-in — ver `tracer` module).
enum StepOutcome {
    Continue,
    Suspend(InterpreterAction),
    Done(InterpreterOutcome),
}

/// La máquina de pila. Ejecuta un frame de bytecode (con su `CallContext`) bajo
/// un límite de gas; el world access va por el seam `Host` (ADR-0002).
///
/// Desde el slice 2.5 el frame es **suspendible**: `run` no consume `self` y
/// devuelve una `InterpreterAction`. En `Call` el frame queda vivo con todo su
/// estado (stack/memory/pc/gas/returndata) hasta que el executor lo reanuda
/// con `resume`.
#[derive(Debug)]
pub struct Interpreter {
    context: CallContext,
    bytecode: Bytecode,
    stack: Stack,
    memory: Memory,
    gas: Gas,
    pc: usize,
    /// EIP-211: output del ÚLTIMO sub-call de ESTE frame. Vacío al entrar
    /// (nunca hereda el del padre).
    return_data: Bytes,
    /// Ventana `[offset, offset+len)` de memoria donde el `resume` vuelca la
    /// returndata; la fija el opcode de call (ya expandida y pagada).
    return_window: (u64, u64),
    /// Halt diferido de un `resume` fallido. Lo devuelve el próximo `run`:
    /// `resume` no puede fallar en silencio (fail-closed) ni obligar al
    /// executor a manejar un `Result` que en la práctica es inalcanzable.
    pending_halt: Option<Halt>,
}

impl Interpreter {
    /// Construye el intérprete para un frame. El código a ejecutar sale del
    /// `context` (`bytecode`), que también alimenta los opcodes de contexto.
    pub fn new(context: CallContext, gas_limit: u64) -> Self {
        let bytecode = Bytecode::analyze(context.bytecode.clone());
        Self {
            context,
            bytecode,
            stack: Stack::new(),
            memory: Memory::new(),
            gas: Gas::new(gas_limit),
            pc: 0,
            return_data: Bytes::new(),
            return_window: (0, 0),
            pending_halt: None,
        }
    }

    /// Conveniencia: frame "desnudo" (contexto en cero) para ejecutar código sin
    /// contexto de call — tests de opcodes puros y el arranque de una tx simple.
    pub fn for_code(code: Bytes, gas_limit: u64) -> Self {
        Self::new(CallContext::for_code(code), gas_limit)
    }

    /// Profundidad de este frame en la pila de calls (raíz = 0).
    pub fn depth(&self) -> usize {
        self.context.depth
    }

    /// Corre hasta que el frame termine **o** abra un sub-frame. `host` es
    /// todo lo que toca el mundo (ADR-0002); el intérprete no lo posee, solo
    /// lo pide prestado por el run.
    pub fn run(&mut self, host: &mut dyn Host) -> InterpreterAction {
        if let Some(reason) = self.pending_halt.take() {
            return InterpreterAction::Return(self.halt(reason));
        }
        loop {
            let Some(&op) = self.bytecode.code().get(self.pc) else {
                // STOP implícito al caer del final del código.
                return InterpreterAction::Return(self.success(Bytes::new()));
            };
            match self.step(op, host) {
                Ok(control) => match self.apply_control(control) {
                    StepOutcome::Continue => {}
                    StepOutcome::Suspend(action) => return action,
                    StepOutcome::Done(outcome) => return InterpreterAction::Return(outcome),
                },
                Err(reason) => return InterpreterAction::Return(self.halt(reason)),
            }
        }
    }

    /// Reanuda el frame con el resultado de su sub-call: status al stack,
    /// returndata a la ventana (truncada, **sin** zero-pad del resto), buffer
    /// completo para RETURNDATA* y re-acreditación del gas no usado.
    ///
    /// Infalible por contrato: la ventana ya fue expandida y pagada por el
    /// opcode de call, y un CALL saca 6-7 palabras del stack y pushea 1, así
    /// que el push no puede desbordar. Si aun así fallara, el halt queda
    /// pendiente y lo devuelve el próximo `run` — nunca se descarta.
    pub fn resume(&mut self, outcome: SubcallOutcome) {
        if let Err(reason) = self.apply_subcall(outcome) {
            self.pending_halt = Some(reason);
        }
    }

    /// Reanuda el frame con el resultado de un CREATE/CREATE2: la DIRECCIÓN
    /// nueva al stack (0 en cualquier fallo), returndata solo si el initcode
    /// revirtió (EIP-211) y re-acreditación del gas no usado.
    ///
    /// Infalible por el mismo contrato que `resume`: CREATE saca 3 palabras
    /// del stack (4 CREATE2) y pushea 1. No hay ventana de memoria de retorno.
    pub fn resume_create(&mut self, outcome: CreateOutcome) {
        let CreateOutcome {
            address,
            output,
            gas_remaining,
        } = outcome;
        self.gas.restore(gas_remaining);
        self.return_data = output;
        let word = address.map_or(U256::ZERO, word_from_address);
        if let Err(reason) = self.stack.push(word) {
            self.pending_halt = Some(reason);
        }
    }

    fn apply_subcall(&mut self, outcome: SubcallOutcome) -> Result<(), Halt> {
        let SubcallOutcome {
            success,
            output,
            gas_remaining,
        } = outcome;
        self.gas.restore(gas_remaining);
        let (offset, len) = self.return_window;
        let output_len = u64::try_from(output.len()).unwrap_or(u64::MAX);
        let copied = len.min(output_len);
        if copied > 0 {
            self.memory.write_padded(offset, &output, 0, copied)?;
        }
        self.return_data = output;
        let status = if success {
            U256::from(CALL_SUCCESS)
        } else {
            U256::ZERO
        };
        self.stack.push(status)
    }

    /// Idéntico a `run`, pero emite un `StepRecord` (EIP-3155) por opcode a
    /// `sink`. Detrás de la feature `tracer` (docs/tasks/003-tracer-eip3155.md):
    /// sin la feature este método NO EXISTE — cero contaminación del guest.
    ///
    /// El tracer OBSERVA: usa el mismo `step`/`apply_control` que `run`, así
    /// que no puede divergir en semántica de ejecución (Prohibido del task).
    ///
    /// El `RefundTrackingHost` lo construye **el executor**, no este método:
    /// con frames anidados el refund acumulado de EIP-3155 cruza los frames, y
    /// un wrapper por `run` lo reiniciaría en cada sub-call.
    #[cfg(feature = "tracer")]
    pub fn run_traced(
        &mut self,
        tracked: &mut crate::tracer::RefundTrackingHost<'_>,
        sink: &mut dyn crate::tracer::StepSink,
    ) -> InterpreterAction {
        use crate::tracer::{StepRecord, halt_name, op_name};

        if let Some(reason) = self.pending_halt.take() {
            return InterpreterAction::Return(self.halt(reason));
        }
        loop {
            let Some(&op) = self.bytecode.code().get(self.pc) else {
                return InterpreterAction::Return(self.success(Bytes::new()));
            };
            let pc = self.pc;
            let gas_before = self.gas.remaining();
            let stack = self.stack.as_slice().to_vec();
            let depth = self.context.depth;
            let mem_size = self.memory.len();
            let refund = tracked.total();
            match self.step(op, tracked) {
                Ok(control) => {
                    let gas_cost = gas_before.saturating_sub(self.gas.remaining());
                    sink.step(&StepRecord {
                        pc,
                        op,
                        op_name: op_name(op),
                        gas: gas_before,
                        gas_cost,
                        stack,
                        depth,
                        mem_size,
                        refund,
                        error: None,
                    });
                    match self.apply_control(control) {
                        StepOutcome::Continue => {}
                        StepOutcome::Suspend(action) => return action,
                        StepOutcome::Done(outcome) => return InterpreterAction::Return(outcome),
                    }
                }
                Err(reason) => {
                    // `gas_cost` es el delta REAL de este paso, igual que en el
                    // camino feliz. El spend-all de la trichotomy ocurre DESPUÉS
                    // de emitir el record, así que no entra acá — es la
                    // semántica de EIP-3155 y la del inspector de revm, contra
                    // el que la traza se compara paso a paso (task 004).
                    let gas_cost = gas_before.saturating_sub(self.gas.remaining());
                    sink.step(&StepRecord {
                        pc,
                        op,
                        op_name: op_name(op),
                        gas: gas_before,
                        gas_cost,
                        stack,
                        depth,
                        mem_size,
                        refund,
                        error: Some(halt_name(reason)),
                    });
                    return InterpreterAction::Return(self.halt(reason));
                }
            }
        }
    }

    /// Aplica un `Control` ya resuelto: avanza pc/jump, o termina la
    /// ejecución (Stop/Return/Revert). Compartido por `run` y `run_traced`.
    fn apply_control(&mut self, control: Control) -> StepOutcome {
        match control {
            Control::Advance(n) => {
                self.pc = self.pc.saturating_add(n);
                StepOutcome::Continue
            }
            Control::Jump(dest) => {
                self.pc = dest;
                StepOutcome::Continue
            }
            Control::Stop => StepOutcome::Done(self.success(Bytes::new())),
            Control::Return { offset, len } => StepOutcome::Done(match self.output(offset, len) {
                Ok(output) => self.success(output),
                Err(reason) => self.halt(reason),
            }),
            Control::Revert { offset, len } => StepOutcome::Done(match self.output(offset, len) {
                Ok(output) => InterpreterOutcome::Revert {
                    output,
                    gas_used: self.gas.used(),
                },
                Err(reason) => self.halt(reason),
            }),
            Control::Call(inputs) => {
                // El pc avanza ANTES de suspender: cuando el executor
                // reanude, el frame sigue por el opcode siguiente.
                self.pc = self.pc.saturating_add(1);
                StepOutcome::Suspend(InterpreterAction::Call(inputs))
            }
            Control::Create(inputs) => {
                self.pc = self.pc.saturating_add(1);
                StepOutcome::Suspend(InterpreterAction::Create(inputs))
            }
        }
    }

    /// Ejecuta el opcode `op`. Errores = `Halt` (el caller consume todo el gas).
    fn step(&mut self, op: u8, host: &mut dyn Host) -> Result<Control, Halt> {
        match op {
            opcode::STOP => Ok(Control::Stop),
            opcode::ADD => {
                self.gas.consume(cost::VERYLOW)?;
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                // Wrapping de protocolo (la EVM no paniquea en overflow aritmético).
                self.stack.push(a.wrapping_add(b))?;
                Ok(Control::Advance(1))
            }
            opcode::MUL => {
                self.gas.consume(cost::LOW)?;
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push(a.wrapping_mul(b))?;
                Ok(Control::Advance(1))
            }
            opcode::SUB => {
                self.gas.consume(cost::VERYLOW)?;
                let a = self.stack.pop()?;
                let b = self.stack.pop()?;
                self.stack.push(a.wrapping_sub(b))?;
                Ok(Control::Advance(1))
            }
            opcode::POP => {
                self.gas.consume(cost::BASE)?;
                self.stack.pop()?;
                Ok(Control::Advance(1))
            }
            opcode::MLOAD => {
                self.gas.consume(cost::VERYLOW)?;
                let offset = word_offset(self.stack.pop()?)?;
                self.memory.expand(offset, 32, &mut self.gas)?;
                let value = self.memory.load_word(offset)?;
                self.stack.push(value)?;
                Ok(Control::Advance(1))
            }
            opcode::MSTORE => {
                self.gas.consume(cost::VERYLOW)?;
                let offset = word_offset(self.stack.pop()?)?;
                let value = self.stack.pop()?;
                self.memory.expand(offset, 32, &mut self.gas)?;
                self.memory.store_word(offset, value)?;
                Ok(Control::Advance(1))
            }
            opcode::JUMP => {
                self.gas.consume(cost::MID)?;
                let dest = self.jump_dest()?;
                Ok(Control::Jump(dest))
            }
            opcode::JUMPI => {
                self.gas.consume(cost::HIGH)?;
                let dest_raw = self.stack.pop()?;
                let condition = self.stack.pop()?;
                if condition.is_zero() {
                    Ok(Control::Advance(1))
                } else {
                    Ok(Control::Jump(validate_jump(&self.bytecode, dest_raw)?))
                }
            }
            opcode::JUMPDEST => {
                self.gas.consume(cost::JUMPDEST)?;
                Ok(Control::Advance(1))
            }
            opcode::PUSH0 => {
                // EIP-3855 (Shanghai+; fork target = Prague, ficha 01).
                self.gas.consume(cost::BASE)?;
                self.stack.push(U256::ZERO)?;
                Ok(Control::Advance(1))
            }
            opcode::PUSH1..=opcode::PUSH32 => {
                self.gas.consume(cost::VERYLOW)?;
                let n = opcode::push_immediate_len(op);
                let value = self.read_push_immediates(n);
                self.stack.push(value)?;
                Ok(Control::Advance(n.saturating_add(1)))
            }
            opcode::DUP1..=opcode::DUP16 => {
                self.gas.consume(cost::VERYLOW)?;
                // `op ∈ [DUP1, DUP16]` garantiza que la resta no underflowea.
                let n = usize::from(op.wrapping_sub(opcode::DUP1)).saturating_add(1);
                self.stack.dup(n)?;
                Ok(Control::Advance(1))
            }
            opcode::SWAP1..=opcode::SWAP16 => {
                self.gas.consume(cost::VERYLOW)?;
                let n = usize::from(op.wrapping_sub(opcode::SWAP1)).saturating_add(1);
                self.stack.swap(n)?;
                Ok(Control::Advance(1))
            }
            opcode::KECCAK256 => self.keccak256_op(),
            opcode::ADDRESS => self.push_context_word(word_from_address(self.context.address)),
            // --- account access ajeno (slice 2.4; seam `Host`, EIP-2929/161) ---
            opcode::BALANCE => {
                let addr = address_from_word(self.stack.pop()?);
                let load = host.load_account(addr);
                self.charge_account_access(load.is_cold)?;
                self.stack.push(load.data.balance)?;
                Ok(Control::Advance(1))
            }
            opcode::CALLER => self.push_context_word(word_from_address(self.context.caller)),
            opcode::CALLVALUE => self.push_context_word(self.context.value),
            opcode::CALLDATALOAD => {
                self.gas.consume(cost::VERYLOW)?;
                let offset = self.stack.pop()?;
                let value = self.calldata_word(offset);
                self.stack.push(value)?;
                Ok(Control::Advance(1))
            }
            opcode::CALLDATASIZE => {
                let size = len_as_word(self.context.calldata.len());
                self.push_context_word(size)
            }
            opcode::CALLDATACOPY => {
                self.gas.consume(cost::VERYLOW)?;
                let dest = self.stack.pop()?;
                let src_offset = self.stack.pop()?;
                let len = self.stack.pop()?;
                let source = self.context.calldata.clone();
                self.copy_to_memory(dest, src_offset, len, &source)?;
                Ok(Control::Advance(1))
            }
            opcode::CODESIZE => {
                let size = len_as_word(self.bytecode.len());
                self.push_context_word(size)
            }
            opcode::CODECOPY => {
                self.gas.consume(cost::VERYLOW)?;
                let dest = self.stack.pop()?;
                let src_offset = self.stack.pop()?;
                let len = self.stack.pop()?;
                let source = self.context.bytecode.clone();
                self.copy_to_memory(dest, src_offset, len, &source)?;
                Ok(Control::Advance(1))
            }
            opcode::EXTCODESIZE => {
                let addr = address_from_word(self.stack.pop()?);
                let code = host.code_by_address(addr);
                self.charge_account_access(code.is_cold)?;
                self.stack.push(len_as_word(code.data.len()))?;
                Ok(Control::Advance(1))
            }
            opcode::EXTCODECOPY => self.extcodecopy_op(host),
            // --- returndata del último sub-call (slice 2.5; EIP-211) ---
            opcode::RETURNDATASIZE => {
                let size = len_as_word(self.return_data.len());
                self.push_context_word(size)
            }
            opcode::RETURNDATACOPY => self.returndatacopy_op(),
            opcode::EXTCODEHASH => {
                let addr = address_from_word(self.stack.pop()?);
                let load = host.load_account(addr);
                self.charge_account_access(load.is_cold)?;
                self.stack.push(extcodehash_word(&load.data))?;
                Ok(Control::Advance(1))
            }
            opcode::PC => {
                let pc = len_as_word(self.pc);
                self.push_context_word(pc)
            }
            opcode::MSIZE => {
                let size = len_as_word(self.memory.len());
                self.push_context_word(size)
            }
            opcode::GAS => {
                // El valor es el gas restante DESPUÉS de descontar el propio GAS.
                self.gas.consume(cost::BASE)?;
                self.stack.push(U256::from(self.gas.remaining()))?;
                Ok(Control::Advance(1))
            }
            // --- opcodes de entorno de tx/bloque (slice 2.3; seam `Host`) ---
            opcode::BLOCKHASH => {
                self.gas.consume(cost::BLOCKHASH)?;
                let number_raw = self.stack.pop()?;
                let hash = block_hash_word(host, number_raw);
                self.stack.push(hash)?;
                Ok(Control::Advance(1))
            }
            opcode::ORIGIN => self.push_context_word(word_from_address(host.tx().origin)),
            opcode::GASPRICE => self.push_context_word(U256::from(host.tx().gas_price)),
            opcode::COINBASE => self.push_context_word(word_from_address(host.env().coinbase)),
            opcode::TIMESTAMP => self.push_context_word(U256::from(host.env().timestamp)),
            opcode::NUMBER => self.push_context_word(U256::from(host.env().number)),
            opcode::PREVRANDAO => self.push_context_word(word_from_b256(host.env().prevrandao)),
            opcode::GASLIMIT => self.push_context_word(U256::from(host.env().gas_limit)),
            opcode::CHAINID => self.push_context_word(U256::from(host.env().chain_id)),
            opcode::SELFBALANCE => {
                self.gas.consume(cost::SELFBALANCE)?;
                let balance = host.self_balance(self.context.address);
                self.stack.push(balance)?;
                Ok(Control::Advance(1))
            }
            opcode::BASEFEE => self.push_context_word(U256::from(host.env().base_fee)),
            opcode::BLOBHASH => {
                self.gas.consume(cost::BLOBHASH)?;
                let index_raw = self.stack.pop()?;
                let hash = blob_hash_word(host, index_raw);
                self.stack.push(hash)?;
                Ok(Control::Advance(1))
            }
            opcode::BLOBBASEFEE => self.push_context_word(U256::from(host.env().blob_base_fee)),
            // --- opcodes de storage (slice 2.2; seam `Host`, ADR-0002) ---
            opcode::SLOAD => {
                let key = self.stack.pop()?;
                let load = host.sload(self.context.address, key);
                let gas_cost = if load.is_cold {
                    cost::COLD_SLOAD
                } else {
                    cost::WARM_ACCESS
                };
                self.gas.consume(gas_cost)?;
                self.stack.push(load.data)?;
                Ok(Control::Advance(1))
            }
            opcode::SSTORE => self.sstore_op(host),
            opcode::TLOAD => {
                self.gas.consume(cost::WARM_ACCESS)?;
                let key = self.stack.pop()?;
                let value = host.tload(self.context.address, key);
                self.stack.push(value)?;
                Ok(Control::Advance(1))
            }
            opcode::TSTORE => {
                if self.context.is_static {
                    return Err(Halt::StateChangeDuringStaticCall);
                }
                self.gas.consume(cost::WARM_ACCESS)?;
                let key = self.stack.pop()?;
                let value = self.stack.pop()?;
                host.tstore(self.context.address, key, value);
                Ok(Control::Advance(1))
            }
            opcode::LOG0..=opcode::LOG4 => {
                // `op ∈ [LOG0, LOG4]` garantiza que la resta no underflowea.
                let n_topics = usize::from(op.wrapping_sub(opcode::LOG0));
                self.log_op(host, n_topics)
            }
            // --- creación de contratos (slice 2.6; ADR-0002 §3) ---
            opcode::CREATE => self.create_op(false),
            opcode::CREATE2 => self.create_op(true),
            opcode::SELFDESTRUCT => self.selfdestruct_op(host),
            // --- sub-calls (slice 2.5; ADR-0002 §3) ---
            opcode::CALL => self.call_op(host, CallKind::Call),
            opcode::CALLCODE => self.call_op(host, CallKind::CallCode),
            opcode::DELEGATECALL => self.call_op(host, CallKind::DelegateCall),
            opcode::STATICCALL => self.call_op(host, CallKind::StaticCall),
            opcode::RETURN => {
                self.gas.consume(cost::ZERO)?;
                let (offset, len) = self.output_range()?;
                Ok(Control::Return { offset, len })
            }
            opcode::REVERT => {
                self.gas.consume(cost::ZERO)?;
                let (offset, len) = self.output_range()?;
                Ok(Control::Revert { offset, len })
            }
            opcode::INVALID => Err(Halt::InvalidFEOpcode),
            // Fail-closed: todo byte no asignado en el set actual halta.
            _ => Err(Halt::OpcodeNotFound),
        }
    }

    /// Lee los `n` bytes inmediatos de un PUSH, rellenando con ceros a la
    /// derecha si el código termina antes (semántica de la spec).
    fn read_push_immediates(&self, n: usize) -> U256 {
        let mut buf = [0u8; 32];
        let code = self.bytecode.code();
        let start = self.pc.saturating_add(1);
        let end = start.saturating_add(n).min(code.len());
        let available = code.get(start..end).unwrap_or(&[]);
        // Los inmediatos son los bytes ALTOS del valor: un PUSH2 truncado a un
        // byte vale `byte << 8`, no `byte`.
        let buf_start = 32usize.saturating_sub(n);
        let buf_end = buf_start.saturating_add(available.len());
        if let Some(slot) = buf.get_mut(buf_start..buf_end) {
            slot.copy_from_slice(available);
        }
        U256::from_be_bytes(buf)
    }

    fn jump_dest(&mut self) -> Result<usize, Halt> {
        let dest_raw = self.stack.pop()?;
        validate_jump(&self.bytecode, dest_raw)
    }

    /// Pop de `(offset, len)` para RETURN/REVERT + expansión de memoria.
    fn output_range(&mut self) -> Result<(u64, u64), Halt> {
        let offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        // Con len == 0 el offset no toca memoria (no se valida ni cobra).
        let offset = if len == 0 {
            0
        } else {
            word_offset(offset_raw)?
        };
        self.memory.expand(offset, len, &mut self.gas)?;
        Ok((offset, len))
    }

    fn output(&self, offset: u64, len: u64) -> Result<Bytes, Halt> {
        if len == 0 {
            return Ok(Bytes::new());
        }
        let slice = self.memory.slice(offset, len)?;
        Ok(Bytes::copy_from_slice(slice))
    }

    fn success(&self, output: Bytes) -> InterpreterOutcome {
        InterpreterOutcome::Success {
            output,
            gas_used: self.gas.used(),
        }
    }

    /// Opcodes de contexto que cuestan `G_base` y solo apilan un valor
    /// (ADDRESS/CALLER/CALLVALUE/CALLDATASIZE/CODESIZE/PC/MSIZE).
    fn push_context_word(&mut self, value: U256) -> Result<Control, Halt> {
        self.gas.consume(cost::BASE)?;
        self.stack.push(value)?;
        Ok(Control::Advance(1))
    }

    /// KECCAK256: hash de `[offset, offset+len)` de memoria. Gas: 30 + 6·palabras
    /// + expansión. `len == 0` no toca memoria y hashea el vacío (revm-idéntico).
    fn keccak256_op(&mut self) -> Result<Control, Halt> {
        let offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let words = len.div_ceil(32);
        let word_cost = words
            .checked_mul(cost::KECCAK256_WORD)
            .ok_or(Halt::OutOfGas)?;
        self.gas.consume(cost::KECCAK256)?;
        self.gas.consume(word_cost)?;
        let hash = if len == 0 {
            KECCAK256_EMPTY
        } else {
            let offset = word_offset(offset_raw)?;
            self.memory.expand(offset, len, &mut self.gas)?;
            keccak256(self.memory.slice(offset, len)?)
        };
        self.stack.push(U256::from_be_slice(hash.as_slice()))?;
        Ok(Control::Advance(1))
    }

    /// LOG0..LOG4: static ⇒ `StateChangeDuringStaticCall` (antes de tocar
    /// stack/memoria). Gas = `375 + 375·n_topics + 8·len` + expansión.
    /// Yellow Paper: µ_s[0]=offset, µ_s[1]=len, µ_s[2..2+n]=topics (topic1
    /// primero) — el orden de `pop` ya los deja así en `topics`.
    fn log_op(&mut self, host: &mut dyn Host, n_topics: usize) -> Result<Control, Halt> {
        if self.context.is_static {
            return Err(Halt::StateChangeDuringStaticCall);
        }
        let offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let mut topics = Vec::with_capacity(n_topics);
        for _ in 0..n_topics {
            let topic = self.stack.pop()?;
            topics.push(B256::new(topic.to_be_bytes()));
        }
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let n_topics_word = u64::try_from(n_topics).unwrap_or(u64::MAX);
        let topics_cost = n_topics_word
            .checked_mul(cost::LOG_TOPIC)
            .ok_or(Halt::OutOfGas)?;
        let data_cost = len.checked_mul(cost::LOG_DATA).ok_or(Halt::OutOfGas)?;
        let static_cost = cost::LOG
            .checked_add(topics_cost)
            .and_then(|c| c.checked_add(data_cost))
            .ok_or(Halt::OutOfGas)?;
        self.gas.consume(static_cost)?;
        let data = if len == 0 {
            Bytes::new()
        } else {
            let offset = word_offset(offset_raw)?;
            self.memory.expand(offset, len, &mut self.gas)?;
            Bytes::copy_from_slice(self.memory.slice(offset, len)?)
        };
        host.log(Log {
            address: self.context.address,
            topics,
            data,
        });
        Ok(Control::Advance(1))
    }

    /// SSTORE (EIP-2200/2929/3529), en el orden de la spec: sentry → gate de
    /// static → costo (cold surcharge + base) → refund.
    fn sstore_op(&mut self, host: &mut dyn Host) -> Result<Control, Halt> {
        // Sentry EIP-2200: protege el stipend de 2300 que financia CALL con
        // value (sin stack pops todavía — el chequeo no los necesita).
        if self.gas.remaining() <= cost::SSTORE_SENTRY {
            return Err(Halt::OutOfGas);
        }
        if self.context.is_static {
            return Err(Halt::StateChangeDuringStaticCall);
        }
        // Yellow Paper: µ_s[0] = key (tope), µ_s[1] = value.
        let key = self.stack.pop()?;
        let value = self.stack.pop()?;
        let load = host.sstore(self.context.address, key, value);
        let SStoreResult {
            original,
            current,
            new,
        } = load.data;
        let base = if new == current {
            cost::WARM_ACCESS
        } else if current == original && original.is_zero() {
            cost::SSTORE_SET
        } else if current == original {
            cost::SSTORE_RESET
        } else {
            cost::WARM_ACCESS
        };
        let surcharge = if load.is_cold { cost::COLD_SLOAD } else { 0 };
        let gas_cost = surcharge.checked_add(base).ok_or(Halt::OutOfGas)?;
        self.gas.consume(gas_cost)?;
        sstore_refund(host, original, current, new);
        Ok(Control::Advance(1))
    }

    /// Lee 32 bytes de calldata desde `offset`, con relleno de ceros más allá del
    /// final (CALLDATALOAD). Un offset irrepresentable ⇒ ventana toda-cero.
    fn calldata_word(&self, offset_raw: U256) -> U256 {
        let mut buf = [0u8; 32];
        let start = usize::try_from(offset_raw).unwrap_or(usize::MAX);
        for (i, slot) in buf.iter_mut().enumerate() {
            if let Some(byte) = start
                .checked_add(i)
                .and_then(|idx| self.context.calldata.get(idx))
            {
                *slot = *byte;
            }
        }
        U256::from_be_slice(&buf)
    }

    /// EIP-2929: costo de un acceso a CUENTA (BALANCE/EXTCODESIZE/
    /// EXTCODECOPY/EXTCODEHASH) — distinto del de storage (`(addr, slot)`).
    fn charge_account_access(&mut self, is_cold: bool) -> Result<(), Halt> {
        let gas_cost = if is_cold {
            cost::COLD_ACCOUNT_ACCESS
        } else {
            cost::WARM_ACCOUNT_ACCESS
        };
        self.gas.consume(gas_cost)
    }

    /// EXTCODECOPY(address, destOffset, offset, length): access cost de la
    /// cuenta + `3·palabras` de copia + expansión (mismo patrón que
    /// `copy_to_memory`/CODECOPY), zero-padded más allá del código real.
    fn extcodecopy_op(&mut self, host: &mut dyn Host) -> Result<Control, Halt> {
        let addr = address_from_word(self.stack.pop()?);
        let code = host.code_by_address(addr);
        self.charge_account_access(code.is_cold)?;
        let dest = self.stack.pop()?;
        let src_offset = self.stack.pop()?;
        let len = self.stack.pop()?;
        self.copy_to_memory(dest, src_offset, len, &code.data)?;
        Ok(Control::Advance(1))
    }

    /// RETURNDATACOPY(destOffset, offset, length) — EIP-211.
    ///
    /// **FOOTGUN de consenso:** a diferencia de CALLDATACOPY/CODECOPY, leer
    /// más allá del buffer NO se zero-padea: es `Halt`. El chequeo usa
    /// `offset + length` saturado, así que un `length == 0` con un offset
    /// fuera del buffer también haltea (semántica de revm y de la spec).
    fn returndatacopy_op(&mut self) -> Result<Control, Halt> {
        self.gas.consume(cost::VERYLOW)?;
        let dest_raw = self.stack.pop()?;
        let src_offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let len = usize::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let src_offset = usize::try_from(src_offset_raw).unwrap_or(usize::MAX);
        if src_offset.saturating_add(len) > self.return_data.len() {
            return Err(Halt::OutOfOffset);
        }
        let source = self.return_data.clone();
        self.copy_to_memory(dest_raw, src_offset_raw, len_raw, &source)?;
        Ok(Control::Advance(1))
    }

    /// CALL/CALLCODE/DELEGATECALL/STATICCALL — el opcode resuelve la tabla de
    /// contexto (spec §3) y TODO el gas; el executor solo abre el frame.
    ///
    /// Orden de cobro (task 007 §4, verificado contra revm — ver attempt_log
    /// it.1: revm cobra la memoria antes de los fijos, pero el total y las
    /// rutas de fallo son idénticos porque el 63/64 se calcula sobre el
    /// `remaining` posterior a todos ellos):
    /// 1. access del target (EIP-2929: cold 2600 / warm 100)
    /// 2. `G_callvalue` (9000) si CALL/CALLCODE con `value > 0`
    /// 3. `G_newaccount` (25000) solo si CALL con `value > 0` a cuenta muerta
    /// 4. expansión de memoria (ventana de args y de retorno)
    /// 5. `min(pedido, remaining − ⌊remaining/64⌋)` (EIP-150), cobrado
    /// 6. `+2300` de stipend al sub-frame si mueve value (gratis para el caller)
    fn call_op(&mut self, host: &mut dyn Host, kind: CallKind) -> Result<Control, Halt> {
        // Yellow Paper: µ_s[0]=gas, µ_s[1]=address, [µ_s[2]=value], luego las
        // dos ventanas de memoria.
        let requested_gas = self.stack.pop()?;
        let code_address = address_from_word(self.stack.pop()?);
        let value = if kind.takes_value_argument() {
            self.stack.pop()?
        } else {
            U256::ZERO
        };
        let moves_value = kind.takes_value_argument() && !value.is_zero();
        // EIP-214: mover value desde un contexto estático es halt. Solo CALL
        // (CALLCODE transfiere a sí mismo: revm no lo gatea).
        if self.context.is_static && kind == CallKind::Call && moves_value {
            return Err(Halt::StateChangeDuringStaticCall);
        }
        let in_offset_raw = self.stack.pop()?;
        let in_len_raw = self.stack.pop()?;
        let out_offset_raw = self.stack.pop()?;
        let out_len_raw = self.stack.pop()?;

        // (1) access del target.
        let target_account = host.load_account(code_address);
        self.charge_account_access(target_account.is_cold)?;
        // (2) surcharge por mover value.
        if moves_value {
            self.gas.consume(cost::CALL_VALUE)?;
        }
        // (3) creación de cuenta: SOLO CALL, solo con value, solo si está
        // muerta (EIP-161: inexistente o vacía).
        if kind == CallKind::Call && moves_value && target_account.data.is_empty {
            self.gas.consume(cost::NEW_ACCOUNT)?;
        }
        // (4) las dos ventanas de memoria.
        let (in_offset, in_len) = self.memory_window(in_offset_raw, in_len_raw)?;
        let (out_offset, out_len) = self.memory_window(out_offset_raw, out_len_raw)?;
        let input = if in_len == 0 {
            Bytes::new()
        } else {
            Bytes::copy_from_slice(self.memory.slice(in_offset, in_len)?)
        };
        // (5) EIP-150.
        let forwarded = u64::try_from(requested_gas)
            .unwrap_or(u64::MAX)
            .min(max_forwardable(self.gas.remaining()));
        self.gas.consume(forwarded)?;
        // (6) el stipend se SUMA al hijo; no se le cobra al caller.
        let stipend = if moves_value { cost::CALL_STIPEND } else { 0 };
        let gas_limit = forwarded.saturating_add(stipend);

        self.return_window = (out_offset, out_len);
        self.return_data = Bytes::new();
        Ok(Control::Call(Box::new(self.call_inputs(
            kind,
            code_address,
            value,
            input,
            gas_limit,
        ))))
    }

    /// CREATE (0xF0) / CREATE2 (0xF5, EIP-1014).
    ///
    /// Orden de cobro **verificado contra revm** (`instructions/contract.rs::create`,
    /// task 008 attempt_log it.1 — el orden del spec de la task estaba mal):
    /// 1. gate de static ANTES de tocar el stack (EIP-214).
    /// 2. pop `value, offset, len` (el `salt` de CREATE2 se popea DESPUÉS).
    /// 3. **solo si `len != 0`**: EIP-3860 (`len > MAX_INITCODE_SIZE` ⇒ halt)
    ///    → `2·⌈len/32⌉` → expansión de memoria → copia del initcode. Con
    ///    `len == 0` el offset ni se valida ni cobra (regla de RETURN/REVERT).
    /// 4. `G_create` (32000); CREATE2 popea `salt` y cobra `32000 + 6·⌈len/32⌉`
    ///    (el hash del initcode que deriva la dirección).
    /// 5. `min(remaining, remaining − ⌊remaining/64⌋)` (EIP-150), cobrado.
    ///    **Sin stipend**: CREATE no tiene equivalente al 2300 de CALL.
    ///
    /// **NO se cobra `NEW_ACCOUNT`**: los 32000 de `G_create` ya incluyen crear
    /// la cuenta (el Yellow Paper los separa de `G_newaccount`, que es de
    /// CALL-con-value y SELFDESTRUCT).
    fn create_op(&mut self, is_create2: bool) -> Result<Control, Halt> {
        if self.context.is_static {
            return Err(Halt::StateChangeDuringStaticCall);
        }
        let value = self.stack.pop()?;
        let offset_raw = self.stack.pop()?;
        let len_raw = self.stack.pop()?;
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;

        let init_code = if len == 0 {
            Bytes::new()
        } else {
            // EIP-3860: el tope se chequea ANTES de cobrar por palabra.
            if len > initcode_size_limit() {
                return Err(Halt::CreateInitCodeSizeLimit);
            }
            let words = len.div_ceil(32);
            let initcode_cost = words
                .checked_mul(cost::INITCODE_WORD)
                .ok_or(Halt::OutOfGas)?;
            self.gas.consume(initcode_cost)?;
            let offset = word_offset(offset_raw)?;
            self.memory.expand(offset, len, &mut self.gas)?;
            Bytes::copy_from_slice(self.memory.slice(offset, len)?)
        };

        let kind = if is_create2 {
            let salt = self.stack.pop()?;
            let hash_cost = len
                .div_ceil(32)
                .checked_mul(cost::KECCAK256_WORD)
                .ok_or(Halt::OutOfGas)?;
            self.gas.consume(cost::CREATE)?;
            self.gas.consume(hash_cost)?;
            CreateKind::Create2 { salt }
        } else {
            self.gas.consume(cost::CREATE)?;
            CreateKind::Create
        };

        let gas_limit = max_forwardable(self.gas.remaining());
        self.gas.consume(gas_limit)?;

        // El buffer de returndata se limpia ya: si el executor decide no
        // ejecutar (depth/fondos/colisión), el frame no debe seguir viendo el
        // output de una call anterior.
        self.return_data = Bytes::new();
        Ok(Control::Create(Box::new(CreateInputs {
            creator: self.context.address,
            kind,
            value,
            init_code,
            gas_limit,
            is_static: self.context.is_static,
        })))
    }

    /// SELFDESTRUCT (0xFF) — EIP-6780 (Cancun+) + EIP-2929 + EIP-3529.
    ///
    /// Orden verificado contra revm (`instructions/host.rs::selfdestruct` +
    /// `gas_params::selfdestruct_cost`):
    /// 1. gate de static ANTES de popear (EIP-214).
    /// 2. base `G_selfdestruct` (5000) — en revm es el `static_gas` del opcode.
    /// 3. pop del `beneficiary` y efecto en el host (transfer + marca 6780).
    /// 4. `+G_newaccount` (25000) si la cuenta tenía balance Y el beneficiary
    ///    estaba muerto (EIP-161) ANTES del transfer.
    /// 5. `+2600` si el beneficiary estaba frío. **A diferencia de
    ///    BALANCE/EXTCODE\*, warm no cobra nada extra** sobre los 5000.
    /// 6. **Sin refund**: EIP-3529 (London) lo eliminó; el fork target es
    ///    Prague.
    ///
    /// Termina el frame como un STOP (output vacío).
    fn selfdestruct_op(&mut self, host: &mut dyn Host) -> Result<Control, Halt> {
        if self.context.is_static {
            return Err(Halt::StateChangeDuringStaticCall);
        }
        self.gas.consume(cost::SELFDESTRUCT)?;
        let beneficiary = address_from_word(self.stack.pop()?);
        let load = host.selfdestruct(self.context.address, beneficiary);
        let SelfDestructResult {
            had_value,
            target_exists,
            previously_destroyed: _,
        } = load.data;
        if had_value && !target_exists {
            self.gas.consume(cost::NEW_ACCOUNT)?;
        }
        if load.is_cold {
            self.gas.consume(cost::SELFDESTRUCT_COLD)?;
        }
        Ok(Control::Stop)
    }

    /// Tabla de contexto de la spec §3, en un solo lugar: quién es `ADDRESS`,
    /// quién `CALLER`, qué `CALLVALUE` ve el sub-frame y qué se transfiere.
    fn call_inputs(
        &self,
        kind: CallKind,
        code_address: Address,
        value: U256,
        input: Bytes,
        gas_limit: u64,
    ) -> CallInputs {
        let (target, caller, apparent_value, is_static) = match kind {
            // Contexto y storage del target; caller = quien ejecuta.
            CallKind::Call => (
                code_address,
                self.context.address,
                value,
                self.context.is_static,
            ),
            // Código del target, storage PROPIO.
            CallKind::CallCode => (
                self.context.address,
                self.context.address,
                value,
                self.context.is_static,
            ),
            // Caller y value HEREDADOS del frame actual.
            CallKind::DelegateCall => (
                self.context.address,
                self.context.caller,
                self.context.value,
                self.context.is_static,
            ),
            // Como CALL con value 0, y `is_static` para TODA la sub-ejecución.
            CallKind::StaticCall => (code_address, self.context.address, U256::ZERO, true),
        };
        CallInputs {
            kind,
            code_address,
            target,
            caller,
            transfer_value: if kind.takes_value_argument() {
                value
            } else {
                U256::ZERO
            },
            value: apparent_value,
            input,
            gas_limit,
            is_static,
        }
    }

    /// Pop ya hecho: expande `[offset, offset+len)` cobrando el delta. Con
    /// `len == 0` el offset no toca memoria (no se valida ni cobra) — misma
    /// regla que RETURN/REVERT.
    fn memory_window(&mut self, offset_raw: U256, len_raw: U256) -> Result<(u64, u64), Halt> {
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let offset = if len == 0 {
            0
        } else {
            word_offset(offset_raw)?
        };
        self.memory.expand(offset, len, &mut self.gas)?;
        Ok((offset, len))
    }

    /// Cuerpo común de CALLDATACOPY/CODECOPY: gas `3·palabras` (base `G_verylow`
    /// ya cobrado por el caller) + expansión, y copia zero-padded a memoria.
    fn copy_to_memory(
        &mut self,
        dest_raw: U256,
        src_offset_raw: U256,
        len_raw: U256,
        source: &[u8],
    ) -> Result<(), Halt> {
        let len = u64::try_from(len_raw).map_err(|_| Halt::OutOfGas)?;
        let words = len.div_ceil(32);
        let copy_cost = words.checked_mul(cost::COPY).ok_or(Halt::OutOfGas)?;
        self.gas.consume(copy_cost)?;
        if len == 0 {
            return Ok(());
        }
        let dest = word_offset(dest_raw)?;
        self.memory.expand(dest, len, &mut self.gas)?;
        let src_offset = usize::try_from(src_offset_raw).unwrap_or(usize::MAX);
        self.memory.write_padded(dest, source, src_offset, len)
    }

    /// Semántica de Halt: consume TODO el gas.
    fn halt(&mut self, reason: Halt) -> InterpreterOutcome {
        self.gas.consume_all();
        InterpreterOutcome::Halt {
            reason,
            gas_used: self.gas.used(),
        }
    }
}

/// `MAX_INITCODE_SIZE` (EIP-3860) como `u64`, para comparar contra el `len`
/// del stack sin castear el input hostil hacia abajo. La constante es 49152:
/// entra en `u64` en cualquier plataforma; el `unwrap_or` es defensa muerta.
fn initcode_size_limit() -> u64 {
    u64::try_from(MAX_INITCODE_SIZE).unwrap_or(u64::MAX)
}

/// Una dirección como palabra de stack: 20 bytes big-endian right-aligned.
fn word_from_address(addr: Address) -> U256 {
    U256::from_be_slice(addr.as_slice())
}

/// Una palabra de stack como dirección (BALANCE/EXTCODE*): los 160 bits bajos
/// (spec: los altos se truncan, no se valida que sean cero).
fn address_from_word(word: U256) -> Address {
    let bytes = word.to_be_bytes::<32>();
    let mut addr_bytes = [0u8; 20];
    // `bytes` tiene 32 elementos: el slice `[12..32]` siempre entra.
    if let Some(low) = bytes.get(12..32) {
        addr_bytes.copy_from_slice(low);
    }
    Address::new(addr_bytes)
}

/// EXTCODEHASH: cuenta vacía (EIP-161) o inexistente ⇒ 0 (footgun clásico:
/// NUNCA `keccak("")`); si no, su `code_hash` (EOA no-vacía ⇒
/// `KECCAK256_EMPTY`, contrato ⇒ el hash real — ambos ya vienen así en
/// `AccountLoad` desde el `Host`).
fn extcodehash_word(account: &AccountLoad) -> U256 {
    if account.is_empty {
        U256::ZERO
    } else {
        word_from_b256(account.code_hash)
    }
}

/// Un hash de 32 bytes como palabra de stack (PREVRANDAO/BLOCKHASH/BLOBHASH).
fn word_from_b256(hash: B256) -> U256 {
    U256::from_be_slice(hash.as_slice())
}

/// BLOCKHASH: fuera de la ventana `[number-256, number-1]` ⇒ 0 SIN consultar
/// al host (protocolo, no fallo de lectura). EIP-2935: ver KNOWN en `opcode.rs`.
fn block_hash_word(host: &mut dyn Host, number_raw: U256) -> U256 {
    let current = host.env().number;
    let Ok(number) = u64::try_from(number_raw) else {
        return U256::ZERO;
    };
    let in_window = number < current && current.saturating_sub(number) <= BLOCKHASH_WINDOW;
    if !in_window {
        return U256::ZERO;
    }
    word_from_b256(host.block_hash(number))
}

/// BLOBHASH: `tx.blob_hashes[index]` o 0 si el índice no entra en `usize` o
/// está fuera de rango (incl. tx no-blob ⇒ lista vacía).
fn blob_hash_word(host: &mut dyn Host, index_raw: U256) -> U256 {
    let Ok(index) = usize::try_from(index_raw) else {
        return U256::ZERO;
    };
    host.tx()
        .blob_hashes
        .get(index)
        .map_or(U256::ZERO, |hash| word_from_b256(*hash))
}

/// Una longitud (`usize`) como palabra de stack. Un valor que no entra en u64
/// se satura (en la práctica inalcanzable: la memoria/código están acotados por
/// gas mucho antes).
fn len_as_word(len: usize) -> U256 {
    U256::from(u64::try_from(len).unwrap_or(u64::MAX))
}

/// Offset de memoria desde el stack. Un offset que no entra en u64 es
/// impagable (el costo de expansión desborda) ⇒ OOG.
fn word_offset(raw: U256) -> Result<u64, Halt> {
    u64::try_from(raw).map_err(|_| Halt::OutOfGas)
}

/// Refund de SSTORE (EIP-3529), literal a la spec (números calculados a mano
/// en los tests, no derivados de este código).
fn sstore_refund(host: &mut dyn Host, original: U256, current: U256, new: U256) {
    if current == original {
        // Primer cambio del slot en esta tx: se libera un `original != 0`.
        if current != new && !original.is_zero() && new.is_zero() {
            host.refund(refund::SSTORE_CLEARS);
        }
        return;
    }
    // Slot "dirty": ya se tocó antes en esta misma tx.
    if !original.is_zero() {
        if current.is_zero() {
            host.refund(-refund::SSTORE_CLEARS);
        }
        if new.is_zero() {
            host.refund(refund::SSTORE_CLEARS);
        }
    }
    if new == original {
        if original.is_zero() {
            host.refund(refund::SSTORE_SET_UNDO);
        } else {
            host.refund(refund::SSTORE_RESET_UNDO);
        }
    }
}

/// Valida un destino de salto: debe entrar en usize Y ser un `JUMPDEST` en
/// posición de opcode. Todo lo demás es `Halt::InvalidJump` (fail-closed).
fn validate_jump(bytecode: &Bytecode, dest_raw: U256) -> Result<usize, Halt> {
    let dest = usize::try_from(dest_raw).map_err(|_| Halt::InvalidJump)?;
    if !bytecode.is_valid_jumpdest(dest) {
        return Err(Halt::InvalidJump);
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interpreter_at_start(code: &[u8]) -> Interpreter {
        Interpreter::for_code(Bytes::copy_from_slice(code), 0)
    }

    #[test]
    fn push_immediates_read_full_width() {
        // PUSH2 0x12 0x34 → 0x1234.
        let interpreter = interpreter_at_start(&[0x61, 0x12, 0x34]);
        assert_eq!(interpreter.read_push_immediates(2), U256::from(0x1234u64));
    }

    #[test]
    fn truncated_push_immediates_zero_pad_low_bytes() {
        // PUSH2 con un solo byte disponible: el byte leído es el ALTO del par
        // (spec: los bytes faltantes tras el fin del código son cero).
        let interpreter = interpreter_at_start(&[0x61, 0x12]);
        assert_eq!(interpreter.read_push_immediates(2), U256::from(0x1200u64));
    }

    #[test]
    fn push_with_no_immediates_available_reads_zero() {
        // PUSH32 como último byte del código: valor = 0.
        let interpreter = interpreter_at_start(&[0x7F]);
        assert_eq!(interpreter.read_push_immediates(32), U256::ZERO);
    }
}
