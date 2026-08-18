//! La **gramática** del generador: programas válidos por construcción.
//!
//! El riesgo central de un fuzzer de EVM no es técnico: un generador uniforme
//! sobre `0x00..=0xFF` produce mayoría de bytes no asignados, casi todo caso haltea en el primer opcode, los dos motores
//! haltean igual y el diferencial contesta `[SAME]`. Se pueden quemar mil
//! horas-core sin haber probado nada.
//!
//! Por eso acá no se sortean bytes: se sortean **instrucciones con su aridad
//! satisfecha**. Reglas que sostiene esta gramática, todas verificables con la
//! métrica de cobertura (`fuzz::coverage`):
//!
//! - **La pila alcanza.** Un `ADD` se emite con sus dos operandos ya
//!   empujados; nunca se apila un opcode sobre una pila que no lo sostiene.
//! - **Los saltos caen en `JUMPDEST` reales**, y solo hacia adelante: un salto
//!   hacia atrás es un lazo, y un lazo quema el gas de la tx entera sin
//!   ejecutar más opcodes DISTINTOS. La cobertura es el objetivo, no el
//!   tiempo de CPU.
//! - **Los opcodes del fork.** Se emite solo lo activado en el fork del caso.
//!   El gating por fork ya tiene su propio set (`opcode-fork`);
//!   meterlo acá gastaría casos en un halt inmediato que no prueba nada nuevo.
//! - **Las magnitudes están acotadas.** Un `EXP` con exponente de 256 bits o
//!   un `MSTORE` en el offset 2^200 no ejercitan una regla: consumen el gas de
//!   la tx en el primer opcode. Los operandos que gobiernan gas (offsets de
//!   memoria, tamaños, exponentes, gas reenviado) salen de distribuciones
//!   acotadas; los operandos que solo gobiernan *valor* salen del conjunto de
//!   bordes de 256 bits.

use repo_b_common::primitives::Address;
use repo_b_evm::types::Spec;

use crate::fuzz::opcodes;
use crate::fuzz::program::{GENERATED_JUMP_WIDTH, Instruction, Program};
use crate::fuzz::rng::Rng;

/// Tope de instrucciones de un programa generado. Acotar todo recurso
/// alimentado por el generador es la misma regla que acota los recursos
/// alimentados por input externo.
pub const MAX_PROGRAM_STEPS: usize = 64;
/// Tope de offsets/tamaños de memoria. 512 bytes son 16 palabras: expansión
/// cuadrática visible, costo despreciable.
const MAX_MEMORY_OFFSET: u64 = 512;
const MAX_MEMORY_SIZE: u64 = 128;
/// Tope del exponente de `EXP`. El gas de EIP-160 es por byte del exponente:
/// con 2 bytes se ejercita el término variable sin quemar el presupuesto.
const MAX_EXPONENT: u64 = 65_535;
/// Gas reenviado a una sub-call. Acotado a propósito: con "todo el gas" el
/// 63/64 le deja al caller una miga y el frame de arriba deja de ejecutar.
const MAX_FORWARDED_GAS: u64 = 100_000;
/// Slots de storage que el programa toca. Pocos y repetidos ⇒ las
/// transiciones de EIP-2200 (0→x, x→0, x→y) ocurren de verdad.
const STORAGE_KEY_SPACE: u64 = 8;

/// Las direcciones que un programa generado puede nombrar.
#[derive(Debug, Clone)]
pub struct AddressPool {
    pub addresses: Vec<Address>,
}

/// Un opcode simple: aridad conocida, operandos sin restricción de magnitud.
struct Simple {
    op: u8,
    pops: usize,
    weight: u32,
}

/// La tabla ponderada de opcodes "de palabra": aritmética, comparación y
/// bitwise. Son el grueso del set implementado y el más barato de ejecutar,
/// así que llevan peso alto.
const SIMPLE_OPS: &[Simple] = &[
    Simple {
        op: opcodes::ADD,
        pops: 2,
        weight: 6,
    },
    Simple {
        op: opcodes::MUL,
        pops: 2,
        weight: 5,
    },
    Simple {
        op: opcodes::SUB,
        pops: 2,
        weight: 6,
    },
    Simple {
        op: opcodes::DIV,
        pops: 2,
        weight: 5,
    },
    Simple {
        op: opcodes::SDIV,
        pops: 2,
        weight: 5,
    },
    Simple {
        op: opcodes::MOD,
        pops: 2,
        weight: 5,
    },
    Simple {
        op: opcodes::SMOD,
        pops: 2,
        weight: 5,
    },
    Simple {
        op: opcodes::ADDMOD,
        pops: 3,
        weight: 4,
    },
    Simple {
        op: opcodes::MULMOD,
        pops: 3,
        weight: 4,
    },
    Simple {
        op: opcodes::SIGNEXTEND,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::LT,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::GT,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::SLT,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::SGT,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::EQ,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::ISZERO,
        pops: 1,
        weight: 4,
    },
    Simple {
        op: opcodes::AND,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::OR,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::XOR,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::NOT,
        pops: 1,
        weight: 4,
    },
    Simple {
        op: opcodes::BYTE,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::SHL,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::SHR,
        pops: 2,
        weight: 4,
    },
    Simple {
        op: opcodes::SAR,
        pops: 2,
        weight: 4,
    },
    // Costo fijo y sin expansión de memoria: un offset gigante devuelve ceros,
    // no gas. Por eso entra acá y no en la familia de memoria.
    Simple {
        op: opcodes::CALLDATALOAD,
        pops: 1,
        weight: 5,
    },
];

/// Opcodes de contexto sin operandos: apilan y ya. Baratos y numerosos.
const NULLARY_OPS: &[u8] = &[
    opcodes::ADDRESS,
    opcodes::ORIGIN,
    opcodes::CALLER,
    opcodes::CALLVALUE,
    opcodes::CALLDATASIZE,
    opcodes::CODESIZE,
    opcodes::GASPRICE,
    opcodes::RETURNDATASIZE,
    opcodes::COINBASE,
    opcodes::TIMESTAMP,
    opcodes::NUMBER,
    opcodes::PREVRANDAO,
    opcodes::GASLIMIT,
    opcodes::CHAINID,
    opcodes::SELFBALANCE,
    opcodes::BASEFEE,
    opcodes::PC,
    opcodes::MSIZE,
    opcodes::GAS,
];

/// Familias de instrucción, con su peso. El peso es la decisión de diseño de
/// este módulo: dice a qué superficie de consenso se le dedican casos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Simple,
    Nullary,
    Exp,
    Memory,
    Storage,
    Transient,
    Log,
    ExternalAccount,
    Call,
    Create,
    StackShuffle,
    Jump,
    Keccak,
    Copy,
    BlockHash,
    Blob,
    /// `PUSHn` de un ancho sorteado. Existe porque los 32 `PUSH` son 32
    /// opcodes DISTINTOS con 32 costos de decodificación distintos, y si el
    /// ancho lo decidiera siempre la magnitud del valor, los anchos raros
    /// (`PUSH6`, `PUSH11`, `PUSH27`…) no se ejecutarían nunca. Medido: sin
    /// esta familia, 20 de los 32 quedaban sin tocar.
    PushWidth,
    /// `DUP`/`SWAP` profundos, con la pila cargada a propósito. Misma razón:
    /// `DUP16` no aparece solo, porque la pila casi nunca llega a 16.
    DeepStack,
}

const FAMILIES: &[(Family, u32)] = &[
    (Family::Simple, 22),
    (Family::Nullary, 10),
    (Family::Exp, 4),
    (Family::Memory, 10),
    (Family::Storage, 9),
    (Family::Transient, 4),
    (Family::Log, 7),
    (Family::ExternalAccount, 6),
    (Family::Call, 6),
    (Family::Create, 3),
    (Family::StackShuffle, 6),
    (Family::Jump, 4),
    (Family::Keccak, 4),
    (Family::Copy, 4),
    (Family::BlockHash, 2),
    (Family::Blob, 2),
    (Family::PushWidth, 6),
    (Family::DeepStack, 5),
];

/// Los terminadores, con su peso. `STOP` domina porque es el único que deja
/// el frame en éxito sin output.
const TERMINATORS: &[(u8, u32)] = &[
    (opcodes::STOP, 10),
    (opcodes::RETURN, 6),
    (opcodes::REVERT, 4),
    (opcodes::INVALID, 2),
    (opcodes::SELFDESTRUCT, 2),
];

/// Estado de emisión de un programa.
struct Builder<'a> {
    instructions: Vec<Instruction>,
    /// Altura simulada de la pila. Es una **heurística de emisión**, no una
    /// verdad: tras un salto la altura real depende del camino. Sirve para no
    /// emitir un `SWAP16` sobre una pila de 2, que es un halt inmediato.
    height: usize,
    /// Etiquetas prometidas por un salto y todavía no emitidas. Se vacían
    /// antes del terminador: un salto sin destino es un halt, y acá el objetivo
    /// es ejecutar.
    pending_labels: Vec<u32>,
    next_label: u32,
    pool: &'a AddressPool,
    spec: Spec,
}

/// Genera un programa de la gramática.
pub fn generate_program(rng: &mut Rng, pool: &AddressPool, spec: Spec, steps: usize) -> Program {
    let mut builder = Builder {
        instructions: Vec::new(),
        height: 0,
        pending_labels: Vec::new(),
        next_label: 0,
        pool,
        spec,
    };
    let steps = steps.min(MAX_PROGRAM_STEPS);
    for _ in 0..steps {
        builder.emit_family(rng);
        // Una etiqueta pendiente se cierra en el medio del programa (y no
        // toda al final) para que un salto hacia adelante caiga ADENTRO del
        // cuerpo, no en el terminador.
        if !builder.pending_labels.is_empty() && rng.chance(1, 3) {
            builder.flush_one_label();
        }
    }
    builder.flush_all_labels();
    builder.emit_terminator(rng);
    Program::new(builder.instructions)
}

/// El generador **uniforme**: bytes al azar, sin gramática. No se usa en la
/// campaña — existe para que la métrica de cobertura tenga contra qué
/// medirse. Si la métrica no se desploma acá, la métrica no
/// mide nada.
pub fn generate_uniform_program(rng: &mut Rng, bytes: usize) -> Program {
    let mut raw = Vec::with_capacity(bytes);
    for _ in 0..bytes {
        raw.push(u8::try_from(rng.below(256)).unwrap_or(0));
    }
    Program::new(vec![Instruction::Raw(raw)])
}

impl Builder<'_> {
    fn push_bytes(&mut self, data: Vec<u8>) {
        self.instructions.push(Instruction::Push(data));
        self.height = self.height.saturating_add(1);
    }

    fn op(&mut self, op: u8, pops: usize, pushes: usize) {
        self.instructions.push(Instruction::Op(op));
        self.height = self.height.saturating_sub(pops).saturating_add(pushes);
    }

    /// Empuja los operandos de un opcode en el orden correcto: el primero de
    /// `args` es el que el opcode **saca primero** (el tope de la pila), así
    /// que se emiten al revés.
    fn push_args(&mut self, rng: &mut Rng, args: &[Operand]) {
        for operand in args.iter().rev() {
            let data = operand.materialize(rng, self.pool);
            self.push_bytes(data);
        }
    }

    fn emit_family(&mut self, rng: &mut Rng) {
        let weights: Vec<u32> = FAMILIES
            .iter()
            .map(|(family, weight)| if self.is_active(*family) { *weight } else { 0 })
            .collect();
        let Some(index) = rng.weighted(&weights) else {
            return;
        };
        let Some((family, _)) = FAMILIES.get(index) else {
            return;
        };
        match family {
            Family::Simple => self.emit_simple(rng),
            Family::Nullary => self.emit_nullary(rng),
            Family::Exp => self.emit_exp(rng),
            Family::Memory => self.emit_memory(rng),
            Family::Storage => self.emit_storage(rng),
            Family::Transient => self.emit_transient(rng),
            Family::Log => self.emit_log(rng),
            Family::ExternalAccount => self.emit_external_account(rng),
            Family::Call => self.emit_call(rng),
            Family::Create => self.emit_create(rng),
            Family::StackShuffle => self.emit_stack_shuffle(rng),
            Family::Jump => self.emit_jump(rng),
            Family::Keccak => self.emit_keccak(rng),
            Family::Copy => self.emit_copy(rng),
            Family::BlockHash => self.emit_block_hash(rng),
            Family::Blob => self.emit_blob(rng),
            Family::PushWidth => self.emit_push_width(rng),
            Family::DeepStack => self.emit_deep_stack(rng),
        }
    }

    /// Gating por fork: el fork del caso decide qué familias existen. La tabla
    /// de activación canónica vive en el intérprete; acá solo se listan las
    /// familias cuyo opcode entero es posterior a Paris.
    fn is_active(&self, family: Family) -> bool {
        match family {
            Family::Transient | Family::Blob => self.spec.is_enabled(Spec::Cancun),
            _ => true,
        }
    }

    fn emit_simple(&mut self, rng: &mut Rng) {
        let weights: Vec<u32> = SIMPLE_OPS.iter().map(|entry| entry.weight).collect();
        let Some(index) = rng.weighted(&weights) else {
            return;
        };
        let Some(entry) = SIMPLE_OPS.get(index) else {
            return;
        };
        for _ in 0..entry.pops {
            let data = Operand::Word.materialize(rng, self.pool);
            self.push_bytes(data);
        }
        self.op(entry.op, entry.pops, 1);
    }

    fn emit_nullary(&mut self, rng: &mut Rng) {
        let Some(op) = rng.pick(NULLARY_OPS).copied() else {
            return;
        };
        self.op(op, 0, 1);
        // Un contexto apilado que nadie consume crece la pila sin fin; el POP
        // la devuelve y de paso ejercita el opcode.
        if rng.chance(1, 2) {
            self.op(opcodes::POP, 1, 0);
        }
    }

    fn emit_exp(&mut self, rng: &mut Rng) {
        self.push_args(rng, &[Operand::Word, Operand::Bounded(MAX_EXPONENT)]);
        self.op(opcodes::EXP, 2, 1);
        self.op(opcodes::POP, 1, 0);
    }

    fn emit_memory(&mut self, rng: &mut Rng) {
        match rng.below(4) {
            0 => {
                self.push_args(rng, &[Operand::MemoryOffset, Operand::Word]);
                self.op(opcodes::MSTORE, 2, 0);
            }
            1 => {
                self.push_args(rng, &[Operand::MemoryOffset, Operand::Word]);
                self.op(opcodes::MSTORE8, 2, 0);
            }
            2 => {
                self.push_args(rng, &[Operand::MemoryOffset]);
                self.op(opcodes::MLOAD, 1, 1);
                self.op(opcodes::POP, 1, 0);
            }
            _ if self.spec.is_enabled(Spec::Cancun) => {
                self.push_args(
                    rng,
                    &[
                        Operand::MemoryOffset,
                        Operand::MemoryOffset,
                        Operand::MemorySize,
                    ],
                );
                self.op(opcodes::MCOPY, 3, 0);
            }
            _ => {
                self.push_args(rng, &[Operand::MemoryOffset]);
                self.op(opcodes::MLOAD, 1, 1);
                self.op(opcodes::POP, 1, 0);
            }
        }
    }

    fn emit_storage(&mut self, rng: &mut Rng) {
        if rng.chance(1, 2) {
            self.push_args(rng, &[Operand::StorageKey, Operand::SmallWord]);
            self.op(opcodes::SSTORE, 2, 0);
        } else {
            self.push_args(rng, &[Operand::StorageKey]);
            self.op(opcodes::SLOAD, 1, 1);
            self.op(opcodes::POP, 1, 0);
        }
    }

    fn emit_transient(&mut self, rng: &mut Rng) {
        if rng.chance(1, 2) {
            self.push_args(rng, &[Operand::StorageKey, Operand::SmallWord]);
            self.op(opcodes::TSTORE, 2, 0);
        } else {
            self.push_args(rng, &[Operand::StorageKey]);
            self.op(opcodes::TLOAD, 1, 1);
            self.op(opcodes::POP, 1, 0);
        }
    }

    fn emit_log(&mut self, rng: &mut Rng) {
        let topics = usize::try_from(rng.below(5)).unwrap_or(0);
        let mut args = vec![Operand::MemoryOffset, Operand::MemorySize];
        for _ in 0..topics {
            args.push(Operand::Word);
        }
        self.push_args(rng, &args);
        let op = opcodes::LOG0.saturating_add(u8::try_from(topics).unwrap_or(0));
        self.op(op, topics.saturating_add(2), 0);
    }

    fn emit_external_account(&mut self, rng: &mut Rng) {
        match rng.below(4) {
            0 => {
                self.push_args(rng, &[Operand::PoolAddress]);
                self.op(opcodes::BALANCE, 1, 1);
                self.op(opcodes::POP, 1, 0);
            }
            1 => {
                self.push_args(rng, &[Operand::PoolAddress]);
                self.op(opcodes::EXTCODESIZE, 1, 1);
                self.op(opcodes::POP, 1, 0);
            }
            2 => {
                self.push_args(rng, &[Operand::PoolAddress]);
                self.op(opcodes::EXTCODEHASH, 1, 1);
                self.op(opcodes::POP, 1, 0);
            }
            _ => {
                self.push_args(
                    rng,
                    &[
                        Operand::PoolAddress,
                        Operand::MemoryOffset,
                        Operand::MemoryOffset,
                        Operand::MemorySize,
                    ],
                );
                self.op(opcodes::EXTCODECOPY, 4, 0);
            }
        }
    }

    fn emit_call(&mut self, rng: &mut Rng) {
        let (op, has_value) = match rng.below(4) {
            0 => (opcodes::CALL, true),
            1 => (opcodes::CALLCODE, true),
            2 => (opcodes::DELEGATECALL, false),
            _ => (opcodes::STATICCALL, false),
        };
        let mut args = vec![Operand::Bounded(MAX_FORWARDED_GAS), Operand::PoolAddress];
        if has_value {
            args.push(Operand::Bounded(2));
        }
        args.extend_from_slice(&[
            Operand::MemoryOffset,
            Operand::MemorySize,
            Operand::MemoryOffset,
            Operand::MemorySize,
        ]);
        let pops = args.len();
        self.push_args(rng, &args);
        self.op(op, pops, 1);
        self.op(opcodes::POP, 1, 0);
    }

    fn emit_create(&mut self, rng: &mut Rng) {
        // El initcode tiene que estar EN MEMORIA antes del CREATE. Se escribe
        // una palabra: 32 bytes de initcode arbitrario, que es exactamente el
        // tipo de código que interesa desplegar.
        self.push_args(rng, &[Operand::Zero, Operand::Word]);
        self.op(opcodes::MSTORE, 2, 0);
        let create2 = rng.chance(1, 2);
        let mut args = vec![Operand::Bounded(2), Operand::Zero, Operand::Fixed(32)];
        if create2 {
            args.push(Operand::SmallWord);
        }
        let pops = args.len();
        self.push_args(rng, &args);
        self.op(
            if create2 {
                opcodes::CREATE2
            } else {
                opcodes::CREATE
            },
            pops,
            1,
        );
        self.op(opcodes::POP, 1, 0);
    }

    fn emit_stack_shuffle(&mut self, rng: &mut Rng) {
        if self.height == 0 {
            self.push_args(rng, &[Operand::Word]);
            return;
        }
        let depth = self.height.min(16);
        let n = u8::try_from(rng.range(1, depth)).unwrap_or(1);
        if rng.chance(1, 2) {
            self.op(opcodes::DUP1.saturating_add(n.saturating_sub(1)), 0, 1);
        } else if self.height > usize::from(n) {
            self.op(opcodes::SWAP1.saturating_add(n.saturating_sub(1)), 0, 0);
        } else {
            self.op(opcodes::POP, 1, 0);
        }
    }

    fn emit_jump(&mut self, rng: &mut Rng) {
        let label = self.next_label;
        self.next_label = self.next_label.saturating_add(1);
        self.pending_labels.push(label);
        let conditional = rng.chance(2, 3);
        if conditional {
            // La condición va DEBAJO del destino: el destino lo empuja el
            // propio `JumpTo`.
            self.push_args(rng, &[Operand::Bounded(2)]);
            self.height = self.height.saturating_sub(1);
        }
        self.instructions.push(Instruction::JumpTo {
            label,
            conditional,
            width: GENERATED_JUMP_WIDTH,
        });
    }

    fn emit_keccak(&mut self, rng: &mut Rng) {
        self.push_args(rng, &[Operand::MemoryOffset, Operand::MemorySize]);
        self.op(opcodes::KECCAK256, 2, 1);
        self.op(opcodes::POP, 1, 0);
    }

    fn emit_copy(&mut self, rng: &mut Rng) {
        let op = match rng.below(3) {
            0 => opcodes::CALLDATACOPY,
            1 => opcodes::CODECOPY,
            // RETURNDATACOPY fuera de rango HALTEA (no zero-padea, al revés
            // que los otros dos): con tamaño 0 el opcode se ejecuta sin matar
            // el programa, y el borde de rango ya lo cubre `calls/`.
            _ => opcodes::RETURNDATACOPY,
        };
        let size = if op == opcodes::RETURNDATACOPY {
            Operand::Zero
        } else {
            Operand::MemorySize
        };
        self.push_args(rng, &[Operand::MemoryOffset, Operand::MemoryOffset, size]);
        self.op(op, 3, 0);
    }

    fn emit_block_hash(&mut self, rng: &mut Rng) {
        self.push_args(rng, &[Operand::Bounded(300)]);
        self.op(opcodes::BLOCKHASH, 1, 1);
        self.op(opcodes::POP, 1, 0);
    }

    fn emit_blob(&mut self, rng: &mut Rng) {
        if rng.chance(1, 2) {
            self.push_args(rng, &[Operand::Bounded(4)]);
            self.op(opcodes::BLOBHASH, 1, 1);
        } else {
            self.op(opcodes::BLOBBASEFEE, 0, 1);
        }
        self.op(opcodes::POP, 1, 0);
    }

    /// Un `PUSHn` de ancho sorteado, seguido de `POP` para no dejar la pila
    /// creciendo. Los bytes NO se recortan: el ancho es el punto.
    fn emit_push_width(&mut self, rng: &mut Rng) {
        let width = rng.range(0, 32);
        let mut data = Vec::with_capacity(width);
        for _ in 0..width {
            data.push(u8::try_from(rng.below(256)).unwrap_or(0));
        }
        // `PUSH0` solo existe desde Shanghai; con ancho 0 en Paris el programa
        // moriría ahí mismo.
        if data.is_empty() && !self.spec.is_enabled(Spec::Shanghai) {
            data.push(0x01);
        }
        self.push_bytes(data);
        self.op(opcodes::POP, 1, 0);
    }

    /// Carga la pila hasta pasar los 16 y usa un `DUP`/`SWAP` profundo. Deja
    /// la pila como estaba para no arrastrar altura al resto del programa.
    fn emit_deep_stack(&mut self, rng: &mut Rng) {
        const DEEP: usize = 17;
        let missing = DEEP.saturating_sub(self.height);
        for _ in 0..missing {
            self.push_args(rng, &[Operand::SmallWord]);
        }
        let n = u8::try_from(rng.range(1, 16)).unwrap_or(1);
        if rng.chance(1, 2) {
            self.op(opcodes::DUP1.saturating_add(n.saturating_sub(1)), 0, 1);
            self.op(opcodes::POP, 1, 0);
        } else {
            self.op(opcodes::SWAP1.saturating_add(n.saturating_sub(1)), 0, 0);
        }
        for _ in 0..missing {
            self.op(opcodes::POP, 1, 0);
        }
    }

    fn flush_one_label(&mut self) {
        if let Some(label) = self.pending_labels.pop() {
            self.instructions.push(Instruction::Label(label));
        }
    }

    fn flush_all_labels(&mut self) {
        while !self.pending_labels.is_empty() {
            self.flush_one_label();
        }
    }

    fn emit_terminator(&mut self, rng: &mut Rng) {
        let weights: Vec<u32> = TERMINATORS.iter().map(|(_, weight)| *weight).collect();
        let Some(index) = rng.weighted(&weights) else {
            return;
        };
        let Some((op, _)) = TERMINATORS.get(index) else {
            return;
        };
        match *op {
            opcodes::RETURN | opcodes::REVERT => {
                self.push_args(rng, &[Operand::MemoryOffset, Operand::MemorySize]);
                self.op(*op, 2, 0);
            }
            opcodes::SELFDESTRUCT => {
                self.push_args(rng, &[Operand::PoolAddress]);
                self.op(*op, 1, 0);
            }
            other => self.op(other, 0, 0),
        }
    }
}

/// De dónde sale el valor de un operando. Separa lo que gobierna **gas**
/// (acotado) de lo que gobierna **valor** (bordes de 256 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    /// Una palabra de 256 bits del conjunto de bordes.
    Word,
    /// Una palabra chica: cabe en 8 bytes.
    SmallWord,
    /// Cero exacto.
    Zero,
    /// Una constante exacta.
    Fixed(u64),
    /// Uniforme en `[0, bound)`.
    Bounded(u64),
    MemoryOffset,
    MemorySize,
    StorageKey,
    PoolAddress,
}

/// Los bordes de 256 bits que valen la pena: los que separan una regla de
/// otra (signo, saturación de shift, límites de `BYTE`/`SIGNEXTEND`, palabra
/// de memoria).
const EDGE_WORDS: &[[u8; 32]] = &[
    [0x00; 32],
    hex32("0000000000000000000000000000000000000000000000000000000000000001"),
    hex32("0000000000000000000000000000000000000000000000000000000000000002"),
    hex32("000000000000000000000000000000000000000000000000000000000000001f"),
    hex32("0000000000000000000000000000000000000000000000000000000000000020"),
    hex32("0000000000000000000000000000000000000000000000000000000000000021"),
    hex32("00000000000000000000000000000000000000000000000000000000000000ff"),
    hex32("0000000000000000000000000000000000000000000000000000000000000100"),
    hex32("00000000000000000000000000000000000000000000000000000000ffffffff"),
    hex32("000000000000000000000000000000000000000000000000ffffffffffffffff"),
    hex32("8000000000000000000000000000000000000000000000000000000000000000"),
    hex32("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    hex32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"),
];

/// Parsea una constante hexadecimal de 32 bytes en tiempo de compilación. Un
/// literal mal escrito no compila, que es donde tiene que fallar.
const fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(bytes[i * 2]) * 16 + nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("literal hexadecimal inválido en EDGE_WORDS"),
    }
}

impl Operand {
    fn materialize(self, rng: &mut Rng, pool: &AddressPool) -> Vec<u8> {
        match self {
            Self::Word => {
                if rng.chance(2, 3) {
                    match rng.pick(EDGE_WORDS) {
                        Some(word) => trim_leading_zeros(word),
                        None => Vec::new(),
                    }
                } else {
                    trim_leading_zeros(&rng.next_u64().to_be_bytes())
                }
            }
            Self::SmallWord => trim_leading_zeros(&rng.next_u64().to_be_bytes()),
            Self::Zero => Vec::new(),
            Self::Fixed(value) => trim_leading_zeros(&value.to_be_bytes()),
            Self::Bounded(bound) => trim_leading_zeros(&rng.below(bound).to_be_bytes()),
            Self::MemoryOffset => trim_leading_zeros(&rng.below(MAX_MEMORY_OFFSET).to_be_bytes()),
            Self::MemorySize => trim_leading_zeros(&rng.below(MAX_MEMORY_SIZE).to_be_bytes()),
            Self::StorageKey => trim_leading_zeros(&rng.below(STORAGE_KEY_SPACE).to_be_bytes()),
            Self::PoolAddress => match rng.pick(&pool.addresses) {
                Some(address) => address.0.to_vec(),
                None => Vec::new(),
            },
        }
    }
}

/// Los ceros a la izquierda de un push son gas gastado en nada: `PUSH1 0x01`
/// dice lo mismo que `PUSH32 0x00…01` y deja el programa más corto, que es lo
/// que el shrinker va a querer después.
fn trim_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|byte| *byte != 0);
    match first {
        Some(index) => bytes.get(index..).unwrap_or_default().to_vec(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PUSH2` no tiene constante propia en `opcode.rs` (el intérprete
    /// decodifica la familia por rango); acá se deriva del mismo `PUSH0`.
    const PUSH2_OPCODE: u8 = opcodes::PUSH0 + 2;

    fn pool() -> AddressPool {
        AddressPool {
            addresses: vec![Address::new([0xB0; 20]), Address::new([0xC0; 20])],
        }
    }

    /// Determinismo, la regla dura: el mismo `(seed, índice)` produce el mismo
    /// programa byte a byte. Sin esto un hallazgo no es reproducible.
    #[test]
    fn the_same_seed_and_index_produce_the_same_program() {
        let build = || {
            let mut rng = Rng::for_case(0x1234, 77);
            generate_program(&mut rng, &pool(), Spec::Prague, 32).assemble()
        };
        assert_eq!(build(), build());
        let mut other = Rng::for_case(0x1234, 78);
        assert_ne!(
            build(),
            generate_program(&mut other, &pool(), Spec::Prague, 32).assemble()
        );
    }

    /// El stream que sale de la gramática vuelve a salir igual del decoder:
    /// el shrinker recibe programas que el decoder entiende.
    #[test]
    fn generated_programs_survive_a_decode_round_trip() {
        for index in 0..64 {
            let mut rng = Rng::for_case(9, index);
            let program = generate_program(&mut rng, &pool(), Spec::Prague, 24);
            let code = program.assemble();
            assert_eq!(Program::decode(&code).assemble(), code);
        }
    }

    /// Todo salto emitido cae en un `JUMPDEST` real. Se verifica sobre los
    /// BYTES, que es donde el motor lo va a mirar.
    #[test]
    fn every_generated_jump_lands_on_a_real_jumpdest() {
        for index in 0..128 {
            let mut rng = Rng::for_case(4242, index);
            let code = generate_program(&mut rng, &pool(), Spec::Prague, 32).assemble();
            let mut pc = 0usize;
            while let Some(op) = code.get(pc).copied() {
                if op == PUSH2_OPCODE
                    && matches!(
                        code.get(pc.saturating_add(3)).copied(),
                        Some(opcodes::JUMP | opcodes::JUMPI)
                    )
                {
                    let hi = usize::from(code.get(pc.saturating_add(1)).copied().unwrap_or(0));
                    let lo = usize::from(code.get(pc.saturating_add(2)).copied().unwrap_or(0));
                    let target = hi.saturating_mul(256).saturating_add(lo);
                    assert_eq!(
                        code.get(target).copied(),
                        Some(opcodes::JUMPDEST),
                        "salto a {target} que no es JUMPDEST"
                    );
                }
                pc = pc
                    .saturating_add(1)
                    .saturating_add(crate::fuzz::program::push_immediate_len(op));
            }
        }
    }

    /// El gating por fork es de la gramática, no una esperanza: en Paris no
    /// se emite un opcode de Cancun.
    #[test]
    fn cancun_only_opcodes_never_appear_in_paris() {
        let cancun_only = [
            opcodes::TLOAD,
            opcodes::TSTORE,
            opcodes::MCOPY,
            opcodes::BLOBHASH,
            opcodes::BLOBBASEFEE,
        ];
        for index in 0..128 {
            let mut rng = Rng::for_case(1, index);
            let program = generate_program(&mut rng, &pool(), Spec::Paris, 32);
            for instruction in &program.instructions {
                if let Instruction::Op(op) = instruction {
                    assert!(!cancun_only.contains(op), "opcode {op:#04x} en Paris");
                }
            }
        }
    }

    #[test]
    fn trimming_leaves_the_value_intact_and_zero_becomes_push0() {
        assert!(trim_leading_zeros(&[0, 0, 0]).is_empty());
        assert_eq!(trim_leading_zeros(&[0, 0, 1, 2]), vec![1, 2]);
        assert_eq!(trim_leading_zeros(&[0xff]), vec![0xff]);
    }

    /// El parser `const` de los bordes: si `hex32` estuviera corrido en un
    /// nibble, TODA la tabla de valores interesantes sería otra cosa y nadie
    /// se enteraría.
    #[test]
    fn edge_words_parse_at_compile_time() {
        assert_eq!(EDGE_WORDS.first(), Some(&[0u8; 32]));
        let mut sign_bit = [0u8; 32];
        sign_bit[0] = 0x80;
        assert!(EDGE_WORDS.contains(&sign_bit));
        assert!(EDGE_WORDS.contains(&[0xffu8; 32]));
        let mut thirty_two = [0u8; 32];
        thirty_two[31] = 0x20;
        assert!(EDGE_WORDS.contains(&thirty_two));
    }
}
