//! El bytecode como **stream de instrucciones**, no como `Vec<u8>`.
//!
//! Es la pieza que hace posible el shrinking, y existe por dos razones que no
//! son estéticas:
//!
//! - **`PUSH` lleva sus datos inline.** Borrar un byte de `0x602A`
//!   (`PUSH1 0x2A`) convierte el dato en opcode y corre el stream entero: el
//!   "caso mínimo" es otro programa, y minimizar sobre bytes produce
//!   reproductores que no reproducen.
//! - **Los saltos son absolutos.** Sacar una instrucción mueve todos los
//!   `JUMPDEST` posteriores. Acá un salto apunta a una **etiqueta** y la
//!   dirección se re-resuelve al re-emitir, así que sacar una instrucción del
//!   medio deja el salto apuntando a donde apuntaba.
//!
//! El shrinker opera sobre este stream; el motor recibe el resultado de
//! `assemble`.

use crate::fuzz::opcodes;

/// Una instrucción del stream. El invariante que la hace útil:
/// `assemble(decode(code)) == code` para cualquier `code` (test).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// Un opcode sin inmediatos.
    Op(u8),
    /// `PUSH0..=PUSH32` con sus inmediatos. `data.len()` **es** el ancho del
    /// push: 0 ⇒ `PUSH0`, n ⇒ `PUSHn`. Guardar los bytes crudos (y no el
    /// valor) conserva los ceros a la izquierda, que son parte del programa.
    Push(Vec<u8>),
    /// Un `JUMPDEST` con identidad. El `id` es arbitrario y solo tiene que ser
    /// único dentro del programa.
    Label(u32),
    /// `PUSHn <dirección de la etiqueta>` + `JUMP`/`JUMPI`.
    ///
    /// `width` es el ancho del `PUSH` y **no cambia nunca**: se fija al
    /// generar (2) o al decodificar (el ancho que traía el código original).
    /// Si el ancho se recalculara según la dirección, mover una etiqueta
    /// cambiaría el tamaño del salto, que a su vez movería la etiqueta — un
    /// punto fijo que habría que iterar, y con él la posibilidad de que el
    /// round-trip no sea exacto. Con ancho fijo, una sola pasada resuelve.
    ///
    /// Si tras una reducción la dirección deja de entrar en `width`, se emite
    /// un destino inválido determinista en vez de ensancharse.
    JumpTo {
        label: u32,
        conditional: bool,
        width: u8,
    },
    /// Bytes que no son instrucciones decodificables: la cola de un `PUSH`
    /// truncado al final del código. Se conservan crudos para que el
    /// round-trip sea exacto — reinterpretarlos sería inventar un programa
    /// distinto del que se está minimizando.
    Raw(Vec<u8>),
}

/// Ancho del `PUSH` de un salto generado por la gramática: `PUSH2` cubre 64 KiB
/// de código, más que el `MAX_CODE_SIZE` de EIP-170.
pub const GENERATED_JUMP_WIDTH: u8 = 2;

impl Instruction {
    /// Bytes que ocupa al emitirse. Necesario ANTES de conocer las
    /// direcciones, y por eso no puede depender de ellas.
    fn encoded_len(&self) -> usize {
        match self {
            Self::Op(_) | Self::Label(_) => 1,
            Self::Push(data) => data.len().saturating_add(1),
            // `PUSHn` + n inmediatos + el `JUMP`/`JUMPI`: exactamente lo mismo
            // que ocupaban el `Push` y el `Op` que reemplazó.
            Self::JumpTo { width, .. } => usize::from(*width).saturating_add(2),
            Self::Raw(bytes) => bytes.len(),
        }
    }
}

/// Un programa: la secuencia de instrucciones.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

impl Program {
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self { instructions }
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// El `id` de etiqueta más alto del programa.
    pub fn max_label(&self) -> Option<u32> {
        self.instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Label(id) => Some(*id),
                _ => None,
            })
            .max()
    }

    /// Corre TODOS los ids de etiqueta (y los saltos que los nombran) por
    /// `delta`. Existe para el splicing: los ids de un programa decodificado
    /// son sus `pc` originales y los de uno generado arrancan en 0, así que
    /// concatenarlos sin renumerar haría que un salto de la cola cayera en una
    /// etiqueta del cuerpo sembrado — un programa que nadie escribió.
    pub fn shift_labels(&mut self, delta: u32) {
        for instruction in &mut self.instructions {
            match instruction {
                Instruction::Label(id) => *id = id.saturating_add(delta),
                Instruction::JumpTo { label, .. } => *label = label.saturating_add(delta),
                Instruction::Op(_) | Instruction::Push(_) | Instruction::Raw(_) => {}
            }
        }
    }

    /// Stream → bytes, **re-resolviendo los saltos**. Dos pasadas: primero las
    /// direcciones de las etiquetas (que solo dependen de los anchos), después
    /// la emisión.
    pub fn assemble(&self) -> Vec<u8> {
        let mut label_offsets: Vec<(u32, usize)> = Vec::new();
        let mut offset = 0usize;
        for instruction in &self.instructions {
            if let Instruction::Label(id) = instruction {
                label_offsets.push((*id, offset));
            }
            offset = offset.saturating_add(instruction.encoded_len());
        }

        let mut code = Vec::with_capacity(offset);
        for instruction in &self.instructions {
            match instruction {
                Instruction::Op(op) => code.push(*op),
                Instruction::Label(_) => code.push(opcodes::JUMPDEST),
                Instruction::Push(data) => {
                    let width = u8::try_from(data.len()).unwrap_or(32);
                    // `PUSH0 + n` es `PUSHn`; con n = 0 queda `PUSH0`.
                    code.push(opcodes::PUSH0.saturating_add(width));
                    code.extend_from_slice(data);
                }
                Instruction::JumpTo {
                    label,
                    conditional,
                    width,
                } => {
                    let width = usize::from(*width);
                    let target = label_offsets
                        .iter()
                        .find(|(id, _)| id == label)
                        .map(|(_, offset)| *offset);
                    code.push(opcodes::PUSH0.saturating_add(u8::try_from(width).unwrap_or(2)));
                    code.extend_from_slice(&encode_target(target, width));
                    code.push(if *conditional {
                        opcodes::JUMPI
                    } else {
                        opcodes::JUMP
                    });
                }
                Instruction::Raw(bytes) => code.extend_from_slice(bytes),
            }
        }
        code
    }

    /// Bytes → stream. Input hostil: no asume nada del código (puede venir de
    /// un fixture escrito a mano, que es justamente el corpus de siembra).
    ///
    /// El `id` de cada etiqueta es su `pc` original — único por construcción y
    /// estable, así que `assemble(decode(code)) == code`.
    pub fn decode(code: &[u8]) -> Self {
        let mut instructions = Vec::new();
        let mut pc = 0usize;
        while let Some(op) = code.get(pc) {
            let op = *op;
            let immediates = push_immediate_len(op);
            if immediates > 0 {
                let start = pc.saturating_add(1);
                let end = start.saturating_add(immediates);
                match code.get(start..end) {
                    Some(data) => {
                        instructions.push(Instruction::Push(data.to_vec()));
                        pc = end;
                    }
                    // `PUSH` truncado al final del código: no hay instrucción
                    // que representar sin cambiar la semántica (el motor lee
                    // ceros por los bytes que faltan), así que la cola entera
                    // se conserva cruda.
                    None => {
                        let tail = code.get(pc..).unwrap_or_default();
                        instructions.push(Instruction::Raw(tail.to_vec()));
                        break;
                    }
                }
                continue;
            }
            if op == opcodes::JUMPDEST {
                let id = u32::try_from(pc).unwrap_or(u32::MAX);
                instructions.push(Instruction::Label(id));
            } else {
                instructions.push(Instruction::Op(op));
            }
            pc = pc.saturating_add(1);
        }
        Self::new(instructions).with_resolved_jumps()
    }

    /// Reescribe el patrón `PUSH2 <addr>; JUMP` en `JumpTo` cuando `addr` es
    /// una etiqueta real. Es lo que le da al shrinker saltos que sobreviven a
    /// una reducción.
    ///
    /// Un salto **calculado** (dirección que no sale de un push literal) queda
    /// como estaba: el stream lo conserva, el shrinker puede romperlo, y el
    /// predicado de "sigue divergiendo" rechaza esa reducción. La corrección
    /// no depende de este reconocimiento — la eficacia sí.
    fn with_resolved_jumps(mut self) -> Self {
        let mut labels: Vec<usize> = Vec::new();
        let mut offset = 0usize;
        for instruction in &self.instructions {
            if let Instruction::Label(_) = instruction {
                labels.push(offset);
            }
            offset = offset.saturating_add(instruction.encoded_len());
        }

        let mut rewritten: Vec<Instruction> = Vec::with_capacity(self.instructions.len());
        let mut index = 0usize;
        while index < self.instructions.len() {
            let current = self.instructions.get(index);
            let next = self.instructions.get(index.saturating_add(1));
            if let (Some(Instruction::Push(data)), Some(Instruction::Op(jump))) = (current, next)
                && (*jump == opcodes::JUMP || *jump == opcodes::JUMPI)
                && let Some(target) = push_value_as_offset(data)
                && labels.contains(&target)
                && let Ok(width) = u8::try_from(data.len())
            {
                rewritten.push(Instruction::JumpTo {
                    label: u32::try_from(target).unwrap_or(u32::MAX),
                    conditional: *jump == opcodes::JUMPI,
                    width,
                });
                index = index.saturating_add(2);
                continue;
            }
            if let Some(instruction) = current {
                rewritten.push(instruction.clone());
            }
            index = index.saturating_add(1);
        }
        self.instructions = rewritten;
        self
    }
}

/// La dirección de una etiqueta en `width` bytes big-endian. Una etiqueta que
/// ya no existe, o que dejó de entrar en el ancho fijado, se emite como todos
/// unos: un destino que NUNCA es un `JUMPDEST` válido, y siempre el mismo.
/// Ensancharse sería mover todas las direcciones posteriores.
fn encode_target(target: Option<usize>, width: usize) -> Vec<u8> {
    let mut bytes = vec![0xFFu8; width];
    let Some(target) = target else {
        return bytes;
    };
    let mut remaining = target;
    for slot in bytes.iter_mut().rev() {
        *slot = u8::try_from(remaining % 256).unwrap_or(0xFF);
        remaining /= 256;
    }
    if remaining > 0 {
        return vec![0xFFu8; width];
    }
    bytes
}

/// El valor de un push, si entra en un offset de código razonable.
fn push_value_as_offset(data: &[u8]) -> Option<usize> {
    if data.len() > 4 {
        return None;
    }
    let mut value = 0usize;
    for byte in data {
        value = value.checked_mul(256)?.checked_add(usize::from(*byte))?;
    }
    Some(value)
}

/// Inmediatos de un `PUSH`: 1..=32 para `PUSH1..=PUSH32`, 0 para todo lo
/// demás (`PUSH0` incluido).
pub fn push_immediate_len(op: u8) -> usize {
    if !(opcodes::PUSH1..=opcodes::PUSH32).contains(&op) {
        return 0;
    }
    usize::from(op.wrapping_sub(opcodes::PUSH1)).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(code: &[u8]) {
        let decoded = Program::decode(code);
        assert_eq!(decoded.assemble(), code, "round-trip roto para {code:02x?}");
    }

    /// La invariante que sostiene todo lo demás: decodificar y re-emitir no
    /// puede cambiar un solo byte. Si cambiara, el "caso mínimo" del shrinker
    /// sería otro programa desde el primer paso.
    #[test]
    fn decode_and_assemble_round_trip_exactly() {
        round_trip(&[]);
        round_trip(&[0x00]);
        // PUSH1 0x2a; PUSH0; ADD; STOP
        round_trip(&[0x60, 0x2a, 0x5f, 0x01, 0x00]);
        // JUMPDEST en 0, PUSH2 0x0000, JUMP (salto hacia atrás resoluble)
        round_trip(&[0x5b, 0x61, 0x00, 0x00, 0x56]);
        // PUSH32 completo
        let mut push32 = vec![0x7f];
        push32.extend_from_slice(&[0xAB; 32]);
        round_trip(&push32);
        // PUSH2 truncado al final: la cola se conserva cruda.
        round_trip(&[0x60, 0x01, 0x61, 0x02]);
        // Byte no asignado: sigue siendo una instrucción del stream.
        round_trip(&[0x0c, 0xfe]);
    }

    /// Un dato de PUSH que "parece" un JUMPDEST no crea una etiqueta: el
    /// decoder respeta los inmediatos, que es el bug clásico del shrinker de
    /// bytes.
    #[test]
    fn push_data_is_never_decoded_as_an_opcode() {
        // PUSH1 0x5b (el dato es el byte de JUMPDEST) + STOP.
        let program = Program::decode(&[0x60, 0x5b, 0x00]);
        assert_eq!(
            program.instructions,
            vec![
                Instruction::Push(vec![0x5b]),
                Instruction::Op(opcodes::STOP)
            ]
        );
    }

    /// El punto entero del stream: sacar una instrucción del medio **no**
    /// mueve el destino del salto.
    #[test]
    fn removing_an_instruction_keeps_the_jump_pointing_at_its_label() {
        let program = Program::new(vec![
            Instruction::JumpTo {
                label: 1,
                conditional: false,
                width: GENERATED_JUMP_WIDTH,
            },
            Instruction::Op(opcodes::STOP),
            Instruction::Op(opcodes::STOP),
            Instruction::Label(1),
            Instruction::Op(opcodes::STOP),
        ]);
        let before = program.assemble();
        assert_eq!(before.get(1..3), Some([0x00, 0x06].as_slice()));

        let mut reduced = program.clone();
        reduced.instructions.remove(1);
        let after = reduced.assemble();
        // La dirección BAJÓ en 1 sola vez, y sigue cayendo en el JUMPDEST.
        assert_eq!(after.get(1..3), Some([0x00, 0x05].as_slice()));
        assert_eq!(after.get(5), Some(&opcodes::JUMPDEST));
    }

    /// Un salto cuya etiqueta desapareció apunta a un destino inválido
    /// **determinista**, nunca a una instrucción vecina por casualidad.
    #[test]
    fn a_jump_to_a_deleted_label_lands_nowhere() {
        let program = Program::new(vec![Instruction::JumpTo {
            label: 42,
            conditional: true,
            width: GENERATED_JUMP_WIDTH,
        }]);
        assert_eq!(program.assemble(), vec![0x61, 0xff, 0xff, opcodes::JUMPI]);
    }

    #[test]
    fn immediate_len_matches_the_push_family() {
        assert_eq!(push_immediate_len(opcodes::PUSH0), 0);
        assert_eq!(push_immediate_len(opcodes::PUSH1), 1);
        assert_eq!(push_immediate_len(opcodes::PUSH32), 32);
        assert_eq!(push_immediate_len(opcodes::STOP), 0);
    }
}
