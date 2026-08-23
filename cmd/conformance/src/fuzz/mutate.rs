//! El **segundo generador** del red-team: mutación de la vecindad de un
//! fixture real del EF.
//!
//! El generador por gramática explora el espacio parejo, guiado por pesos que
//! elegimos nosotros: es buena en lo ancho y ciega a lo que no se nos ocurrió
//! ponderar. Acá se hace lo contrario — cada uno de los 39 025 `state_test` de
//! EEST ya está parado sobre un borde que un humano del EF fue a buscar (el gas
//! justo, el límite del fork, el input degenerado de una precompile, la
//! colisión de CREATE), y lo que se explora es **su vecindad**.
//!
//! ## La trampa, que es la misma que la del shrinker
//!
//! Mutar el bytecode a nivel de **byte** rompe los inmediatos de `PUSH` (borrar
//! un byte de `0x602A` convierte el dato en opcode y corre el stream entero) y
//! corre todos los `JUMPDEST`. Acá se muta el **stream de instrucciones** de
//! `program.rs` y se re-emite, exactamente como minimiza el shrinker. Es la
//! diferencia entre "el 22.7 % de los casos pasa del primer opcode" y "el
//! 99 %", medida.
//!
//! ## Qué NO se muta, y por qué importa
//!
//! El **envelope** de la tx (access list, blob hashes, lista de autorizaciones)
//! se hereda del fixture semilla tal cual. Ahí está el terreno propio de este
//! generador: `FuzzCase` no puede representar una tx 2930/4844/7702 —sus
//! campos son `None` por construcción—, así que **ninguna campaña de la
//! gramática, con ningún presupuesto, ejercita el gas intrínseco de una access
//! list ni el costo por tupla de EIP-7702**. Medido con un bug plantado en ese
//! gas: la gramática no lo encuentra en 200 000 casos y acá cae en el 56.

use repo_b_common::primitives::{Address, U256};

use crate::fixture::{PostCase, StateTest};
use crate::fuzz::grammar::{nullary_ops, word_op_arity, word_ops_with_arity};
use crate::fuzz::program::{Instruction, Program};
use crate::fuzz::rng::Rng;
use crate::fuzz::seeds::{SeedCase, SeedCorpus};
use crate::fuzz::shrink::Shrinkable;

/// Cuántos operadores se aplican a un caso, como mucho. Más de un puñado y el
/// caso deja de ser "la vecindad de un fixture" para ser otro fixture — y con
/// él se pierde justamente el borde por el que se lo eligió.
const MAX_OPERATORS: usize = 3;
/// Los cuatro forks del scope, en orden de protocolo. La mutación de fork
/// camina esta lista.
const FORKS: [&str; 4] = ["Paris", "Shanghai", "Cancun", "Prague"];
/// Tope del bytecode mutado. EIP-170 acota el código desplegado en 24 576; un
/// `pre` puede traer más, pero insertar sin techo haría crecer el caso sin
/// límite a lo largo de una campaña.
const MAX_CODE_INSTRUCTIONS: usize = 4_096;

/// Un caso mutado: el `state_test` semilla con sus mutaciones aplicadas.
///
/// `seed_name` es la **identidad del fixture semilla** y es obligatoria: el
/// índice del caso depende del tamaño del corpus (que cambia con el release de
/// EEST) mientras el nombre no. Un hallazgo se archiva con los dos.
#[derive(Debug, Clone)]
pub struct MutCase {
    pub seed_name: String,
    pub seed_index: usize,
    /// Qué operadores se aplicaron, en orden. Se reporta con el hallazgo: sin
    /// esto, "el caso 900 000 diverge" no dice qué se tocó.
    pub applied: Vec<&'static str>,
    /// ¿El caso quedó **estructuralmente** distinto de su semilla? Se calcula
    /// al construirlo, comparando campo a campo (no "¿se aplicó un
    /// operador?"): es la métrica de vecindad, y con la pregunta fácil un
    /// generador con los operadores desactivados seguiría reportando 100 %.
    pub changed: bool,
    /// **Localidad de la mutación de bytecode**: `(instrucciones del stream que
    /// cambiaron, instrucciones del stream)`, acumulado sobre las mutaciones de
    /// código de este caso.
    ///
    /// Es la métrica que separa mutar el **stream** de mutar **bytes**, y no es
    /// la profundidad: un solo byte cambiado en un programa real sigue
    /// ejecutando hondo (medido), pero **re-encuadra todo el stream a partir del
    /// byte tocado** — los inmediatos de `PUSH` se corren y con ellos los
    /// `JUMPDEST`. O sea que la mutación que se pidió ("cambiá un opcode por
    /// otro de la misma aridad") no es la que se aplicó. Sin este número, esa
    /// diferencia es una creencia.
    pub stream_delta: Option<(usize, usize)>,
    /// **Saltos que siguen aterrizando en un `JUMPDEST`**, antes y después de
    /// la mutación de bytecode. Es la trampa del §4.1 medida directamente: los
    /// saltos de la EVM son ABSOLUTOS, así que correr los `JUMPDEST` deja un
    /// `PUSH2 0x0042 ; JUMP` cayendo en cualquier lado. Mutar el stream los
    /// re-resuelve por etiqueta; mutar bytes no puede.
    pub jump_delta: Option<(usize, usize)>,
    pub test: StateTest,
    pub post: PostCase,
}

impl MutCase {
    /// ¿El caso quedó realmente distinto de su semilla?
    ///
    /// La comparación es **estructural** y no "¿se aplicó algún operador?": un
    /// operador que no cambia nada (elegir el mismo opcode, sumar 0) no cuenta.
    /// Es lo que hace que la métrica de vecindad mida algo — con la pregunta
    /// fácil, un generador con los operadores desactivados seguiría reportando
    /// 100 % de casos mutados.
    pub fn differs_from(&self, seed: &SeedCase) -> bool {
        if self.post.fork != seed.post.fork {
            return true;
        }
        if self.test.pre != seed.test.pre {
            return true;
        }
        let ours = &self.test.tx;
        let theirs = &seed.test.tx;
        ours.data != theirs.data
            || ours.gas_limit != theirs.gas_limit
            || ours.value != theirs.value
            || ours.gas_price != theirs.gas_price
            || ours.max_fee_per_gas != theirs.max_fee_per_gas
            || ours.nonce != theirs.nonce
    }
}

/// El caso `index` de la campaña `seed`. **Función pura de los tres
/// argumentos**, igual que `generate_case_with`: es lo que hace que un hallazgo
/// se reproduzca con `--seed`/`--case`.
pub fn mutate_case(
    seed: u64,
    index: u64,
    corpus: &SeedCorpus,
    byte_level: bool,
) -> Option<MutCase> {
    let mut rng = Rng::for_case(seed, index);
    let len = u64::try_from(corpus.len()).unwrap_or(u64::MAX);
    let pick = usize::try_from(rng.below(len)).unwrap_or(0);
    let seed_case = corpus.cases.get(pick)?;

    let mut case = MutCase {
        seed_name: seed_case.name.clone(),
        seed_index: pick,
        applied: Vec::new(),
        changed: false,
        stream_delta: None,
        jump_delta: None,
        test: seed_case.test.clone(),
        post: seed_case.post.clone(),
    };

    let operators = rng.range(1, MAX_OPERATORS);
    for _ in 0..operators {
        apply_one(&mut case, &mut rng, byte_level);
    }
    case.changed = case.differs_from(seed_case);
    Some(case)
}

/// El caso `index` **sin mutar**: el fixture semilla tal cual.
///
/// No es una comodidad: es el modo de contraste del §5 (M2). Sin él, "los
/// operadores aportan" sería una creencia — con él, la métrica de vecindad
/// tiene contra qué medirse, igual que la gramática tiene el modo uniforme.
pub fn passthrough_case(seed: u64, index: u64, corpus: &SeedCorpus) -> Option<MutCase> {
    let mut rng = Rng::for_case(seed, index);
    let len = u64::try_from(corpus.len()).unwrap_or(u64::MAX);
    let pick = usize::try_from(rng.below(len)).unwrap_or(0);
    let seed_case = corpus.cases.get(pick)?;
    Some(MutCase {
        seed_name: seed_case.name.clone(),
        seed_index: pick,
        applied: Vec::new(),
        changed: false,
        stream_delta: None,
        jump_delta: None,
        test: seed_case.test.clone(),
        post: seed_case.post.clone(),
    })
}

/// Los operadores y sus pesos. El bytecode pesa más porque es donde vive el
/// grueso del consenso; el fork pesa alto porque es la mutación **más barata y
/// más potente** que hay acá — correr el mismo caso en un fork vecino ya
/// destapó cientos de divergencias de gating cuando el motor las tenía.
const OPERATORS: &[(&str, u32)] = &[
    ("code.replace-op", 10),
    ("code.tweak-push", 9),
    ("code.delete", 7),
    ("code.insert", 7),
    ("calldata", 8),
    ("fork", 8),
    ("value", 5),
    ("gas-limit", 6),
    ("gas-price", 4),
    ("balance", 4),
    ("nonce", 3),
    ("storage", 6),
];

fn apply_one(case: &mut MutCase, rng: &mut Rng, byte_level: bool) {
    let weights: Vec<u32> = OPERATORS.iter().map(|(_, weight)| *weight).collect();
    let Some(index) = rng.weighted(&weights) else {
        return;
    };
    let Some((name, _)) = OPERATORS.get(index) else {
        return;
    };
    // El modo de contraste del §5 (M3): los cuatro operadores de bytecode se
    // reemplazan por uno solo que muta **bytes crudos**. Existe para que la
    // métrica de profundidad tenga contra qué medirse, igual que el modo
    // uniforme de la gramática — el punto entero del §4.1 es que mutar bytes
    // rompe los inmediatos de `PUSH` y corre los `JUMPDEST`, y eso hay que
    // poder MEDIRLO en vez de creerlo.
    let changed = match *name {
        _ if byte_level && name.starts_with("code.") => mutate_raw_byte(case, rng),
        "code.replace-op" => mutate_code(case, rng, CodeOp::ReplaceOp),
        "code.tweak-push" => mutate_code(case, rng, CodeOp::TweakPush),
        "code.delete" => mutate_code(case, rng, CodeOp::Delete),
        "code.insert" => mutate_code(case, rng, CodeOp::Insert),
        "calldata" => mutate_calldata(case, rng),
        "fork" => mutate_fork(case, rng),
        "value" => mutate_value(case, rng),
        "gas-limit" => mutate_gas_limit(case, rng),
        "gas-price" => mutate_gas_price(case, rng),
        "balance" => mutate_account(case, rng, AccountField::Balance),
        "nonce" => mutate_account(case, rng, AccountField::Nonce),
        "storage" => mutate_storage(case, rng),
        _ => false,
    };
    if changed {
        case.applied.push(name);
    }
}

// ------------------------------------------------------------------ bytecode

#[derive(Debug, Clone, Copy)]
enum CodeOp {
    ReplaceOp,
    TweakPush,
    Delete,
    Insert,
}

/// Las direcciones del `pre` con código, en orden determinista (`BTreeMap`).
fn coded_addresses(test: &StateTest) -> Vec<Address> {
    test.pre
        .iter()
        .filter(|(_, account)| !account.code.is_empty())
        .map(|(address, _)| *address)
        .collect()
}

/// **El modo de contraste, no el operador bueno.** Muta un byte del código sin
/// mirar la estructura: flip, inserción o borrado. Es exactamente el error que
/// `program.rs` existe para no cometer, y por eso vive acá con nombre propio en
/// vez de ser una edición temporal del código.
fn mutate_raw_byte(case: &mut MutCase, rng: &mut Rng) -> bool {
    let addresses = coded_addresses(&case.test);
    let Some(address) = rng.pick(&addresses).copied() else {
        return false;
    };
    let Some(account) = case.test.pre.get_mut(&address) else {
        return false;
    };
    let mut bytes = account.code.to_vec();
    if bytes.is_empty() {
        return false;
    }
    let position = rng.range(0, bytes.len().saturating_sub(1));
    match rng.below(3) {
        0 => {
            let Some(slot) = bytes.get_mut(position) else {
                return false;
            };
            *slot = u8::try_from(rng.below(256)).unwrap_or(0);
        }
        1 => bytes.insert(position, u8::try_from(rng.below(256)).unwrap_or(0)),
        _ => {
            bytes.remove(position);
        }
    }
    if bytes == account.code.as_ref() {
        return false;
    }
    let before = account.code.to_vec();
    account.code = bytes.clone().into();
    record_delta(case, &before, &bytes);
    true
}

fn mutate_code(case: &mut MutCase, rng: &mut Rng, op: CodeOp) -> bool {
    let addresses = coded_addresses(&case.test);
    let Some(address) = rng.pick(&addresses).copied() else {
        return false;
    };
    let Some(account) = case.test.pre.get_mut(&address) else {
        return false;
    };
    // Bytes → stream → mutación → bytes. **Nunca sobre los bytes crudos**: el
    // motivo está en el doc-comment de `program.rs`.
    let mut program = Program::decode(&account.code);
    if program.is_empty() && !matches!(op, CodeOp::Insert) {
        return false;
    }
    let changed = match op {
        CodeOp::ReplaceOp => replace_op(&mut program, rng),
        CodeOp::TweakPush => tweak_push(&mut program, rng),
        CodeOp::Delete => delete_instruction(&mut program, rng),
        CodeOp::Insert => insert_instruction(&mut program, rng),
    };
    if !changed {
        return false;
    }
    let assembled = program.assemble();
    if assembled == account.code.as_ref() {
        return false;
    }
    let before = account.code.to_vec();
    account.code = assembled.clone().into();
    record_delta(case, &before, &assembled);
    true
}

/// Cuántas instrucciones del stream cambiaron, sobre cuántas hay.
///
/// **Prefijo común + sufijo común**, no comparación posición a posición. La
/// diferencia no es un detalle: insertar o borrar una instrucción corre todas
/// las de después una posición, y una comparación posicional contaría el
/// programa entero como "tocado" cuando en realidad sobrevivió intacto. Con
/// prefijo+sufijo, una inserción, un borrado o un reemplazo dan **1**, que es
/// lo que el operador dice hacer; un byte que re-encuadra los inmediatos deja
/// el sufijo sin alinear y da todo lo que sigue al byte tocado.
///
/// La primera versión de esta función era posicional y medía 16.9 % para el
/// operador de instrucción: un artefacto de la medición, no del mutador.
fn stream_delta(before: &[u8], after: &[u8]) -> (usize, usize) {
    let old = Program::decode(before).instructions;
    let new = Program::decode(after).instructions;
    let total = old.len().max(new.len());
    let common = old.len().min(new.len());

    let mut prefix = 0usize;
    while prefix < common && old.get(prefix) == new.get(prefix) {
        prefix = prefix.saturating_add(1);
    }
    let mut suffix = 0usize;
    while suffix < common.saturating_sub(prefix)
        && old.get(old.len().saturating_sub(suffix).saturating_sub(1))
            == new.get(new.len().saturating_sub(suffix).saturating_sub(1))
    {
        suffix = suffix.saturating_add(1);
    }
    let survived = prefix.saturating_add(suffix).min(total);
    (total.saturating_sub(survived), total)
}

/// Los saltos que aterrizan en un `JUMPDEST` real. `Program::decode` los
/// reconoce como `JumpTo` justamente cuando el destino es una etiqueta que
/// existe; un `PUSH ... ; JUMP` que quedó apuntando a cualquier lado se queda
/// como el par crudo.
fn resolved_jumps(code: &[u8]) -> usize {
    Program::decode(code)
        .instructions
        .iter()
        .filter(|instruction| matches!(instruction, Instruction::JumpTo { .. }))
        .count()
}

fn record_delta(case: &mut MutCase, before: &[u8], after: &[u8]) {
    let (touched, total) = stream_delta(before, after);
    let (acc_touched, acc_total) = case.stream_delta.unwrap_or((0, 0));
    case.stream_delta = Some((
        acc_touched.saturating_add(touched),
        acc_total.saturating_add(total),
    ));
    let (acc_before, acc_after) = case.jump_delta.unwrap_or((0, 0));
    case.jump_delta = Some((
        acc_before.saturating_add(resolved_jumps(before)),
        acc_after.saturating_add(resolved_jumps(after)),
    ));
}

/// Reemplaza un opcode por **otro de la misma aridad**. Un reemplazo de aridad
/// distinta desbalancea la pila y el programa muere de underflow unas
/// instrucciones después: el caso mutado ya no ejerce el borde del fixture.
fn replace_op(program: &mut Program, rng: &mut Rng) -> bool {
    let positions: Vec<usize> = program
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| match instruction {
            Instruction::Op(op) => word_op_arity(*op).is_some() || nullary_ops().contains(op),
            _ => false,
        })
        .map(|(index, _)| index)
        .collect();
    let Some(position) = rng.pick(&positions).copied() else {
        return false;
    };
    let Some(Instruction::Op(current)) = program.instructions.get(position).cloned() else {
        return false;
    };
    let alternatives = match word_op_arity(current) {
        Some(arity) => word_ops_with_arity(arity),
        None => nullary_ops().to_vec(),
    };
    let Some(replacement) = rng.pick(&alternatives).copied() else {
        return false;
    };
    if replacement == current {
        return false;
    }
    let Some(slot) = program.instructions.get_mut(position) else {
        return false;
    };
    *slot = Instruction::Op(replacement);
    true
}

/// Palabras de borde para los inmediatos: los valores donde una regla de la
/// EVM cambia de rama. Un byte al azar casi nunca cae en uno.
const EDGE_IMMEDIATES: &[&[u8]] = &[
    &[],
    &[0x01],
    &[0x20],
    &[0x1F],
    &[0xFF],
    &[0xFF, 0xFF],
    &[0xFF; 32],
    &[0x80],
];

/// Cambia el inmediato de un `PUSH`. Es el operador más barato que hay: un
/// `PUSH1 0x20` que pasa a `PUSH1 0x1F` cruza el borde de una palabra de
/// memoria sin tocar una sola instrucción.
fn tweak_push(program: &mut Program, rng: &mut Rng) -> bool {
    let positions: Vec<usize> = program
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| matches!(instruction, Instruction::Push(_)))
        .map(|(index, _)| index)
        .collect();
    let Some(position) = rng.pick(&positions).copied() else {
        return false;
    };
    let Some(Instruction::Push(current)) = program.instructions.get(position).cloned() else {
        return false;
    };
    let replacement = if rng.chance(1, 2) {
        // Un byte al azar del inmediato: conserva el ancho del `PUSH` y por lo
        // tanto el tamaño del programa, así que ninguna etiqueta se mueve.
        let mut bytes = current.clone();
        if bytes.is_empty() {
            return false;
        }
        let index = rng.range(0, bytes.len().saturating_sub(1));
        let Some(slot) = bytes.get_mut(index) else {
            return false;
        };
        *slot = u8::try_from(rng.below(256)).unwrap_or(0);
        bytes
    } else {
        match rng.pick(EDGE_IMMEDIATES) {
            Some(edge) => (*edge).to_vec(),
            None => return false,
        }
    };
    if replacement == current {
        return false;
    }
    let Some(slot) = program.instructions.get_mut(position) else {
        return false;
    };
    *slot = Instruction::Push(replacement);
    true
}

fn delete_instruction(program: &mut Program, rng: &mut Rng) -> bool {
    if program.is_empty() {
        return false;
    }
    let position = rng.range(0, program.len().saturating_sub(1));
    if position >= program.len() {
        return false;
    }
    program.instructions.remove(position);
    true
}

fn insert_instruction(program: &mut Program, rng: &mut Rng) -> bool {
    if program.len() >= MAX_CODE_INSTRUCTIONS {
        return false;
    }
    let position = rng.range(0, program.len());
    let instruction = match rng.below(4) {
        0 => match rng.pick(nullary_ops()) {
            Some(op) => Instruction::Op(*op),
            None => return false,
        },
        1 => Instruction::Op(crate::fuzz::opcodes::POP),
        2 => {
            let width = rng.range(0, 32);
            let mut data = Vec::with_capacity(width);
            for _ in 0..width {
                data.push(u8::try_from(rng.below(256)).unwrap_or(0));
            }
            Instruction::Push(data)
        }
        // Un `JUMPDEST` nuevo: el destino de un salto que hoy es inválido puede
        // pasar a serlo, que es un cambio de rama entero.
        _ => Instruction::Label(program.max_label().map_or(0, |max| max.saturating_add(1))),
    };
    if position > program.len() {
        return false;
    }
    program.instructions.insert(position, instruction);
    true
}

// ------------------------------------------------------------------ tx y pre

fn mutate_calldata(case: &mut MutCase, rng: &mut Rng) -> bool {
    let index = case.post.data_index;
    let Some(data) = case.test.tx.data.get(index) else {
        return false;
    };
    let mut bytes = data.to_vec();
    match rng.below(4) {
        0 if !bytes.is_empty() => {
            let position = rng.range(0, bytes.len().saturating_sub(1));
            let Some(slot) = bytes.get_mut(position) else {
                return false;
            };
            *slot ^= u8::try_from(rng.below(256)).unwrap_or(1).max(1);
        }
        1 => {
            let extra = rng.range(1, 32);
            for _ in 0..extra {
                bytes.push(u8::try_from(rng.below(256)).unwrap_or(0));
            }
        }
        2 if !bytes.is_empty() => {
            let keep = rng.range(0, bytes.len().saturating_sub(1));
            bytes.truncate(keep);
        }
        // El selector: los primeros 4 bytes deciden a qué rama de un contrato
        // real entra la llamada.
        _ => {
            while bytes.len() < 4 {
                bytes.push(0);
            }
            for slot in bytes.iter_mut().take(4) {
                *slot = u8::try_from(rng.below(256)).unwrap_or(0);
            }
        }
    }
    if bytes == data.as_ref() {
        return false;
    }
    let Some(slot) = case.test.tx.data.get_mut(index) else {
        return false;
    };
    *slot = bytes.into();
    true
}

/// Corre el caso a un fork **vecino**. Una regla gateada por fork puede estar
/// mal en el fork VIEJO, y el mismo caso corrido en dos forks se delata solo.
fn mutate_fork(case: &mut MutCase, rng: &mut Rng) -> bool {
    let Some(current) = FORKS.iter().position(|fork| *fork == case.post.fork) else {
        return false;
    };
    let target = if rng.chance(1, 2) {
        current.saturating_sub(1)
    } else {
        current.saturating_add(1).min(FORKS.len().saturating_sub(1))
    };
    if target == current {
        return false;
    }
    let Some(fork) = FORKS.get(target) else {
        return false;
    };
    case.post.fork = (*fork).to_owned();
    true
}

/// Un escalar mutado: ±1, ×2, /2, cero, o el tope. Los deltas de 1 son los que
/// cruzan un borde de gas o de balance; los saltos grandes son los que
/// cambian de rama entera.
fn mutate_scalar_u256(value: U256, rng: &mut Rng) -> U256 {
    match rng.below(6) {
        0 => value.saturating_add(U256::from(1u64)),
        1 => value.saturating_sub(U256::from(1u64)),
        2 => value.saturating_mul(U256::from(2u64)),
        3 => value.wrapping_shr(1),
        4 => U256::ZERO,
        _ => U256::from(rng.next_u64()),
    }
}

fn mutate_scalar_u64(value: u64, rng: &mut Rng) -> u64 {
    match rng.below(6) {
        0 => value.saturating_add(1),
        1 => value.saturating_sub(1),
        2 => value.saturating_mul(2),
        3 => value / 2,
        4 => 0,
        _ => rng.next_u64() % 10_000_000,
    }
}

fn mutate_value(case: &mut MutCase, rng: &mut Rng) -> bool {
    let index = case.post.value_index;
    let Some(current) = case.test.tx.value.get(index).copied() else {
        return false;
    };
    let mutated = mutate_scalar_u256(current, rng);
    if mutated == current {
        return false;
    }
    let Some(slot) = case.test.tx.value.get_mut(index) else {
        return false;
    };
    *slot = mutated;
    true
}

fn mutate_gas_limit(case: &mut MutCase, rng: &mut Rng) -> bool {
    let index = case.post.gas_index;
    let Some(current) = case.test.tx.gas_limit.get(index).copied() else {
        return false;
    };
    let mutated = mutate_scalar_u64(current, rng);
    if mutated == current {
        return false;
    }
    let Some(slot) = case.test.tx.gas_limit.get_mut(index) else {
        return false;
    };
    *slot = mutated;
    true
}

/// El precio se muta en el campo que la tx **tiene**: tocar `gasPrice` en una
/// tx que declara `maxFeePerGas` no cambiaría el tipo pero sí lo haría
/// malformado (el parser lo rechaza), y el caso se perdería entero.
fn mutate_gas_price(case: &mut MutCase, rng: &mut Rng) -> bool {
    if let Some(price) = case.test.tx.gas_price {
        let mutated = u128::from(mutate_scalar_u64(
            u64::try_from(price).unwrap_or(u64::MAX),
            rng,
        ));
        if mutated == price {
            return false;
        }
        case.test.tx.gas_price = Some(mutated);
        return true;
    }
    let Some(fee) = case.test.tx.max_fee_per_gas else {
        return false;
    };
    let mutated = u128::from(mutate_scalar_u64(
        u64::try_from(fee).unwrap_or(u64::MAX),
        rng,
    ));
    if mutated == fee {
        return false;
    }
    case.test.tx.max_fee_per_gas = Some(mutated);
    true
}

#[derive(Debug, Clone, Copy)]
enum AccountField {
    Balance,
    Nonce,
}

fn mutate_account(case: &mut MutCase, rng: &mut Rng, field: AccountField) -> bool {
    let addresses: Vec<Address> = case.test.pre.keys().copied().collect();
    let Some(address) = rng.pick(&addresses).copied() else {
        return false;
    };
    let Some(account) = case.test.pre.get_mut(&address) else {
        return false;
    };
    match field {
        AccountField::Balance => {
            let mutated = mutate_scalar_u256(account.balance, rng);
            if mutated == account.balance {
                return false;
            }
            account.balance = mutated;
        }
        AccountField::Nonce => {
            let mutated = mutate_scalar_u64(account.nonce, rng);
            if mutated == account.nonce {
                return false;
            }
            account.nonce = mutated;
        }
    }
    true
}

/// Slots del `pre`. Las tres ramas de EIP-2200 (0→x, x→y, x→0) dependen del
/// valor ORIGINAL del slot, así que tocarlo en el pre-state cambia la regla que
/// el fixture ejerce sin tocar una instrucción.
fn mutate_storage(case: &mut MutCase, rng: &mut Rng) -> bool {
    let addresses: Vec<Address> = case.test.pre.keys().copied().collect();
    let Some(address) = rng.pick(&addresses).copied() else {
        return false;
    };
    let Some(account) = case.test.pre.get_mut(&address) else {
        return false;
    };
    let keys: Vec<U256> = account.storage.keys().copied().collect();
    match rng.below(3) {
        0 if !keys.is_empty() => {
            let Some(key) = rng.pick(&keys).copied() else {
                return false;
            };
            account.storage.remove(&key);
            true
        }
        1 if !keys.is_empty() => {
            let Some(key) = rng.pick(&keys).copied() else {
                return false;
            };
            let Some(slot) = account.storage.get_mut(&key) else {
                return false;
            };
            let mutated = mutate_scalar_u256(*slot, rng);
            if mutated == *slot {
                return false;
            }
            *slot = mutated;
            true
        }
        _ => {
            let key = U256::from(rng.below(16));
            let value = U256::from(rng.below(4));
            account.storage.insert(key, value) != Some(value)
        }
    }
}

// ------------------------------------------------------------------ shrinking

impl Shrinkable for MutCase {
    /// Todo lo que el shrinker puede reducir, sumado. El código cuenta en
    /// **instrucciones** y no en bytes: es la unidad sobre la que se reduce, y
    /// medir en bytes haría que cambiar un `PUSH32` por un `PUSH1` contara como
    /// reducción sin haber sacado una sola instrucción.
    fn size(&self) -> usize {
        let mut size = self.test.pre.len();
        for account in self.test.pre.values() {
            size = size
                .saturating_add(Program::decode(&account.code).len())
                .saturating_add(account.storage.len());
        }
        for data in &self.test.tx.data {
            size = size.saturating_add(data.len());
        }
        size
    }

    fn candidates(&self) -> Vec<Self> {
        let mut out = Vec::new();

        // 1. Cuentas que no participan. Ni el sender ni el destino: sacar
        //    cualquiera de los dos cambia la tx, no la reduce.
        for address in self.test.pre.keys().copied().collect::<Vec<_>>() {
            if address == self.test.tx.sender || Some(address) == self.test.tx.to {
                continue;
            }
            let mut reduced = self.clone();
            reduced.test.pre.remove(&address);
            out.push(reduced);
        }

        // 2. Bloques contiguos de instrucciones, de grande a chico
        //    (delta-debugging sobre el stream, nunca sobre los bytes).
        for address in self.test.pre.keys().copied().collect::<Vec<_>>() {
            let Some(account) = self.test.pre.get(&address) else {
                continue;
            };
            let program = Program::decode(&account.code);
            let len = program.len();
            if len == 0 {
                continue;
            }
            let mut block = len;
            while block > 0 {
                let mut start = 0usize;
                while start < len {
                    let end = start.saturating_add(block).min(len);
                    let mut shorter = program.clone();
                    shorter.instructions.drain(start..end);
                    let mut reduced = self.clone();
                    if let Some(target) = reduced.test.pre.get_mut(&address) {
                        target.code = shorter.assemble().into();
                        out.push(reduced);
                    }
                    start = end;
                }
                block /= 2;
            }
        }

        // 3. Los inmediatos de un `PUSH`.
        for address in self.test.pre.keys().copied().collect::<Vec<_>>() {
            let Some(account) = self.test.pre.get(&address) else {
                continue;
            };
            let program = Program::decode(&account.code);
            for (index, instruction) in program.instructions.iter().enumerate() {
                let Instruction::Push(data) = instruction else {
                    continue;
                };
                if data.is_empty() {
                    continue;
                }
                for shorter in [Vec::new(), vec![0x01], vec![0x00]] {
                    if shorter.len() >= data.len() {
                        continue;
                    }
                    let mut candidate = program.clone();
                    let Some(slot) = candidate.instructions.get_mut(index) else {
                        continue;
                    };
                    *slot = Instruction::Push(shorter);
                    let mut reduced = self.clone();
                    if let Some(target) = reduced.test.pre.get_mut(&address) {
                        target.code = candidate.assemble().into();
                        out.push(reduced);
                    }
                }
            }
        }

        // 4. Slots de storage.
        for address in self.test.pre.keys().copied().collect::<Vec<_>>() {
            let Some(account) = self.test.pre.get(&address) else {
                continue;
            };
            for key in account.storage.keys().copied().collect::<Vec<_>>() {
                let mut reduced = self.clone();
                if let Some(target) = reduced.test.pre.get_mut(&address) {
                    target.storage.remove(&key);
                    out.push(reduced);
                }
            }
        }

        // 5. Calldata: mitades primero, después la cola.
        let index = self.post.data_index;
        if let Some(data) = self.test.tx.data.get(index)
            && !data.is_empty()
        {
            let len = data.len();
            for keep in [0usize, len / 4, len / 2, len.saturating_sub(1)] {
                if keep >= len {
                    continue;
                }
                let mut reduced = self.clone();
                if let Some(slot) = reduced.test.tx.data.get_mut(index) {
                    *slot = data.slice(0..keep);
                    out.push(reduced);
                }
            }
        }

        out
    }
}

/// Un corpus mínimo, para tests que no pueden depender del cache de EEST (que
/// no está versionado — son 257 MB y CI no los tiene).
#[cfg(test)]
pub fn synthetic_corpus() -> SeedCorpus {
    use crate::fixture::{FixtureAccount, RawEnv, RawTransaction};
    use repo_b_common::primitives::{B256, Bytes};
    use std::collections::BTreeMap;

    let sender = Address::new([0xA0; 20]);
    let target = Address::new([0xB0; 20]);
    let mut pre = BTreeMap::new();
    pre.insert(
        sender,
        FixtureAccount {
            balance: U256::from(1_000_000_000_000_000_000u64),
            nonce: 0,
            code: Bytes::new(),
            storage: BTreeMap::new(),
        },
    );
    pre.insert(
        target,
        FixtureAccount {
            balance: U256::ZERO,
            nonce: 1,
            // PUSH1 0x01 ; PUSH1 0x02 ; ADD ; PUSH1 0x00 ; SSTORE ; STOP
            code: Bytes::from_static(&[0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x55, 0x00]),
            storage: BTreeMap::new(),
        },
    );
    let post = PostCase {
        fork: "Prague".to_owned(),
        data_index: 0,
        gas_index: 0,
        value_index: 0,
        state_root: B256::ZERO,
        logs_hash: B256::ZERO,
        expected_state: None,
        expect_exception: None,
    };
    let test = StateTest {
        name: "sintetico".to_owned(),
        chain_id: 1,
        env: RawEnv {
            coinbase: Address::new([0xCC; 20]),
            number: 1,
            timestamp: 1_000,
            gas_limit: 30_000_000,
            base_fee: Some(10),
            prevrandao: Some(B256::with_last_byte(0x42)),
            excess_blob_gas: Some(0),
            block_hashes: [(0u64, crate::fuzz::seeds::ancestor_hash(0))]
                .into_iter()
                .collect(),
        },
        pre,
        tx: RawTransaction {
            secret_key: None,
            authorization_signatures: None,
            sender,
            to: Some(target),
            nonce: 0,
            gas_price: Some(10),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            data: vec![Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF])],
            gas_limit: vec![200_000],
            value: vec![U256::from(7u64)],
            access_lists: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            authorization_list: None,
        },
        posts: vec![post.clone()],
    };
    SeedCorpus {
        cases: vec![SeedCase {
            name: "sintetico [Prague]".to_owned(),
            test,
            post,
        }],
        out_of_scope: 0,
        unparsed: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La regla dura: `(semilla, índice)` reproduce **el mismo fixture semilla
    /// y la misma mutación**, bit a bit. Sin esto un hallazgo no es un
    /// hallazgo, es una anécdota.
    #[test]
    fn seed_and_index_reproduce_the_same_seed_case_and_the_same_mutation() {
        let corpus = synthetic_corpus();
        for index in [0u64, 1, 17, 5_000, 1_000_000] {
            let Some(first) = mutate_case(0xC0FFEE, index, &corpus, false) else {
                panic!("el corpus sintético no produjo caso");
            };
            let Some(second) = mutate_case(0xC0FFEE, index, &corpus, false) else {
                panic!("el corpus sintético no produjo caso");
            };
            assert_eq!(first.seed_name, second.seed_name);
            assert_eq!(first.seed_index, second.seed_index);
            assert_eq!(first.applied, second.applied);
            assert_eq!(first.post.fork, second.post.fork);
            assert_eq!(first.test.pre, second.test.pre);
            assert_eq!(first.test.tx.data, second.test.tx.data);
            assert_eq!(first.test.tx.gas_limit, second.test.tx.gas_limit);
            assert_eq!(first.test.tx.value, second.test.tx.value);
        }
    }

    /// Reproducir el caso N no depende de haber generado el N-1: una campaña se
    /// reparte por rangos de índice sin coordinación.
    #[test]
    fn a_case_does_not_depend_on_the_ones_before_it() {
        let corpus = synthetic_corpus();
        let alone = mutate_case(1, 999, &corpus, false).map(|case| case.applied);
        let mut after_a_run = None;
        for index in 0..1_000 {
            after_a_run = mutate_case(1, index, &corpus, false).map(|case| case.applied);
        }
        assert_eq!(alone, after_a_run);
    }

    /// El pass-through **no muta nada**: es la referencia contra la que se mide
    /// la métrica de vecindad (M2). Si esto mutara, el contraste no mediría.
    #[test]
    fn the_passthrough_mode_changes_nothing() {
        let corpus = synthetic_corpus();
        for index in 0..64 {
            let Some(case) = passthrough_case(7, index, &corpus) else {
                panic!("sin caso");
            };
            let Some(seed) = corpus.cases.get(case.seed_index) else {
                panic!("índice de semilla fuera de rango");
            };
            assert!(
                !case.differs_from(seed),
                "el pass-through mutó el caso {index}"
            );
            assert!(case.applied.is_empty());
        }
    }

    /// Y el generador de verdad **sí** muta, la gran mayoría de las veces. El
    /// número no tiene que ser 100 % (un operador puede caer en un caso donde
    /// no hay nada que tocar), pero un generador que muta poco es un
    /// pass-through con otro nombre.
    #[test]
    fn the_mutating_mode_actually_changes_the_seed() {
        let corpus = synthetic_corpus();
        let mut mutated = 0u32;
        let total = 256u32;
        for index in 0..u64::from(total) {
            let Some(case) = mutate_case(9, index, &corpus, false) else {
                panic!("sin caso");
            };
            let Some(seed) = corpus.cases.get(case.seed_index) else {
                panic!("índice de semilla fuera de rango");
            };
            if case.differs_from(seed) {
                mutated = mutated.saturating_add(1);
            }
        }
        assert!(
            mutated * 10 >= total * 9,
            "solo {mutated}/{total} casos quedaron distintos de su semilla"
        );
    }

    /// La trampa del §4.1: el bytecode mutado **sigue siendo decodificable a sí
    /// mismo**. Si el mutador hubiera roto un inmediato de `PUSH`, el
    /// round-trip del stream fallaría y el "caso mínimo" del shrinker sería
    /// otro programa desde el primer paso.
    #[test]
    fn mutated_bytecode_still_round_trips_through_the_instruction_stream() {
        let corpus = synthetic_corpus();
        for index in 0..512 {
            let Some(case) = mutate_case(0xBEEF, index, &corpus, false) else {
                panic!("sin caso");
            };
            for account in case.test.pre.values() {
                let code = account.code.to_vec();
                assert_eq!(
                    Program::decode(&code).assemble(),
                    code,
                    "round-trip roto en el caso {index}"
                );
            }
        }
    }

    /// El fork mutado sigue siendo uno de los cuatro del scope: mutar a un
    /// nombre inventado haría `SkippedFork` y el caso no probaría nada.
    #[test]
    fn the_mutated_fork_is_always_one_of_the_four_in_scope() {
        let corpus = synthetic_corpus();
        let mut seen = std::collections::BTreeSet::new();
        for index in 0..512 {
            let Some(case) = mutate_case(0xF0, index, &corpus, false) else {
                panic!("sin caso");
            };
            assert!(
                crate::fixture::spec_for_fork(&case.post.fork).is_some(),
                "fork fuera de scope: {}",
                case.post.fork
            );
            seen.insert(case.post.fork.clone());
        }
        assert!(seen.len() > 1, "el operador de fork nunca movió el fork");
    }

    /// La métrica de localidad mide lo que dice medir: un reemplazo, una
    /// inserción y un borrado de instrucción dan **1**, y un byte que corre los
    /// inmediatos de un `PUSH` da todo lo que sigue.
    ///
    /// Sin este test la métrica sería una creencia — y su primera versión, que
    /// comparaba posición a posición, contaba una inserción como si hubiera
    /// tocado el programa entero.
    #[test]
    fn the_locality_metric_separates_a_stream_edit_from_a_byte_reframe() {
        // PUSH1 0x01 ; PUSH1 0x02 ; ADD ; PUSH1 0x00 ; SSTORE ; STOP
        let base: &[u8] = &[0x60, 0x01, 0x60, 0x02, 0x01, 0x60, 0x00, 0x55, 0x00];

        // Reemplazo de un opcode por otro de la misma aridad (ADD → MUL).
        let replaced: &[u8] = &[0x60, 0x01, 0x60, 0x02, 0x02, 0x60, 0x00, 0x55, 0x00];
        assert_eq!(stream_delta(base, replaced).0, 1);

        // Inserción de un `POP`: corre todo lo de atrás una posición y NO es
        // eso lo que la métrica tiene que contar.
        let inserted: &[u8] = &[0x60, 0x01, 0x60, 0x02, 0x01, 0x50, 0x60, 0x00, 0x55, 0x00];
        assert_eq!(stream_delta(base, inserted).0, 1);

        // Borrado de una instrucción.
        let deleted: &[u8] = &[0x60, 0x01, 0x60, 0x02, 0x60, 0x00, 0x55, 0x00];
        assert_eq!(stream_delta(base, deleted).0, 1);

        // Un byte crudo que convierte el `ADD` en `PUSH1`: se come el byte
        // siguiente como inmediato y **re-encuadra el resto del programa**.
        let reframed: &[u8] = &[0x60, 0x01, 0x60, 0x02, 0x60, 0x60, 0x00, 0x55, 0x00];
        let (touched, total) = stream_delta(base, reframed);
        assert!(
            touched > 1,
            "el re-encuadre tocó {touched} de {total} instrucciones"
        );
    }

    /// El shrinker reduce un `MutCase` de verdad. Predicado sintético y
    /// **multidimensional** —exige calldata Y programa—: con un predicado de una
    /// sola dimensión, un shrinker ciego pasa por delante sin que nadie lo note.
    #[test]
    fn the_shrinker_reduces_a_mutated_case_and_keeps_the_predicate() {
        let corpus = synthetic_corpus();
        let Some(case) = corpus.cases.first() else {
            panic!("corpus vacío");
        };
        let start = MutCase {
            seed_name: case.name.clone(),
            seed_index: 0,
            applied: Vec::new(),
            changed: false,
            stream_delta: None,
            jump_delta: None,
            test: case.test.clone(),
            post: case.post.clone(),
        };
        let target = case.test.tx.to.unwrap_or_default();
        let predicate = |candidate: &MutCase| {
            let has_calldata = candidate
                .test
                .tx
                .data
                .first()
                .is_some_and(|data| data.len() >= 2);
            let has_program = candidate
                .test
                .pre
                .get(&target)
                .is_some_and(|account| Program::decode(&account.code).len() >= 3);
            has_calldata && has_program
        };
        let (minimized, stats) = crate::fuzz::shrink::shrink(&start, predicate);
        assert!(predicate(&minimized), "lo minimizado ya no reproduce");
        assert!(
            stats.size_after < stats.size_before,
            "no redujo: {} → {}",
            stats.size_before,
            stats.size_after
        );
    }
}
