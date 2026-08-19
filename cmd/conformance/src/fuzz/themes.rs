//! **Cobertura por tema**: qué territorio de consenso tocó una campaña.
//!
//! ## Por qué hace falta otra métrica
//!
//! `coverage.rs` mide **profundidad** (casos vivos, casos que llegan a 10+
//! opcodes, la traza más larga) y el set de opcodes ejercitado. M5 de 2.9d-2
//! midió que la fracción de opcodes casi no discrimina y que la profundidad sí,
//! y eso sigue valiendo — pero las dos son ciegas a lo que separa a los tres
//! generadores, que **no es el bytecode**: es el **envelope de la tx** y los
//! **cruces entre EIPs**.
//!
//! Dos campañas pueden ejecutar los mismos 149 opcodes con la misma
//! profundidad y una no haber tocado jamás una access list, una blob tx ni una
//! delegación. Ese número no existía antes de este módulo, y sin él "el tercer
//! generador agrega algo" es una creencia.
//!
//! ## Los temas son territorio, no opcodes
//!
//! Un tema se decide mirando el **caso entero** —el envelope de la tx, el `pre`
//! y su bytecode—, no la traza: es barato (no ejecuta nada) y dice dónde
//! **podría** pegar el caso, que es justo lo que hay que comparar entre
//! generadores.
//!
//! Los cruces (`x:…`) son el punto: los 21 sets diferenciales están
//! organizados **por tema** y por eso no se cruzan, y los cruces son donde
//! viven los bugs que ningún set mira.

use std::collections::{BTreeMap, BTreeSet};

use repo_b_common::authorization::{DELEGATION_DESIGNATOR_LEN, DELEGATION_PREFIX};
use repo_b_common::primitives::Address;

use crate::fixture::{PostCase, StateTest};
use crate::fuzz::program::{Instruction, Program};

/// El rango reservado de precompiles más `P256VERIFY` (`0x0100`), que rompe la
/// contigüidad. Se compara la dirección **completa**, igual que hace
/// `precompiles::precompile_for` desde 2.9b-3a: una tabla por último byte no
/// podría representar `0x0100`.
fn is_precompile_address(address: Address) -> bool {
    let bytes = address.into_array();
    if bytes[..18] != [0u8; 18] {
        return false;
    }
    let low = u16::from(bytes[18]) << 8 | u16::from(bytes[19]);
    (1..=0x11).contains(&low) || low == 0x0100
}

/// La dirección a la que delega este código, si es un designator.
fn delegation_target(code: &[u8]) -> Option<Address> {
    if code.len() != DELEGATION_DESIGNATOR_LEN
        || code.get(..DELEGATION_PREFIX.len())? != DELEGATION_PREFIX
    {
        return None;
    }
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(code.get(DELEGATION_PREFIX.len()..)?);
    Some(Address::new(bytes))
}

/// Qué opcodes de interés aparecen en un bytecode. Se decodifica el **stream**
/// y no se buscan bytes sueltos: `PUSH1 0xF0` no es un `CREATE`, y contarlo
/// como tal convertiría la métrica en ruido.
fn opcodes_of(code: &[u8]) -> BTreeSet<u8> {
    let mut ops = BTreeSet::new();
    for instruction in Program::decode(code).instructions {
        match instruction {
            Instruction::Op(op) => {
                ops.insert(op);
            }
            // Un `PUSH` no aporta su inmediato, un `Label` es un `JUMPDEST` y
            // un `JumpTo` es el par `PUSHn`+`JUMP` ya reconocido: ninguno de
            // los tres puede ser un CREATE ni un SELFDESTRUCT. `Raw` es la
            // cola de un `PUSH` truncado — bytes que el motor lee como ceros,
            // no como opcodes.
            Instruction::Push(_)
            | Instruction::Label(_)
            | Instruction::JumpTo { .. }
            | Instruction::Raw(_) => {}
        }
    }
    ops
}

/// Los temas que toca un caso. Nombres estables: entran al reporte y se
/// comparan entre campañas.
pub fn themes_of(test: &StateTest, post: &PostCase) -> BTreeSet<&'static str> {
    let mut themes = BTreeSet::new();
    themes.insert(fork_theme(&post.fork));

    let tx = &test.tx;
    let has_access_list = tx
        .access_lists
        .as_ref()
        .and_then(|lists| lists.get(post.data_index))
        .is_some_and(|list| !list.is_empty());
    let has_blobs = tx
        .blob_versioned_hashes
        .as_ref()
        .is_some_and(|hashes| !hashes.is_empty());
    let authorizations = tx.authorization_list.as_deref().unwrap_or_default();

    if has_access_list {
        themes.insert("tx:2930-access-list");
    }
    if has_blobs {
        themes.insert("tx:4844-blob");
    }
    if !authorizations.is_empty() {
        themes.insert("tx:7702-set-code");
    }
    if !has_access_list && !has_blobs && authorizations.is_empty() {
        themes.insert("tx:legacy-o-1559");
    }
    if tx.to.is_none() {
        themes.insert("tx:creación");
    }

    // --- el `pre`: qué hay puesto antes de ejecutar
    let mut pre_delegations = Vec::new();
    let mut has_create = false;
    let mut has_selfdestruct = false;
    let mut has_ghost = false;
    for (address, account) in &test.pre {
        if let Some(target) = delegation_target(&account.code) {
            pre_delegations.push((*address, target));
        }
        let ops = opcodes_of(&account.code);
        has_create |= ops.contains(&0xF0) || ops.contains(&0xF5);
        has_selfdestruct |= ops.contains(&0xFF);
        // La cuenta fantasma de EIP-7610: nonce 0, sin código, con storage.
        has_ghost |= account.nonce == 0 && account.code.is_empty() && !account.storage.is_empty();
    }
    if !pre_delegations.is_empty() {
        themes.insert("pre:designator-7702");
    }
    if has_create {
        themes.insert("pre:CREATE");
    }
    if has_selfdestruct {
        themes.insert("pre:SELFDESTRUCT");
    }
    if has_ghost {
        themes.insert("pre:cuenta-fantasma-7610");
    }

    // --- los cruces, que son el punto del módulo
    let delegates_to_precompile = authorizations
        .iter()
        .any(|authorization| is_precompile_address(authorization.address))
        || pre_delegations
            .iter()
            .any(|(_, target)| is_precompile_address(*target));
    if delegates_to_precompile {
        themes.insert("x:7702→precompile");
    }
    if has_blobs && has_access_list {
        themes.insert("x:4844×access-list");
    }
    if !authorizations.is_empty() && has_access_list {
        themes.insert("x:7702×access-list");
    }
    if !pre_delegations.is_empty() && has_access_list {
        // El cruce que EEST no trae: la access list calienta una cuenta que YA
        // está delegada, porque `prewarm_tx` corre ANTES de las autorizaciones.
        themes.insert("x:access-list×designator");
    }
    if !pre_delegations.is_empty() && has_blobs {
        themes.insert("x:4844×designator");
    }
    if !pre_delegations.is_empty() && has_create {
        themes.insert("x:designator×CREATE");
    }
    if !pre_delegations.is_empty() && has_selfdestruct {
        themes.insert("x:designator×SELFDESTRUCT");
    }
    // El SENDER delegado a una precompile cruza EIP-3607 con EIP-7702: la tx
    // tiene que aceptarse igual. Las dos formas cuentan —la delegación creada
    // por esta tx y la que ya venía en el `pre`—, y **la segunda es la que
    // EEST no tiene**: sin ella, el tema quedaría en cero justo donde el
    // corpus dirigido sí llega.
    let sender_delegated_to_precompile = authorizations.iter().any(|authorization| {
        authorization.authority == Some(tx.sender) && is_precompile_address(authorization.address)
    }) || pre_delegations
        .iter()
        .any(|(address, target)| *address == tx.sender && is_precompile_address(*target));
    if sender_delegated_to_precompile {
        themes.insert("x:7702→precompile×sender-delegado");
    }
    if has_ghost && has_create {
        themes.insert("x:7610×CREATE");
    }
    themes
}

fn fork_theme(fork: &str) -> &'static str {
    match fork {
        "Paris" => "fork:Paris",
        "Shanghai" => "fork:Shanghai",
        "Cancun" => "fork:Cancun",
        "Prague" => "fork:Prague",
        _ => "fork:fuera-de-scope",
    }
}

/// El tally de temas de una campaña.
#[derive(Debug, Clone, Default)]
pub struct ThemeTally {
    pub cases: u64,
    pub hits: BTreeMap<&'static str, u64>,
}

impl ThemeTally {
    pub fn observe(&mut self, test: &StateTest, post: &PostCase) {
        self.cases = self.cases.saturating_add(1);
        for theme in themes_of(test, post) {
            let slot = self.hits.entry(theme).or_default();
            *slot = slot.saturating_add(1);
        }
    }

    /// Cuántos temas distintos tocó. Es el número grueso; el reparto está en
    /// `hits` y se imprime entero, porque un solo caso de un tema y mil casos
    /// no son lo mismo.
    pub fn distinct(&self) -> usize {
        self.hits.len()
    }

    /// Los cruces (`x:…`) que tocó. Separados a propósito: un generador que
    /// toca los cinco envelopes y ningún cruce no está cubriendo el terreno
    /// que este slice existe para cubrir.
    pub fn crossings(&self) -> Vec<(&'static str, u64)> {
        self.hits
            .iter()
            .filter(|(theme, _)| theme.starts_with("x:"))
            .map(|(theme, count)| (*theme, *count))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use repo_b_common::primitives::Bytes;

    fn designator(target: u8) -> Bytes {
        let mut code: Vec<u8> = DELEGATION_PREFIX.to_vec();
        code.extend_from_slice(Address::with_last_byte(target).as_slice());
        code.into()
    }

    /// El designator se reconoce por largo Y prefijo: 23 bytes exactos. Un
    /// código que empieza igual pero mide otra cosa **no** es una delegación,
    /// y contarlo inflaría el cruce que este slice mide.
    #[test]
    fn a_delegation_designator_needs_the_exact_length_and_prefix() {
        assert_eq!(
            delegation_target(&designator(0x42)),
            Some(Address::with_last_byte(0x42))
        );
        assert_eq!(delegation_target(&[0xEF, 0x01, 0x00]), None);
        let mut too_long = designator(0x42).to_vec();
        too_long.push(0x00);
        assert_eq!(delegation_target(&too_long), None);
        assert_eq!(delegation_target(&[0x60, 0x01, 0x00]), None);
    }

    /// `0x0100` (P256VERIFY) es precompile y rompe la contigüidad del rango:
    /// una tabla por último byte no podría representarlo. `0x12` no lo es.
    #[test]
    fn the_precompile_range_includes_the_discontiguous_one() {
        assert!(is_precompile_address(Address::with_last_byte(0x01)));
        assert!(is_precompile_address(Address::with_last_byte(0x11)));
        assert!(!is_precompile_address(Address::with_last_byte(0x12)));
        assert!(!is_precompile_address(Address::ZERO));
        let mut bytes = [0u8; 20];
        bytes[18] = 0x01;
        assert!(is_precompile_address(Address::new(bytes)));
    }

    /// **Un `PUSH1 0xF0` no es un `CREATE`.** Si el clasificador buscara bytes
    /// sueltos, el tema `pre:CREATE` se prendería en medio corpus y dejaría de
    /// medir nada.
    #[test]
    fn an_immediate_is_never_mistaken_for_an_opcode() {
        assert!(opcodes_of(&[0xF0]).contains(&0xF0));
        assert!(!opcodes_of(&[0x60, 0xF0, 0x00]).contains(&0xF0));
        assert!(!opcodes_of(&[0x60, 0xFF]).contains(&0xFF));
    }
}
