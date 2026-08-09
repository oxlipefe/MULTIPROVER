//! EIP-7702 set-code: la tupla de autorización y el **designator de
//! delegación** (slice 2.7c; mínimo vendoreado, reconciliar con zeth en Fase 5).
//!
//! El designator es el único formato de código que la EVM interpreta como
//! "esta cuenta ejecuta el código de otra": 23 bytes `0xef 0x01 0x00 ++
//! address`. Vive en `common` —y no en `evm`— porque lo necesitan los DOS
//! lados del seam: el intérprete (para cobrar el acceso a la cuenta delegada,
//! EIP-2929) y el executor (para resolver qué bytecode corre un frame).

use alloc::vec::Vec;

use crate::primitives::{Address, Bytes, U256};

/// Prefijo del designator de delegación: `0xef01` (magic) + `0x00` (versión).
/// Empieza con `0xEF` a propósito: EIP-3541 prohíbe desplegar código con ese
/// primer byte, así que un designator NUNCA colisiona con código real y
/// ejecutarlo literalmente haltea de inmediato.
pub const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

/// Largo exacto del designator: 3 de prefijo + 20 de dirección.
pub const DELEGATION_DESIGNATOR_LEN: usize = DELEGATION_PREFIX.len() + 20;

/// Una tupla de autorización de una tx tipo 4 (EIP-7702).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// `U256` como en la EIP (y en revm), NO `u64`: un `chain_id` que no entra
    /// en 64 bits es representable y simplemente no matchea el del bloque
    /// (la autorización se saltea), que es exactamente lo que dice la regla.
    pub chain_id: U256,
    /// Dirección delegada. `Address::ZERO` = **limpiar** la delegación: el
    /// código de `authority` vuelve a vacío (verificado contra revm,
    /// `JournalAccount::delegate`).
    pub address: Address,
    pub nonce: u64,
    /// El firmante **YA recuperado FUERA del EVM** — mismo contrato que
    /// `Transaction::sender`. `None` = firma inválida: la EIP saltea ESA
    /// tupla sin invalidar la tx (a diferencia del sender, que sí la invalida).
    pub authority: Option<Address>,
}

pub type AuthorizationList = Vec<Authorization>;

/// El designator de 23 bytes que se escribe como código de `authority`.
pub fn delegation_designator(address: Address) -> Bytes {
    let mut code = [0u8; DELEGATION_DESIGNATOR_LEN];
    let (prefix, target) = code.split_at_mut(DELEGATION_PREFIX.len());
    prefix.copy_from_slice(&DELEGATION_PREFIX);
    target.copy_from_slice(address.as_slice());
    Bytes::copy_from_slice(&code)
}

/// ¿Este código es un designator de delegación? Devuelve la dirección
/// delegada. Estricto en las DOS condiciones (largo exacto **y** prefijo):
/// cualquier otra cosa es código común y se ejecuta literal.
pub fn delegation_target(code: &[u8]) -> Option<Address> {
    if code.len() != DELEGATION_DESIGNATOR_LEN {
        return None;
    }
    let (prefix, target) = code.split_at(DELEGATION_PREFIX.len());
    if prefix != DELEGATION_PREFIX {
        return None;
    }
    let bytes: [u8; 20] = target.try_into().ok()?;
    Some(Address::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: Address = Address::new([0xBB; 20]);

    #[test]
    fn a_designator_round_trips_to_its_delegated_address() {
        let code = delegation_designator(TARGET);
        assert_eq!(code.len(), DELEGATION_DESIGNATOR_LEN);
        assert_eq!(&code[..3], &DELEGATION_PREFIX);
        assert_eq!(delegation_target(&code), Some(TARGET));
    }

    /// Fail-closed: nada que no sea EXACTAMENTE 23 bytes con el prefijo exacto
    /// se resuelve como delegación (un byte de más, de menos, o una versión
    /// distinta ⇒ código común, que además haltea por EIP-3541).
    #[test]
    fn anything_that_is_not_the_exact_designator_is_regular_code() {
        let valid = delegation_designator(TARGET);
        assert_eq!(delegation_target(&[]), None);
        assert_eq!(delegation_target(&valid[..22]), None);

        let mut too_long = valid.to_vec();
        too_long.push(0x00);
        assert_eq!(delegation_target(&too_long), None);

        for (index, byte) in [(0u8, 0xefu8), (1, 0x01), (2, 0x00)] {
            let mut wrong = valid.to_vec();
            wrong[usize::from(index)] = byte.wrapping_add(1);
            assert_eq!(delegation_target(&wrong), None);
        }
    }
}
