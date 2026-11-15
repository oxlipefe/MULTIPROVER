//! El bloque **tal como viaja**: `rlp([header, txs, ommers, withdrawals])`.
//!
//! Es el objeto que un cliente recibe y el que EIP-7934 mide, así que se lee
//! de sus bytes y no se re-describe: el header sale de su propio RLP, las txs
//! salen como sus envelopes EIP-2718 (lo que el `transactionsRoot` commitea) y
//! los ommers se **cuentan** del RLP recibido, no de un campo aparte que pueda
//! decir otra cosa.
//!
//! **Este decoder no interpreta las txs.** Devuelve los envelopes crudos: el
//! decoder de cada envelope es el mismo que arma el hash de firma, y vive con
//! él. Separar el corte del bloque del decode de la tx es lo que permite
//! computar el `transactionsRoot` sobre los bytes recibidos y no sobre una
//! re-codificación nuestra.
//!
//! Todo error es un rechazo: un cuerpo que no decodifica es un bloque inválido,
//! nunca un bloque con menos txs.

use alloc::vec::Vec;

use alloy_primitives::Address;
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};
use repo_b_common::spec::Spec;
use repo_b_common::withdrawal::Withdrawal;

use crate::error::BlockError;
use crate::header::Header;

/// El primer byte de la cabecera de una lista RLP. Una tx legacy es una lista;
/// un envelope tipado arranca con su byte de tipo, que es menor que esto.
const RLP_LIST_OFFSET: u8 = 0xc0;

/// Un bloque decodificado de sus bytes. Las txs y los ommers **prestan** del
/// buffer recibido: lo que se commitea es lo que llegó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block<'a> {
    pub header: Header,
    /// Los envelopes EIP-2718, en orden: la lista RLP de una legacy, o
    /// `type ‖ rlp(payload)` de una tipada.
    pub transactions: Vec<&'a [u8]>,
    /// Cuántos ommers trae el cuerpo. Post-Merge tiene que ser cero
    /// ([`crate::check_ommers`]); se cuenta del RLP, no se cree.
    pub ommers: usize,
    /// `None` si el cuerpo no trae la lista (pre-Shanghai). Que esté o no lo
    /// juzga [`check_body_fields`] contra el fork.
    pub withdrawals: Option<Vec<Withdrawal>>,
}

/// El próximo ítem RLP de `buf`: su cabecera, su payload y el ítem entero
/// (cabecera incluida). Deja `buf` después del ítem.
fn next_item<'a>(buf: &mut &'a [u8]) -> Result<(RlpHeader, &'a [u8], &'a [u8]), BlockError> {
    let start: &'a [u8] = buf;
    let mut cursor: &'a [u8] = buf;
    let header = RlpHeader::decode(&mut cursor).map_err(BlockError::BlockRlp)?;
    let prefix = start.len().saturating_sub(cursor.len());
    let (payload, rest) = cursor
        .split_at_checked(header.payload_length)
        .ok_or(BlockError::BlockRlp(alloy_rlp::Error::InputTooShort))?;
    let total = prefix
        .checked_add(header.payload_length)
        .ok_or(BlockError::BlockRlp(alloy_rlp::Error::Overflow))?;
    let item = start
        .get(..total)
        .ok_or(BlockError::BlockRlp(alloy_rlp::Error::InputTooShort))?;
    *buf = rest;
    Ok((header, payload, item))
}

/// El payload de la próxima lista de `buf`. Una cadena donde va una lista es un
/// cuerpo con otra forma.
fn next_list<'a>(buf: &mut &'a [u8], what: &'static str) -> Result<&'a [u8], BlockError> {
    let (header, payload, _) = next_item(buf)?;
    if !header.list {
        return Err(BlockError::BodyShape { reason: what });
    }
    Ok(payload)
}

/// Una tx del cuerpo → su envelope EIP-2718.
///
/// EIP-2718 en el cuerpo de un bloque: una legacy va como **lista** y una
/// tipada como **cadena** cuyo contenido es `type ‖ rlp(payload)`. Una cadena
/// que adentro tiene una lista sería una legacy envuelta, que no es ninguna de
/// las dos formas y no tiene un envelope canónico.
fn envelope<'a>(buf: &mut &'a [u8]) -> Result<&'a [u8], BlockError> {
    let (header, payload, item) = next_item(buf)?;
    if header.list {
        return Ok(item);
    }
    match payload.first() {
        Some(byte) if *byte < RLP_LIST_OFFSET => Ok(payload),
        _ => Err(BlockError::BodyShape {
            reason: "una tx tipada que no empieza con su byte de tipo",
        }),
    }
}

/// `rlp([index, validatorIndex, address, amount])` (EIP-4895), sin campos de
/// más.
fn withdrawal(buf: &mut &[u8]) -> Result<Withdrawal, BlockError> {
    let mut fields = next_list(buf, "una withdrawal que no es una lista")?;
    let rlp = BlockError::BlockRlp;
    let decoded = Withdrawal {
        index: u64::decode(&mut fields).map_err(rlp)?,
        validator_index: u64::decode(&mut fields).map_err(rlp)?,
        address: Address::decode(&mut fields).map_err(rlp)?,
        amount: u64::decode(&mut fields).map_err(rlp)?,
    };
    if !fields.is_empty() {
        return Err(BlockError::BodyShape {
            reason: "una withdrawal con campos de más",
        });
    }
    Ok(decoded)
}

/// Decodifica un bloque que ocupa **exactamente** `raw`.
///
/// # Errors
/// [`BlockError::BlockRlp`] si los bytes no son RLP canónico y
/// [`BlockError::BodyShape`] si el RLP es válido pero el bloque tiene otra
/// forma (menos de tres o más de cuatro ítems, una tx envuelta mal, bytes
/// detrás del bloque).
pub fn decode_block(raw: &[u8]) -> Result<Block<'_>, BlockError> {
    let mut cursor = raw;
    let mut items = next_list(&mut cursor, "el bloque no es una lista")?;
    if !cursor.is_empty() {
        return Err(BlockError::BodyShape {
            reason: "hay bytes después del bloque",
        });
    }
    let header = Header::decode(&mut items).map_err(BlockError::HeaderRlp)?;

    let mut txs = next_list(&mut items, "las txs no son una lista")?;
    let mut transactions = Vec::new();
    while !txs.is_empty() {
        transactions.push(envelope(&mut txs)?);
    }

    let mut ommer_items = next_list(&mut items, "los ommers no son una lista")?;
    let mut ommers = 0usize;
    while !ommer_items.is_empty() {
        next_item(&mut ommer_items)?;
        ommers = ommers
            .checked_add(1)
            .ok_or(BlockError::BlockRlp(alloy_rlp::Error::Overflow))?;
    }

    let withdrawals = if items.is_empty() {
        None
    } else {
        let mut list = next_list(&mut items, "las withdrawals no son una lista")?;
        let mut out = Vec::new();
        while !list.is_empty() {
            out.push(withdrawal(&mut list)?);
        }
        Some(out)
    };
    if !items.is_empty() {
        return Err(BlockError::BodyShape {
            reason: "el bloque trae más ítems que los que conoce Osaka",
        });
    }
    Ok(Block {
        header,
        transactions,
        ommers,
        withdrawals,
    })
}

/// La lista de withdrawals está en el cuerpo **si y solo si** el fork la tiene
/// (EIP-4895, Shanghai). Un cuerpo de Shanghai sin la lista no es un cuerpo sin
/// withdrawals: es otra forma de bloque.
pub fn check_body_fields(block: &Block<'_>, spec: Spec) -> Result<(), BlockError> {
    match (spec.is_enabled(Spec::Shanghai), block.withdrawals.is_some()) {
        (true, false) => Err(BlockError::BodyShape {
            reason: "el fork exige la lista de withdrawals y el cuerpo no la trae",
        }),
        (false, true) => Err(BlockError::BodyShape {
            reason: "el cuerpo trae withdrawals y el fork no las tiene",
        }),
        _ => Ok(()),
    }
}

/// Envuelve `payload` en una cabecera de lista.
fn list_into(payload: &[u8], out: &mut Vec<u8>) {
    RlpHeader {
        list: true,
        payload_length: payload.len(),
    }
    .encode(out);
    out.extend_from_slice(payload);
}

/// La inversa de [`decode_block`], **sin ommers** (post-Merge no hay). Cada
/// envelope entra en la forma de EIP-2718: la legacy como la lista que ya es,
/// la tipada como cadena.
#[must_use]
pub fn encode_block<T: AsRef<[u8]>>(
    header: &Header,
    transactions: &[T],
    withdrawals: Option<&[Withdrawal]>,
) -> Vec<u8> {
    let mut items = header.rlp();
    let mut txs = Vec::new();
    for tx in transactions {
        let tx = tx.as_ref();
        match tx.first() {
            Some(byte) if *byte >= RLP_LIST_OFFSET => txs.extend_from_slice(tx),
            _ => tx.encode(&mut txs),
        }
    }
    list_into(&txs, &mut items);
    list_into(&[], &mut items);
    if let Some(withdrawals) = withdrawals {
        let mut ws = Vec::new();
        for w in withdrawals {
            w.encode(&mut ws);
        }
        list_into(&ws, &mut items);
    }
    let mut out = Vec::with_capacity(items.len().saturating_add(9));
    list_into(&items, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use alloy_primitives::{Bytes, U256};

    use super::*;
    use crate::header::tests::prague_genesis as sample_header;

    const LEGACY: &[u8] = &[0xc3, 0x01, 0x02, 0x03];
    const TYPED: &[u8] = &[0x02, 0xc2, 0x05, 0x06];

    fn withdrawals() -> Vec<Withdrawal> {
        vec![Withdrawal {
            index: 7,
            validator_index: 8,
            address: Address::repeat_byte(0xaa),
            amount: 9,
        }]
    }

    #[test]
    fn a_block_survives_a_round_trip() {
        let header = sample_header();
        let ws = withdrawals();
        let raw = encode_block(&header, &[LEGACY, TYPED], Some(&ws));
        let Ok(block) = decode_block(&raw) else {
            panic!("el bloque tiene que decodificar");
        };
        assert_eq!(block.header, header);
        assert_eq!(block.transactions, vec![LEGACY, TYPED]);
        assert_eq!(block.ommers, 0);
        assert_eq!(block.withdrawals, Some(ws));
    }

    /// La legacy viaja como la lista que ya es; la tipada, como cadena. Un
    /// envelope tipado sin envolver dejaría un ítem que no es ni una cosa ni
    /// la otra.
    #[test]
    fn a_typed_tx_travels_as_a_string_and_a_legacy_one_as_a_list() {
        let raw = encode_block(&sample_header(), &[LEGACY, TYPED], None);
        let typed_as_string = [0x84, 0x02, 0xc2, 0x05, 0x06];
        assert!(raw.windows(LEGACY.len()).any(|w| w == LEGACY));
        assert!(
            raw.windows(typed_as_string.len())
                .any(|w| w == typed_as_string)
        );
    }

    /// Una legacy envuelta en una cadena no tiene envelope canónico.
    #[test]
    fn a_legacy_tx_wrapped_in_a_string_is_refused() {
        let mut raw = encode_block(&sample_header(), &[TYPED], None);
        let at = raw
            .windows(TYPED.len())
            .position(|w| w == TYPED)
            .unwrap_or_default();
        if let Some(byte) = raw.get_mut(at) {
            *byte = 0xc2;
        }
        assert_eq!(
            decode_block(&raw),
            Err(BlockError::BodyShape {
                reason: "una tx tipada que no empieza con su byte de tipo",
            })
        );
    }

    /// Los ommers se CUENTAN del RLP: un cuerpo que los trae dice cuántos, y
    /// lo juzga `check_ommers`.
    #[test]
    fn the_ommers_are_counted_from_the_rlp() {
        let header = sample_header();
        let mut items = header.rlp();
        list_into(&[], &mut items);
        let mut ommers = Vec::new();
        ommers.extend_from_slice(&header.rlp());
        ommers.extend_from_slice(&header.rlp());
        list_into(&ommers, &mut items);
        let mut raw = Vec::new();
        list_into(&items, &mut raw);
        assert_eq!(decode_block(&raw).map(|b| b.ommers), Ok(2));
    }

    #[test]
    fn trailing_bytes_after_the_block_are_refused() {
        let mut raw = encode_block(&sample_header(), &[LEGACY], None);
        raw.push(0x00);
        assert_eq!(
            decode_block(&raw),
            Err(BlockError::BodyShape {
                reason: "hay bytes después del bloque"
            })
        );
    }

    #[test]
    fn a_fifth_item_is_refused() {
        let header = sample_header();
        let mut items = header.rlp();
        for _ in 0..3 {
            list_into(&[], &mut items);
        }
        Bytes::from_static(b"x").encode(&mut items);
        let mut raw = Vec::new();
        list_into(&items, &mut raw);
        assert_eq!(
            decode_block(&raw),
            Err(BlockError::BodyShape {
                reason: "el bloque trae más ítems que los que conoce Osaka",
            })
        );
    }

    #[test]
    fn a_withdrawal_with_an_extra_field_is_refused() {
        let header = sample_header();
        let mut items = header.rlp();
        list_into(&[], &mut items);
        list_into(&[], &mut items);
        let mut fields = Vec::new();
        for value in [1u64, 2] {
            value.encode(&mut fields);
        }
        Address::ZERO.encode(&mut fields);
        U256::from(3u8).encode(&mut fields);
        4u64.encode(&mut fields);
        let mut one = Vec::new();
        list_into(&fields, &mut one);
        let mut ws = Vec::new();
        list_into(&one, &mut ws);
        items.extend_from_slice(&ws);
        let mut raw = Vec::new();
        list_into(&items, &mut raw);
        assert_eq!(
            decode_block(&raw),
            Err(BlockError::BodyShape {
                reason: "una withdrawal con campos de más"
            })
        );
    }

    /// Un largo que miente: la lista declara más de lo que hay.
    #[test]
    fn a_truncated_block_is_refused() {
        let raw = encode_block(&sample_header(), &[LEGACY], None);
        let cut = raw.get(..raw.len().saturating_sub(1)).unwrap_or_default();
        assert!(matches!(decode_block(cut), Err(BlockError::BlockRlp(_))));
    }

    #[test]
    fn the_withdrawals_list_is_there_iff_the_fork_has_it() {
        let header = sample_header();
        let sin = encode_block(&header, &[LEGACY], None);
        let con = encode_block(&header, &[LEGACY], Some(&[]));
        let (Ok(sin), Ok(con)) = (decode_block(&sin), decode_block(&con)) else {
            panic!("los dos bloques tienen que decodificar");
        };
        assert_eq!(check_body_fields(&sin, Spec::Paris), Ok(()));
        assert_eq!(check_body_fields(&con, Spec::Shanghai), Ok(()));
        assert!(check_body_fields(&sin, Spec::Shanghai).is_err());
        assert!(check_body_fields(&con, Spec::Paris).is_err());
    }
}
