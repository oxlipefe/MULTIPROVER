//! La identidad del bloque: `keccak(rlp(header))`.
//!
//! Vive en el harness y no en el motor por el mismo corte que el resto del
//! encoding: es RLP y hashing sobre el header, no transición de estado. En
//! producción lo hace el cliente stateless.
//!
//! **Por qué existe este módulo.** El hash del bloque se puede **tomar** del
//! fixture, y así arrancó el eje: alimentaba `BLOCKHASH`, movía el head y se
//! contrastaba contra `lastblockhash` — o sea, contra sí mismo. Con eso el eje
//! podía figurar 100 % verde con una familia entera de reglas de consenso —el
//! encoding del header y la identidad del bloque— sin una sola aserción que las
//! tocara. Computarlo convierte el campo `hash` de cada header en un oráculo
//! generado por EEST, y con eso el encoder pasa de no tener evidencia a tener la
//! más ancha del repo.
//!
//! Regla del corte: **nada se compara contra sí mismo.** Lo que se computa acá se
//! contrasta contra el `hash` que el fixture publica, y ningún otro camino del
//! driver lee ese campo.

use alloy_rlp::{Encodable, Header as RlpHeader};
use repo_b_common::primitives::{B256, keccak256};

use super::fixture::BlockHeader;

/// `keccak(rlp(header))` — el hash del bloque.
pub fn block_hash(header: &BlockHeader) -> B256 {
    let payload = encode_payload(header);
    let mut out = Vec::new();
    RlpHeader {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(&payload);
    keccak256(&out)
}

/// Los campos del header, en el orden posicional del RLP.
///
/// **Los quince primeros son de todo header desde Frontier**; los seis del final
/// los agregó un fork, y de ahí la trampa: un encoder que emite siempre todos
/// produce un hash equivocado en Paris, y uno que emite siempre el mínimo lo
/// produce en Prague.
///
/// La presencia se resuelve **por el fixture y no por `Spec`**: los seis se
/// parsean como `Option` sin default (verificado: presencia y fork coinciden
/// exacto en los cuatro forks en scope, en el header de genesis y en los de
/// bloque). Y se emiten con una cadena de `let Some(..) else { return }`, que
/// hace **estructuralmente imposible** emitir uno del tail sin los anteriores:
/// RLP es posicional, un hueco no es representable, y un `if let` por campo sí
/// dejaría escribirlo.
fn encode_payload(header: &BlockHeader) -> Vec<u8> {
    let mut out = Vec::new();
    header.parent_hash.encode(&mut out);
    header.uncle_hash.encode(&mut out);
    header.coinbase.encode(&mut out);
    header.state_root.encode(&mut out);
    header.transactions_trie.encode(&mut out);
    header.receipt_trie.encode(&mut out);
    header.bloom.encode(&mut out);
    header.difficulty.encode(&mut out);
    header.number.encode(&mut out);
    header.gas_limit.encode(&mut out);
    header.gas_used.encode(&mut out);
    header.timestamp.encode(&mut out);
    header.extra_data.encode(&mut out);
    header.mix_hash.encode(&mut out);
    header.nonce.encode(&mut out);

    // London (EIP-1559).
    let Some(base_fee) = header.base_fee else {
        return out;
    };
    base_fee.encode(&mut out);
    // Shanghai (EIP-4895).
    let Some(withdrawals_root) = header.withdrawals_root else {
        return out;
    };
    withdrawals_root.encode(&mut out);
    // Cancun: los tres van juntos (EIP-4844 + EIP-4788).
    let Some(blob_gas_used) = header.blob_gas_used else {
        return out;
    };
    blob_gas_used.encode(&mut out);
    let Some(excess_blob_gas) = header.excess_blob_gas else {
        return out;
    };
    excess_blob_gas.encode(&mut out);
    let Some(parent_beacon_block_root) = header.parent_beacon_block_root else {
        return out;
    };
    parent_beacon_block_root.encode(&mut out);
    // Prague (EIP-7685).
    let Some(requests_hash) = header.requests_hash else {
        return out;
    };
    requests_hash.encode(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B64, Bloom};
    use repo_b_common::primitives::{Address, Bytes, U256};

    use super::*;

    /// El root de la lista vacía de ommers, que es lo que declara todo header
    /// post-Merge.
    const EMPTY_UNCLE_HASH: &str =
        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

    /// 64 nibbles → `B256`. El `match`/`panic!` en vez de `unwrap`/`expect`
    /// sigue la convención del repo (`clippy::expect_used` está activo también
    /// en los tests).
    #[track_caller]
    fn b256(hex: &str) -> B256 {
        let mut raw = [0u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            let at = i * 2;
            match hex.get(at..at.saturating_add(2)).map(|pair| {
                u8::from_str_radix(pair, 16).map_err(|_| ()) //
            }) {
                Some(Ok(parsed)) => *byte = parsed,
                _ => panic!("hex del test mal escrito: {hex}"),
            }
        }
        B256::new(raw)
    }

    /// Los cuatro vectores del set difieren SOLO en `stateRoot` y en el tail por
    /// fork; todo lo demás es el genesis de EEST. Compartir la base es lo que
    /// hace que el test aísle el gating por fork y no la aritmética de otro campo.
    fn genesis(state_root: &str) -> BlockHeader {
        BlockHeader {
            hash: B256::ZERO,
            parent_hash: B256::ZERO,
            uncle_hash: b256(EMPTY_UNCLE_HASH),
            number: 0,
            coinbase: Address::ZERO,
            timestamp: 0,
            gas_limit: 0x0727_0e00,
            gas_used: 0,
            difficulty: U256::ZERO,
            extra_data: Bytes::from(vec![0x00]),
            nonce: B64::ZERO,
            base_fee: Some(7),
            mix_hash: B256::ZERO,
            state_root: b256(state_root),
            transactions_trie: repo_b_common::primitives::EMPTY_ROOT_HASH,
            receipt_trie: repo_b_common::primitives::EMPTY_ROOT_HASH,
            bloom: Bloom::ZERO,
            withdrawals_root: None,
            excess_blob_gas: None,
            blob_gas_used: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    /// **La trampa del gating, con los cuatro forks a la vez.** El mismo encoder
    /// tiene que producir cuatro largos de header distintos, y los cuatro hashes
    /// los generó EEST. Un encoder que emitiera siempre todos los campos
    /// fallaría en Paris; uno que emitiera siempre el mínimo, en Prague.
    #[test]
    fn the_four_genesis_headers_of_the_set_hash_to_their_published_value() {
        let paris = genesis("cd80a6fda833aad457e1d85a8ae4a3b41912ccfa7d317552c6662b630301e1b9");
        assert_eq!(
            block_hash(&paris),
            b256("dc96a2f7507bcbdc7c956e729d78973006a5742dbb202c918aea96e335bf9da6"),
            "Paris: 15 campos + baseFeePerGas"
        );

        let mut shanghai =
            genesis("44f44c5b9b3b3a2d26cd468ca33d571f858b1ac0f8e49fa893bfcc4b48858ea7");
        shanghai.withdrawals_root = Some(repo_b_common::primitives::EMPTY_ROOT_HASH);
        assert_eq!(
            block_hash(&shanghai),
            b256("fcb4518bfe4d79253e1863af2f018879545e722360a24832685ee997acf26727"),
            "Shanghai: + withdrawalsRoot"
        );

        let mut cancun =
            genesis("e045360fd0e4d7b9b5fd566be2db5616b2bd028621fdb9ebfd74bdb2f4b58e7c");
        cancun.withdrawals_root = Some(repo_b_common::primitives::EMPTY_ROOT_HASH);
        cancun.blob_gas_used = Some(0);
        cancun.excess_blob_gas = Some(0);
        cancun.parent_beacon_block_root = Some(B256::ZERO);
        assert_eq!(
            block_hash(&cancun),
            b256("f7cfd98b2706945dcd5e222765e4ce33a791ef29ade87d8cb75550054dcf6c9f"),
            "Cancun: + blobGasUsed, excessBlobGas, parentBeaconBlockRoot"
        );

        let mut prague =
            genesis("755e9866412352cda67b128b453dceb286cdf41885ba39a3c805884f92b8a582");
        prague.withdrawals_root = Some(repo_b_common::primitives::EMPTY_ROOT_HASH);
        prague.blob_gas_used = Some(0);
        prague.excess_blob_gas = Some(0);
        prague.parent_beacon_block_root = Some(B256::ZERO);
        // `sha256("")`: un bloque sin requests declara el commitment de la lista
        // vacía, no el hash cero.
        prague.requests_hash = Some(b256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ));
        assert_eq!(
            block_hash(&prague),
            b256("1f12a8f8544ef0eb37b2cdaa334073e4163aac5a148a57196f8e5a54b20239ec"),
            "Prague: + requestsHash"
        );
    }

    /// El tail es un PREFIJO, no un conjunto: sin `withdrawalsRoot` no se puede
    /// emitir `requestsHash`, porque RLP es posicional. Lo garantiza la cadena de
    /// `let Some(..) else { return }`, y esto lo pinea: un header al que le
    /// falte un campo del medio produce el hash del prefijo, no el de un header
    /// con hueco.
    #[test]
    fn a_gap_in_the_tail_truncates_instead_of_skipping() {
        const ANY: &str = "cd80a6fda833aad457e1d85a8ae4a3b41912ccfa7d317552c6662b630301e1b9";
        let mut with_gap = genesis(ANY);
        with_gap.requests_hash = Some(B256::ZERO);
        let paris = genesis(ANY);
        assert_eq!(
            block_hash(&with_gap),
            block_hash(&paris),
            "sin withdrawalsRoot ni los de Cancun, el requestsHash no se emite"
        );
    }

    /// Cada campo del header entra al hash. Si alguno no entrara, el encoder
    /// aceptaría dos bloques distintos como el mismo — y el corpus podría no
    /// tener un caso que los separe.
    #[test]
    fn every_field_moves_the_hash() {
        let base = genesis("cd80a6fda833aad457e1d85a8ae4a3b41912ccfa7d317552c6662b630301e1b9");
        let reference = block_hash(&base);

        /// Un campo del header, con el nombre que usa el fixture y la función que
        /// lo cambia.
        type FieldMutation = (&'static str, fn(&mut BlockHeader));

        let mutate: Vec<FieldMutation> = vec![
            ("parentHash", |h| h.parent_hash = B256::repeat_byte(1)),
            ("uncleHash", |h| h.uncle_hash = B256::repeat_byte(2)),
            ("coinbase", |h| h.coinbase = Address::repeat_byte(3)),
            ("stateRoot", |h| h.state_root = B256::repeat_byte(4)),
            ("transactionsTrie", |h| {
                h.transactions_trie = B256::repeat_byte(5);
            }),
            ("receiptTrie", |h| h.receipt_trie = B256::repeat_byte(6)),
            ("bloom", |h| h.bloom = Bloom::new([7u8; 256])),
            ("difficulty", |h| h.difficulty = U256::from(8)),
            ("number", |h| h.number = 9),
            ("gasLimit", |h| h.gas_limit = 10),
            ("gasUsed", |h| h.gas_used = 11),
            ("timestamp", |h| h.timestamp = 12),
            ("extraData", |h| h.extra_data = Bytes::from(vec![13])),
            ("mixHash", |h| h.mix_hash = B256::repeat_byte(14)),
            ("nonce", |h| h.nonce = B64::repeat_byte(15)),
            ("baseFeePerGas", |h| h.base_fee = Some(16)),
        ];
        for (name, apply) in mutate {
            let mut mutated = base.clone();
            apply(&mut mutated);
            assert_ne!(
                block_hash(&mutated),
                reference,
                "{name} no entra al hash del header"
            );
        }
    }

    /// El `nonce` es una cadena de 8 bytes, no un escalar: codificarlo como
    /// escalar daría `0x80` para el cero y el hash de todo header post-Merge
    /// saldría mal. Lo mismo con `difficulty`, que SÍ es escalar — confundir los
    /// dos es el bug simétrico.
    #[test]
    fn the_pow_nonce_is_eight_bytes_and_the_difficulty_is_a_scalar() {
        let mut nonce = Vec::new();
        B64::ZERO.encode(&mut nonce);
        assert_eq!(nonce, vec![0x88, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut difficulty = Vec::new();
        U256::ZERO.encode(&mut difficulty);
        assert_eq!(difficulty, vec![0x80]);
    }
}
