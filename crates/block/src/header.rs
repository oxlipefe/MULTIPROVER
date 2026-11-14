//! El header de un bloque: sus campos, su RLP y su hash.
//!
//! **La identidad del bloque es `keccak(rlp(header))`.** Todo lo que se pueda
//! computar se computa: un hash tomado de afuera y contrastado contra sí mismo
//! no prueba nada.

use alloc::vec::Vec;

use alloy_primitives::{Address, B64, B256, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{Encodable, Header as RlpHeader};

/// Un header de Ethereum, de Frontier a Osaka.
///
/// **Los quince primeros campos son de todo header desde Frontier**; los seis
/// del final los agregó un fork, y de ahí la trampa: un encoder que emite
/// siempre todos produce un hash equivocado en Paris, y uno que emite siempre
/// el mínimo lo produce en Prague. Qué campos exige cada fork lo decide
/// la validación del header, no este tipo: acá un campo ausente es
/// `None` y nada más.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub parent_hash: B256,
    /// Post-Merge es siempre el root de la lista vacía, pero es un campo del
    /// RLP y omitirlo cambia el hash.
    pub ommers_hash: B256,
    pub beneficiary: Address,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    /// Escalar de 256 bits; post-Merge, cero.
    pub difficulty: U256,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Bytes,
    /// Post-Merge es el `prevrandao`.
    pub mix_hash: B256,
    /// El `nonce` de PoW: una cadena de **8 bytes**, no un escalar. Post-Merge
    /// es cero, y codificarlo como escalar daría `0x80` en vez de los ocho
    /// bytes.
    pub nonce: B64,
    pub base_fee_per_gas: Option<u64>,
    pub withdrawals_root: Option<B256>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_block_root: Option<B256>,
    pub requests_hash: Option<B256>,
}

impl Header {
    /// `keccak(rlp(header))` — el hash del bloque.
    #[must_use]
    pub fn hash(&self) -> B256 {
        keccak256(self.rlp())
    }

    /// El header entero en RLP.
    #[must_use]
    pub fn rlp(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.length());
        self.encode(&mut out);
        out
    }

    /// Los campos en el orden posicional del RLP.
    ///
    /// El tail se emite con una cadena de `let Some(..) else { return }`, que
    /// hace **estructuralmente imposible** emitir uno sin los anteriores: RLP es
    /// posicional, un hueco no es representable, y un `if let` por campo sí
    /// dejaría escribirlo.
    fn encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.parent_hash.encode(out);
        self.ommers_hash.encode(out);
        self.beneficiary.encode(out);
        self.state_root.encode(out);
        self.transactions_root.encode(out);
        self.receipts_root.encode(out);
        self.logs_bloom.encode(out);
        self.difficulty.encode(out);
        self.number.encode(out);
        self.gas_limit.encode(out);
        self.gas_used.encode(out);
        self.timestamp.encode(out);
        self.extra_data.encode(out);
        self.mix_hash.encode(out);
        self.nonce.encode(out);

        let Some(base_fee) = self.base_fee_per_gas else {
            return;
        };
        base_fee.encode(out);
        let Some(withdrawals_root) = self.withdrawals_root else {
            return;
        };
        withdrawals_root.encode(out);
        let Some(blob_gas_used) = self.blob_gas_used else {
            return;
        };
        blob_gas_used.encode(out);
        let Some(excess_blob_gas) = self.excess_blob_gas else {
            return;
        };
        excess_blob_gas.encode(out);
        let Some(parent_beacon_block_root) = self.parent_beacon_block_root else {
            return;
        };
        parent_beacon_block_root.encode(out);
        let Some(requests_hash) = self.requests_hash else {
            return;
        };
        requests_hash.encode(out);
    }

    /// El largo del payload, con la MISMA cadena de prefijo que el encoder: si
    /// las dos divergieran, el prefijo de la lista mentiría sobre su contenido.
    fn payload_length(&self) -> usize {
        let mut fields = [
            self.parent_hash.length(),
            self.ommers_hash.length(),
            self.beneficiary.length(),
            self.state_root.length(),
            self.transactions_root.length(),
            self.receipts_root.length(),
            self.logs_bloom.length(),
            self.difficulty.length(),
            self.number.length(),
            self.gas_limit.length(),
            self.gas_used.length(),
            self.timestamp.length(),
            self.extra_data.length(),
            self.mix_hash.length(),
            self.nonce.length(),
        ]
        .into_iter()
        .fold(0usize, usize::saturating_add);
        let tail = [
            self.base_fee_per_gas.map(|v| v.length()),
            self.withdrawals_root.map(|v| v.length()),
            self.blob_gas_used.map(|v| v.length()),
            self.excess_blob_gas.map(|v| v.length()),
            self.parent_beacon_block_root.map(|v| v.length()),
            self.requests_hash.map(|v| v.length()),
        ];
        for field in tail {
            let Some(length) = field else { break };
            fields = fields.saturating_add(length);
        }
        fields
    }
}

impl Encodable for Header {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        RlpHeader {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);
        self.encode_fields(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.payload_length();
        RlpHeader {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec;

    use repo_b_common::primitives::EMPTY_ROOT_HASH;

    use super::*;

    /// El root de la lista vacía de ommers, que es lo que declara todo header
    /// post-Merge.
    const EMPTY_UNCLE_HASH: &str =
        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

    /// 64 nibbles → `B256`. El `match`/`panic!` en vez de `unwrap`/`expect`
    /// sigue la convención del repo (`clippy::expect_used` está activo también
    /// en los tests).
    #[track_caller]
    pub(crate) fn b256(hex: &str) -> B256 {
        let mut raw = [0u8; 32];
        for (i, byte) in raw.iter_mut().enumerate() {
            let at = i * 2;
            match hex
                .get(at..at.saturating_add(2))
                .map(|pair| u8::from_str_radix(pair, 16).map_err(|_| ()))
            {
                Some(Ok(parsed)) => *byte = parsed,
                _ => panic!("hex del test mal escrito: {hex}"),
            }
        }
        B256::new(raw)
    }

    /// Los cuatro vectores del set difieren SOLO en `stateRoot` y en el tail por
    /// fork; todo lo demás es el genesis de EEST. Compartir la base es lo que
    /// hace que el test aísle el gating por fork y no la aritmética de otro campo.
    pub(crate) fn genesis(state_root: &str) -> Header {
        Header {
            parent_hash: B256::ZERO,
            ommers_hash: b256(EMPTY_UNCLE_HASH),
            number: 0,
            beneficiary: Address::ZERO,
            timestamp: 0,
            gas_limit: 0x0727_0e00,
            gas_used: 0,
            difficulty: U256::ZERO,
            extra_data: Bytes::from(vec![0x00]),
            nonce: B64::ZERO,
            base_fee_per_gas: Some(7),
            mix_hash: B256::ZERO,
            state_root: b256(state_root),
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            logs_bloom: Bloom::ZERO,
            withdrawals_root: None,
            excess_blob_gas: None,
            blob_gas_used: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        }
    }

    /// El genesis de Prague del set, con todo el tail.
    pub(crate) fn prague_genesis() -> Header {
        let mut prague =
            genesis("755e9866412352cda67b128b453dceb286cdf41885ba39a3c805884f92b8a582");
        prague.withdrawals_root = Some(EMPTY_ROOT_HASH);
        prague.blob_gas_used = Some(0);
        prague.excess_blob_gas = Some(0);
        prague.parent_beacon_block_root = Some(B256::ZERO);
        // `sha256("")`: un bloque sin requests declara el commitment de la lista
        // vacía, no el hash cero.
        prague.requests_hash = Some(b256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ));
        prague
    }

    /// **La trampa del gating, con los cuatro forks a la vez.** El mismo encoder
    /// tiene que producir cuatro largos de header distintos, y los cuatro hashes
    /// los generó EEST.
    #[test]
    fn the_four_genesis_headers_of_the_set_hash_to_their_published_value() {
        let paris = genesis("cd80a6fda833aad457e1d85a8ae4a3b41912ccfa7d317552c6662b630301e1b9");
        assert_eq!(
            paris.hash(),
            b256("dc96a2f7507bcbdc7c956e729d78973006a5742dbb202c918aea96e335bf9da6"),
            "Paris: 15 campos + baseFeePerGas"
        );

        let mut shanghai =
            genesis("44f44c5b9b3b3a2d26cd468ca33d571f858b1ac0f8e49fa893bfcc4b48858ea7");
        shanghai.withdrawals_root = Some(EMPTY_ROOT_HASH);
        assert_eq!(
            shanghai.hash(),
            b256("fcb4518bfe4d79253e1863af2f018879545e722360a24832685ee997acf26727"),
            "Shanghai: + withdrawalsRoot"
        );

        let mut cancun =
            genesis("e045360fd0e4d7b9b5fd566be2db5616b2bd028621fdb9ebfd74bdb2f4b58e7c");
        cancun.withdrawals_root = Some(EMPTY_ROOT_HASH);
        cancun.blob_gas_used = Some(0);
        cancun.excess_blob_gas = Some(0);
        cancun.parent_beacon_block_root = Some(B256::ZERO);
        assert_eq!(
            cancun.hash(),
            b256("f7cfd98b2706945dcd5e222765e4ce33a791ef29ade87d8cb75550054dcf6c9f"),
            "Cancun: + blobGasUsed, excessBlobGas, parentBeaconBlockRoot"
        );

        assert_eq!(
            prague_genesis().hash(),
            b256("1f12a8f8544ef0eb37b2cdaa334073e4163aac5a148a57196f8e5a54b20239ec"),
            "Prague: + requestsHash"
        );
    }

    /// El tail es un PREFIJO, no un conjunto: sin `withdrawalsRoot` no se puede
    /// emitir `requestsHash`, porque RLP es posicional.
    #[test]
    fn a_gap_in_the_tail_truncates_instead_of_skipping() {
        const ANY: &str = "cd80a6fda833aad457e1d85a8ae4a3b41912ccfa7d317552c6662b630301e1b9";
        let mut with_gap = genesis(ANY);
        with_gap.requests_hash = Some(B256::ZERO);
        assert_eq!(with_gap.hash(), genesis(ANY).hash());
        assert_eq!(with_gap.length(), with_gap.rlp().len());
    }

    /// Cada campo del header entra al hash.
    #[test]
    fn every_field_moves_the_hash() {
        let base = genesis("cd80a6fda833aad457e1d85a8ae4a3b41912ccfa7d317552c6662b630301e1b9");
        let reference = base.hash();

        type FieldMutation = (&'static str, fn(&mut Header));

        let mutate: Vec<FieldMutation> = vec![
            ("parentHash", |h| h.parent_hash = B256::repeat_byte(1)),
            ("ommersHash", |h| h.ommers_hash = B256::repeat_byte(2)),
            ("beneficiary", |h| h.beneficiary = Address::repeat_byte(3)),
            ("stateRoot", |h| h.state_root = B256::repeat_byte(4)),
            ("transactionsRoot", |h| {
                h.transactions_root = B256::repeat_byte(5);
            }),
            ("receiptsRoot", |h| h.receipts_root = B256::repeat_byte(6)),
            ("logsBloom", |h| h.logs_bloom = Bloom::new([7u8; 256])),
            ("difficulty", |h| h.difficulty = U256::from(8)),
            ("number", |h| h.number = 9),
            ("gasLimit", |h| h.gas_limit = 10),
            ("gasUsed", |h| h.gas_used = 11),
            ("timestamp", |h| h.timestamp = 12),
            ("extraData", |h| h.extra_data = Bytes::from(vec![13])),
            ("mixHash", |h| h.mix_hash = B256::repeat_byte(14)),
            ("nonce", |h| h.nonce = B64::repeat_byte(15)),
            ("baseFeePerGas", |h| h.base_fee_per_gas = Some(16)),
        ];
        for (name, apply) in mutate {
            let mut mutated = base.clone();
            apply(&mut mutated);
            assert_ne!(
                mutated.hash(),
                reference,
                "{name} no entra al hash del header"
            );
        }
    }

    /// El `nonce` es una cadena de 8 bytes; `difficulty` es un escalar.
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
