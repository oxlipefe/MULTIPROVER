//! El header de un bloque: sus campos, su RLP en las dos direcciones y su hash.
//!
//! **La identidad del bloque es `keccak(rlp(header))`.** Todo lo que se pueda
//! computar se computa: un hash tomado de afuera y contrastado contra sí mismo
//! no prueba nada.

use alloc::vec::Vec;

use alloy_primitives::{Address, B64, B256, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{Decodable, Encodable, Header as RlpHeader};

use crate::error::BlockError;

/// Un header de Ethereum, de Frontier a Osaka.
///
/// **Los quince primeros campos son de todo header desde Frontier**; los seis
/// del final los agregó un fork, y de ahí la trampa: un encoder que emite
/// siempre todos produce un hash equivocado en Paris, y uno que emite siempre
/// el mínimo lo produce en Prague. Qué campos exige cada fork lo decide
/// [`crate::validate_fork_fields`], no este tipo: acá un campo ausente es
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

    /// Decodifica un header que ocupa **exactamente** `raw`: un byte de más
    /// detrás de la lista es un input que no es un header, no un header con
    /// basura que se ignora.
    pub fn decode_exact(raw: &[u8]) -> Result<Self, BlockError> {
        let mut cursor = raw;
        let header = Self::decode(&mut cursor).map_err(BlockError::HeaderRlp)?;
        if !cursor.is_empty() {
            return Err(BlockError::HeaderTrailingBytes {
                trailing: cursor.len(),
            });
        }
        Ok(header)
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

/// Decodifica el próximo campo del tail si el payload no se terminó.
fn optional<T: Decodable>(payload: &mut &[u8]) -> alloy_rlp::Result<Option<T>> {
    if payload.is_empty() {
        return Ok(None);
    }
    T::decode(payload).map(Some)
}

impl Decodable for Header {
    /// La inversa exacta de `encode`: los quince campos de Frontier
    /// obligatorios, el tail como prefijo (un campo ausente apaga todos los de
    /// después) y **nada más**. Un campo de un fork que este tipo no conoce
    /// hace fallar el decode en vez de perderse en silencio. Los enteros los
    /// decodifica `alloy_rlp`, que rechaza los ceros a la izquierda: el único
    /// encoding aceptado es el canónico, así que `rlp(decode(x)) == x`.
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let rlp_header = RlpHeader::decode(buf)?;
        if !rlp_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let (mut payload, rest) = buf
            .split_at_checked(rlp_header.payload_length)
            .ok_or(alloy_rlp::Error::InputTooShort)?;
        let p = &mut payload;
        let mut header = Self {
            parent_hash: Decodable::decode(p)?,
            ommers_hash: Decodable::decode(p)?,
            beneficiary: Decodable::decode(p)?,
            state_root: Decodable::decode(p)?,
            transactions_root: Decodable::decode(p)?,
            receipts_root: Decodable::decode(p)?,
            logs_bloom: Decodable::decode(p)?,
            difficulty: Decodable::decode(p)?,
            number: Decodable::decode(p)?,
            gas_limit: Decodable::decode(p)?,
            gas_used: Decodable::decode(p)?,
            timestamp: Decodable::decode(p)?,
            extra_data: Decodable::decode(p)?,
            mix_hash: Decodable::decode(p)?,
            nonce: Decodable::decode(p)?,
            base_fee_per_gas: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };
        header.base_fee_per_gas = optional(p)?;
        header.withdrawals_root = optional(p)?;
        header.blob_gas_used = optional(p)?;
        header.excess_blob_gas = optional(p)?;
        header.parent_beacon_block_root = optional(p)?;
        header.requests_hash = optional(p)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::Custom(
                "el header trae más campos que los que conoce Osaka",
            ));
        }
        *buf = rest;
        Ok(header)
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
            let at = i.saturating_mul(2);
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

    /// El decode es la inversa exacta del encode, en los cuatro largos de tail.
    #[test]
    fn decode_inverts_encode_for_every_tail_length() {
        let mut header = prague_genesis();
        for _ in 0..6 {
            let raw = header.rlp();
            assert_eq!(Header::decode_exact(&raw), Ok(header.clone()));
            // Apagar el último campo presente del tail.
            if header.requests_hash.take().is_none()
                && header.parent_beacon_block_root.take().is_none()
                && header.excess_blob_gas.take().is_none()
                && header.blob_gas_used.take().is_none()
                && header.withdrawals_root.take().is_none()
            {
                header.base_fee_per_gas = None;
            }
        }
    }

    /// Un byte detrás del header no es parte del header.
    #[test]
    fn trailing_bytes_after_the_header_are_rejected() {
        let mut raw = prague_genesis().rlp();
        raw.push(0x00);
        assert_eq!(
            Header::decode_exact(&raw),
            Err(BlockError::HeaderTrailingBytes { trailing: 1 })
        );
    }

    /// Un campo de más dentro de la lista (el de un fork que este tipo no
    /// conoce) no se pierde en silencio: el decode falla.
    #[test]
    fn a_field_beyond_osaka_is_rejected() {
        let prague = prague_genesis();
        let mut payload = Vec::new();
        prague.encode_fields(&mut payload);
        B256::ZERO.encode(&mut payload);
        let mut raw = Vec::new();
        RlpHeader {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut raw);
        raw.extend_from_slice(&payload);
        assert!(matches!(
            Header::decode_exact(&raw),
            Err(BlockError::HeaderRlp(_))
        ));
    }

    /// Un header que no es una lista, uno truncado y uno con un entero no
    /// canónico (cero a la izquierda) no decodifican.
    #[test]
    fn malformed_headers_are_rejected() {
        assert!(Header::decode_exact(&[0x80]).is_err());
        assert!(Header::decode_exact(&[]).is_err());
        let raw = prague_genesis().rlp();
        let truncated = raw.get(..raw.len().saturating_sub(1)).unwrap_or_default();
        assert!(Header::decode_exact(truncated).is_err());

        // `number` con un cero a la izquierda: mismo valor, encoding no
        // canónico. El valor es distintivo para que su encoding sea una
        // secuencia que no aparece en otro campo.
        let mut header = prague_genesis();
        header.number = 0x0102_0304_0506;
        let mut payload = Vec::new();
        header.encode_fields(&mut payload);
        let canonical_number: [u8; 7] = [0x86, 1, 2, 3, 4, 5, 6];
        let Some(at) = payload
            .windows(canonical_number.len())
            .position(|w| w == canonical_number.as_slice())
        else {
            panic!("el payload no contiene el number");
        };
        let mut tampered_payload = payload.get(..at).unwrap_or_default().to_vec();
        tampered_payload.extend_from_slice(&[0x87, 0, 1, 2, 3, 4, 5, 6]);
        tampered_payload.extend_from_slice(
            payload
                .get(at.saturating_add(canonical_number.len())..)
                .unwrap_or_default(),
        );
        let mut tampered = Vec::new();
        RlpHeader {
            list: true,
            payload_length: tampered_payload.len(),
        }
        .encode(&mut tampered);
        tampered.extend_from_slice(&tampered_payload);
        assert!(Header::decode_exact(&header.rlp()).is_ok());
        assert!(Header::decode_exact(&tampered).is_err());
    }

    /// Cada campo del header en su RLP canónico, en orden posicional. La
    /// concatenación tiene que ser el payload que emite el encoder: si no, el
    /// helper estaría probando otro layout.
    fn encoded_fields(header: &Header) -> Vec<Vec<u8>> {
        fn one(field: &dyn Encodable) -> Vec<u8> {
            let mut out = Vec::new();
            field.encode(&mut out);
            out
        }
        let mut fields = vec![
            one(&header.parent_hash),
            one(&header.ommers_hash),
            one(&header.beneficiary),
            one(&header.state_root),
            one(&header.transactions_root),
            one(&header.receipts_root),
            one(&header.logs_bloom),
            one(&header.difficulty),
            one(&header.number),
            one(&header.gas_limit),
            one(&header.gas_used),
            one(&header.timestamp),
            one(&header.extra_data),
            one(&header.mix_hash),
            one(&header.nonce),
        ];
        let tail: [Option<&dyn Encodable>; 6] = [
            header
                .base_fee_per_gas
                .as_ref()
                .map(|v| v as &dyn Encodable),
            header
                .withdrawals_root
                .as_ref()
                .map(|v| v as &dyn Encodable),
            header.blob_gas_used.as_ref().map(|v| v as &dyn Encodable),
            header.excess_blob_gas.as_ref().map(|v| v as &dyn Encodable),
            header
                .parent_beacon_block_root
                .as_ref()
                .map(|v| v as &dyn Encodable),
            header.requests_hash.as_ref().map(|v| v as &dyn Encodable),
        ];
        for field in tail {
            let Some(field) = field else { break };
            fields.push(one(field));
        }
        let mut payload = Vec::new();
        header.encode_fields(&mut payload);
        assert_eq!(fields.concat(), payload, "el helper no reproduce el layout");
        fields
    }

    /// `payload` envuelto en el prefijo de lista CANÓNICO: lo único no canónico
    /// del resultado es lo que el test puso adentro.
    fn wrap_list(payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        RlpHeader {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut raw);
        raw.extend_from_slice(payload);
        raw
    }

    /// El header con el campo `index` reemplazado por `bytes`, crudos.
    fn with_field(header: &Header, index: usize, bytes: &[u8]) -> Vec<u8> {
        let mut fields = encoded_fields(header);
        match fields.get_mut(index) {
            Some(field) => *field = bytes.to_vec(),
            None => panic!("el header no tiene campo {index}"),
        }
        wrap_list(&fields.concat())
    }

    #[track_caller]
    fn rejects(raw: &[u8], expected: alloy_rlp::Error) {
        assert_eq!(
            Header::decode_exact(raw),
            Err(BlockError::HeaderRlp(expected))
        );
    }

    const EXTRA_DATA: usize = 12;
    const NONCE: usize = 14;
    const BASE_FEE: usize = 15;
    const BLOB_GAS_USED: usize = 17;
    const REQUESTS_HASH: usize = 20;
    const PARENT_HASH: usize = 0;

    /// Un prefijo de lista en forma larga solo vale para un payload de 56
    /// bytes o más, y su largo no lleva ceros a la izquierda.
    #[test]
    fn a_long_form_list_prefix_must_be_canonical() {
        // `0xf8` con un largo menor que 56: la forma corta era obligatoria.
        rejects(
            &[0xf8, 0x02, 0x80, 0x80],
            alloy_rlp::Error::NonCanonicalSize,
        );

        // El header real con su largo en forma larga y un cero de más.
        let raw = prague_genesis().rlp();
        let (Some(&0xf9), Some(length), Some(payload)) = (raw.first(), raw.get(1..3), raw.get(3..))
        else {
            panic!("el header del set no tiene un prefijo de dos bytes de largo");
        };
        let mut padded = vec![0xfa, 0x00];
        padded.extend_from_slice(length);
        padded.extend_from_slice(payload);
        rejects(&padded, alloy_rlp::Error::LeadingZero);
    }

    /// El largo de la lista no puede mentir, ni por defecto ni por exceso.
    #[test]
    fn a_list_length_that_lies_is_rejected() {
        let mut payload = Vec::new();
        prague_genesis().encode_fields(&mut payload);
        for declared in [
            payload.len().saturating_sub(1),
            payload.len().saturating_add(1),
        ] {
            let mut raw = Vec::new();
            RlpHeader {
                list: true,
                payload_length: declared,
            }
            .encode(&mut raw);
            raw.extend_from_slice(&payload);
            rejects(&raw, alloy_rlp::Error::InputTooShort);
        }
    }

    /// Un byte por debajo de `0x80` es su propio encoding: `0x81 0x05` es el
    /// mismo valor que `0x05` en forma no canónica.
    #[test]
    fn a_single_byte_string_in_long_form_is_rejected() {
        let mut header = prague_genesis();
        header.extra_data = Bytes::from(vec![0x05]);
        assert_eq!(
            Header::decode_exact(&with_field(&header, EXTRA_DATA, &[0x05])),
            Ok(header.clone())
        );
        rejects(
            &with_field(&header, EXTRA_DATA, &[0x81, 0x05]),
            alloy_rlp::Error::NonCanonicalSingleByte,
        );
    }

    /// Un hash son 32 bytes exactos: ni 31 (que un decoder laxo rellenaría) ni
    /// 33.
    #[test]
    fn a_hash_of_31_or_33_bytes_is_rejected() {
        let header = prague_genesis();
        let mut short = vec![0x9f];
        short.extend_from_slice(&[0x11; 31]);
        rejects(
            &with_field(&header, PARENT_HASH, &short),
            alloy_rlp::Error::UnexpectedLength,
        );
        let mut long = vec![0xa1];
        long.extend_from_slice(&[0x11; 33]);
        rejects(
            &with_field(&header, PARENT_HASH, &long),
            alloy_rlp::Error::UnexpectedLength,
        );
    }

    /// El `nonce` son 8 bytes exactos.
    #[test]
    fn a_nonce_of_7_or_9_bytes_is_rejected() {
        let header = prague_genesis();
        let mut short = vec![0x87];
        short.extend_from_slice(&[0; 7]);
        rejects(
            &with_field(&header, NONCE, &short),
            alloy_rlp::Error::UnexpectedLength,
        );
        let mut long = vec![0x89];
        long.extend_from_slice(&[0; 9]);
        rejects(
            &with_field(&header, NONCE, &long),
            alloy_rlp::Error::UnexpectedLength,
        );
    }

    /// Los enteros de la cola también son canónicos: un cero a la izquierda en
    /// `baseFeePerGas` o en `blobGasUsed` es el mismo valor con otros bytes, y
    /// otro hash.
    #[test]
    fn a_leading_zero_in_a_tail_integer_is_rejected() {
        let mut header = prague_genesis();
        // 7 → `0x07`; con el cero de más, `0x82 0x00 0x07`.
        rejects(
            &with_field(&header, BASE_FEE, &[0x82, 0x00, 0x07]),
            alloy_rlp::Error::LeadingZero,
        );
        // Un blob: `0x83 0x02 0x00 0x00`; con el cero de más, cuatro bytes.
        header.blob_gas_used = Some(0x0002_0000);
        assert_eq!(
            Header::decode_exact(&with_field(
                &header,
                BLOB_GAS_USED,
                &[0x83, 0x02, 0x00, 0x00]
            )),
            Ok(header.clone())
        );
        rejects(
            &with_field(&header, BLOB_GAS_USED, &[0x84, 0x00, 0x02, 0x00, 0x00]),
            alloy_rlp::Error::LeadingZero,
        );
    }

    /// El último campo declara 32 bytes y trae 31; el prefijo de la lista dice
    /// la verdad sobre lo que hay. El campo no puede completarse con nada.
    #[test]
    fn a_field_truncated_inside_a_list_of_the_right_length_is_rejected() {
        let mut truncated = vec![0xa0];
        truncated.extend_from_slice(&[0x22; 31]);
        rejects(
            &with_field(&prague_genesis(), REQUESTS_HASH, &truncated),
            alloy_rlp::Error::InputTooShort,
        );
    }

    /// Los quince campos de Frontier sin cola decodifican: el decoder no
    /// decide la presencia por fork (eso lo hace `validate_fork_fields`, que
    /// rechaza este header en todo fork en scope).
    #[test]
    fn a_header_with_an_empty_tail_decodes_and_no_fork_in_scope_accepts_it() {
        let mut bare = prague_genesis();
        bare.base_fee_per_gas = None;
        bare.withdrawals_root = None;
        bare.blob_gas_used = None;
        bare.excess_blob_gas = None;
        bare.parent_beacon_block_root = None;
        bare.requests_hash = None;
        let raw = bare.rlp();
        assert_eq!(encoded_fields(&bare).len(), 15);
        assert_eq!(Header::decode_exact(&raw), Ok(bare.clone()));
        assert_eq!(
            crate::validate_fork_fields(&bare, repo_b_common::spec::Spec::Paris),
            Err(BlockError::MissingField {
                field: crate::error::HeaderField::BaseFeePerGas,
                spec: repo_b_common::spec::Spec::Paris,
            })
        );
    }

    /// La dificultad más grande representable va y vuelve.
    #[test]
    fn the_largest_difficulty_round_trips() {
        let mut header = prague_genesis();
        header.difficulty = U256::MAX;
        assert_eq!(Header::decode_exact(&header.rlp()), Ok(header));
    }
}
