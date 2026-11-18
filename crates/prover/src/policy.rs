//! **La política de verificación de una prueba de bloque**: qué tiene que
//! decir el journal para que el consumidor lo acepte como la prueba del bloque
//! que espera.
//!
//! Es una sola función y la usan todos los consumidores del árbol: el `prove`
//! y el `verify` del bloque real, la corrida que solo ejecuta y el cruce entre
//! backends. Dos políticas escritas a mano en dos lugares divergirían en el
//! campo que uno de los dos se olvidó de mirar.
//!
//! # Por qué no alcanza con decodificar
//!
//! `Journal::decode` dice si los bytes son un journal; no dice si es el journal
//! **de este bloque**. Un journal de `DecodeOnly`, uno de `StateTest`, uno con
//! `fork` en cero o uno con `block_hash` en cero decodifican igual. Lo que lo
//! vuelve la prueba de un bloque es que el consumidor lo contraste contra lo
//! que él sabe y la prueba no puede saber:
//!
//! - **el `fork`**, porque Prague y Osaka tienen el mismo header y el header no
//!   lo compromete: la misma ejecución puede publicarse bajo los dos. El
//!   consumidor sabe qué fork le corresponde al `timestamp` del bloque;
//! - **el `chain_id`**, porque el header tampoco lo compromete;
//! - **el `block_hash`** (y el `parent_hash`, si lo conoce), porque es lo que
//!   el consumidor pidió probar.
//!
//! `Mode::StateTest` se rechaza por el modo, antes de mirar ningún campo: no
//! tiene ancla y no nombra ningún bloque.

use repo_b_block::Header;
use repo_b_common::chainspec::{MAINNET_CHAIN_ID, mainnet_spec};
use repo_b_common::primitives::B256;
use repo_b_common::spec::Spec;

use crate::journal::{JOURNAL_BYTES, JOURNAL_VERSION, MAX_PUBLIC_OUTPUT_BYTES};
use crate::{Journal, Mode};

/// Lo que el consumidor sabe del bloque, **de su propio chainspec y de su
/// cadena**, nunca de la prueba.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedBlock {
    pub chain_id: u64,
    /// El fork que el chainspec del consumidor asigna al bloque.
    pub fork: Spec,
    pub block_hash: B256,
    /// El padre, si el consumidor lo conoce. Sin él, la prueba igual tiene que
    /// nombrar uno distinto de cero.
    pub parent_hash: Option<B256>,
}

impl ExpectedBlock {
    /// Lo esperado para un header de **mainnet** que el consumidor tiene de su
    /// propia cadena: el fork sale del chainspec de mainnet por número y
    /// timestamp, el hash se computa (`keccak(rlp(header))`) y el padre es el
    /// que el header nombra.
    ///
    /// `None` para un bloque anterior al Merge (el motor no lo ejecuta) y para
    /// uno posterior al horizonte revisado de la tabla de mainnet (la tabla no
    /// sabe qué fork lo rige).
    #[must_use]
    pub fn mainnet(header: &Header) -> Option<Self> {
        let fork = mainnet_spec(header.number, header.timestamp)?;
        Some(Self {
            chain_id: MAINNET_CHAIN_ID,
            fork,
            block_hash: header.hash(),
            parent_hash: Some(header.parent_hash),
        })
    }
}

/// Por qué un journal no es la prueba del bloque esperado. Una variante por
/// condición, para que un test pueda fijar cuál cayó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Los bytes no tienen el largo de un journal (ni exacto ni rellenado).
    Length(usize),
    /// Otra versión del formato: los mismos bytes afirman otra cosa.
    Version(u8),
    /// Tiene el largo y la versión, y el resto no decodifica (modo o fork
    /// desconocidos, relleno que no es relleno).
    Malformed,
    /// Un modo que no es `Full`: no ejecutó y validó el bloque entero.
    Mode(Mode),
    ChainId {
        expected: u64,
        published: u64,
    },
    Fork {
        expected: Spec,
        published: Option<Spec>,
    },
    /// `block_hash` en cero: la prueba no nombra ningún bloque.
    ZeroBlockHash,
    BlockHash {
        expected: B256,
        published: B256,
    },
    /// `parent_hash` en cero: la prueba no ancla el bloque en ninguna cadena.
    ZeroParentHash,
    ParentHash {
        expected: B256,
        published: B256,
    },
    /// Un state root en cero no es el root de ningún trie (el del trie vacío
    /// es `EMPTY_ROOT_HASH`): el modo no lo computó.
    ZeroStateRoot(&'static str),
    /// `output_digest` en cero: el digest de lo ejecutado nunca es cero (es un
    /// keccak), así que el modo no ejecutó.
    ZeroOutputDigest,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length(n) => write!(f, "{n} bytes no son un journal"),
            Self::Version(v) => write!(
                f,
                "journal de la versión {v}, se acepta la {JOURNAL_VERSION}"
            ),
            Self::Malformed => write!(f, "el journal no decodifica"),
            Self::Mode(m) => write!(f, "el journal es del modo {m:?}, no de Full"),
            Self::ChainId {
                expected,
                published,
            } => {
                write!(f, "chain_id {published}, se esperaba {expected}")
            }
            Self::Fork {
                expected,
                published,
            } => {
                write!(f, "fork {published:?}, se esperaba {expected:?}")
            }
            Self::ZeroBlockHash => write!(f, "block_hash en cero"),
            Self::BlockHash {
                expected,
                published,
            } => {
                write!(f, "block_hash {published}, se esperaba {expected}")
            }
            Self::ZeroParentHash => write!(f, "parent_hash en cero"),
            Self::ParentHash {
                expected,
                published,
            } => {
                write!(f, "parent_hash {published}, se esperaba {expected}")
            }
            Self::ZeroStateRoot(campo) => write!(f, "{campo} en cero"),
            Self::ZeroOutputDigest => write!(f, "output_digest en cero"),
        }
    }
}

impl core::error::Error for Refusal {}

/// **Acepta los public values como la prueba del bloque esperado, o dice por
/// qué no.** Ver el doc del módulo.
///
/// Recibe los bytes y no un `Journal`: la versión no sobrevive a la
/// decodificación (un `Journal` no la lleva), así que mirarla después sería
/// confiar en que alguien la miró antes.
///
/// # Errors
/// La primera condición que falla, en este orden: largo, versión, forma, modo,
/// `chain_id`, `fork`, `block_hash`, `parent_hash`, roots, `output_digest`.
pub fn require_full_block(
    public_values: &[u8],
    expected: &ExpectedBlock,
) -> Result<Journal, Refusal> {
    let len = public_values.len();
    if len != JOURNAL_BYTES && len != MAX_PUBLIC_OUTPUT_BYTES {
        return Err(Refusal::Length(len));
    }
    let version = public_values.first().copied().ok_or(Refusal::Length(len))?;
    if version != JOURNAL_VERSION {
        return Err(Refusal::Version(version));
    }
    let journal = Journal::decode(public_values).ok_or(Refusal::Malformed)?;
    if journal.mode != Mode::Full {
        return Err(Refusal::Mode(journal.mode));
    }
    if journal.chain_id != expected.chain_id {
        return Err(Refusal::ChainId {
            expected: expected.chain_id,
            published: journal.chain_id,
        });
    }
    if journal.fork != Some(expected.fork) {
        return Err(Refusal::Fork {
            expected: expected.fork,
            published: journal.fork,
        });
    }
    if journal.block_hash == B256::ZERO {
        return Err(Refusal::ZeroBlockHash);
    }
    if journal.block_hash != expected.block_hash {
        return Err(Refusal::BlockHash {
            expected: expected.block_hash,
            published: journal.block_hash,
        });
    }
    if journal.parent_hash == B256::ZERO {
        return Err(Refusal::ZeroParentHash);
    }
    if let Some(parent) = expected.parent_hash
        && journal.parent_hash != parent
    {
        return Err(Refusal::ParentHash {
            expected: parent,
            published: journal.parent_hash,
        });
    }
    if journal.pre_state_root == B256::ZERO {
        return Err(Refusal::ZeroStateRoot("pre_state_root"));
    }
    if journal.post_state_root == B256::ZERO {
        return Err(Refusal::ZeroStateRoot("post_state_root"));
    }
    if journal.output_digest == B256::ZERO {
        return Err(Refusal::ZeroOutputDigest);
    }
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::{ExpectedBlock, Refusal, require_full_block};
    use crate::journal::{JOURNAL_BYTES, JOURNAL_VERSION, MAX_PUBLIC_OUTPUT_BYTES};
    use crate::{Journal, Mode};
    use repo_b_common::primitives::B256;
    use repo_b_common::spec::Spec;

    const BLOQUE: B256 = B256::repeat_byte(0xb1);
    const PADRE: B256 = B256::repeat_byte(0xa0);

    fn journal() -> Journal {
        Journal {
            mode: Mode::Full,
            chain_id: 1,
            fork: Some(Spec::Osaka),
            block_hash: BLOQUE,
            parent_hash: PADRE,
            pre_state_root: B256::repeat_byte(0x11),
            post_state_root: B256::repeat_byte(0x22),
            output_digest: B256::repeat_byte(0x33),
        }
    }

    fn esperado() -> ExpectedBlock {
        ExpectedBlock {
            chain_id: 1,
            fork: Spec::Osaka,
            block_hash: BLOQUE,
            parent_hash: Some(PADRE),
        }
    }

    fn con(cambio: impl Fn(&mut Journal)) -> Result<Journal, Refusal> {
        let mut j = journal();
        cambio(&mut j);
        require_full_block(&j.encode(), &esperado())
    }

    /// La recíproca: sin ella, todos los rechazos de abajo podrían ser un
    /// verificador que rechaza todo.
    #[test]
    fn the_expected_block_is_accepted_exact_and_padded() {
        assert_eq!(
            require_full_block(&journal().encode(), &esperado()),
            Ok(journal())
        );
        let mut padded = [0u8; MAX_PUBLIC_OUTPUT_BYTES];
        padded[..JOURNAL_BYTES].copy_from_slice(&journal().encode());
        assert_eq!(require_full_block(&padded, &esperado()), Ok(journal()));
        let sin_padre = ExpectedBlock {
            parent_hash: None,
            ..esperado()
        };
        assert_eq!(
            require_full_block(&journal().encode(), &sin_padre),
            Ok(journal())
        );
    }

    #[test]
    fn a_length_that_is_not_a_journal_is_refused() {
        assert_eq!(
            require_full_block(&[0u8; 97], &esperado()),
            Err(Refusal::Length(97))
        );
        assert_eq!(
            require_full_block(&[], &esperado()),
            Err(Refusal::Length(0))
        );
    }

    #[test]
    fn another_version_is_refused_by_name() {
        let mut bytes = journal().encode();
        bytes[0] = JOURNAL_VERSION.wrapping_add(1);
        assert_eq!(
            require_full_block(&bytes, &esperado()),
            Err(Refusal::Version(JOURNAL_VERSION.wrapping_add(1)))
        );
    }

    #[test]
    fn an_undecodable_journal_is_refused() {
        let mut bytes = journal().encode();
        bytes[1] = 0xee;
        assert_eq!(
            require_full_block(&bytes, &esperado()),
            Err(Refusal::Malformed)
        );
    }

    /// Todo modo que no es `Full`, incluido `StateTest`, que no tiene ancla.
    #[test]
    fn every_mode_but_full_is_refused() {
        for mode in [
            Mode::NoRoot,
            Mode::NoTxs,
            Mode::StateOnly,
            Mode::Recover,
            Mode::DecodeOnly,
            Mode::Nop,
            Mode::Kat,
            Mode::StateTest,
        ] {
            assert_eq!(con(|j| j.mode = mode), Err(Refusal::Mode(mode)), "{mode:?}");
        }
    }

    #[test]
    fn another_chain_id_is_refused() {
        assert_eq!(
            con(|j| j.chain_id = 7),
            Err(Refusal::ChainId {
                expected: 1,
                published: 7
            })
        );
    }

    /// **La ambigüedad que el header no cierra**: el mismo bloque publicado
    /// bajo Prague cuando el chainspec dice Osaka. Y el fork en cero.
    #[test]
    fn another_fork_with_the_same_header_is_refused() {
        assert_eq!(
            con(|j| j.fork = Some(Spec::Prague)),
            Err(Refusal::Fork {
                expected: Spec::Osaka,
                published: Some(Spec::Prague)
            })
        );
        assert_eq!(
            con(|j| j.fork = None),
            Err(Refusal::Fork {
                expected: Spec::Osaka,
                published: None
            })
        );
    }

    /// El cero se rechaza por ser cero, aunque el consumidor esperara cero: un
    /// `ExpectedBlock` mal armado no puede convertir un journal ablacionado en
    /// una prueba.
    #[test]
    fn a_zero_block_hash_is_refused_even_if_expected() {
        let cero = ExpectedBlock {
            block_hash: B256::ZERO,
            ..esperado()
        };
        let mut j = journal();
        j.block_hash = B256::ZERO;
        assert_eq!(
            require_full_block(&j.encode(), &cero),
            Err(Refusal::ZeroBlockHash)
        );
    }

    #[test]
    fn another_block_hash_is_refused() {
        let otro = B256::repeat_byte(0xb2);
        assert_eq!(
            con(|j| j.block_hash = otro),
            Err(Refusal::BlockHash {
                expected: BLOQUE,
                published: otro
            })
        );
    }

    #[test]
    fn a_zero_parent_hash_is_refused_even_without_an_expected_parent() {
        let sin_padre = ExpectedBlock {
            parent_hash: None,
            ..esperado()
        };
        let mut j = journal();
        j.parent_hash = B256::ZERO;
        assert_eq!(
            require_full_block(&j.encode(), &sin_padre),
            Err(Refusal::ZeroParentHash)
        );
    }

    #[test]
    fn another_parent_hash_is_refused() {
        let otro = B256::repeat_byte(0xa1);
        assert_eq!(
            con(|j| j.parent_hash = otro),
            Err(Refusal::ParentHash {
                expected: PADRE,
                published: otro
            })
        );
    }

    #[test]
    fn a_zero_output_digest_is_refused() {
        assert_eq!(
            con(|j| j.output_digest = B256::ZERO),
            Err(Refusal::ZeroOutputDigest)
        );
    }

    #[test]
    fn a_zero_state_root_is_refused() {
        assert_eq!(
            con(|j| j.pre_state_root = B256::ZERO),
            Err(Refusal::ZeroStateRoot("pre_state_root"))
        );
        assert_eq!(
            con(|j| j.post_state_root = B256::ZERO),
            Err(Refusal::ZeroStateRoot("post_state_root"))
        );
    }

    fn mainnet_header(number: u64, timestamp: u64) -> repo_b_block::Header {
        use repo_b_common::primitives::{Address, Bytes, U256};
        repo_b_block::Header {
            parent_hash: PADRE,
            ommers_hash: B256::repeat_byte(0x1d),
            beneficiary: Address::ZERO,
            state_root: B256::repeat_byte(0x11),
            transactions_root: B256::repeat_byte(0x12),
            receipts_root: B256::repeat_byte(0x13),
            logs_bloom: alloy_primitives::Bloom::ZERO,
            difficulty: U256::ZERO,
            number,
            gas_limit: 60_000_000,
            gas_used: 0,
            timestamp,
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: alloy_primitives::B64::ZERO,
            base_fee_per_gas: Some(7),
            withdrawals_root: Some(B256::repeat_byte(0x14)),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::repeat_byte(0x15)),
            requests_hash: Some(B256::repeat_byte(0x16)),
        }
    }

    #[test]
    fn a_mainnet_header_expects_its_fork_its_hash_and_its_parent() {
        use repo_b_common::chainspec::{MAINNET_BPO2_TIMESTAMP, MAINNET_PARIS_BLOCK};
        let header = mainnet_header(24_179_383, MAINNET_BPO2_TIMESTAMP);
        let Some(expected) = ExpectedBlock::mainnet(&header) else {
            panic!("un bloque post-Merge tiene fork");
        };
        assert_eq!(expected.chain_id, 1);
        assert_eq!(expected.fork, Spec::Bpo2);
        assert_eq!(expected.block_hash, header.hash());
        assert_eq!(expected.parent_hash, Some(PADRE));

        let before = mainnet_header(24_179_382, MAINNET_BPO2_TIMESTAMP - 1);
        assert_eq!(
            ExpectedBlock::mainnet(&before).map(|e| e.fork),
            Some(Spec::Bpo1)
        );

        let pre_merge = mainnet_header(MAINNET_PARIS_BLOCK - 1, MAINNET_BPO2_TIMESTAMP);
        assert_eq!(ExpectedBlock::mainnet(&pre_merge), None);

        let past_horizon = mainnet_header(
            30_000_000,
            repo_b_common::chainspec::MAINNET_SCHEDULE_REVIEWED_UNTIL + 1,
        );
        assert_eq!(ExpectedBlock::mainnet(&past_horizon), None);
    }

    /// Una prueba publicada bajo Osaka no es la de un bloque BPO2, aunque
    /// todo lo demás coincida: BPO2 tiene otros números de blob.
    #[test]
    fn an_osaka_journal_is_refused_for_a_bpo2_mainnet_block() {
        use repo_b_common::chainspec::MAINNET_BPO2_TIMESTAMP;
        let header = mainnet_header(24_179_383, MAINNET_BPO2_TIMESTAMP);
        let Some(expected) = ExpectedBlock::mainnet(&header) else {
            panic!("un bloque post-Merge tiene fork");
        };
        let mut j = journal();
        j.block_hash = expected.block_hash;
        assert_eq!(
            require_full_block(&j.encode(), &expected),
            Err(Refusal::Fork {
                expected: Spec::Bpo2,
                published: Some(Spec::Osaka)
            })
        );
        j.fork = Some(Spec::Bpo2);
        assert!(require_full_block(&j.encode(), &expected).is_ok());
    }
}
