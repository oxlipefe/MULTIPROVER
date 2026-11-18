//! Qué fork rige un bloque: la regla timestamp → fork, y el chainspec de mainnet.
//!
//! Desde Shanghai los forks se activan por **timestamp**, no por número de
//! bloque: el primer bloque con `timestamp >= T` corre bajo el fork nuevo. Esa
//! regla vive en UNA función ([`ForkSchedule::spec_at`]) parametrizada por la
//! tabla de activaciones, y la usan las dos puntas que la necesitan: el
//! chainspec de mainnet (lo que un consumidor sabe del bloque que pide probar)
//! y el harness de `blockchain_test` (las redes de transición de EEST, que
//! cambian de fork dentro de un mismo caso). Dos implementaciones de la misma
//! regla divergirían justo en el borde, que es donde se miden.
//!
//! El guest **no** usa esto: el fork le llega en el input y se publica en el
//! journal, y es el consumidor quien lo contrasta contra su chainspec.

use crate::spec::Spec;

/// Un fork que se activa en `timestamp` (inclusivo).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkActivation {
    pub timestamp: u64,
    pub spec: Spec,
}

/// Un fork base más las activaciones por timestamp que lo suceden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkSchedule<'a> {
    /// El fork que rige antes de la primera activación.
    pub base: Spec,
    /// En orden estricto de timestamp **y** de fork.
    pub activations: &'a [ForkActivation],
}

impl<'a> ForkSchedule<'a> {
    #[must_use]
    pub const fn new(base: Spec, activations: &'a [ForkActivation]) -> Self {
        Self { base, activations }
    }

    /// El fork que rige un bloque con este `timestamp`.
    ///
    /// **Fail-closed sobre la tabla:** `None` si las activaciones no crecen
    /// estrictamente en timestamp y en fork, o si alguna no es posterior a
    /// `base`. Una tabla así no describe ninguna cadena, y resolverla igual
    /// sería elegir en silencio cuál de sus filas creer.
    #[must_use]
    pub fn spec_at(&self, timestamp: u64) -> Option<Spec> {
        let mut current = self.base;
        let mut previous_timestamp: Option<u64> = None;
        for activation in self.activations {
            let grows_in_time = previous_timestamp.is_none_or(|t| activation.timestamp > t);
            if !grows_in_time || activation.spec <= current {
                return None;
            }
            previous_timestamp = Some(activation.timestamp);
            current = activation.spec;
        }
        // La tabla es válida: ahora sí, la última activación alcanzada.
        let mut spec = self.base;
        for activation in self.activations {
            if timestamp < activation.timestamp {
                break;
            }
            spec = activation.spec;
        }
        Some(spec)
    }
}

/// Ethereum mainnet.
pub const MAINNET_CHAIN_ID: u64 = 1;

/// El primer bloque post-Merge de mainnet (Paris). La activación fue por
/// dificultad total (TTD 58 750 000 000 000 000 000 000), no por timestamp;
/// en la cadena canónica eso fija este número, y es lo único que el chainspec
/// necesita para decir "antes de acá el motor no corre".
pub const MAINNET_PARIS_BLOCK: u64 = 15_537_394;

pub const MAINNET_SHANGHAI_TIMESTAMP: u64 = 1_681_338_455;
pub const MAINNET_CANCUN_TIMESTAMP: u64 = 1_710_338_135;
pub const MAINNET_PRAGUE_TIMESTAMP: u64 = 1_746_612_311;
pub const MAINNET_OSAKA_TIMESTAMP: u64 = 1_764_798_551;
pub const MAINNET_BPO1_TIMESTAMP: u64 = 1_765_290_071;
pub const MAINNET_BPO2_TIMESTAMP: u64 = 1_767_747_671;

const MAINNET_ACTIVATIONS: [ForkActivation; 6] = [
    ForkActivation {
        timestamp: MAINNET_SHANGHAI_TIMESTAMP,
        spec: Spec::Shanghai,
    },
    ForkActivation {
        timestamp: MAINNET_CANCUN_TIMESTAMP,
        spec: Spec::Cancun,
    },
    ForkActivation {
        timestamp: MAINNET_PRAGUE_TIMESTAMP,
        spec: Spec::Prague,
    },
    ForkActivation {
        timestamp: MAINNET_OSAKA_TIMESTAMP,
        spec: Spec::Osaka,
    },
    ForkActivation {
        timestamp: MAINNET_BPO1_TIMESTAMP,
        spec: Spec::Bpo1,
    },
    ForkActivation {
        timestamp: MAINNET_BPO2_TIMESTAMP,
        spec: Spec::Bpo2,
    },
];

/// Los forks post-Merge de mainnet, por timestamp.
pub const MAINNET: ForkSchedule<'static> = ForkSchedule::new(Spec::Paris, &MAINNET_ACTIVATIONS);

/// El fork de un bloque de mainnet.
///
/// **Fail-closed hacia atrás:** un bloque anterior al Merge no tiene `Spec`
/// (el motor es post-Merge) y devuelve `None`.
///
/// **Lo que esta tabla NO puede saber:** un fork de mainnet posterior a BPO2.
/// Un bloque con un timestamp posterior a una activación que la tabla no
/// tiene se resolvería a BPO2. Ningún chainspec se protege de eso solo; lo
/// cierra actualizar la tabla antes de la activación, como en cualquier
/// cliente.
#[must_use]
pub fn mainnet_spec(number: u64, timestamp: u64) -> Option<Spec> {
    if number < MAINNET_PARIS_BLOCK {
        return None;
    }
    MAINNET.spec_at(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cada activación de mainnet, en su borde exacto y un segundo antes.
    #[test]
    fn mainnet_switches_at_every_activation_inclusive() {
        let block = MAINNET_PARIS_BLOCK;
        let cases = [
            (MAINNET_SHANGHAI_TIMESTAMP, Spec::Paris, Spec::Shanghai),
            (MAINNET_CANCUN_TIMESTAMP, Spec::Shanghai, Spec::Cancun),
            (MAINNET_PRAGUE_TIMESTAMP, Spec::Cancun, Spec::Prague),
            (MAINNET_OSAKA_TIMESTAMP, Spec::Prague, Spec::Osaka),
            (MAINNET_BPO1_TIMESTAMP, Spec::Osaka, Spec::Bpo1),
            (MAINNET_BPO2_TIMESTAMP, Spec::Bpo1, Spec::Bpo2),
        ];
        for (at, before, after) in cases {
            assert_eq!(mainnet_spec(block, at - 1), Some(before), "{at} - 1");
            assert_eq!(mainnet_spec(block, at), Some(after), "{at}");
            assert_eq!(mainnet_spec(block, at + 1), Some(after), "{at} + 1");
        }
    }

    /// Los timestamps de activación, tal como los publican el chainspec de
    /// mainnet de go-ethereum y la meta-EIP de Fusaka (EIP-7607). Un número
    /// corrido en uno pasa los bordes de arriba —que se escriben con la misma
    /// constante—; este no.
    #[test]
    fn mainnet_activation_timestamps_are_the_published_ones() {
        assert_eq!(MAINNET_SHANGHAI_TIMESTAMP, 1_681_338_455);
        assert_eq!(MAINNET_CANCUN_TIMESTAMP, 1_710_338_135);
        assert_eq!(MAINNET_PRAGUE_TIMESTAMP, 1_746_612_311);
        assert_eq!(MAINNET_OSAKA_TIMESTAMP, 1_764_798_551);
        assert_eq!(MAINNET_BPO1_TIMESTAMP, 1_765_290_071);
        assert_eq!(MAINNET_BPO2_TIMESTAMP, 1_767_747_671);
        assert_eq!(MAINNET_PARIS_BLOCK, 15_537_394);
        assert_eq!(MAINNET_CHAIN_ID, 1);
    }

    #[test]
    fn a_pre_merge_mainnet_block_has_no_spec() {
        assert_eq!(
            mainnet_spec(MAINNET_PARIS_BLOCK - 1, MAINNET_BPO2_TIMESTAMP),
            None
        );
        assert_eq!(mainnet_spec(0, 0), None);
        assert_eq!(mainnet_spec(MAINNET_PARIS_BLOCK, 0), Some(Spec::Paris));
    }

    /// La tabla de mainnet es válida para la misma regla que la usa: si una
    /// fila quedara fuera de orden, `spec_at` no resolvería nada.
    #[test]
    fn the_mainnet_table_is_well_formed() {
        assert!(MAINNET.spec_at(0).is_some());
        assert_eq!(MAINNET.spec_at(u64::MAX), Some(Spec::Bpo2));
    }

    const T: u64 = 15_000;
    const ONE: [ForkActivation; 1] = [ForkActivation {
        timestamp: T,
        spec: Spec::Osaka,
    }];

    #[test]
    fn the_activation_timestamp_is_inclusive() {
        let schedule = ForkSchedule::new(Spec::Prague, &ONE);
        assert_eq!(schedule.spec_at(T - 1), Some(Spec::Prague));
        assert_eq!(schedule.spec_at(T), Some(Spec::Osaka));
        assert_eq!(schedule.spec_at(T + 1), Some(Spec::Osaka));
        assert_eq!(schedule.spec_at(0), Some(Spec::Prague));
        assert_eq!(schedule.spec_at(u64::MAX), Some(Spec::Osaka));
    }

    #[test]
    fn an_empty_schedule_is_its_base_fork() {
        let schedule = ForkSchedule::new(Spec::Cancun, &[]);
        assert_eq!(schedule.spec_at(0), Some(Spec::Cancun));
        assert_eq!(schedule.spec_at(u64::MAX), Some(Spec::Cancun));
    }

    #[test]
    fn later_activations_win() {
        let table = [
            ForkActivation {
                timestamp: 10,
                spec: Spec::Cancun,
            },
            ForkActivation {
                timestamp: 20,
                spec: Spec::Prague,
            },
        ];
        let schedule = ForkSchedule::new(Spec::Shanghai, &table);
        assert_eq!(schedule.spec_at(9), Some(Spec::Shanghai));
        assert_eq!(schedule.spec_at(10), Some(Spec::Cancun));
        assert_eq!(schedule.spec_at(19), Some(Spec::Cancun));
        assert_eq!(schedule.spec_at(20), Some(Spec::Prague));
    }

    #[test]
    fn a_malformed_table_resolves_nothing() {
        let backwards_in_time = [
            ForkActivation {
                timestamp: 20,
                spec: Spec::Cancun,
            },
            ForkActivation {
                timestamp: 10,
                spec: Spec::Prague,
            },
        ];
        let backwards_in_fork = [
            ForkActivation {
                timestamp: 10,
                spec: Spec::Prague,
            },
            ForkActivation {
                timestamp: 20,
                spec: Spec::Cancun,
            },
        ];
        let same_time = [
            ForkActivation {
                timestamp: 10,
                spec: Spec::Cancun,
            },
            ForkActivation {
                timestamp: 10,
                spec: Spec::Prague,
            },
        ];
        let not_after_base = [ForkActivation {
            timestamp: 10,
            spec: Spec::Prague,
        }];
        for (base, table) in [
            (Spec::Shanghai, &backwards_in_time[..]),
            (Spec::Shanghai, &backwards_in_fork[..]),
            (Spec::Shanghai, &same_time[..]),
            (Spec::Prague, &not_after_base[..]),
        ] {
            let schedule = ForkSchedule::new(base, table);
            for ts in [0, 9, 10, 15, 20, u64::MAX] {
                assert_eq!(schedule.spec_at(ts), None, "{base:?} {table:?} @ {ts}");
            }
        }
    }
}
