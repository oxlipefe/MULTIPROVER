//! El campo `network` de un `blockchain_test`, resuelto a la regla timestamp →
//! fork que rige cada bloque del caso.
//!
//! Una red pura (`"Osaka"`) es un fork para todos los bloques. Una red de
//! transición (`"PragueToOsakaAtTime15k"`) arranca en el primer fork y cambia
//! al segundo en el primer bloque con `timestamp >= 15 000`: el fork se decide
//! **por bloque**, con la misma regla que el chainspec de mainnet
//! ([`ForkSchedule::spec_at`]), no con una copia escrita para el harness.

use repo_b_common::chainspec::{ForkActivation, ForkSchedule};
use repo_b_common::spec::Spec;

use crate::fixture::spec_for_fork;

/// El timestamp de activación de toda red `…AtTime15k` de EEST.
pub const TRANSITION_TIMESTAMP: u64 = 15_000;

/// El sufijo que nombra ese timestamp en el campo `network`.
const TRANSITION_SUFFIX: &str = "AtTime15k";

/// Qué fork rige cada bloque de un caso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkForks {
    base: Spec,
    activation: Option<ForkActivation>,
}

impl NetworkForks {
    /// El fork de un bloque con este `timestamp`. `None` si la red no describe
    /// una cadena (transición hacia atrás o hacia el mismo fork).
    #[must_use]
    pub fn spec_at(&self, timestamp: u64) -> Option<Spec> {
        ForkSchedule::new(self.base, self.activation.as_slice()).spec_at(timestamp)
    }

    /// Todos los forks que la red alcanza: el base y el de cada activación, en
    /// orden. Recorre la tabla entera, así que no supone cuántas activaciones
    /// tiene.
    pub fn reached(&self) -> impl Iterator<Item = Spec> + '_ {
        core::iter::once(self.base).chain(self.activation.as_slice().iter().map(|a| a.spec))
    }

    /// El fork del genesis: el que rige antes de toda activación.
    #[cfg(test)]
    pub fn base(&self) -> Spec {
        self.base
    }
}

/// Resuelve el campo `network`. **Fail-closed:** un nombre que no es un fork
/// conocido ni una transición `XToYAtTime15k` entre dos forks conocidos, en
/// orden, no resuelve.
#[must_use]
pub fn resolve(network: &str) -> Option<NetworkForks> {
    if let Some(base) = spec_for_fork(network) {
        return Some(NetworkForks {
            base,
            activation: None,
        });
    }
    let pair = network.strip_suffix(TRANSITION_SUFFIX)?;
    let (from, to) = pair.split_once("To")?;
    let base = spec_for_fork(from)?;
    let next = spec_for_fork(to)?;
    let forks = NetworkForks {
        base,
        activation: Some(ForkActivation {
            timestamp: TRANSITION_TIMESTAMP,
            spec: next,
        }),
    };
    // Una transición que no avanza no es una red: se rechaza acá y no en el
    // primer bloque que cruce el borde.
    forks.spec_at(0)?;
    Some(forks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pure_network_is_one_fork_for_every_block() {
        let Some(forks) = resolve("Osaka") else {
            panic!("Osaka resuelve");
        };
        assert_eq!(forks.spec_at(0), Some(Spec::Osaka));
        assert_eq!(forks.spec_at(u64::MAX), Some(Spec::Osaka));
        assert_eq!(resolve("Merge").map(|f| f.base()), Some(Spec::Paris));
    }

    #[test]
    fn a_transition_switches_at_15k_inclusive() {
        let Some(forks) = resolve("PragueToOsakaAtTime15k") else {
            panic!("transición conocida");
        };
        assert_eq!(forks.base(), Spec::Prague);
        assert_eq!(forks.spec_at(TRANSITION_TIMESTAMP - 1), Some(Spec::Prague));
        assert_eq!(forks.spec_at(TRANSITION_TIMESTAMP), Some(Spec::Osaka));
        assert_eq!(forks.spec_at(TRANSITION_TIMESTAMP + 1), Some(Spec::Osaka));
    }

    #[test]
    fn reached_lists_every_fork_of_the_network() {
        let reached = |n: &str| resolve(n).map(|f| f.reached().collect::<Vec<_>>());
        assert_eq!(reached("Osaka"), Some(vec![Spec::Osaka]));
        assert_eq!(
            reached("OsakaToBPO1AtTime15k"),
            Some(vec![Spec::Osaka, Spec::Bpo1])
        );
        assert_eq!(
            reached("BPO1ToBPO2AtTime15k"),
            Some(vec![Spec::Bpo1, Spec::Bpo2])
        );
    }

    #[test]
    fn unknown_or_backwards_networks_do_not_resolve() {
        for network in [
            "",
            "Frontier",
            "Amsterdam",
            "PragueToOsaka",
            "PragueToOsakaAtTime16k",
            "OsakaToPragueAtTime15k",
            "OsakaToOsakaAtTime15k",
            "PragueToAmsterdamAtTime15k",
            "BerlinToLondonAtTime15k",
            "ToOsakaAtTime15k",
        ] {
            assert_eq!(resolve(network), None, "`{network}` no debería resolver");
        }
    }
}
