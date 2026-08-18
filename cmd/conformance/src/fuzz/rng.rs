//! PRNG del fuzzer: **sembrado explícito y direccionable por `(semilla,
//! índice)`**.
//!
//! El determinismo absoluto aplica al harness igual que al guest: mismo input,
//! mismo resultado, siempre. Acá eso significa dos cosas independientes, y la
//! segunda es la que decidió el diseño:
//!
//! 1. **Nada de entropía del SO adentro del lazo.** La semilla se elige al
//!    arrancar la campaña, se imprime y se guarda con el hallazgo. Sin eso, un
//!    hallazgo no es reproducible y por lo tanto no es un hallazgo.
//! 2. **`(semilla, índice)` reproduce el caso exacto en O(1)**, sin re-correr
//!    los `índice - 1` casos anteriores. Un stream secuencial (un solo RNG que
//!    avanza caso a caso) NO tiene esa propiedad: para reproducir el caso
//!    900 000 hay que generar los 899 999 de antes.
//!
//! SplitMix64 (Steele/Lea/Flood 2014) es exactamente la primitiva de este
//! problema: es una **función** del contador, no un estado que hay que
//! arrastrar. Se implementa acá en 20 líneas en vez de traer un crate: el
//! algoritmo es una constante de la literatura, cabe en un test de vectores, y
//! una dependencia más en el harness es una dependencia más que auditar.

/// Constante de incremento de SplitMix64 (el "golden gamma", 2^64/φ).
const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
const MIX_MULTIPLIER_1: u64 = 0xBF58_476D_1CE4_E5B9;
const MIX_MULTIPLIER_2: u64 = 0x94D0_49BB_1331_11EB;

/// El paso de mezcla de SplitMix64. Todo `wrapping_*` acá es **deliberado**:
/// es aritmética modular de 64 bits, no un overflow que haya que atajar
/// (explícito y justificado, como toda aritmética del repo).
const fn mix(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(MIX_MULTIPLIER_1);
    z ^= z >> 27;
    z = z.wrapping_mul(MIX_MULTIPLIER_2);
    z ^= z >> 31;
    z
}

/// El generador. Barato de crear: un `u64` de estado.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// El stream del caso `index` de la campaña `seed`. **O(1)**: es la
    /// propiedad que hace que un hallazgo se reproduzca solo con dos números,
    /// y que una campaña se pueda repartir por rangos de índice sin
    /// coordinación.
    pub const fn for_case(seed: u64, index: u64) -> Self {
        Self {
            state: mix(seed ^ mix(index.wrapping_mul(GOLDEN_GAMMA))),
        }
    }

    /// Un stream a partir de un estado crudo. Solo los tests de vectores: la
    /// campaña direcciona SIEMPRE por `(semilla, índice)`, y una segunda
    /// puerta de entrada al PRNG sería una segunda forma de sembrarlo.
    #[cfg(test)]
    pub const fn from_state(state: u64) -> Self {
        Self { state }
    }

    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GOLDEN_GAMMA);
        mix(self.state)
    }

    /// Uniforme en `[0, bound)`. `bound == 0` devuelve 0 en vez de dividir por
    /// cero: fail-soft acá es correcto porque el único caller con bound 0 es
    /// "elegir de una lista vacía", y ahí el caller ya no usa el resultado.
    pub const fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        // Módulo simple: el sesgo es de orden 2^-64 · bound y ninguna
        // distribución del generador depende de más precisión que ésa.
        self.next_u64() % bound
    }

    /// Elige un elemento. `None` solo si la lista está vacía.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        let len = u64::try_from(items.len()).unwrap_or(u64::MAX);
        let index = usize::try_from(self.below(len)).unwrap_or(0);
        items.get(index)
    }

    /// Índice elegido con probabilidad proporcional a su peso. Devuelve `None`
    /// si la tabla está vacía o si todos los pesos son cero — un caller que
    /// pase una tabla muerta debe enterarse, no recibir el índice 0.
    pub fn weighted(&mut self, weights: &[u32]) -> Option<usize> {
        let total: u64 = weights.iter().map(|w| u64::from(*w)).sum();
        if total == 0 {
            return None;
        }
        let mut target = self.below(total);
        for (index, weight) in weights.iter().enumerate() {
            let weight = u64::from(*weight);
            if target < weight {
                return Some(index);
            }
            target = target.saturating_sub(weight);
        }
        None
    }

    /// `true` con probabilidad `numerator / denominator`.
    pub const fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.below(denominator) < numerator
    }

    /// Un `usize` en `[low, high]`, inclusivo en los dos extremos.
    pub const fn range(&mut self, low: usize, high: usize) -> usize {
        if high <= low {
            return low;
        }
        let span = (high - low) as u64;
        low.saturating_add(self.below(span.saturating_add(1)) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectores de SplitMix64 con semilla 0, de la referencia del algoritmo.
    /// Pinean que esto ES SplitMix64 y no una variante propia: el día que
    /// alguien "optimice" la mezcla, una campaña vieja deja de reproducirse.
    #[test]
    fn splitmix64_matches_the_reference_vectors() {
        let mut rng = Rng::from_state(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    /// La propiedad que define el determinismo: `(seed, i)` reproduce el caso, y
    /// lo reproduce **sin pasar por los anteriores**.
    #[test]
    fn seed_and_index_address_the_same_stream_in_any_order() {
        let direct: Vec<u64> = (0..8)
            .map(|i| Rng::for_case(0xDEAD_BEEF, i).next_u64())
            .collect();
        let reversed: Vec<u64> = (0..8)
            .rev()
            .map(|i| Rng::for_case(0xDEAD_BEEF, i).next_u64())
            .collect();
        let mut reversed_back = reversed;
        reversed_back.reverse();
        assert_eq!(direct, reversed_back);
    }

    /// Dos semillas distintas no comparten stream; dos índices distintos
    /// tampoco. Sin esto, "una campaña de 10^6 casos" podría ser el mismo caso
    /// 10^6 veces y el gate no lo notaría.
    #[test]
    fn distinct_seeds_and_indices_give_distinct_streams() {
        let a = Rng::for_case(1, 0).next_u64();
        let b = Rng::for_case(2, 0).next_u64();
        let c = Rng::for_case(1, 1).next_u64();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn weighted_respects_a_zeroed_slot_and_reports_a_dead_table() {
        let weights = [0u32, 5, 0];
        let mut rng = Rng::for_case(7, 7);
        for _ in 0..200 {
            assert_eq!(rng.weighted(&weights), Some(1));
        }
        assert_eq!(rng.weighted(&[0, 0]), None);
        assert_eq!(rng.weighted(&[]), None);
    }

    #[test]
    fn below_and_range_stay_inside_their_bounds() {
        let mut rng = Rng::for_case(3, 9);
        for _ in 0..500 {
            assert!(rng.below(10) < 10);
            let value = rng.range(4, 9);
            assert!((4..=9).contains(&value));
            assert_eq!(rng.range(5, 5), 5);
            assert_eq!(rng.range(9, 4), 9);
        }
        assert_eq!(rng.below(0), 0);
    }
}
