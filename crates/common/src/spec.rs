//! Reglas de fork en UN solo lugar.
//!
//! Vive en `common` —y no en `evm`— porque **el intérprete también las
//! necesita** y solo depende de este crate: el gating de opcodes (EIP-3855,
//! EIP-1153, EIP-5656, EIP-4844, EIP-7516) y el costo por palabra de initcode
//! (EIP-3860) son decisiones del intérprete, no del executor.
//!
//! Una sola definición para los tres crates: dos enums de fork en paralelo es
//! exactamente la clase de duplicación que produce divergencias silenciosas.

/// Los forks en scope, en orden de activación. El piso es **Paris** (el motor
/// es post-Merge-first); `is_enabled` compara por ese orden.
///
/// **Sin `Default` a propósito.** Un fork plausible por omisión haría que un
/// motor mal construido conteste la regla de consenso equivocada en silencio,
/// que es justo lo que este repo no acepta: el fork se pasa explícito o no se
/// compila.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Spec {
    Paris,
    Shanghai,
    Cancun,
    Prague,
}

impl Spec {
    /// ¿Este fork incluye a `target`? (`>=` sobre el orden de activación.)
    pub fn is_enabled(&self, target: Spec) -> bool {
        *self >= target
    }
}
