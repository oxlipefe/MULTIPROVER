//! **Fuzzing diferencial estructurado**: el generador de casos del red-team.
//!
//! El fuzzer no tiene oráculo propio: hereda el que ya existe
//! (`diff::run_case`, un solo camino de comparación, con logs adentro del
//! `Summary` y su inventario de puntos ciegos). Lo que agrega este módulo es
//! **entradas**: casos estructurados, minimizados al reproductor mínimo y
//! serializados al corpus.
//!
//! ## Dónde vive y por qué
//!
//! En `cmd/`, nunca en `crates/`: es harness. El motor compila a
//! `riscv64gc-unknown-none-elf` y no puede arrastrar `std` ni una dependencia
//! de generación.
//!
//! ## El reparto entre feature y no-feature
//!
//! Solo `campaign` y el tally de `coverage` necesitan a revm. Todo lo demás
//! —PRNG, gramática, stream de instrucciones, shrinker, emisor, triage— vive
//! afuera, así que sus tests corren en `cargo test --workspace` **sin** la
//! feature. Es la misma decisión que se tomó con `oracle.rs`, y por la misma
//! razón: un test que CI no corre no pinea nada.
//!
//! ## Lo que este módulo NO puede decir
//!
//! "0 divergencias" y "el fuzzer está roto" producen exactamente el mismo
//! output. Por eso el veredicto nunca se publica solo: va con la **cobertura
//! medida** (`coverage`), que dice qué fracción del set de opcodes ejecutó el
//! corpus y qué fracción de casos pasó del primer opcode.

// Sin la feature `diff-revm` el binario no consume el generador — pero sus
// tests SÍ corren, que es exactamente el motivo de que viva fuera de la
// feature.
#![cfg_attr(not(feature = "diff-revm"), allow(dead_code))]

/// Los opcodes son los del intérprete, no una copia. Una tabla propia se
/// desincroniza el día que entra un opcode nuevo, y el fuzzer dejaría de
/// generarlo sin que nadie se entere.
pub use repo_b_interpreter::opcode as opcodes;

#[cfg(feature = "diff-revm")]
pub mod campaign;
pub mod corpus;
pub mod coverage;
pub mod emit;
/// Los dos tipos que produce el triage: el hallazgo y el reporte.
#[cfg(feature = "diff-revm")]
pub mod finding;
pub mod generate;
pub mod grammar;
pub mod ledger;
pub mod mutate;
pub mod program;
/// El reporte de la campaña. Detrás de la feature porque lee el reporte, que
/// solo existe con el oráculo.
#[cfg(feature = "diff-revm")]
pub mod report;
pub mod rng;
pub mod seeds;
pub mod shrink;
/// El **sitio** de una divergencia. Detrás de la feature porque computarlo
/// exige trazar los DOS motores, y uno de ellos es revm.
#[cfg(feature = "diff-revm")]
pub mod site;
pub mod triage;
