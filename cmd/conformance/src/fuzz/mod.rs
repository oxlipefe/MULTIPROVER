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

/// El **presupuesto como gas**: se cobra antes de gastar, se devuelve lo no
/// usado, y sin presupuesto configurado no arranca nada. Fuera de la feature
/// porque acota dinero, no divergencias.
pub mod budget;
#[cfg(feature = "diff-revm")]
pub mod campaign;
pub mod corpus;
pub mod coverage;
/// El corpus DIRIGIDO: semillas escritas contra una interacción entre EIPs.
/// Fuera de la feature a propósito — la validación fail-closed de sus semillas
/// no necesita al oráculo, y un test que CI no corre no pinea nada.
pub mod directed;
pub mod emit;
/// Los dos tipos que produce el triage: el hallazgo y el reporte.
#[cfg(feature = "diff-revm")]
pub mod finding;
/// **El loop de PROFUNDIDAD**: la flota efímera, su seam de proveedor y el
/// proveedor falso con el que se gatea sin nube.
pub mod fleet;
pub mod generate;
pub mod grammar;
/// Qué se hace con una divergencia una vez encontrada. Detrás de la feature
/// porque minimizar exige volver a correr el oráculo.
#[cfg(feature = "diff-revm")]
pub mod harvest;
pub mod ledger;
pub mod mutate;
pub mod program;
/// **El loop de REGRESIÓN**: el corpus sembrado con cada divergencia histórica
/// ya cazada, barrido en el gate de merge.
pub mod regression;
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
/// **Cobertura por tema**: qué territorio de consenso tocó una campaña. Es la
/// métrica que separa a los tres generadores, y la que `coverage` no puede dar.
pub mod themes;
pub mod triage;
