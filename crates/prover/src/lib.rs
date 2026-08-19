//! `repo-b-prover` — el seam `Prover`: abstrae el backend de proving.
//!
//! **Fase 4 (PENDIENTE). NO tocar hasta Fase 4** (primero el EVM bit-idéntico).
//! El motor (`interpreter`/`evm`) compila a `riscv64gc` como *guest*; este seam
//! permite backends intercambiables (`SP1`/`RSP`, `RISC0`/zeth, `OpenVM`, `ZisK`)
//! —multiproof del EF, ADR 0001. NINGÚN backend hardcodeado; cuarentena en este crate.
#![no_std]
#![forbid(unsafe_code)]

use repo_b_common::witness::ExecutionWitness;

/// Contrato del backend de proving. Las firmas concretas (`GuestProgram`,
/// `Proof`) se decidirán just-in-time en Fase 4 contra el backend elegido.
pub trait Prover {
    type Proof;
    type Error;

    /// Prueba la ejecución del guest contra un witness. Devuelve prueba verificable.
    fn prove(&self, witness: &ExecutionWitness) -> Result<Self::Proof, Self::Error>;

    /// Verifica una prueba previamente generada.
    fn verify(&self, proof: &Self::Proof) -> Result<bool, Self::Error>;
}
