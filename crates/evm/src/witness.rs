//! El witness vive en `repo-b-common`: lo miran los dos lados del seam (el
//! motor lo referencia en su outcome, el backend de proving lo consume) y el
//! motor no puede depender del crate que lo produce.
//!
//! El tipo que había acá era un mínimo de la Fase 0 con otra forma (mapas
//! semánticos) y un doc-comment que prometía alinearlo "al `ExecutionWitness`
//! de zeth": zeth no define un formato propio, lo importa de alloy. La forma
//! canónica es la de alloy y ahora es la única que existe en el repo.

pub use repo_b_common::witness::ExecutionWitness;
