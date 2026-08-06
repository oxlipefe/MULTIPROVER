# Repo B — EVM propio provable (MULTIPROVER / NEX MULTIPROOF GENERATION)

Un **EVM mínimo, Type-1-exacto, stateless y formalmente-verificable** en Rust `no_std`, proyecto paralelo de `zeth` (Repo A). Compila a `riscv64gc` y se prueba con zkVMs intercambiables (multiproof del EF). *La máquina que no puede mentir.*

> **Decisión estratégica vinculante (ADR 0001):** plug-and-play la zkVM, NO build-own. Ver `docs/adr/0001-plug-and-play-zkvm.md`.

## Leer antes de codear (orden)
1. `docs/REPO_B_KICKOFF.md` — documento fundacional.
2. `ARCHITECTURE.md` — misión, seams (`Vm`/`State`/`Prover`), reglas en piedra.
3. `ENGINEERING_RULES.md` — reglas por componente + 6 preguntas universales.
4. `PRODUCTION_PLAN.md` — fases 0→6 con DoD y gate.
5. `CLAUDE.md` — reglas sine qua non de trabajo.
6. `docs/knowledge/` — ficha por componente; `CONFORMANCE.md` = fuente única de verdad del gate.

## Estructura del workspace
```
crates/
  common/       # no_std: primitives + tipos (idénticos a zeth)
  interpreter/  # máquina de pila (Fase 1)
  evm/          # seam Vm/State (vendoreado de zeth) + impl del EVM propio (Fase 2)
  witness/      # recorder stateless (Fase 3)
  prover/       # seam Prover + backends zkVM (Fase 4)
cmd/
  conformance/  # runner EF tests + diferencial-vs-revm (el GATE; RED por defecto)
```

## Estado
**Fase 0 — Bootstrap: EN CURSO.** Andamiaje creado; el gate (compila/CI/no_std) aún **no verificado** en este entorno (sin toolchain). Correr en tu máquina:

```sh
cargo build
cargo clippy --all-targets -- -D warnings
cargo run -p conformance        # cableado RED por diseño
cargo deny check
cargo build -p repo-b-evm --target riscv64gc-unknown-none-elf   # chequeo no_std/RISC-V
```
