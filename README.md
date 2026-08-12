# MULTIPROVER

**A Type-1-exact, stateless Ethereum execution engine written from scratch in `no_std` Rust — built to be a diverse state-transition function for Ethereum's multiproof strategy.**

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

| | |
|---|---|
| **EEST conformance** | **38,644 / 39,024** `state_test` cases (**99.0%**) — `execution-spec-tests` v5.4.0, `--until=Prague` |
| **Differential vs `revm`** | **249 / 249** cases, **0 divergences**, byte-for-byte |
| **Precompiles** | `0x01..=0x11` — the full reserved range, no gaps, pure Rust |
| **Transaction types** | All four Prague types: legacy, 2930, 1559, 4844, 7702 |
| **`unsafe` in first-party code** | **0** — `#![forbid(unsafe_code)]` across all five crates |

---

## Why this exists

Ethereum is moving toward a zkEVM-secured L1. The Ethereum Foundation's own security analysis is explicit about what that requires:

> *"Diversity among implementations of zkEVMs will be a critical component of security. This diversity should be diversity of both of zkVM provers **and of STF implementations**."*
> — [zkEVM Security Overview](https://zkevm.ethereum.foundation/blog/zkevm-security-overview), 2026-01-14

That diversity does not exist yet. Across the provers listed on [ethproofs.org](https://ethproofs.org/), there are **four** distinct state-transition function implementations, and the majority run the same one.

A monoculture of STFs means a single semantic bug is provable, proven, and wrong on every backend simultaneously. Proof diversity without implementation diversity buys much less than it appears to.

**MULTIPROVER is an independent STF.** Not a fork, not a wrapper — a second opinion, written from scratch, whose entire purpose is to disagree with the incumbent implementation when the incumbent is wrong.

## The thesis

> **The machine that cannot lie.**

Correctness is not asserted. It is *established*, against oracles, in this priority order:

**correctness → determinism → consensus safety → simplicity → performance**

Three properties follow from that ordering, and they are enforced mechanically:

- **Type-1-exact.** Bit-identical to `revm` and to the Ethereum Foundation's test suite. Not "compatible" — identical. A divergence is a bug by definition, never a design choice.
- **Stateless.** The engine never touches disk. It consumes a witness and emits a state diff, which is what makes it provable inside a zkVM.
- **Built to be formally verifiable.** `no_std`, no `unsafe`, no floating point, no hash-map iteration order, no ambient I/O, explicit checked arithmetic everywhere. These are not style preferences: non-determinism does not compile to RISC-V, and what does not compile does not prove.

## How correctness is established

Passing tests is not evidence. These are the oracles, in increasing order of strength:

**1. Unit tests per opcode, including adversarial cases.** Every opcode and precompile that consumes external input has negative tests — malformed input, overflow, stack/gas/memory limits, EIP edge cases — not just a happy path.

**2. Byte-for-byte differential against `revm`.** The same transaction runs in both engines and every observable is compared: state root, gas used, refunds, logs hash, return data, halt reason. On divergence, the harness prints the **first diverging execution step** on both sides (EIP-3155 traces) — never a bare "the root differs."

**3. Mutation testing on the differential suite.** A test suite that has never failed is not known to work. Before any slice closes, deliberate bugs are injected into the engine and the suite must catch them, with the *expected signal* recorded. Over 100 deliberate mutations have been run to date. Several found real coverage holes; one found a bug in the fixture generator that both engines agreed on — which is exactly the failure mode differential testing is blind to.

**4. Post-state audit.** `[SAME]` is not evidence until the post-state is read. In one slice, 33 of 33 cases passed while 6 of them tested nothing at all — the caller died of out-of-gas before reaching the code under test. Reading the post-state is now mandatory before a slice can close.

**5. The full Ethereum Foundation test suite.** `execution-spec-tests` v5.4.0, pinned and `sha256`-verified, with a real recomputed MPT state root. Progress is a **ratchet**: the harness exits non-zero if the number of passing cases ever regresses. Raising the baseline is an explicit, committed act.

The differential oracle has repeatedly corrected the specification rather than the other way around — for example, that a high `s` value in `ECRECOVER` is *not* rejected, that the EIP-7702 authorization refund survives both revert and halt, and that one `InvalidTransaction` variant in `revm` is unreachable dead code.

## Status

| Phase | Scope | State |
|---|---|---|
| **0 — Bootstrap** | Workspace, CI, `no_std`/RISC-V build, supply-chain gates | ✅ **Closed** |
| **1 — Interpreter core** | Stack machine, memory, gas, first EF test green | ✅ **Closed** |
| **2 — Conformance** | Bit-identical vs `revm` + the full EF suite. **The gate of existence.** | 🟡 **99.0%** |
| 3 — Witness | Stateless recorder wrapping `State` | Not started |
| 4 — Prover seam | Compile to RISC-V, integrate zkVM backends | Not started |
| 5 — Integration | Reconciliation behind the `Vm` seam | Not started |
| 6 — Formal verification | Extraction and proof of consensus-critical modules | Not started |

**Nothing integrates without passing its testing gate.** Phase 2 is not a milestone, it is an existence condition: until the engine is bit-identical, a second opinion that disagrees for the wrong reasons is worse than no second opinion.

### What is not done yet

Stated plainly, because credibility is worth more than a good-looking table:

- **380 conformance failures remain**, and they are the hard ones — 354 are pure consensus divergences where both engines succeed and the state root differs. Root causes are mapped: fork-gating of the precompile set and the opcode set, EIP-3860 charged pre-Shanghai, EIP-6780 applied unconditionally, and EIP-7610 never implemented.
- **The fork target is Prague.** Mainnet is ahead: `P256VERIFY` (EIP-7951, live since 2025-12-03) and the Osaka MODEXP repricing are not implemented.
- **"Formally verifiable" is a design constraint, not an achieved property.** There is no formal artifact yet. The engine was written to be verifiable — no `unsafe`, no floats, explicit arithmetic — which is a precondition, not a proof.
- **Blockchain tests have no baseline.** Multi-transaction blocks, withdrawals, header validation and `blockHashes` need a block driver.
- **This is not yet a zkVM guest program.** Compiling to bare-metal RISC-V is gated in CI; the standardized guest interface is Phase 4 work.

Current detail always lives in [`docs/knowledge/CONFORMANCE.md`](docs/knowledge/CONFORMANCE.md), which is the single source of truth for what passes and what does not.

## Architecture

```
crates/
  common/       # no_std primitives and shared types
  interpreter/  # the stack machine: opcodes, memory, gas
  evm/          # Vm/State seams, journal, frame stack, precompiles
  witness/      # stateless recorder (Phase 3)
  prover/       # Prover seam + zkVM backends (Phase 4)
cmd/
  conformance/  # EF test runner, EEST harness, revm differential — the gate
```

Three seams carry the design, and each one is a decision recorded as an ADR:

- **`Vm`** — the engine behind an interface, so it can be swapped and compared.
- **`State`** — the world as data. The engine reads a witness and emits a diff; it never performs I/O. Statelessness comes from *wrapping* `State` with a recorder, not from contaminating the engine.
- **`Prover`** — the zkVM as an interchangeable backend. We do not build a prover. ([ADR-0001](docs/adr/0001-plug-and-play-zkvm.md))

## Building

Requires the pinned toolchain in `rust-toolchain.toml`.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p repo-b-common -p repo-b-evm -p repo-b-interpreter \
    --target riscv64imac-unknown-none-elf     # no_std / bare-metal RISC-V gate

cargo run -p conformance                       # vendored EF fixtures
cargo run -p conformance --features diff-revm -- --diff fixtures/diff
bash scripts/fetch-eest.sh                     # pinned, sha256-verified (~257 MB)
cargo run -p conformance --release -- --eest   # the full EF suite, ~6s
```

Supply chain is gated with `cargo deny` and `cargo audit` in CI.

## How this is built

Development runs as a durable task loop: every unit of work is a file with a specification, an explicit dependency graph, a **gate defined as a command whose exit code decides "done"**, a monotone progress metric, a budget, and an attempt log in which re-trying a falsified hypothesis is forbidden. See [`docs/AGENT_LOOP.md`](docs/AGENT_LOOP.md).

The point of that structure is that no participant — human or otherwise — can substitute their own judgment for the oracle. "Done" is an exit code against `revm` and the Ethereum Foundation's tests. Progress is a number that only moves one way.

## Documentation

| Document | What it holds |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Mission, seams, global design decisions, scope |
| [`ENGINEERING_RULES.md`](ENGINEERING_RULES.md) | Per-component rules and the six universal questions |
| [`PRODUCTION_PLAN.md`](PRODUCTION_PLAN.md) | Phases 0→6 with definitions of done |
| [`docs/knowledge/CONFORMANCE.md`](docs/knowledge/CONFORMANCE.md) | **Single source of truth** for the conformance gate |
| [`docs/adr/`](docs/adr/) | Architecture decision records. Accepted ADRs are binding |
| [`docs/GTM_GUEST_PROGRAM.md`](docs/GTM_GUEST_PROGRAM.md) | Path into the EF proving ecosystem, with sources |

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
