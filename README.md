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

## Design goals

Correctness is not asserted, it is *established* against oracles, in this priority order:

**correctness → determinism → consensus safety → simplicity → performance**

Three properties follow from that ordering, and they are enforced mechanically:

- **Type-1-exact.** Bit-identical to `revm` and to the Ethereum Foundation's test suite. Not "compatible" — identical. A divergence is a bug by definition, never a design choice.
- **Stateless.** The engine never touches disk. It consumes a witness and emits a state diff, which is what makes it provable inside a zkVM.
- **Built to be formally verifiable.** `no_std`, no `unsafe`, no floating point, no hash-map iteration order, no ambient I/O, explicit checked arithmetic everywhere. These are not style preferences: non-determinism does not compile to RISC-V, and what does not compile does not prove.

## Architecture

```
crates/
  common/       # no_std primitives and shared types
  interpreter/  # the stack machine: opcodes, memory, gas
  evm/          # Vm/State seams, journal, frame stack, precompiles
  witness/      # stateless recorder (not started)
  prover/       # Prover seam + zkVM backends (not started)
cmd/
  conformance/  # EF test runner, EEST harness, revm differential — the gate
```

Three seams carry the design:

- **`Vm`** — the engine behind an interface, so it can be swapped and compared against another implementation.
- **`State`** — the world as data. The engine reads a witness and emits a diff; it never performs I/O. Statelessness comes from *wrapping* `State` with a recorder, not from contaminating the engine.
- **`Prover`** — the zkVM as an interchangeable backend. We do not build a prover: the engine is written in `no_std` Rust, compiled to `riscv64`, and proved by general-purpose zkVMs. Multiproof means supporting several backends rather than marrying one.

Inside the engine, the interpreter is a plain `match` dispatch over opcodes — legibility and verifiability over raw throughput. The `Journal` owns balances, nonces, storage and the code overlay, with an explicit checkpoint stack so a reverted sub-call unwinds exactly what it touched. Nested calls do **not** recurse in Rust: the interpreter returns an `InterpreterAction` and suspends with its stack, memory, program counter and gas intact, and an executor with an explicit frame stack resumes it. A chain of 1024 calls cannot blow the native stack — a hard requirement for a RISC-V guest.

## How correctness is established

Passing tests is not evidence. These are the oracles, in increasing order of strength:

**1. Adversarial unit tests per opcode.** Every opcode and precompile that consumes external input has negative tests — malformed input, overflow, stack/gas/memory limits, EIP edge cases — not just a happy path.

**2. Byte-for-byte differential against `revm`.** The same transaction runs in both engines and every observable is compared: state root, gas used, refunds, logs hash, return data, halt reason. On divergence, the harness prints the **first diverging execution step** on both sides (EIP-3155 traces) — never a bare "the root differs".

**3. Mutation testing on the differential suite.** A test suite that has never failed is not known to work. Deliberate bugs are injected into the engine and the suite must catch them, with the *expected signal* recorded. Over 100 deliberate mutations have been run to date. Several found real coverage holes; one found a bug in the fixture generator that both engines agreed on — which is exactly the failure mode differential testing is blind to.

**4. Post-state audit.** `[SAME]` is not evidence until the post-state is read. In one case, 33 of 33 fixtures passed while 6 of them tested nothing at all — the caller died of out-of-gas before ever reaching the code under test.

**5. The full Ethereum Foundation test suite.** `execution-spec-tests` v5.4.0, pinned and `sha256`-verified, with a real recomputed MPT state root. Progress is a **ratchet**: the harness exits non-zero if the number of passing cases ever regresses.

The differential oracle has repeatedly corrected the specification rather than the other way around — for example, that a high `s` value in `ECRECOVER` is *not* rejected, that the EIP-7702 authorization refund survives both revert and halt, and that one `InvalidTransaction` variant in `revm` is unreachable dead code.

## What is not done yet

Stated plainly, because credibility is worth more than a good-looking table:

- **380 conformance failures remain**, and they are the hard ones — 354 are pure consensus divergences where both engines succeed and the state root differs. Root causes are mapped: fork-gating of the precompile set and the opcode set, EIP-3860 charged pre-Shanghai, EIP-6780 applied unconditionally, and EIP-7610 never implemented.
- **The fork target is Prague.** Mainnet is ahead: `P256VERIFY` (EIP-7951) and the Osaka MODEXP repricing are not implemented.
- **"Formally verifiable" is a design constraint, not an achieved property.** There is no formal artifact yet. The engine was written to be verifiable — no `unsafe`, no floats, explicit arithmetic — which is a precondition, not a proof.
- **Blockchain tests have no baseline.** Multi-transaction blocks, withdrawals, header validation and `blockHashes` need a block driver.
- **This is not yet a zkVM guest program.** Compiling to bare-metal RISC-V is gated in CI; the standardized guest interface is not started.

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

## How this was built

This engine was written in collaboration with **Claude** (Anthropic), used as an implementation and review partner throughout.

That collaboration is not a substitute for the oracle, and the project is structured so that it cannot be. "Done" is never a judgment call: it is an exit code against `revm` and against the Ethereum Foundation's test suite. Every consensus rule in this repository was verified against the reference implementation's source rather than recalled from memory; every differential suite was mutation-tested before being trusted; and the conformance number only moves in one direction, because the harness refuses to let it regress. Where the specification and the oracle disagreed, the oracle won and the specification was corrected.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
