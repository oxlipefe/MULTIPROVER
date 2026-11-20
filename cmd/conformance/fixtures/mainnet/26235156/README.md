# Mainnet block 26 235 156 — block and execution witness

A real Ethereum mainnet block (Osaka/BPO2) and the witness that lets the guest
execute it statelessly, in the two files the importer reads
(`--import-block block.json witness.json <out.bin> --expect-block-hash …`).

## Origin

- Repository: `0xPolygonHermez/zisk-eth-client`, commit `dfa27ff2`.
- File: `bin/guests/stateless-validator-reth/inputs/mainnet_26235156_91_5_zec_reth.bin`
  (sha256 `164e87f73ce0cf4db975d8e5b148b6b40d828cdd412d7cf53aeca2c1e2a0123f`).
- License of that repository: Apache-2.0. The content is public chain data.

**This is a re-serialization, not the raw JSON of an RPC call.** The source
file is a `ZiskStdin` (block RLP + reth's `ExecutionWitness` in bincode). It
was decoded and written back as:

- `block.json` — a JSON string `"0x…"` with the block RLP, the shape of the
  `result` of `debug_getRawBlock`;
- `witness.json` — an object with `state`, `codes`, `keys`, `headers` (lists
  of `"0x…"`), the shape of the `result` of `debug_executionWitness`.

Whitespace was removed; no value was changed (the compact and the original
files import to the same input byte for byte).

## Reference values (from a public mainnet node, `eth_getBlockByNumber`)

| field | value |
|---|---|
| number | 26 235 156 |
| hash | `0xa9533744986888244d786721fc0506984585de242dc3d4e0db6d8337abe75bc4` |
| parentHash | `0x14cd2ccb955333f34102373483c30ad5e8f25162c998feb2eb3c7cad57ba129f` |
| stateRoot | `0xe471049224c65cef0fc04f14a0e02fcb784b13a8bf36a320984ac99e7339a3f9` |
| gasUsed | 5 443 474 |
| transactions | 91 |
| timestamp | 1 792 515 695 |

The witness carries 2 821 state nodes, 85 codes, 463 keys and 1 header (the
parent). The hash is the anchor: the importer refuses the files unless the
recomputed header hash is this one, and the test compares the post-state root
the guest computes against the `stateRoot` above.
