#!/usr/bin/env python3
"""Genera el set diferencial Osaka de CLZ (EIP-7939).

Los hashes esperados quedan en cero a propósito: el juez es revm. El primer
caso cruza Prague→Osaka con el mismo bytecode; los demás fijan los bordes del
resultado en Osaka. Los bordes de gas y underflow viven en unit tests directos,
donde el presupuesto del opcode se puede aislar sin ruido de una transacción.
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20
RICH = "0x3635c9adc5dea00000"


def push32(value):
    return "7f" + value.to_bytes(32, "big").hex()


def code(value):
    # PUSH32 value; CLZ; PUSH1 0; SSTORE; STOP
    return "0x" + push32(value) + "1e60005500"


def account(nonce=0, balance="0x0", bytecode="0x"):
    return {"nonce": hex(nonce), "balance": balance, "code": bytecode, "storage": {}}


def case(comment, value, forks):
    return {
        "_comment": comment,
        "env": {
            "currentCoinbase": COINBASE,
            "currentNumber": "0x01",
            "currentTimestamp": "0x03e8",
            "currentGasLimit": "0x01c9c380",
            "currentBaseFee": "0x0a",
            "currentRandom": "0x" + "00" * 32,
        },
        "config": {"chainid": "0x01"},
        "pre": {
            SENDER: account(0, RICH),
            MAIN: account(1, bytecode=code(value)),
        },
        "transaction": {
            "sender": SENDER,
            "to": MAIN,
            "nonce": "0x00",
            "gasPrice": "0x0c",
            "data": ["0x"],
            "gasLimit": ["0x0f4240"],
            "value": ["0x0"],
        },
        "post": {
            fork: [{
                "indexes": {"data": 0, "gas": 0, "value": 0},
                "hash": "0x" + "00" * 32,
                "logs": "0x" + "00" * 32,
            }]
            for fork in forks
        },
    }


CASES = {
    "clz_crosses_the_prague_osaka_fork_boundary": case(
        "El mismo opcode 0x1e es inválido en Prague y CLZ(1)=255 en Osaka.",
        1,
        ["Prague", "Osaka"],
    ),
    "clz_of_zero_is_256": case("Borde especial fijado por EIP-7939.", 0, ["Osaka"]),
    "clz_of_the_most_significant_bit_is_zero": case(
        "El bit 255 puesto no tiene ceros líderes.", 1 << 255, ["Osaka"]
    ),
    "clz_counts_an_intermediate_pattern": case(
        "Patrón no trivial: el bit más alto está en la posición 200.",
        (1 << 200) | 0x1234,
        ["Osaka"],
    ),
}


def main():
    out_dir = os.environ.get("FIXTURE_DIR", "cmd/conformance/fixtures/diff/clz")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "clz.json")
    with open(path, "w") as handle:
        json.dump(CASES, handle, indent=2)
        handle.write("\n")
    print(f"{path}: {len(CASES)} casos, {sum(len(c['post']) for c in CASES.values())} corridas")


if __name__ == "__main__":
    main()
