#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/opcode-fork/*.json.

Gating por fork de opcodes y de EIP-3860. Forma heredada de precompile-fork y
selfdestruct-fork: el mismo caso con `post` en DOS forks, mismo bytecode y
mismo pre-state.

Los dos ejes que cubre son de naturaleza distinta y hay que verlos por
separado:

  1. EXISTENCIA de opcodes. Un opcode anterior a su fork HALTEA
     (OpcodeNotFound) y consume todo el gas. Se ve en el status y en el gas.
  2. COSTO de EIP-3860. NO cambia ningun resultado: solo el gas. Es la clase
     de bug que un fixture de solo-resultado no ve, y la que costo 66 casos --
     por eso hay casos que miden el gas con GAS/SWAP1/SUB.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/opcode-fork python3 scripts/gen-opcode-fork-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20

RICH = "0x3635c9adc5dea00000"

# ---------------------------------------------------------------- ensamblador

STOP = "00"
SUB = "03"
POP = "50"
MSTORE = "52"
SSTORE = "55"
GAS = "5a"
SWAP1 = "90"
CREATE = "f0"
CREATE2 = "f5"
PUSH0 = "5f"
BLOBHASH = "49"
BLOBBASEFEE = "4a"
TLOAD = "5c"
TSTORE = "5d"
MCOPY = "5e"


def push(value_hex):
    n = len(value_hex) // 2
    assert 1 <= n <= 32, value_hex
    return "%02x" % (0x60 + n - 1) + value_hex


def push_int(value, width=1):
    assert 0 <= value < (1 << (8 * width)), (value, width)
    return push(("%%0%dx" % (width * 2)) % value)


def cat(*parts):
    return "".join(parts)


def store_top_plus_one(slot):
    return cat(push_int(1), "01", push_int(slot), SSTORE)


def marker(slot, value):
    """Marca que la ejecucion LLEGO hasta aca. Si el opcode de arriba halteo,
    este SSTORE nunca corre y el slot queda ausente -- que es justo la senal."""
    return cat(push_int(value), push_int(slot), SSTORE)


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


def case(name, comment, code, forks, pre_extra=None):
    pre = {SENDER: account(0, RICH), MAIN: account(1, "0x0", "0x" + code)}
    pre.update(pre_extra or {})
    return name, {
        "_comment": comment,
        "env": {
            "currentCoinbase": COINBASE,
            "currentNumber": "0x01",
            "currentTimestamp": "0x03e8",
            "currentGasLimit": "0x01c9c380",
            "currentBaseFee": "0x0a",
            "currentRandom": "0x" + "00" * 32,
            "currentExcessBlobGas": "0x00",
        },
        "config": {"chainid": "0x01"},
        "pre": pre,
        "transaction": {
            "sender": SENDER,
            "to": MAIN,
            "nonce": "0x00",
            "gasPrice": "0x0c",
            "data": ["0x"],
            "gasLimit": ["0x0f4240"],
            "value": ["0x0"],
            "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
        },
        "post": {
            fork: [
                {
                    "indexes": {"data": 0, "gas": 0, "value": 0},
                    "hash": "0x" + "00" * 32,
                    "logs": "0x" + "00" * 32,
                }
            ]
            for fork in forks
        },
    }


# ------------------------------------------------------- existencia de opcodes

OPCODES = [
    ("push0", PUSH0, cat(PUSH0, POP), "Shanghai", ["Paris", "Shanghai"], "EIP-3855"),
    (
        "tload",
        TLOAD,
        cat(push_int(0), TLOAD, POP),
        "Cancun",
        ["Shanghai", "Cancun"],
        "EIP-1153",
    ),
    (
        "tstore",
        TSTORE,
        cat(push_int(1), push_int(0), TSTORE),
        "Cancun",
        ["Shanghai", "Cancun"],
        "EIP-1153",
    ),
    (
        "mcopy",
        MCOPY,
        cat(push_int(0x20), push_int(0), push_int(0x20), MCOPY),
        "Cancun",
        ["Shanghai", "Cancun"],
        "EIP-5656",
    ),
    (
        "blobhash",
        BLOBHASH,
        cat(push_int(0), BLOBHASH, POP),
        "Cancun",
        ["Shanghai", "Cancun"],
        "EIP-4844",
    ),
    (
        "blobbasefee",
        BLOBBASEFEE,
        cat(BLOBBASEFEE, POP),
        "Cancun",
        ["Shanghai", "Cancun"],
        "EIP-7516",
    ),
]

EXISTENCE = [
    case(
        f"{name}_halts_as_unknown_before_{activated.lower()}",
        f"{name.upper()} se activa en {activated} ({eip}). Antes NO EXISTE: el "
        "frame haltea con OpcodeNotFound y consume TODO el gas -- no es un "
        "revert ni un no-op. El SSTORE marcador de abajo solo corre si el "
        "opcode existio, asi que su AUSENCIA en el post-state es la senal.",
        cat(body, marker(1, 0x2a)),
        forks,
    )
    for (name, _op, body, activated, forks, eip) in OPCODES
]

# --------------------------------------------------------- costo de EIP-3860

INITCODE_WORDS = 4  # 128 bytes => 4 palabras => 8 gas de diferencia


def measure_create_cost(opcode, slot):
    """Mide con GAS el costo de un CREATE/CREATE2 con initcode de N palabras.

    El resultado del CREATE es IDENTICO en los dos forks -- lo unico que
    cambia es el gas, que es exactamente lo que un fixture de solo-resultado
    no ve. Es el bug que costo 66 casos.
    """
    # Orden del Yellow Paper: el operando de arriba es el PRIMERO que pide el
    # opcode. CREATE(value, offset, length) => se apila length, offset, value.
    # CREATE2(value, offset, length, salt) => salt, length, offset, value.
    #
    # Escrito explicito y NO con reversed(): la primera version uso reversed()
    # sobre una lista mal ordenada y el CREATE recibia length = 0, o sea
    # initcode VACIO y cero costo de EIP-3860 en los dos forks. El caso daba
    # [SAME] sin probar nada, y lo destapo la auditoria de post-state.
    args = [push_int(INITCODE_WORDS * 32), push_int(0), push_int(0)]
    if opcode == CREATE2:
        args = [push_int(0)] + args  # salt, hasta abajo
    return cat(
        GAS,
        *args,
        opcode,
        POP,
        GAS,
        SWAP1,
        SUB,
        push_int(slot),
        SSTORE,
    )


INITCODE_COST = [
    case(
        "create_initcode_word_cost_starts_in_shanghai",
        f"CREATE con initcode de {INITCODE_WORDS} palabras. EIP-3860 (Shanghai) "
        f"cobra 2 gas por palabra = {INITCODE_WORDS * 2}; Paris no cobra nada. "
        "El slot guarda el delta de GAS medido alrededor del opcode: el "
        "RESULTADO del CREATE es identico en los dos forks y solo cambia el "
        "gas. Este es el bug que costo 66 casos de EEST.",
        measure_create_cost(CREATE, 1),
        ["Paris", "Shanghai"],
    ),
    case(
        "create2_initcode_word_cost_starts_in_shanghai",
        "Identico con CREATE2: el costo por palabra es del initcode, no del "
        "opcode, asi que las dos formas de crear lo pagan igual.",
        measure_create_cost(CREATE2, 1),
        ["Paris", "Shanghai"],
    ),
]

FILES = {
    "opcodes.json": EXISTENCE,
    "initcode-cost.json": INITCODE_COST,
}


def main():
    out_dir = os.environ.get("FIXTURE_DIR", "cmd/conformance/fixtures/diff/opcode-fork")
    os.makedirs(out_dir, exist_ok=True)
    total = 0
    for filename, cases in FILES.items():
        payload = {}
        for name, body in cases:
            assert name not in payload, name
            payload[name] = body
        path = os.path.join(out_dir, filename)
        with open(path, "w") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        runs = sum(len(body["post"]) for _, body in cases)
        total += runs
        print(f"  {path}: {len(cases)} casos, {runs} corridas")
    print(f"total: {total} corridas")


if __name__ == "__main__":
    main()
