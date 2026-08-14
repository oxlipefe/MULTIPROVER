#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/precompile-fork/*.json.

Mismo criterio que los otros generadores del set diferencial: los fixtures
estan versionados y este script existe para que sean REPRODUCIBLES. El oraculo
es revm, no este archivo (`hash`/`logs` van en cero a proposito).

Lo que este set ejercita: una direccion del rango reservado NO es precompile
antes de su fork de activacion -- es una cuenta vacia normal. Eso se ve en DOS
dimensiones, y un fixture que solo mire el output ve la mitad:

  1. EXISTENCIA. Un CALL a `0x0A` en Shanghai va a una cuenta vacia (exito,
     sin output); en Cancun corre KZG (y falla, porque el input no mide 192).
  2. ACCESSED SET (EIP-2929). La direccion que todavia no es precompile
     arranca COLD (2600), no warm (100). No cambia el resultado, cambia el
     GAS -- por eso hay casos que miden el delta de gas explicitamente.

La estructura del set es "el mismo caso en dos forks": mismo bytecode, mismo
pre-state, y `post` con dos claves de fork. Si el motor no gatea, los dos
forks dan lo mismo y el diferencial lo canta.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/precompile-fork python3 scripts/gen-precompile-fork-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20  # el contrato que llama
COINBASE = "0x" + "c0" * 20
SUICIDAL = "0x" + "e0" * 20  # el que hace SELFDESTRUCT

ECRECOVER = "0x" + "00" * 19 + "01"
KZG = "0x" + "00" * 19 + "0a"  # Cancun
BLS_G1_ADD = "0x" + "00" * 19 + "0b"  # Prague
BLS_MAP_FP_TO_G1 = "0x" + "00" * 19 + "10"  # Prague -- el beneficiario del SELFDESTRUCT
PAST_THE_SET = "0x" + "00" * 19 + "12"  # nunca precompile, en ningun fork

# ---------------------------------------------------------------- ensamblador

STOP = "00"
SUB = "03"
POP = "50"
MSTORE = "52"
SSTORE = "55"
GAS = "5a"
SWAP1 = "90"
CALL = "f1"
BALANCE = "31"
RETURNDATASIZE = "3d"
SELFDESTRUCT = "ff"


def push(value_hex):
    n = len(value_hex) // 2
    assert 1 <= n <= 32, value_hex
    return "%02x" % (0x60 + n - 1) + value_hex


def push_int(value, width=1):
    assert 0 <= value < (1 << (8 * width)), (value, width)
    return push(("%%0%dx" % (width * 2)) % value)


def push_addr(addr):
    return push(addr[2:])


def cat(*parts):
    return "".join(parts)


def store_top_plus_one(slot):
    """Guarda `tope + 1`: un 0 no existe en el trie, asi que sin el +1 un slot
    ausente no distinguiria "fallo" de "no corrio"."""
    return cat(push_int(1), "01", push_int(slot), SSTORE)


def store_top(slot):
    return cat(push_int(slot), SSTORE)


# Gas reenviado al CALL: acotado y MUY por debajo del presupuesto de la tx.
# La leccion de 2.8d generalizada: si el CALL puede consumir casi todo el
# presupuesto, un fallo del precompile haltea la tx ENTERA y el fixture deja de
# probar lo que dice -- el caller tiene que conservar margen en exito Y en
# fallo, para que las SSTORE posteriores corran igual.
FORWARDED_GAS = "00c350"  # 50_000
TX_GAS_LIMIT = "0x0f4240"  # 1_000_000


def call_and_record(addr, slot_status, slot_retsize, arg_length=0):
    """CALL a `addr` sin input; guarda status+1 y RETURNDATASIZE.

    `RETURNDATASIZE` es la mitad que distingue "cuenta vacia" de "precompile
    que devolvio vacio": las dos dan status 1, pero solo una puede devolver
    bytes. Es el mismo observable que usa `test_precompile_absence.json` de
    EEST."""
    return cat(
        push_int(0),  # ret_length
        push_int(0),  # ret_offset
        push_int(arg_length),  # arg_length
        push_int(0),  # arg_offset
        push_int(0),  # value
        push_addr(addr),
        push(FORWARDED_GAS),
        CALL,
        store_top_plus_one(slot_status),
        RETURNDATASIZE,
        store_top_plus_one(slot_retsize),
    )


def measure_access_cost(addr, slot):
    """Guarda el costo de acceder a `addr`, medido con GAS antes y despues.

    El delta incluye el overhead fijo de los opcodes de medicion, que es
    IDENTICO en los dos forks y en los dos motores -- lo unico que se mueve es
    cold (2600) vs warm (100). Esto es lo que un post-state de solo-resultado
    NO muestra: el prewarm indebido no cambia el output de nada, cambia el gas.

        GAS               -> [g0]
        <addr> BALANCE    -> [g0, balance]
        POP               -> [g0]
        GAS               -> [g0, g1]
        SWAP1 SUB         -> [g0 - g1]
    """
    return cat(
        GAS,
        push_addr(addr),
        BALANCE,
        POP,
        GAS,
        SWAP1,
        SUB,
        store_top(slot),
    )


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


RICH = "0x3635c9adc5dea00000"


def case(name, comment, pre, forks, to=MAIN, value="0x0", gas_limit=TX_GAS_LIMIT):
    """Un caso corrido en VARIOS forks: mismo pre-state, mismo bytecode.

    Que `post` lleve dos claves de fork es el corazon del set. Si el motor
    resolviera precompiles por rango en vez de por fork, los dos forks darian
    exactamente lo mismo y el caso no probaria nada."""
    assert len(forks) >= 2 or name.endswith("_in_every_fork"), name
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
            "to": to,
            "nonce": "0x00",
            "gasPrice": "0x0c",
            "data": ["0x"],
            "gasLimit": [gas_limit],
            "value": [value],
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


def base_pre(code, extra=None):
    pre = {
        SENDER: account(0, RICH),
        MAIN: account(1, "0x0", "0x" + code),
    }
    pre.update(extra or {})
    return pre


# ------------------------------------------------------------------- los casos

EXISTENCE = [
    case(
        "kzg_at_0x0a_is_an_empty_account_before_cancun",
        "CALL a 0x0A sin input. En Shanghai la direccion NO es precompile: es "
        "una cuenta vacia, el CALL tiene EXITO (status 1) y RETURNDATASIZE = 0. "
        "En Cancun corre KZG, que exige el largo EXACTO de 192 bytes y por lo "
        "tanto FALLA (status 0). Mismo bytecode, mismo pre-state: lo unico que "
        "cambia es el fork.",
        base_pre(call_and_record(KZG, 1, 2)),
        ["Shanghai", "Cancun"],
    ),
    case(
        "bls_g1_add_at_0x0b_is_an_empty_account_before_prague",
        "Identico al de KZG pero en la frontera de Prague: en Cancun 0x0B es "
        "cuenta vacia (status 1), en Prague corre BLS12_G1_ADD de EIP-2537, que "
        "rechaza el input vacio (status 0).",
        base_pre(call_and_record(BLS_G1_ADD, 1, 2)),
        ["Cancun", "Prague"],
    ),
    case(
        "ecrecover_at_0x01_is_a_precompile_in_every_fork_in_scope",
        "No-regresion de la otra punta: 0x01 se activo en Frontier, muy antes "
        "del scope de este motor, asi que existe en los cuatro forks. Con input "
        "vacio ECRECOVER tiene EXITO con output VACIO (no es un fallo: la firma "
        "no recupera nada) -- status 1 y RETURNDATASIZE 0, igual que una cuenta "
        "vacia. Por eso este caso solo cubre existencia, no discrimina solo.",
        base_pre(call_and_record(ECRECOVER, 1, 2)),
        ["Paris", "Shanghai", "Cancun", "Prague"],
    ),
    case(
        "address_past_the_set_is_an_empty_account_in_every_fork",
        "0x12 esta justo despues de la ultima BLS y no es precompile en NINGUN "
        "fork. No-regresion del test que reemplazo al gate fail-closed borrado "
        "cuando se cerro el rango completo: sigue siendo una cuenta vacia "
        "normal, en los cuatro forks.",
        base_pre(call_and_record(PAST_THE_SET, 1, 2)),
        ["Paris", "Shanghai", "Cancun", "Prague"],
    ),
]

ACCESS_COST = [
    case(
        "an_address_not_yet_a_precompile_costs_cold_access",
        "LA MITAD DEL BUG QUE EL OUTPUT NO MUESTRA. Mide con GAS el costo de un "
        "BALANCE sobre 0x0B. En Prague la direccion es precompile y el "
        "prewarming de la tx (EIP-2929) la deja WARM: 100. En Cancun todavia no "
        "es precompile, asi que arranca COLD: 2600. Delta de 2500 en el slot, y "
        "cero diferencia en el resultado de nada -- calentar el rango entero "
        "era exactamente este recargo regalado.",
        base_pre(measure_access_cost(BLS_G1_ADD, 1)),
        ["Cancun", "Prague"],
    ),
    case(
        "kzg_access_cost_crosses_the_cancun_boundary",
        "El mismo delta de 2500 en la otra frontera: 0x0A cold en Shanghai, "
        "warm en Cancun. Dos fronteras medidas por separado porque un gateo que "
        "acierte una y erre la otra tiene que caer aca.",
        base_pre(measure_access_cost(KZG, 1)),
        ["Shanghai", "Cancun"],
    ),
    case(
        "an_address_past_the_set_costs_cold_access_in_every_fork",
        "0x12 nunca se calienta: cold (2600) en los cuatro forks. Es el control "
        "del caso de arriba -- si el prewarm se fuera de rango hacia arriba, "
        "este es el que lo caza.",
        base_pre(measure_access_cost(PAST_THE_SET, 1)),
        ["Paris", "Shanghai", "Cancun", "Prague"],
    ),
]

SELFDESTRUCT_BENEFICIARY = [
    case(
        "selfdestruct_to_an_address_not_yet_a_precompile_pays_cold",
        "El escenario de create2collisionSelfdestructed, aislado: un contrato "
        "hace SELFDESTRUCT con beneficiario 0x10. En Prague 0x10 es "
        "BLS_MAP_FP_TO_G1 y viene prewarmeada (warm); en Cancun no es "
        "precompile y el acceso al beneficiario cuesta cold. La diferencia no "
        "aparece en ningun slot: aparece en el gas_used de la tx, que el "
        "comparador si mira.",
        {
            SENDER: account(0, RICH),
            SUICIDAL: account(
                1,
                "0x0de0b6b3a7640000",  # 1 ETH, para que el beneficiario reciba algo
                "0x" + cat(push_addr(BLS_MAP_FP_TO_G1), SELFDESTRUCT),
            ),
        },
        ["Cancun", "Prague"],
        to=SUICIDAL,
    ),
]

FILES = {
    "existence.json": EXISTENCE,
    "access-cost.json": ACCESS_COST,
    "selfdestruct.json": SELFDESTRUCT_BENEFICIARY,
}


def main():
    out_dir = os.environ.get(
        "FIXTURE_DIR", "cmd/conformance/fixtures/diff/precompile-fork"
    )
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
        # Cada caso corre una vez POR FORK: eso es lo que cuenta el comparador.
        runs = sum(len(body["post"]) for _, body in cases)
        total += runs
        print(f"  {path}: {len(cases)} casos, {runs} corridas")
    print(f"total: {total} corridas")


if __name__ == "__main__":
    main()
