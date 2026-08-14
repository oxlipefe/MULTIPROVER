#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/selfdestruct-fork/*.json.

EIP-6780 ("SELFDESTRUCT solo destruye si la cuenta se creo en ESTA tx") arranca
en CANCUN. Antes -- Paris, Shanghai -- SELFDESTRUCT borra la cuenta entera:
storage, codigo, nonce y balance.

Forma del set (heredada del set precompile-fork): cada caso lleva `post` con
DOS claves de fork, sobre el mismo bytecode y el mismo pre-state. Si el gateo
no existiera, los dos forks darian identico y el caso no probaria nada -- la
discriminacion esta construida en la estructura, no confiada al autor.

AVISO sobre el juez: `diff.rs::normalize()` es estructuralmente ciego a EIP-161
(descarta cuentas vacias de los dos lados). Una cuenta destruida que quede
"vacia pero presente" puede pasar el diferencial y fallar el root MPT que EEST
recomputa. Por eso las victimas de este set tienen STORAGE NO VACIO: el storage
que desaparece si es observable en el post-state, y no depende de la ceguera.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/selfdestruct-fork python3 scripts/gen-selfdestruct-fork-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
CALLER = "0x" + "b0" * 20   # el que llama a la victima
VICTIM = "0x" + "e0" * 20   # la que hace SELFDESTRUCT
HEIR = "0x" + "d0" * 20     # beneficiario
COINBASE = "0x" + "c0" * 20

# ---------------------------------------------------------------- ensamblador

STOP = "00"
POP = "50"
MSTORE = "52"
SSTORE = "55"
REVERT = "fd"
CALL = "f1"
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


def selfdestruct_to(beneficiary):
    """El bytecode minimo de la victima: PUSH20 <benef> SELFDESTRUCT."""
    return cat(push_addr(beneficiary), SELFDESTRUCT)


def call_then(addr, tail, gas="0186a0"):
    """CALL a `addr` sin input ni retorno, y despues `tail`."""
    return cat(
        push_int(0), push_int(0), push_int(0), push_int(0), push_int(0),
        push_addr(addr), push(gas), CALL, POP,
        tail,
    )


def revert_empty():
    return cat(push_int(0), push_int(0), REVERT)


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


RICH = "0x3635c9adc5dea00000"
# Storage NO vacio en la victima: es lo que hace observable la destruccion sin
# depender de la ceguera de normalize() a EIP-161.
VICTIM_STORAGE = {"0x01": "0x2a", "0x02": "0x2b"}


def case(name, comment, pre, forks, to=CALLER, data="0x", value="0x0"):
    # >= 2 forks es necesario pero NO suficiente para discriminar: ver el caso
    # del revert, que corre en dos forks y da identico. La discriminacion se
    # verifica leyendo el post-state, no contando claves.
    assert len(forks) >= 2, f"{name}: un solo fork no compara nada"
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
            "data": [data],
            "gasLimit": ["0x0f4240"],
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


PRE_EXISTING = [
    case(
        "a_pre_existing_contract_dies_whole_before_cancun",
        "La victima existe en el pre-state (NO se crea en esta tx), tiene codigo "
        "y DOS slots de storage, y hace SELFDESTRUCT hacia un heredero. En "
        "Shanghai desaparece entera: storage, codigo, nonce y balance. En Cancun "
        "EIP-6780 la deja viva con su storage intacto y solo le mueve el balance. "
        "El storage es lo que hace la diferencia visible sin depender de la "
        "ceguera de normalize() a EIP-161.",
        {
            SENDER: account(0, RICH),
            VICTIM: account(1, "0x0de0b6b3a7640000", "0x" + selfdestruct_to(HEIR), VICTIM_STORAGE),
        },
        ["Shanghai", "Cancun"],
        to=VICTIM,
    ),
    case(
        "selfdestruct_to_itself_burns_the_balance_before_cancun",
        "beneficiary == addr: no hay a donde mover el saldo. Pre-Cancun la cuenta "
        "muere y el saldo se QUEMA (sale del supply). Desde Cancun no pasa nada: "
        "ni se destruye ni se mueve el balance. Hoy la rama del quemado solo se "
        "alcanza para cuentas creadas en la tx.",
        {
            SENDER: account(0, RICH),
            VICTIM: account(1, "0x0de0b6b3a7640000", "0x" + selfdestruct_to(VICTIM), VICTIM_STORAGE),
        },
        ["Shanghai", "Cancun"],
        to=VICTIM,
    ),
    case(
        "a_pre_existing_contract_with_zero_balance_still_dies_before_cancun",
        "Sin balance que mover, la unica diferencia entre los forks es la "
        "DESTRUCCION en si. Aisla el efecto de estado del efecto de balance: si "
        "alguien implementara 6780 moviendo saldo pero sin borrar la cuenta, este "
        "caso lo caza y el de arriba no.",
        {
            SENDER: account(0, RICH),
            VICTIM: account(1, "0x0", "0x" + selfdestruct_to(HEIR), VICTIM_STORAGE),
        },
        ["Paris", "Cancun"],
        to=VICTIM,
    ),
]

CREATED_IN_TX = [
    case(
        "a_contract_created_in_this_tx_dies_in_every_fork",
        "EL CONTROL que prueba que el gate se CONDICIONO y no se BORRO. Una tx de "
        "creacion cuyo initcode hace SELFDESTRUCT: la cuenta se crea en esta tx, "
        "asi que muere en TODOS los forks, antes y despues de 6780. Si este caso "
        "empieza a divergir entre forks, el cambio rompio Cancun+ -- y eso, "
        "medido, cuesta 533 casos de EEST.",
        {SENDER: account(0, RICH)},
        # Paris queda AFUERA a proposito, y no por conveniencia: este caso lo
        # destapo. `own_vm::intrinsic_gas` suma el costo por palabra de
        # EIP-3860 SIN gatear por fork, y 3860 es Shanghai+. Con un initcode de
        # 22 bytes (1 palabra) eso son exactamente 2 gas de mas en Paris, que
        # es la divergencia que midio el comparador. Es un bug REAL y ya
        # catalogado, pero es de 2.9b-3b (gating de 3860), no de este slice:
        # meterlo aca le robaria el cambio de seam y su review.
        ["Shanghai", "Cancun", "Prague"],
        to="",
        data="0x" + selfdestruct_to(HEIR),
    ),
]

REVERT = [
    case(
        "a_reverted_selfdestruct_of_a_pre_existing_contract_undoes_the_destruction",
        "NO DISCRIMINA ENTRE FORKS, y se deja igual sabiendolo. La auditoria de "
        "post-state mostro que los dos forks dan el MISMO resultado: en Shanghai "
        "la destruccion ocurre y el revert la deshace; en Cancun nunca ocurre. "
        "Estado final y gas identicos. Su valor es de REGRESION -- que un revert "
        "restaure una cuenta destruida, camino que pre-Cancun no se ejercitaba "
        "nunca -- no de discriminacion; el que discrimina el gate es el par de "
        "abajo, que NO revierte. Decirlo es la leccion de 2.6: [SAME] no es "
        "evidencia y un caso que no prueba lo que dice es peor que no tenerlo. El "
        "checkpoint por frame se prueba sobre una cuenta pre-existente, que es "
        "un camino que hoy no se ejecuta nunca antes de Cancun.",
        {
            SENDER: account(0, RICH),
            CALLER: account(1, "0x0", "0x" + call_then(VICTIM, revert_empty())),
            VICTIM: account(1, "0x0de0b6b3a7640000", "0x" + selfdestruct_to(HEIR), VICTIM_STORAGE),
        },
        ["Shanghai", "Cancun"],
        to=CALLER,
    ),
    case(
        "a_selfdestruct_in_a_sub_call_that_succeeds_survives_the_commit",
        "La recíproca del anterior: el caller llama y NO revierte. Pre-Cancun la "
        "victima muere de verdad; desde Cancun sobrevive. Sin este par, un "
        "revert que se tragara todo pasaria el test de arriba por la razon "
        "equivocada.",
        {
            SENDER: account(0, RICH),
            CALLER: account(1, "0x0", "0x" + call_then(VICTIM, cat(push_int(1), push_int(9), SSTORE))),
            VICTIM: account(1, "0x0de0b6b3a7640000", "0x" + selfdestruct_to(HEIR), VICTIM_STORAGE),
        },
        ["Shanghai", "Cancun"],
        to=CALLER,
    ),
]

FILES = {
    "pre-existing.json": PRE_EXISTING,
    "created-in-tx.json": CREATED_IN_TX,
    "revert.json": REVERT,
}


def main():
    out_dir = os.environ.get(
        "FIXTURE_DIR", "cmd/conformance/fixtures/diff/selfdestruct-fork"
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
        runs = sum(len(body["post"]) for _, body in cases)
        total += runs
        print(f"  {path}: {len(cases)} casos, {runs} corridas")
    print(f"total: {total} corridas")


if __name__ == "__main__":
    main()
