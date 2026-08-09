#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/bn254/*.json (slice 2.8c, task 014).

Mismo criterio que gen-modexp-fixtures.py: los fixtures estan versionados
y este script existe para que sean REPRODUCIBLES. El oraculo es revm, no
este archivo (los campos `hash`/`logs` van en cero a proposito; ver
cmd/conformance/fixtures/diff/README.md).

Los vectores de ADD/MUL/PAIRING son los MISMOS que trae
revm-precompile-34.0.0/src/bn254.rs::tests -- ver el attempt_log de 014
it.1.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/bn254 python3 scripts/gen-bn254-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20

BN254_ADD = "0x" + "00" * 19 + "06"
BN254_MUL = "0x" + "00" * 19 + "07"
BN254_PAIRING = "0x" + "00" * 19 + "08"

# ---------------------------------------------------------------- ensamblador

STOP = "00"
ADD = "01"
MLOAD = "51"
MSTORE = "52"
SSTORE = "55"
CALL = "f1"
STATICCALL = "fa"


def push(value_hex):
    n = len(value_hex) // 2
    assert 1 <= n <= 32, value_hex
    return "%02x" % (0x60 + n - 1) + value_hex


def push_int(value, width=1):
    return push(("%%0%dx" % (width * 2)) % value)


def push_dyn(value):
    """`push_int` con el ancho MINIMO que hace falta para `value` (a
    diferencia de `push_int(value, 1)`, que corrompe el bytecode en
    silencio si `value > 255` -- ver PAIRING de 2 pares, 384 bytes de
    input, y `RET_WORD_OFFSET=1200`, ambos > 255)."""
    if value == 0:
        return push_int(0, 1)
    width = (value.bit_length() + 7) // 8
    return push_int(value, width)


def push_addr(addr):
    return push(addr[2:])


def cat(*parts):
    return "".join(parts)


def mstore_word(offset, word_hex_64chars):
    assert len(word_hex_64chars) == 64, word_hex_64chars
    # push_dyn, NO push_int(offset) (width=1 fijo): un input de mas de 8
    # palabras (256 bytes -- el vector de PAIRING de 2 pares tiene 384)
    # necesita un offset >255, que push_int(offset, 1) corrompe en
    # silencio (mismo bug de largo-impar que gas_hex, pero en el offset).
    return cat(push(word_hex_64chars), push_dyn(offset), MSTORE)


def store_top_plus_one(slot):
    return cat(push_int(1), ADD, push_int(slot), SSTORE)


def store_top(slot):
    return cat(push_int(slot), SSTORE)


def gas_hex(n):
    h = "%x" % n
    return h if len(h) % 2 == 0 else "0" + h


def call_precompile(addr, gas, arg_offset, arg_length, ret_offset, ret_length, value=0, opcode=CALL):
    args = [
        push_dyn(ret_length),
        push_dyn(ret_offset),
        push_dyn(arg_length),
        push_dyn(arg_offset),
    ]
    if opcode == CALL:
        args.append(push_dyn(value))
    return cat(*args, push_addr(addr), push(gas_hex(gas)), opcode)


def mstore_bytes(offset, raw: bytes):
    ops = []
    i = 0
    while i < len(raw):
        chunk = raw[i : i + 32]
        word = chunk + b"\x00" * (32 - len(chunk))
        ops.append(mstore_word(offset + i, word.hex()))
        i += 32
    return cat(*ops)


# Offset de retorno bien lejos de cualquier input real de este set (el mas
# largo son 6*192=1152 bytes, la pairing de 6 pares).
RET_WORD_OFFSET = 1200


def precompile_call_code(addr, raw: bytes, ret_len: int, arg_length=None, gas=1_000_000, value=0, opcode=CALL):
    """Escribe `raw` en memoria [0, len(raw)), llama al precompile `addr`
    con `arg_length` bytes de input (por defecto `len(raw)`), guarda
    status+1 en slot 1 y hasta 32 bytes del output en slot 2 (si
    `ret_len < 32`, left-padded -- mismo convenio que 012/013; si
    `ret_len == 64`, el output completo de un G1 se guarda en los slots
    2 y 3, x e y por separado)."""
    if arg_length is None:
        arg_length = len(raw)
    ret_offset = RET_WORD_OFFSET
    code = cat(
        mstore_bytes(0, raw),
        call_precompile(addr, gas, arg_offset=0, arg_length=arg_length, ret_offset=ret_offset, ret_length=ret_len, value=value, opcode=opcode),
        store_top_plus_one(1),
    )
    if ret_len == 64:
        code += cat(
            push_int(ret_offset, width=2),
            MLOAD,
            store_top(2),
            push_int(ret_offset + 32, width=2),
            MLOAD,
            store_top(3),
        )
    elif ret_len > 0:
        code += cat(
            push_int(ret_offset, width=2),
            MLOAD,
            store_top(2),
        )
    code += STOP
    return code


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


RICH = "0x3635c9adc5dea00000"


def case(name, comment, pre, to=MAIN, data="0x", value="0x0", gas_limit="0xf4240", fork="Prague"):
    tx = {
        "sender": SENDER,
        "to": to,
        "nonce": "0x00",
        "gasPrice": "0x0c",
        "data": [data],
        "gasLimit": [gas_limit],
        "value": [value],
    }
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
        "transaction": tx,
        "post": {
            fork: [
                {
                    "indexes": {"data": 0, "gas": 0, "value": 0},
                    "hash": "0x" + "00" * 32,
                    "logs": "0x" + "00" * 32,
                }
            ]
        },
    }


FILES = {}


def add(filename, *cases):
    FILES.setdefault(filename, {}).update(dict(cases))


def base_pre(code):
    return {
        SENDER: account(0, RICH),
        MAIN: account(1, "0x0", "0x" + code),
    }


# --- vectores reales de revm-precompile-34.0.0/src/bn254.rs::tests --------

ADD_INPUT = bytes.fromhex(
    "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9"
    "063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"
    "07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed"
    "06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7"
)

MUL_INPUT = bytes.fromhex(
    "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7"
    "21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204"
    "00000000000000000000000000000000000000000000000011138ce750fa15c2"
)

PAIR_INPUT_TRUE = bytes.fromhex(
    "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
    "3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
    "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"
    "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"
    "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"
    "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
    "111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c"
    "2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
)

G1_INFINITY_G2_REAL = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"
    "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"
    "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"
    "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
)

ADD_GAS = 150
MUL_GAS = 6_000
PAIR_BASE_GAS = 45_000
PAIR_PER_POINT_GAS = 34_000

# --- 1. ADD -------------------------------------------------------------
add(
    "add.json",
    case(
        "bn254_add_matches_the_revm_test_vector",
        "Vector real de test_bn254_add: P1+P2, gas flat 150.",
        base_pre(precompile_call_code(BN254_ADD, ADD_INPUT, ret_len=64, gas=ADD_GAS)),
    ),
    case(
        "bn254_add_of_two_points_at_infinity_stays_at_infinity",
        "(0,0)+(0,0)=(0,0): el punto al infinito se codifica como 64 ceros.",
        base_pre(precompile_call_code(BN254_ADD, bytes(128), ret_len=64, gas=ADD_GAS)),
    ),
    case(
        "bn254_add_of_a_point_not_on_the_curve_fails",
        "Los 128 bytes en 0x11 no forman un punto en la curva: el CALL "
        "entero falla (status 0), mismo tratamiento que OOG.",
        base_pre(precompile_call_code(BN254_ADD, bytes([0x11]) * 128, ret_len=0, gas=ADD_GAS)),
    ),
    case(
        "bn254_add_out_of_gas_is_an_err",
        "149 de gas (1 menos que el flat de 150), SIN value (el flat de "
        "ADD es tan barato que el stipend de 2300 de un CALL con "
        "value>0 lo rescataria SIEMPRE, sin importar cuan poco gas se "
        "pida explicitamente -- ver el caso de abajo para 'value "
        "revierte', que usa un punto invalido en vez de OOG).",
        base_pre(precompile_call_code(BN254_ADD, bytes(128), ret_len=0, gas=ADD_GAS - 1)),
    ),
    case(
        "bn254_add_with_value_reverts_on_any_failure_not_just_oog",
        "Punto fuera de curva (falla SIEMPRE, sin importar el gas) con "
        "value>0: el CALL falla y el value transferido se REVIERTE -- "
        "el mismo patron de 012/013, pero via una falla del algoritmo "
        "en vez de OOG (que el stipend de 2300 rescataria en un "
        "precompile tan barato como ADD).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x" + precompile_call_code(BN254_ADD, bytes([0x11]) * 128, ret_len=0, gas=ADD_GAS, value=1),
            ),
        },
    ),
)

# --- 2. MUL ---------------------------------------------------------------
add(
    "mul.json",
    case(
        "bn254_mul_matches_the_revm_test_vector",
        "Vector real de test_bn254_mul: P*s, gas flat 6000.",
        base_pre(precompile_call_code(BN254_MUL, MUL_INPUT, ret_len=64, gas=MUL_GAS)),
    ),
    case(
        "bn254_mul_of_the_point_at_infinity_stays_at_infinity",
        "(0,0)*escalar sigue siendo (0,0) para cualquier escalar.",
        base_pre(precompile_call_code(BN254_MUL, bytes(95) + bytes([2]), ret_len=64, gas=MUL_GAS)),
    ),
    case(
        "bn254_mul_of_a_point_not_on_the_curve_fails",
        "Punto fuera de curva: el CALL entero falla.",
        base_pre(precompile_call_code(BN254_MUL, bytes([0x11]) * 64 + bytes(31) + bytes([0x0F]), ret_len=0, gas=MUL_GAS)),
    ),
    case(
        "bn254_mul_out_of_gas_reverts_the_value_transfer",
        "1 de gas con value>0: incluso sumando el stipend de 2300 "
        "(1+2300=2301 < 6000, el flat de MUL) el faltante sigue siendo "
        "real -- a diferencia de ADD, el costo de MUL supera el stipend, "
        "asi que ACA si hace falta el margen (5999 rescataria igual que "
        "en ADD, ver el hallazgo del task 013 sobre este mismo stipend).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x" + precompile_call_code(BN254_MUL, bytes(96), ret_len=0, gas=1, value=1),
            ),
        },
    ),
)

# --- 3. PAIRING -------------------------------------------------------------
add(
    "pairing.json",
    case(
        "bn254_pairing_matches_the_revm_test_vector",
        "Vector real de test_bn254_pair: 2 pares, resultado true. "
        "Ejercita el orden invertido de Fq2 en G2 (sus componentes no "
        "son simetricas).",
        base_pre(precompile_call_code(BN254_PAIRING, PAIR_INPUT_TRUE, ret_len=32, gas=PAIR_BASE_GAS + 2 * PAIR_PER_POINT_GAS)),
    ),
    case(
        "bn254_pairing_of_empty_input_is_true",
        "Input vacio: exito, true -- a diferencia de EIP-2537/BLS12-381 "
        "(2.8f) que rechaza el input vacio.",
        base_pre(precompile_call_code(BN254_PAIRING, b"", ret_len=32, gas=PAIR_BASE_GAS)),
    ),
    case(
        "bn254_pairing_with_a_g1_point_at_infinity_is_skipped_and_stays_true",
        "G1 al infinito + G2 real: el par se saltea, resultado true por "
        "vacuidad.",
        base_pre(precompile_call_code(BN254_PAIRING, G1_INFINITY_G2_REAL, ret_len=32, gas=PAIR_BASE_GAS + PAIR_PER_POINT_GAS)),
    ),
    case(
        "bn254_pairing_of_a_point_not_on_the_curve_fails",
        "192 bytes en 0x11 no forman un par valido: el CALL entero falla.",
        base_pre(precompile_call_code(BN254_PAIRING, bytes([0x11]) * 192, ret_len=0, gas=PAIR_BASE_GAS + PAIR_PER_POINT_GAS)),
    ),
    case(
        "bn254_pairing_with_invalid_length_fails",
        "160 bytes (no multiplo de 192, 0 pares completos): el chequeo de "
        "gas (piso de 45000, 0 pares) pasa con este monto MODESTO -- no "
        "'de sobra', para que el caller conserve gas de sobra despues de "
        "que el precompile falle y se coma el forwarded -- y falla por "
        "longitud, no por gas.",
        base_pre(precompile_call_code(BN254_PAIRING, bytes([0x11]) * 160, ret_len=0, gas=PAIR_BASE_GAS)),
    ),
    case(
        "bn254_pairing_out_of_gas_reverts_the_value_transfer",
        "Solo el piso (45000) de gas para un input de 2 pares (necesita "
        "45000+34000*2=113000) con value>0: el faltante (68000) supera "
        "por lejos el stipend de 2300 -- falla de verdad y el value "
        "transferido se REVIERTE (mismo hallazgo del stipend que 013: un "
        "faltante de 'solo 1 unidad' NO alcanza cuando hay value>0, hace "
        "falta un margen mayor a 2300).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + precompile_call_code(
                    BN254_PAIRING,
                    PAIR_INPUT_TRUE,
                    ret_len=0,
                    gas=PAIR_BASE_GAS,
                    value=1,
                ),
            ),
        },
    ),
)

# --- 4. STATICCALL ------------------------------------------------------------
add(
    "call-kinds.json",
    case(
        "staticcall_to_bn254_add_succeeds_like_a_normal_call",
        "STATICCALL a ADD: no hay nada que gatear, pero confirma que no "
        "rompe nada -- mismo resultado que el caso CALL.",
        base_pre(precompile_call_code(BN254_ADD, ADD_INPUT, ret_len=64, gas=ADD_GAS, opcode=STATICCALL)),
    ),
)


def main():
    target = os.environ.get("FIXTURE_DIR")
    assert target, "FIXTURE_DIR no seteado"
    os.makedirs(target, exist_ok=True)
    for filename, cases in FILES.items():
        path = os.path.join(target, filename)
        with open(path, "w") as fh:
            json.dump(cases, fh, indent=2)
            fh.write("\n")
        print("%-24s %d casos" % (filename, len(cases)))
    print("total: %d casos" % sum(len(c) for c in FILES.values()))


if __name__ == "__main__":
    main()
