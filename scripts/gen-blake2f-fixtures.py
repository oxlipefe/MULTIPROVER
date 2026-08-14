#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/blake2f/*.json.

Mismo criterio que gen-bn254-fixtures.py: los fixtures estan versionados y
este script existe para que sean REPRODUCIBLES. El oraculo es revm, no
este archivo (los campos `hash`/`logs` van en cero a proposito; ver
cmd/conformance/fixtures/diff/README.md).

A diferencia de 012-014, revm-precompile no trae un vector de test con
expected conocido reusable (blake2.rs::tests::perfblake2 es un benchmark
sin aserciones). El vector "abc" que usa este script se generó y verificó
independientemente contra hashlib.blake2b de Python -- ver el
de 015 it.1 (el h0 resultante coincide, de hecho, con el que ya usa el
benchmark de revm).

    FIXTURE_DIR=cmd/conformance/fixtures/diff/blake2f python3 scripts/gen-blake2f-fixtures.py
"""
import json
import os
import struct

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20

BLAKE2F = "0x" + "00" * 19 + "09"

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
# largo son 213 bytes).
RET_WORD_OFFSET = 300


def precompile_call_code(raw: bytes, ret_len: int, arg_length=None, gas=1_000_000, value=0, opcode=CALL):
    """Escribe `raw` en memoria [0, len(raw)), llama a BLAKE2F con
    `arg_length` bytes de input (por defecto `len(raw)` -- NUNCA se
    right-padea a proposito, BLAKE2F exige el largo EXACTO de 213), guarda
    status+1 en slot 1 y hasta 64 bytes del output en los slots 2-5 (8
    bytes por slot, uno por palabra de h -- no left-padded, cada slot es
    una palabra de 8 bytes escrita en los ULTIMOS 8 bytes de un slot de 32
    para que MLOAD la lea limpia)."""
    if arg_length is None:
        arg_length = len(raw)
    ret_offset = RET_WORD_OFFSET
    code = cat(
        mstore_bytes(0, raw),
        call_precompile(BLAKE2F, gas, arg_offset=0, arg_length=arg_length, ret_offset=ret_offset, ret_length=ret_len, value=value, opcode=opcode),
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


# --------------------------------------------------------- BLAKE2b (Python)

IV = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]
MASK = (1 << 64) - 1


def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


def g(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & MASK
    v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & MASK
    v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & MASK
    v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK
    v[b] = rotr(v[b] ^ v[c], 63)


def compress(rounds, h, m, t, f):
    v = h[:] + IV[:]
    v[12] ^= t[0]
    v[13] ^= t[1]
    if f:
        v[14] ^= MASK
    for i in range(rounds):
        s = SIGMA[i % 10]
        g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]
    return h


def blake2f_input(rounds, h, m, t0, t1, f):
    b = struct.pack(">I", rounds)
    b += b"".join(struct.pack("<Q", w) for w in h)
    b += b"".join(struct.pack("<Q", w) for w in m)
    b += struct.pack("<Q", t0)
    b += struct.pack("<Q", t1)
    b += bytes([1 if f else 0])
    assert len(b) == 213
    return b


# Vector "abc" -- inicializacion estandar de BLAKE2b-512 para un mensaje de
# un solo bloque, verificado contra hashlib.blake2b en el de
# 015 it.1 (el h0 coincide con el que ya usa revm-precompile en su propio
# benchmark).
H0_ABC = IV[:]
H0_ABC[0] ^= 0x01010040
MSG_ABC = list(struct.unpack("<16Q", b"abc" + b"\x00" * 125))
ABC_INPUT = blake2f_input(12, H0_ABC, MSG_ABC, 3, 0, True)

# --- 1. eito / gas -----------------------------------------------------------
add(
    "blake2f.json",
    case(
        "blake2f_matches_the_abc_vector",
        "F(h0,'abc' padded,t=(3,0),f=true,rounds=12) con h0 = IV XOR "
        "param_block es la inicializacion estandar de BLAKE2b-512 para "
        "un mensaje de un solo bloque -- verificado contra hashlib.blake2b "
        "en Python. Gas = 12 (rounds*1).",
        base_pre(precompile_call_code(ABC_INPUT, ret_len=64, gas=12)),
    ),
    case(
        "blake2f_zero_rounds_costs_zero_gas",
        "rounds=0 cuesta 0 de gas y tiene exito -- el unico precompile "
        "sin piso ni costo flat.",
        base_pre(precompile_call_code(blake2f_input(0, IV, [0] * 16, 0, 0, False), ret_len=0, gas=0)),
    ),
    case(
        "blake2f_out_of_gas_is_an_err",
        "rounds=10 con 9 de gas (1 menos que el costo real de 10): falla, "
        "SIN value (mismo criterio que 013/014 -- el stipend de 2300 "
        "rescataria cualquier vector de rounds chico).",
        base_pre(precompile_call_code(blake2f_input(10, IV, [0] * 16, 0, 0, False), ret_len=0, gas=9)),
    ),
)

# --- 2. formato de input invalido -------------------------------------------
add(
    "invalid-format.json",
    case(
        "blake2f_with_a_length_of_212_fails",
        "212 bytes (1 de menos que el largo EXACTO de 213 que exige "
        "EIP-152, a diferencia de todos los precompiles anteriores que "
        "toleran un input mas corto via right-pad).",
        base_pre(precompile_call_code(ABC_INPUT, ret_len=0, arg_length=212, gas=1_000)),
    ),
    case(
        "blake2f_with_a_length_of_214_fails",
        "214 bytes (1 de mas).",
        base_pre(precompile_call_code(ABC_INPUT + b"\x00", ret_len=0, arg_length=214, gas=1_000)),
    ),
    case(
        "blake2f_with_an_invalid_final_block_flag_fails",
        "f=2 (ni 0 ni 1): fail-closed explicito.",
        base_pre(
            precompile_call_code(
                blake2f_input(0, IV, [0] * 16, 0, 0, False)[:-1] + bytes([2]),
                ret_len=0,
                gas=1_000,
            )
        ),
    ),
)

# --- 3. value + STATICCALL ----------------------------------------------------
SMALL_VECTOR = blake2f_input(1, IV, [0] * 16, 0, 0, False)  # 1 de gas

add(
    "call-kinds.json",
    case(
        "blake2f_with_value_moves_the_balance_and_still_computes",
        "CALL con value>0 y rounds=1 (1 de gas, de sobra cubierto por "
        "cualquier gas forwarded): el balance se mueve Y el output es "
        "correcto.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x" + precompile_call_code(SMALL_VECTOR, ret_len=64, gas=1, value=1),
            ),
        },
    ),
    case(
        "blake2f_with_value_reverts_on_any_failure_not_just_oog",
        "Largo invalido (212 bytes) con value>0: el CALL falla "
        "SIEMPRE sin importar el gas (inmune al stipend de 2300 -- "
        "mismo criterio que el caso analogo de ADD ) y "
        "el value transferido se REVIERTE.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + precompile_call_code(ABC_INPUT, ret_len=0, arg_length=212, gas=1_000, value=1),
            ),
        },
    ),
    case(
        "staticcall_to_blake2f_succeeds_like_a_normal_call",
        "STATICCALL a BLAKE2F: no hay nada que gatear, pero confirma que "
        "no rompe nada -- mismo resultado que el caso CALL.",
        base_pre(precompile_call_code(ABC_INPUT, ret_len=64, gas=12, opcode=STATICCALL)),
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
