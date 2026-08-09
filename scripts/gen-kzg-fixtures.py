#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/kzg/*.json (slice 2.8e, task 016).

Mismo criterio que gen-blake2f-fixtures.py: los fixtures estan versionados
y este script existe para que sean REPRODUCIBLES. El oraculo es revm, no
este archivo (los campos `hash`/`logs` van en cero a proposito; ver
cmd/conformance/fixtures/diff/README.md).

A diferencia de 2.8d, SI hay un vector de oraculo con expected conocido:
`kzg_point_evaluation.rs::tests::basic_test` de revm-precompile (datos
reales de `c-kzg-4844` upstream) -- transcrito acá, `versioned_hash`
calculado con hashlib.sha256 (verificado en el attempt_log de 016 it.1).
Los casos de EXITO reusan ese UNICO vector real (KZG no tiene una funcion
de "generar una prueba nueva" disponible en Python puro sin una libreria de
polynomial commitments completa) -- lo que varia entre fixtures es la
envoltura (value, gas forwarded, largo del input), no el punto evaluado.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/kzg python3 scripts/gen-kzg-fixtures.py
"""
import hashlib
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20

KZG = "0x" + "00" * 19 + "0a"

# ---------------------------------------------------------------- ensamblador

ADD = "01"
MLOAD = "51"
MSTORE = "52"
SSTORE = "55"
STOP = "00"
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


# Offset de retorno lejos de cualquier input real de este set (el mas largo
# son 193 bytes, el caso de largo invalido de sobra).
RET_WORD_OFFSET = 300


def precompile_call_code(raw: bytes, ret_len: int, arg_length=None, gas=51_000, value=0, opcode=CALL):
    """Escribe `raw` en memoria [0, len(raw)), llama a KZG con `arg_length`
    bytes de input (por defecto `len(raw)` -- NUNCA se right-padea a
    proposito, KZG exige el largo EXACTO de 192), guarda status+1 en slot 1
    y hasta 64 bytes del output en los slots 2-3 (32 bytes por slot)."""
    if arg_length is None:
        arg_length = len(raw)
    ret_offset = RET_WORD_OFFSET
    code = cat(
        mstore_bytes(0, raw),
        call_precompile(KZG, gas, arg_offset=0, arg_length=arg_length, ret_offset=ret_offset, ret_length=ret_len, value=value, opcode=opcode),
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


def case(name, comment, pre, to=MAIN, data="0x", value="0x0", gas_limit="0x30d40", fork="Prague"):
    # gas_limit por defecto 0x30d40 = 200_000: de sobra por encima de
    # cualquier gas forwarded al CALL (max 51_000) para que el caller
    # SIEMPRE tenga margen para la SSTORE posterior, en exito Y en fallo
    # (la leccion de 2.8c/2.8d -- un "gas de sobra" que en realidad es casi
    # todo el presupuesto de la tx hace haltear la tx ENTERA al fallar el
    # precompile, en vez de fallar limpio con la SSTORE registrando el 0).
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


# --------------------------------------------------- vector real (c-kzg-4844)
# Transcrito de revm-precompile-34.0.0/src/kzg_point_evaluation.rs::tests::
# basic_test (datos de
# https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_4_4/data.yaml)
# -- ver attempt_log de 016 it.1.
COMMITMENT = bytes.fromhex(
    "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7"
)
Z = bytes.fromhex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
Y = bytes.fromhex("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9")
PROOF = bytes.fromhex(
    "a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c"
)


def versioned_hash_of(commitment: bytes) -> bytes:
    h = bytearray(hashlib.sha256(commitment).digest())
    h[0] = 0x01
    return bytes(h)


VERSIONED_HASH = versioned_hash_of(COMMITMENT)
assert len(COMMITMENT) == 48 and len(PROOF) == 48 and len(Z) == 32 and len(Y) == 32


def kzg_input(versioned_hash=VERSIONED_HASH, z=Z, y=Y, commitment=COMMITMENT, proof=PROOF) -> bytes:
    raw = versioned_hash + z + y + commitment + proof
    assert len(raw) == 192, len(raw)
    return raw


EXPECTED_OUTPUT = bytes.fromhex(
    "000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
)
assert len(EXPECTED_OUTPUT) == 64

VALID_INPUT = kzg_input()

# --- 1. exito / gas -----------------------------------------------------------
add(
    "kzg.json",
    case(
        "kzg_point_evaluation_with_the_reference_vector_succeeds",
        "Vector real de c-kzg-4844 (basic_test de revm-precompile), gas "
        "EXACTO 50_000 -- output CONSTANTE (FIELD_ELEMENTS_PER_BLOB ++ "
        "BLS_MODULUS), no derivado del computo (task 016 S6).",
        base_pre(precompile_call_code(VALID_INPUT, ret_len=64, gas=50_000)),
    ),
    case(
        "kzg_point_evaluation_out_of_gas_by_one_is_an_err",
        "49_999 (1 menos que el costo FLAT de 50_000): falla, SIN value "
        "(mismo criterio que 013-015 -- el stipend de 2300 no alcanzaria "
        "de cualquier forma, 49_999 >> 2300).",
        base_pre(precompile_call_code(VALID_INPUT, ret_len=0, gas=49_999)),
    ),
)

# --- 2. formato de input invalido -------------------------------------------
add(
    "invalid-format.json",
    case(
        "kzg_point_evaluation_with_a_length_of_191_fails",
        "191 bytes (1 de menos que el largo EXACTO de 192 que exige "
        "EIP-4844, a diferencia de ECRECOVER/MODEXP/BN254 que toleran un "
        "input mas corto via right-pad -- mismo criterio estricto que "
        "BLAKE2F en 2.8d).",
        base_pre(precompile_call_code(VALID_INPUT, ret_len=0, arg_length=191, gas=51_000)),
    ),
    case(
        "kzg_point_evaluation_with_a_length_of_193_fails",
        "193 bytes (1 de mas).",
        base_pre(precompile_call_code(VALID_INPUT + b"\x00", ret_len=0, arg_length=193, gas=51_000)),
    ),
    case(
        "kzg_point_evaluation_with_a_versioned_hash_mismatch_fails",
        "versioned_hash mutado (segundo byte, el primero se deja como "
        "0x01 -- version valida -- pero el hash ya no coincide con el "
        "commitment real): falla ANTES del pairing (task 016 S4).",
        base_pre(
            precompile_call_code(
                kzg_input(versioned_hash=bytes(VERSIONED_HASH[:1]) + bytes([VERSIONED_HASH[1] ^ 0xFF]) + VERSIONED_HASH[2:]),
                ret_len=0,
                gas=51_000,
            )
        ),
    ),
    case(
        "kzg_point_evaluation_with_a_commitment_that_is_not_a_valid_g1_point_fails",
        "commitment reemplazado por 48 bytes que no describen ningun punto "
        "real de la curva (versioned_hash recalculado para que coincida "
        "-- este caso falla en el PARSEO del punto, no en el pairing, "
        "task 016 S7).",
        base_pre(
            precompile_call_code(
                kzg_input(
                    versioned_hash=versioned_hash_of(b"\xff" * 48),
                    commitment=b"\xff" * 48,
                ),
                ret_len=0,
                gas=51_000,
            )
        ),
    ),
    case(
        "kzg_point_evaluation_with_a_non_canonical_z_fails",
        "z = 2*BLS_MODULUS - 1 (byte-representable en 32 bytes -- p tiene "
        "255 bits, 2p-1 cabe justo en 256 -- pero FUERA del rango "
        "canonico [0,p); construccion DELIBERADA: (2p-1) mod p == p-1, "
        "exactamente el z REAL del vector -- si el chequeo de canonicidad "
        "estuviera roto, la reduccion daria el z correcto y el pairing "
        "verificaria, un test que no discrimina nada; z=BLS_MODULUS a "
        "secas reduce a 0, no al z real, y fallaria en el pairing SIN que "
        "el chequeo de canonicidad hiciera nada -- ver attempt_log 016 "
        "it.3, mutation testing). A diferencia de BN254 (task 014 S3), "
        "donde el escalar de MUL NO necesita ser canonico.",
        base_pre(
            precompile_call_code(
                kzg_input(z=bytes.fromhex("e7db4ea6533afa906673b0101343b00aa77b4805fffcb7fdfffffffe00000001")),
                ret_len=0,
                gas=51_000,
            )
        ),
    ),
    case(
        "kzg_point_evaluation_with_a_proof_that_does_not_verify_fails",
        "z mutado (primer byte decrementado en 1, 0x73->0x72 -- CANONICO "
        "por construccion, un byte lider MENOR con el mismo largo es "
        "SIEMPRE un valor estrictamente menor, nunca cruza el modulo; el "
        "vector real usa z = BLS_MODULUS - 1, el maximo canonico, asi que "
        "mutar el ULTIMO byte cruzaria el modulo y dispararia el chequeo "
        "de canonicidad en vez del pairing check -- no lo que este caso "
        "quiere ejercitar): el commitment/proof/y siguen siendo puntos "
        "validos, pero ya no verifican para este z -- falla en el PAIRING, "
        "no en el parseo (distingue esta clase de la de arriba, task 016 "
        "S7).",
        base_pre(
            precompile_call_code(
                kzg_input(z=bytes([Z[0] - 1]) + Z[1:]),
                ret_len=0,
                gas=51_000,
            )
        ),
    ),
)

# --- 3. value + STATICCALL ----------------------------------------------------
add(
    "call-kinds.json",
    case(
        "kzg_point_evaluation_with_value_moves_the_balance_and_still_computes",
        "CALL con value>0 y el vector real (gas 50_000, de sobra cubierto "
        "por el gas forwarded): el balance se mueve Y el output es el "
        "constante esperado.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x" + precompile_call_code(VALID_INPUT, ret_len=64, gas=50_000, value=1),
            ),
        },
    ),
    case(
        "kzg_point_evaluation_with_value_reverts_on_any_failure_not_just_oog",
        "Largo invalido (191 bytes) con value>0: el CALL falla SIEMPRE sin "
        "importar el gas (inmune al stipend de 2300 -- mismo criterio que "
        "los casos analogos de 2.8c/2.8d) y el value transferido se "
        "REVIERTE.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + precompile_call_code(VALID_INPUT, ret_len=0, arg_length=191, gas=51_000, value=1),
            ),
        },
    ),
    case(
        "staticcall_to_kzg_point_evaluation_succeeds_like_a_normal_call",
        "STATICCALL al vector real: no hay nada que gatear (KZG no muta "
        "estado), pero confirma que no rompe nada -- mismo resultado que "
        "el caso CALL.",
        base_pre(precompile_call_code(VALID_INPUT, ret_len=64, gas=50_000, opcode=STATICCALL)),
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
