#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/precompile-basic/*.json (slice 2.8a,
task 012).

Mismo criterio que gen-create-fixtures.py/gen-set-code-fixtures.py: los
fixtures estan versionados y este script existe para que sean REPRODUCIBLES.
El oraculo es revm, no este archivo (los campos `hash`/`logs` van en cero a
proposito; ver cmd/conformance/fixtures/diff/README.md).

El vector de ECRECOVER (msg/r/s/v/direccion recuperada, y su contraparte de
"s" alto) es una firma real de secp256k1, generada y auto-verificada con
`k256::ecdsa::SigningKey` en un generador standalone (offline, fuera de este
repo `no_std` -- firmar no es algo que el motor necesite, solo recuperar). Los
MISMOS bytes viven en `crates/evm/src/precompiles.rs::tests` -- ver el
attempt_log de 012 it.1 para el detalle de como se derivaron y por que un
"s" alto NO se rechaza (corrige la Spec del task-file).

    FIXTURE_DIR=cmd/conformance/fixtures/diff/precompile-basic python3 scripts/gen-precompile-basic-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20  # contrato que llama (el "caller")
COINBASE = "0x" + "c0" * 20
FRESH_EOA = "0x" + "d0" * 20  # nunca tocada en el pre-state ni la AL

ECRECOVER = "0x" + "00" * 19 + "01"
SHA256 = "0x" + "00" * 19 + "02"
RIPEMD160 = "0x" + "00" * 19 + "03"
IDENTITY = "0x" + "00" * 19 + "04"

# ---------------------------------------------------------------- ensamblador

STOP = "00"
ADD = "01"
POP = "50"
MLOAD = "51"
MSTORE = "52"
SSTORE = "55"
CALL = "f1"
STATICCALL = "fa"
BALANCE = "31"


def push(value_hex):
    n = len(value_hex) // 2
    assert 1 <= n <= 32, value_hex
    return "%02x" % (0x60 + n - 1) + value_hex


def push_int(value, width=1):
    return push(("%%0%dx" % (width * 2)) % value)


def push_addr(addr):
    return push(addr[2:])


def cat(*parts):
    return "".join(parts)


def mstore_word(offset, word_hex_64chars):
    """Escribe una palabra de 32 bytes en `offset` (asume `len==64` hex)."""
    assert len(word_hex_64chars) == 64, word_hex_64chars
    return cat(push(word_hex_64chars), push_int(offset), MSTORE)


def store_top_plus_one(slot):
    """Guarda `tope + 1` en `slot` (un 0 no existe en el trie, asi que sin el
    +1 un slot ausente no distinguiria "fallo" de "no corrio")."""
    return cat(push_int(1), ADD, push_int(slot), SSTORE)


def store_top(slot):
    """Guarda el tope tal cual (para valores que nunca son cero: direcciones
    recuperadas, hashes)."""
    return cat(push_int(slot), SSTORE)


def call_precompile(
    addr, gas_hex, arg_offset=0, arg_length=0, ret_offset=0, ret_length=0, value=0, opcode=CALL
):
    """CALL/STATICCALL a un precompile. Deja el status en el stack."""
    args = [
        push_int(ret_length),
        push_int(ret_offset),
        push_int(arg_length),
        push_int(arg_offset),
    ]
    if opcode == CALL:
        args.append(push_int(value))
    return cat(*args, push_addr(addr), push(gas_hex), opcode)


CALL_GAS = "030d40"  # 200000 -- de sobra para cualquiera de los 4 (ECRECOVER cuesta 3000 flat)
STARVED_GAS = "01f4"  # 500 -- por debajo de los 3000 flat de ECRECOVER

# ---------------------------------------------------------- vector real de ECRECOVER
# Generado con k256::ecdsa::SigningKey sobre una clave privada fija
# (RFC6979 determinista) y auto-verificado round-trip firmar->recuperar. Ver
# attempt_log de 012 it.1.
ECR_MSG = "c84960bf5f880448ea5fa2d25a2095f677fb4b11e026748e205594f9e77a4a79"
ECR_R = "46072087b50b111047dbdd86dc58a4ac8d597693950eb2e2d37d733107b55dfd"
ECR_S_LOW = "65c753fef8762f3662275adea6691bd2c623af4ebd14447ea503aa1af5b9bfe6"
ECR_V_LOW = 27
# n - ECR_S_LOW (orden de secp256k1), con v de paridad flipeada: la MISMA
# firma bajo malleability (BIP-62) -- normaliza al vector de arriba.
ECR_S_HIGH = "9a38ac010789d0c99dd8a5215996e42bf48b2d97f2345bbd1aceb471da7c815b"
ECR_V_HIGH = 28
ECR_ADDR = "19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"  # direccion recuperada esperada


def v_word(v):
    return "00" * 31 + ("%02x" % v)


def ecrecover_call_code(v, r, s, gas_hex=CALL_GAS, msg=ECR_MSG):
    """Escribe (msg,v,r,s) en memoria [0,128), llama a ECRECOVER, guarda
    status+1 en slot 1 y la palabra devuelta (0 si vacia) en slot 2."""
    return cat(
        mstore_word(0, msg),
        mstore_word(32, v_word(v)),
        mstore_word(64, r),
        mstore_word(96, s),
        call_precompile(ECRECOVER, gas_hex, arg_offset=0, arg_length=128, ret_offset=128, ret_length=32),
        store_top_plus_one(1),
        push_int(128),
        MLOAD,
        store_top(2),
        STOP,
    )


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


RICH = "0x3635c9adc5dea00000"


def case(
    name,
    comment,
    pre,
    to=MAIN,
    data="0x",
    value="0x0",
    gas_limit="0xf4240",
    fork="Prague",
):
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


# --- 1. ECRECOVER ------------------------------------------------------------
add(
    "ecrecover.json",
    case(
        "ecrecover_with_a_valid_signature_recovers_the_signer_address",
        "Firma real de secp256k1 (ver attempt_log it.1): el CALL a 0x01 "
        "tiene exito y el slot 2 queda con la direccion recuperada, "
        "left-padded a 32 bytes.",
        base_pre(ecrecover_call_code(ECR_V_LOW, ECR_R, ECR_S_LOW)),
    ),
    case(
        "ecrecover_with_a_high_s_signature_recovers_the_same_address_via_malleability",
        "CORRECCION sobre la Spec del task-file (verificada contra "
        "secp256k1/k256.rs de revm): un 's' alto NO se rechaza. "
        "`normalize_s` lo reduce a n-s y flipea `v` -- recupera la MISMA "
        "direccion que el caso anterior. La EIP-2 de low-s es una regla de "
        "validacion de TX, no del precompile.",
        base_pre(ecrecover_call_code(ECR_V_HIGH, ECR_R, ECR_S_HIGH)),
    ),
    case(
        "ecrecover_with_an_invalid_v_succeeds_with_empty_output",
        "v=5 (ni 27 ni 28): el CALL es EXITOSO (status 1) pero el output es "
        "VACIO -- el slot 2 queda en 0, distinto de cualquier direccion real "
        "recuperada. El gas cobrado es el flat de 3000 igual (verificado por "
        "el diferencial, no a mano).",
        base_pre(ecrecover_call_code(5, ECR_R, ECR_S_LOW)),
    ),
    case(
        "ecrecover_out_of_gas_reverts_the_value_transfer",
        "CALL con value>0 pero gas reenviado (500) por debajo del flat de "
        "3000: el precompile entero es un OOG normal de sub-frame -- status "
        "0 y el value transferido se REVIERTE (el balance de MAIN hacia "
        "ECRECOVER no debe moverse).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + cat(
                    call_precompile(ECRECOVER, STARVED_GAS, value=1),
                    store_top_plus_one(1),
                    STOP,
                ),
            ),
        },
    ),
)

# --- 2. SHA256 / RIPEMD160 ----------------------------------------------------
add(
    "hash.json",
    case(
        "sha256_of_empty_input_matches_the_known_digest",
        "CALL a 0x02 con input vacio: cuesta el flat de 60 (0 palabras) y "
        "el output es sha256(''), guardado en el slot 2.",
        base_pre(
            cat(
                call_precompile(SHA256, CALL_GAS, arg_offset=0, arg_length=0, ret_offset=0, ret_length=32),
                store_top_plus_one(1),
                push_int(0),
                MLOAD,
                store_top(2),
                STOP,
            )
        ),
    ),
    case(
        "sha256_of_33_bytes_crosses_the_32_byte_word_boundary",
        "Input de 33 bytes (una palabra de 32 escrita + 1 byte de expansion "
        "de memoria en cero): ceil(33/32)=2 palabras, ejercita el termino "
        "12*ceil(len/32) del costo lineal.",
        base_pre(
            cat(
                mstore_word(0, "11" * 32),
                call_precompile(SHA256, CALL_GAS, arg_offset=0, arg_length=33, ret_offset=64, ret_length=32),
                store_top_plus_one(1),
                push_int(64),
                MLOAD,
                store_top(2),
                STOP,
            )
        ),
    ),
    case(
        "ripemd160_of_empty_input_is_left_padded_to_32_bytes",
        "CALL a 0x03 con input vacio: el digest de 20 bytes queda "
        "left-padded a 32 (12 bytes de cero + el hash) en el slot 2.",
        base_pre(
            cat(
                call_precompile(RIPEMD160, CALL_GAS, arg_offset=0, arg_length=0, ret_offset=0, ret_length=32),
                store_top_plus_one(1),
                push_int(0),
                MLOAD,
                store_top(2),
                STOP,
            )
        ),
    ),
)

# --- 3. IDENTITY --------------------------------------------------------------
add(
    "identity.json",
    case(
        "identity_copies_a_non_trivial_input_byte_for_byte",
        "CALL a 0x04 con un input no-trivial (32 bytes con un patron "
        "reconocible): el output tiene que ser BYTE-A-BYTE el input, no una "
        "transformacion. Se guarda en el slot 2.",
        base_pre(
            cat(
                mstore_word(0, "0123456789abcdef" * 4),
                call_precompile(IDENTITY, CALL_GAS, arg_offset=0, arg_length=32, ret_offset=64, ret_length=32),
                store_top_plus_one(1),
                push_int(64),
                MLOAD,
                store_top(2),
                STOP,
            )
        ),
    ),
)

# --- 4. warm-desde-el-inicio (EIP-2929) --------------------------------------
add(
    "warm.json",
    case(
        "a_precompile_address_is_warm_on_its_very_first_access_in_the_tx",
        "Aisla el warm-desde-el-inicio de prewarm_tx SIN ruido de otros "
        "costos de gas: BALANCE(IDENTITY) -- nunca antes tocada en esta tx "
        "-- comparado directamente contra BALANCE(FRESH_EOA), una direccion "
        "genuinamente fria. Si las precompiles NO arrancaran warm, las dos "
        "costarian 2600 (cold); si arrancan warm, la primera cuesta 100 y "
        "la segunda 2600 -- el gas total de la tx distingue los dos casos, "
        "y el diferencial vs revm es el juez.",
        base_pre(
            cat(
                push_addr(IDENTITY),
                BALANCE,
                POP,
                push_addr(FRESH_EOA),
                BALANCE,
                POP,
                STOP,
            )
        ),
    ),
)

# --- 5. value + STATICCALL ----------------------------------------------------
add(
    "call-kinds.json",
    case(
        "a_call_with_value_to_a_precompile_moves_the_balance_without_running_bytecode",
        "CALL con value>0 a IDENTITY: el balance se mueve igual que "
        "cualquier CALL exitoso, sin que haya bytecode que corra -- "
        "verificado por el diferencial en el post-state completo (balance "
        "de MAIN e IDENTITY).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + cat(
                    call_precompile(IDENTITY, CALL_GAS, arg_offset=0, arg_length=0, ret_offset=0, ret_length=0, value=1),
                    store_top_plus_one(1),
                    STOP,
                ),
            ),
        },
    ),
    case(
        "staticcall_to_a_precompile_succeeds_like_a_normal_call",
        "STATICCALL a SHA256: no hay nada que gatear (los precompiles no "
        "escriben estado), pero confirma que no rompe nada -- status exito "
        "y el mismo digest de sha256('') que el caso CALL.",
        base_pre(
            cat(
                call_precompile(
                    SHA256, CALL_GAS, arg_offset=0, arg_length=0, ret_offset=0, ret_length=32, opcode=STATICCALL
                ),
                store_top_plus_one(1),
                push_int(0),
                MLOAD,
                store_top(2),
                STOP,
            )
        ),
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
