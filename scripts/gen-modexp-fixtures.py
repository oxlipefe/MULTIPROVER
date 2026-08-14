#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/modexp/*.json.

Mismo criterio que gen-precompile-basic-fixtures.py: los fixtures estan
versionados y este script existe para que sean REPRODUCIBLES. El oraculo es
revm, no este archivo (los campos `hash`/`logs` van en cero a proposito; ver
cmd/conformance/fixtures/diff/README.md).

El vector "eip198_example_1" (base=3, exponente/modulo de 32 bytes) es el
vector real de EIP-198, el mismo que trae
revm-precompile-34.0.0/src/modexp.rs::tests::TESTS -- ver el de
013 it.1.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/modexp python3 scripts/gen-modexp-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20

MODEXP = "0x" + "00" * 19 + "05"

# ---------------------------------------------------------------- ensamblador

STOP = "00"
ADD = "01"
POP = "50"
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


def push_addr(addr):
    return push(addr[2:])


def cat(*parts):
    return "".join(parts)


def mstore_word(offset, word_hex_64chars):
    assert len(word_hex_64chars) == 64, word_hex_64chars
    return cat(push(word_hex_64chars), push_int(offset), MSTORE)


def store_top_plus_one(slot):
    return cat(push_int(1), ADD, push_int(slot), SSTORE)


def store_top(slot):
    return cat(push_int(slot), SSTORE)


def call_precompile(addr, gas_hex, arg_offset, arg_length, ret_offset, ret_length, value=0, opcode=CALL):
    args = [
        push_int(ret_length),
        push_int(ret_offset),
        push_int(arg_length),
        push_int(arg_offset),
    ]
    if opcode == CALL:
        args.append(push_int(value))
    return cat(*args, push_addr(addr), push(gas_hex), opcode)


CALL_GAS = "030d40"  # 200000 -- de sobra para cualquiera de estos casos


def gas_hex(n):
    """Hex de largo PAR (bytes completos) -- `push()` exige un numero exacto
    de bytes, un largo impar corrompe el byte siguiente en el bytecode."""
    h = "%x" % n
    return h if len(h) % 2 == 0 else "0" + h

# --------------------------------------------------------------- input EIP-198


def be(n, length):
    return n.to_bytes(length, "big")


def header(n):
    return be(n, 32)


def modexp_raw(base: bytes, exp: bytes, modulus: bytes) -> bytes:
    """Input EIP-198 completo: 3 headers de 32 bytes + base + exponente +
    modulo, sin padding adicional (el precompile bajo test es el que debe
    rellenar lo que falte)."""
    return header(len(base)) + header(len(exp)) + header(len(modulus)) + base + exp + modulus


def mstore_bytes(offset, raw: bytes):
    """Escribe `raw` en memoria en palabras de 32 bytes consecutivas (la
    ultima, si `raw` no es multiplo de 32, se completa con cero -- esos
    bytes de relleno NUNCA entran al input real porque `arg_length` en el
    CALL es exactamente `len(raw)`, no un multiplo de 32)."""
    ops = []
    i = 0
    while i < len(raw):
        chunk = raw[i : i + 32]
        word = chunk + b"\x00" * (32 - len(chunk))
        ops.append(mstore_word(offset + i, word.hex()))
        i += 32
    return cat(*ops)


# Offset de retorno bien lejos de cualquier input real de este set (el mas
# largo son ~135 bytes) para que jamas se pisen.
RET_WORD_OFFSET = 200


def modexp_call_code(raw: bytes, mod_len: int, arg_length=None, gas_hex=CALL_GAS, value=0, opcode=CALL):
    """Escribe `raw` en memoria [0, len(raw)), llama a MODEXP con
    `arg_length` bytes de input (por defecto `len(raw)` -- un valor menor
    ejercita el right-pad de un input mas corto que lo declarado en el
    header), guarda status+1 en slot 1 y el output LEFT-PADDED a 32 bytes
    (mismo convenio que RIPEMD160/ECRECOVER) en slot 2.

    `mod_len == 0`: no hay nada que copiar (`ret_length=0`); slot 2 queda en
    el cero con el que arranca la memoria fresca -- indistinguible de "no
    corrio" salvo por slot 1 (mismo patron que ECRECOVER con output vacio,
    ).
    """
    if arg_length is None:
        arg_length = len(raw)
    ret_offset = RET_WORD_OFFSET + (32 - mod_len) if mod_len > 0 else RET_WORD_OFFSET
    return cat(
        mstore_bytes(0, raw),
        call_precompile(
            MODEXP,
            gas_hex,
            arg_offset=0,
            arg_length=arg_length,
            ret_offset=ret_offset,
            ret_length=mod_len,
            value=value,
            opcode=opcode,
        ),
        store_top_plus_one(1),
        push_int(RET_WORD_OFFSET),
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


# --- 1. vector real EIP-198 + casos de la formula de iteration_count -------
EIP198_EXP = bytes.fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")
EIP198_MOD = bytes.fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")

add(
    "eip198.json",
    case(
        "modexp_matches_the_eip198_example_1_vector",
        "Vector real de EIP-198 (revm-precompile::modexp::tests::TESTS): "
        "3^E mod M = 1, con E/M de 32 bytes -- gas=1360 verificado a mano "
        "(words=4, multiplication_complexity=16, iteration_count=255).",
        base_pre(modexp_call_code(modexp_raw(b"\x03", EIP198_EXP, EIP198_MOD), mod_len=32)),
    ),
    case(
        "modexp_with_a_zero_exponent_gives_one_mod_m",
        "exp_len<=32 con exp_highp==0 (exponente cero explicito): "
        "5^0 mod 7 = 1. Ejercita la rama iteration_count=0 -> max(0,1)=1 "
        "de calculate_iteration_count.",
        base_pre(modexp_call_code(modexp_raw(b"\x05", b"\x00", b"\x07"), mod_len=1)),
    ),
    case(
        "modexp_with_a_short_nonzero_exponent_left_pads_exp_highp_correctly",
        "exp_len=4 (1<exp_len<32, a diferencia de los otros casos de este "
        "archivo que caen justo en 1 o en 32) CON base_len=mod_len=32 "
        "(para que multiplication_complexity=16 sea grande y el gas "
        "distinga las dos formas de padding, no solo el piso de 200): "
        "2^10 mod 1000000007 = 1024, gas=200 (mc=16, iteration_count="
        "bit_len(10)-1=3, 16*3/3=16 -- el piso domina). El punto de "
        "mayor riesgo de la Spec (S3): si `exp_highp` quedara "
        "right-padded en vez de left-padded, el gas seria ENORME "
        "(bit_len de un valor ~2^228 en vez de bit_len(10)=4 -> "
        "gas~1210) aunque el RESULTADO del modexp seguiria siendo "
        "correcto (exp_highp solo afecta el gas estimado, no el "
        "exponente real que usa aurora_engine_modexp).",
        base_pre(
            modexp_call_code(
                modexp_raw(
                    (2).to_bytes(32, "big"),
                    (10).to_bytes(4, "big"),
                    (1_000_000_007).to_bytes(32, "big"),
                ),
                mod_len=32,
            )
        ),
    ),
    case(
        "modexp_crosses_into_the_exp_len_over_32_branch",
        "exp_len=33 (>32): cruza a la rama del multiplicador 8 de "
        "calculate_iteration_count. Valor real del exponente = 3 (los "
        "primeros 32 bytes declarados son cero): 2^3 mod 1000000007 = 8.",
        base_pre(
            modexp_call_code(
                modexp_raw(b"\x02", b"\x00" * 32 + b"\x03", (1_000_000_007).to_bytes(4, "big")),
                mod_len=4,
            )
        ),
    ),
)

# --- 2. modulo efectivamente cero (por longitud declarada o por right-pad) -
add(
    "zero-modulus.json",
    case(
        "modexp_with_zero_base_and_zero_modulus_takes_the_success_shortcut",
        "base_len==0 && mod_len==0: atajo de exito inmediato con output "
        "vacio -- slot 2 queda en el cero de memoria "
        "fresca (retLength=0, nada se copia).",
        base_pre(modexp_call_code(modexp_raw(b"", b"\x02", b""), mod_len=0)),
    ),
    case(
        "modexp_with_zero_modulus_and_nonzero_base_is_empty_via_the_normal_path",
        "mod_len==0 con base_len>0: NO es el atajo de arriba -- pasa por "
        "el camino normal y aurora_engine_modexp da el mismo resultado "
        "(modulo cero => output vacio) por otra via.",
        base_pre(modexp_call_code(modexp_raw(b"\x03", b"\x02", b""), mod_len=0)),
    ),
    case(
        "modexp_with_modulus_bytes_missing_from_the_input_is_zero_padded",
        "mod_len declarado = 4 pero CERO bytes reales de modulo en el "
        "input (arg_length excluye la porcion de modulo): right_pad "
        "adentro de modexp() rellena el modulo entero con cero -> mismo "
        "resultado que un modulo explicitamente 0, pero ejercitando el "
        "right-pad de un input mas corto que lo declarado en el header "
        "(distinto de mod_len==0 explicito).",
        base_pre(
            modexp_call_code(
                modexp_raw(b"\x03", b"\x02", b"\x00" * 4),
                mod_len=4,
                arg_length=96 + 1 + 1,  # header + base(1) + exp(1), sin modulo
            )
        ),
    ),
)

# --- 3. gas insuficiente / input hostil en el header ------------------------
EIP198_GAS = 1_360  # costo exacto del vector de eip198.json (verificado a mano)

add(
    "oog-and-hostile-header.json",
    case(
        "modexp_gas_insufficient_by_exactly_one_unit_fails",
        "Mismo vector de eip198.json (gas=1360, verificado a mano y por "
        "el unit test de precompiles.rs) pero con 1359 de gas reenviado, "
        "SIN value (para no confundir el limite exacto con el stipend de "
        "2300 que un CALL con value>0 agrega -- ver el caso de abajo, que "
        "SI usa value pero con un faltante mucho mayor a 2300): el CALL "
        "entero falla como OOG normal de sub-frame, status 0.",
        base_pre(
            modexp_call_code(
                modexp_raw(b"\x03", EIP198_EXP, EIP198_MOD),
                mod_len=32,
                gas_hex=gas_hex(EIP198_GAS - 1),
            )
        ),
    ),
    case(
        "modexp_out_of_gas_with_value_reverts_the_value_transfer",
        "Vector DEDICADO mas caro que eip198.json a proposito: el vector "
        "de 1360 de gas es MAS BARATO que el stipend de 2300 que un CALL "
        "con value>0 agrega -- CUALQUIER gas explicito, por mas chico que "
        "sea, alcanzaria igual (2300 solo ya cubre 1360). Este vector "
        "(base_len=32, mod_len=32, exp_len=64 con los primeros 32 bytes "
        "del exponente en 0xff..ff) cuesta 2725 -- por encima del "
        "stipend -- para que un gas explicito de 1 (1+2300=2301 < 2725) "
        "SI falle: status 0 y el value transferido se REVIERTE (mismo "
        "patron que 012, `ecrecover_out_of_gas_...`).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + modexp_call_code(
                    modexp_raw(b"\x00" * 32, b"\xff" * 32 + b"\x00" * 32, b"\x00" * 32),
                    mod_len=32,
                    gas_hex=gas_hex(1),
                    value=1,
                ),
            ),
        },
    ),
    case(
        "modexp_with_a_base_length_that_does_not_fit_in_usize_fails_closed",
        "base_len declarado ~2^248 (no entra en usize): fail-closed "
        "explicito -- el CALL entero falla (mismo tratamiento que OOG, "
        "), status 0 y el value transferido se REVIERTE. "
        "Sin este slice el motor jamas ve un valor asi.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + modexp_call_code(
                    b"\x01" + b"\x00" * 31 + b"\x00" * 32 + b"\x00" * 32,  # base_len~2^248, exp_len=0, mod_len=0
                    mod_len=0,
                    value=1,
                ),
            ),
        },
    ),
)

# --- 4. value + STATICCALL ---------------------------------------------------
SMALL_VECTOR = modexp_raw(b"\x03", b"\x02", b"\x05")  # 3^2 mod 5 = 4

add(
    "call-kinds.json",
    case(
        "modexp_with_value_moves_the_balance_and_still_computes",
        "CALL con value>0 a MODEXP usando el caso chico (3^2 mod 5 = 4, "
        "gas=200 por el piso): el balance se mueve Y el output es "
        "correcto -- verificado por el diferencial en el post-state "
        "completo (balance de MAIN/MODEXP + slot 2).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x" + modexp_call_code(SMALL_VECTOR, mod_len=1, value=1),
            ),
        },
    ),
    case(
        "staticcall_to_modexp_succeeds_like_a_normal_call",
        "STATICCALL a MODEXP: no hay nada que gatear (MODEXP no escribe "
        "estado), pero confirma que no rompe nada -- mismo resultado "
        "(3^2 mod 5 = 4) que el caso CALL.",
        base_pre(modexp_call_code(SMALL_VECTOR, mod_len=1, opcode=STATICCALL)),
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
        print("%-32s %d casos" % (filename, len(cases)))
    print("total: %d casos" % sum(len(c) for c in FILES.values()))


if __name__ == "__main__":
    main()
