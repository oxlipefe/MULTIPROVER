#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/bls12-381/*.json.

Mismo criterio que los generadores previos (012-016): los fixtures estan
versionados y este script existe para que sean REPRODUCIBLES. El oraculo
es revm, no este archivo.

Dos vectores son REALES, transcritos de revm-precompile-34.0.0 (no
regenerados): g1_msm.rs::bls_g1multiexp_g1_not_on_curve_but_in_subgroup y
map_fp_to_g1.rs::sanity_test. El resto de los vectores (generador de G1/G2,
2*G, 3*G, puntos on-curve-pero-off-subgroup) se generaron offline con un
mini-proyecto Cargo standalone de ark-bls12-381 (mismo patron que 016) --
ver /it.2.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/bls12-381 python3 scripts/gen-bls12-381-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20

G1_ADD = "0x" + "00" * 19 + "0b"
G1_MSM = "0x" + "00" * 19 + "0c"
G2_ADD = "0x" + "00" * 19 + "0d"
G2_MSM = "0x" + "00" * 19 + "0e"
PAIRING = "0x" + "00" * 19 + "0f"
MAP_FP_TO_G1 = "0x" + "00" * 19 + "10"
MAP_FP2_TO_G2 = "0x" + "00" * 19 + "11"

# ---------------------------------------------------------------- ensamblador

ADD = "01"
MLOAD = "51"
MSTORE = "52"
SSTORE = "55"
STOP = "00"
CALL = "f1"


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


def call_precompile(addr, gas, arg_offset, arg_length, ret_offset, ret_length, value=0):
    args = [
        push_dyn(ret_length),
        push_dyn(ret_offset),
        push_dyn(arg_length),
        push_dyn(arg_offset),
        push_dyn(value),
    ]
    return cat(*args, push_addr(addr), push(gas_hex(gas)), CALL)


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
# son 2*384=768 bytes para PAIRING con 2 pares).
RET_WORD_OFFSET = 1024


def precompile_call_code(addr, raw: bytes, ret_len, arg_length=None, gas=30_000_000, value=0):
    """Escribe `raw` en memoria [0, len(raw)), llama a `addr` con
    `arg_length` bytes de input (por defecto `len(raw)`), guarda
    status+1 en slot 1 y hasta 256 bytes del output en los slots 2-9 (32
    bytes por slot)."""
    if arg_length is None:
        arg_length = len(raw)
    ret_offset = RET_WORD_OFFSET
    code = cat(
        mstore_bytes(0, raw),
        call_precompile(addr, gas, arg_offset=0, arg_length=arg_length, ret_offset=ret_offset, ret_length=ret_len, value=value),
        store_top_plus_one(1),
    )
    slot = 2
    off = 0
    while off < ret_len:
        code += cat(push_int(ret_offset + off, width=2), MLOAD, store_top(slot))
        slot += 1
        off += 32
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


def case(name, comment, pre, to=MAIN, data="0x", value="0x0", gas_limit="0x1c9c380", fork="Prague"):
    # gas_limit por defecto 0x1c9c380 = 30_000_000: de sobra por encima de
    # cualquier gas forwarded al CALL para que el caller SIEMPRE tenga
    # margen para la SSTORE posterior, en exito Y en fallo (leccion de
    # exito Y en fallo).
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


# --------------------------------------------------- vectores (ver it.1/it.2)
G1_GENERATOR = "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
G2_GENERATOR = "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
G1_TWO_G = "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"
G1_ON_CURVE_OFF_SUBGROUP = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000d3c6da1211ebe797bc0790f1e6e7d669b180a8e59196825506d2bb2185f53715df092c8a7ceb64843ea7df67dbad60d"
G2_ON_CURVE_OFF_SUBGROUP = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018c6b864ae17dc9da64203ffefb966306425a7bc6aeb7c75247438372716284a4173830420cd476ba1a365b95bfcec3800000000000000000000000000000000172e93db764a8400a7d5071b6b6f5de0da2f0f4a063119abca014006b7c40a2cfe291a1924e65db0d6d0fcfbf3bf3d5c"
G1_INFINITY = "00" * 128
G2_INFINITY = "00" * 256


def scalar(n):
    return "%064x" % n


def hx(*parts):
    return bytes.fromhex("".join(parts))


# --- 1. G1ADD -----------------------------------------------------------
add(
    "g1-add.json",
    case(
        "g1_add_of_the_generator_with_itself_succeeds",
        "G1ADD(G,G) -- exito, gas flat 375.",
        base_pre(precompile_call_code(G1_ADD, hx(G1_GENERATOR, G1_GENERATOR), ret_len=128, gas=375)),
    ),
    case(
        "g1_add_of_two_points_at_infinity_stays_at_infinity",
        "(0,0)+(0,0) es el punto al infinito por convencion de la EVM.",
        base_pre(precompile_call_code(G1_ADD, hx(G1_INFINITY, G1_INFINITY), ret_len=128, gas=375)),
    ),
    case(
        "g1_add_accepts_a_point_on_curve_but_off_subgroup",
        "SIN chequeo de subgrupo -- al reves de MSM/PAIRING, "
        "un punto real en curva pero fuera del subgrupo de orden primo se "
        "acepta en ADD.",
        base_pre(precompile_call_code(G1_ADD, hx(G1_ON_CURVE_OFF_SUBGROUP, G1_GENERATOR), ret_len=128, gas=375)),
    ),
    case(
        "g1_add_with_a_length_other_than_256_fails",
        "255 bytes (1 de menos que el largo EXACTO de 256).",
        base_pre(precompile_call_code(G1_ADD, hx(G1_GENERATOR, G1_GENERATOR), ret_len=0, arg_length=255, gas=375)),
    ),
    case(
        "g1_add_with_non_zero_padding_fails",
        "El primer byte de padding (deberia ser cero) mutado a 0x01 -- "
        "fallo INMEDIATO, distinto de largo incorrecto.",
        base_pre(
            precompile_call_code(
                G1_ADD,
                bytes([0x01]) + hx(G1_GENERATOR, G1_GENERATOR)[1:],
                ret_len=0,
                gas=375,
            )
        ),
    ),
    case(
        "g1_add_out_of_gas_is_an_err",
        "374 (1 menos que el costo flat de 375).",
        base_pre(precompile_call_code(G1_ADD, hx(G1_GENERATOR, G1_GENERATOR), ret_len=0, gas=374)),
    ),
)

# --- 2. G2ADD -----------------------------------------------------------
add(
    "g2-add.json",
    case(
        "g2_add_of_the_generator_with_itself_succeeds",
        "G2ADD(G,G) -- exito, gas flat 600.",
        base_pre(precompile_call_code(G2_ADD, hx(G2_GENERATOR, G2_GENERATOR), ret_len=256, gas=600)),
    ),
    case(
        "g2_add_of_two_points_at_infinity_stays_at_infinity",
        "(0,0)+(0,0) al infinito.",
        base_pre(precompile_call_code(G2_ADD, hx(G2_INFINITY, G2_INFINITY), ret_len=256, gas=600)),
    ),
    case(
        "g2_add_accepts_a_point_on_curve_but_off_subgroup",
        "SIN chequeo de subgrupo, analogo a G1ADD.",
        base_pre(precompile_call_code(G2_ADD, hx(G2_ON_CURVE_OFF_SUBGROUP, G2_GENERATOR), ret_len=256, gas=600)),
    ),
    case(
        "g2_add_with_a_length_other_than_512_fails",
        "511 bytes (1 de menos).",
        base_pre(precompile_call_code(G2_ADD, hx(G2_GENERATOR, G2_GENERATOR), ret_len=0, arg_length=511, gas=600)),
    ),
    case(
        "g2_add_out_of_gas_is_an_err",
        "599 (1 menos que el costo flat de 600).",
        base_pre(precompile_call_code(G2_ADD, hx(G2_GENERATOR, G2_GENERATOR), ret_len=0, gas=599)),
    ),
)

# --- 3. G1MSM -------------------------------------------------------------
# indice = min(k-1, len-1); para k=2, indice=1 -> discount_table[1]=949
# (NO discount_table[2]=848, que es para k=3 -- el bug real que la
# auditoria de post-state destapo en it.3, ver).
G1_MSM_GAS_K2 = (2 * 949 * 12000) // 1000
add(
    "g1-msm.json",
    case(
        "g1_msm_scalar_mult_by_one_succeeds",
        "k=1: MSM([G],[1]) -- exito, gas = discount[0]=1000 -> 12000 "
        "(el mismo costo que la escalar mult explicita del EIP).",
        base_pre(precompile_call_code(G1_MSM, hx(G1_GENERATOR, scalar(1)), ret_len=128, gas=12000)),
    ),
    case(
        "g1_msm_with_two_pairs_ejercita_the_discount_table",
        "k=2: MSM([G,G],[1,2]) -- deberia dar 3*G, ejercita la tabla de "
        "descuento con k>1 (discount[1]=949).",
        base_pre(
            precompile_call_code(
                G1_MSM,
                hx(G1_GENERATOR, scalar(1), G1_GENERATOR, scalar(2)),
                ret_len=128,
                gas=G1_MSM_GAS_K2,
            )
        ),
    ),
    case(
        "g1_msm_skips_a_zero_scalar_pair_but_still_validates_its_point",
        "Un scalar CERO se saltea del computo, pero el punto SI se valida "
        ".",
        base_pre(
            precompile_call_code(
                G1_MSM,
                hx(G1_GENERATOR, scalar(3), G1_GENERATOR, scalar(0)),
                ret_len=128,
                gas=G1_MSM_GAS_K2,
            )
        ),
    ),
    case(
        "g1_msm_validates_an_invalid_point_even_with_a_zero_scalar",
        "El punto se valida ANTES de mirar si el scalar es cero "
        "(verificado contra arkworks.rs::p1_msm_bytes -- 'Skip zero "
        "scalars AFTER validating the point'): un punto invalido "
        "(padding no-cero) con scalar 0 falla igual, no se saltea la "
        "validacion junto con la contribucion (mutation "
        "testing de it.3 mostro que saltear SOLO la contribucion es "
        "invisible matematicamente, 0*P=O -- este caso prueba el orden "
        "real, no la aritmetica).",
        base_pre(
            precompile_call_code(
                G1_MSM,
                hx(G1_GENERATOR, scalar(1)) + bytes([0x11]) * 128 + hx(scalar(0)),
                ret_len=0,
                gas=G1_MSM_GAS_K2,
            )
        ),
    ),
    case(
        "g1_msm_with_a_point_not_on_curve_fails",
        "Vector REAL de g1_msm.rs::bls_g1multiexp_g1_not_on_curve_but_in_subgroup "
        "de revm-precompile, transcrito.",
        base_pre(
            precompile_call_code(
                G1_MSM,
                hx(
                    "000000000000000000000000000000000a2833e497b38ee3ca5c62828bf4887a9f940c9e426c7890a759c20f248c23a7210d2432f4c98a514e524b5184a0ddac00000000000000000000000000000000150772d56bf9509469f9ebcd6e47570429fd31b0e262b66d512e245c38ec37255529f2271fd70066473e393a8bead0c30000000000000000000000000000000000000000000000000000000000000000"
                ),
                ret_len=0,
                gas=12000,
            )
        ),
    ),
    case(
        "g1_msm_rejects_a_point_on_curve_but_off_subgroup",
        "CON chequeo de subgrupo -- al reves de ADD.",
        base_pre(precompile_call_code(G1_MSM, hx(G1_ON_CURVE_OFF_SUBGROUP, scalar(1)), ret_len=0, gas=12000)),
    ),
    case(
        "g1_msm_with_a_length_not_a_multiple_of_160_fails",
        "159 bytes.",
        base_pre(precompile_call_code(G1_MSM, hx(G1_GENERATOR, scalar(1)), ret_len=0, arg_length=159, gas=12000)),
    ),
    case(
        "g1_msm_out_of_gas_is_an_err",
        "11999 (1 menos que el costo real de k=1).",
        base_pre(precompile_call_code(G1_MSM, hx(G1_GENERATOR, scalar(1)), ret_len=0, gas=11999)),
    ),
)

# --- 4. G2MSM -------------------------------------------------------------
# indice = min(k-1, len-1); para k=2, indice=1 -> discount_table[1]=1000
# (NO discount_table[2]=923, que es para k=3 -- mismo bug que G1MSM).
G2_MSM_GAS_K2 = (2 * 1000 * 22500) // 1000
add(
    "g2-msm.json",
    case(
        "g2_msm_scalar_mult_by_one_succeeds",
        "k=1: MSM([G],[1]) -- exito, gas 22500.",
        base_pre(precompile_call_code(G2_MSM, hx(G2_GENERATOR, scalar(1)), ret_len=256, gas=22500)),
    ),
    case(
        "g2_msm_with_two_pairs_ejercita_the_discount_table",
        "k=2: MSM([G,G],[1,2]) -- deberia dar 3*G.",
        base_pre(
            precompile_call_code(
                G2_MSM,
                hx(G2_GENERATOR, scalar(1), G2_GENERATOR, scalar(2)),
                ret_len=256,
                gas=G2_MSM_GAS_K2,
            )
        ),
    ),
    case(
        "g2_msm_rejects_a_point_on_curve_but_off_subgroup",
        "CON chequeo de subgrupo.",
        base_pre(precompile_call_code(G2_MSM, hx(G2_ON_CURVE_OFF_SUBGROUP, scalar(1)), ret_len=0, gas=22500)),
    ),
    case(
        "g2_msm_with_a_length_not_a_multiple_of_288_fails",
        "287 bytes.",
        base_pre(precompile_call_code(G2_MSM, hx(G2_GENERATOR, scalar(1)), ret_len=0, arg_length=287, gas=22500)),
    ),
    case(
        "g2_msm_out_of_gas_is_an_err",
        "22499 (1 menos que el costo real de k=1).",
        base_pre(precompile_call_code(G2_MSM, hx(G2_GENERATOR, scalar(1)), ret_len=0, gas=22499)),
    ),
)

# --- 5. PAIRING -------------------------------------------------------------
PAIRING_GAS_K1 = 32600 * 1 + 37700
add(
    "pairing.json",
    case(
        "pairing_of_the_generators_alone_is_not_the_identity",
        "e(G1,G2) solo -- NO deberia dar la identidad (un solo pair "
        "generico no es 1). El oraculo es revm, no un expected calculado "
        "a mano.",
        base_pre(precompile_call_code(PAIRING, hx(G1_GENERATOR, G2_GENERATOR), ret_len=32, gas=PAIRING_GAS_K1)),
    ),
    case(
        "pairing_with_a_g1_point_at_infinity_is_skipped_and_stays_true",
        "Un par con G1 al infinito se saltea del computo real; si es el "
        "unico par, el resultado es true por vacuidad.",
        base_pre(precompile_call_code(PAIRING, hx(G1_INFINITY, G2_GENERATOR), ret_len=32, gas=PAIRING_GAS_K1)),
    ),
    case(
        "pairing_with_empty_input_fails",
        "Input vacio es FALLO explicito -- AL REVES de BN254/PAIRING, "
        "la trampa central de este slice.",
        base_pre(precompile_call_code(PAIRING, b"", ret_len=0, gas=PAIRING_GAS_K1)),
    ),
    case(
        "pairing_rejects_a_g1_point_on_curve_but_off_subgroup",
        "CON chequeo de subgrupo en ambos G1 y G2.",
        base_pre(precompile_call_code(PAIRING, hx(G1_ON_CURVE_OFF_SUBGROUP, G2_GENERATOR), ret_len=0, gas=PAIRING_GAS_K1)),
    ),
    case(
        "pairing_with_a_length_not_a_multiple_of_384_fails",
        "383 bytes.",
        base_pre(precompile_call_code(PAIRING, hx(G1_GENERATOR, G2_GENERATOR), ret_len=0, arg_length=383, gas=PAIRING_GAS_K1)),
    ),
    case(
        "pairing_out_of_gas_is_an_err",
        "1 menos que el costo real de k=1.",
        base_pre(precompile_call_code(PAIRING, hx(G1_GENERATOR, G2_GENERATOR), ret_len=0, gas=PAIRING_GAS_K1 - 1)),
    ),
)

# --- 6. MAP_FP_TO_G1 / MAP_FP2_TO_G2 -----------------------------------------
add(
    "map-to-curve.json",
    case(
        "map_fp_to_g1_of_zero_succeeds",
        "Fp=0 es un elemento de campo valido -- exito, gas flat 5500. El "
        "resultado ya esta en el subgrupo correcto por construccion "
        ".",
        base_pre(precompile_call_code(MAP_FP_TO_G1, hx("00" * 64), ret_len=128, gas=5500)),
    ),
    case(
        "map_fp_to_g1_with_a_non_canonical_fp_fails",
        "Vector REAL de map_fp_to_g1.rs::sanity_test de revm-precompile, "
        "transcrito -- falla por Fp no canonico.",
        base_pre(
            precompile_call_code(
                MAP_FP_TO_G1,
                hx("000000000000000000000000000000006900000000000000636f6e7472616374595a603f343061cd305a03f40239f5ffff31818185c136bc2595f2aa18e08f17"),
                ret_len=0,
                gas=5500,
            )
        ),
    ),
    case(
        "map_fp_to_g1_with_a_length_other_than_64_fails",
        "63 bytes.",
        base_pre(precompile_call_code(MAP_FP_TO_G1, hx("00" * 64), ret_len=0, arg_length=63, gas=5500)),
    ),
    case(
        "map_fp_to_g1_out_of_gas_is_an_err",
        "5499 (1 menos que el costo flat).",
        base_pre(precompile_call_code(MAP_FP_TO_G1, hx("00" * 64), ret_len=0, gas=5499)),
    ),
    case(
        "map_fp2_to_g2_of_zero_succeeds",
        "Fp2=(0,0) -- exito, gas flat 23800.",
        base_pre(precompile_call_code(MAP_FP2_TO_G2, hx("00" * 128), ret_len=256, gas=23800)),
    ),
    case(
        "map_fp2_to_g2_with_a_length_other_than_128_fails",
        "127 bytes.",
        base_pre(precompile_call_code(MAP_FP2_TO_G2, hx("00" * 128), ret_len=0, arg_length=127, gas=23800)),
    ),
    case(
        "map_fp2_to_g2_out_of_gas_is_an_err",
        "23799 (1 menos que el costo flat).",
        base_pre(precompile_call_code(MAP_FP2_TO_G2, hx("00" * 128), ret_len=0, gas=23799)),
    ),
)

# --- 7. value + reverts -----------------------------------------------------
add(
    "call-kinds.json",
    case(
        "g1_add_with_value_moves_the_balance_and_still_computes",
        "CALL con value>0 y G1ADD(G,G) -- el balance se mueve Y el "
        "resultado es correcto.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x" + precompile_call_code(G1_ADD, hx(G1_GENERATOR, G1_GENERATOR), ret_len=128, gas=375, value=1),
            ),
        },
    ),
    case(
        "g1_add_with_value_reverts_on_any_failure_not_just_oog",
        "Largo invalido con value>0: el CALL falla SIEMPRE (inmune al "
        "stipend de 2300) y el value "
        "transferido se REVIERTE.",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x10",
                "0x"
                + precompile_call_code(G1_ADD, hx(G1_GENERATOR, G1_GENERATOR), ret_len=0, arg_length=255, gas=375, value=1),
            ),
        },
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
