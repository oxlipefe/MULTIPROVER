#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/set-code/*.json.

Mismo criterio que gen-create-fixtures.py: los fixtures estan versionados y
este script existe para que sean REPRODUCIBLES. El oraculo es revm, no este
archivo (los campos `hash`/`logs` van en cero a proposito; ver
cmd/conformance/fixtures/diff/README.md).

    FIXTURE_DIR=cmd/conformance/fixtures/diff/set-code python3 scripts/gen-set-code-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20      # contrato que llama (el "caller")
CODED = "0x" + "b1" * 20     # cuenta con codigo REAL (no designator)
COINBASE = "0x" + "c0" * 20
ALICE = "0x" + "d0" * 20     # authority: EOA que EXISTE (balance != 0)
GHOST = "0x" + "d1" * 20     # authority: existe en el trie pero VACIA
FRESH = "0x" + "e0" * 20     # authority: NO existe en el pre-state
IMPL = "0x" + "f0" * 20      # implementacion delegada #1 (escribe 0x2a)
IMPL2 = "0x" + "f1" * 20     # implementacion delegada #2 (escribe 0x2b)
HOP = "0x" + "f2" * 20       # cuenta YA delegada (para la cadena de 2 saltos)
ZERO_ADDR = "0x" + "00" * 20

# create(SENDER, 0) — misma direccion precomputada que usa el set `create/`
# (la fija `crates/evm/tests/creates.rs`).
DERIVED_FROM_SENDER = "0xc64cd893165675fa0ad5604d39ecb5af8e073bd2"

# ---------------------------------------------------------------- ensamblador

STOP = "00"
ADD = "01"
MSTORE = "52"
MLOAD = "51"
SSTORE = "55"
REVERT = "fd"
CALL = "f1"
DELEGATECALL = "f4"
STATICCALL = "fa"
EXTCODESIZE = "3b"
EXTCODECOPY = "3c"
EXTCODEHASH = "3f"
BALANCE = "31"
INVALID = "fe"


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


# Gas ACOTADO para las sub-calls (misma convencion que `calls/` y `create/`):
# con el 63/64 de EIP-150, un hijo que haltea se lleva TODO el gas reenviado y
# al caller le queda 1/64 — que NO alcanza para el SSTORE que registra el
# resultado. Pedir un limite chico deja al caller vivo, que es justo lo que el
# caso quiere probar.
CALL_GAS = "ea60"  # 60000


def call_to(addr, opcode=CALL, gas_hex=CALL_GAS, value=0):
    """CALL/STATICCALL/DELEGATECALL a `addr`. Deja el status en el stack."""
    args = [push_int(0), push_int(0), push_int(0), push_int(0)]  # retLen retOff argLen argOff
    if opcode == CALL:
        args.append(push_int(value))
    return cat(*args, push_addr(addr), push(gas_hex), opcode)


def store_top_plus_one(slot):
    """Guarda `tope + 1` en `slot` (convencion del set: un 0 no existe en el
    trie, asi que sin el +1 un slot ausente no distingue "fallo" de "no corrio").
    """
    return cat(push_int(1), ADD, push_int(slot), SSTORE)


def store_top(slot):
    """Guarda el tope tal cual (para valores que nunca son cero: size 23, hash)."""
    return cat(push_int(slot), SSTORE)


def extcodesize_into(addr, slot):
    return cat(push_addr(addr), EXTCODESIZE, store_top(slot))


def extcodehash_into(addr, slot):
    return cat(push_addr(addr), EXTCODEHASH, store_top(slot))


def extcodecopy_into(addr, slot, length=32):
    """EXTCODECOPY(addr, 0, 0, length) y guarda la primera palabra."""
    return cat(
        push_int(length),
        push_int(0),
        push_int(0),
        push_addr(addr),
        EXTCODECOPY,
        push_int(0),
        MLOAD,
        store_top(slot),
    )


def balance_into(addr, slot):
    return cat(push_addr(addr), BALANCE, store_top_plus_one(slot))


# Implementaciones delegadas: escriben SU marca en el slot 0 de la cuenta EN
# EJECUCION — que con una delegacion es la `authority`, no la implementacion.
IMPL_CODE = cat(push_int(0x2A), push_int(0), SSTORE, STOP)
IMPL2_CODE = cat(push_int(0x2B), push_int(0), SSTORE, STOP)
# Codigo real (no designator) para probar que una authority con codigo propio
# no se puede pisar.
CODED_CODE = cat(push_int(0x07), push_int(7), SSTORE, STOP)


def designator(addr):
    return "ef0100" + addr[2:]


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": nonce if isinstance(nonce, str) else hex(nonce),
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


def auth(address, nonce=0, authority=ALICE, chain_id="0x01"):
    return {
        "chainId": chain_id,
        "address": address,
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "authority": authority,
    }


RICH = "0x3635c9adc5dea00000"


def base_pre(extra=None):
    pre = {
        SENDER: account(0, RICH),
        MAIN: account(1, "0x0", "0x" + cat(call_to(ALICE), store_top_plus_one(1), STOP)),
        IMPL: account(1, "0x0", "0x" + IMPL_CODE),
    }
    if extra:
        pre.update(extra)
    return pre


def case(
    name,
    comment,
    pre,
    authorizations,
    to=MAIN,
    data="0x",
    value="0x0",
    gas_limit="0xf4240",
    sender_nonce="0x00",
    access_lists=None,
    fork="Prague",
):
    tx = {
        "sender": SENDER,
        "to": to,
        "nonce": sender_nonce,
        # EIP-7702 no tiene mercado de fee propio: mismo 1559 que el resto.
        # `maxPriorityFeePerGas != 0` a proposito — el tip le da al coinbase un
        # balance proporcional al gas cobrado, o sea un SEGUNDO observable del
        # gas en el post-state (no solo el balance del sender).
        "maxFeePerGas": "0x14",
        "maxPriorityFeePerGas": "0x02",
        "data": [data],
        "gasLimit": [gas_limit],
        "value": [value],
    }
    if authorizations is not None:
        tx["authorizationList"] = authorizations
    else:
        # Sin authorizationList la tx NO es tipo 4: se usa para los casos que
        # prueban delegaciones YA presentes en el pre-state.
        del tx["maxFeePerGas"]
        del tx["maxPriorityFeePerGas"]
        tx["gasPrice"] = "0x0c"
    if access_lists is not None:
        tx["accessLists"] = access_lists
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


# --- 1. delegar y ejecutar -------------------------------------------------
add(
    "delegation.json",
    case(
        "a_delegated_eoa_runs_the_implementation_code_with_its_own_storage",
        "El caso canonico: la tx tipo 4 delega ALICE -> IMPL y MAIN la llama. "
        "El SSTORE de IMPL cae en el storage de ALICE (el codigo delegado corre "
        "COMO propio, no como un DELEGATECALL implicito). ALICE queda con el "
        "designator de 23 bytes y nonce 1.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000")}),
        [auth(IMPL)],
    ),
    case(
        "a_transaction_sent_to_a_delegated_eoa_runs_the_implementation_in_the_root_frame",
        "ALICE ya viene delegada en el pre-state y la tx (legacy, sin "
        "authorizationList) va DIRECTO a ella: el frame RAIZ tiene que resolver "
        "la delegacion, no solo las sub-calls.",
        {
            SENDER: account(0, RICH),
            ALICE: account(1, "0x0de0b6b3a7640000", "0x" + designator(IMPL)),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        None,
        to=ALICE,
    ),
    case(
        "a_delegated_eoa_can_originate_its_own_transaction_eip3607",
        "EXCEPCION de EIP-3607 (verificada contra revm): un sender con codigo "
        "de designator SI puede mandar transacciones. Sin esto el caso canonico "
        "de 7702 se rechazaria de entrada.",
        {
            SENDER: account(0, RICH, "0x" + designator(IMPL)),
            MAIN: account(1, "0x0", "0x" + cat(push_int(0x09), push_int(9), SSTORE, STOP)),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        None,
        to=MAIN,
    ),
    case(
        "the_self_delegation_pattern_uses_the_nonce_already_bumped_by_the_tx",
        "El patron canonico: el SENDER se auto-delega y se manda calldata a si "
        "mismo en la MISMA tx. Como el bump del nonce del sender pasa ANTES de "
        "aplicar las autorizaciones, la tupla tiene que declarar nonce 1 (no 0). "
        "El frame raiz corre IMPL sobre el storage del SENDER y su nonce final "
        "es 2 (bump de la tx + bump de la delegacion).",
        {
            SENDER: account(0, RICH),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        [auth(IMPL, nonce=1, authority=SENDER)],
        to=SENDER,
        data="0xabcd",
    ),
)

# --- 2. lo que EXTCODE* ve -------------------------------------------------
add(
    "extcode.json",
    case(
        "extcode_of_a_delegated_account_sees_the_designator_not_the_implementation",
        "EXTCODESIZE devuelve 23 (el designator), EXTCODEHASH el keccak del "
        "designator y EXTCODECOPY los bytes 0xef0100||IMPL. NINGUNO resuelve la "
        "delegacion (verificado contra revm: los opcodes usan load_account_info, "
        "no la variante _delegated).",
        {
            SENDER: account(0, RICH),
            MAIN: account(
                1,
                "0x0",
                "0x"
                + cat(
                    extcodesize_into(ALICE, 2),
                    extcodehash_into(ALICE, 3),
                    extcodecopy_into(ALICE, 4),
                    balance_into(ALICE, 5),
                    STOP,
                ),
            ),
            ALICE: account(0, "0x0de0b6b3a7640000"),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        [auth(IMPL)],
    ),
    case(
        "a_delegated_call_with_the_implementation_in_the_access_list_pays_the_warm_price",
        "Mismo CALL que el caso canonico pero con IMPL declarada en la access "
        "list: resolver la delegacion cuesta 100 (warm) en vez de 2600 (100 + "
        "2500 de cold). El delta de 2500 se ve en el balance del sender y del "
        "coinbase.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000")}),
        [auth(IMPL)],
        access_lists=[[{"address": IMPL, "storageKeys": []}]],
    ),
)

# --- 3. autorizaciones salteadas -------------------------------------------
add(
    "skipped.json",
    case(
        "an_authorization_with_the_wrong_nonce_is_skipped",
        "La tupla declara nonce 5 y ALICE tiene 0: se saltea. ALICE NO queda "
        "delegada (sin codigo, nonce intacto), el CALL de MAIN cae sobre una EOA "
        "vacia (status 1 => slot 1 = 2) y la tx igual paga los 25000 de la tupla "
        "SIN refund (la autorizacion no se aplico).",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000")}),
        [auth(IMPL, nonce=5)],
    ),
    case(
        "an_authorization_for_another_chain_is_skipped",
        "chainId 0x63 != chainId 0x01 del bloque: se saltea.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000")}),
        [auth(IMPL, chain_id="0x63")],
    ),
    case(
        "chain_id_zero_authorizes_on_every_chain",
        "chainId 0 es el comodin de la EIP: la autorizacion SI se aplica.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000")}),
        [auth(IMPL, chain_id="0x00")],
    ),
    case(
        "an_authorization_over_an_account_with_real_code_is_skipped",
        "CODED tiene codigo propio (no un designator): la autorizacion NO puede "
        "pisarlo. Su codigo y su nonce quedan intactos y el CALL de MAIN ejecuta "
        "el codigo ORIGINAL (escribe 0x07 en su slot 7). La tupla declara el "
        "nonce CORRECTO (1) a proposito: con un nonce que no coincide, el "
        "chequeo de nonce enmascararia al de codigo y el caso no probaria nada "
        ".",
        {
            SENDER: account(0, RICH),
            MAIN: account(1, "0x0", "0x" + cat(call_to(CODED), store_top_plus_one(1), STOP)),
            CODED: account(1, "0x0", "0x" + CODED_CODE),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        [auth(IMPL, nonce=1, authority=CODED)],
    ),
    case(
        "an_authorization_with_an_invalid_signature_is_skipped_and_the_next_one_applies",
        "La primera tupla no recupero firmante (`authority: null`): se saltea "
        "SIN invalidar la tx. La segunda si aplica. Se pagan los 25000 de LAS "
        "DOS (el costo es por tupla declarada) y se refunda una sola.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000")}),
        [
            {"chainId": "0x01", "address": IMPL2, "nonce": "0x0", "authority": None},
            auth(IMPL),
        ],
    ),
    case(
        "an_authorization_with_the_max_nonce_is_skipped",
        "nonce = 2^64-1: bumpearlo desbordaria, asi que la EIP la saltea antes "
        "de mirar nada mas (revm chequea esto ANTES de recuperar el firmante).",
        base_pre({ALICE: account("0xffffffffffffffff", "0x0de0b6b3a7640000")}),
        [auth(IMPL, nonce="0xffffffffffffffff")],
    ),
)

# --- 4. undelegate y cadenas ----------------------------------------------
add(
    "chains.json",
    case(
        "delegating_to_the_zero_address_clears_the_delegation",
        "ALICE ya viene delegada; la tupla apunta a la direccion CERO: el codigo "
        "vuelve a vacio (undelegate) y el nonce igual se bumpea. El CALL de MAIN "
        "cae entonces sobre una EOA sin codigo y el slot 0 de ALICE queda como "
        "estaba.",
        base_pre(
            {
                ALICE: account(
                    1, "0x0de0b6b3a7640000", "0x" + designator(IMPL), {"0x05": "0x63"}
                )
            }
        ),
        [auth(ZERO_ADDR, nonce=1)],
    ),
    case(
        "a_two_hop_delegation_chain_executes_the_second_designator_literally_and_halts",
        "ALICE -> HOP y HOP -> IMPL (ya delegada en el pre-state). Llamar a ALICE "
        "resuelve UN SOLO hop: se ejecutan los 23 bytes del designator de HOP "
        "como bytecode, y 0xEF no es un opcode valido (EIP-3541) => halt del "
        "sub-frame. El slot 0 de IMPL/ALICE NO se escribe y MAIN registra el "
        "fallo (slot 1 = 1).",
        base_pre(
            {
                ALICE: account(0, "0x0de0b6b3a7640000"),
                HOP: account(1, "0x0", "0x" + designator(IMPL)),
            }
        ),
        [auth(HOP)],
    ),
    case(
        "two_authorizations_over_the_same_authority_apply_in_order",
        "Dos tuplas sobre ALICE en la MISMA tx: la primera la delega a IMPL y "
        "bumpea el nonce a 1; la segunda declara nonce 1 (el YA bumpeado) y la "
        "re-delega a IMPL2. Gana la SEGUNDA (el CALL escribe 0x2b) y el nonce "
        "final es 2, con refund por las dos.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000"), IMPL2: account(1, "0x0", "0x" + IMPL2_CODE)}),
        [auth(IMPL), auth(IMPL2, nonce=1)],
    ),
    case(
        "the_second_authorization_over_the_same_authority_is_skipped_if_it_reuses_the_nonce",
        "Igual que el anterior pero la segunda tupla declara nonce 0 otra vez: "
        "ya no coincide con el nonce (1) que dejo la primera, asi que se saltea. "
        "Gana la PRIMERA (el CALL escribe 0x2a), el nonce final es 1 y se paga "
        "el costo de las dos tuplas con UN solo refund.",
        base_pre({ALICE: account(0, "0x0de0b6b3a7640000"), IMPL2: account(1, "0x0", "0x" + IMPL2_CODE)}),
        [auth(IMPL), auth(IMPL2, nonce=0)],
    ),
)

# --- 4b. los otros tres opcodes de call ------------------------------------
add(
    "call-kinds.json",
    case(
        "delegatecall_to_a_delegated_account_runs_the_implementation_over_the_caller_storage",
        "DELEGATECALL a ALICE (delegada a IMPL): la resolucion de la delegacion "
        "vale para los CUATRO opcodes de call, no solo para CALL. Como es "
        "DELEGATECALL, el SSTORE de IMPL cae en el storage de MAIN (slot 0 = "
        "0x2a), no en el de ALICE.",
        base_pre(
            {
                ALICE: account(0, "0x0de0b6b3a7640000"),
                MAIN: account(
                    1,
                    "0x0",
                    "0x" + cat(call_to(ALICE, opcode=DELEGATECALL), store_top_plus_one(1), STOP),
                ),
            }
        ),
        [auth(IMPL)],
    ),
    case(
        "staticcall_to_a_delegated_account_halts_when_the_implementation_writes",
        "STATICCALL a ALICE delegada: el codigo de IMPL corre igual, pero su "
        "SSTORE haltea por EIP-214 => status 0 (slot 1 = 1) y el storage de "
        "ALICE queda intacto.",
        base_pre(
            {
                ALICE: account(0, "0x0de0b6b3a7640000"),
                MAIN: account(
                    1,
                    "0x0",
                    "0x" + cat(call_to(ALICE, opcode=STATICCALL), store_top_plus_one(1), STOP),
                ),
            }
        ),
        [auth(IMPL)],
    ),
    case(
        "a_call_with_value_to_a_delegated_account_moves_the_balance_and_runs_the_code",
        "CALL con value 1 a ALICE delegada: se cobra `G_callvalue` (9000) Y el "
        "acceso a la cuenta delegada, el balance se mueve a ALICE (no a IMPL) y "
        "el codigo corre sobre el storage de ALICE.",
        base_pre(
            {
                ALICE: account(0, "0x0de0b6b3a7640000"),
                MAIN: account(
                    1,
                    "0x10",
                    "0x" + cat(call_to(ALICE, value=1), store_top_plus_one(1), STOP),
                ),
            }
        ),
        [auth(IMPL)],
    ),
)

# --- 5. el refund condicional y la supervivencia a revert/halt -------------
add(
    "refund.json",
    case(
        "an_authorization_over_an_account_that_does_not_exist_gets_no_refund",
        "FRESH no esta en el pre-state: la autorizacion se aplica (la crea con "
        "el designator y nonce 1) pero NO refunda. Comparar el balance final del "
        "sender con el del caso canonico (ALICE, que si existe) da exactamente "
        "los 12500 de PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST.",
        {
            SENDER: account(0, RICH),
            MAIN: account(1, "0x0", "0x" + cat(call_to(FRESH), store_top_plus_one(1), STOP)),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        [auth(IMPL, authority=FRESH)],
    ),
    case(
        "an_authorization_over_an_account_that_exists_but_is_empty_gets_the_refund",
        "GHOST existe en el trie con balance 0, nonce 0 y sin codigo. La "
        "condicion exacta de revm es `!(is_empty && no_existe_ni_fue_tocada)`: "
        "existir alcanza, aunque este vacia => SI refunda. Es el borde que "
        "separa este caso del de FRESH.",
        {
            SENDER: account(0, RICH),
            MAIN: account(1, "0x0", "0x" + cat(call_to(GHOST), store_top_plus_one(1), STOP)),
            GHOST: account(0, "0x0"),
            IMPL: account(1, "0x0", "0x" + IMPL_CODE),
        },
        [auth(IMPL, authority=GHOST)],
    ),
    case(
        "the_delegation_and_its_refund_survive_a_reverting_transaction",
        "MAIN revierte despues de llamar. La delegacion se aplico FUERA de todo "
        "checkpoint, asi que sobrevive al revert — y el refund de EIP-7702 "
        "tambien (revm lo suma en post_execution, despues de que last_frame_result "
        "descarto el refund del frame). Solo el SSTORE del sub-frame se pierde.",
        base_pre(
            {
                ALICE: account(0, "0x0de0b6b3a7640000"),
                MAIN: account(
                    1,
                    "0x0",
                    "0x" + cat(call_to(ALICE), push_int(0), push_int(0), REVERT),
                ),
            }
        ),
        [auth(IMPL)],
    ),
    case(
        "the_delegation_and_its_refund_survive_a_halting_transaction",
        "Igual pero MAIN haltea (opcode 0xFE, EIP-141): se consume TODO el gas "
        "de la tx MENOS el refund de 7702, que sobrevive igual. La delegacion "
        "queda aplicada.",
        base_pre(
            {
                ALICE: account(0, "0x0de0b6b3a7640000"),
                MAIN: account(1, "0x0", "0x" + cat(call_to(ALICE), INVALID)),
            }
        ),
        [auth(IMPL)],
    ),
    # RETIRADO. El caso afirmaba que una tx tipo
    # 4 con `to == None` NO se rechaza, "verificado contra revm". La
    # observacion sobre revm era correcta -- `validate_tx_env` no tiene ese
    # chequeo -- pero la premisa estaba mal enunciada: es una afirmacion sobre
    # el CODIGO de revm, no sobre el protocolo. EEST declara
    # `TransactionException.TYPE_4_TX_CONTRACT_CREATION`, y el input ni siquiera
    # es RLP-codificable (el `to` de EIP-7702 no es nullable), asi que revm
    # nunca lo ve y no fue disenado para contestar esa pregunta.
    #
    # Con el chequeo implementado, este fixture hacia divergir a los dos
    # motores sobre un input que no existe en la red: no protegia ninguna
    # propiedad real. Se retira; la regla la sostienen EEST y el unit test
    # `a_set_code_tx_without_to_is_rejected_even_though_revm_has_no_such_check`.
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
