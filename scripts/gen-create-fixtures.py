#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/create/*.json (slice 2.6, task 008).

Los fixtures estan versionados; este script existe para que sean REPRODUCIBLES
y para que agregar un caso no sea copiar-pegar bytecode a mano. El oraculo es
revm, no este archivo: los campos `hash`/`logs` van en cero a proposito (ver
cmd/conformance/fixtures/diff/README.md).

    FIXTURE_DIR=cmd/conformance/fixtures/diff/create python3 scripts/gen-create-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20
OTHER = "0x" + "d0" * 20   # cuenta existente no vacia (beneficiary "vivo")
DEAD = "0x" + "e0" * 20    # cuenta inexistente (beneficiary "muerto")
PROXY = "0x" + "f0" * 20   # contrato intermedio (para STATICCALL)
# create(SENDER, 0): la direccion que despliega una tx de creacion con nonce 0.
# Precomputada con `alloy_primitives::Address::create` (mismo helper que usa el
# motor y que revm); el unit test de `crates/evm/tests/creates.rs` la fija.
DERIVED_FROM_SENDER = "0xc64cd893165675fa0ad5604d39ecb5af8e073bd2"

# ---------------------------------------------------------------- ensamblador


def push(value_hex):
    """PUSHn con el minimo de bytes (value_hex sin 0x, longitud par)."""
    n = len(value_hex) // 2
    assert 1 <= n <= 32, value_hex
    return "%02x" % (0x60 + n - 1) + value_hex


def push_int(value, width=1):
    return push(("%%0%dx" % (width * 2)) % value)


def cat(*parts):
    return "".join(parts)


STOP = "00"
MSTORE = "52"
MLOAD = "51"
SSTORE = "55"
RETURN = "f3"
REVERT = "fd"
CREATE = "f0"
CREATE2 = "f5"
CALL = "f1"
STATICCALL = "fa"
SELFDESTRUCT = "ff"
RETURNDATASIZE = "3d"
RETURNDATACOPY = "3e"
BALANCE = "31"
GAS = "5a"
ADD = "01"
DUP1 = "80"
DUP6 = "85"
INVALID = "fe"
EXTCODEHASH = "3f"
EXTCODESIZE = "3b"
POP = "50"

# Con el 63/64 de EIP-150, un sub-frame que se lleva TODO el gas le deja al
# caller solo `remaining/64`. Para que MAIN SOBREVIVA a un CREATE fallido y
# pueda registrar el 0 (que es justo lo que el caso quiere probar), el limite
# de la tx tiene que dejar ese 1/64 por encima del costo de los SSTORE que
# siguen. Mismo razonamiento que el "gas ACOTADO" del set `calls/`.
GAS_ONE_SLOT_AFTER_BURN = "0x2dc6c0"    # 3.000.000: 1/64 ~= 46k > 22100
GAS_TWO_SLOTS_AFTER_BURN = "0x5b8d80"   # 6.000.000: 1/64 ~= 93k > 44200


def deployer(runtime_hex):
    """Initcode que despliega `runtime_hex` (<= 32 bytes) tal cual."""
    n = len(runtime_hex) // 2
    assert 1 <= n <= 32
    return cat(
        push(runtime_hex),
        push_int(0),
        MSTORE,
        push_int(n),
        push_int(32 - n),
        RETURN,
    )


def deployer_zeros(size):
    """Initcode que despliega `size` bytes en cero (memoria virgen)."""
    width = 2 if size > 0xFF else 1
    return cat(push_int(size, width), push_int(0), RETURN)


def store_initcode(initcode_hex):
    """Deja el initcode en memoria [0, len) y devuelve (codigo, offset, len).

    Se usa PUSHn + MSTORE, que alinea a DERECHA dentro de la palabra: el
    initcode arranca en `32 - len`.
    """
    n = len(initcode_hex) // 2
    assert n <= 32
    return cat(push(initcode_hex), push_int(0), MSTORE), 32 - n, n


def create_call(initcode_hex, value=0, salt=None):
    """CREATE/CREATE2 del initcode dado. Deja la direccion nueva en el stack."""
    prologue, offset, length = store_initcode(initcode_hex)
    args = []
    if salt is not None:
        args.append(push_int(salt))
    args.append(push_int(length))
    args.append(push_int(offset))
    args.append(push_int(value))
    return cat(prologue, *args, CREATE2 if salt is not None else CREATE)


def store_address_plus_one(slot):
    """Convencion del set (igual que `calls/`): se guarda `valor + 1`.

    Un 0 no existe en el trie, asi que un slot ausente no distinguiria "la
    creacion fallo" de "el codigo ni corrio". Con `+1` el slot SIEMPRE aparece.
    """
    return cat(push_int(1), ADD, push_int(slot), SSTORE)


def plain_call(gas_hex="5a"):
    """CALL con todo el gas a la direccion que esta en el tope del stack."""
    # stack: [addr] -> push retLen, retOff, argLen, argOff, value; DUP6 = addr
    return cat(
        push_int(0),  # retLen
        push_int(0),  # retOff
        push_int(0),  # argLen
        push_int(0),  # argOff
        push_int(0),  # value
        DUP6,         # addr
        GAS if gas_hex == "5a" else push(gas_hex),
        CALL,
    )


# ------------------------------------------------------------------- fixtures

# Runtime "testigo": escribe 0x0A en su propio slot 0 si alguien lo llama.
WITNESS_RUNTIME = cat(push_int(0x0A), push_int(0), SSTORE)
WITNESS_INITCODE = deployer(WITNESS_RUNTIME)


def selfdestruct_runtime(beneficiary):
    return cat(push(beneficiary[2:]), SELFDESTRUCT)


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": nonce if isinstance(nonce, str) else hex(nonce),
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


def case(
    name,
    comment,
    pre,
    to=MAIN,
    data="0x",
    value="0x0",
    gas_limit="0xf4240",
    fork="Prague",
    sender_nonce="0x00",
):
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
            "nonce": sender_nonce,
            "gasPrice": "0x0a",
            "data": [data],
            "gasLimit": [gas_limit],
            "value": [value],
        },
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


def pre_with_main(code, main_balance="0x0", extra=None):
    pre = {
        SENDER: account(0, "0x3635c9adc5dea00000"),
        MAIN: account(1, main_balance, "0x" + code),
    }
    if extra:
        pre.update(extra)
    return pre


FILES = {}


def add(filename, *cases):
    FILES.setdefault(filename, {}).update(dict(cases))


# --- 1. CREATE simple: despliega codigo y guarda la direccion --------------
add(
    "create.json",
    case(
        "create_deploys_and_returns_the_derived_address",
        "CREATE de un initcode de 14 bytes que despliega 5 bytes de runtime. "
        "El slot 0 de MAIN guarda direccion+1 (convencion del set) y el "
        "contrato nuevo aparece en el post-state con nonce 1 (EIP-161) y su "
        "codigo. El nonce de MAIN pasa de 1 a 2.",
        pre_with_main(cat(create_call(WITNESS_INITCODE), store_address_plus_one(0), STOP)),
    ),
    case(
        "two_creates_in_a_row_use_consecutive_nonces",
        "Dos CREATE seguidos desde MAIN: direcciones distintas derivadas de "
        "los nonces 1 y 2. El nonce final de MAIN es 3.",
        pre_with_main(
            cat(
                create_call(WITNESS_INITCODE),
                store_address_plus_one(0),
                create_call(WITNESS_INITCODE),
                store_address_plus_one(1),
                STOP,
            )
        ),
    ),
    case(
        "create_with_value_moves_the_balance_to_the_new_contract",
        "CREATE con value 0x64: el balance sale de MAIN y queda en el "
        "contrato nuevo ANTES de correr el initcode. CREATE no cobra "
        "G_newaccount (25000) por crear la cuenta: ya esta en sus 32000.",
        pre_with_main(
            cat(create_call(WITNESS_INITCODE, value=0x64), store_address_plus_one(0), STOP),
            main_balance="0x3e8",
        ),
    ),
    case(
        "create_without_funds_is_not_executed_and_leaves_the_nonce_alone",
        "CREATE con value mayor que el balance de MAIN: NO se ejecuta, se "
        "pushea 0, el gas reenviado vuelve ENTERO y el nonce de MAIN NO se "
        "bumpea (sigue en 1).",
        pre_with_main(
            cat(create_call(WITNESS_INITCODE, value=0x64), store_address_plus_one(0), STOP),
            main_balance="0x0a",
        ),
    ),
    case(
        "extcode_of_a_contract_created_in_the_same_tx_sees_the_fresh_code",
        "EXTCODEHASH y EXTCODESIZE de un contrato creado en ESTA misma tx: el "
        "codigo todavia no existe para el State, asi que el overlay del "
        "journal tiene que ganar. Slot 2 = keccak del runtime, slot 3 = 5.",
        pre_with_main(
            cat(
                create_call(WITNESS_INITCODE),
                DUP1,
                EXTCODEHASH,
                push_int(2),
                SSTORE,
                DUP1,
                EXTCODESIZE,
                push_int(3),
                SSTORE,
                store_address_plus_one(0),
                STOP,
            )
        ),
    ),
    case(
        "create_of_an_empty_initcode_deploys_an_empty_account",
        "CREATE con length 0: sin costo de initcode ni expansion de memoria. "
        "El initcode vacio termina en STOP implicito con output vacio, asi "
        "que se despliega una cuenta con nonce 1 y sin codigo.",
        pre_with_main(
            cat(
                push_int(0),  # length
                push_int(0),  # offset
                push_int(0),  # value
                CREATE,
                store_address_plus_one(0),
                STOP,
            )
        ),
    ),
)

# --- 2. CREATE2 ------------------------------------------------------------
add(
    "create2.json",
    case(
        "create2_derives_the_address_from_the_salt",
        "CREATE2 (EIP-1014) con salt 0x2a: la direccion sale de "
        "keccak(0xff ++ MAIN ++ salt ++ keccak(initcode))[12..], no del nonce. "
        "El nonce de MAIN se bumpea igual.",
        pre_with_main(
            cat(create_call(WITNESS_INITCODE, salt=0x2A), store_address_plus_one(0), STOP)
        ),
    ),
    case(
        "create2_with_a_different_salt_lands_on_a_different_address",
        "Mismo initcode, dos salts distintos: dos contratos distintos. Prueba "
        "que el salt entra de verdad en la formula.",
        pre_with_main(
            cat(
                create_call(WITNESS_INITCODE, salt=0x2A),
                store_address_plus_one(0),
                create_call(WITNESS_INITCODE, salt=0x2B),
                store_address_plus_one(1),
                STOP,
            )
        ),
    ),
    case(
        "create2_twice_with_the_same_salt_collides",
        "El segundo CREATE2 con el mismo salt cae en una direccion que YA "
        "tiene codigo: colision. Se pushea 0, TODO el gas reenviado (63/64) "
        "se pierde -- pero el nonce de MAIN se bumpeo IGUAL las dos veces "
        "(1 -> 3), porque el bump ocurre ANTES del checkpoint de la creacion.",
        pre_with_main(
            cat(
                create_call(WITNESS_INITCODE, salt=0x2A),
                store_address_plus_one(0),
                create_call(WITNESS_INITCODE, salt=0x2A),
                store_address_plus_one(1),
                STOP,
            )
        ),
        gas_limit=GAS_ONE_SLOT_AFTER_BURN,
    ),
)

# --- 3. Limites del codigo (EIP-3860 / 170 / 3541) -------------------------
add(
    "create-limits.json",
    case(
        "initcode_over_the_eip3860_limit_halts_before_charging_per_word",
        "CREATE con length 49153 (MAX_INITCODE_SIZE + 1): halt inmediato, "
        "ANTES de cobrar el costo por palabra y de expandir memoria. Se "
        "consume todo el gas de la tx.",
        pre_with_main(
            cat(
                push_int(49153, width=3),  # length
                push_int(0),               # offset
                push_int(0),               # value
                CREATE,
                store_address_plus_one(0),
                STOP,
            )
        ),
        gas_limit=GAS_ONE_SLOT_AFTER_BURN,
    ),
    case(
        "initcode_exactly_at_the_eip3860_limit_is_allowed",
        "CREATE con length 49152 (el tope exacto) SI entra: el halt es "
        "estricto (>), no >=. La expansion de memoria de 48 KiB y el costo "
        "por palabra se pagan; el initcode son ceros (STOP) y despliega una "
        "cuenta vacia.",
        pre_with_main(
            cat(
                push_int(49152, width=3),  # length
                push_int(0),               # offset
                push_int(0),               # value
                CREATE,
                store_address_plus_one(0),
                STOP,
            )
        ),
        gas_limit="0x2625a0",
    ),
    case(
        "deployed_code_starting_with_ef_is_rejected_eip3541",
        "El initcode devuelve 0xEF00: EIP-3541 rechaza el deploy. Es un halt "
        "del sub-frame (se pierde todo el gas reenviado), el value vuelve y "
        "el contrato NO queda -- pero el nonce de MAIN se bumpeo igual.",
        pre_with_main(
            cat(
                create_call(deployer("ef00")),
                store_address_plus_one(0),
                STOP,
            )
        ),
        gas_limit=GAS_ONE_SLOT_AFTER_BURN,
    ),
    case(
        "deployed_code_over_24576_bytes_is_rejected_eip170",
        "El initcode devuelve 24577 bytes (MAX_CODE_SIZE + 1): EIP-170 "
        "rechaza el deploy. Mismo tratamiento que 3541.",
        pre_with_main(
            cat(
                create_call(deployer_zeros(24577)),
                store_address_plus_one(0),
                STOP,
            )
        ),
        gas_limit=GAS_ONE_SLOT_AFTER_BURN,
    ),
    case(
        "deployed_code_exactly_24576_bytes_is_allowed",
        "24576 bytes justos SI entran (el chequeo es >, no >=). El deposito "
        "cuesta 200 x 24576 = 4915200 de gas, asi que la tx necesita un "
        "limite grande.",
        pre_with_main(
            cat(
                create_call(deployer_zeros(24576)),
                store_address_plus_one(0),
                STOP,
            )
        ),
        gas_limit="0x5b8d80",
    ),
    case(
        "code_deposit_without_enough_gas_is_out_of_gas",
        "El initcode devuelve 20000 bytes: el deposito son 200 x 20000 = "
        "4.000.000 de gas, mas de lo que el 63/64 le pudo reenviar. EIP-2 "
        "punto 3: la creacion falla con OOG en vez de dejar un contrato "
        "vacio. Se pierde TODO el gas del sub-frame, pero MAIN sobrevive con "
        "su 1/64 y registra el 0.",
        pre_with_main(
            cat(
                create_call(deployer_zeros(20000)),
                store_address_plus_one(0),
                STOP,
            )
        ),
        gas_limit="0x1b7740",
    ),
)

# --- 4. Resultado del initcode: revert / halt / anidado --------------------
REVERTING_INITCODE = cat(
    push_int(0xAA), push_int(0), MSTORE, push_int(1), push_int(31), REVERT
)

add(
    "create-outcomes.json",
    case(
        "a_reverting_initcode_pushes_zero_and_leaves_the_revert_reason_as_returndata",
        "El initcode revierte con 1 byte (0xAA). El caller pushea 0, RECUPERA "
        "el gas no consumido y ve la razon de revert en RETURNDATA (EIP-211): "
        "slot 1 = RETURNDATASIZE + 1, slot 2 = el byte copiado.",
        pre_with_main(
            cat(
                create_call(REVERTING_INITCODE),
                store_address_plus_one(0),
                RETURNDATASIZE,
                push_int(1),
                ADD,
                push_int(1),
                SSTORE,
                push_int(1),  # length
                push_int(0),  # offset
                push_int(0),  # dest
                RETURNDATACOPY,
                push_int(0),
                MLOAD,
                push_int(2),
                SSTORE,
                STOP,
            )
        ),
    ),
    case(
        "a_halting_initcode_pushes_zero_burns_the_gas_and_leaves_no_returndata",
        "El initcode ejecuta INVALID (0xFE): halt. El caller pushea 0, NO "
        "recupera nada del gas reenviado y RETURNDATA queda VACIA (a "
        "diferencia del revert).",
        pre_with_main(
            cat(
                create_call(INVALID),
                store_address_plus_one(0),
                RETURNDATASIZE,
                push_int(1),
                ADD,
                push_int(1),
                SSTORE,
                STOP,
            )
        ),
        gas_limit=GAS_TWO_SLOTS_AFTER_BURN,
    ),
    case(
        "a_successful_create_leaves_no_returndata",
        "Un CREATE exitoso deja RETURNDATA VACIA: el output del initcode es "
        "CODIGO desplegado, no data (EIP-211). Slot 1 = 1 (0 + 1).",
        pre_with_main(
            cat(
                create_call(WITNESS_INITCODE),
                store_address_plus_one(0),
                RETURNDATASIZE,
                push_int(1),
                ADD,
                push_int(1),
                SSTORE,
                STOP,
            )
        ),
    ),
    case(
        "a_failed_create_still_leaves_the_derived_address_warm",
        "El initcode revierte, pero la direccion derivada QUEDA WARM: revm la "
        "carga (EIP-2929) ANTES de tomar el checkpoint de la creacion, asi "
        "que el revert no la enfria. MAIN hace EXTCODESIZE de esa direccion "
        "(0xA6E7... = create(MAIN, 1), precomputada) y el EXTCODESIZE cuesta "
        "100 y no 2600 -- el diferencial lo ve en gas_used.",
        pre_with_main(
            cat(
                create_call(REVERTING_INITCODE),
                store_address_plus_one(0),
                push("a6e7b03d660b0872b54f955e533db53050e7c994"),
                EXTCODESIZE,
                push_int(1),
                ADD,
                push_int(1),
                SSTORE,
                STOP,
            )
        ),
    ),
    case(
        "a_nested_create_that_reverts_is_invisible_to_the_grandparent",
        "El initcode del hijo hace un CREATE (nieto) y despues REVIERTE: ni "
        "el nieto ni el hijo quedan en el post-state, y el nonce del hijo "
        "(bumpeado por el CREATE del nieto) desaparece con el revert. Lo "
        "unico que sobrevive es el bump del nonce de MAIN.",
        pre_with_main(
            cat(
                create_call(
                    cat(
                        create_call(WITNESS_INITCODE),
                        push_int(0),
                        push_int(0),
                        REVERT,
                    )
                ),
                store_address_plus_one(0),
                STOP,
            )
        ),
    ),
)

# --- 5. CREATE en contexto estatico ---------------------------------------
add(
    "create-static.json",
    case(
        "create_inside_a_static_context_halts",
        "MAIN hace STATICCALL a PROXY, que hace CREATE: EIP-214 lo haltea "
        "ANTES de tocar el stack. El STATICCALL devuelve 0 (slot 0 = 1) y "
        "MAIN sobrevive.",
        pre_with_main(
            cat(
                push_int(0),  # retLen
                push_int(0),  # retOff
                push_int(0),  # argLen
                push_int(0),  # argOff
                push(PROXY[2:]),
                push("ea60"),
                STATICCALL,
                store_address_plus_one(0),
                STOP,
            ),
            extra={
                PROXY: account(
                    1,
                    "0x0",
                    "0x" + cat(create_call(WITNESS_INITCODE), push_int(0), SSTORE, STOP),
                )
            },
        ),
    ),
    case(
        "selfdestruct_inside_a_static_context_halts",
        "Mismo esquema con SELFDESTRUCT: EIP-214 lo haltea antes de popear "
        "el beneficiary. PROXY sigue vivo y con su codigo.",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                push("ea60"),
                STATICCALL,
                store_address_plus_one(0),
                STOP,
            ),
            extra={
                PROXY: account(1, "0x64", "0x" + selfdestruct_runtime(OTHER)),
                OTHER: account(0, "0x01"),
            },
        ),
    ),
)

# --- 6. SELFDESTRUCT (EIP-6780) -------------------------------------------
add(
    "selfdestruct.json",
    case(
        "selfdestruct_of_an_account_created_in_the_same_tx_destroys_it",
        "MAIN crea un contrato cuyo runtime es SELFDESTRUCT(OTHER) y lo "
        "llama en la MISMA tx: EIP-6780 lo destruye ENTERO (desaparece del "
        "post-state) y su balance va a OTHER.",
        pre_with_main(
            cat(
                create_call(deployer(selfdestruct_runtime(OTHER)), value=0x64),
                DUP1,
                store_address_plus_one(0),
                plain_call(),
                push_int(1),
                ADD,
                push_int(1),
                SSTORE,
                STOP,
            ),
            main_balance="0x3e8",
            extra={OTHER: account(0, "0x01")},
        ),
    ),
    case(
        "selfdestruct_of_a_preexisting_account_only_moves_the_balance",
        "OTRO contrato ya existente ejecuta SELFDESTRUCT: EIP-6780 (Cancun+) "
        "lo deja VIVO -- codigo y storage intactos -- y solo mueve el "
        "balance. Este es el caso NUEVO de 6780.",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                GAS,
                CALL,
                push_int(1),
                ADD,
                push_int(0),
                SSTORE,
                STOP,
            ),
            extra={
                PROXY: account(
                    1, "0x64", "0x" + selfdestruct_runtime(OTHER), {"0x01": "0x07"}
                ),
                OTHER: account(0, "0x01"),
            },
        ),
    ),
    case(
        "selfdestruct_to_self_of_an_account_created_in_the_same_tx_burns_the_balance",
        "El contrato creado en esta tx se autodestruye con beneficiary == el "
        "mismo: el transfer es un no-op y la destruccion QUEMA el saldo.",
        pre_with_main(
            cat(
                create_call(deployer(cat("30", SELFDESTRUCT)), value=0x64),
                DUP1,
                store_address_plus_one(0),
                plain_call(),
                push_int(1),
                ADD,
                push_int(1),
                SSTORE,
                STOP,
            ),
            main_balance="0x3e8",
        ),
    ),
    case(
        "selfdestruct_to_self_of_a_preexisting_account_is_a_no_op",
        "Contrato preexistente con beneficiary == el mismo: no se crea ni se "
        "destruye nada y el balance queda donde estaba (EIP-6780).",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                GAS,
                CALL,
                push_int(1),
                ADD,
                push_int(0),
                SSTORE,
                STOP,
            ),
            extra={PROXY: account(1, "0x64", "0x" + cat("30", SELFDESTRUCT))},
        ),
    ),
    case(
        "selfdestruct_with_a_cold_beneficiary_pays_the_2600_surcharge",
        "Beneficiary FRIO: 5000 + 2600. Comparar el gas_used con el caso "
        "warm de abajo (mismo programa salvo el BALANCE previo).",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                GAS,
                CALL,
                push_int(1),
                ADD,
                push_int(0),
                SSTORE,
                STOP,
            ),
            extra={
                PROXY: account(1, "0x64", "0x" + selfdestruct_runtime(OTHER)),
                OTHER: account(0, "0x01"),
            },
        ),
    ),
    case(
        "selfdestruct_with_a_warm_beneficiary_pays_no_surcharge",
        "Igual que el anterior pero PROXY hace BALANCE(OTHER) primero: el "
        "beneficiary queda warm y SELFDESTRUCT paga 5000 pelados -- a "
        "diferencia de BALANCE/EXTCODE*, NO hay un cargo warm aparte.",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                GAS,
                CALL,
                push_int(1),
                ADD,
                push_int(0),
                SSTORE,
                STOP,
            ),
            extra={
                PROXY: account(
                    1,
                    "0x64",
                    "0x"
                    + cat(
                        push(OTHER[2:]),
                        BALANCE,
                        "50",  # POP
                        selfdestruct_runtime(OTHER),
                    ),
                ),
                OTHER: account(0, "0x01"),
            },
        ),
    ),
    case(
        "selfdestruct_to_a_dead_account_with_balance_pays_g_newaccount",
        "Beneficiary MUERTO (EIP-161: inexistente) y la cuenta tiene balance "
        "> 0: se suman los 25000 de G_newaccount ademas del cold. El "
        "beneficiary nace con el balance transferido.",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                GAS,
                CALL,
                push_int(1),
                ADD,
                push_int(0),
                SSTORE,
                STOP,
            ),
            extra={PROXY: account(1, "0x64", "0x" + selfdestruct_runtime(DEAD))},
        ),
    ),
    case(
        "selfdestruct_to_a_dead_account_without_balance_pays_no_g_newaccount",
        "Mismo caso con balance 0: NO se cobran los 25000 (la condicion es "
        "had_value && !target_exists) y el beneficiary muerto no nace.",
        pre_with_main(
            cat(
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push_int(0),
                push(PROXY[2:]),
                GAS,
                CALL,
                push_int(1),
                ADD,
                push_int(0),
                SSTORE,
                STOP,
            ),
            extra={PROXY: account(1, "0x0", "0x" + selfdestruct_runtime(DEAD))},
        ),
    ),
    case(
        "selfdestruct_in_the_constructor_destroys_the_contract_immediately",
        "El initcode mismo hace SELFDESTRUCT: la cuenta se creo en esta tx, "
        "asi que se destruye. El CREATE igual reporta exito (SELFDESTRUCT "
        "termina como STOP: output vacio, codigo desplegado vacio).",
        pre_with_main(
            cat(
                create_call(cat(push(OTHER[2:]), SELFDESTRUCT), value=0x64),
                store_address_plus_one(0),
                STOP,
            ),
            main_balance="0x3e8",
            extra={OTHER: account(0, "0x01")},
        ),
    ),
)

# --- 7. Tx de creacion top-level ------------------------------------------
add(
    "create-tx.json",
    case(
        "a_top_level_create_transaction_deploys_the_contract",
        "Tx con to == null: el initcode es tx.input y corre como frame de "
        "creacion en profundidad 0. La direccion sale de (sender, tx.nonce) y "
        "el nonce del sender queda en 1 (un solo bump, no dos). El gas "
        "intrinseco incluye G_txcreate (32000) + el termino EIP-3860.",
        {SENDER: account(0, "0x3635c9adc5dea00000")},
        to="",
        data="0x" + WITNESS_INITCODE,
    ),
    case(
        "a_top_level_create_transaction_with_value_funds_the_contract",
        "Igual con value: el contrato nuevo nace con el balance.",
        {SENDER: account(0, "0x3635c9adc5dea00000")},
        to="",
        data="0x" + WITNESS_INITCODE,
        value="0x64",
    ),
    case(
        "a_top_level_create_transaction_whose_initcode_reverts_keeps_the_nonce_bump",
        "El initcode de la tx revierte: no queda contrato, pero el bump del "
        "nonce del sender persiste (ocurre fuera del checkpoint de la "
        "creacion) y se cobra el gas consumido.",
        {SENDER: account(0, "0x3635c9adc5dea00000")},
        to="",
        data="0x" + REVERTING_INITCODE,
    ),
    case(
        "a_top_level_create_transaction_onto_an_address_with_code_collides",
        "La direccion derivada de (sender, nonce 0) YA tiene codigo: "
        "colision. La tx haltea consumiendo TODO su gas y no despliega nada. "
        "Mitad 1 de la regla `code_hash != KECCAK_EMPTY || nonce != 0`.",
        {
            SENDER: account(0, "0x3635c9adc5dea00000"),
            # keccak(rlp([SENDER, 0]))[12..], precomputado con alloy (ver el
            # unit test `create_derives_the_address_from_the_creator_nonce`).
            DERIVED_FROM_SENDER: account(0, "0x0", "0x" + WITNESS_RUNTIME),
        },
        to="",
        data="0x" + WITNESS_INITCODE,
    ),
    case(
        "a_top_level_create_transaction_onto_an_address_with_a_nonce_collides",
        "La direccion derivada NO tiene codigo pero SI nonce != 0 (una EOA "
        "que ya mando txs): tambien colisiona. Mitad 2 de la regla.",
        {
            SENDER: account(0, "0x3635c9adc5dea00000"),
            DERIVED_FROM_SENDER: account(1, "0x0"),
        },
        to="",
        data="0x" + WITNESS_INITCODE,
    ),
    case(
        "a_top_level_create_transaction_onto_a_prefunded_address_succeeds",
        "La direccion derivada tiene SOLO balance (nonce 0, sin codigo): NO "
        "es colision -- se le puede mandar ETH a una direccion contrafactual "
        "antes de desplegar. El contrato nace conservando ese balance.",
        {
            SENDER: account(0, "0x3635c9adc5dea00000"),
            DERIVED_FROM_SENDER: account(0, "0x1e"),
        },
        to="",
        data="0x" + WITNESS_INITCODE,
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
