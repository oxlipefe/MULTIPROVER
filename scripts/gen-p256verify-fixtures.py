#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/p256verify/*.json.

Mismo criterio que los otros generadores del set diferencial: los fixtures
estan versionados y este script existe para que sean REPRODUCIBLES. El oraculo
es revm, no este archivo (`hash`/`logs` van en cero a proposito).

Lo que este set ejercita: P256VERIFY (`0x0000...0100`, EIP-7951, Osaka).

  * El VEREDICTO. Un vector valido publica 32 bytes con un 1 al final; todo
    fallo publica output VACIO con el mismo gas cobrado, y el CALL nunca
    revierte.
  * Los BORDES de la politica: largo exacto 160 (sin right-pad), `r,s` en
    `(0,n)`, `qx,qy < p`, punto en la curva, punto al infinito.
  * Que un `s` ALTO se ACEPTA. No hay regla low-s en EIP-7951, y es el unico
    caso del set donde normalizar `s` -- lo correcto en secp256k1 -- seria
    una divergencia de consenso.
  * El GAS: 6900 flat, medido con un delta de GAS alrededor del CALL, y los
    dos bordes (6899 reenviados = OOG del sub-frame, 6901 = exito).
  * El FORK: en Prague `0x0100` es una cuenta vacia, y ni siquiera arranca
    warm. Ese par de casos lleva `post` en dos forks -- si el motor no gateara,
    los dos darian lo mismo y el caso no probaria nada.

Cada caso guarda CUATRO observables: status del CALL, RETURNDATASIZE, la
palabra devuelta y el GAS que le queda al caller. El ultimo no es decorativo:
un fixture donde el caller muere despues del CALL deja de probar lo que dice,
y eso ya paso dos veces en este repo.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/p256verify python3 scripts/gen-p256verify-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
MAIN = "0x" + "b0" * 20  # el contrato que llama
COINBASE = "0x" + "c0" * 20

P256VERIFY = "0x" + "00" * 18 + "0100"

# Parametros de la curva P-256 (NIST prime256v1 / secp256r1).
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# El vector conocido-bueno del propio EIP-7951 (derivado de Wycheproof).
EIP_MSG = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
EIP_R = "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18"
EIP_S = "4cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76"
EIP_QX = "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838"
EIP_QY = "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e"

# Un segundo vector valido, de otra fuente (la bateria que revm usa para este
# mismo precompile, de origen daimo-eth/p256-verifier). Dos fuentes y no una:
# un solo vector no distingue "la curva esta bien" de "el vector y el bug se
# cancelan".
ALT = (
    "4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4d"
    "a73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac"
    "36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d60"
    "4aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff3"
    "7618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"
)
ALT_WORDS = [ALT[i : i + 64] for i in range(0, 320, 64)]

ZERO = "00" * 32


def word(value):
    return "%064x" % value


# `s` complementario: `n - s`. Es la MISMA firma vista desde el otro lado, y
# las dos tienen que verificar. Se calcula, no se transcribe -- un valor
# copiado probaria que ese valor verifica, no que la regla no existe.
EIP_S_COMPLEMENT = word(N - int(EIP_S, 16))
assert (int(EIP_S, 16) > N // 2) != (int(EIP_S_COMPLEMENT, 16) > N // 2), (
    "uno de los dos `s` tiene que caer en la mitad alta, o el caso es vacuo"
)

# Un punto que NO esta en la curva: mismas coordenadas validas, un bit menos.
OFF_CURVE_QY = word(int(EIP_QY, 16) ^ 1)

VALID = [EIP_MSG, EIP_R, EIP_S, EIP_QX, EIP_QY]

# ---------------------------------------------------------------- ensamblador

STOP = "00"
ADD = "01"
SUB = "03"
MLOAD = "51"
MSTORE = "52"
SSTORE = "55"
GAS = "5a"
SWAP1 = "90"
CALL = "f1"

# Donde el CALL deposita el output. **Ancho auto**, nunca fijo: un offset
# mayor a 255 codificado con ancho 1 corrompe el bytecode en silencio y los dos
# motores coinciden en el escenario equivocado.
RET_OFFSET = 0x0100


def push(value_hex):
    n = len(value_hex) // 2
    assert 1 <= n <= 32, value_hex
    return "%02x" % (0x60 + n - 1) + value_hex


def push_int(value):
    """PUSH del ancho MINIMO que alcanza. Que el ancho salga del valor y no de
    un parametro es lo que hace imposible el truncamiento."""
    assert 0 <= value < (1 << 256), value
    raw = "%x" % value
    if len(raw) % 2:
        raw = "0" + raw
    return push(raw)


def push_addr(addr):
    return push(addr[2:])


def cat(*parts):
    return "".join(parts)


def store_top_plus_one(slot):
    """Guarda `tope + 1`: un 0 no existe en el trie, asi que sin el +1 un slot
    ausente no distinguiria "fallo" de "no corrio"."""
    return cat(push_int(1), ADD, push_int(slot), SSTORE)


def store_top(slot):
    return cat(push_int(slot), SSTORE)


TX_GAS_LIMIT = "0x0f4240"  # 1_000_000
# Gas reenviado al CALL en los casos que no miden el borde: sobra para el
# precompile y deja al caller con margen para las SSTORE de despues, en exito
# Y en fallo. La leccion de dos slices anteriores: un CALL que puede llevarse
# casi todo el presupuesto hace HALTEAR la tx entera y el fixture deja de
# probar lo que dice.
FORWARDED_GAS = 50_000

SLOT_STATUS = 1
SLOT_RETSIZE = 2
SLOT_WORD = 3
SLOT_GAS_LEFT = 4
SLOT_CALL_COST = 5


def store_input(words):
    """Deja los 32·len(words) bytes del input en memoria, desde el offset 0."""
    parts = []
    for i, w in enumerate(words):
        assert len(w) == 64, w
        parts.append(push(w))
        parts.append(push_int(i * 32))
        parts.append(MSTORE)
    return cat(*parts)


def call(arg_length, forwarded_gas=FORWARDED_GAS, value=0):
    return cat(
        push_int(32),  # ret_length
        push_int(RET_OFFSET),  # ret_offset
        push_int(arg_length),
        push_int(0),  # arg_offset
        push_int(value),
        push_addr(P256VERIFY),
        push_int(forwarded_gas),
        CALL,
    )


def record():
    """Los cuatro observables, en el orden en que quedan en el stack."""
    return cat(
        store_top_plus_one(SLOT_STATUS),
        "3d",  # RETURNDATASIZE
        store_top_plus_one(SLOT_RETSIZE),
        push_int(RET_OFFSET),
        MLOAD,
        store_top_plus_one(SLOT_WORD),
        GAS,
        store_top(SLOT_GAS_LEFT),
    )


def program(words, arg_length=160, forwarded_gas=FORWARDED_GAS, value=0):
    return cat(
        store_input(words),
        call(arg_length, forwarded_gas, value),
        record(),
    )


def program_measuring_cost(words):
    """Igual que `program` pero con un delta de GAS alrededor del CALL.

    La ventana de medicion NO incluye ninguna SSTORE: el status se guarda
    DESPUES de cerrar el delta. Con la SSTORE adentro, el numero medido sale
    ~29 000 y el caso ya no dice "6900 flat" sino "6900 mas los 20 000 de
    escribir un slot", que es una afirmacion distinta y peor.

    Lo que queda adentro es el CALL, un SWAP1 y un GAS: overhead fijo,
    identico en los dos motores. Lo unico que puede mover el numero es el
    precio del precompile."""
    return cat(
        store_input(words),
        GAS,  # [g0]
        call(160),  # [g0, status]
        SWAP1,  # [status, g0]
        GAS,  # [status, g0, g1]
        SWAP1,  # [status, g1, g0]
        SUB,  # [status, g0 - g1]
        store_top(SLOT_CALL_COST),  # [status]
        store_top_plus_one(SLOT_STATUS),
        GAS,
        store_top(SLOT_GAS_LEFT),
    )


def measure_access_cost(addr, slot):
    """Costo de tocar `addr` con BALANCE, medido con GAS antes y despues.

    No cambia el resultado de nada: cambia el GAS. Cold 2600 vs warm 100 es la
    mitad del bug que un post-state de solo-resultado no muestra."""
    return cat(
        GAS,
        push_addr(addr),
        "31",  # BALANCE
        "50",  # POP
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


def case(name, comment, code, forks=("Osaka",), main_balance="0x0"):
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
        "pre": {
            SENDER: account(0, RICH),
            MAIN: account(1, main_balance, "0x" + code),
        },
        "transaction": {
            "sender": SENDER,
            "to": MAIN,
            "nonce": "0x00",
            "gasPrice": "0x0c",
            "data": ["0x"],
            "gasLimit": [TX_GAS_LIMIT],
            "value": ["0x0"],
            "secretKey": (
                "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
            ),
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


def replaced(index, value):
    words = list(VALID)
    words[index] = value
    return words


# ------------------------------------------------------------------- los casos

VALID_CASES = [
    case(
        "verifies_the_vector_of_the_eip",
        "El vector conocido-bueno del propio EIP-7951. Exito: status 1, "
        "RETURNDATASIZE 32 y la palabra devuelta es 0x...01. Es el unico caso "
        "del set que publica output, asi que tambien es el que distingue "
        "'verifica' de 'no verifica' -- todo lo demas publica vacio.",
        program(VALID),
    ),
    case(
        "verifies_a_vector_from_a_second_source",
        "Otro vector valido, de origen independiente del anterior. Dos fuentes "
        "y no una: un solo vector no separa 'la curva esta bien' de 'el vector "
        "y el bug se cancelan'.",
        program(ALT_WORDS),
    ),
    case(
        "accepts_a_high_s_because_there_is_no_low_s_rule",
        "EL CASO QUE DEFINE EL SLICE. Mismo vector con `s` reemplazado por "
        "`n - s`, que es la MISMA firma vista desde el otro lado. EIP-7951 NO "
        "tiene regla low-s, asi que tiene que verificar igual. Normalizar `s` "
        "-- lo correcto en la recuperacion de secp256k1 -- aca seria rechazar "
        "una firma que el protocolo acepta, y este caso es el unico que lo "
        "canta.",
        program(replaced(2, EIP_S_COMPLEMENT)),
    ),
]

INVALID_CASES = [
    case(
        "rejects_an_input_of_159_bytes",
        "Largo EXACTO, sin right-pad: un byte de menos no se completa con "
        "ceros. La memoria tiene los 160 bytes buenos y el CALL pasa 159. "
        "Exito con output VACIO y los 6900 cobrados igual.",
        program(VALID, arg_length=159),
    ),
    case(
        "rejects_an_input_of_161_bytes",
        "La otra mitad del largo exacto: un byte de mas tampoco se trunca. El "
        "byte 161 sale de memoria sin escribir, que es cero.",
        program(VALID, arg_length=161),
    ),
    case(
        "rejects_r_equal_to_zero",
        "`r` tiene que estar en el intervalo ABIERTO (0, n). El cero es el "
        "borde de abajo.",
        program(replaced(1, ZERO)),
    ),
    case(
        "rejects_r_equal_to_n",
        "El borde de arriba, y el que un `<=` mal puesto dejaria pasar: `r = n` "
        "se rechaza. RIP-7212 tenia aca uno de sus dos bugs (aceptaba `r' = r "
        "mod n`), y EIP-7951 lo corrige.",
        program(replaced(1, word(N))),
    ),
    case(
        "rejects_s_equal_to_n",
        "Lo mismo para `s`. Que este caso y el de arriba existan por separado "
        "es lo que separa 'se chequea el rango' de 'se chequea el rango de "
        "uno de los dos'.",
        program(replaced(2, word(N))),
    ),
    case(
        "rejects_qx_equal_to_p",
        "Una coordenada tiene que ser un elemento del campo: `qx < p`. Igualar "
        "`p` es el borde exacto, no un valor grande cualquiera.",
        program(replaced(3, word(P))),
    ),
    case(
        "rejects_a_point_that_is_not_on_the_curve",
        "Coordenadas que son elementos validos del campo pero que no satisfacen "
        "la ecuacion de la curva (`qy` con el bit de abajo invertido). Es la "
        "regla que el motor NO chequea por su cuenta: la contesta la curva.",
        program(replaced(4, OFF_CURVE_QY)),
    ),
    case(
        "rejects_the_point_at_infinity",
        "`(0, 0)` es el unico modo que la codificacion sin prefijo le deja al "
        "punto al infinito, y EIP-7951 lo nombra explicitamente: se rechaza. Es "
        "el otro bug que RIP-7212 tenia y que este EIP corrige.",
        program([EIP_MSG, EIP_R, EIP_S, ZERO, ZERO]),
    ),
    case(
        "rejects_a_signature_over_another_message",
        "El modo de fallo que no es de formato ni de curva: todo bien formado, "
        "y la firma no corresponde a este hash. Sin este caso el set probaria "
        "el parser y no la verificacion.",
        program(replaced(0, word(int(EIP_MSG, 16) ^ 1))),
    ),
]

GAS_CASES = [
    case(
        "the_measured_cost_of_the_call_is_flat",
        "Mide con GAS el costo del CALL entero. El delta lleva adentro el "
        "overhead fijo de los opcodes de medicion y el acceso warm a la "
        "direccion, que son identicos en los dos motores: lo unico que puede "
        "moverlo es el precio del precompile. Es el observable que pincha los "
        "6900 de EIP-7951 contra los 3450 de RIP-7212.",
        program_measuring_cost(VALID),
    ),
    case(
        "a_call_forwarding_one_gas_short_runs_out_of_gas",
        "Con 6899 reenviados el precompile no puede correr: el sub-frame se "
        "queda sin gas y el CALL devuelve 0. No es 'exito con output vacio' -- "
        "esa es la otra familia de fallos, y distinguirlas es la mitad del "
        "contrato. El caller sobrevive y guarda sus cuatro observables.",
        program(VALID, forwarded_gas=6_899),
    ),
    case(
        "a_call_forwarding_one_gas_over_succeeds",
        "El borde de al lado: con 6901 el precompile corre y verifica. Los dos "
        "casos juntos son los que fijan el numero; uno solo diria 'alcanza' o "
        "'no alcanza', nunca cual es.",
        program(VALID, forwarded_gas=6_901),
    ),
    case(
        "a_call_with_value_leaves_the_caller_with_gas",
        "CALL con `value > 0` a la precompile: paga los 9000 de transferencia y "
        "recibe el stipend de 2300. Esta aca por una trampa medida: un stipend "
        "puede RESCATAR un vector que se creia caro, asi que un caso 'sin gas' "
        "que lleve value no prueba lo que dice. Aca el value es explicito y el "
        "gas que le queda al caller se guarda.",
        program(VALID, value=1),
        main_balance="0x0de0b6b3a7640000",
    ),
]

FORK_CASES = [
    case(
        "p256verify_is_an_empty_account_before_osaka",
        "EL MISMO CASO EN DOS FORKS. En Prague `0x0100` no es precompile: el "
        "CALL va a una cuenta vacia, tiene EXITO, RETURNDATASIZE 0 y la palabra "
        "de retorno queda en cero. En Osaka corre P256VERIFY y publica 0x...01. "
        "Si el motor no gateara por fork, los dos forks darian identico y el "
        "caso no probaria nada.",
        program(VALID),
        forks=("Prague", "Osaka"),
    ),
    case(
        "the_access_cost_of_0x0100_crosses_the_osaka_boundary",
        "La mitad que el output no muestra. BALANCE sobre `0x0100`: en Osaka la "
        "direccion es precompile y el prewarming de la tx (EIP-2929) la deja "
        "WARM (100); en Prague todavia no lo es y arranca COLD (2600). Delta de "
        "2500 y cero diferencia en el resultado de nada -- calentar una "
        "direccion un fork antes de que exista es exactamente este recargo "
        "regalado.",
        measure_access_cost(P256VERIFY, SLOT_CALL_COST),
        forks=("Prague", "Osaka"),
    ),
]

FILES = {
    "valid.json": VALID_CASES,
    "invalid.json": INVALID_CASES,
    "gas.json": GAS_CASES,
    "fork.json": FORK_CASES,
}


def main():
    out_dir = os.environ.get("FIXTURE_DIR", "cmd/conformance/fixtures/diff/p256verify")
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
