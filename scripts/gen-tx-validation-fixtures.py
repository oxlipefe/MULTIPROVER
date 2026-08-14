#!/usr/bin/env python3
"""Genera cmd/conformance/fixtures/diff/tx-validation/*.json.

Este slice agrega RECHAZOS (gating por fork de los tipos 3/4, tope de blobs,
to==None en tipo 4, EIP-2681). Una tx rechazada no produce post-state, asi que
el diferencial compara dos motores que no ejecutaron nada -- es facil que de
[SAME] por vacuidad. **El juez de los rechazos es EEST**, que chequea las tres
direcciones.

Lo que este set cubre es el BORDE: la tx VALIDA mas cercana a cada limite, que
si ejecuta y si tiene post-state. Un gateo que se pase de rosca (que rechace lo
bueno) es peor que el bug original, y estos son los casos que lo cazan.

    FIXTURE_DIR=cmd/conformance/fixtures/diff/tx-validation python3 scripts/gen-tx-validation-fixtures.py
"""
import json
import os

SENDER = "0x" + "a0" * 20
RECEIVER = "0x" + "b0" * 20
COINBASE = "0x" + "c0" * 20
DELEGATE = "0x" + "d0" * 20
# Autoridad fresca: NO el sender. La tx bumpea el nonce del sender ANTES
# de aplicar autorizaciones, asi que una tupla con `authority: SENDER` y
# `nonce: 0` se saltea por el chequeo de NONCE y enmascara lo que el caso
# dice probar. Es el mismo enmascaramiento que ya mordio en 2.7c.
AUTHORITY = "0x" + "f0" * 20

RICH = "0x3635c9adc5dea00000"

# Topes por fork: EIP-4844 (Cancun) = 2 x target(3) = 6; EIP-7691 (Prague) = 9.
MAX_BLOBS = {"Cancun": 6, "Prague": 9}


def account(nonce=0, balance="0x0", code="0x", storage=None):
    return {
        "nonce": hex(nonce) if not isinstance(nonce, str) else nonce,
        "balance": balance,
        "code": code,
        "storage": storage or {},
    }


def kzg_hash(tag):
    return "0x01" + "%02x" % tag + "00" * 30


def base_env():
    return {
        "currentCoinbase": COINBASE,
        "currentNumber": "0x01",
        "currentTimestamp": "0x03e8",
        "currentGasLimit": "0x01c9c380",
        "currentBaseFee": "0x0a",
        "currentRandom": "0x" + "00" * 32,
        "currentExcessBlobGas": "0x00",
    }


def case(name, comment, tx_extra, forks, pre=None, nonce="0x00"):
    tx = {
        "sender": SENDER,
        "to": RECEIVER,
        "nonce": nonce,
        "gasPrice": "0x0c",
        "data": ["0x"],
        "gasLimit": ["0x0f4240"],
        "value": ["0x0"],
        "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
    }
    # `None` significa BORRAR el campo, no escribir null: una tx 1559/4844 no
    # lleva `gasPrice`, y dejarlo puesto (o mandarlo como null) la vuelve
    # malformada. Este mismo descuido hizo fallar 4 de 8 corridas la primera
    # vez que se corrio el set.
    for key, value in tx_extra.items():
        if value is None:
            tx.pop(key, None)
        else:
            tx[key] = value
    return name, {
        "_comment": comment,
        "env": base_env(),
        "config": {"chainid": "0x01"},
        "pre": pre or {SENDER: account(0, RICH)},
        "transaction": tx,
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


def blob_fields(count):
    return {
        "gasPrice": None,
        "maxFeePerGas": "0x14",
        "maxPriorityFeePerGas": "0x03",
        "maxFeePerBlobGas": "0x01",
        "blobVersionedHashes": [kzg_hash(i) for i in range(count)],
    }


BLOB_BORDER = [
    case(
        f"exactly_{MAX_BLOBS[fork]}_blobs_is_the_limit_and_is_valid_in_{fork.lower()}",
        f"EL BORDE, del lado bueno: {MAX_BLOBS[fork]} blobs es EXACTAMENTE el tope "
        f"de {fork} y la tx es VALIDA. El tope cambia con el fork (6 en Cancun por "
        "EIP-4844, 9 en Prague por EIP-7691), asi que hardcodear uno solo rechaza "
        "txs buenas en el otro -- y rechazar lo bueno es peor que el bug original. "
        "El caso de tope+1 lo juzga EEST, no este set: una tx rechazada no deja "
        "post-state que comparar.",
        blob_fields(MAX_BLOBS[fork]),
        [fork],
    )
    for fork in ("Cancun", "Prague")
]

TYPE_BORDER = [
    case(
        "a_blob_tx_is_valid_from_cancun_onwards",
        "La reciproca del gateo por fork: el tipo 3 EXISTE desde Cancun, asi que "
        "en Cancun y Prague tiene que ejecutar normal. Si el gateo se pasa de "
        "rosca, este caso se cae.",
        blob_fields(1),
        ["Cancun", "Prague"],
    ),
    case(
        "a_set_code_tx_is_valid_from_prague_onwards",
        "Idem para el tipo 4: existe desde Prague. Corre en un solo fork porque "
        "Prague es el ultimo en scope -- su contraparte (rechazo en Cancun) la "
        "juzga EEST.",
        {
            "gasPrice": None,
            "maxFeePerGas": "0x14",
            "maxPriorityFeePerGas": "0x03",
            "authorizationList": [
                {
                    "chainId": "0x01",
                    "address": DELEGATE,
                    "nonce": "0x00",
                    "authority": RECEIVER,
                }
            ],
        },
        ["Prague"],
    ),
]

NONCE_BORDER = [
    case(
        "a_nonce_one_below_the_u64_limit_is_valid_and_bumps_to_the_limit",
        "EIP-2681 rechaza `nonce == u64::MAX`. Su VECINO -- u64::MAX - 1 -- es "
        "valido, ejecuta, y al bumpearse deja el nonce exactamente en u64::MAX. "
        "Es el borde del lado bueno: un chequeo con >= en vez de == rechazaria "
        "esta tx, y eso no se ve en ningun caso de rechazo.",
        {"nonce": "0xfffffffffffffffe"},
        ["Paris", "Prague"],
        pre={SENDER: account("0xfffffffffffffffe", RICH)},
        nonce="0xfffffffffffffffe",
    ),
]

AUTH_SIGNATURE = [
    case(
        "an_authorization_with_s_out_of_range_is_skipped_not_fatal",
        "EIP-2 aplicado a EIP-7702: una tupla con `s > secp256k1n/2` no recupera "
        "y se SALTEA -- no invalida la tx. Aca van dos tuplas: la primera con `s` "
        "fuera de rango (se saltea, pero igual cuesta sus 25000 de gas "
        "intrinseco por estar DECLARADA) y la segunda valida (se aplica). El "
        "post-state muestra las dos mitades: el gas cobrado por ambas y la "
        "delegacion de una sola. La segunda tupla usa una autoridad FRESCA y no "
        "el sender: con el sender, el bump de nonce de la tx la saltearia por el "
        "chequeo de nonce y el caso pasaria sin probar nada (lo destapo la "
        "auditoria de post-state, gas 71000 con cero delegaciones aplicadas).",
        {
            "gasPrice": None,
            "maxFeePerGas": "0x14",
            "maxPriorityFeePerGas": "0x03",
            "authorizationList": [
                {
                    "chainId": "0x01",
                    "address": DELEGATE,
                    "nonce": "0x00",
                    "signer": RECEIVER,
                    # s = secp256k1n/2 + 1: fuera de rango por exactamente 1.
                    "s": "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
                    "r": "0x01",
                    "yParity": "0x00",
                },
                {
                    "chainId": "0x01",
                    "address": DELEGATE,
                    "nonce": "0x00",
                    "authority": AUTHORITY,
                },
            ],
        },
        ["Prague"],
    ),
]

FILES = {
    "blob-limit.json": BLOB_BORDER,
    "tx-type.json": TYPE_BORDER,
    "nonce.json": NONCE_BORDER,
    "auth-signature.json": AUTH_SIGNATURE,
}


def main():
    out_dir = os.environ.get("FIXTURE_DIR", "cmd/conformance/fixtures/diff/tx-validation")
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
