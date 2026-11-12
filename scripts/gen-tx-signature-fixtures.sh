#!/usr/bin/env bash
# Genera cmd/conformance/fixtures/diff/tx-signature/tx-signature.json.
#
# El set compara el remitente que deriva el guest (decode_2718 + recover)
# contra el de alloy (decode_2718_exact + chequeo de chainId de revm +
# recover_signer, que aplica EIP-2). Los envelopes los arma alloy y los firma
# k256 con RFC 6979: regenerar produce los mismos bytes, y el payload firmado no
# sale del encoder del repo.
#
#     bash scripts/gen-tx-signature-fixtures.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/cmd/conformance/fixtures/diff/tx-signature"
OUT_FILE="${OUT_DIR}/tx-signature.json"

mkdir -p "${OUT_DIR}"
TMP="$(mktemp "${OUT_DIR}/.tx-signature.XXXXXX")"
trap 'rm -f "${TMP}"' EXIT

cargo run --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" -p conformance \
    --features diff-revm -- --gen-tx-signature > "${TMP}"

# Fail-closed: un archivo vacío no reemplaza al set.
if [[ ! -s "${TMP}" ]]; then
    echo "el generador no produjo nada" >&2
    exit 1
fi
mv "${TMP}" "${OUT_FILE}"
trap - EXIT
echo "escrito ${OUT_FILE}"
