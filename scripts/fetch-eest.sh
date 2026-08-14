#!/usr/bin/env bash
# Fetch pineado y verificado del release de execution-spec-tests (EEST).
#
# El artefacto NO se vendorea (257 MB): vive en un cache gitignoreado. Este
# script es la materialización de la higiene de content-addressing de
# §1 — el harness consume un artefacto cuyo hash está FIJADO acá, no "lo que
# haya en el release hoy".
#
# Fail-closed: si el sha256 no coincide, aborta. Nunca sigue con un artefacto
# no verificado.
#
# Idempotente: si el cache ya existe y el hash coincide, no re-descarga.
set -euo pipefail

# --- pineo ---
TAG="v5.4.0"
ASSET="fixtures_stable.tar.gz"
# Construido con `--until=Prague` — exactamente el scope de Repo B.
# commit del ref: 4f68564f47c7e577ad6cbb570858316f5ff0e7bb
SHA256="92cf1b47ad12fb27163261fc3c1cea5df72439cab507983d06b56c94f8741909"
URL="https://github.com/ethereum/execution-spec-tests/releases/download/${TAG}/${ASSET}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${EEST_CACHE_DIR:-${REPO_ROOT}/.eest-cache}"
TARBALL="${CACHE_DIR}/${TAG}-${ASSET}"
EXTRACT_DIR="${CACHE_DIR}/${TAG}"
STAMP="${EXTRACT_DIR}/.verified-${SHA256}"

mkdir -p "${CACHE_DIR}"

# Ya extraído y verificado con ESTE hash: nada que hacer.
if [[ -f "${STAMP}" ]]; then
  echo "EEST ${TAG} ya en cache y verificado (${CACHE_DIR})"
  echo "  sha256 = ${SHA256}"
  exit 0
fi

if [[ ! -f "${TARBALL}" ]]; then
  echo "Descargando EEST ${TAG} (${ASSET}, ~257 MB)…"
  curl -sSL --fail -o "${TARBALL}.part" "${URL}"
  mv "${TARBALL}.part" "${TARBALL}"
fi

echo "Verificando sha256…"
if command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "${TARBALL}" | awk '{print $1}')"
else
  ACTUAL="$(sha256sum "${TARBALL}" | awk '{print $1}')"
fi

if [[ "${ACTUAL}" != "${SHA256}" ]]; then
  echo "ERROR: sha256 NO coincide (fail-closed)." >&2
  echo "  esperado: ${SHA256}" >&2
  echo "  obtenido: ${ACTUAL}" >&2
  echo "  archivo:  ${TARBALL}" >&2
  echo "Se borra el artefacto no verificado." >&2
  rm -f "${TARBALL}"
  exit 1
fi

echo "Extrayendo…"
rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"
tar -xzf "${TARBALL}" -C "${EXTRACT_DIR}"
touch "${STAMP}"

echo "EEST ${TAG} listo:"
echo "  tag     = ${TAG}"
echo "  sha256  = ${SHA256}"
echo "  dir     = ${EXTRACT_DIR}"
