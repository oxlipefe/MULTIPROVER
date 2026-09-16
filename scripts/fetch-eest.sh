#!/usr/bin/env bash
# Fetch pineado y verificado del release de execution-spec-tests (EEST).
#
# El artefacto NO se vendorea (515 MB): vive en un cache gitignoreado. Este
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
# `ethereum/execution-spec-tests` fue ARCHIVADO el 2026-07-02: los fixtures se
# publican desde entonces en `ethereum/execution-specs`, con tag `tests@vN` y un
# solo asset (`fixtures_stable` ya no existe).
TAG="tests@v20.0.2"
# El `@` del tag se percent-encodea en la URL pero NO en el nombre del cache:
# el directorio se llama igual que el tag, que es lo que pinea el código.
TAG_URL="tests%40v20.0.2"
ASSET="fixtures.tar.gz"
# "Patch Osaka/BPO2 mainnet fixture release for tests@v20.0.0" (2026-08-27).
# Cubre Paris/Cancun/Prague/Osaka; NO Amsterdam.
SHA256="1280540950a4c3470a421416b6f35458a9b635827265c29e5aef1ae839ae1788"
URL="https://github.com/ethereum/execution-specs/releases/download/${TAG_URL}/${ASSET}"

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
  echo "Descargando EEST ${TAG} (${ASSET}, ~515 MB)…"
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
