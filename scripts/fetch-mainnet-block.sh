#!/usr/bin/env bash
# Un bloque real de mainnet, del archivo público hasta el input del guest, sin
# vendorearlo.
#
# De dónde sale: los inputs `stateless-validator-reth` de
# `0xPolygonHermez/zisk-eth-client` (Apache-2.0), en un commit FIJO. Cada uno
# es un `ZiskStdin` (bloque RLP + `ExecutionWitness` en bincode); se baja, se
# compara contra su sha256 pineado, se reserializa a los dos JSON del
# importador (`conformance --zisk-stdin`) y se importa con el hash del bloque
# como ancla (`conformance --import-block … --expect-block-hash`), que además
# lo ejecuta en el host y exige que el post-state sea el del header.
#
# Qué pinea cada fila: el sha256 dice "es ESTE archivo"; el hash del bloque,
# tomado de nodos públicos (no del archivo), dice "es ESTE bloque de mainnet".
# El importador rechaza un archivo cuyo header no hashea al nombrado.
#
# Uso:
#   bash scripts/fetch-mainnet-block.sh <número> <directorio>
# Deja en <directorio>: el .bin bajado, block.json, witness.json e input.bin.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="0xPolygonHermez/zisk-eth-client"
COMMIT="dfa27ff2e3544fb3c7467499415830d20de2218d"
RUTA="bin/guests/stateless-validator-reth/inputs"

# número · archivo · sha256 del archivo · hash del bloque
PINES="
26235156 mainnet_26235156_91_5_zec_reth.bin 164e87f73ce0cf4db975d8e5b148b6b40d828cdd412d7cf53aeca2c1e2a0123f 0xa9533744986888244d786721fc0506984585de242dc3d4e0db6d8337abe75bc4
26235168 mainnet_26235168_260_29_zec_reth.bin 540e91b0846b81d18d49268456f647c4853f2e5781c7a835c13c5af35b2946c2 0x07cddb3b33def263e86256977358a0313899e16a31aaae2e3444368e68da60c9
"

[[ $# -eq 2 ]] || { echo "uso: fetch-mainnet-block.sh <número> <directorio>" >&2; exit 2; }
NUMERO="$1"
DIR="$2"
read -r _ ARCHIVO SHA HASH <<< "$(awk -v n="$NUMERO" '$1 == n' <<< "$PINES")" || true
if [[ -z "${HASH:-}" ]]; then
  echo "error: el bloque $NUMERO no tiene pin en esta receta." >&2
  exit 2
fi

sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$DIR"
BIN="$DIR/$ARCHIVO"
if [[ ! -f "$BIN" || "$(sha256_de "$BIN")" != "$SHA" ]]; then
  rm -f "$BIN"
  curl -sfL --retry 3 -o "$BIN.partial" \
    "https://raw.githubusercontent.com/$REPO/$COMMIT/$RUTA/$ARCHIVO"
  mv "$BIN.partial" "$BIN"
fi
GOT=$(sha256_de "$BIN")
if [[ "$GOT" != "$SHA" ]]; then
  echo "error: $BIN tiene sha256 $GOT y el pin es $SHA." >&2
  rm -f "$BIN"
  exit 1
fi
echo "[fetch] $ARCHIVO ($(wc -c < "$BIN" | tr -d ' ') B, sha256 el pineado)"

cd "$ROOT"
cargo build --release -q -p conformance
./target/release/conformance --zisk-stdin "$BIN" "$DIR/block.json" "$DIR/witness.json"
./target/release/conformance --import-block "$DIR/block.json" "$DIR/witness.json" \
  "$DIR/input.bin" --expect-block-hash "$HASH"
echo "[fetch] $DIR/input.bin ($(wc -c < "$DIR/input.bin" | tr -d ' ') B, sha256 $(sha256_de "$DIR/input.bin"))"
echo "[fetch] para la receta: --input $DIR/input.bin --expect-block-hash $HASH"
