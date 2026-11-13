#!/usr/bin/env bash
# Los guests compilan el MISMO motor que juzga EEST, con las MISMAS versiones.
#
# QUÉ REGLA ES ÉSTA
#
# Cada guest concreto (`crates/guest-*`) tiene su propio `[workspace]` y por lo
# tanto su propio `Cargo.lock`. Nada obliga a ese lock a resolver las mismas
# versiones que el de la raíz, que es el que corren los ejes de conformance: un
# `cargo generate-lockfile` adentro de la imagen de un backend toma lo último
# que haya en crates.io. Así, el MPT, el RLP, el MODEXP o el keccak que corre
# una zkVM pueden ser una versión que EEST nunca vio, con todo verde.
#
# La regla: para cada crate de la lista de abajo que aparezca en el lock de un
# guest, TODA versión que ese lock resuelva tiene que existir también en el lock
# de la raíz. Es por nombre y versión; la fuente (un `[patch]` que reemplaza un
# crate) es la regla de `check-crypto-config.sh`, no ésta.
#
# POR QUÉ UNA LISTA Y NO EL GRAFO ENTERO
#
# El lock de un guest mezcla el motor con la plataforma del backend (serde, syn,
# rand de su SDK), y esas versiones no cambian ningún resultado de consenso. La
# lista son los crates cuya lógica decide un byte del resultado: codificación,
# trie, enteros, hashes y curvas.
#
# DIVERGENCIAS DECLARADAS
#
# Una divergencia que no se puede cerrar todavía se declara abajo con su versión
# EXACTA, y se imprime en cada corrida. Otra versión del mismo crate vuelve a
# fallar: la declaración no es un permiso para derivar.
#
# Uso: bash scripts/check-guest-locks.sh [raíz-del-repo]
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

CONSENSO=(
  alloy-primitives alloy-rlp alloy-rlp-derive alloy-trie nybbles ruint
  aurora-engine-modexp blst
  k256 p256 ecdsa elliptic-curve primeorder crypto-bigint
  sha2 sha3 keccak ripemd
  ark-bn254 ark-bls12-381 ark-ec ark-ff ark-poly ark-serialize
)

# `guest crate versión`, una por línea. Vacío = ninguna divergencia aceptada.
DECLARADAS="${GUEST_LOCKS_DECLARADAS-$(cat <<'EOF'
guest-sp1 alloy-primitives 1.6.1
guest-sp1 alloy-rlp 0.3.16
guest-sp1 alloy-rlp-derive 0.3.16
guest-sp1 keccak 0.2.2
guest-sp1 primeorder 0.13.1
guest-openvm alloy-primitives 1.7.1
guest-openvm alloy-rlp 0.3.16
guest-openvm alloy-rlp-derive 0.3.16
guest-openvm keccak 0.2.2
EOF
)}"

# `nombre versión` de cada paquete de un Cargo.lock.
versiones() {
  awk '/^\[\[package\]\]/ { n = "" }
       /^name = /    { n = $3; gsub(/"/, "", n) }
       /^version = / { v = $3; gsub(/"/, "", v); print n " " v }' "$1" | sort -u
}

raiz_lock="$ROOT/Cargo.lock"
[ -s "$raiz_lock" ] || { echo "FAIL: no hay $raiz_lock"; exit 1; }
raiz="$(versiones "$raiz_lock")"

fallas=0
revisados=0
for lock in "$ROOT"/crates/guest-*/Cargo.lock; do
  [ -e "$lock" ] || continue
  guest="$(basename "$(dirname "$lock")")"
  revisados=$((revisados + 1))
  guest_versiones="$(versiones "$lock")"
  for crate in "${CONSENSO[@]}"; do
    while read -r nombre version; do
      [ -n "$nombre" ] || continue
      if printf '%s\n' "$raiz" | grep -qxF "$nombre $version"; then
        continue
      fi
      en_raiz="$(printf '%s\n' "$raiz" | awk -v n="$nombre" '$1 == n { printf "%s ", $2 }')"
      if printf '%s\n' "$DECLARADAS" | grep -qxF "$guest $nombre $version"; then
        echo "DIVERGENCIA DECLARADA: $guest resuelve $nombre $version (raíz: ${en_raiz:-ausente})"
        continue
      fi
      echo "FAIL: $guest resuelve $nombre $version y la raíz no (raíz: ${en_raiz:-ausente})"
      fallas=$((fallas + 1))
    done < <(printf '%s\n' "$guest_versiones" | awk -v c="$crate" '$1 == c')
  done
done

if [ "$revisados" -eq 0 ]; then
  echo "FAIL: no se encontró ningún crates/guest-*/Cargo.lock"
  exit 1
fi
if [ "$fallas" -gt 0 ]; then
  echo "FAIL: $fallas versiones de consenso de los guests no son las de la raíz"
  exit 1
fi
echo "OK: $revisados locks de guests, ${#CONSENSO[@]} crates de consenso, sin versiones fuera de la raíz"
