#!/usr/bin/env bash
# Los guests compilan el MISMO motor que juzga EEST, con las MISMAS dependencias.
#
# QUÉ REGLA ES ÉSTA
#
# Cada guest concreto (`crates/guest-*`) tiene su propio `[workspace]` y por lo
# tanto su propio `Cargo.lock`. Nada obliga a ese lock a resolver lo mismo que
# el de la raíz, que es el que corren los ejes de conformance: un
# `cargo generate-lockfile` adentro de la imagen de un backend toma lo último
# que haya en crates.io. Así, el MPT, el RLP, el MODEXP o el keccak que corre
# una zkVM pueden ser una versión que EEST nunca vio, con todo verde.
#
# La regla: para cada crate de la lista de abajo, cada paquete que el CIERRE
# DEL MOTOR (`repo-b-guest` y todo lo que arrastra) consume adentro de un guest
# tiene que ser el MISMO paquete que consume el cierre del motor en la raíz:
# misma versión, misma fuente y mismo checksum.
#
# POR QUÉ EL CIERRE DEL MOTOR Y NO EL LOCK ENTERO
#
# Un lock puede tener varias versiones del mismo crate (ark-ff, ark-std y digest
# conviven en varias en el de la raíz, por `revm` y la plataforma). Comparar
# contra "alguna versión del lock de la raíz" deja pasar un guest que le da al
# motor una versión que el motor nativo no usa. Se compara contra lo que el
# motor nativo realmente consume, que sale de `cargo tree -p repo-b-guest`: es
# lo mismo que `cargo tree -i <crate>` restringido al motor, para todos los
# crates de la lista a la vez.
#
# El grafo se resuelve para el target de evidencia (`riscv64imac`): los guests
# compilan para RISC-V, y lo que un `cfg` solo trae en otra arquitectura (p.ej.
# `cpufeatures` en x86) no llega a ninguna zkVM. El lock resuelve UNA versión
# por requisito para todos los targets, así que el target elige qué paquetes
# entran al cierre, nunca su versión.
#
# FUENTE Y CHECKSUM
#
# Un `[patch]` o un pin a git con la misma versión cambia el código sin cambiar
# el número. Por eso se compara la fuente entera (`registry+…` o
# `git+…?tag=…#commit`) y, para crates de registro, el checksum del lock.
# Una diferencia de checksum con la misma versión y fuente no se acepta nunca:
# no hay declaración que la cubra.
#
# POR QUÉ UNA LISTA Y NO EL CIERRE ENTERO
#
# El cierre del motor también arrastra utilitarios (proc-macro2, syn, zerocopy)
# cuyas versiones no cambian ningún byte de consenso. La lista son los crates
# cuya lógica decide un byte del resultado: codificación, trie, enteros, hashes,
# curvas y el álgebra de campos que las sostiene.
#
# Fuera de la lista, de forma explícita, quedan los crates que trae SOLO la
# plataforma de un backend (`PLATAFORMA`): el chequeo exige que ninguno aparezca
# en el cierre del motor, en la raíz ni en ningún guest. Si el motor empieza a
# consumir uno, falla y hay que moverlo a la lista.
#
# DIVERGENCIAS DECLARADAS
#
# Hay dos formas de aceptar una divergencia, y las dos se imprimen en cada
# corrida:
#
#   1. Un patch de un backend enumerado en `crypto-configs.toml`: la fuente git
#      del guest es exactamente el `tag#commit` que la configuración de ese
#      guest pinea para ese crate. Esa enumeración (pin contra manifiesto, lock
#      y evidencia de nivel 2) la hace cumplir `check-crypto-config.sh`, que
#      este script invoca cuando acepta una divergencia por esa vía.
#   2. Cualquier otra, abajo, con versión y fuente EXACTAS. Otra versión u otra
#      fuente del mismo crate vuelve a fallar: la declaración no es un permiso
#      para derivar. Una declaración que no corresponde a ninguna divergencia
#      también falla, para que la lista no envejezca.
#
# Uso: bash scripts/check-guest-locks.sh [raíz-del-repo]
# Offline por default; con red (un runner sin caché): CARGO_NET_OFFLINE=false.
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
TARGET=riscv64imac-unknown-none-elf
MANIFIESTO="$ROOT/crypto-configs.toml"
CRATES_IO="registry+https://github.com/rust-lang/crates.io-index"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

CONSENSO=(
  alloy-primitives alloy-rlp alloy-rlp-derive alloy-trie nybbles ruint
  aurora-engine-modexp blst c-kzg num-bigint
  k256 p256 ecdsa elliptic-curve primeorder crypto-bigint
  sha2 sha3 keccak ripemd digest generic-array
  ark-bn254 ark-bls12-381 ark-ec ark-ff ark-ff-asm ark-ff-macros ark-poly
  ark-serialize ark-std
)

# Solo de la plataforma de un backend (hoy: `ziskos`). Nunca en el motor.
PLATAFORMA=(tiny-keccak secp256k1)

# `guest crate versión fuente`, una por línea; fuente `crates.io` o la `source`
# completa del lock. Vacío = ninguna divergencia aceptada por esta vía.
DECLARADAS="${GUEST_LOCKS_DECLARADAS-$(cat <<'EOF'
guest-sp1 alloy-primitives 1.6.1 crates.io
guest-sp1 alloy-rlp 0.3.16 crates.io
guest-sp1 alloy-rlp-derive 0.3.16 crates.io
guest-sp1 keccak 0.2.2 crates.io
guest-sp1 num-bigint 0.3.3 crates.io
guest-sp1 num-bigint 0.4.8 crates.io
guest-sp1 ecdsa 0.16.9 git+https://github.com/sp1-patches/signatures?tag=sp1-skip-verify-on-recovery#1880299a48fe7ef249edaa616fd411239fb5daf1
guest-sp1 primeorder 0.13.1 git+https://github.com/sp1-patches/elliptic-curves?tag=patch-p256-13.2-sp1-6.2.0#778543de72a8160a9ce253870da1efae6b18e6d3
guest-openvm alloy-primitives 1.7.1 crates.io
guest-openvm alloy-rlp 0.3.16 crates.io
guest-openvm alloy-rlp-derive 0.3.16 crates.io
guest-openvm keccak 0.2.2 crates.io
guest-openvm num-bigint 0.4.8 crates.io
EOF
)}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Cada paquete de un Cargo.lock: `nombre versión fuente-como-cargo-tree fuente checksum`.
# `cargo tree` muestra la fuente git con el commit en 8 caracteres y nada para
# crates.io; la tercera columna es esa forma, para unir los dos.
paquetes_lock() { # $1 = lock
  awk -v cio="$CRATES_IO" '
    function emitir() {
      if (n == "") return
      if (s == "") { corta = "path"; larga = "path" }
      else if (s == cio) { corta = "-"; larga = "crates.io" }
      else if (s ~ /^git\+/) {
        corta = s; sub(/^git\+/, "", corta)
        h = index(corta, "#"); if (h > 0) corta = substr(corta, 1, h + 8)
        larga = s
      } else { corta = s; larga = s }
      print n, v, corta, larga, (c == "" ? "-" : c)
    }
    /^\[\[package\]\]/ { emitir(); n = ""; v = ""; s = ""; c = ""; next }
    /^name = /     { n = $3; gsub(/"/, "", n) }
    /^version = /  { v = $3; gsub(/"/, "", v) }
    /^source = /   { s = $3; gsub(/"/, "", s) }
    /^checksum = / { c = $3; gsub(/"/, "", c) }
    END { emitir() }
  ' "$1"
}

# El cierre del motor en un workspace: `nombre versión fuente checksum`.
cierre_motor() { # $1 = directorio del workspace, $2 = salida, resto = args de cargo tree
  local dir="$1" salida="$2"; shift 2
  local lock="$dir/Cargo.lock"
  [ -s "$lock" ] || { echo "FAIL: no hay $lock"; return 1; }
  paquetes_lock "$lock" >"$TMP/lock"
  cargo tree --manifest-path "$dir/Cargo.toml" --locked -p repo-b-guest "$@" \
    -e normal,build --target "$TARGET" --prefix none -f '{p}' >"$TMP/arbol" ||
    { echo "FAIL: cargo tree no resolvió el motor en $dir (lock inconsistente o sin caché offline)"; return 1; }
  awk '
    NR == FNR { clave[$1 " " $2 " " $3] = $1 " " $2 " " $4 " " $5; next }
    {
      linea = $0; sub(/ \(\*\)$/, "", linea); sub(/ \(proc-macro\)/, "", linea)
      split(linea, p, " "); nombre = p[1]; ver = p[2]; sub(/^v/, "", ver)
      fuente = "-"
      if (match(linea, /\(.*\)$/)) fuente = substr(linea, RSTART + 1, RLENGTH - 2)
      if (fuente ~ /^\//) fuente = "path"
      k = nombre " " ver " " fuente
      if (!(k in clave)) { print "SIN-LOCK " k; next }
      print clave[k]
    }
  ' "$TMP/lock" "$TMP/arbol" | sort -u >"$salida"
  if grep -q '^SIN-LOCK ' "$salida"; then
    echo "FAIL: $dir: paquetes del árbol sin entrada única en el lock:"
    grep '^SIN-LOCK ' "$salida"
    return 1
  fi
  grep -q '^repo-b-evm .* path ' "$salida" || {
    echo "FAIL: $dir: el cierre de repo-b-guest no contiene repo-b-evm"
    return 1
  }
}

# Los pins `crate=tag#commit` de la configuración cuyo manifiesto es el del guest.
pins_de_guest() { # $1 = nombre del guest
  [ -f "$MANIFIESTO" ] || return 0
  awk -v man="crates/$1/Cargo.toml" '
    /^\[config\./ { en = 0; pins = ""; next }
    /^manifest[ \t]*=/ { m = $0; sub(/^[^"]*"/, "", m); sub(/".*$/, "", m); en = (m == man) }
    /^pins[ \t]*=/ { pins = $0 }
    en && pins != "" {
      q = pins; sub(/^[^=]*=[ \t]*\[/, "", q); sub(/\].*$/, "", q)
      gsub(/[",]/, " ", q); k = split(q, a, /[ \t]+/)
      for (i = 1; i <= k; i++) if (a[i] != "") print a[i]
      pins = ""; en = 0
    }
  ' "$MANIFIESTO"
}

cierre_motor "$ROOT" "$TMP/raiz" --features repo-b-guest/crypto-reference

fallas=0
revisados=0
por_config=0
aceptadas=()
usadas=""
for lock in "$ROOT"/crates/guest-*/Cargo.lock; do
  [ -e "$lock" ] || continue
  guest_dir="$(dirname "$lock")"
  guest="$(basename "$guest_dir")"
  revisados=$((revisados + 1))
  cierre_motor "$guest_dir" "$TMP/guest"
  pins="$(pins_de_guest "$guest")"
  for crate in "${CONSENSO[@]}"; do
    while read -r nombre version fuente suma; do
      [ -n "$nombre" ] || continue
      grep -qxF "$nombre $version $fuente $suma" "$TMP/raiz" && continue
      if awk -v n="$nombre" -v v="$version" -v f="$fuente" '$1 == n && $2 == v && $3 == f { e = 1 } END { exit !e }' "$TMP/raiz"; then
        echo "FAIL CHECKSUM: $guest resuelve $nombre $version ($fuente) con checksum $suma, distinto del de la raíz"
        fallas=$((fallas + 1))
        continue
      fi
      en_raiz="$(awk -v n="$nombre" '$1 == n { printf "%s(%s) ", $2, $3 }' "$TMP/raiz")"
      tc="${fuente#*\?tag=}"
      if [ "$tc" != "$fuente" ] && printf '%s\n' "$pins" | grep -qxF "$nombre=$tc"; then
        echo "DIVERGENCIA DECLARADA (crypto-configs.toml): $guest resuelve $nombre $version de $fuente (motor en la raíz: ${en_raiz:-ausente})"
        aceptadas+=("$guest $nombre $version (patch pineado)")
        por_config=$((por_config + 1))
        continue
      fi
      if printf '%s\n' "$DECLARADAS" | grep -qxF "$guest $nombre $version $fuente"; then
        echo "DIVERGENCIA DECLARADA: $guest resuelve $nombre $version de $fuente (motor en la raíz: ${en_raiz:-ausente})"
        aceptadas+=("$guest $nombre $version")
        usadas="$usadas$guest $nombre $version $fuente"$'\n'
        continue
      fi
      echo "FAIL: $guest le da al motor $nombre $version de $fuente, y el motor en la raíz usa: ${en_raiz:-ausente}"
      fallas=$((fallas + 1))
    done < <(awk -v c="$crate" '$1 == c' "$TMP/guest")
  done
  for crate in "${PLATAFORMA[@]}"; do
    if awk -v c="$crate" '$1 == c { e = 1 } END { exit !e }' "$TMP/guest" "$TMP/raiz"; then
      echo "FAIL PLATAFORMA: el motor consume $crate (en la raíz o en $guest); va a la lista de consenso"
      fallas=$((fallas + 1))
    fi
  done
done

if [ "$revisados" -eq 0 ]; then
  echo "FAIL: no se encontró ningún crates/guest-*/Cargo.lock"
  exit 1
fi

while read -r linea; do
  [ -n "$linea" ] || continue
  if ! printf '%s' "$usadas" | grep -qxF "$linea"; then
    echo "FAIL DECLARACIÓN HUÉRFANA: '$linea' no corresponde a ninguna divergencia; borrala"
    fallas=$((fallas + 1))
  fi
done <<<"$DECLARADAS"

if [ "$por_config" -gt 0 ]; then
  if ! bash "$ROOT/scripts/check-crypto-config.sh" >"$TMP/crypto-config" 2>&1; then
    cat "$TMP/crypto-config"
    echo "FAIL: se aceptaron $por_config patches por crypto-configs.toml y check-crypto-config.sh falla"
    fallas=$((fallas + 1))
  else
    echo "check-crypto-config.sh: $(tail -n 1 "$TMP/crypto-config")"
  fi
fi

if [ "$fallas" -gt 0 ]; then
  echo "FAIL: $fallas paquetes de consenso de los guests no son los del motor en la raíz"
  exit 1
fi
if [ "${#aceptadas[@]}" -eq 0 ]; then
  echo "OK: $revisados guests, ${#CONSENSO[@]} crates de consenso, el motor resuelve lo mismo que en la raíz"
  exit 0
fi
lista="$(printf '%s; ' "${aceptadas[@]}")"
echo "OK con ${#aceptadas[@]} divergencias declaradas: ${lista%; }"
