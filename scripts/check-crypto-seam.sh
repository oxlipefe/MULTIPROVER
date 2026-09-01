#!/usr/bin/env bash
# check-crypto-seam.sh — el seam `Crypto` es el ÚNICO camino criptográfico del
# motor.
#
# Archivo propio y no un caso más de `check-crypto-config.sh`, por el mismo
# criterio con el que `check-guest-isa.sh` es su propio archivo: es otra regla.
# Aquél verifica que una configuración acelerada tenga su evidencia; éste
# verifica que la criptografía no tenga forma de esquivar el seam.
#
# Chequea en LAS DOS DIRECCIONES, y esa recíproca no es adorno: cuando este repo
# escribió la cuarentena criptográfica pidió una sola dirección, y esa mitad
# faltante dejaba que la evidencia sobreviviera a la configuración que describe.
#
#   (1) Nadie fuera del provider habla con una librería criptográfica.
#   (2) Todo método del trait tiene al menos un consumidor.
#
# Sin (2) el trait acumula métodos muertos que ningún eje ejercita y que cada
# provider nuevo tiene que implementar a ciegas.
set -euo pipefail

cd "$(dirname "$0")/.."

RED=$'\033[31m'; GREEN=$'\033[32m'; OFF=$'\033[0m'
fail() { echo "${RED}FALLA${OFF}  $*" >&2; FAILED=1; }
FAILED=0

# Las librerías que implementan matemática criptográfica y que solo el provider
# tiene permitido nombrar.
CRYPTO_CRATES='k256|sha2|ripemd|aurora_engine_modexp|ark_bn254|ark_bls12_381|ark_ec|ark_ff|ark_serialize'

# El único lugar donde vive la matemática.
PROVIDER_DIR='crates/evm/src/crypto'

# ---------------------------------------------------------------- dirección 1

# `use` de una librería criptográfica fuera del provider. Se miran los dos
# crates que TIENEN call-sites, medido y no supuesto: el motor y el guest
# —donde viven los senders, que es la criptografía que más pesa y la que un seam
# mal cortado dejaría afuera.
while IFS= read -r hit; do
  file="${hit%%:*}"
  case "$file" in
    "$PROVIDER_DIR"/*) continue ;;
  esac
  fail "camino criptográfico directo, fuera del seam: $hit"
done < <(grep -rnE "^ *use +($CRYPTO_CRATES)(::|;)" crates/evm/src crates/guest/src crates/interpreter/src crates/witness/src 2>/dev/null || true)

# Y la puerta de atrás: una dependencia criptográfica declarada en un crate que
# no es el que tiene el provider. Un `use` se puede esconder detrás de un alias;
# una dependencia en el `Cargo.toml`, no.
#
# **El guest concreto de cada backend también entra en la lista**, porque es un
# manifiesto en el que una dependencia criptográfica pasaría desapercibida: no
# es miembro del workspace, así que `cargo tree` de la raíz no lo alcanza. El de
# SP1 queda afuera por una razón mecánica y no de política: su
# `[patch.crates-io]` nombra `k256` y `sha2` en el margen izquierdo, que es
# exactamente lo que este `grep` busca. Un patch NO es una dependencia nueva
# —redirige el mismo crate a otra fuente— y su gate es
# `check-crypto-config.sh`, que lo enumera con su evidencia. Distinguir las dos
# formas acá exigiría saber en qué sección está la línea; mientras el guest de
# SP1 sea el único con patch, cubrirlo dos veces no agrega nada y confundir los
# dos mensajes sí quita.
for manifest in crates/guest/Cargo.toml crates/interpreter/Cargo.toml \
                crates/witness/Cargo.toml crates/common/Cargo.toml \
                crates/guest-openvm/Cargo.toml; do
  [ -f "$manifest" ] || continue
  while IFS= read -r dep; do
    fail "dependencia criptográfica fuera del crate del provider: $manifest → ${dep%% *}"
  done < <(grep -E "^(k256|sha2|ripemd|aurora-engine-modexp|ark-[a-z0-9-]+) *=" "$manifest" || true)
done

# ---------------------------------------------------------------- dirección 2

TRAIT='crates/common/src/crypto.rs'
[ -f "$TRAIT" ] || { fail "no existe el trait en $TRAIT"; exit 1; }

# Los métodos declarados en el trait.
methods=$(grep -oE '^ *fn [a-z0-9_]+' "$TRAIT" | awk '{print $2}' | sort -u)
[ -n "$methods" ] || { fail "el trait no declara ningún método"; exit 1; }

for method in $methods; do
  # Un consumidor es una llamada `Active::<method>` desde fuera del provider.
  if ! grep -rqE "Active::${method}\b" crates cmd --include='*.rs' 2>/dev/null; then
    fail "método del seam sin ningún consumidor: Crypto::${method} — o lo usa alguien, o no va"
  fi
done

# ------------------------------------------------------------------- veredicto

if [ "$FAILED" -ne 0 ]; then
  echo
  echo "${RED}El seam criptográfico tiene un agujero.${OFF} La criptografía del motor" >&2
  echo "pasa por \`repo_b_common::crypto::Crypto\` y por ningún otro lado: si hace" >&2
  echo "falta una operación nueva, se agrega al trait y al provider de referencia." >&2
  exit 1
fi

count=$(echo "$methods" | wc -w | tr -d ' ')
echo "${GREEN}ok${OFF}  el seam es el único camino criptográfico, y sus $count métodos tienen consumidor"
