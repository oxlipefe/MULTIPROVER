#!/usr/bin/env bash
# El nivel 2 del gate escalonado: correr los ejes con OTRA configuración
# criptográfica y verificar que el swap no movió la semántica.
#
# QUÉ PRUEBA ESTO, Y QUÉ NO — LEER ANTES DE CITAR UN VERDE DE ACÁ
#
# Corre **nativo**. Compiladas para la máquina de desarrollo, las librerías
# parcheadas caen al algoritmo genérico: la instrucción especial que le pide al
# circuito resolver la operación por hardware **solo se emite adentro del
# zkVM**. O sea que un verde de este script dice exactamente una cosa —*cambiar
# de librería no cambió la semántica del EVM*— y **no** dice nada sobre el
# camino acelerado, que es el que efectivamente se prueba. Eso es el nivel 3, y
# todavía no existe.
#
# POR QUÉ EL PATCH SE EXTRAE Y NO SE ESCRIBE ACÁ
#
# La configuración vive en UN solo lugar: el `Cargo.toml` del crate del backend.
# Este script la lee de ahí y la inyecta con `cargo --config`. Si la copiara,
# habría dos declaraciones de la misma configuración y podrían separarse — y la
# que se testea dejaría de ser la que se compila.
#
# POR QUÉ `--config` Y NO EDITAR EL `Cargo.toml` DE LA RAÍZ
#
# Porque un patch en la raíz es exactamente la violación que
# `check-crypto-config.sh` rechaza: ahí el grafo del MOTOR cambia según qué
# prover se piense usar. `--config` aplica la resolución para una invocación y
# no deja rastro en el árbol.
#
# EL LOCK SE RESTAURA
#
# Resolver con el patch reescribe `Cargo.lock` del workspace. Se guarda antes y
# se repone después, en un `trap`: dejar el lock de otra configuración en el
# árbol sería publicar como estado normal algo que solo vale para una medición.
#
# Uso: bash scripts/level2-crypto-config.sh <id de crypto-configs.toml>
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

ID="${1:?uso: level2-crypto-config.sh <id>}"
MANIFIESTO=crypto-configs.toml

leer() {
  awk -v want="$1" -v campo="$2" '
    /^\[config\./ { id = $0; sub(/^\[config\./, "", id); sub(/\]$/, "", id); next }
    id == want && $1 == campo { v = $0; sub(/^[^"]*"/, "", v); sub(/".*$/, "", v); print v; exit }
  ' "$MANIFIESTO"
}

MAN=$(leer "$ID" manifest)
EV=$(leer "$ID" evidence)
[[ -n "$MAN" && -n "$EV" ]] || { echo "error: $MANIFIESTO no declara la configuración \`$ID\`" >&2; exit 1; }
[[ -f "$MAN" ]] || { echo "error: el manifiesto declarado ($MAN) no existe" >&2; exit 1; }

# El patch, extraído del manifiesto de la configuración. Para la referencia el
# bloque no existe y el archivo queda vacío: cargo lo acepta y la corrida es la
# de siempre, que es lo correcto — la referencia también es una configuración y
# también necesita evidencia.
CFG="$(mktemp -d -t crypto-config-XXXXXX)/patch.toml"
awk '/^\[patch\.crates-io\]/ { on = 1 } on && /^\[/ && !/^\[patch\.crates-io\]/ { on = 0 } on' "$MAN" > "$CFG"
PATCHES=$(awk '/^[A-Za-z0-9_-]+[ \t]*=/ { printf "%s ", $1 }' "$CFG")

echo "[nivel 2] configuración : $ID"
echo "[nivel 2] manifiesto    : $MAN"
echo "[nivel 2] patches       : ${PATCHES:-<ninguno>}"

# `target/` aparte: el árbol se recompila entero contra otra librería, y
# compartir el directorio haría que cada corrida invalide a la anterior.
export CARGO_TARGET_DIR="target/level2-$ID"

LOCK_BAK=$(mktemp -t Cargo-lock-XXXXXX)
cp Cargo.lock "$LOCK_BAK"
restaurar() { cp "$LOCK_BAK" Cargo.lock; rm -rf "$LOCK_BAK" "$(dirname "$CFG")"; }
trap restaurar EXIT

CARGO=(cargo --config "$CFG")

ok=1
marca() { if [[ "$1" -eq 0 ]]; then echo OK; else ok=0; echo "FALLA (exit $1)"; fi; }

echo "[nivel 2] --eest …"
"${CARGO[@]}" run --release -p conformance -- --eest > "$CFG.eest" 2>&1 && r=0 || r=$?
EEST=$(grep -oE 'PASS [0-9]+ \| FAIL [0-9]+' "$CFG.eest" | tail -1)
EEST_R=$(marca $r)

echo "[nivel 2] --eest-blockchain …"
"${CARGO[@]}" run --release -p conformance -- --eest-blockchain > "$CFG.bc" 2>&1 && r=0 || r=$?
BC=$(grep -oE 'PASS [0-9]+ \| FAIL [0-9]+' "$CFG.bc" | tail -1)
BC_R=$(marca $r)

# **UNA INVOCACIÓN POR SET.** `--diff` con varios directorios corre solo el
# primero, en silencio: el gate saldría verde habiendo medido 8 de 327.
# **Los ejes del witness NO son opcionales acá, y son los que más importan.**
# `--eest`/`--eest-blockchain` ejercitan la recuperación ECDSA solo cuando un
# fixture llama al precompile `0x01`. Los del witness la ejercitan en CADA caso:
# el sender de toda tx se deriva de su firma. Como el fork de `k256` que este
# repo parchea trae a su vez un `ecdsa` cuyo tag se llama
# `sp1-skip-verify-on-recovery`, dejar afuera el eje que recupera 86 000 firmas
# sería medir la configuración justo donde no cambia.
echo "[nivel 2] --witness-eest …"
"${CARGO[@]}" run --release -p conformance -- --witness-eest > "$CFG.we" 2>&1 && r=0 || r=$?
WE=$(grep -oE 'DESDE EL WITNESS [0-9]+ \| diferidos [0-9]+ \| FAIL [0-9]+' "$CFG.we" | tail -1)
WE_SIG=$(grep -oE 'senders DERIVADOS.*' "$CFG.we" | tail -1)
WE_R=$(marca $r)

echo "[nivel 2] --witness-blocks …"
"${CARGO[@]}" run --release -p conformance -- --witness-blocks > "$CFG.wb" 2>&1 && r=0 || r=$?
WB=$(grep -oE 'bloques reproducidos desde su witness: [0-9]+' "$CFG.wb" | tail -1)
WB_SIG=$(grep -oE 'senders DERIVADOS.*' "$CFG.wb" | tail -1)
WB_R=$(marca $r)

echo "[nivel 2] --diff, un set por invocación …"
CORRIDAS=0
DIVER=0
SETS=0
for d in cmd/conformance/fixtures/diff/*/; do
  [[ -d "$d" ]] || continue
  set_name=$(basename "$d")
  "${CARGO[@]}" run --release -p conformance --features diff-revm -- --diff "fixtures/diff/$set_name" > "$CFG.diff" 2>&1 && r=0 || r=$?
  linea=$(grep -oE 'diferencial: [0-9]+ casos, [0-9]+ divergencias' "$CFG.diff" | tail -1)
  n=$(echo "$linea" | grep -oE '^diferencial: [0-9]+' | grep -oE '[0-9]+' || echo 0)
  d_n=$(echo "$linea" | grep -oE '[0-9]+ divergencias' | grep -oE '[0-9]+' || echo 0)
  CORRIDAS=$((CORRIDAS + n))
  DIVER=$((DIVER + d_n))
  SETS=$((SETS + 1))
  if [[ $r -ne 0 ]]; then ok=0; echo "  FALLA en $set_name (exit $r)"; fi
  printf '  %-20s %4s corridas, %s divergencias\n' "$set_name" "$n" "$d_n"
done
[[ $DIVER -eq 0 ]] || ok=0

mkdir -p "$(dirname "$EV")"
{
  echo "# Evidencia de NIVEL 2 — generada por scripts/level2-crypto-config.sh"
  echo "#"
  echo "# Qué prueba: que compilar el motor contra OTRAS librerías de"
  echo "# criptografía no cambia la semántica del EVM."
  echo "# Qué NO prueba: el camino acelerado. Este nivel corre NATIVO, donde las"
  echo "# librerías parcheadas caen al algoritmo genérico — la instrucción"
  echo "# especial solo se emite adentro del zkVM. Eso es el nivel 3."
  echo
  echo "configuración : $ID"
  echo "manifiesto    : $MAN"
  echo "patches       : ${PATCHES:-<ninguno>}"
  echo "fecha         : $(date -u +%Y-%m-%d)"
  echo "commit        : $(git rev-parse --short HEAD)"
  echo "toolchain     : $(rustc -V)"
  echo
  echo "--eest              : ${EEST:-<sin línea de resultado>}  $EEST_R"
  echo "--eest-blockchain   : ${BC:-<sin línea de resultado>}  $BC_R"
  echo "--witness-eest      : ${WE:-<sin línea de resultado>}  $WE_R"
  echo "--witness-blocks    : ${WB:-<sin línea de resultado>}  $WB_R"
  echo
  echo "# La recuperación ECDSA, que es lo que \`k256\` decide:"
  echo "  witness-eest  : ${WE_SIG:-<sin línea>}"
  echo "  witness-blocks: ${WB_SIG:-<sin línea>}"
  echo "--diff ($SETS sets)      : $CORRIDAS corridas, $DIVER divergencias"
  echo
  if [[ $ok -eq 1 ]]; then
    echo "VEREDICTO: nivel 2 verde"
  else
    echo "VEREDICTO: nivel 2 ROJO"
  fi
} > "$EV"

cat "$EV"
rm -f "$CFG.eest" "$CFG.bc" "$CFG.we" "$CFG.wb" "$CFG.diff"
[[ $ok -eq 1 ]] || exit 1
