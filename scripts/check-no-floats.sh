#!/usr/bin/env bash
# Verifica que el motor no contenga aritmética de punto flotante.
#
# POR QUÉ NO ALCANZA CON QUE COMPILE
#
# Un target sin las extensiones F/D (`riscv64imac-unknown-none-elf`, ABI
# `lp64`) NO rechaza un `f64`: rustc lo baja a llamadas a las rutinas de
# software de `compiler_builtins` (`__muldf3`, `__adddf3`, `__fixdfdi`, …).
# Medido: un `f64` metido en el cálculo de gas compila en LOS DOS targets, con
# `fmul.d` nativo en `riscv64gc` y `call __muldf3` en `riscv64imac`.
#
# O sea que "compila para el target del guest" no prueba ausencia de floats en
# NINGUNO de los dos. Lo que sí la prueba es que el binario no referencie esas
# rutinas — y el target sin F/D es el que lo vuelve detectable, porque ahí todo
# float tiene que pasar por un símbolo con nombre conocido en vez de esconderse
# en una instrucción.
#
# QUÉ ES UNA FALLA Y QUÉ NO
#
# Rust monomorfiza los genéricos en el crate que los USA, así que cualquier
# float que una dependencia produjera para nuestras instanciaciones aterriza en
# NUESTROS rlibs. Por eso el chequeo duro son los tres crates del motor.
#
# El código no-genérico de una dependencia se queda en su propio rlib y el
# linker lo descarta si nadie lo llama. Eso se reporta aparte, con el test de
# si alguien referencia sus símbolos: código muerto en un rlib no llega al
# guest, y tratarlo como falla sería un falso positivo.
#
# Requiere el componente `llvm-tools` (`rustup component add llvm-tools`).
set -euo pipefail

TARGET=riscv64imac-unknown-none-elf
CRATES=(repo_b_common repo_b_evm repo_b_interpreter)
# Rutinas soft-float de compiler-rt: `__<op><modo><n>`, con el modo en
# sf (f32) / df (f64) / tf (f128) / hf (f16).
SOFTFLOAT_RE='__[a-z]+(sf|df|tf|hf)[0-9]+'

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

NM="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-nm"
if [[ ! -x "$NM" ]]; then
  echo "error: falta llvm-nm en $NM — corré: rustup component add llvm-tools" >&2
  exit 1
fi

# `grep` sin match devuelve 1; con `set -e` eso mataría el chequeo justo en el
# caso bueno. Se normaliza acá y no en cada llamada.
softfloat_refs() {
  "$NM" --undefined-only "$1" 2>/dev/null \
    | { grep -oE "$SOFTFLOAT_RE" || true; } | sort -u | tr '\n' ' '
}

cargo build --release --target "$TARGET" \
  -p repo-b-common -p repo-b-evm -p repo-b-interpreter

DEPS="target/$TARGET/release/deps"
fail=0

echo "== motor (falla si hay UNA sola referencia) =="
for c in "${CRATES[@]}"; do
  rlib=$(ls "$DEPS"/lib"$c"-*.rlib 2>/dev/null | head -1)
  if [[ -z "$rlib" ]]; then
    echo "error: no se encontró el rlib de $c para $TARGET" >&2
    exit 1
  fi
  found=$(softfloat_refs "$rlib")
  if [[ -n "$found" ]]; then
    echo "  FAIL $c: $found"
    fail=1
  else
    echo "  ok   $c"
  fi
done

echo "== dependencias que CONTIENEN float (informativo: muerto si nadie lo llama) =="
for rlib in "$DEPS"/*.rlib; do
  base=$(basename "$rlib" .rlib)
  base=${base#lib}
  crate=${base%-*}
  case " ${CRATES[*]} " in *" $crate "*) continue ;; esac
  found=$(softfloat_refs "$rlib")
  [[ -z "$found" ]] && continue
  # ¿Alguien referencia símbolos de este crate? Si no, el linker lo descarta.
  referrers=0
  for other in "$DEPS"/*.rlib; do
    [[ "$other" == "$rlib" ]] && continue
    if "$NM" --undefined-only "$other" 2>/dev/null | grep -q "${#crate}$crate"; then
      referrers=$((referrers + 1))
    fi || true
  done
  if [[ $referrers -eq 0 ]]; then
    echo "  huérfano  $crate (nadie referencia sus símbolos ⇒ no llega al guest)"
  else
    echo "  REVISAR   $crate — $referrers crate(s) lo referencian: $found"
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "RESULTADO: hay punto flotante en el motor." >&2
  exit 1
fi
echo "RESULTADO: el motor no referencia ninguna rutina de punto flotante."
