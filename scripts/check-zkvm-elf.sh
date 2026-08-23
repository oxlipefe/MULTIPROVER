#!/usr/bin/env bash
# Audita el ELF que compiló el **backend**, no el nuestro.
#
# POR QUÉ NO ALCANZA CON LA EVIDENCIA DEL ELF PROPIO
#
# `check-no-floats.sh` y `check-guest-isa.sh` auditan el ELF que produce la
# receta de este repo (`scripts/guest-build.sh`): nuestro nightly pineado,
# nuestros `RUSTFLAGS`, nuestro `-Z build-std`. El ELF que ejecuta adentro de una
# zkVM **no es ése**: lo compila el toolchain del backend, adentro de su imagen,
# con sus flags y su `core`. Es un binario nuevo, y las preguntas hay que
# rehacerlas sobre él.
#
# Este repo ya pagó dos veces la lección de heredar una respuesta:
#   - el predicado del chequeo de floats **cambia** entre un rlib y un ELF
#     (`--undefined-only` es ciego sobre un binario estático);
#   - un ELF de cascarón de 4 512 B pasa TODAS las aserciones de ISA, y lo
#     único que lo caza es el chequeo de presencia del motor. Medido de nuevo
#     acá sobre un cascarón que compiló el backend: 82 872 B, misma ISA, sin
#     floats, y sin un solo símbolo del motor.
#
# Por eso acá se afirman las tres cosas juntas, y la primera manda: si el motor
# no está adentro, lo demás no mide nada.
#
# Uso: bash scripts/check-zkvm-elf.sh <elf>
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
# shellcheck source=scripts/guest-build.sh
source "$ROOT/scripts/guest-build.sh"

ELF="${1:?uso: check-zkvm-elf.sh <elf>}"
[[ -f "$ELF" ]] || { echo "error: no existe $ELF" >&2; exit 1; }

# Los mismos crates que exigen los otros dos chequeos. Si estas listas se
# separan, un ELF puede pasar uno y no el otro sin que nadie lo note.
EN_EL_ELF=(repo_b_interpreter repo_b_evm repo_b_witness)
SOFTFLOAT_RE='__[a-z]+(sf|df|tf|hf)[0-9]+\b'

NM=$(guest_llvm_tool llvm-nm)
READOBJ=$(guest_llvm_tool llvm-readobj)

fail=0

echo "== el motor está adentro del ELF del backend =="
for c in "${EN_EL_ELF[@]}"; do
  n=$("$NM" "$ELF" 2>/dev/null | grep -c "$c" || true)
  if [[ "$n" -eq 0 ]]; then
    echo "  FAIL $c: ni un símbolo suyo." >&2
    echo "        Un cascarón pasa todo lo demás sin contener nada." >&2
    fail=1
  else
    echo "  ok   $c ($n símbolos)"
  fi
done

echo "== punto de entrada del guest =="
# El símbolo de nuestro punto de entrada genérico. Que el motor esté adentro no
# prueba que sea ALCANZABLE desde el arranque: el linker puede conservar código
# por una referencia muerta.
if "$NM" "$ELF" 2>/dev/null | grep -q "repo_b_guest.*entry\|entry.*repo_b_guest"; then
  echo "  ok   el punto de entrada genérico de \`repo-b-guest\` está en el ELF"
else
  echo "  (aviso) el símbolo de \`entry\` no aparece: puede estar inlineado en \`main\`."
fi

echo "== floats, con el predicado del ELF (TODOS los símbolos) =="
found=$("$NM" "$ELF" 2>/dev/null | { grep -oE "$SOFTFLOAT_RE" || true; } | sort -u | tr '\n' ' ')
if [[ -n "$found" ]]; then
  echo "  FAIL contiene rutinas de punto flotante: $found" >&2
  fail=1
else
  echo "  ok   sin ninguna rutina de punto flotante"
fi

echo "== la ISA que declara =="
"$READOBJ" --file-headers "$ELF" | sed -n 's/^  Flags \[ (\(0x[0-9a-fA-F]*\))$/  e_flags = \1/p'
isa=$("$READOBJ" --arch-specific "$ELF" 2>/dev/null | grep -oE 'rv(32|64)[a-z0-9_p]+' | head -1)
echo "  ISA: ${isa:-<el ELF del backend no declara cadena de ISA>}"
echo "  (informativo: la receta del backend es SUYA, no la nuestra — lo que este"
echo "   chequeo exige es el motor adentro y la ausencia de floats)"

echo "  ELF: $(wc -c < "$ELF" | tr -d ' ') bytes, $("$NM" "$ELF" | wc -l | tr -d ' ') símbolos"

if [[ $fail -ne 0 ]]; then
  echo "RESULTADO: el ELF del backend NO es auditable como el nuestro." >&2
  exit 1
fi
echo "RESULTADO: el ELF que compiló el backend tiene el motor adentro y no contiene floats."
