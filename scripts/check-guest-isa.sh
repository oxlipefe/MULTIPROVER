#!/usr/bin/env bash
# Verifica que el ELF del guest declare la ISA que un zkVM puede ejecutar.
#
# QUÉ REGLA ES ÉSTA, Y POR QUÉ NO VIVE EN check-no-floats.sh
#
# Son dos reglas distintas sobre el mismo binario: aquélla dice "el motor no
# hace aritmética de punto flotante", ésta dice "el ELF no usa instrucciones que
# el circuito no sabe decodificar". Juntarlas haría que una falla tape a la
# otra — la lección que este repo aprendió cuando una regla nueva quedó
# invisible detrás de la vieja hasta que se le dio granularidad propia.
#
# POR QUÉ LA COMPRESIÓN IMPORTA TANTO
#
# El estándar de zkVM de `eth-act` (RV64I + M + Zicclsm) **excluye C de forma
# explícita**, y ninguno de los backends de proving confirma decodificar
# instrucciones de 16 bits. Un ELF con compresión ahí no es más lento: es
# RECHAZADO — el decodificador se encuentra un símbolo que no está en su
# alfabeto. Descubrirlo al integrar un backend cuesta el slice entero; acá
# cuesta un exit code.
#
# SE MIRA LO QUE FALTA, NO SOLO LO QUE SOBRA
#
# Un chequeo que solo verificara la ausencia de C pasaría en verde si la receta
# perdiera `+zicclsm` o si la **A** desapareciera (y sin A el árbol ni siquiera
# compila, pero eso lo diría el compilador, no este chequeo). Se afirman las
# dos direcciones.
#
# Y ANTES QUE NADA, QUE EL MOTOR ESTÉ ADENTRO
#
# La ISA declarada por un binario vacío es igual de limpia que la de uno bueno.
# Sin verificar que el motor está adentro, este chequeo no mide nada — es la
# misma trampa que `check-no-floats.sh` documenta para los floats.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
# shellcheck source=scripts/guest-build.sh
source "$ROOT/scripts/guest-build.sh"

# Lo que la ISA declarada NO puede contener, con el nombre de por qué.
PROHIBIDAS=(c2p0 zca)
# Lo que TIENE que contener.
REQUERIDAS=(a2p1 zicclsm)
# Los crates que prueban que el ELF no es un cascarón.
EN_EL_ELF=(repo_b_interpreter repo_b_evm repo_b_witness)

NM=$(guest_llvm_tool llvm-nm)
READOBJ=$(guest_llvm_tool llvm-readobj)

echo "== construyendo el ELF con la receta pineada =="
echo "   toolchain: $GUEST_NIGHTLY"
echo "   flags:     $GUEST_RUSTFLAGS"
echo "   build-std: $GUEST_BUILD_STD"
guest_build_elf >/dev/null

fail=0

echo "== el motor está adentro =="
for c in "${EN_EL_ELF[@]}"; do
  n=$("$NM" "$GUEST_ELF" 2>/dev/null | grep -c "$c" || true)
  if [[ "$n" -eq 0 ]]; then
    echo "  FAIL $c: ni un símbolo suyo en el ELF." >&2
    echo "        La ISA de un binario vacío es igual de limpia que la de uno" >&2
    echo "        bueno: sin el motor adentro, este chequeo no mide nada." >&2
    fail=1
  else
    echo "  ok   $c ($n símbolos)"
  fi
done

echo "== e_flags del header =="
flags=$("$READOBJ" --file-headers "$GUEST_ELF" | sed -n 's/^  Flags \[ (\(0x[0-9a-fA-F]*\))$/\1/p')
if [[ "$flags" != "0x0" ]]; then
  echo "  FAIL e_flags = $flags, se esperaba 0x0" >&2
  "$READOBJ" --file-headers "$GUEST_ELF" | sed -n '/^  Flags \[/,/^  \]/p' | sed 's/^/        /' >&2
  echo "        EF_RISCV_RVC prendido = el ELF contiene instrucciones" >&2
  echo "        comprimidas. Ver la receta en scripts/guest-build.sh." >&2
  fail=1
else
  echo "  ok   e_flags = 0x0 (sin EF_RISCV_RVC)"
fi

echo "== la ISA declarada =="
isa=$("$READOBJ" --arch-specific "$GUEST_ELF" 2>/dev/null | grep -oE 'rv64[a-z0-9_p]+' | head -1)
if [[ -z "$isa" ]]; then
  echo "  FAIL el ELF no declara ninguna cadena de ISA — no hay nada que verificar." >&2
  exit 1
fi
echo "  $isa"
for ext in "${PROHIBIDAS[@]}"; do
  if grep -qE "(^|_)${ext}" <<<"$isa"; then
    echo "  FAIL la ISA declara \`$ext\`, que el estándar excluye." >&2
    fail=1
  else
    echo "  ok   sin \`$ext\`"
  fi
done
for ext in "${REQUERIDAS[@]}"; do
  if grep -qE "(^|_)${ext}" <<<"$isa"; then
    echo "  ok   con \`$ext\`"
  else
    echo "  FAIL la ISA no declara \`$ext\`, que hace falta." >&2
    fail=1
  fi
done

echo "  ELF: $(wc -c < "$GUEST_ELF" | tr -d ' ') bytes"

if [[ $fail -ne 0 ]]; then
  echo "RESULTADO: el ELF del guest NO declara una ISA que un zkVM pueda ejecutar." >&2
  exit 1
fi
echo "RESULTADO: el ELF del guest es RV64IMA + Zicclsm, sin compresión."
