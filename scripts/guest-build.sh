#!/usr/bin/env bash
# Cómo se construye el ELF del guest. **Se hace `source`, no se ejecuta.**
#
# POR QUÉ ESTE ARCHIVO EXISTE
#
# Dos chequeos distintos necesitan el MISMO ELF: `check-no-floats.sh` (que el
# motor no arrastre punto flotante) y `check-guest-isa.sh` (que el ELF no
# declare instrucciones comprimidas). Si cada uno tuviera su copia de la receta,
# se separarían — y este repo ya pagó ese bug: dos listas de crates que debían
# ser la misma terminaron mirando un rlib viejo.
#
# LA RECETA, Y POR QUÉ CADA PIEZA
#
# El estándar de zkVM de `eth-act` es RV64I + M + Zicclsm, **sin C**, y ningún
# backend de proving confirma decodificar instrucciones de 16 bits: un ELF con
# compresión no corre más lento ahí, es RECHAZADO.
#
#   -C target-feature=-zca    El que hace el trabajo. `zca` es una feature
#                             SEPARADA en LLVM y apagarla saca la compresión
#                             entera.
#   -C target-feature=-c      **Redundante hoy, y se deja igual.** La implicación
#                             va en UNA sola dirección, medido con los dos flags
#                             por separado sobre esta toolchain:
#                               -zca solo          -> ISA limpia, e_flags 0x0
#                               -c solo            -> conserva `c2p0` Y `zca1p0`,
#                                                     e_flags 0x1
#                             O sea que `-zca` implica sacar C, pero `-c` NO
#                             implica sacar `zca` — que es lo contrario de lo que
#                             sugiere el nombre. Esa relación es un detalle de
#                             implementación de LLVM, no una garantía del spec, y
#                             el nightly de acá arriba se va a mover: dejar los
#                             dos cuesta cero y no depende de que la implicación
#                             siga valiendo.
#   -C target-feature=+zicclsm  Loads/stores desalineados, que el estándar exige.
#   -Z build-std=core,alloc   Imprescindible. Los flags de arriba solo afectan
#                             NUESTROS crates; el `core` que distribuye rustup
#                             viene compilado CON C, y el linker propaga su bit.
#                             Sin recompilar `core`, apagar C es un falso
#                             arreglo: los objetos cambian y `e_flags` no.
#
# LA **A** SE QUEDA, Y NO ES UN DESCUIDO
#
# El estándar de `eth-act` dice IM, sin atómicos. Nuestro árbol NO compila así:
#
#   error[E0599]: no method named `fetch_sub` found for struct `Atomic<usize>`
#     --> bytes-1.12.0/src/bytes.rs:1530
#
# Por eso SP1, OpenVM y ZisK shipean **IMA** aunque el estándar diga IM: el
# ecosistema Rust no compila sin atómicos. El estándar describe el mínimo del
# circuito, no lo que un guest real necesita.
#
# POR QUÉ UN NIGHTLY, Y POR QUÉ CON FECHA
#
# `-Z build-std` es inestable, así que este build —y SOLO este— necesita
# nightly. El resto del workspace se queda en la toolchain pineada de
# `rust-toolchain.toml`: este archivo no bumpea la MSRV de nadie.
#
# La fecha está clavada porque un build de EVIDENCIA que dependa de "el nightly
# de hoy" no es reproducible, y el determinismo es regla dura del repo. Cambiar
# esta constante es una decisión: se re-verifica la ISA resultante, no se
# actualiza de pasada.
#
# TARGET DIR APARTE
#
# El ELF se construye con `RUSTFLAGS` distintos de los del resto del workspace.
# Compartir `target/` haría que cada build invalide al anterior y el árbol se
# recompile entero, ida y vuelta. Con directorio propio, conviven.

GUEST_TARGET=riscv64imac-unknown-none-elf
GUEST_NIGHTLY=nightly-2026-06-20
GUEST_RUSTFLAGS="-C target-feature=-c,-zca,+zicclsm"
GUEST_BUILD_STD="core,alloc"
GUEST_BIN=repo-b-guest
GUEST_TARGET_DIR=target/guest
GUEST_ELF="${GUEST_TARGET_DIR}/${GUEST_TARGET}/release/${GUEST_BIN}"

# Las herramientas de LLVM salen del sysroot de la toolchain POR DEFAULT (la
# estable pineada), no del nightly: leen un ELF, no lo compilan.
guest_llvm_tool() {
  local tool="$1"
  local path
  path="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/${tool}"
  if [[ ! -x "$path" ]]; then
    echo "error: falta ${tool} en ${path} — corré: rustup component add llvm-tools" >&2
    return 1
  fi
  printf '%s' "$path"
}

# La toolchain se DECLARA y se satisface, no se asume instalada.
#
# La alternativa —fallar pidiendo un `rustup install` a mano— crea una
# dependencia de ORDEN entre este repo y la configuración de CI: un commit que
# empiece a usar la toolchain nueva deja el gate rojo hasta que alguien toque
# `.github/`. Eso ya pasó una vez con este mismo script, y un CI rojo en espera
# de una acción humana es la contracara exacta de un gate que nunca falla.
#
# Lo que NO se hace es degradar: si la toolchain falta y no se puede instalar,
# esto FALLA. Saltearse la mitad del ELF "porque no está el compilador" sería un
# gate que deja de medir justo cuando importa. Instalar es idempotente y sale
# gratis cuando ya está.
guest_ensure_toolchain() {
  if ! rustup toolchain list 2>/dev/null | grep -q "^${GUEST_NIGHTLY}"; then
    echo "  (instalando la toolchain pineada ${GUEST_NIGHTLY})"
    if ! rustup toolchain install "${GUEST_NIGHTLY}" --component rust-src --profile minimal >&2; then
      echo "error: no se pudo instalar ${GUEST_NIGHTLY}, que \`-Z build-std\` necesita." >&2
      echo "       corré a mano: rustup toolchain install ${GUEST_NIGHTLY} --component rust-src --profile minimal" >&2
      return 1
    fi
  fi
  if ! rustup component list --toolchain "${GUEST_NIGHTLY}" --installed 2>/dev/null | grep -q '^rust-src'; then
    echo "  (agregando rust-src a ${GUEST_NIGHTLY})"
    if ! rustup component add rust-src --toolchain "${GUEST_NIGHTLY}" >&2; then
      echo "error: ${GUEST_NIGHTLY} no tiene \`rust-src\`, que \`-Z build-std\` necesita." >&2
      echo "       corré a mano: rustup component add rust-src --toolchain ${GUEST_NIGHTLY}" >&2
      return 1
    fi
  fi
}

guest_build_elf() {
  guest_ensure_toolchain || return 1

  RUSTFLAGS="$GUEST_RUSTFLAGS" CARGO_TARGET_DIR="$GUEST_TARGET_DIR" \
    cargo "+${GUEST_NIGHTLY}" build \
    -Z build-std="$GUEST_BUILD_STD" \
    --release --target "$GUEST_TARGET" -p "$GUEST_BIN" \
    --features "$GUEST_BIN/crypto-reference" "$@"

  if [[ ! -f "$GUEST_ELF" ]]; then
    echo "error: el build no produjo $GUEST_ELF" >&2
    return 1
  fi
}
