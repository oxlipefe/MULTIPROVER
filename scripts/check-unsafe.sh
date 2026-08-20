#!/usr/bin/env bash
# Acota el `unsafe` del repo con un exit code, no con un comentario.
#
# El workspace declara `unsafe_code = "forbid"`, que es absoluto y no se levanta
# con un `allow` local. UN solo crate baja a "deny": el del guest, porque un
# binario bare-metal necesita dos cosas imposibles en Rust seguro — registrar un
# `#[global_allocator]` (`GlobalAlloc` es un trait `unsafe`) y exportar `_start`
# sin manglear.
#
# Sin este chequeo, "justificación escrita y revisada" depende de que alguien
# mire. Acá es un número: si aparece un `unsafe` que no está declarado abajo, o
# si un crate que debería estar bajo `forbid` deja de estarlo, esto falla.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

# El ÚNICO archivo autorizado a contener `unsafe`, y cuántas veces.
#   - `unsafe impl Sync for Arena`
#   - `unsafe impl GlobalAlloc for Bump`  +  sus dos `unsafe fn` (alloc/dealloc)
#   - `#[unsafe(no_mangle)]` de `_start`
ARCHIVO_AUTORIZADO="crates/guest/src/main.rs"
ESPERADAS=5

fail=0

echo "== crates bajo el \`forbid\` del workspace =="
for c in crates/common crates/interpreter crates/evm crates/witness crates/prover cmd/conformance; do
  # La línea EXACTA de `[lints]`, anclada. Sin el ancla, cualquier
  # `repo-b-common.workspace = true` de las dependencias la da por buena — y ése
  # fue el tercer falso positivo de este chequeo, encontrado mutándolo.
  if grep -qE '^workspace = true$' "$c/Cargo.toml" 2>/dev/null; then
    echo "  ok   $c hereda los lints del workspace"
  else
    echo "  FAIL $c dejó de heredar los lints del workspace (\`forbid(unsafe_code)\`)" >&2
    fail=1
  fi
done

echo "== \`unsafe\` en el árbol =="
# Se cuentan las apariciones de la palabra como token, en el código fuente.
while IFS= read -r f; do
  # Se cuenta CÓDIGO, no prosa: las líneas de comentario se sacan antes. Sin
  # esto, explicar por qué hay un `unsafe` cuenta como tener uno — y el primer
  # falso positivo de este chequeo fue exactamente ése — y el segundo fue un
  # comentario de FIN de línea, que el primer arreglo no sacaba.
  # `unsafe_code` (de `forbid`/`allow`) no matchea: el `_` es parte del token.
  n=$(sed -E 's|//.*$||' "$f" \
      | grep -cE '(^|[^a-zA-Z_])unsafe([^a-zA-Z_]|$)' || true)
  [ "$n" -eq 0 ] && continue
  if [ "$f" = "$ARCHIVO_AUTORIZADO" ]; then
    if [ "$n" -ne "$ESPERADAS" ]; then
      echo "  FAIL $f: $n apariciones de \`unsafe\`, se declararon $ESPERADAS." >&2
      echo "        Crecer la excepción es una decisión, no un accidente: si es" >&2
      echo "        deliberada, actualizá ESPERADAS acá con la razón al lado." >&2
      fail=1
    else
      echo "  ok   $f: $n apariciones, las declaradas"
    fi
  else
    echo "  FAIL $f contiene \`unsafe\` y no es el archivo autorizado." >&2
    fail=1
  fi
done < <(find crates cmd -name '*.rs' -not -path '*/target/*' | sort)

if [ $fail -ne 0 ]; then
  echo "RESULTADO: el \`unsafe\` del repo se salió de lo declarado." >&2
  exit 1
fi
echo "RESULTADO: el único \`unsafe\` del repo es el del arranque bare-metal, y no creció."
