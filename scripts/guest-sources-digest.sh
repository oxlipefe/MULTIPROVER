#!/usr/bin/env bash
# El digest de las fuentes que determinan los ELF del guest, contra el que se
# registró al pinear los ELF.
#
# Un pin de ELF (tamaño + sha256) dice "es ESTE binario", no que ese binario
# siga saliendo del árbol. El nivel 3 y la receta comparan este digest con
# `--check` antes de correr nada: un guest que cambió después del pin falla
# ruidosamente en vez de ser algo que alguien tiene que recordar.
#
# QUÉ ENTRA (y por qué)
#
#   - Los crates que se enlazan al ELF: common, interpreter, evm, witness,
#     block, guest, crypto-openvm-sys y las cuatro hojas guest-{sp1,openvm,zisk,pico}.
#     De cada uno: `Cargo.toml`, `Cargo.lock`, `build.rs`,
#     `rust-toolchain.toml` y todo `src/`. Los `tests/` y `benches/` no
#     entran al binario y quedan afuera.
#   - El `Cargo.toml` raíz: los crates del motor heredan de él versiones,
#     features y lints (`workspace = true`).
#   - La entrada de `ere-dockerized` del `Cargo.lock` raíz: fija la imagen con
#     la que `zkvm compile` compila. El resto de ese lock es del host y un
#     cambio ahí no toca el ELF.
#
# Lo que queda afuera y puede mover el ELF (una imagen re-publicada con el
# mismo tag) lo caza el sha256 del pin: esto afirma "las fuentes no cambiaron",
# no "el binario es reproducible".
#
# Uso:
#   bash scripts/guest-sources-digest.sh            informa (sale 0 siempre que pueda medir)
#   bash scripts/guest-sources-digest.sh --check    sale 1 si los pines están desactualizados
#   bash scripts/guest-sources-digest.sh --write    registra el digest actual (al re-pinear)
#   bash scripts/guest-sources-digest.sh --list     las fuentes, una por línea
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PINES="scripts/guest-elf-sources.txt"
CRATES="common interpreter evm witness block guest crypto-openvm-sys guest-sp1 guest-openvm guest-zisk guest-pico"

sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

# Las fuentes del ELF, en orden de bytes (no del locale): el orden es parte
# del digest. Versionadas o nuevas sin ignorar; una borrada no está.
fuentes() {
  local c
  for c in $CRATES; do
    [[ -d "crates/$c" ]] || { echo "error: falta crates/$c" >&2; return 1; }
    git ls-files --cached --others --exclude-standard -- "crates/$c" |
      awk -v c="crates/$c/" '{
        r = substr($0, length(c) + 1)
        if (r ~ /^src\// || r == "Cargo.toml" || r == "Cargo.lock" || r == "build.rs" || r == "rust-toolchain.toml") print
      }'
  done | LC_ALL=C sort -u
  echo "Cargo.toml"
}

digest() {
  local f
  {
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      printf '%s  %s\n' "$(sha256_de < "$f")" "$f"
    done < <(fuentes)
    # La imagen del compilador, como texto: nombre, versión y fuente pineada.
    awk '/^\[\[package\]\]/ { on = 0 } $0 == "name = \"ere-dockerized\"" { on = 1 } on && /^(name|version|source) / { print }' Cargo.lock
  } | sha256_de
}

pineado() { awk '$1 == "digest" { print $2; exit }' "$PINES" 2>/dev/null; }
pineado_en() { awk '$1 == "commit" { print $2; exit }' "$PINES" 2>/dev/null; }

modo="${1:-}"
case "$modo" in
  --list) fuentes; exit 0 ;;
  --write)
    actual=$(digest)
    {
      echo "# Digest de las fuentes del guest con las que se compilaron los ELF pineados."
      echo "# Lo escribe y lo compara scripts/guest-sources-digest.sh; se mueve solo al re-pinear."
      echo "digest $actual"
      echo "commit $(git rev-parse --short HEAD)"
    } > "$PINES"
    echo "registrado: $actual ($(git rev-parse --short HEAD))"
    exit 0 ;;
  ""|--check) ;;
  *) echo "uso: guest-sources-digest.sh [--check | --write | --list]" >&2; exit 2 ;;
esac

actual=$(digest)
pin=$(pineado)
[[ "$actual" =~ ^[0-9a-f]{64}$ ]] || { echo "error: no se pudo calcular el digest" >&2; exit 1; }
if [[ ! "$pin" =~ ^[0-9a-f]{64}$ ]]; then
  echo "error: $PINES no trae un \`digest\` válido" >&2
  exit 1
fi
echo "fuentes del guest: $actual"
if [[ "$actual" == "$pin" ]]; then
  echo "pines al día: los ELF pineados salen de estas fuentes (registrado en $(pineado_en))"
  exit 0
fi
echo "PINES DESACTUALIZADOS: los ELF se pinearon con las fuentes de $(pineado_en) ($pin)"
echo "  y el guest cambió desde entonces. Recompilá los ELF de cada hoja, re-pineá tamaño y sha256"
echo "  (level3.rs y prove-block.sh) y registrá: bash scripts/guest-sources-digest.sh --write"
[[ "$modo" == "--check" ]] && exit 1
exit 0
