#!/usr/bin/env bash
# La imagen del servidor de ZisK con la que el cruce PRUEBA en CPU.
#
# POR QUÉ EXISTE
#
# El proofman de ZisK espera a que las pruebas recursivas se asienten con un
# tope de 600 s por default (`PROOFMAN_SETTLE_TIMEOUT_S`). En CPU, las
# recursivas de un bloque real tardan más que eso en asentarse —medido: ~29
# min de silencio antes de que cierren— y con el default el `prove` aborta con
# "timed out waiting for proofs to settle". `ere` reenvía al contenedor solo
# sus propias `ERE_ZISK_*`, no esa variable; la única vía sin forkear `ere` es
# una imagen que la traiga en su `ENV`.
#
# QUÉ HACE (idempotente)
#
#   1. Trae la imagen de `ere` FIJADA POR DIGEST: un tag se puede mover, un
#      digest no.
#   2. Deriva `FROM <base>@<digest>` + `ENV PROOFMAN_SETTLE_TIMEOUT_S=<tope>`
#      con un tag PROPIO (`multiprover/ere-server-zisk:<tag de ere>-settle<tope>`),
#      que nombra una sola imagen. Si ya existe con la misma base y el mismo
#      tope, no se reconstruye.
#   3. Retaguea el nombre que `ere` levanta a esa derivada.
#
# POR QUÉ EL RETAG Y NO UN TAG PROPIO PARA `ere`
#
# `ere` arma el nombre del servidor como
# `<ERE_IMAGE_REGISTRY>/ere-server-zisk:<ERE_IMAGE_TAG>` y usa la imagen local
# si existe con ese nombre. Pero `ERE_IMAGE_TAG` es UNO para todos los
# backends —y para las imágenes base y de compilación—: dentro de un cruce que
# levanta sp1, openvm y zisk en el mismo proceso no hay forma de apuntar solo
# a ZisK a otro tag. Así que el nombre de `ere` se retaguea a la derivada, y
# la identidad la fija el tag propio: `verificar` exige que los dos nombres
# resuelvan al MISMO id. El nombre de `ere` en esta caja deja de designar la
# imagen publicada; por eso la receta lo dice en la evidencia, con los dos ids.
#
# Uso:
#   bash scripts/zisk-image.sh              # deriva (idempotente) y verifica
#   bash scripts/zisk-image.sh verificar    # solo verifica; rc != 0 si no está
#
# Se puede `source`ar: define las constantes y las funciones sin correr nada.

ZISK_REGISTRO_BASE="ghcr.io/eth-act/ere"
# El tag que `ere` v0.20.0 usa para sus imágenes (`DOCKER_IMAGE_TAG`, el
# commit corto de su árbol). Un test del driver lo ata a la constante de `ere`.
ZISK_TAG_DE_ERE="a1bf10e"
# La imagen publicada de la que se deriva, por digest.
ZISK_BASE_DIGEST="sha256:008d7f64430f2f3f62770ac60c79c77652d75203a60d8034a59f43a1ff240d3b"
# El tope de asentamiento del proofman, en segundos. Con 3600 las recursivas
# de un bloque real cerraron en CPU; con el default de 600, no.
ZISK_SETTLE_TIMEOUT_S=3600
ZISK_TAG_PROPIO="${ZISK_TAG_DE_ERE}-settle${ZISK_SETTLE_TIMEOUT_S}"
ZISK_ETIQUETA_BASE="org.multiprover.zisk.base"

zisk_imagen_base() { echo "${ZISK_REGISTRO_BASE}/ere-server-zisk@${ZISK_BASE_DIGEST}"; }
zisk_imagen_propia() { echo "multiprover/ere-server-zisk:${ZISK_TAG_PROPIO}"; }
# El nombre que `ere` levanta. Sin `ERE_IMAGE_REGISTRY`, `ere` no le antepone
# nada; con él, se lo antepone sin la barra final.
zisk_imagen_de_ere() {
  local reg="${ERE_IMAGE_REGISTRY:-}"
  reg="${reg%/}"
  if [[ -n "$reg" ]]; then
    echo "${reg}/ere-server-zisk:${ZISK_TAG_DE_ERE}"
  else
    echo "ere-server-zisk:${ZISK_TAG_DE_ERE}"
  fi
}

zisk_id_de() { docker image inspect -f '{{.Id}}' "$1" 2>/dev/null || true; }
zisk_settle_de() {
  docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null \
    | awk -F= '$1 == "PROOFMAN_SETTLE_TIMEOUT_S" { print $2; exit }' || true
}
zisk_base_de() {
  docker image inspect -f "{{index .Config.Labels \"$ZISK_ETIQUETA_BASE\"}}" "$1" 2>/dev/null || true
}

# Deriva la imagen si hace falta y retaguea el nombre de `ere`. Idempotente.
zisk_derivar() {
  local base propia de_ere
  base=$(zisk_imagen_base)
  propia=$(zisk_imagen_propia)
  de_ere=$(zisk_imagen_de_ere)
  if [[ -n "$(zisk_id_de "$propia")" \
        && "$(zisk_settle_de "$propia")" == "$ZISK_SETTLE_TIMEOUT_S" \
        && "$(zisk_base_de "$propia")" == "$ZISK_BASE_DIGEST" ]]; then
    echo "[zisk-image] ya derivada: $propia ($(zisk_id_de "$propia"))"
  else
    echo "[zisk-image] trayendo la base $base"
    docker pull -q "$base" || { echo "error: no se pudo traer $base" >&2; return 1; }
    echo "[zisk-image] derivando $propia"
    printf 'FROM %s\nENV PROOFMAN_SETTLE_TIMEOUT_S=%s\nLABEL %s=%s\n' \
      "$base" "$ZISK_SETTLE_TIMEOUT_S" "$ZISK_ETIQUETA_BASE" "$ZISK_BASE_DIGEST" \
      | docker build -q -t "$propia" - \
      || { echo "error: no se pudo derivar $propia" >&2; return 1; }
  fi
  if [[ "$(zisk_id_de "$de_ere")" != "$(zisk_id_de "$propia")" ]]; then
    echo "[zisk-image] retag: $de_ere → $propia"
    docker tag "$propia" "$de_ere" || { echo "error: no se pudo retaguear $de_ere" >&2; return 1; }
  fi
}

# Una línea con la identidad de la imagen que `ere` va a levantar. Sale con
# rc != 0 si no es la derivada con el tope de la constante: el `prove` de ZisK
# con el default no cierra en CPU, y caer a él en silencio sería medir otra
# configuración que la que la evidencia nombra.
zisk_verificar() {
  local propia de_ere id_propia id_ere settle base_lbl digests
  propia=$(zisk_imagen_propia)
  de_ere=$(zisk_imagen_de_ere)
  id_propia=$(zisk_id_de "$propia")
  id_ere=$(zisk_id_de "$de_ere")
  settle=$(zisk_settle_de "$de_ere")
  base_lbl=$(zisk_base_de "$de_ere")
  digests=$(docker image inspect -f '{{join .RepoDigests " "}}' "$(zisk_imagen_base)" 2>/dev/null || true)
  printf '%s = id %s · derivada %s (id %s) · base %s (RepoDigests: %s) · PROOFMAN_SETTLE_TIMEOUT_S=%s\n' \
    "$de_ere" "${id_ere:-ausente}" "$propia" "${id_propia:-ausente}" \
    "${base_lbl:-sin etiqueta}" "${digests:-no está local}" "${settle:-ausente (rige el default de 600)}"
  [[ -n "$id_ere" && "$id_ere" == "$id_propia" ]] || return 1
  [[ "$settle" == "$ZISK_SETTLE_TIMEOUT_S" ]] || return 1
  [[ "$base_lbl" == "$ZISK_BASE_DIGEST" ]] || return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  command -v docker >/dev/null || { echo "error: falta docker" >&2; exit 1; }
  export ERE_IMAGE_REGISTRY="${ERE_IMAGE_REGISTRY:-$ZISK_REGISTRO_BASE}"
  export DOCKER_DEFAULT_PLATFORM="${DOCKER_DEFAULT_PLATFORM:-linux/amd64}"
  case "${1:-derivar}" in
    derivar) zisk_derivar ;;
    verificar) ;;
    *) echo "uso: zisk-image.sh [derivar|verificar]" >&2; exit 2 ;;
  esac
  if ! zisk_verificar; then
    echo "error: la imagen que \`ere\` levantaría para zisk no es la derivada con PROOFMAN_SETTLE_TIMEOUT_S=$ZISK_SETTLE_TIMEOUT_S." >&2
    exit 1
  fi
fi
