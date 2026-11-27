#!/usr/bin/env bash
# El muestreo de GPU de la receta. Se `source`a: define funciones, no corre nada.
#
# QUÉ MIDE: por muestra, la VRAM ocupada (suma sobre las GPUs visibles) y la
# utilización (la máxima entre ellas), de `nvidia-smi --query-gpu`. Es de las
# GPUs, no de un proceso: se atribuye a un backend porque su contenedor era el
# único `ere-server` vivo. Muestrear da una COTA INFERIOR del pico, no el pico.
#
# TOLERANTE A PROPÓSITO: corre en el lazo de fondo de la receta, bajo
# `set -euo pipefail`, junto a la observación del techo de memoria. Una muestra
# que falla —`nvidia-smi` que no responde, salida vacía, basura— se cuenta y se
# salta: nunca mata el lazo.
#
# `GPU_CONSULTA` es el comando que se consulta (un test lo reemplaza).

GPU_CONSULTA="${GPU_CONSULTA:-nvidia-smi}"

# Una muestra: imprime "<VRAM MiB> <utilización %>", o sale != 0 si la salida
# no es una línea numérica por GPU.
gpu_muestra() {
  local out
  out=$("$GPU_CONSULTA" --query-gpu=memory.used,utilization.gpu \
    --format=csv,noheader,nounits 2>/dev/null) || return 1
  printf '%s\n' "$out" | awk -F', *' '
    NF == 2 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ { s += $1; if ($2 > m) m = $2; k++; next }
    { malo = 1 }
    END { if (k == 0 || malo) exit 1; print s, m + 0 }'
}

# Un tick del lazo. Sin backend vivo, la muestra queda como la base del que
# venga (`<dir>/gpu-reposo`). Con uno vivo, acumula en `<dir>/gpu-<backend>`:
# "válidas fallidas base VRAM_máx utilización_máx"; la base es la del último
# reposo antes de que naciera su contenedor ("?" si no hubo ninguno válido).
# Cada archivo se reemplaza entero (temporal + `mv`): matar el lazo a mitad
# de una escritura no deja una línea cortada.
gpu_tick() { # $1=dir $2=backend vivo, o vacío
  local dir="$1" b="$2" m="" v=0 u=0 ok=0 mal=0 base="?" vm=0 um=0 f
  if m=$(gpu_muestra); then read -r v u <<< "$m"; else m=""; fi
  if [[ -z "$b" ]]; then
    if [[ -n "$m" ]]; then echo "$v" > "$dir/gpu-reposo.t" && mv "$dir/gpu-reposo.t" "$dir/gpu-reposo"; fi
    return 0
  fi
  f="$dir/gpu-$b"
  if [[ -f "$f" ]]; then
    read -r ok mal base vm um < "$f" || true
  elif [[ -f "$dir/gpu-reposo" ]]; then
    base=$(cat "$dir/gpu-reposo")
  fi
  if [[ -n "$m" ]]; then
    ok=$((ok + 1))
    if [[ $v -gt $vm ]]; then vm=$v; fi
    if [[ $u -gt $um ]]; then um=$u; fi
  else
    mal=$((mal + 1))
  fi
  echo "$ok $mal $base $vm $um" > "$f.t" && mv "$f.t" "$f"
}
