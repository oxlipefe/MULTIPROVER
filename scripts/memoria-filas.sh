#!/usr/bin/env bash
# Las filas `memoria` de la evidencia. Se `source`a: define funciones, no corre nada.
#
# Leen las líneas compactas `memoria|backend|fase|pico|base|ventana|qué cuenta`
# que imprime el driver, con el pico y la base en bytes de `memory.peak`.
#
# **Un pico igual al tope del contenedor no es un pico.** Sin swap, al llegar a
# `memory.max` el kernel reclama (page cache primero) en vez de dejar crecer el
# cgroup, así que `memory.peak` se clava en el tope: es el techo que se le puso,
# no lo que el backend necesitaba, y no dice si entró con holgura o justo. La
# fila lo marca en la misma línea para que el número no se lea como requisito.

# `memory.max` se redondea hacia abajo al tamaño de página del kernel (4 KiB en
# x86_64, hasta 64 KiB en arm64): un cgroup clavado en el tope puede reportar un
# pico que quede debajo de los bytes pedidos por menos de una página. Se toma
# la página más grande para no dejar pasar ese caso como "por debajo".
MEMORIA_TOLERANCIA_TOPE_B=65536

MEMORIA_NOTA_TOPE="alcanzó el tope del contenedor: es el techo, no el pico; margen no medido"

# Las filas de memoria de un backend, legibles. Con $3 (el tope en bytes), la
# fila cuyo pico lo alcanza lleva la nota; sin $3 no se compara nada.
memoria_legible() { # $1=log $2=backend [$3=tope en bytes]
  awk -F'|' -v b="$2" -v tope="${3:-}" -v tol="$MEMORIA_TOLERANCIA_TOPE_B" -v nota="$MEMORIA_NOTA_TOPE" '
    $1 == "memoria" && $2 == b {
      if (NF >= 6 && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/) {
        en_tope = (tope ~ /^[0-9]+$/ && $4 + 0 >= tope - tol)
        printf "  memoria   %-10s pico %.2f GiB (%s) · base %.2f GiB · %s%s\n", $3, $4/1073741824, (NF >= 7 ? $7 : "sin decir qué cuenta"), $5/1073741824, $6, (en_tope ? " · " nota : "")
      } else {
        printf "  memoria   %-10s %s\n", $3, $4
      }
    }
  ' "$1"
}

# Los backends (de los pedidos, en ese orden) con alguna fase cuyo pico alcanzó
# el tope, separados por ", ". Vacío si ninguno.
memoria_en_tope() { # $1=log $2=tope en bytes $3...=backends
  local log="$1" tope="$2" b out=()
  shift 2
  [[ "$tope" =~ ^[0-9]+$ ]] || return 0
  for b in "$@"; do
    if awk -F'|' -v b="$b" -v tope="$tope" -v tol="$MEMORIA_TOLERANCIA_TOPE_B" '
      $1 == "memoria" && $2 == b && NF >= 6 && $4 ~ /^[0-9]+$/ && $4 + 0 >= tope - tol { hay = 1 }
      END { exit !hay }' "$log"; then
      out+=("$b")
    fi
  done
  local IFS=,
  [[ ${#out[@]} -gt 0 ]] && echo "${out[*]}" | sed 's/,/, /g'
  return 0
}

# El párrafo `NO AFIRMA` de los backends que alcanzaron el tope, con la línea en
# blanco que lo separa del siguiente. No imprime nada si ninguno lo alcanzó.
memoria_no_afirma_tope() { # $1=log $2=tope en bytes $3...=backends
  local tope="$2" en
  en=$(memoria_en_tope "$@")
  [[ -n "$en" ]] || return 0
  echo "NO AFIRMA cuánta memoria necesitan $en: su pico alcanzó el tope del"
  echo "contenedor ($(awk -v b="$tope" 'BEGIN{ printf "%.2f GiB", b / 1073741824 }') = $tope B), así que la memoria quedó acotada"
  echo "por el tope y el número es el techo, no el pico. El requisito real no está medido."
  echo
}
