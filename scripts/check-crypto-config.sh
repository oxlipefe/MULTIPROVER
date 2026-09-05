#!/usr/bin/env bash
# La cuarentena del motor, contra la forma en que un backend entra DE VERDAD.
#
# QUÉ REGLA ES ÉSTA, Y POR QUÉ NO VIVE EN OTRO CHEQUEO
#
# Archivo propio porque es otra regla, igual que `check-guest-isa.sh` no vive
# adentro de `check-no-floats.sh`. Aquéllos miran un ELF; éste mira la
# CONFIGURACIÓN DE BUILD, que es donde un backend entra sin importar nada.
#
# LA REGLA VIEJA CHEQUEABA LO QUE NO ES
#
# La regla escrita exigía que el motor no importe ningún backend, verificado por
# CI. La sustitución de una librería criptográfica no se hace importando nada: se
# hace con un `[patch]`, un redireccionamiento a nivel de resolución de
# dependencias que **ningún chequeo de imports puede ver**. Un `grep` de `use sp1_` sobre `crates/evm` da verde con el motor
# compilado contra las librerías de SP1.
#
# La intención se respeta entera: el motor tiene que poder cambiar de prover sin
# reescribirse. Lo que cambia es qué se chequea — de "no hay imports" a "no hay
# configuración sin evidencia".
#
# LOS TRES INVARIANTES, Y POR QUÉ SON TRES MENSAJES DISTINTOS
#
#   1. PATCH SIN ENUMERAR — un patch (de `crates-io`, de una fuente git, o como
#      sub-tabla de un crate) que `crypto-configs.toml` no declara. Es la
#      violación central: una configuración que existe y de la que nadie sabe.
#   2. ENUMERADO SIN EVIDENCIA — una configuración declarada cuyo archivo de
#      evidencia no existe, está vacío, o no trae el veredicto de una corrida de
#      nivel 2. Enumerar sin medir sería mover el problema, no resolverlo.
#   2.bis ENUMERADO SIN PATCH — la recíproca de 1: una configuración que declara
#      parchear algo que su manifiesto ya no parchea. Sin ésta el comparador es
#      tuerto y la evidencia puede sobrevivir a la configuración que describe.
#   3. PATCH EN LA RAÍZ — el manifiesto del workspace del motor no lleva
#      patches. Ahí, un patch cambia el grafo del motor según qué prover se
#      piense usar, que es exactamente lo que la cuarentena prohíbe.
#
# Si los tres dieran el mismo mensaje, serían una regla disfrazada de tres, y
# nadie podría saber cuál se rompió.
#
# LO QUE ESTE CHEQUEO NO PUEDE VER, Y HAY QUE DECIRLO
#
# `cargo --config <archivo>` puede inyectar un `[patch]` en una invocación
# suelta, sin dejar rastro en ningún archivo del árbol. Eso es deliberado y es
# como corre el nivel 2 (`scripts/level2-crypto-config.sh`), que toma la
# configuración de un manifiesto ENUMERADO. Un chequeo estático no puede
# auditar la línea de comandos de nadie: lo que sí puede es que ninguna
# configuración quede escrita en el árbol sin declararse.
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

MANIFIESTO="${CRYPTO_CONFIGS:-crypto-configs.toml}"
# El manifiesto del workspace del motor. Un patch acá es la violación 3.
RAIZ="Cargo.toml"

[[ -f "$MANIFIESTO" ]] || { echo "FAIL no existe $MANIFIESTO: no hay enumeración que hacer cumplir." >&2; exit 1; }

fail=0

# --- Lo que el manifiesto declara -------------------------------------------
#
# Formato: `[config.<id>]` con `manifest`, `patches` y `evidence`. Se lee con
# awk y no con un parser de TOML porque no hay uno en el sistema base y una
# dependencia nueva para leer tres campos sería peor que el problema.
declarados=$(awk '
  /^\[config\./ { id = $0; sub(/^\[config\./, "", id); sub(/\]$/, "", id); next }
  id != "" && /^manifest[ \t]*=/ { m = $0; sub(/^[^"]*"/, "", m); sub(/".*$/, "", m); man[id] = m; next }
  id != "" && /^patches[ \t]*=/ {
    p = $0; sub(/^[^=]*=[ \t]*\[/, "", p); sub(/\].*$/, "", p);
    gsub(/[",]/, " ", p); gsub(/[ \t]+/, " ", p); pat[id] = p; next
  }
  id != "" && /^evidence[ \t]*=/ { e = $0; sub(/^[^"]*"/, "", e); sub(/".*$/, "", e); ev[id] = e; next }
  END { for (i in man) printf "%s\t%s\t%s\t%s\n", i, man[i], ev[i], pat[i] }
' "$MANIFIESTO")

[[ -n "$declarados" ]] || { echo "FAIL $MANIFIESTO no declara ninguna configuración." >&2; exit 1; }

echo "== las configuraciones declaradas =="
while IFS=$'\t' read -r id man ev pats; do
  echo "  $id  ($man)  patches:[${pats// /, }]"
done <<<"$declarados"

# --- Los patches de un manifiesto, en TODAS las formas que Cargo honra -------
#
# UNA SOLA LECTURA, TRES CONSUMIDORES. La sección 1, la 1.ter y la 1.bis
# preguntaban lo mismo con tres copias del mismo `awk`, y esa duplicación fue
# exactamente el modo de falla: la afirmación "todo patch está enumerado" era
# falsa para dos de las tres formas y había que arreglarla en tres lugares.
#
# Imprime una línea `fuente<TAB>crate` por patch.

patches_de() { # $1 = ruta de un Cargo.toml
  awk '
    # El encabezado de una tabla de patch, en TODAS sus formas:
    #   [patch.crates-io]                       — el registro por default
    #   [patch."https://github.com/x/y.git"]    — una fuente git, entre comillas
    #                                             DOBLES
    #   la misma, entre comillas SIMPLES         — TOML las trata igual
    #   [patch.crates-io.k256]                  — la sub-tabla de UN crate
    # Cargo honra las cuatro. Mirar solo la primera dejaba pasar un patch que
    # redirige una dependencia con fuente git sin que nada lo viera; mirar solo
    # la comilla doble deja el MISMO agujero corrido un carácter — la forma con
    # comilla simple caía al camino sin comillas, se cortaba en el primer punto
    # de la URL y devolvía un token basura en vez de los crates parcheados. Que
    # hoy diera FAIL igual era casualidad: el token basura tampoco está
    # declarado, pero los crates de verdad nunca entraban al barrido.
    /^[ \t]*\[patch\./ {
      linea = $0
      sub(/^[ \t]*\[patch\./, "", linea)
      sub(/\][ \t]*$/, "", linea)
      crate = ""
      q = substr(linea, 1, 1)
      if (q == "\"" || q == "\047") {
        # Fuente entre comillas: la URL puede traer puntos, así que el corte
        # es la comilla de cierre —de la MISMA especie— y no el primer punto.
        cierre = index(substr(linea, 2), q)
        fuente = substr(linea, 2, cierre - 1)
        resto  = substr(linea, cierre + 2)
      } else {
        p = index(linea, ".")
        if (p == 0) { fuente = linea; resto = "" }
        else { fuente = substr(linea, 1, p - 1); resto = substr(linea, p) }
      }
      if (resto ~ /^\./) crate = substr(resto, 2)
      gsub(/["\047]/, "", crate)
      if (crate != "") {
        # Sub-tabla de un crate: el nombre está en el encabezado y sus claves
        # son `git`/`path`/`branch`, no nombres de crates.
        print fuente "\t" crate
        on = 0
      } else {
        on = 1
        fuente_actual = fuente
      }
      next
    }
    /^[ \t]*\[/ { on = 0 }
    on && /^[ \t]*["\047]?[A-Za-z0-9_.-]+["\047]?[ \t]*=/ {
      k = $1
      sub(/[ \t]*=.*$/, "", k)
      gsub(/["\047]/, "", k)
      if (k != "") print fuente_actual "\t" k
    }
  ' "$1" | sort -u
}

# --- 1. Todo patch del árbol está enumerado ---------------------------------
#
# Se buscan TODOS los patches, no solo los de crates que alguien haya
# clasificado como criptográficos. Una lista de "qué es cripto" envejece y falla
# en silencio; "todo patch se enumera" es fail-closed y no exige juicio.
#
# TODOS quiere decir TODAS LAS FORMAS, y esto se aprendió fallando. El barrido
# miraba el literal `[patch.crates-io]` y nada más, así que un
# `[patch."https://github.com/…"]` —la forma con la que se redirige una
# dependencia de fuente git, que es como entra un backend— pasaba **con exit 0 y
# sin un solo FAIL**. Una regla que se afirma para "todo patch" y se implementa
# para una sintaxis de patch no es estricta: es una regla con una puerta al
# costado. Las tres formas se leen en un solo lugar (`patches_de`), porque el
# defecto vivía en tener tres copias del mismo `awk` incompleto.
#
# QUÉ ÁRBOL, Y POR QUÉ ESE Y NO OTRO
#
# El árbol que este repo CONSTRUYE. `docs/` no lo es: no lo compila nada, no
# viaja en el repo público, y por eso el gate corriendo en CI **nunca puede
# verlo**. Cuando el barrido lo incluía, el mismo chequeo daba dos respuestas
# distintas según dónde corriera —rojo en el árbol de trabajo, verde en CI—, que
# es la peor forma de gate: la que dice verde donde nadie mira.
#
# La exclusión NO es un agujero, porque nada desaparece: lo que hay ahí se lista
# igual, más abajo, con el nombre de lo que parchea. Lo que cambia es que un
# reproductor de un defecto ajeno deja de contar como una configuración
# criptográfica del guest sin evidencia — es un diagnóstico, y su evidencia es
# su propia salida registrada al lado.
echo "== 1. todo \`[patch.…]\` del árbol está enumerado (cualquier fuente) =="
# `mapfile` no existe en el bash 3.2 que trae macOS: se lee por pipe.
todos=$(find . -name Cargo.toml -not -path "./target/*" -not -path "*/target/*" -not -path "./.git/*" | sed 's|^\./||' | sort)
manifiestos=$(grep -v '^docs/' <<<"$todos" || true)
fuera=$(grep '^docs/' <<<"$todos" || true)
encontrado=0
for m in $manifiestos; do
  hallados=$(patches_de "$m")
  [[ -z "$hallados" ]] && continue
  encontrado=1
  while IFS=$'\t' read -r fuente c; do
    [[ -z "$c" ]] && continue
    ok=0
    while IFS=$'\t' read -r _id man _ev pats; do
      [[ "$man" == "$m" ]] || continue
      for p in $pats; do [[ "$p" == "$c" ]] && ok=1; done
    done <<<"$declarados"
    if [[ $ok -eq 1 ]]; then
      echo "  ok   $m parchea \`$c\` (fuente $fuente), y está enumerado"
    else
      echo "  FAIL PATCH SIN ENUMERAR: $m parchea \`$c\` (fuente $fuente) y $MANIFIESTO no lo declara." >&2
      echo "       Una configuración criptográfica que existe y que nadie declaró es" >&2
      echo "       una configuración sin evidencia. Enumerala en $MANIFIESTO con su" >&2
      echo "       archivo de evidencia, o sacá el patch." >&2
      fail=1
    fi
  done <<<"$hallados"
done
[[ $encontrado -eq 0 ]] && echo "  (ningún manifiesto del árbol declara patches)"

# --- 1.ter Lo que quedó fuera del barrido, dicho por su nombre ---------------
#
# Una exclusión silenciosa es un agujero; una exclusión que se imprime es un
# límite. Esto no falla —lo de acá no se construye ni se publica— pero deja el
# patch a la vista, para que nadie tenga que leer el `find` para saber qué no
# se está mirando.
echo "== 1.ter fuera del barrido: el árbol de proceso, que no se construye =="
if [[ -z "$fuera" ]]; then
  echo "  (no hay manifiestos fuera del barrido)"
else
  for m in $fuera; do
    crates=$(patches_de "$m" | cut -f2 | sort -u | tr '\n' ' ')
    if [[ -z "$crates" ]]; then
      echo "  --   $m sin patches"
    else
      echo "  --   $m parchea \`${crates% }\` — diagnóstico, no se compila ni se publica"
    fi
  done
fi

# --- 1.bis Y LA RECÍPROCA -----------------------------------------------------
#
# Sin ésta el comparador es tuerto: una configuración declarada con patches que
# el manifiesto ya no tiene deja el archivo de evidencia describiendo algo que
# el árbol no construye. La evidencia no se vuelve falsa por sí sola — se vuelve
# falsa cuando alguien saca el patch y nadie mira el manifiesto.
echo "== 1.bis todo patch enumerado existe de verdad en su manifiesto =="
while IFS=$'\t' read -r id man ev pats; do
  [[ -z "$pats" ]] && { echo "  ok   $id no declara patches (nada que verificar)"; continue; }
  reales=$(patches_de "$man" | cut -f2 | sort -u)
  for p in $pats; do
    if grep -qx "$p" <<<"$reales"; then
      echo "  ok   $id declara \`$p\` y $man lo parchea"
    else
      echo "  FAIL ENUMERADO SIN PATCH: \`$id\` declara parchear \`$p\` y $man no lo parchea." >&2
      echo "       El archivo de evidencia describiría una configuración que el árbol" >&2
      echo "       no construye. Actualizá $MANIFIESTO y volvé a correr el nivel 2." >&2
      fail=1
    fi
  done
done <<<"$declarados"

# --- 2. Toda configuración enumerada tiene evidencia ------------------------
echo "== 2. toda configuración enumerada tiene evidencia de nivel 2 =="
while IFS=$'\t' read -r id man ev pats; do
  if [[ -z "$ev" ]]; then
    echo "  FAIL ENUMERADO SIN EVIDENCIA: la configuración \`$id\` no declara archivo de evidencia." >&2
    fail=1
    continue
  fi
  if [[ ! -s "$ev" ]]; then
    echo "  FAIL ENUMERADO SIN EVIDENCIA: la configuración \`$id\` apunta a \`$ev\`, que no existe o está vacío." >&2
    echo "       Enumerar sin medir mueve el problema, no lo resuelve. Generalo con:" >&2
    echo "         bash scripts/level2-crypto-config.sh $id" >&2
    fail=1
    continue
  fi
  if ! grep -q '^VEREDICTO: nivel 2 verde' "$ev"; then
    echo "  FAIL ENUMERADO SIN EVIDENCIA: \`$ev\` no trae el veredicto de una corrida de nivel 2 verde." >&2
    echo "       Un archivo que existe pero no dice cómo salió la corrida no es evidencia." >&2
    fail=1
    continue
  fi
  if ! grep -q "^configuración *: *$id\$" "$ev"; then
    echo "  FAIL ENUMERADO SIN EVIDENCIA: \`$ev\` no es la evidencia de \`$id\` (declara otra configuración)." >&2
    fail=1
    continue
  fi
  echo "  ok   $id -> $ev ($(grep -c . "$ev") líneas, veredicto verde)"
done <<<"$declarados"

# --- 3. El workspace del motor no lleva patches -----------------------------
echo "== 3. el manifiesto del motor no lleva ningún patch =="
for f in "$RAIZ" ".cargo/config.toml" ".cargo/config"; do
  [[ -f "$f" ]] || continue
  if grep -qE '^\[patch(\.|\])' "$f"; then
    echo "  FAIL PATCH EN LA RAÍZ: $f declara un \`[patch]\`." >&2
    echo "       Ahí, el grafo de dependencias del MOTOR cambia según qué prover se" >&2
    echo "       piense usar, y el motor deja de ser agnóstico. La configuración de" >&2
    echo "       un backend va en el crate donde ese backend se nombra." >&2
    fail=1
  else
    echo "  ok   $f sin patches"
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "RESULTADO: hay configuración criptográfica sin gate." >&2
  exit 1
fi
echo "RESULTADO: toda configuración criptográfica está enumerada, tiene evidencia, y el motor sigue agnóstico."
