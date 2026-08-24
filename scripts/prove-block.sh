#!/usr/bin/env bash
# El NIVEL 4 del gate escalonado: un bloque real de Ethereum **prueba y
# verifica**, y queda reproducible.
#
# POR QUÉ ESTE SCRIPT EXISTE, SI EL RESULTADO YA ESTÁ MEDIDO
#
# Porque una prueba que verificó una vez, a mano, en una caja que ya no existe,
# **no es un gate: es una anécdota**. La caja de la primera corrida murió por
# preemption cinco minutos después de producir el número. Lo que convierte esa
# corrida en evidencia es que cualquiera pueda repetirla con un comando, en
# cualquier Linux x86_64, y obtener el mismo journal.
#
# QUÉ AFIRMA UN VERDE DE ACÁ, Y QUÉ NO
#
#   Sí : "un bloque real de Ethereum prueba y verifica, con UN backend".
#   No : "multiproof". Eso necesita un segundo backend; con uno, afirmarlo
#        sería vapor.
#   No : que el tiempo medido sea "lo que cuesta probar un bloque". Es el de
#        ESTE bloque (1 tx), en ESTA configuración, con las curvas SIN acelerar.
#        Un bloque de mainnet no es esto.
#
# POR QUÉ EL CHEQUEO NO CONFÍA EN EL EXIT CODE DEL DRIVER
#
# `cmd/zkvm` ya contrasta las tres puntas y los tres campos, y sale distinto de
# cero si algo no coincide. Si este script solo mirara ese exit code, una
# mutación que volviera decorativa la comparación de adentro —un `verify` que
# devuelve `Ok` sin comparar bytes— saldría **verde**. Por eso acá se vuelve a
# afirmar desde afuera y contra la MISMA fuente de verdad que el driver: se
# extraen los valores que la corrida publicó y se contrastan contra el fixture
# leído de nuevo. Dos afirmaciones independientes sobre el mismo hecho; matar
# una no alcanza.
#
# EL ENTORNO ES PARTE DE LA RECETA
#
# `ERE_IMAGE_REGISTRY` no se recuerda: se pone acá. **Y lo que hace depende de la
# arquitectura, medido de los dos lados:**
#
#   x86_64 nativo : sin la variable, `ere` NO falla — construye la cadena de
#                   imágenes desde cero (`ere-base`, `ere-base-sp1`,
#                   `ere-server-sp1`, ~2 h) y sigue. Acá la variable es una
#                   optimización de TIEMPO.
#   arm64 (Mac)   : sin la variable, las imágenes que se construyen son arm64 y
#                   el ejecutor mínimo de SP1 PANICKEA (`todo!()` en su fallback
#                   `portable`). Ahí la variable es precondición de que ande.
#
# Ponerla siempre evita las dos cosas, y por eso se pone siempre. Pero el aviso
# no dice "sin esto no ejecuta": eso sería cierto solo en ARM.
#
# Uso:
#   bash scripts/prove-block.sh [--elf <elf>] [--mode N] [--memory <GiB>]
#   bash scripts/prove-block.sh --verificar-log <log>   (solo el chequeo)
#   bash scripts/prove-block.sh --piso-memoria [--desde <GiB>] [--hasta <GiB>]
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

# --- lo que la receta fija, y por qué -----------------------------------------

# El registro público de imágenes de `ere`. Ver arriba qué pasa sin él: en
# x86_64 nativo se paga en horas de build, en ARM se paga en un panic.
REGISTRY_POR_DEFAULT="ghcr.io/eth-act/ere"

# El ELF **con** el patch criptográfico del guest. El de antes del patch mide
# 1 426 384 B y **verifica igual** —es un guest válido—, así que el exit code de
# una corrida no distingue cuál se probó. Lo único que los separa acá es el
# tamaño, y por eso la aserción existe.
ELF_POR_DEFAULT="target/guest-sp1.elf"
ELF_BYTES_ESPERADOS=1317160

# El caso congelado: el bloque real y el journal que el harness computó AFUERA
# del zkVM, con el estado completo.
CASO="cmd/conformance/fixtures/guest"

# Dónde va la evidencia versionada del nivel 4, en paralelo a la del nivel 2.
EVIDENCIA="evidence/proof/sp1.txt"

# El piso de memoria va a su propio artefacto, y no adentro del de la prueba.
# Son dos afirmaciones distintas: una es sobre el guest, la otra sobre la caja
# donde corre. Mezclarlas haría que un cambio de máquina invalidara la evidencia
# de la prueba, que no depende de la máquina.
EVIDENCIA_MEM="evidence/proof/sp1-memoria.txt"

MODO=0
ELF="$ELF_POR_DEFAULT"
SOLO_LOG=""
PISO=0
# Un límite de memoria explícito para la corrida normal. Sirve para acotar el
# consumo del contenedor y para reproducir a mano cualquier peldaño de
# `--piso-memoria`.
#
# **Y acá va una conclusión mía que se cayó, porque la forma de equivocarse vale
# más que el flag.** Con 3 corridas sin límite muertas por OOM en fila y 2 con
# `--memory=30` en verde, escribí que poner el límite AYUDABA, con mecanismo
# plausible incluido (el kernel hace reclaim dentro del cgroup antes de matar).
# La corrida siguiente **con** límite también murió. La cuenta completa en esa
# caja (8 vCPU / 31 GB) es **5 verdes y 4 OOM, con y sin límite mezclados**: no
# hay efecto, había una racha. El pico de esta prueba **straddlea** la capacidad
# de una caja de 31 GB, y ahí el resultado es una moneda — las rachas son lo que
# hace una moneda, no una señal.
LIMITE=""
# El bracket del piso de memoria. `DESDE` se AFIRMA que entra y `HASTA` se
# AFIRMA que no: los dos se verifican antes de bisecar, porque un bracket que
# nadie verificó no es un bracket — es una suposición con forma de número.
DESDE=28
HASTA=2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --elf) ELF="$2"; shift 2 ;;
    --mode) MODO="$2"; shift 2 ;;
    --verificar-log) SOLO_LOG="$2"; shift 2 ;;
    --piso-memoria) PISO=1; shift ;;
    --memory) LIMITE="$2"; shift 2 ;;
    --desde) DESDE="$2"; shift 2 ;;
    --hasta) HASTA="$2"; shift 2 ;;
    *) echo "uso: prove-block.sh [--elf <elf>] [--mode N] [--memory <GiB>]" >&2
       echo "     prove-block.sh --verificar-log <log>" >&2
       echo "     prove-block.sh --piso-memoria [--desde <GiB>] [--hasta <GiB>]" >&2
       exit 2 ;;
  esac
done

fail=0
malo() { echo "  FAIL $*" >&2; fail=1; }
bien() { echo "  ok   $*"; }

# --- el journal esperado, leído del fixture ----------------------------------
#
# **Se lee acá y no se hereda del driver.** Es la fuente de verdad contra la que
# se contrasta lo que la corrida publicó, y tiene que venir del archivo, no de
# la memoria del proceso que se está juzgando.

campo_fixture() {
  grep -E "^$1 " "$CASO/block-journal.txt" | head -1 | awk '{print $2}'
}

PRE_ESPERADO=$(campo_fixture pre_state_root)
POST_ESPERADO=$(campo_fixture post_state_root)
DIGEST_ESPERADO=$(campo_fixture output_digest)
CASO_LINEA=$(grep -E '^case ' "$CASO/block-journal.txt" | head -1 | sed 's/^case //')

# --- el chequeo, sobre la salida de una corrida ------------------------------
#
# Vive aparte del que corre porque es lo que las mutaciones apuntan: se lo puede
# aplicar a un log ya producido sin quemar tres minutos de `prove`. **Nunca
# escribe evidencia**: un log de archivo no es una corrida, y dejarlo firmar
# evidencia convertiría la receta en un sello sobre texto.

verificar() {
  local log="$1"

  echo
  echo "== las tres puntas publican los mismos bytes =="
  for punta in "execute vs prove" "prove vs verify"; do
    if grep -qF "ok   $punta: los mismos" "$log"; then
      bien "$punta"
    else
      malo "falta la aserción \`$punta\`: la corrida no afirmó que las puntas coinciden."
      echo "       Un \`verify\` que devuelve Ok sin contrastar QUÉ verificó no cuenta." >&2
    fi
  done

  echo
  echo "== el journal verificado es el que el harness computó afuera =="
  local visto
  for par in "pre_state_root:$PRE_ESPERADO" "post_state_root:$POST_ESPERADO" \
             "output_digest:$DIGEST_ESPERADO"; do
    local campo="${par%%:*}" esperado="${par#*:}"
    # El valor que la corrida imprimió para este campo, no la marca `ok` que le
    # puso: la marca la escribe el mismo código que la mutación apagaría.
    visto=$(grep -E "^  (ok|FAIL) +$campo " "$log" | head -1 | awk '{print $3}')
    if [[ -z "$visto" ]]; then
      malo "$campo: la corrida no publicó este campo."
    elif [[ "$visto" == "$esperado" ]]; then
      bien "$campo $visto"
    else
      malo "$campo: la prueba afirma $visto y el fixture dice $esperado"
    fi
  done

  # El modo pedido tiene que ser el que la prueba dice haber corrido. `Full` es
  # el único que ejecuta el bloque entero; los ablacionados publican ceros en lo
  # que no computaron y "verifican" igual.
  echo
  echo "== el modo que se probó =="
  if grep -qE "^  ok +modo " "$log"; then
    bien "$(grep -E '^  ok +modo ' "$log" | head -1 | sed 's/^  ok  *//')"
  else
    malo "la corrida no afirmó qué modo publicó la prueba."
  fi
}

# --- modo "solo chequeo": para las mutaciones --------------------------------

if [[ -n "$SOLO_LOG" ]]; then
  [[ -f "$SOLO_LOG" ]] || { echo "error: no existe $SOLO_LOG" >&2; exit 1; }
  echo "[nivel 4] chequeando un log YA producido: $SOLO_LOG"
  echo "[nivel 4] esto NO escribe evidencia: un log de archivo no es una corrida."
  verificar "$SOLO_LOG"
  [[ $fail -eq 0 ]] || { echo "RESULTADO: el chequeo del nivel 4 RECHAZA este log." >&2; exit 1; }
  echo "RESULTADO: el log pasa el chequeo del nivel 4."
  exit 0
fi

# --- el entorno --------------------------------------------------------------
#
# x86_64 **nativo**. No "una VM de un proveedor": eso fue una elección y resultó
# de más. Lo que importa es la arquitectura, y por eso lo que se chequea es la
# arquitectura.

ARCH=$(uname -m)
SO=$(uname -s)
echo "[nivel 4] entorno: $SO $ARCH, $(nproc 2>/dev/null || sysctl -n hw.ncpu) cpus"

if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" ]]; then
  cat >&2 <<AVISO
error: esto pide x86_64 NATIVO y acá corre $ARCH.

  Las imágenes de \`ere\` son amd64. En un host ARM corren EMULADAS, y ahí la
  medición dice otra cosa: en un Mac ARM \`prove\` murió por OOM con 105 146
  ciclos, mientras que en x86_64 nativo el bloque entero —2 566 473 ciclos, 24
  veces más trabajo— probó sin problema. **El techo de la Mac no era función
  del tamaño del trabajo.** La causa exacta no está medida y queda como
  hipótesis (emulación y/o el techo de la VM de Docker Desktop), no como
  conclusión.

  \`execute\` sí anda acá: \`cargo run --release -p zkvm -- run --elf <elf>\`.
AVISO
  exit 1
fi

command -v docker >/dev/null || { echo "error: falta docker" >&2; exit 1; }

# El camino de Docker se elige por entorno porque `ere` lo lee del proceso.
export ERE_IMAGE_REGISTRY="${ERE_IMAGE_REGISTRY:-$REGISTRY_POR_DEFAULT}"
echo "[nivel 4] ERE_IMAGE_REGISTRY=$ERE_IMAGE_REGISTRY"

# --- el ELF ------------------------------------------------------------------

[[ -f "$ELF" ]] || {
  echo "error: no existe $ELF" >&2
  echo "       producilo con: cargo run --release -p zkvm -- compile --out $ELF" >&2
  exit 1
}
ELF_BYTES=$(wc -c < "$ELF" | tr -d ' ')
if [[ "$ELF_BYTES" != "$ELF_BYTES_ESPERADOS" ]]; then
  echo "error: el ELF mide $ELF_BYTES B y el parcheado mide $ELF_BYTES_ESPERADOS B." >&2
  echo "       El de antes del patch (1 426 384 B) VERIFICA IGUAL — es un guest" >&2
  echo "       válido—, así que sin esta aserción se estaría probando otra cosa" >&2
  echo "       y la corrida saldría verde igual." >&2
  exit 1
fi
echo "[nivel 4] ELF: $ELF ($ELF_BYTES B, el parcheado)"

# --- el caso congelado -------------------------------------------------------
#
# **Una prueba de un bloque vacío también verifica.** Por eso el caso se
# reporta, y se exige que tenga al menos una transacción: la vacuidad es el modo
# de falla clásico de este repo.

[[ -f "$CASO/block-input.bin" ]] || { echo "error: falta $CASO/block-input.bin" >&2; exit 1; }
TXS=$(echo "$CASO_LINEA" | grep -oE '[0-9]+ txs' | grep -oE '^[0-9]+' || echo 0)
if [[ "${TXS:-0}" -lt 1 ]]; then
  echo "error: el caso congelado no tiene transacciones ($CASO_LINEA)." >&2
  echo "       Una prueba de un bloque vacío verifica y no dice nada." >&2
  exit 1
fi
echo "[nivel 4] caso: $CASO_LINEA"
echo "[nivel 4] input: $(wc -c < "$CASO/block-input.bin" | tr -d ' ') bytes"

# --- el piso de memoria ------------------------------------------------------
#
# LA PREGUNTA QUE ESTO CONTESTA
#
# ¿Alcanza cualquier Linux x86_64, o hace falta una máquina grande? De la
# respuesta depende que esto pueda ser un job de CI o tenga que ser una corrida
# manual sobre infraestructura provisionada a mano. Y **no se estima**: se mide
# bajando el límite de memoria del contenedor hasta que la prueba deja de
# entrar.
#
# POR QUÉ EL LÍMITE SE APLICA DESPUÉS Y NO AL CREAR EL CONTENEDOR
#
# `ere` crea el contenedor él mismo (`docker container create`) y su
# `DockerizedzkVMConfig` expone solo timeouts: **no hay por dónde pasarle
# `--memory`**. Lo que sí acepta un contenedor ya creado es `docker update`, que
# reescribe el cgroup en vivo. Un watcher espera a que el contenedor aparezca y
# le aplica el límite en el primer segundo de vida, antes de que el prover
# asigne nada — si el límite llegara tarde, se estaría midiendo otra cosa.
#
# POR QUÉ EL PICO OBSERVADO NO ES EL PISO
#
# Son dos números distintos y no hay que confundirlos. El **pico sin límite**
# es cuánto pidió un allocator que no tenía ninguna presión; el **piso** es con
# cuánto la corrida todavía termina. Por eso el pico no reemplaza esta medición
# — y medido: en una caja el pico observado salió **menor** que el piso de otra.
#
# LA BISECCIÓN SUPONE UN PREDICADO DETERMINISTA, Y ÉSTE NO LO ES — MEDIDO
#
# `entra(L)` no es una función: el mismo límite da resultados distintos entre
# corridas. Medido acá con **29 GiB, que entró una vez y la siguiente murió por
# OOM**, y con **30 GiB, que murió una vez y a la siguiente venía bien**. O sea
# que cerca del borde el resultado es **probabilístico**, y una bisección —que
# asume monotonía y determinismo— devuelve un **punto**, no un umbral.
#
# **Una hipótesis sobre la causa, falsificada.** Parecía que el desajuste entre
# el límite y el `pico visto` (muerto en 30 GiB con el sampler marcando 26,04)
# venía de la memoria compartida: SP1 pide `--shm-size=32G`, y en cgroup v2 las
# páginas de tmpfs cuentan contra `memory.max` sin aparecer en `docker stats`.
# Se midió leyendo el cgroup directo: **`shmem` es 0 durante toda la corrida** y
# `memory.current` sigue a `docker stats` de cerca. Toda la memoria es `anon`.
# Lo que hay es un pico **angosto y variable entre corridas**, que un sampler
# cada 2 s no ve — por eso `pico visto` dice COTA INFERIOR y no "pico".
#
# Qué se hace con eso, y qué NO. **No** se repite cada peldaño N veces: eso
# multiplica por N una corrida de 5 minutos para afinar un borde que ninguna
# decisión usa. Lo que sí se hace es **decir qué significa el número**: el
# resultado se publica como *"el más chico que pasó UNA vez"* y *"el más grande
# que falló"*, y cuando los dos son adyacentes eso es exactamente lo que se
# afirma. La decisión que este número alimenta —¿entra en un runner de CI de
# 16 GB?— se contesta con un margen de más de 10 GiB, así que la borrosidad del
# borde no la toca.

# El contenedor se busca por prefijo de nombre y no por el nombre exacto: el
# nombre lo arma `ere` con el `Display` de su enum de backend, que es suyo y
# puede cambiar entre versiones.
contenedor_ere() {
  docker ps -a --filter 'name=ere-server' --format '{{.Names}}' 2>/dev/null | head -1
}

# El watcher. Devuelve, en archivos, tres cosas que después se reportan:
# si el límite se llegó a aplicar, el pico observado y si el kernel mató al
# contenedor por memoria.
VIGIA=""
vigilar() {
  local gib="$1" dir="$2"
  (
    local n=""
    for _ in $(seq 1 900); do
      n=$(contenedor_ere)
      [[ -n "$n" ]] && break
      sleep 0.2
    done
    if [[ -z "$n" ]]; then echo "el contenedor nunca apareció" > "$dir/limite"; return; fi
    if docker update --memory="${gib}g" --memory-swap="${gib}g" "$n" >"$dir/update.log" 2>&1; then
      echo "aplicado a $n" > "$dir/limite"
    else
      echo "NO SE PUDO APLICAR a $n: $(tr -d '\n' < "$dir/update.log")" > "$dir/limite"
      return
    fi
    # Muestreo del uso y del veredicto del kernel mientras el contenedor viva.
    local pico=0 usado oom
    while oom=$(docker inspect -f '{{.State.OOMKilled}}' "$n" 2>/dev/null); do
      echo "$oom" > "$dir/oom"
      # `docker stats` devuelve `12.5GiB / 26GiB`: hay que quedarse con el lado
      # izquierdo Y sacarle el espacio, porque con el espacio pegado el patrón
      # `*GiB` no matchea y el pico sale en blanco sin que nadie se entere.
      usado=$(docker stats --no-stream --format '{{.MemUsage}}' "$n" 2>/dev/null \
              | awk -F/ '{print $1}' | tr -d '[:space:]')
      case "$usado" in
        *GiB) usado=${usado%GiB} ;;
        *MiB) usado=$(awk -v m="${usado%MiB}" 'BEGIN{printf "%.2f", m/1024}') ;;
        *) usado="" ;;
      esac
      if [[ -n "$usado" ]]; then
        pico=$(awk -v a="$pico" -v b="$usado" 'BEGIN{print (b>a)?b:a}')
        echo "$pico" > "$dir/pico"
      fi
      sleep 2
    done
  ) &
  VIGIA=$!
}

# Una sonda: probar el bloque entero con `--memory=<gib>`. Devuelve 0 si la
# receta ENTERA pasa —no solo si el proceso salió con cero—, porque un `prove`
# que termina publicando otra cosa no es "entra en memoria".
sonda_memoria() {
  local gib="$1"
  local dir; dir=$(mktemp -d -t piso-XXXXXX)
  local viejo_fail=$fail
  fail=0

  docker rm -f "$(contenedor_ere)" >/dev/null 2>&1 || true
  echo
  echo "── sonda: --memory=${gib}g ────────────────────────────────────────────"
  vigilar "$gib" "$dir"
  local t0 t1 r
  t0=$(date +%s)
  set +e
  cargo run --release -p zkvm -- prove --elf "$ELF" --mode 0 > "$dir/log" 2>&1
  r=$?
  set -e
  t1=$(date +%s)
  # El watcher se corta a mano y con cota. `wait` a secas esperaría a que el
  # contenedor desaparezca, y un contenedor que quedó colgado colgaría el gate.
  sleep 3
  [[ -n "$VIGIA" ]] && kill "$VIGIA" 2>/dev/null
  wait "$VIGIA" 2>/dev/null || true
  VIGIA=""

  local pico_visto; pico_visto=$(cat "$dir/pico" 2>/dev/null || echo '?')
  echo "   límite      : $(cat "$dir/limite" 2>/dev/null || echo '<no se aplicó>')"
  echo "   pico visto  : $pico_visto GiB (muestreo cada 2 s ⇒ COTA INFERIOR del pico real)"
  echo "   OOMKilled   : $(cat "$dir/oom" 2>/dev/null || echo '?')"
  echo "   exit driver : $r en $((t1 - t0))s"

  if [[ $r -ne 0 ]]; then
    # De dónde sale el veredicto de OOM. `docker inspect` no sirve solo: cuando
    # el kernel mata al contenedor, `ere` lo borra en su `Drop` y la última
    # muestra del watcher es de ANTES de la muerte. El que lo sabe con certeza
    # es el error del driver, que trae el exit code del contenedor.
    if grep -q 'OOM killed' "$dir/log"; then
      echo "   VEREDICTO   : NO entra — OOM killed (exit 137)"
    else
      echo "   VEREDICTO   : NO entra, y NO por OOM — mirar el error antes de contarlo como piso"
    fi
    echo "   $(grep -iE '^Error|killed|OOM' "$dir/log" | tail -2 | tr '\n' '|')"
    printf '  %3s GiB | %8s GiB | %4ss | NO entra\n' "$gib" "$pico_visto" "$((t1 - t0))" >> "$BITACORA"
    fail=$viejo_fail
    rm -rf "$dir"
    return 1
  fi
  # Salir con cero no alcanza: se le aplican las MISMAS aserciones que a la
  # corrida que firma evidencia.
  verificar "$dir/log" > "$dir/chequeo" 2>&1
  local v=$fail
  fail=$viejo_fail
  if [[ $v -ne 0 ]]; then
    echo "   VEREDICTO   : el driver salió 0 pero la receta NO pasa — esto no cuenta como \"entra\""
    sed 's/^/     /' "$dir/chequeo"
    rm -rf "$dir"
    return 1
  fi
  echo "   VEREDICTO   : entra, y con las tres aserciones verdes"
  printf '  %3s GiB | %8s GiB | %4ss | ENTRA\n' "$gib" "$pico_visto" "$((t1 - t0))" >> "$BITACORA"
  rm -rf "$dir"
  return 0
}

piso_memoria() {
  local hi="$1" lo="$2"
  local hi0="$1" lo0="$2"
  BITACORA=$(mktemp -t bitacora-XXXXXX)
  echo "[nivel 4] midiendo el PISO de memoria por bisección en [$lo, $hi] GiB."
  echo "[nivel 4] el bracket se VERIFICA antes de bisecar: sin eso no es un bracket."

  sonda_memoria "$hi" || {
    echo "error: el techo del bracket ($hi GiB) no entra. Subilo con --desde." >&2
    exit 1
  }
  if sonda_memoria "$lo"; then
    echo
    echo "RESULTADO: entra con $lo GiB, que era el piso del bracket. **El piso real es"
    echo "           MENOR o igual que $lo** y esta corrida no lo acota: bajá --hasta."
    echo "           No se escribe evidencia: un bracket que no acota no es una medición."
    rm -f "$BITACORA"
    exit 0
  fi

  while [[ $((hi - lo)) -gt 1 ]]; do
    local mid=$(((hi + lo) / 2))
    if sonda_memoria "$mid"; then hi=$mid; else lo=$mid; fi
  done

  mkdir -p "$(dirname "$EVIDENCIA_MEM")"
  {
    echo "# Evidencia de NIVEL 4 (memoria) — generada por scripts/prove-block.sh --piso-memoria"
    echo "#"
    echo "# Qué contesta: si probar un bloque real puede correr en un runner de CI"
    echo "# corriente o si pide una máquina grande. Se mide bajando el límite de"
    echo "# memoria del contenedor hasta que la receta deja de pasar — no se estima."
    echo "#"
    echo "# Qué NO es este número:"
    echo "#   - NO es una propiedad del bloque. Es del par (bloque, caja). La misma"
    echo "#     receta en otra máquina da otro piso, y ya se midió que lo da: en la"
    echo "#     caja de 16 vCPU el pico observado fue MENOR que el piso de ésta."
    echo "#   - NO es el pico. El pico es lo que pide un allocator sin presión; el"
    echo "#     piso es con cuánto la corrida todavía termina."
    echo "#   - NO se puede reconstruir de un log viejo: cada fila de abajo es una"
    echo "#     corrida entera con las tres aserciones verificadas."
    echo
    echo "entorno       : $SO $ARCH nativo, $(nproc 2>/dev/null || echo '?') cpus, $(free -g 2>/dev/null | awk '/^Mem:/{print $2" GB"}' || echo '?')"
    echo "ELF           : $ELF ($ELF_BYTES B — el parcheado)"
    echo "caso          : $CASO_LINEA"
    echo "backend       : sp1 por ere, imágenes de $ERE_IMAGE_REGISTRY"
    echo "fecha         : $(date -u +%Y-%m-%d)"
    echo "commit        : $(git rev-parse --short HEAD)"
    echo
    echo "bracket       : [$lo0, $hi0] GiB, con los DOS extremos verificados antes de bisecar"
    echo
    echo "  límite  |    pico visto | tiempo | resultado"
    cat "$BITACORA"
    echo
    echo "PISO: el límite más chico que PASÓ es ${hi} GiB; el más grande que FALLÓ, ${lo} GiB."
    echo
    echo "# \"Pasó\" y \"falló\" son de UNA corrida cada uno. \`entra(L)\` no es"
    echo "# determinista cerca del borde: medido, 29 GiB entró una vez y murió por OOM"
    echo "# la siguiente, con picos de 25,46 y 26,35 GiB en corridas idénticas. El"
    echo "# número de arriba es un punto, no un umbral — y la decisión que alimenta se"
    echo "# contesta igual, porque el margen contra un runner de 16 GB es de >10 GiB."
    echo
    if [[ $hi -le 16 ]]; then
      echo "CONSECUENCIA: ENTRA en un runner hosted estándar de GitHub (16 GB)."
    else
      echo "CONSECUENCIA: NO entra en un runner hosted estándar de GitHub (16 GB)."
      echo "Esto puede ser un job de CI solo sobre un runner grande o self-hosted."
    fi
  } > "$EVIDENCIA_MEM"
  rm -f "$BITACORA"

  echo
  echo "════════════════════════════════════════════════════════════════════════"
  cat "$EVIDENCIA_MEM"
  echo "════════════════════════════════════════════════════════════════════════"
}

if [[ $PISO -eq 1 ]]; then
  piso_memoria "$DESDE" "$HASTA"
  exit 0
fi

# --- la corrida --------------------------------------------------------------

LOG=$(mktemp -t nivel4-XXXXXX)
limpiar() { rm -f "$LOG"; }
trap limpiar EXIT

if [[ -n "$LIMITE" ]]; then
  MARCA=$(mktemp -d -t limite-XXXXXX)
  echo "[nivel 4] con --memory=${LIMITE}g en el contenedor (ver por qué en el encabezado del flag)"
  vigilar "$LIMITE" "$MARCA"
fi

echo "[nivel 4] probando (modo $MODO) — levantar el zkVM son ~40 s y \`prove\` unos minutos…"
T0=$(date +%s)
set +e
cargo run --release -p zkvm -- prove --elf "$ELF" --mode "$MODO" 2>&1 | tee "$LOG"
DRIVER=${PIPESTATUS[0]}
set -e
T1=$(date +%s)
DURACION=$((T1 - T0))

if [[ -n "$LIMITE" ]]; then
  sleep 3
  [[ -n "$VIGIA" ]] && kill "$VIGIA" 2>/dev/null
  wait "$VIGIA" 2>/dev/null || true
  echo "[nivel 4] límite: $(cat "$MARCA/limite" 2>/dev/null || echo '<no se aplicó>')"
  echo "[nivel 4] pico visto: $(cat "$MARCA/pico" 2>/dev/null || echo '?') GiB (cota inferior)"
  rm -rf "$MARCA"
fi

[[ $DRIVER -eq 0 ]] || malo "el driver salió con $DRIVER"

verificar "$LOG"

# --- los números de la corrida ----------------------------------------------

# Cada número se extrae acotado a su campo. Cortar por el prefijo y quedarse
# con "el resto de la línea" arrastraría el resto del `println!` adentro de la
# evidencia, y un artefacto versionado que copia ruido envejece mal.
CICLOS=$(grep -oE '[0-9]+ ciclos' "$LOG" | head -1 | grep -oE '[0-9]+' || true)
PRUEBA_S=$(grep -E '^prueba en ' "$LOG" | head -1 | sed -E 's/^prueba en ([^ ]+).*/\1/' || true)
PRUEBA_B=$(grep -oE '[0-9]+ bytes de prueba' "$LOG" | head -1 | grep -oE '[0-9]+' || true)
VERIFY_S=$(grep -E '^verificada en ' "$LOG" | head -1 | sed -E 's/^verificada en ([^ ]+).*/\1/' || true)
# El nombre y la versión del backend los imprime `ere`, y **no se hardcodean**:
# la evidencia tiene que decir qué SDK produjo la prueba, no cuál creíamos.
SDK=$(grep -E '^\[zkvm\] arriba en ' "$LOG" | head -1 | sed -E 's/.*— //' || true)

# --- la evidencia ------------------------------------------------------------
#
# Solo de una corrida real, y solo del modo que ejecuta el bloque entero. Un
# modo ablacionado publica ceros en lo que no computó y "verifica" igual: firmar
# evidencia con eso sería exactamente el `[SAME]` que no prueba nada.

if [[ $fail -eq 0 && "$MODO" == "0" ]]; then
  mkdir -p "$(dirname "$EVIDENCIA")"
  {
    echo "# Evidencia de NIVEL 4 — generada por scripts/prove-block.sh"
    echo "#"
    echo "# Qué prueba: que un bloque REAL de Ethereum, ejecutado por nuestro guest"
    echo "# adentro de un zkVM, produce una prueba que VERIFICA, y que lo que esa"
    echo "# prueba afirma es el post-state root que el harness computó afuera con"
    echo "# el estado completo."
    echo "#"
    echo "# Qué NO prueba:"
    echo "#   - multiproof. Es UN backend; multiproof empieza en dos."
    echo "#   - que el tiempo de acá sea 'lo que cuesta probar un bloque'. Es el de"
    echo "#     ESTE bloque (1 tx), en ESTA configuración, con las curvas SIN"
    echo "#     acelerar. Un bloque de mainnet no es esto."
    echo "#   - nada sobre otras configuraciones criptográficas. La matriz se"
    echo "#     gatea por configuración (crypto-configs.toml), y ésta es UNA fila:"
    echo "#     la del guest de SP1. Otra fila necesita su propia corrida."
    echo "#   - el piso de memoria. Ese número lo mide \`--piso-memoria\`, y se"
    echo "#     reporta aparte porque es una medición del ENTORNO, no del guest."
    echo
    echo "backend       : ${SDK:-<sin línea>} (por ere, imágenes de $ERE_IMAGE_REGISTRY)"
    echo "ELF           : $ELF ($ELF_BYTES B — el parcheado)"
    echo "caso          : $CASO_LINEA"
    echo "input         : $(wc -c < "$CASO/block-input.bin" | tr -d ' ') bytes"
    echo "entorno       : $SO $ARCH nativo, $(nproc 2>/dev/null || echo '?') cpus, límite de memoria del contenedor: ${LIMITE:+${LIMITE} GiB}${LIMITE:-ninguno}"
    echo "fecha         : $(date -u +%Y-%m-%d)"
    echo "commit        : $(git rev-parse --short HEAD)"
    echo "toolchain     : $(rustc -V)"
    echo
    echo "execute       : ${CICLOS:-?} ciclos"
    echo "prove         : ${PRUEBA_S:-?} → ${PRUEBA_B:-?} bytes de prueba"
    echo "verify        : ${VERIFY_S:-?}"
    echo "receta entera : ${DURACION}s (incluye levantar el zkVM)"
    echo
    echo "# Las aserciones. Las dos primeras hacen que \"verifica\" signifique algo:"
    echo "  execute == prove == verify : los mismos bytes públicos"
    echo "  pre_state_root  $PRE_ESPERADO"
    echo "  post_state_root $POST_ESPERADO"
    echo "  output_digest   $DIGEST_ESPERADO"
    echo
    echo "VEREDICTO: nivel 4 verde — un bloque real prueba y verifica, con un backend"
  } > "$EVIDENCIA"
  echo
  cat "$EVIDENCIA"
fi

if [[ $fail -ne 0 ]]; then
  echo >&2
  echo "RESULTADO: nivel 4 ROJO." >&2
  exit 1
fi
if [[ "$MODO" != "0" ]]; then
  echo
  echo "(modo $MODO: ablacionado. No se escribió evidencia — solo el bloque entero la firma.)"
fi
echo
echo "RESULTADO: nivel 4 verde."
