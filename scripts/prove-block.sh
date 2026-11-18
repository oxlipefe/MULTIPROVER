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
# `cmd/zkvm` ya contrasta las tres puntas y los campos del journal, y sale distinto de
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
# EL CONTRASTE ENTRE BACKENDS (--multiproof)
#
# `--multiproof` corre los TRES backends (sp1, openvm, zisk) sobre el mismo
# peldaño, en secuencia, y cruza el journal de cada uno contra el del primero.
# Es otra afirmación que la de arriba y por eso va a otro archivo de evidencia:
#
#   Sí : "tres backends independientes corren el MISMO programa y publican el
#        MISMO journal de 171 bytes", y cada uno coincide además con su oráculo.
#   Sí : con `--mode 0`, que cada journal pasa la política de bloque
#        (`require_full_block`) del lado del consumidor; la receta EXIGE la
#        línea de la política por backend.
#   No : nada sobre el COSTO de OpenVM, que corre con su cuarentena de build.
#   No : nada que compare el COSTO entre backends. Cada uno estima en SU
#        unidad, así que las columnas no se restan ni se dividen.
#
# Y ese camino NO exige x86_64 nativo, a diferencia del de arriba. Lo que la
# arquitectura decide es si `prove` del bloque entero entra en memoria; que dos
# backends publiquen los mismos 171 bytes no depende de eso. Lo que sí depende es
# el COSTO, así que la arquitectura queda escrita en la evidencia.
#
# Uso:
#   bash scripts/prove-block.sh [--elf <elf>] [--mode N] [--memory <GiB>]
#   bash scripts/prove-block.sh --verificar-log <log>   (solo el chequeo)
#   bash scripts/prove-block.sh --piso-memoria [--desde <GiB>] [--hasta <GiB>]
#   bash scripts/prove-block.sh --multiproof [--mode N]
#        [--sin-prueba | --sin-prueba-de sp1|openvm|zisk]
#        [--backends sp1,openvm --motivo-excluidos "<por qué zisk queda afuera>"]
#   bash scripts/prove-block.sh --verificar-log <log> [--backends <lista>]
#        [--elf-sp1 <elf>] [--elf-openvm <elf>] [--elf-zisk <elf>]
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

# La imagen derivada de ZisK (base por digest + el tope de asentamiento del
# proofman): constantes y funciones, sin correr nada al cargarlas.
# shellcheck source=zisk-image.sh
source "$ROOT/scripts/zisk-image.sh"

# --- lo que la receta fija, y por qué -----------------------------------------

# El registro público de imágenes de `ere`. Ver arriba qué pasa sin él: en
# x86_64 nativo se paga en horas de build, en ARM se paga en un panic.
REGISTRY_POR_DEFAULT="ghcr.io/eth-act/ere"

# El ELF **con** el patch criptográfico del guest. El de antes del patch mide
# 1 426 384 B y **verifica igual** —es un guest válido—, así que el exit code de
# una corrida no distingue cuál se probó. Lo único que los separa acá es el
# tamaño, y por eso la aserción existe.
#
# **Y separa menos de lo que parece.** El tamaño distingue este ELF del de antes
# del patch; no distingue dos ELFs del mismo guest compilados contra dos
# versiones del runtime del backend — medido: subir `ere` de 0.16.2 a 0.18.0 cambió el
# `sha256` y dejó el tamaño en los mismos bytes. Esto afirma "no es el ELF sin
# patch", no "es este ELF".
ELF_POR_DEFAULT="target/guest-sp1.elf"
# Medido sobre el guest de input v2 (el bloque tal como viaja, validado contra
# su padre) y journal v2 de 171 B, compilado por `zkvm compile --backend sp1`
# en una caja x86_64 nativa. El valor del guest anterior era 1 386 128 B.
ELF_BYTES_ESPERADOS=1540248

# Y por eso el hash también se pinea: el tamaño dice "no es el ELF sin patch",
# el `sha256` dice "es ESTE ELF". Se mueve con el guest, el patch o el runtime
# del backend, y solo con el valor medido del ELF que compiló el backend.
# Debe coincidir con `ELF_CON_PATCH_SHA256` de cmd/conformance/src/level3.rs.
ELF_SHA256_ESPERADO=6ec35fec3f4067c45fb43f39f12a77a7f2ab3d376c99a496d8420895b6d1fed9

# Los ELFs de los otros dos backends del cruce. Sin patch criptográfico: lo que
# el pin afirma es "es ESTE binario", y deben coincidir con `ELF_OPENVM_*` y
# `ELF_ZISK_*` de cmd/conformance/src/level3.rs (un test lo exige).
ELF_OPENVM_BYTES_ESPERADOS=7807328
ELF_OPENVM_SHA256_ESPERADO=2913e60d6c86895e5f51eef4a05def7aaa343f15bc487b2ac7d19fd7d3a8e03c
ELF_ZISK_BYTES_ESPERADOS=1428248
ELF_ZISK_SHA256_ESPERADO=8579c73b4700bf187fffb3027d805784540d7e9b39c21104fbfe243c91fe29d0

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

# El contraste entre backends: otra afirmación, otro archivo. Mezclarla con la
# de arriba haría que una corrida de un backend firmara una afirmación sobre dos.
EVIDENCIA_MP="evidence/proof/multiproof.txt"
ELF_SP1_POR_DEFAULT="target/guest-sp1.elf"
ELF_OPENVM_POR_DEFAULT="target/guest-openvm.elf"
ELF_ZISK_POR_DEFAULT="target/guest-zisk.elf"

# El segmento de memoria de OpenVM. Con el default de `ere` (14,5 GiB) el
# `prove` de `Kat` murió por OOM a los 33 min en la caja de 31 GiB; con éste
# entra y verifica. El número y su procedencia viven en
# `SEGMENTO_OPENVM_POR_DEFAULT` de `cmd/zkvm/src/main.rs`, y el driver imprime
# el que está corriendo: si los dos se separan, el log lo dice.
SEGMENTO_OPENVM_POR_DEFAULT=4294967296

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
MULTI=0
SIN_PRUEBA=0
# **Apagar la prueba de UN backend, no de los dos.** No es un atajo: hay un
# backend cuyo `prove` no entra en ninguna caja medida, y sin esta forma la
# única manera de correr el cruce sería apagar la prueba de los dos, tirando la
# mitad que sí se puede firmar. El global sigue existiendo — lo usan las
# mutaciones registradas — y los dos son excluyentes.
SIN_PRUEBA_DE=""
# **El alcance del cruce, declarado.** Vacío = el orden entero (los tres). Una
# lista más corta firma un cruce de MENOS backends y lo dice: el chequeo exige
# exactamente esos (ni uno menos ni uno más), y la evidencia nombra a los que
# quedaron afuera con `--motivo-excluidos`, que es obligatorio en ese caso.
BACKENDS_PEDIDOS=""
MOTIVO_EXCLUIDOS=""
ELF_SP1="$ELF_SP1_POR_DEFAULT"
ELF_OPENVM="$ELF_OPENVM_POR_DEFAULT"
ELF_ZISK="$ELF_ZISK_POR_DEFAULT"
# **Apagar la caja al terminar, desde adentro de la caja.** Una corrida de horas
# se lanza por ssh y se deja sola; si el apagado dependiera del proceso que la
# lanzó, no apaga cuando ese proceso muere — ya pasó: la VM quedó 3,8 días
# encendida sin hacer nada. Es opt-in porque la misma receta corre en una laptop.
APAGAR=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --elf) ELF="$2"; shift 2 ;;
    --mode) MODO="$2"; shift 2 ;;
    --verificar-log) SOLO_LOG="$2"; shift 2 ;;
    --piso-memoria) PISO=1; shift ;;
    --memory) LIMITE="$2"; shift 2 ;;
    --desde) DESDE="$2"; shift 2 ;;
    --hasta) HASTA="$2"; shift 2 ;;
    --multiproof) MULTI=1; shift ;;
    --sin-prueba) SIN_PRUEBA=1; shift ;;
    --sin-prueba-de) SIN_PRUEBA_DE="$2"; shift 2 ;;
    --backends) BACKENDS_PEDIDOS="${2:-}"; [[ -n "$BACKENDS_PEDIDOS" ]] || { echo "error: --backends necesita una lista (p. ej. sp1,openvm)" >&2; exit 2; }; shift 2 ;;
    --motivo-excluidos) MOTIVO_EXCLUIDOS="${2:-}"; shift 2 ;;
    --elf-sp1) ELF_SP1="$2"; shift 2 ;;
    --elf-openvm) ELF_OPENVM="$2"; shift 2 ;;
    --elf-zisk) ELF_ZISK="$2"; shift 2 ;;
    --apagar-al-terminar) APAGAR=1; shift ;;
    *) echo "uso: prove-block.sh [--elf <elf>] [--mode N] [--memory <GiB>]" >&2
       echo "     prove-block.sh --verificar-log <log>" >&2
       echo "     prove-block.sh --piso-memoria [--desde <GiB>] [--hasta <GiB>]" >&2
       echo "     prove-block.sh --multiproof [--mode N] [--sin-prueba | --sin-prueba-de sp1|openvm|zisk]" >&2
       echo "          [--backends sp1,openvm --motivo-excluidos \"<texto>\"]" >&2
       echo "     … [--apagar-al-terminar]   (apaga ESTA caja al salir; para una VM efímera)" >&2
       exit 2 ;;
  esac
done

# **El flag se valida ahora y no dentro del trap.** Descubrir al final de una
# corrida de horas que no hay con qué apagar es descubrirlo tarde: el gasto que
# esto evita ya se hizo.
if [[ $APAGAR -eq 1 ]]; then
  if [[ "$(uname -s)" != "Linux" ]] || ! command -v shutdown >/dev/null 2>&1; then
    echo "error: --apagar-al-terminar es para una VM Linux efímera, y acá corre $(uname -s)." >&2
    echo "       Apagar la máquina de alguien por un flag copiado no se hace en silencio." >&2
    exit 2
  fi
fi

# --- la salida, una sola ------------------------------------------------------
#
# Bash tiene UN solo `trap EXIT`: un segundo lo pisa al primero en silencio. Por
# eso los temporales se registran acá en vez de instalar su propio trap, y el
# apagado va en el mismo lugar — así corre pase lo que pase (verde, rojo, o un
# `exit` temprano) y **sin depender de que el proceso que lanzó esto siga vivo**,
# que es exactamente lo que falló la vez que la caja quedó prendida días.
TEMPORALES=()
al_salir() {
  local codigo=$?
  local t
  # **Ningún fallo de limpieza puede impedir llegar al apagado.** `errexit` sigue
  # vigente adentro de un trap `EXIT`: un `rm -rf` que devuelva ≠ 0 —un archivo
  # que otro proceso todavía tiene abierto, un montaje que se fue— abortaría la
  # función acá mismo y el bloque de abajo no correría nunca. Sería el fallo
  # exacto que `--apagar-al-terminar` existe para evitar: nadie mirando y la
  # caja prendida facturando. Por eso cada paso de acá en adelante se salda con
  # `|| true`, y el código de salida que el trap propaga es el de la receta, no
  # el de la limpieza.
  for t in ${TEMPORALES[@]+"${TEMPORALES[@]}"}; do rm -rf "$t" || true; done
  if [[ $APAGAR -eq 1 ]]; then
    echo
    echo "[apagado] la receta terminó con código $codigo: apagando ESTA caja."
    # Los logs primero: un `shutdown` no espera a que el page cache baje a disco.
    sync || true
    # `-h now` y no `+1`: el minuto de gracia solo sirve si hay alguien mirando,
    # y el caso que esto arregla es justamente el que no lo hay.
    sudo shutdown -h now || {
      echo "[apagado] FALLÓ el shutdown: apagá la caja a mano, sigue facturando." >&2
    }
  fi
  return $codigo
}
trap al_salir EXIT

# **La combinación inválida se rechaza, no se resuelve por precedencia.** Un
# orden de prioridad dejaría una línea de comandos que dice una cosa y una
# corrida que hace otra, y la evidencia diría la de la corrida.
if [[ -n "$SIN_PRUEBA_DE" ]]; then
  case "$SIN_PRUEBA_DE" in
    sp1|openvm|zisk) ;;
    *) echo "error: --sin-prueba-de: \`$SIN_PRUEBA_DE\` no es un backend (sp1|openvm|zisk)" >&2; exit 2 ;;
  esac
  if [[ $SIN_PRUEBA -eq 1 ]]; then
    echo "error: --sin-prueba y --sin-prueba-de son excluyentes: el primero apaga la" >&2
    echo "       prueba de TODOS los backends y el segundo la de uno." >&2
    exit 2
  fi
fi

# Qué se le corre a cada backend, derivado de los flags de ESTA corrida. Es la
# fuente independiente contra la que se contrasta lo que el driver reportó: si
# saliera del log del driver, el chequeo miraría la marca que escribió el mismo
# código que una mutación apagaría.
corrida_de() { # $1=backend
  if [[ $SIN_PRUEBA -eq 1 || "$SIN_PRUEBA_DE" == "$1" ]]; then
    echo "solo execute"
  else
    echo "execute+prove+verify"
  fi
}

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

# Los campos del journal v2, en el orden del layout. Los lee el chequeo de una
# corrida contra el fixture y el chequeo del cruce contra el hexa.
CAMPOS_JOURNAL="chain_id fork block_hash parent_hash pre_state_root post_state_root output_digest"
CASO_LINEA=$(grep -E '^case ' "$CASO/block-journal.txt" | head -1 | sed 's/^case //')

# --- el chequeo, sobre la salida de una corrida ------------------------------
#
# Vive aparte del que corre porque es lo que las mutaciones apuntan: se lo puede
# aplicar a un log ya producido sin quemar tres minutos de `prove`. **Nunca
# escribe evidencia**: un log de archivo no es una corrida, y dejarlo firmar
# evidencia convertiría la receta en un sello sobre texto.

verificar() { # $1=log  $2=modo pedido (0 = Full, el único que firma)
  local log="$1" modo="${2:-0}"

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
  for campo in $CAMPOS_JOURNAL; do
    local esperado; esperado=$(campo_fixture "$campo")
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

  # **La política del consumidor, exigida desde afuera.** Que los campos
  # coincidan con el fixture lo afirma esta receta; que el journal sea
  # ACEPTABLE como prueba de un bloque —versión, modo `Full`, cadena, fork,
  # hash, padre, roots y digest no nulos— lo decide `require_full_block`, y
  # una corrida que no la pasó (o que no la corrió) no firma el nivel 4. Sin
  # esta exigencia, el binario podía saltearse la política y el log salía
  # verde igual.
  echo
  echo "== la política de bloque del consumidor =="
  if [[ "$modo" != "0" ]]; then
    echo "  (modo $modo: no es la prueba de un bloque; la política no aplica y esto no firma el nivel 4)"
  elif ! grep -qE "^  ok +modo Full" "$log"; then
    malo "se pidió \`Full\` y la corrida no afirma haber publicado \`Full\`."
  elif grep -qE "^  FAIL +política de bloque: " "$log"; then
    malo "require_full_block RECHAZA el journal: $(grep -E '^  FAIL +política de bloque: ' "$log" | head -1 | sed 's/^  FAIL  *//')"
  elif grep -qE "^  ok +política de bloque: " "$log"; then
    bien "$(grep -E '^  ok +política de bloque: ' "$log" | head -1 | sed 's/^  ok  *//')"
  else
    malo "falta la línea \`política de bloque\`: el journal no pasó por require_full_block."
  fi
}


# --- el chequeo del contraste entre backends ---------------------------------
#
# POR QUÉ NO ES EL MISMO `verificar()` DE ARRIBA
#
# Aquél juzga UNA corrida contra el fixture. Éste juzga N corridas, una contra
# la otra, y la afirmación central —"los mismos 171 bytes"— no existe allá. Un
# solo chequeo que hiciera las dos cosas tendría que decidir cuál de las
# fuentes es la verdad, y en el cruce no hay ninguna: todos los lados son
# candidatos.
#
# Y ACÁ TAMPOCO SE CONFÍA EN LAS MARCAS QUE ESCRIBIÓ EL DRIVER
#
# El archivo trae el journal de cada backend en hexa, y de ahí se derivan los
# campos y se comparan **contra lo que la sección del cruce dice**. Si
# alguien edita un byte de un journal, se cae la igualdad entre los journals Y
# la consistencia con el cruce. Confiar en las filas `ok` del cruce sería
# mirar la marca que escribió el mismo código que una mutación apagaría.

MARCA_MP="CONTRASTE ENTRE BACKENDS"

# El orden del cruce. El primero es contra el que se cruza cada uno de los
# otros; tiene que ser el mismo `ORDEN` de cmd/zkvm/src/multiproof.rs.
ORDEN_CRUCE="sp1 openvm zisk"

# El alcance de ESTA corrida: el orden entero, o la lista de `--backends`
# reordenada al orden del cruce. **Se valida igual que en el driver** —nombre
# conocido, sin repetidos, al menos dos—, y la validación vive acá también
# porque el chequeo de `--verificar-log` no pasa por el driver.
alcance_de() { # $1=lista separada por comas; imprime la lista en orden, o falla
  local lista="$1" n b x vistos="" fuera=""
  IFS=',' read -r -a pedidos <<< "$lista"
  [[ "$lista" == *, || "$lista" == ,* || "$lista" == *,,* ]] && { echo "hay un elemento vacío en \`$lista\`"; return 1; }
  for x in "${pedidos[@]}"; do
    x="${x// /}"
    case " $ORDEN_CRUCE " in
      *" $x "*) ;;
      *) echo "\`$x\` no es un backend del cruce (sp1, openvm, zisk)"; return 1 ;;
    esac
    case " $vistos " in
      *" $x "*) echo "\`$x\` aparece más de una vez"; return 1 ;;
    esac
    vistos="$vistos $x"
  done
  n=0
  for b in $ORDEN_CRUCE; do
    case " $vistos " in *" $b "*) fuera="$fuera $b"; n=$((n + 1)) ;; esac
  done
  [[ $n -ge 2 ]] || { echo "un cruce necesita al menos 2 backends y la lista trae $n"; return 1; }
  echo "${fuera# }"
}

if [[ -z "$BACKENDS_PEDIDOS" ]]; then
  BACKENDS_CRUCE="$ORDEN_CRUCE"
elif ! BACKENDS_CRUCE=$(alcance_de "$BACKENDS_PEDIDOS"); then
  echo "error: --backends: $BACKENDS_CRUCE" >&2
  exit 2
fi
# Los del orden que quedaron afuera de esta corrida.
EXCLUIDOS=""
for b in $ORDEN_CRUCE; do
  case " $BACKENDS_CRUCE " in *" $b "*) ;; *) EXCLUIDOS="$EXCLUIDOS $b" ;; esac
done
EXCLUIDOS="${EXCLUIDOS# }"

campo_mp() { # $1=archivo $2=backend $3=clave
  awk -v b="$2" -v k="$3" '
    $1 == "backend" { cur = $2; next }
    cur == b && $1 == k { $1 = ""; sub(/^ +/, ""); print; exit }
  ' "$1"
}

# Las filas `memoria` de un backend, una por fase.
memoria_mp() { # $1=archivo $2=backend $3=fase
  awk -v b="$2" -v fase="$3" '
    $1 == "backend" { cur = $2; next }
    cur == b && $1 == "memoria" && $2 == fase { $1 = ""; sub(/^ +/, ""); print; exit }
  ' "$1"
}

# TODAS las filas de la sección del cruce para un campo, una por par.
filas_cruce() { # $1=archivo $2=campo
  awk -v k="$2" '
    /^EL CRUCE/ { on = 1; next }
    on && /^VEREDICTO/ { on = 0 }
    on && $2 == k { print $1 " " $3 }
  ' "$1"
}

# El pin del ELF de un backend: la receta lo conoce, y la evidencia tiene que
# citar ESE hash.
sha_pineado() { # $1=backend
  case "$1" in
    sp1) echo "$ELF_SHA256_ESPERADO" ;;
    openvm) echo "$ELF_OPENVM_SHA256_ESPERADO" ;;
    zisk) echo "$ELF_ZISK_SHA256_ESPERADO" ;;
  esac
}
bytes_pineados() { # $1=backend
  case "$1" in
    sp1) echo "$ELF_BYTES_ESPERADOS" ;;
    openvm) echo "$ELF_OPENVM_BYTES_ESPERADOS" ;;
    zisk) echo "$ELF_ZISK_BYTES_ESPERADOS" ;;
  esac
}

# Los campos de un journal v2 en hexa (342 caracteres), en el orden del
# layout: version · mode · chain_id (8 B) · fork · block_hash · parent_hash ·
# pre_state_root · post_state_root · output_digest. Los enteros salen en
# decimal y los hashes con `0x`, como los escribe el fixture. Falla si el hexa
# no tiene la forma.
campos_de_journal() { # $1=hexa
  local j="$1"
  [[ ${#j} -eq 342 && "$j" =~ ^[0-9a-fA-F]+$ ]] || return 1
  printf '%s %s %s %s 0x%s 0x%s 0x%s 0x%s 0x%s\n' \
    "$((16#${j:0:2}))" "$((16#${j:2:2}))" "$((16#${j:4:16}))" "$((16#${j:20:2}))" \
    "${j:22:64}" "${j:86:64}" "${j:150:64}" "${j:214:64}" "${j:278:64}"
}

verificar_multiproof() {
  local f="$1"
  local b n_backends=0 primero="" j0=""
  for b in $BACKENDS_CRUCE; do n_backends=$((n_backends + 1)); done
  local pares=$((n_backends - 1))

  # **El alcance, exacto.** El archivo dice qué backends entraron y cuáles
  # quedaron afuera; el chequeo lo contrasta contra el alcance que se le PIDIÓ
  # (el orden entero, o `--backends`), que es una fuente independiente del
  # archivo. Uno de menos es un cruce incompleto; uno de más, una afirmación
  # que nadie pidió; y un excluido sin motivo, un agujero sin nombre.
  echo
  echo "== el alcance de la corrida: exactamente $BACKENDS_CRUCE =="
  local declarado secciones x m
  declarado=$(awk -F' *: *' '$1 == "backends" { print $2; exit }' "$f")
  if [[ "$declarado" == "$BACKENDS_CRUCE" ]]; then
    bien "el archivo declara el alcance pedido: $declarado"
  else
    malo "el archivo declara el alcance \"$declarado\" y se pidió \"$BACKENDS_CRUCE\"."
  fi
  secciones=$(awk '$1 == "backend" { printf "%s%s", s, $2; s = " " }' "$f")
  if [[ "$secciones" == "$BACKENDS_CRUCE" ]]; then
    bien "trae una sección por backend del alcance, y ninguna más"
  else
    malo "las secciones del archivo son \"$secciones\" y el alcance es \"$BACKENDS_CRUCE\" (falta o sobra un backend)."
  fi
  for x in $ORDEN_CRUCE; do
    m=$(awk -v b="$x" '$1 == "excluido" && $3 == b { $1 = $2 = $3 = $4 = ""; sub(/^ +/, ""); print; exit }' "$f")
    case " $BACKENDS_CRUCE " in
      *" $x "*)
        if [[ -n "$(awk -v b="$x" '$1 == "excluido" && $3 == b' "$f")" ]]; then
          malo "$x está en el alcance y el archivo además lo da por excluido."
        fi
        ;;
      *)
        if [[ -n "$m" ]]; then
          bien "$x excluido: $m"
        else
          malo "$x quedó afuera del alcance y el archivo no lo declara excluido con su motivo."
        fi
        ;;
    esac
  done

  echo
  echo "== cada backend corrió y se reportó =="
  for b in $BACKENDS_CRUCE; do
    local j; j=$(campo_mp "$f" "$b" journal)
    if [[ -z "$j" ]]; then
      malo "$b: el archivo no trae su journal. Sin todos no hay cruce."
    elif [[ "$j" == "—" ]]; then
      # El guión es lo que el driver escribe cuando un backend NO CORRIÓ, y hay
      # que reconocerlo antes de medirlo: contarle los caracteres contesta "el
      # journal mide 1 caracteres", que manda a buscar un journal corrupto donde
      # lo que pasó es que no hubo corrida.
      malo "$b: NO CORRIÓ — no hay journal de este lado, y el cruce necesita TODOS."
    elif [[ ${#j} -ne 342 ]]; then
      malo "$b: el journal mide ${#j} caracteres y un journal son 171 bytes (342 hexa)."
    else
      bien "$b publicó un journal de 171 bytes"
    fi
  done

  echo
  echo "== cada ELF es el pineado =="
  for b in $BACKENDS_CRUCE; do
    local e pin; e=$(campo_mp "$f" "$b" elf); pin=$(sha_pineado "$b")
    if [[ "$e" == *"sha256 $pin"* && "$e" == *"($(bytes_pineados "$b") B"* ]]; then
      bien "$b: $e"
    else
      malo "$b: la fila del ELF (\"$e\") no cita el pin de la receta ($(bytes_pineados "$b") B, sha256 $pin)."
    fi
  done

  echo
  echo "== la afirmación central: los $n_backends journals son los mismos 171 bytes =="
  primero=${BACKENDS_CRUCE%% *}
  j0=$(campo_mp "$f" "$primero" journal)
  for b in $BACKENDS_CRUCE; do
    [[ "$b" == "$primero" ]] && continue
    local j; j=$(campo_mp "$f" "$b" journal)
    if [[ -z "$j0" || -z "$j" || "$j0" == "—" || "$j" == "—" ]]; then
      malo "$primero vs $b: falta un journal (no corrió), no hay nada que cruzar."
    elif [[ "$j" == "$j0" ]]; then
      bien "$primero y $b publican los mismos 171 bytes"
    else
      malo "$primero vs $b: los journals DIFIEREN. Al menos uno computó otra cosa."
      echo "       $primero $j0" >&2
      echo "       $b $j" >&2
    fi
  done
  [[ ${#j0} -eq 342 ]] && echo "       $j0"

  # Los campos, derivados del hexa y contrastados contra CADA par de la
  # sección del cruce. Dos afirmaciones independientes sobre el mismo hecho;
  # matar una no alcanza.
  echo
  echo "== los campos del cruce salen del journal, no de la marca del driver =="
  local n_par; n_par=$(awk '/^EL CRUCE/{on=1;next} on && /^VEREDICTO/{on=0} on && $1=="par"' "$f" | wc -l | tr -d ' ')
  if [[ "$n_par" -eq "$pares" ]]; then
    bien "la sección del cruce trae los $pares pares contra $primero"
  else
    malo "la sección del cruce trae $n_par pares y el orden pide $pares."
  fi
  if [[ ${#j0} -eq 342 ]]; then
    # El layout v2: version · mode · chain_id (8 B) · fork · block_hash ·
    # parent_hash · pre_state_root · post_state_root · output_digest.
    local v_hex="${j0:0:2}" m_hex="${j0:2:2}"
    local chain_hex="${j0:4:16}" fork_hex="${j0:20:2}"
    local bh="0x${j0:22:64}" ph="0x${j0:86:64}" pre="0x${j0:150:64}"
    local post="0x${j0:214:64}" dig="0x${j0:278:64}"
    local chain="" fork=""
    [[ "$chain_hex" =~ ^[0-9a-fA-F]{16}$ ]] && chain=$((16#$chain_hex))
    [[ "$fork_hex" =~ ^[0-9a-fA-F]{2}$ ]] && fork=$((16#$fork_hex))
    if [[ "$v_hex" == "02" ]]; then
      bien "version 2"
    else
      malo "version: el byte 0 del journal es \`$v_hex\` y el formato es el 2."
    fi
    for par in "chain_id:$chain" "fork:$fork" "block_hash:$bh" "parent_hash:$ph" \
               "pre_state_root:$pre" "post_state_root:$post" "output_digest:$dig"; do
      local campo="${par%%:*}" valor="${par#*:}"
      local filas buenas
      filas=$(filas_cruce "$f" "$campo")
      buenas=$(printf '%s\n' "$filas" | grep -cxF "ok $valor" || true)
      if [[ -z "$filas" ]]; then
        malo "$campo: la sección del cruce no lo publicó."
      elif [[ "$buenas" -eq "$pares" && "$(printf '%s\n' "$filas" | wc -l | tr -d ' ')" -eq "$pares" ]]; then
        bien "$campo $valor (los $pares pares)"
      else
        malo "$campo: el journal dice $valor y el cruce dice: $(printf '%s' "$filas" | tr '\n' '|')"
      fi
    done
    # El byte de modo, **derivado del journal como los otros campos**, y
    # contrastado contra el peldaño que el archivo dice haber corrido, que lo
    # escribe la receta desde su propio flag: dos fuentes independientes.
    local m_dec="" modo_pedido
    modo_pedido=$(awk '$1 == "peldaño" { print $NF; exit }' "$f")
    [[ "$m_hex" =~ ^[0-9a-fA-F]{2}$ ]] && m_dec=$((16#$m_hex))
    if [[ -z "$m_dec" ]]; then
      malo "mode: el byte 1 del journal (\`$m_hex\`) no es hexa."
    elif [[ -z "$modo_pedido" ]]; then
      malo "mode: el archivo no dice qué peldaño se corrió, así que el byte de modo no se puede contrastar contra nada."
    elif [[ "$m_dec" != "$modo_pedido" ]]; then
      malo "mode: el journal trae el modo $m_dec (byte 0x$m_hex) y el archivo dice que se corrió el modo $modo_pedido."
    elif [[ "$(filas_cruce "$f" mode | grep -vc '^ok ' || true)" -ne 0 ]]; then
      malo "mode: algún par del cruce no lo afirmó."
    else
      bien "mode $m_dec (byte 0x$m_hex), el peldaño que el archivo dice"
    fi
    # **La vacuidad es el modo de falla clásico de este repo.** Un journal en
    # ceros lo publican backends que no computaron nada, y el cruce saldría
    # verde igual. Se exige que el peldaño que firma evidencia diga algo.
    if [[ "$post$dig" == "0x0000000000000000000000000000000000000000000000000000000000000000""0x0000000000000000000000000000000000000000000000000000000000000000" ]]; then
      malo "el journal es TRIVIAL: post_state_root y output_digest en cero."
      echo "       Backends que no computaron nada publicarían esto mismo." >&2
    else
      bien "el journal no es trivial (hay al menos un campo computado)"
    fi
  fi

  # **El oráculo y la política se RECOMPUTAN desde el hexa, no se leen de la
  # fila que escribió el driver.** Cada journal se decodifica acá y cada campo
  # se contrasta contra el caso congelado (`block-journal.txt`), igual que
  # `verificar()` hace con una corrida sola; y la política de bloque se
  # rehace con lo mismo que exige `require_full_block`: versión 2, modo
  # `Full`, cadena, fork, block_hash y parent_hash del caso, roots y digest no
  # nulos. Una fila `ok` editada a mano, o escrita por un driver que se salteó
  # el chequeo, no alcanza para pasar.
  echo
  echo "== cada journal, decodificado acá, contra el caso congelado =="
  local peldano_fx cero="0x0000000000000000000000000000000000000000000000000000000000000000"
  peldano_fx=$(awk '$1 == "peldaño" { print $NF; exit }' "$f")
  for b in $BACKENDS_CRUCE; do
    local jb campos
    jb=$(campo_mp "$f" "$b" journal)
    if ! campos=$(campos_de_journal "$jb"); then
      malo "$b: el journal no se puede decodificar (no son 342 hexa)."
      continue
    fi
    if [[ "$peldano_fx" != "0" ]]; then
      echo "  --   $b: el peldaño $peldano_fx no es el bloque; el caso congelado es de \`Full\` y no aplica (el oráculo de este peldaño es la fila del driver)."
      continue
    fi
    local v md ch fk bh ph pre post dig nombre_campo valor esperado mal_b=0
    read -r v md ch fk bh ph pre post dig <<< "$campos"
    for par in "version:$v" "mode:$md" "chain_id:$ch" "fork:$fk" "block_hash:$bh" \
               "parent_hash:$ph" "pre_state_root:$pre" "post_state_root:$post" "output_digest:$dig"; do
      nombre_campo="${par%%:*}" valor="${par#*:}"
      esperado=$(campo_fixture "$nombre_campo")
      if [[ -z "$esperado" ]]; then
        malo "$b: el caso congelado no trae \`$nombre_campo\`."; mal_b=1
      elif [[ "$valor" != "$esperado" ]]; then
        malo "$b $nombre_campo: el journal dice $valor y el caso congelado $esperado."; mal_b=1
      fi
    done
    [[ $mal_b -eq 0 ]] && bien "$b: los 9 campos del journal son los del caso congelado"
    # La política, recomputada. Los campos de identidad ya se contrastaron
    # arriba; acá se suma lo que el caso no dice: que lo computado no sea cero.
    if [[ "$v" == "2" && "$md" == "0" && $mal_b -eq 0 && \
          "$pre" != "$cero" && "$post" != "$cero" && "$dig" != "$cero" ]]; then
      bien "$b: la política de bloque, recomputada desde el hexa, acepta el journal"
    else
      malo "$b: la política de bloque, recomputada desde el hexa, RECHAZA el journal."
    fi
  done

  echo

  echo "== cada backend coincide además con su PROPIO oráculo =="
  # El cruce solo dice que coinciden entre sí. Dos ELFs viejos del mismo commit
  # coinciden perfectamente y computan otra cosa que el árbol de hoy — medido,
  # no hipotético. Lo que separa "todos iguales" de "todos bien" es esta fila.
  for b in $BACKENDS_CRUCE; do
    local o; o=$(campo_mp "$f" "$b" oraculo)
    case "$o" in
      ok*) bien "$b vs su oráculo: $o" ;;
      "") malo "$b: el archivo no dice cómo salió contra su oráculo." ;;
      *)  malo "$b vs su oráculo: $o" ;;
    esac
  done

  # **La política de bloque, por backend, exigida.** Con el peldaño `Full`
  # cada journal tiene que pasar `require_full_block`; con otro peldaño la
  # fila tiene que decir que no aplica — un "ok" ahí afirmaría un chequeo que
  # no corrió.
  echo
  echo "== la política de bloque del consumidor, por backend =="
  local modo_pedido_p; modo_pedido_p=$(awk '$1 == "peldaño" { print $NF; exit }' "$f")
  for b in $BACKENDS_CRUCE; do
    local p; p=$(campo_mp "$f" "$b" politica)
    if [[ -z "$p" ]]; then
      malo "$b: falta la fila de la política de bloque."
    elif [[ "$modo_pedido_p" == "0" ]]; then
      case "$p" in
        ok*) bien "$b: $p" ;;
        *) malo "$b: el peldaño es Full y la política dice \"$p\"." ;;
      esac
    else
      case "$p" in
        "no aplica"*) bien "$b: $p" ;;
        *) malo "$b: el peldaño $modo_pedido_p no es un bloque y la política dice \"$p\"." ;;
      esac
    fi
  done

  # **Lo que se le corrió a cada backend es un dato del archivo, por backend.**
  # Desde que un backend puede probar y otro no, "con prueba / sin prueba"
  # dejó de ser una propiedad de la corrida: preguntarlo global le aplicaría al
  # que probó el chequeo del que no, y saldría verde por vacuidad.
  echo
  echo "== las tres puntas y la memoria, por backend, según lo que a cada uno se le corrió =="
  for b in $BACKENDS_CRUCE; do
    local c t fases fase; c=$(campo_mp "$f" "$b" corrida); t=$(campo_mp "$f" "$b" puntas)
    fases="execute"
    case "$c" in
      "execute+prove+verify")
        fases="execute prove verify"
        case "$t" in
          ok*) bien "$b probó y verificó: $t" ;;
          *) malo "$b: el archivo dice que probó y falta la aserción \`execute == prove == verify\` (dice \"$t\")." ;;
        esac
        # Y la prueba tiene que existir: una fila de puntas en `ok` con un
        # `prove` que no corrió sería una afirmación sin objeto.
        local pr; pr=$(campo_mp "$f" "$b" prove)
        case "$pr" in
          *"bytes de prueba"*) bien "$b: $pr" ;;
          *) malo "$b: el archivo dice que probó y la fila de prove dice \"$pr\"." ;;
        esac
        ;;
      "solo execute")
        case "$t" in
          "no se corrieron"*) bien "$b corrió solo \`execute\`, y el archivo lo dice ($t)" ;;
          *) malo "$b: el archivo dice \`solo execute\` y la fila de puntas dice \"$t\"." ;;
        esac
        ;;
      "") malo "$b: el archivo no dice qué se le corrió. Sin eso, el chequeo de las puntas no sabe qué exigir." ;;
      *)  malo "$b: corrida desconocida \"$c\"." ;;
    esac
    # La memoria de cada fase corrida tiene su fila, medida o con el motivo
    # por el que no se midió: una fase sin fila es un hueco que se lee como
    # "no consumió nada".
    for fase in $fases; do
      local m; m=$(memoria_mp "$f" "$b" "$fase")
      [[ -z "$m" ]] && m=$(memoria_mp "$f" "$b" todas)
      if [[ -z "$m" ]]; then
        malo "$b: falta la fila de memoria de \`$fase\`."
      elif [[ "$m" == *" pico "* && "$m" != *"page cache"* ]]; then
        # Un pico sin decir qué cuenta se lee como RSS del prover, y el
        # número de `memory.peak` incluye shmem y page cache.
        malo "$b memoria \`$fase\`: el pico no dice qué cuenta (\"$m\")."
      else
        bien "$b memoria $m"
      fi
    done
    # **El arranque no es de una fase**: su fase empezó antes de que existiera
    # el cgroup, así que el número es el acumulado desde que nació el
    # contenedor, y la fila tiene que decirlo así.
    local arr; arr=$(memoria_mp "$f" "$b" arranque)
    if [[ "$arr" == *" pico "* && "$arr" != *"desde que nació el contenedor"* ]]; then
      malo "$b memoria \`arranque\`: la fila no dice que es acumulada desde que nació el contenedor (\"$arr\")."
    fi
  done

  # **La procedencia del binario y de la imagen de ZisK.** Son filas que las
  # corridas anteriores no escribían, así que se exigen solo a las nuevas: en
  # la corrida en vivo siempre (`$2 = nueva`), y en `--verificar-log` cuando el
  # archivo es del formato nuevo (trae la fila `árbol`). Exigirlas a un archivo
  # viejo lo volvería rojo por algo que no existía cuando se corrió; re-correr
  # para agregarlas costaría horas de prueba sin cambiar ningún número.
  if [[ "${2:-}" == "nueva" || -n "$(awk '$1 == "árbol"' "$f")" ]]; then
    echo
    echo "== de qué binario y de qué imagen salió la corrida =="
    local cm; cm=$(awk -F' *: *' '$1 == "commit" { print $2; exit }' "$f")
    if [[ "$cm" =~ ^[0-9a-f]{7}\ \(del\ binario\ zkvm ]]; then
      bien "commit del binario: ${cm%% *}"
    else
      malo "la fila \`commit\` no trae el commit embebido en el binario (dice \"$cm\")."
    fi
    if [[ " $BACKENDS_CRUCE " == *" zisk "* ]]; then
      local im en; im=$(campo_mp "$f" zisk imagen); en=$(campo_mp "$f" zisk entorno)
      if [[ "$im" == *"PROOFMAN_SETTLE_TIMEOUT_S=$ZISK_SETTLE_TIMEOUT_S" && "$im" == *"base $ZISK_BASE_DIGEST "* ]]; then
        bien "zisk imagen: $im"
      else
        malo "zisk: la fila \`imagen\` no nombra la derivada de la base $ZISK_BASE_DIGEST con PROOFMAN_SETTLE_TIMEOUT_S=$ZISK_SETTLE_TIMEOUT_S (dice \"$im\")."
      fi
      if [[ "$en" == *"PROOFMAN_SETTLE_TIMEOUT_S=$ZISK_SETTLE_TIMEOUT_S (de la imagen"* ]]; then
        bien "zisk: el tope de asentamiento leído de la imagen es el de la receta"
      else
        malo "zisk: la fila \`entorno\` no lee PROOFMAN_SETTLE_TIMEOUT_S=$ZISK_SETTLE_TIMEOUT_S de la imagen (dice \"$en\")."
      fi
    fi
  fi

  echo
  echo "== ninguna fila del archivo quedó en FAIL =="
  if grep -qE '(^|  )FAIL' "$f"; then
    malo "el archivo trae filas en FAIL:"
    grep -nE '(^|  )FAIL' "$f" | sed 's/^/       /' >&2
  else
    bien "sin FAIL"
  fi
}

# --- modo "solo chequeo": para las mutaciones --------------------------------
#
# El archivo dice cuál de los dos chequeos le corresponde. **Se decide por el
# contenido y no por un flag**: un flag equivocado aplicaría el chequeo de una
# afirmación al archivo de la otra, y saldría verde por vacuidad.

if [[ -n "$SOLO_LOG" ]]; then
  [[ -f "$SOLO_LOG" ]] || { echo "error: no existe $SOLO_LOG" >&2; exit 1; }
  echo "[nivel 4] chequeando un log YA producido: $SOLO_LOG"
  echo "[nivel 4] esto NO escribe evidencia: un log de archivo no es una corrida."
  if grep -q "$MARCA_MP" "$SOLO_LOG"; then
    echo "[nivel 4] es el contraste entre backends."
    verificar_multiproof "$SOLO_LOG"
  else
    verificar "$SOLO_LOG" 0
  fi
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
CPUS=$(nproc 2>/dev/null || sysctl -n hw.ncpu)

# --- la caja, que es parte del número ----------------------------------------
#
# Un tiempo de `prove` es del par (programa, caja): el mismo ELF, con los mismos
# ciclos y la prueba del mismo tamaño AL BYTE, se midió en 174,66 s en una caja
# y en 362 s en otra. Un número de segundos sin la caja al lado no se puede
# comparar ni reproducir, así que la caja viaja escrita en la evidencia.
#
# **Y la memoria que manda no es la del host: es la que el demonio de Docker
# ve.** En Linux nativo son la misma; en una Mac el techo es el de la VM de
# Docker, que es contra el que muere un `prove` que no entra. Reportar solo la
# del host diría "32 GiB" de una caja donde el prover tiene 19,5.

ram_host() {
  if command -v free >/dev/null 2>&1; then
    free -g 2>/dev/null | awk '/^Mem:/{print $2" GiB"}'
  elif [[ "$SO" == "Darwin" ]]; then
    awk -v b="$(sysctl -n hw.memsize 2>/dev/null || echo 0)" \
        'BEGIN{ if (b > 0) printf "%.0f GiB", b/1073741824; else print "?" }'
  else
    echo "?"
  fi
}

# Devuelve vacío —y NUNCA falla— si el demonio no contesta: bajo `set -e` una
# función que sale distinto de cero acá mataría la receta entera por no poder
# imprimir un dato de contexto.
ram_docker() {
  local b
  b=$(docker info --format '{{.MemTotal}}' 2>/dev/null) || return 0
  if [[ -n "$b" && "$b" != "0" ]]; then
    awk -v b="$b" 'BEGIN{printf "%.1f GiB", b/1073741824}'
  fi
  return 0
}

CAJA="$SO $ARCH, $CPUS cpus, $(ram_host) de RAM"
echo "[nivel 4] entorno: $CAJA"

if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" && $MULTI -eq 1 ]]; then
  # **Para el cruce la arquitectura no es una precondición, es un dato.** Lo que
  # x86_64 decide es si `prove` del bloque entero entra en memoria; que dos
  # backends publiquen los mismos 171 bytes no depende de eso. Lo que sí depende
  # es el COSTO, así que la arquitectura queda ESCRITA en la evidencia en vez de
  # cerrarle la puerta a la afirmación que no la necesita.
  echo "[nivel 4] arquitectura $ARCH: las imágenes de \`ere\` son amd64 y acá corren"
  echo "[nivel 4] EMULADAS. Los tiempos de abajo no son comparables con los de una"
  echo "[nivel 4] caja nativa, y así queda dicho en la evidencia."
elif [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" ]]; then
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

# Se lee una vez, acá: `docker info` levanta el demonio si hace falta y no es
# gratis, y llamarlo desde adentro del bloque que escribe la evidencia lo
# metería en la medición de tiempo de la receta.
RAM_DOCKER=$(ram_docker || true)
[[ -n "$RAM_DOCKER" ]] && echo "[nivel 4] memoria que ve Docker: $RAM_DOCKER"

# El camino de Docker se elige por entorno porque `ere` lo lee del proceso.
export ERE_IMAGE_REGISTRY="${ERE_IMAGE_REGISTRY:-$REGISTRY_POR_DEFAULT}"
echo "[nivel 4] ERE_IMAGE_REGISTRY=$ERE_IMAGE_REGISTRY"

# Las imágenes publicadas son SOLO amd64. En arm64 el `docker pull` falla
# (`no matching manifest for linux/arm64`) y `ere` cae a construir imágenes
# arm64 locales con el nombre de las publicadas, o sea que la corrida mediría
# otra cosa con el mismo nombre. Fijar la plataforma hace que el pull
# encuentre el manifiesto (emulado en arm64, nativo en x86_64, donde no cambia
# nada).
export DOCKER_DEFAULT_PLATFORM="${DOCKER_DEFAULT_PLATFORM:-linux/amd64}"
echo "[nivel 4] DOCKER_DEFAULT_PLATFORM=$DOCKER_DEFAULT_PLATFORM"

# El segmento de OpenVM viaja por el mismo camino y por el mismo motivo: `ere` lo
# lee del proceso y el driver no puede exportarlo desde adentro (`set_var` es
# `unsafe` en la edición 2024). El valor de la receta es el DEFAULT: lo que ya
# esté en el entorno manda, para poder mover la palanca sin recompilar.
export ERE_OPENVM_SEGMENT_MEMORY="${ERE_OPENVM_SEGMENT_MEMORY:-$SEGMENTO_OPENVM_POR_DEFAULT}"
echo "[nivel 4] ERE_OPENVM_SEGMENT_MEMORY=$ERE_OPENVM_SEGMENT_MEMORY"

# --- de qué configuración salió cada número ----------------------------------
#
# **La regla es (programa, caja, segmento) o no se cita.** El costo de OpenVM
# depende del segmento Y de la caja —medido: el mismo ELF, en el mismo modo y con
# el mismo runtime, dio 5,14x entre dos hosts—, y que su `prove` entre en memoria
# depende del segmento y del techo del contenedor: con el default de `ere` murió
# por OOM y con 4 GiB entró. Un archivo que trae los números sin esa fila deja al
# lector deduciendo la configuración, y así es como un número correcto termina
# citándose para una corrida que no es la suya.
#
# **El techo del contenedor se OBSERVA, no se declara.** Quien lo pone puede ser
# esta receta o quien la lanzó (`docker update` desde afuera, que es como se
# corrió la primera vez que los dos backends probaron), así que lo único que no
# miente es preguntárselo a Docker mientras el contenedor vive — después no
# existe más. Sin observación no se escribe "sin límite": eso sería afirmar lo
# que no se midió. Se escribe "no observado".
#
# **Y se observa mientras vive, no una sola vez.** El techo se puede cambiar con
# el contenedor ya arrancado (`docker update`), y la primera lectura puede caer
# antes de ese cambio: pasó, y la evidencia dijo "sin límite" de un contenedor
# que corrió con 56 GiB. Por eso cada valor DISTINTO que se ve se agrega al
# historial del backend, y la fila reporta el último junto con los anteriores.
OBSERVADOR=""
DIR_ENTORNO=""
observar_contenedores() { # $1 = directorio donde dejar lo observado
  local dir="$1"
  (
    local n b lim
    while :; do
      for n in $(docker ps --filter 'name=ere-server' --format '{{.Names}}' 2>/dev/null); do
        # El nombre lo arma `ere` con el `Display` de su enum de backend: se
        # matchea por subcadena y no por nombre exacto, como hace `vigilar`.
        case "$n" in
          *sp1*) b=sp1 ;;
          *openvm*) b=openvm ;;
          *zisk*) b=zisk ;;
          *) continue ;;
        esac
        lim=$(docker inspect -f '{{.HostConfig.Memory}}' "$n" 2>/dev/null || true)
        [[ -n "$lim" ]] || continue
        if [[ ! -f "$dir/$b" || "$(tail -n 1 "$dir/$b")" != "$lim" ]]; then
          echo "$lim" >> "$dir/$b"
        fi
      done
      sleep 2
    done
  ) &
  OBSERVADOR=$!
}

en_gib() { awk -v b="$1" 'BEGIN{ printf "%.2f GiB", b / 1073741824 }'; }

# El `sha256` de un archivo: `sha256sum` en Linux, `shasum -a 256` en macOS.
# Vacío si ninguno está o falla, y el que lo compara lo trata como distinto.
sha256_de() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
  fi
}

# El segmento con el que corrió cada backend. Es una palanca de OpenVM: para SP1
# la fila dice que no aplica, en vez de repetir un número que no lo toca —lo
# midió `docker inspect`, que muestra la variable en el contenedor de OpenVM y
# NO en el de SP1—.
segmento_de() { # $1=backend
  if [[ "$1" == "zisk" ]]; then
    echo "segmento: no aplica (es palanca de OpenVM) · $(palancas_zisk)"
    return
  fi
  if [[ "$1" != "openvm" ]]; then
    echo "segmento: no aplica (es palanca de OpenVM)"
    return
  fi
  echo "segmento: $ERE_OPENVM_SEGMENT_MEMORY B ($(en_gib "$ERE_OPENVM_SEGMENT_MEMORY"), ERE_OPENVM_SEGMENT_MEMORY)"
}

# **Las palancas de ZisK que cambian si el `prove` cierra.** Las `ERE_ZISK_*`
# las reenvía `ere` al contenedor desde este entorno; el tope de asentamiento
# del proofman (`PROOFMAN_SETTLE_TIMEOUT_S`) `ere` NO lo reenvía, así que solo
# puede venir de la imagen del servidor (ver scripts/zisk-image.sh). Se lee de
# la imagen con el nombre EXACTO que `ere` levanta, y si no trae el tope de la
# constante la fila dice FAIL: con el default de 600 s el `prove` no cierra en
# CPU, y escribirlo como un valor más sería esconder otra configuración.
palancas_zisk() {
  local img settle
  img=$(zisk_imagen_de_ere)
  settle=$(zisk_settle_de "$img")
  if [[ "$settle" != "$ZISK_SETTLE_TIMEOUT_S" ]]; then
    settle="FAIL ${settle:-ausente} (la receta exige $ZISK_SETTLE_TIMEOUT_S)"
  fi
  printf 'palancas de zisk: ERE_ZISK_MAX_STREAMS=%s · ERE_ZISK_MAX_RECURSIVE_STREAMS=%s · ERE_ZISK_NUMBER_THREADS_WITNESS=%s · PROOFMAN_SETTLE_TIMEOUT_S=%s (de la imagen %s, id %s)' \
    "${ERE_ZISK_MAX_STREAMS:-default}" "${ERE_ZISK_MAX_RECURSIVE_STREAMS:-default}" \
    "${ERE_ZISK_NUMBER_THREADS_WITNESS:-default}" \
    "$settle" "$img" "$(zisk_id_de "$img")"
}

techo_legible() { # $1=bytes de HostConfig.Memory; 0 = sin límite
  if [[ "$1" == "0" ]]; then echo "sin límite"; else en_gib "$1"; fi
}

limite_de() { # $1=backend
  local f="$DIR_ENTORNO/$1" v previos n
  if [[ -z "$DIR_ENTORNO" || ! -f "$f" ]]; then
    echo "memoria del contenedor: no observado"
    return
  fi
  # El último valor visto es el que tenía el contenedor al final; si antes se
  # vio otro, se dice cuál, en orden, para que el cambio no quede escondido.
  v=$(tail -n 1 "$f")
  n=$(wc -l < "$f" | tr -d ' ')
  if [[ "$n" -le 1 ]]; then
    echo "memoria del contenedor: $(techo_legible "$v") (observado)"
    return
  fi
  previos=$(head -n $((n - 1)) "$f" | while read -r p; do printf '%s → ' "$(techo_legible "$p")"; done)
  echo "memoria del contenedor: $(techo_legible "$v") (observado; cambió durante la corrida: ${previos}$(techo_legible "$v"))"
}

# --- el contraste entre backends ---------------------------------------------
#
# Se corre acá y no al final porque no comparte nada con la receta de abajo: ni
# el ELF (son tres), ni el archivo de evidencia. Lo único compartido es el
# entorno.

elf_de() { # $1=backend
  case "$1" in
    sp1) echo "$ELF_SP1" ;;
    openvm) echo "$ELF_OPENVM" ;;
    zisk) echo "$ELF_ZISK" ;;
  esac
}

# Las filas de memoria de un backend, legibles, desde las líneas compactas
# `memoria|backend|fase|pico|base|ventana|qué cuenta` que imprime el driver.
memoria_legible() { # $1=log $2=backend
  awk -F'|' -v b="$2" '
    $1 == "memoria" && $2 == b {
      if (NF >= 6 && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/) {
        printf "  memoria   %-10s pico %.2f GiB (%s) · base %.2f GiB · %s\n", $3, $4/1073741824, (NF >= 7 ? $7 : "sin decir qué cuenta"), $5/1073741824, $6
      } else {
        printf "  memoria   %-10s %s\n", $3, $4
      }
    }
  ' "$1"
}

if [[ $MULTI -eq 1 ]]; then
  # **Un alcance reducido sin motivo no se corre**, y un motivo sin nadie
  # excluido tampoco: el motivo va a la evidencia pegado a cada excluido, y
  # cualquiera de los dos desajustes la dejaría diciendo algo que no pasó.
  if [[ -n "$EXCLUIDOS" && -z "${MOTIVO_EXCLUIDOS// /}" ]]; then
    echo "error: el alcance deja afuera a $EXCLUIDOS y falta --motivo-excluidos \"<por qué>\"." >&2
    exit 2
  fi
  if [[ -z "$EXCLUIDOS" && -n "$MOTIVO_EXCLUIDOS" ]]; then
    echo "error: --motivo-excluidos sin ningún backend excluido: el alcance es el orden entero." >&2
    exit 2
  fi
  if [[ -n "$SIN_PRUEBA_DE" && " $BACKENDS_CRUCE " != *" $SIN_PRUEBA_DE "* ]]; then
    echo "error: --sin-prueba-de $SIN_PRUEBA_DE nombra un backend fuera del alcance ($BACKENDS_CRUCE)." >&2
    exit 2
  fi
  # **Cada ELF se aserta contra su pin antes de levantar nada.** El contraste
  # con el oráculo nativo caza un ELF viejo que computa otra cosa; el pin caza
  # además uno que computa LO MISMO con otro binario, que es el que la
  # evidencia tiene que nombrar.
  for b in $BACKENDS_CRUCE; do
    e=$(elf_de "$b")
    [[ -f "$e" ]] || {
      echo "error: no existe $e" >&2
      echo "       producilo con: cargo run --release -p zkvm -- compile --backend $b --out $e" >&2
      exit 1
    }
    tam=$(wc -c < "$e" | tr -d ' ')
    sha=$(sha256_de "$e")
    if [[ "$tam" != "$(bytes_pineados "$b")" || "$sha" != "$(sha_pineado "$b")" ]]; then
      echo "error: el ELF de $b ($e) mide $tam B con sha256 ${sha:-ilegible};" >&2
      echo "       el pin de la receta es $(bytes_pineados "$b") B con sha256 $(sha_pineado "$b")." >&2
      exit 1
    fi
    echo "[cruce] $b: $e ($tam B, sha256 $sha, el pineado)"
  done

  # **La imagen de ZisK es parte de la receta, como el ELF.** Se deriva (o se
  # confirma que ya está) antes de levantar nada, y si el nombre que `ere`
  # levanta no es la derivada con el tope de la constante, no se corre: caer
  # al default de 600 s mediría otra configuración con el mismo nombre.
  IMAGEN_ZISK=""
  if [[ " $BACKENDS_CRUCE " == *" zisk "* ]]; then
    zisk_derivar || { echo "error: no se pudo derivar la imagen de zisk (scripts/zisk-image.sh)." >&2; exit 1; }
    if ! IMAGEN_ZISK=$(zisk_verificar); then
      echo "error: la imagen de zisk no es la derivada con PROOFMAN_SETTLE_TIMEOUT_S=$ZISK_SETTLE_TIMEOUT_S:" >&2
      echo "       $IMAGEN_ZISK" >&2
      exit 1
    fi
    echo "[cruce] zisk: $IMAGEN_ZISK"
  fi

  LOG_MP=$(mktemp -t cruce-XXXXXX)
  TEMPORALES+=("$LOG_MP")
  DIR_ENTORNO=$(mktemp -d -t entorno-XXXXXX)
  TEMPORALES+=("$DIR_ENTORNO")
  ARGS_MP=(multiproof --elf-sp1 "$ELF_SP1" --elf-openvm "$ELF_OPENVM" --elf-zisk "$ELF_ZISK" --mode "$MODO" --costo)
  ARGS_MP+=(--backends "${BACKENDS_CRUCE// /,}")
  [[ $SIN_PRUEBA -eq 1 ]] && ARGS_MP+=(--sin-prueba)
  [[ -n "$SIN_PRUEBA_DE" ]] && ARGS_MP+=(--sin-prueba-de "$SIN_PRUEBA_DE")
  echo "[cruce] corriendo los backends en secuencia (modo $MODO)…"
  # Arranca ANTES que el driver: los contenedores nacen y mueren adentro de la
  # corrida, y lo que no se observó mientras vivían no se puede reconstruir
  # después.
  observar_contenedores "$DIR_ENTORNO"
  T0=$(date +%s)
  set +e
  cargo run --release -p zkvm -- "${ARGS_MP[@]}" 2>&1 | tee "$LOG_MP"
  DRIVER=${PIPESTATUS[0]}
  set -e
  T1=$(date +%s)
  if [[ -n "$OBSERVADOR" ]]; then
    kill "$OBSERVADOR" 2>/dev/null || true
    wait "$OBSERVADOR" 2>/dev/null || true
    OBSERVADOR=""
  fi

  # La línea compacta que el driver imprime por backend. Se parsea de ahí y no
  # de la tabla legible: la tabla está para leer y esto para extraer, y mezclar
  # las dos cosas hace que un cambio de formato rompa el gate en silencio.
  linea_backend() { grep -E "^resumen\|$1\|" "$LOG_MP" | head -1; }
  campo_linea() { echo "$1" | cut -d'|' -f"$2"; }

  mkdir -p "$(dirname "$EVIDENCIA_MP")"
  N_ALCANCE=$(echo $BACKENDS_CRUCE | wc -w | tr -d " ")
  LISTA_ALCANCE=${BACKENDS_CRUCE// /, }
  {
    echo "CONTRASTE ENTRE BACKENDS — el journal de cada uno contra el del primero"
    echo "======================================================================="
    echo
    echo "Generado por \`scripts/prove-block.sh --multiproof\`."
    echo
    echo "LO QUE ESTE ARCHIVO AFIRMA, Y LO QUE NO"
    echo "---------------------------------------"
    echo
    echo "AFIRMA: $N_ALCANCE backends independientes ($LISTA_ALCANCE) corren el MISMO"
    echo "programa y publican el MISMO journal de 171 bytes, contrastado como bytes y"
    echo "campo por campo; y cada uno coincide además con su PROPIO oráculo. Las dos"
    echo "mitades hacen falta: los backends pueden coincidir entre sí y estar todos"
    echo "equivocados — medido, con dos ELFs de un commit anterior que daban el mismo"
    echo "digest y no el del árbol."
    if [[ "$MODO" == "0" ]]; then
      echo
      echo "AFIRMA además, con el peldaño \`Full\` (el bloque entero): que el journal de"
      echo "cada backend pasa la política del consumidor (\`require_full_block\`):"
      echo "versión, modo, cadena, fork, block_hash y parent_hash recomputados del input,"
      echo "roots y digest no nulos. La fila \`politica\` de cada backend lo dice."
    else
      echo
      echo "NO AFIRMA el bloque real: el peldaño de acá no es \`Mode::Full\`, y la"
      echo "política de bloque no aplica a un journal que no dice ser un bloque."
    fi
    echo
    echo "NO AFIRMA nada sobre el COSTO de OpenVM. Su guest se compila bajo la"
    echo "cuarentena que su \`Cargo.toml\` documenta (\`opt-level = 0\`), así que sus"
    echo "números son los de un binario inflado a propósito; compararlos contra los de"
    echo "los otros —que corren optimizados— sería comparar dos cosas distintas."
    echo
    echo "NO AFIRMA nada comparando el COSTO entre backends. Cada uno estima el costo"
    echo "de probar una corrida en SU unidad —sp1 pesa \`3·área de traza + complejidad\`,"
    echo "openvm cuenta celdas de traza y zisk celdas de SUS tablas—, así que las"
    echo "columnas no se restan ni se dividen. La unidad viaja pegada al número."
    echo
    if [[ -n "$EXCLUIDOS" ]]; then
      echo "NO AFIRMA nada de $EXCLUIDOS: quedó afuera del alcance de esta corrida,"
      echo "declarado con \`--backends\`. El motivo está en la fila \`excluido\`."
      echo
    fi
    echo "NO AFIRMA que una prueba de zisk sea un ancla de confianza: con advisories de"
    echo "soundness abiertos upstream, es un voto del multiproof."
    echo
    echo "CÓMO SE LEEN LAS FILAS \`memoria\`: el pico de lo cargado al cgroup del"
    echo "contenedor del backend (anónima, shmem y page cache), leído de \`memory.peak\`"
    echo "del kernel —no de un muestreador—. \"de la fase\" es el máximo entre el"
    echo "reinicio antes de la fase y la lectura después, por el mismo descriptor;"
    echo "\"acumulado desde que nació el contenedor\" es el máximo desde entonces: el"
    echo "de \`arranque\` siempre (su fase empezó antes que el cgroup), y el de"
    echo "cualquier fase cuando el kernel no admitió el reinicio. Cada fila lo"
    echo "repite: el pico incluye anónima, shmem y page cache. \`base\` es lo cargado al empezar la"
    echo "fase. No es el piso con el que la corrida todavía termina, ni incluye al"
    echo "proceso del driver, que vive afuera del contenedor."
    echo
    echo "CÓMO SE LEEN LOS TIEMPOS: son de (programa, caja). La fila \`entorno\` trae el"
    echo "segmento de OpenVM y el techo observado de cada contenedor."
    if [[ $SIN_PRUEBA -eq 1 ]]; then
      echo
      echo "NO AFIRMA que los backends PRUEBEN este peldaño. Esta corrida es solo"
      echo "\`execute\`: lo que se cruza es lo que EJECUTAN. Que publiquen el mismo"
      echo "journal DENTRO de una prueba verificada es una afirmación más fuerte."
    elif [[ -n "$SIN_PRUEBA_DE" ]]; then
      echo
      echo "NO AFIRMA que TODOS los backends prueben este peldaño: $SIN_PRUEBA_DE corrió"
      echo "solo \`execute\` (--sin-prueba-de $SIN_PRUEBA_DE). El cruce vale lo que vale el"
      echo "lado más débil."
    fi
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" ]]; then
      echo
      echo "NO AFIRMA nada sobre el costo en general: esta máquina es $ARCH y las"
      echo "imágenes de \`ere\` son amd64, o sea que corren EMULADAS."
    fi
    echo
    echo "fecha         : $(date -u +%Y-%m-%d)"
    # El commit lo dice el BINARIO que corrió (lo embebe al compilarse), no el
    # `HEAD` de ahora: un `target/` que no se reconstruyó corre código viejo
    # sobre un árbol nuevo. El del árbol va al lado para que la diferencia se vea.
    echo "commit        : $(grep -E '^driver\|commit\|' "$LOG_MP" | head -1 | cut -d'|' -f3) (del binario zkvm, embebido al compilar)"
    echo "árbol         : $(git rev-parse --short HEAD)"
    echo "máquina       : $CAJA"
    echo "memoria docker: ${RAM_DOCKER:-—} (el techo que ve el prover, no el del host)"
    echo "kernel        : $(uname -r)"
    echo "imágenes      : $ERE_IMAGE_REGISTRY"
    echo "toolchain     : $(rustc -V)"
    echo "peldaño       : modo $MODO"
    echo "backends      : $BACKENDS_CRUCE"
    for x in $EXCLUIDOS; do
      echo "excluido      : $x — $MOTIVO_EXCLUIDOS"
    done
    echo "corrida       : $(for x in $BACKENDS_CRUCE; do printf "%s%s → %s" "${sep:-}" "$x" "$(corrida_de "$x")"; sep=" · "; done)"
    echo "receta entera : $((T1 - T0))s (incluye levantar los zkVM)"
    echo
    echo "POR BACKEND"
    echo "-----------"
    for b in $BACKENDS_CRUCE; do
      L=$(linea_backend "$b")
      elf_b=$(elf_de "$b")
      echo
      echo "  backend   $b"
      if [[ -z "$L" ]]; then
        echo "  sdk       —"
        echo "  corrida   $(corrida_de "$b")"
        echo "  elf       $elf_b ($(wc -c < "$elf_b" | tr -d ' ') B, sha256 $(sha256_de "$elf_b"))"
        echo "  execute   —"
        echo "  prove     —"
        echo "  verify    —"
        echo "  entorno   $(segmento_de "$b") · $(limite_de "$b")"
        echo "  puntas    NO CORRIÓ"
        echo "  oraculo   NO CORRIÓ"
        echo "  politica  NO CORRIÓ"
        echo "  journal   —"
        continue
      fi
      echo "  sdk       $(campo_linea "$L" 3)"
      # **La procedencia va pegada a los números, por backend.** Un costo y un
      # pico de OpenVM sin el segmento al lado no se pueden volver a producir, y
      # el techo del contenedor decide si el `prove` entra o lo mata el kernel:
      # las dos cosas son de la corrida, no del backend.
      echo "  entorno   $(segmento_de "$b") · $(limite_de "$b")"
      # La identidad de la imagen que se levantó: el nombre de `ere` es el
      # mismo para la publicada y para la derivada, así que solo el id dice
      # cuál fue.
      if [[ "$b" == "zisk" ]]; then echo "  imagen    $IMAGEN_ZISK"; fi
      # **Lo escribe la receta, no el driver.** Es lo que se le PIDIÓ a este
      # backend, y contra eso se contrasta lo que el driver dice que corrió.
      echo "  corrida   $(corrida_de "$b")"
      echo "  elf       $elf_b ($(wc -c < "$elf_b" | tr -d ' ') B, sha256 $(sha256_de "$elf_b"))"
      echo "  execute   $(campo_linea "$L" 5) · $(campo_linea "$L" 6) · $(campo_linea "$L" 7) bytes públicos"
      echo "  prove     $(campo_linea "$L" 8)"
      echo "  verify    $(campo_linea "$L" 9)"
      echo "  puntas    $(campo_linea "$L" 10)"
      echo "  oraculo   $(campo_linea "$L" 11)"
      echo "  politica  $(campo_linea "$L" 13)"
      memoria_legible "$LOG_MP" "$b"
      echo "  journal   $(campo_linea "$L" 12)"
    done
    echo
    echo "EL CRUCE"
    echo "--------"
    sed -n '/EL CRUCE — el journal/,/^$/p' "$LOG_MP" | grep -E '^  (ok|FAIL|par) ' || echo "  FAIL no se pudo cruzar"
    echo
    if [[ $DRIVER -eq 0 ]]; then
      echo "VEREDICTO: el cruce es verde — $N_ALCANCE backends ($LISTA_ALCANCE), el mismo programa, el mismo journal."
    else
      echo "VEREDICTO: ROJO — el driver salió con $DRIVER."
    fi
  } > "$EVIDENCIA_MP"

  [[ $DRIVER -eq 0 ]] || malo "el driver salió con $DRIVER"
  verificar_multiproof "$EVIDENCIA_MP" nueva

  echo
  echo "════════════════════════════════════════════════════════════════════════"
  cat "$EVIDENCIA_MP"
  echo "════════════════════════════════════════════════════════════════════════"

  if [[ $fail -ne 0 ]]; then
    echo >&2
    echo "RESULTADO: el contraste entre backends está ROJO." >&2
    exit 1
  fi
  echo
  echo "RESULTADO: el contraste entre backends es verde. Evidencia en $EVIDENCIA_MP"
  exit 0
fi

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
ELF_SHA256=$(sha256_de "$ELF")
if [[ "$ELF_SHA256" != "$ELF_SHA256_ESPERADO" ]]; then
  echo "error: el ELF mide lo esperado pero su sha256 es ${ELF_SHA256:-ilegible}" >&2
  echo "       y el pineado es $ELF_SHA256_ESPERADO. Mismo tamaño no es mismo ELF." >&2
  exit 1
fi
echo "[nivel 4] ELF: $ELF ($ELF_BYTES B, sha256 $ELF_SHA256, el parcheado)"

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
  verificar "$dir/log" 0 > "$dir/chequeo" 2>&1
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
    echo "ELF           : $ELF ($ELF_BYTES B, sha256 $ELF_SHA256 — el parcheado)"
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
TEMPORALES+=("$LOG")

if [[ -n "$LIMITE" ]]; then
  MARCA=$(mktemp -d -t limite-XXXXXX)
  echo "[nivel 4] con --memory=${LIMITE}g en el contenedor (ver por qué en el encabezado del flag)"
  vigilar "$LIMITE" "$MARCA"
fi

echo "[nivel 4] probando (modo $MODO) — levantar el zkVM son ~40 s y \`prove\` unos minutos…"
T0=$(date +%s)
set +e
cargo run --release -p zkvm -- prove --elf "$ELF" --mode "$MODO" --costo 2>&1 | tee "$LOG"
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

verificar "$LOG" "$MODO"

# --- los números de la corrida ----------------------------------------------

# Cada número se extrae acotado a su campo. Cortar por el prefijo y quedarse
# con "el resto de la línea" arrastraría el resto del `println!` adentro de la
# evidencia, y un artefacto versionado que copia ruido envejece mal.
# **El costo, con su unidad.** No se corta el número solo: cada backend estima
# en la suya —SP1 pesa `3·área de traza + complejidad`, OpenVM cuenta celdas de
# traza— y un número pelado en un archivo versionado invita a compararlo contra
# el de otro backend, o contra un conteo de ciclos de otra versión del runtime,
# que no es la misma cosa. La unidad viaja pegada porque es parte del dato.
COSTO=$(grep -E '^costo estimado: ' "$LOG" | head -1 | sed -E 's/^costo estimado: //' || true)
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
    echo "ELF           : $ELF ($ELF_BYTES B, sha256 $ELF_SHA256 — el parcheado)"
    echo "caso          : $CASO_LINEA"
    echo "input         : $(wc -c < "$CASO/block-input.bin" | tr -d ' ') bytes"
    echo "entorno       : $SO $ARCH nativo, $(nproc 2>/dev/null || echo '?') cpus, límite de memoria del contenedor: ${LIMITE:+${LIMITE} GiB}${LIMITE:-ninguno}"
    echo "fecha         : $(date -u +%Y-%m-%d)"
    echo "commit        : $(git rev-parse --short HEAD)"
    echo "toolchain     : $(rustc -V)"
    echo
    echo "execute       : ${COSTO:-<no estimado>}"
    echo "#   costo estimado por el backend, en SU unidad. NO es un conteo de"
    echo "#   ciclos y no se compara contra uno: hasta ere 0.16.2 esta línea decía"
    echo "#   2 566 473 ciclos, y ese número queda acá como historia y NO como"
    echo "#   punto de comparación — no comparable: otra unidad."
    echo "prove         : ${PRUEBA_S:-?} → ${PRUEBA_B:-?} bytes de prueba"
    echo "verify        : ${VERIFY_S:-?}"
    echo "politica      : $(grep -E '^  (ok|FAIL) +política de bloque: ' "$LOG" | head -1 | sed -E 's/^  (ok|FAIL) +política de bloque: /\1 — /')"
    memoria_legible "$LOG" sp1 | sed 's/^  memoria   /memoria       : /'
    echo "receta entera : ${DURACION}s (incluye levantar el zkVM)"
    echo
    echo "# Las aserciones. Las dos primeras hacen que \"verifica\" signifique algo:"
    echo "  execute == prove == verify : los mismos bytes públicos"
    for c in $CAMPOS_JOURNAL; do
      printf "  %-15s %s\n" "$c" "$(campo_fixture "$c")"
    done
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
