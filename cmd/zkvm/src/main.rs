//! El driver que corre el guest **adentro de un zkVM de verdad**.
//!
//! # Qué hace y qué no
//!
//! `execute` corre el guest; `prove` produce una prueba y `verify` la verifica.
//! El costo de probar una corrida es **otra ejecución** (`--costo`), y llega en
//! la unidad que define cada backend — no en ciclos, y no en la misma unidad
//! para dos backends. Que estén separados fue deliberado: probar es lento y
//! caro, y un guest que no ejecuta no prueba nada — juntar las dos cosas haría
//! imposible saber cuál de las dos falló.
//!
//! # Lo que hace que "verifica" signifique algo
//!
//! Un `verify` que devuelve `Ok` sin contrastar QUÉ verificó es un `[SAME]` que
//! no prueba nada: la prueba podría ser de otro programa, de otro input o de
//! otro modo. Por eso `prove` contrasta **los bytes públicos de las tres
//! puntas** —`execute`, `prove` y `verify`— y recién después decodifica el
//! journal y lo contrasta contra lo que el harness computó afuera.
//!
//! El journal se acepta con `repo_b_prover::require_full_block`. El bloque
//! esperado (`bloque_esperado`) recomputa `block_hash` y `parent_hash` del
//! input congelado y los contrasta contra `block-journal.txt`. **KNOWN:** la
//! cadena y el fork no tienen fuente independiente en el CLI — salen del input y
//! del archivo que escribió el harness, no de un chainspec del consumidor.
//!
//! # El peldaño por default entra en memoria, y eso está medido
//!
//! `prove` del bloque entero (`Mode::Full`, 4 884 110 ciclos) **no entra** en
//! los 19,5 GiB de Docker de esta máquina: muere por OOM con el pico pegado al
//! límite. La escalera acorrala el techo entre 52 285 y 2 422 783 ciclos. El
//! default es por eso `Mode::DecodeOnly`, y el techo medido va en el mensaje de
//! error cuando no entra — no en un panic críptico.
//!
//! # Los dos caminos de Docker, y por qué están los dos
//!
//! `ere-dockerized` construye sus imágenes localmente por default (**~2 h** la
//! primera vez, medido) y las **pulea** si `ERE_IMAGE_REGISTRY` está puesto
//! (5,35 GB de descarga, y son `amd64` ⇒ emuladas en un Mac ARM, con un
//! impuesto medido de ~4 %). Las dos andan, y este driver deja elegir con
//! `--registry`, porque **que el conteo de ciclos no dependa del camino es algo
//! que se verifica, no que se asume**: un ciclo de RISC-V debería ser el mismo
//! lo ejecute quien lo ejecute, y si no lo fuera, la medición que alimenta la
//! decisión de la matriz criptográfica dependería del setup.
//!
//! # Un driver, varios backends
//!
//! `--backend sp1|openvm|zisk` elige el zkVM. El default es `sp1` porque es el que
//! tiene la evidencia medida —el múltiplo de la aceleración, el piso de memoria
//! de `prove`, el ELF del nivel 3— y una receta guardada que empezara a
//! levantar otro backend estaría midiendo otra cosa sin decirlo. Lo que cambia
//! con el flag son **tres** cosas y no una: qué zkVM se levanta, qué directorio
//! se compila y contra qué ELF por default se corre. Atarlas al mismo flag es
//! lo que evita la combinación imposible —el ELF de un backend adentro del
//! otro— sin un chequeo que haya que acordarse de escribir.
//!
//! # Uso
//!
//! ```sh
//! ERE_IMAGE_REGISTRY=ghcr.io/eth-act/ere cargo run --release -p zkvm -- compile --out /tmp/guest.elf
//! ERE_IMAGE_REGISTRY=ghcr.io/eth-act/ere cargo run --release -p zkvm -- run --elf /tmp/guest.elf [--mode N]
//! ERE_IMAGE_REGISTRY=ghcr.io/eth-act/ere cargo run --release -p zkvm -- compile --backend openvm
//! ```

mod memoria;
mod multiproof;
mod prueba;
mod verificacion;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ere_dockerized::{
    CompilerKind, DockerizedCompiler, DockerizedzkVM, DockerizedzkVMConfig, zkVMKind,
};
use repo_b_common::primitives::B256;
use repo_b_prover::{
    Compiler, CostEstimation, Elf, EstimateCost, Execute, Input, Journal, Mode, ProverResource,
    PublicValues, cost,
};

use crate::multiproof::{Mutaciones, QuienPrueba};

/// Dónde vive el caso congelado. Ver `cmd/conformance/src/blockchain/dump.rs`.
pub(crate) const CASO: &str = "cmd/conformance/fixtures/guest";

/// El registro público de imágenes de `ere`. Es el camino rápido: sin esto,
/// `ere-dockerized` construye las imágenes desde cero.
const REGISTRY: &str = "ghcr.io/eth-act/ere";

/// La variable que le fija a OpenVM cuánta memoria acumula un segmento antes de
/// que empiece otro. `ere` la hereda del entorno del proceso hacia el contenedor
/// —y solo para OpenVM—, así que el driver la lee, no la escribe.
const ERE_OPENVM_SEGMENT_MEMORY: &str = "ERE_OPENVM_SEGMENT_MEMORY";

/// El segmento medido, y el único número de esta palanca que el repo cita.
///
/// Medido, una corrida por valor, en una caja de 31 GiB con el contenedor
/// acotado a 29: con el default de `ere` (14,5 GiB) el `prove` de `Kat` en
/// OpenVM murió por **OOM a los 33 min**; con este valor entra en 64,7 min con
/// un pico de 23,46 GiB y verifica. Bajarlo más baja el pico y sube el tiempo
/// (1 GiB: 185 min, pico 9,01 GiB), así que no es "más chico es mejor".
const SEGMENTO_OPENVM_POR_DEFAULT: u64 = 4 * 1024 * 1024 * 1024;

/// Qué segmento va a correr OpenVM, y de dónde salió.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentoOpenVm {
    /// La variable está puesta con un número: manda el entorno, que es lo que
    /// `ere` va a leer.
    DelEntorno(u64),
    /// No está puesta. **El driver no puede exportarla él mismo**: `set_var` es
    /// `unsafe` en la edición 2024 y el workspace declara `forbid`, el mismo
    /// motivo por el que `ERE_IMAGE_REGISTRY` también viaja por entorno. La
    /// aplica la receta; acá se dice cuál es el valor medido.
    SinSetear(u64),
    /// Puesta con algo que no es un número **para `ere`** —un `"4GiB"`, pero
    /// también un `" 4294967296 "`, porque su `parse` no hace `trim`—: `ere` la
    /// ignora **en silencio** y cae a su propio default, que es el que murió
    /// por OOM. Que se note es todo el punto.
    Invalida,
}

/// Resuelve el segmento **calcando la regla de `ere` byte a byte**: `ere` hace
/// `var.ok().and_then(|value| value.parse().ok()).unwrap_or(DEFAULT)`, o sea
/// `parse` sobre el valor **crudo, sin `trim`**. Cualquier política propia acá
/// —tolerar espacios, rechazar un cero— haría que el driver reportara un
/// segmento y el contenedor corriera otro, que es el falso-verde exacto que
/// esta función existe para evitar: con `.trim()`, un `" 4294967296 "` se
/// anunciaba como "el entorno manda" mientras `ere` lo descartaba en silencio y
/// corría su default de 14,5 GiB, el que murió por OOM.
fn segmento_openvm(var: Option<&str>) -> SegmentoOpenVm {
    match var {
        None => SegmentoOpenVm::SinSetear(SEGMENTO_OPENVM_POR_DEFAULT),
        Some(v) => match v.parse::<u64>() {
            Ok(n) => SegmentoOpenVm::DelEntorno(n),
            Err(_) => SegmentoOpenVm::Invalida,
        },
    }
}

/// Lo que el log tiene que decir sobre el segmento antes de una corrida larga.
/// Sin esta línea, las tres situaciones se ven igual desde afuera y recién se
/// distinguen media hora después, cuando el contenedor muere.
fn avisar_segmento_openvm() {
    let var = std::env::var(ERE_OPENVM_SEGMENT_MEMORY).ok();
    match segmento_openvm(var.as_deref()) {
        SegmentoOpenVm::DelEntorno(n) if n == SEGMENTO_OPENVM_POR_DEFAULT => {
            eprintln!("[zkvm] segmento de OpenVM: {n} bytes (del entorno, el valor medido)");
        }
        SegmentoOpenVm::DelEntorno(n) => {
            eprintln!(
                "[zkvm] segmento de OpenVM: {n} bytes (del entorno). El valor medido es \
                 {SEGMENTO_OPENVM_POR_DEFAULT}: esta corrida NO es la de la evidencia."
            );
        }
        SegmentoOpenVm::SinSetear(medido) => {
            eprintln!(
                "[zkvm] segmento de OpenVM: {ERE_OPENVM_SEGMENT_MEMORY} SIN SETEAR ⇒ corre el \
                 default de `ere` (14,5 GiB), que en la caja de 31 GiB murió por OOM a los\n       \
                 33 min. El valor medido que entra es {medido}, y lo exporta \
                 `scripts/prove-block.sh`; el driver no puede exportarlo solo."
            );
        }
        SegmentoOpenVm::Invalida => {
            eprintln!(
                "[zkvm] segmento de OpenVM: {ERE_OPENVM_SEGMENT_MEMORY} está puesta con algo que \
                 no es un número. `ere` la IGNORA en silencio y usa su default\n       \
                 (14,5 GiB), el que murió por OOM. El valor medido es \
                 {SEGMENTO_OPENVM_POR_DEFAULT}."
            );
        }
    }
}

/// El peldaño que `prove` corre por default, y por qué éste.
///
/// Medido en esta máquina con 19,5 GiB de límite de Docker: `Nop` (9 284
/// ciclos) y `DecodeOnly` (52 285) prueban en ~133-135 s; `Recover`
/// (2 422 783) y `Full` (4 884 110) mueren por **OOM** con el pico pegado al
/// límite. Se elige el más grande que entra y que además hace trabajo real:
/// probar `Nop` probaría que la maquinaria anda, no que el guest hizo algo.
pub(crate) const MODO_QUE_ENTRA: Mode = Mode::DecodeOnly;

/// El techo medido, para el mensaje de error. No se adivina: se cita.
///
/// **Los números de acá están en CICLOS y son de un runtime anterior.** El
/// runtime de hoy no reporta ciclos: reporta un costo estimado en la unidad de
/// cada backend. Se conservan porque son mediciones reales de qué entró y qué
/// no en cada caja —y "entra / no entra" no depende de en qué se cuente el
/// trabajo—, pero **no se comparan contra el costo que este driver imprime
/// hoy: es otra unidad**. No se borra la historia, se la etiqueta.
///
/// **Y el techo NO es una función del conteo de ciclos** — eso se creyó hasta
/// que se midió del otro lado. La primera sonda lo dejó acorralado entre 52 285
/// (`DecodeOnly`, prueba) y 2 422 783 (`Recover` sin acelerar, OOM), lo que
/// sugería un umbral en ciclos. Con `k256` parcheado, `Recover` baja a **105 146
/// ciclos y sigue sin entrar** (exit 137, OOM killed): un trace que contiene el
/// precompile de secp256k1 pide memoria que el doble de ciclos sin él no pide.
/// Lo que manda es **qué hay adentro del trace**, no cuántos ciclos tiene.
pub(crate) const TECHO_MEDIDO: &str = "\
medido en esta máquina (Docker con 19,5 GiB), y el techo NO es un umbral de
ciclos:
  `Nop`           2 241 ciclos → prueba en 122,6 s, 1 272 665 B (entra)
  `DecodeOnly`   52 285 ciclos (sin patch) → prueba en ~135 s, 1,27 MB
  `Recover`     105 146 ciclos (ECDSA ACELERADA) → OOM killed (exit 137)
  `Kat`         195 063 ciclos → OOM killed (exit 137)
  `Recover`   2 422 783 ciclos (sin acelerar)    → OOM, pico 19 395 MiB
  `Full`      2 566 473 / 4 884 110              → OOM, pico 19 507 MiB
Con la mitad de los ciclos de lo que ya fallaba, `Recover` acelerado igual no
entra: lo que pesa es que el trace contenga el chip de secp256k1, no su largo.
Y el peldaño de aritmética tampoco entra, aunque el de línea base sí: entre los
dos hay dos órdenes de magnitud de ciclos y el mismo techo de caja.
Y no hay una configuración que falte poner — `ere` pide SIEMPRE prueba
comprimida y `DockerizedzkVMConfig` expone solo timeouts, ningún knob de shard.

El OTRO backend también se midió acá, y da el mismo veredicto por peldaño: el
de línea base prueba (658,8 s, 267 559 B) y el de aritmética muere por OOM. Los
tiempos NO son comparables entre los dos —guest en cuarentena de un lado,
optimizado del otro—, pero «entra / no entra» sí lo es, porque es una propiedad
de la caja.

EL PELDAÑO DE ARITMÉTICA (`Kat`, 195 063 ciclos) EN DOS CAJAS x86_64 NATIVAS.
Procedencia: GCP n2-highmem-8 (8 vCPU), 2026-09-04 la de 31 GB y 2026-09-05 la
de 64 GB, con un muestreador cada 5 s ⇒ **todos estos picos son cota inferior,
nunca el pico**: entre dos muestras el consumo sube y baja sin que nadie lo vea.
  sp1     Docker 31,3 GiB → prueba en 278,8 s, 1 272 665 B, pico visto 24,04 GiB
  sp1     Docker 62,8 GiB → prueba en 306,7 s, 1 272 665 B, pico visto 24,37 GiB
  sp1     Docker 62,8 GiB → prueba en 307,9 s, 1 272 665 B, pico visto 27,04 GiB
                            (otra corrida, MISMA caja y MISMO ELF)
  openvm  Docker 31,3 GiB → OOM killed (137) a los ~22 min, última muestra 21,03 GiB
  openvm  Docker 62,8 GiB → NO entra: última muestra 60,28 GiB con 515 MB libres
                            en el host, y ahí se colgó la CAJA ENTERA — sin swap,
                            sin OOM killer y sin consola. Y NO volvió sola:
                            estuvo colgada 52 minutos hasta que la resetearon a
                            mano. Un `prove` que no entra no siempre falla como
                            un proceso: a veces falla como una máquina, y no hay
                            evidencia de que la máquina se recupere.
El pico de sp1 NO escala con la memoria libre ⇒ es del programa y no de la caja.
Pero TAMPOCO es reproducible al 1 %: tres corridas del mismo ELF dieron 24,04 /
24,37 / 27,04 GiB, las tres cota inferior. El de openvm sí escala, y con dos
puntos no se puede separar «pide más de 62,8 GiB» de «dimensiona contra la
memoria disponible»: lo único medido es que se pasó del techo en las dos. Su
consumo se queda plano en ~3 GiB durante 29 minutos y sube de 3 a 60 en los
últimos ~90 segundos, así que el requerimiento tampoco se extrapola.

En x86_64 NATIVO el bloque entero SÍ prueba, y el requerimiento está medido:
bisecando `--memory` sobre una caja de 8 vCPU / 31 GB, entra con 30 GiB y no
entra con 29, con picos observados de 27 a 28,4 GiB. Y `entra(L)` NO es
determinista cerca del borde: en esa caja, SIN límite, la receta salió verde
cuatro veces y murió por OOM una. O sea que ~31 GB de RAM es el filo del
cuchillo — para que esto sea repetible hace falta holgura, no el mínimo.
Ver `evidence/proof/sp1-memoria.txt` y `scripts/prove-block.sh --piso-memoria`.";

/// El zkVM que este driver levanta.
///
/// **Por qué el enum vive acá y no en el seam.** `repo-b-prover` es agnóstico a
/// propósito: adopta los traits de `ere` y no nombra ningún backend. Qué
/// backend se instancia es una decisión de la línea de comandos, y este driver
/// es el único lugar del árbol que importa `ere-dockerized`. Un enum en el seam
/// obligaría al motor a enumerar los backends que existen, que es exactamente
/// la dependencia que la cuarentena evita.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Sp1,
    OpenVm,
    Zisk,
}

impl Backend {
    /// **Fail-closed**: un nombre desconocido no cae en el default.
    pub(crate) fn parse(nombre: &str) -> Option<Self> {
        match nombre {
            "sp1" => Some(Self::Sp1),
            "openvm" => Some(Self::OpenVm),
            "zisk" => Some(Self::Zisk),
            _ => None,
        }
    }

    /// El nombre corto con el que este backend aparece en flags, archivos y
    /// evidencia. **No es `zkVMKind::name()`**: aquél lo elige `ere` y puede
    /// cambiar entre versiones, y acá nombra rutas que la receta cita.
    pub(crate) const fn nombre(self) -> &'static str {
        match self {
            Self::Sp1 => "sp1",
            Self::OpenVm => "openvm",
            Self::Zisk => "zisk",
        }
    }

    /// **En qué unidad cuenta el costo este backend.**
    ///
    /// `ere` estima el costo de probar una corrida, pero la unidad no está en
    /// su API: está en la documentación de cada backend, y **no es la misma**.
    /// SP1 pesa `3 · área de traza + complejidad`; OpenVM cuenta celdas de
    /// traza sin padding; ZisK también cuenta celdas (filas × ancho de cada
    /// tabla), pero de SUS tablas, con otro campo y otra aritmetización: que
    /// las dos palabras coincidan no vuelve comparables los dos números, y por
    /// eso la etiqueta de ZisK lleva su nombre. Un número sin esto al lado no se puede leer, y dos
    /// números de backends distintos no se restan ni se dividen — que es
    /// exactamente el error que se cometió mientras la columna se llamaba
    /// "ciclos" y un backend la devolvía siempre en cero.
    ///
    /// Vive acá y no en el seam por lo mismo que el enum: `repo-b-prover` es
    /// agnóstico, y este driver es el único lugar del árbol que sabe qué
    /// backend levantó.
    pub(crate) const fn unidad_de_costo(self) -> &'static str {
        match self {
            Self::Sp1 => "unidades de sp1 (3·área de traza + complejidad)",
            Self::OpenVm => "celdas de traza",
            Self::Zisk => "celdas de traza de zisk (filas × ancho, por tabla)",
        }
    }

    pub(crate) const fn kind(self) -> zkVMKind {
        match self {
            Self::Sp1 => zkVMKind::SP1,
            Self::OpenVm => zkVMKind::OpenVM,
            Self::Zisk => zkVMKind::Zisk,
        }
    }

    /// El toolchain con el que se compila el guest de este backend.
    ///
    /// **Todos usan el customizado, y no es una coincidencia que convenga
    /// verificar cada vez.** `ere` ofrece dos: `Rust` compila con un nightly de
    /// stock a un target bare-metal y exige que el guest traiga su propio
    /// `_start`, su allocator y su panic handler a mano; `RustCustomized`
    /// compila con el toolchain que shipea el backend y con su target propio,
    /// que es el único camino por el que el arranque y el ABI de entrada/salida
    /// del backend entran solos. Nuestros guests dependen de la `Platform`
    /// del backend, así que todos son del segundo caso — que es también el
    /// que `ere` ejercita para un guest con `Platform` en cada uno de sus
    /// backends. En ZisK el customizado es además el que compila a su target
    /// propio (`riscv64ima-zisk-zkvm-elf`), donde `ziskos` trae el arranque.
    const fn compiler(self) -> CompilerKind {
        CompilerKind::RustCustomized
    }

    /// El crate hoja que se compila. Va atado al backend y no a un flag aparte:
    /// compilar el guest de un backend con el toolchain de otro es una
    /// combinación que no tiene por qué ser representable.
    const fn guest_dir(self) -> &'static str {
        match self {
            Self::Sp1 => "crates/guest-sp1",
            Self::OpenVm => "crates/guest-openvm",
            Self::Zisk => "crates/guest-zisk",
        }
    }

    /// Dónde queda el ELF si nadie dice otra cosa. **Uno por backend**: con un
    /// nombre compartido, compilar el segundo pisaría al primero y la corrida
    /// siguiente mediría un ELF que no es el que cree.
    pub(crate) const fn elf_por_default(self) -> &'static str {
        match self {
            Self::Sp1 => "target/guest-sp1.elf",
            Self::OpenVm => "target/guest-openvm.elf",
            Self::Zisk => "target/guest-zisk.elf",
        }
    }
}

/// Un backend nombrado en un flag de `multiproof`.
///
/// **Fail-closed también sobre los que existen y no cruzan.** Un backend que
/// el driver sabe levantar pero que no está en el orden del cruce sería, en
/// `--sin-prueba-de` o en una mutación, un flag aceptado que no cambia nada:
/// la corrida diría que apagó o mutó algo y no habría tocado nada.
fn backend_del_cruce(nombre: &str) -> Option<Backend> {
    Backend::parse(nombre).filter(|b| multiproof::cruza(*b))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |f: &str| args.iter().any(|a| a == f);
    let val = |f: &str| {
        args.iter()
            .position(|a| a == f)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    // **El camino de Docker se elige con `ERE_IMAGE_REGISTRY` en el entorno**, no
    // con un flag: `ere` lo lee del proceso, y setearlo desde adentro exigiría
    // `set_var`, que es `unsafe` en la edición 2024 — o sea agrandar la única
    // excepción de `unsafe` del repo para elegir una imagen de Docker.
    eprintln!(
        "[zkvm] camino de Docker: {}",
        match std::env::var("ERE_IMAGE_REGISTRY") {
            // Las imágenes publicadas son `amd64`: nativas en x86_64 y emuladas
            // en ARM. Decirlo según la arquitectura de esta máquina y no en
            // absoluto — en una caja x86_64 el mensaje viejo mentía.
            Ok(r) => format!(
                "imágenes de {r} (amd64, {})",
                if cfg!(target_arch = "x86_64") {
                    "nativas acá"
                } else {
                    "emuladas acá"
                }
            ),
            Err(_) => format!(
                "imágenes locales (se construyen si faltan; poné ERE_IMAGE_REGISTRY={REGISTRY} \
                 para usar las publicadas)"
            ),
        }
    );

    // El backend por default es SP1: es el que tiene la evidencia medida, y una
    // receta guardada que empezara a levantar otro estaría midiendo otra cosa
    // sin decirlo.
    let backend = match val("--backend") {
        None => Backend::Sp1,
        Some(n) => match Backend::parse(&n) {
            Some(b) => b,
            None => {
                eprintln!("[zkvm] backend desconocido: `{n}` — son `sp1`, `openvm` o `zisk`.");
                std::process::exit(2);
            }
        },
    };
    eprintln!("[zkvm] backend: {}", backend.kind().name());

    // El segmento solo lo lee OpenVM, y `multiproof` lo levanta siempre.
    if backend == Backend::OpenVm || args.first().map(String::as_str) == Some("multiproof") {
        avisar_segmento_openvm();
    }

    let elf_pedido =
        || PathBuf::from(val("--elf").unwrap_or_else(|| backend.elf_por_default().into()));

    match args.first().map(String::as_str) {
        Some("compile") => {
            let out =
                PathBuf::from(val("--out").unwrap_or_else(|| backend.elf_por_default().into()));
            compile(backend, &out)
        }
        Some("run") => {
            let elf = elf_pedido();
            let modo = val("--mode").and_then(|m| m.parse::<u8>().ok());
            let corrupto = has("--mutar-input-vacio");
            let nulo = has("--mutar-input-nulo");
            let root_mutado = val("--mutar-root-esperado");
            let firma_falsa = has("--mutar-firma");
            run(
                backend,
                &elf,
                modo,
                corrupto,
                nulo,
                root_mutado.as_deref(),
                firma_falsa,
            )
        }
        Some("kat") => kat(backend, &elf_pedido(), has("--mutar-kat")),
        Some("verify") => {
            let Some(prueba) = val("--proof") else {
                eprintln!("[zkvm] `verify` necesita --proof <archivo>.");
                std::process::exit(2);
            };
            verificacion::verificar_prueba(
                backend,
                &elf_pedido(),
                Path::new(&prueba),
                has("--mutar-journal"),
            )
        }
        Some("prove") => {
            let elf = elf_pedido();
            let modo = val("--mode").and_then(|m| m.parse::<u8>().ok());
            prueba::probar(
                backend,
                &elf,
                modo,
                has("--mutar-public-values"),
                has("--costo"),
            )
        }
        Some("multiproof") => {
            let elf_de = |b: Backend| {
                PathBuf::from(
                    val(&format!("--elf-{}", b.nombre()))
                        .unwrap_or_else(|| b.elf_por_default().into()),
                )
            };
            let elfs = multiproof::Elfs {
                sp1: elf_de(Backend::Sp1),
                openvm: elf_de(Backend::OpenVm),
                zisk: elf_de(Backend::Zisk),
            };
            // **Sin default silencioso.** El peldaño que se cruza cambia lo que
            // el resultado afirma —`Nop` publica un journal en ceros que dos
            // backends comparten sin haber computado nada—, así que el modo se
            // pide y no se hereda.
            let Some(modo) = val("--mode").and_then(|m| m.parse::<u8>().ok()) else {
                eprintln!(
                    "[zkvm] `multiproof` necesita --mode N. Un default acá elegiría qué\n                     afirma el cruce sin que nadie lo dijera."
                );
                std::process::exit(2);
            };
            let mutaciones = Mutaciones {
                journal_de: match val("--mutar-journal-de") {
                    None => None,
                    Some(n) => match backend_del_cruce(&n) {
                        Some(b) => Some(b),
                        None => {
                            eprintln!(
                                "[zkvm] --mutar-journal-de: `{n}` no es un backend del cruce."
                            );
                            std::process::exit(2);
                        }
                    },
                },
                modo_openvm: match val("--mutar-modo-openvm") {
                    None => None,
                    Some(m) => match m.parse::<u8>().ok().and_then(Mode::from_byte) {
                        Some(x) => Some(x),
                        None => {
                            eprintln!("[zkvm] --mutar-modo-openvm: `{m}` no es un modo.");
                            std::process::exit(2);
                        }
                    },
                },
                cruce_solo_modo: has("--mutar-cruce-solo-modo"),
                verificador_cruzado: has("--mutar-verificador-cruzado"),
                oraculo_de: match val("--mutar-oraculo-de") {
                    None => None,
                    Some(n) => match backend_del_cruce(&n) {
                        Some(b) => Some(b),
                        None => {
                            eprintln!(
                                "[zkvm] --mutar-oraculo-de: `{n}` no es un backend del cruce."
                            );
                            std::process::exit(2);
                        }
                    },
                },
            };
            // **La combinación inválida no se resuelve por precedencia: se
            // rechaza.** `--sin-prueba` apaga la prueba de los dos y
            // `--sin-prueba-de` la de uno; darle prioridad a cualquiera de los
            // dos dejaría una línea de comandos que dice una cosa y una
            // corrida que hace otra, que es exactamente lo que la evidencia no
            // puede permitirse.
            // **Repetido no gana el último ni el primero: se rechaza.** `val`
            // toma la primera ocurrencia, así que un segundo
            // `--sin-prueba-de <otro>` se ignoraría **en silencio** y la
            // corrida probaría un backend distinto del que la línea de comandos
            // parece pedir — y la evidencia diría el de la corrida.
            if args
                .iter()
                .filter(|a| a.as_str() == "--sin-prueba-de")
                .count()
                > 1
            {
                eprintln!(
                    "[zkvm] --sin-prueba-de aparece más de una vez. Se rechaza en vez de \
                     quedarse con uno: el que se ignore cambiaría qué backend prueba sin \
                     que nadie lo dijera."
                );
                std::process::exit(2);
            }
            let sin_prueba_de = match val("--sin-prueba-de") {
                // El flag sin valor no cae en "probá los dos": pedirlo y no
                // decir cuál es un error del que lo escribió, y tratarlo como
                // ausencia correría una corrida distinta de la que se pidió.
                None if has("--sin-prueba-de") => {
                    eprintln!(
                        "[zkvm] --sin-prueba-de necesita un backend: `sp1`, `openvm` o `zisk`."
                    );
                    std::process::exit(2);
                }
                None => None,
                Some(n) => match backend_del_cruce(&n) {
                    Some(b) => Some(b),
                    None => {
                        eprintln!(
                            "[zkvm] --sin-prueba-de: `{n}` no es un backend del cruce — son `sp1`, `openvm` o `zisk`."
                        );
                        std::process::exit(2);
                    }
                },
            };
            let quien = match (has("--sin-prueba"), sin_prueba_de) {
                (true, Some(b)) => {
                    eprintln!(
                        "[zkvm] --sin-prueba y --sin-prueba-de {} son excluyentes: el primero \
                         apaga la prueba de TODOS los backends y el segundo la de uno.",
                        b.nombre()
                    );
                    std::process::exit(2);
                }
                (true, None) => QuienPrueba::Ninguno,
                (false, Some(b)) => QuienPrueba::TodosMenos(b),
                (false, None) => QuienPrueba::Todos,
            };
            multiproof::multiproof(&elfs, modo, quien, mutaciones, has("--costo"))
        }
        _ => {
            eprintln!("uso: zkvm compile [--backend sp1|openvm|zisk] --out <elf>");
            eprintln!(
                "     zkvm kat   [--backend sp1|openvm|zisk] --elf <elf>            (aritmética de consenso)"
            );
            eprintln!("     zkvm run   [--backend sp1|openvm|zisk] --elf <elf> [--mode N]");
            eprintln!(
                "     zkvm prove [--backend sp1|openvm|zisk] --elf <elf> [--mode N] [--costo]  (prueba Y verifica)"
            );
            eprintln!(
                "     zkvm verify [--backend sp1|openvm|zisk] --elf <elf> --proof <archivo> [--mutar-journal]"
            );
            eprintln!(
                "     zkvm multiproof [--elf-sp1 <elf>] [--elf-openvm <elf>] [--elf-zisk <elf>] --mode N [--costo]"
            );
            eprintln!("            [--sin-prueba | --sin-prueba-de sp1|openvm|zisk]");
            eprintln!(
                "            (los tres backends, en secuencia, y el journal de cada uno contra el del primero)"
            );
            std::process::exit(2);
        }
    }
}

/// **El gate de la regla dura de este proyecto sobre los backends:** un bug
/// del zkVM *te deja afuera, no te forkea la cadena*.
///
/// Esa regla estaba escrita y **nada la hacía cumplir**: OpenVM `v2.1.0-preview` miscompila la
/// división de enteros grandes con divisor de bit alto prendido —silenciosa y
/// dependiente del valor— y `DIV`/`MOD`/`ADDMOD`/`MULMOD` del intérprete pasan
/// por ahí. Sin este chequeo, ese backend habría producido **pruebas válidas de
/// ejecuciones incorrectas**.
///
/// Corre `Mode::Kat` adentro del backend y contrasta **tres** cosas contra la
/// corrida NATIVA de la misma función:
///
/// 1. el magic, que dice que el modo corrió de verdad y que el ELF es el nuestro;
/// 2. el bitmask de fallas, que nombra qué caso se rompió;
/// 3. el digest de TODOS los valores, que caza incluso un resultado equivocado
///    que ningún caso supiera esperar.
///
/// El oráculo no está hardcodeado a propósito: el lado nativo es el que ya
/// sostiene los dos ejes de EEST, y una constante escrita a mano podría estar
/// mal. Es la forma del nivel 3, en chico y en segundos.
///
/// # Errors
/// Cualquier discrepancia es **fail-closed**: no se degrada a warning.
fn kat(backend: Backend, elf_path: &Path, mutar: bool) -> Result<(), Box<dyn std::error::Error>> {
    let elf = Elf(std::fs::read(elf_path)?);

    // El lado nativo, ANTES de levantar nada: si el KAT no pasa acá, el
    // problema es del KAT y no del backend, y hacer arrancar Docker para
    // descubrirlo sería tirar seis minutos.
    let nativo = prueba::kat_nativo()?;

    eprintln!("[zkvm] levantando el zkVM…");
    let t = Instant::now();
    let zkvm = DockerizedzkVM::new(backend.kind(), elf, ProverResource::Cpu, config_backend())?;
    let nombre = zkvm.name().to_string();
    eprintln!(
        "[zkvm] arriba en {:?} — {} {}",
        t.elapsed(),
        nombre,
        zkvm.sdk_version()
    );

    // El KAT no mira el cuerpo del input: su razón de ser es contestar si la
    // aritmética de ESTE ELF es correcta, y atarlo a decodificar algo lo haría
    // depender de una pieza que puede estar rota por lo mismo que se investiga.
    let corrida = repo_b_prover::execute_block(
        &Dockerizado(zkvm, backend),
        repo_b_guest::journal::Mode::Kat,
        &[],
    )?;
    let j = corrida.journal;

    // MUTACIÓN: publicar el digest nativo en vez del que salió del backend.
    // Sin esto el contraste no se puede falsificar desde afuera, y un chequeo
    // que no sabe ponerse rojo no es evidencia.
    let digest_publicado = if mutar {
        eprintln!("[zkvm] MUTACIÓN --mutar-kat: se contrasta el nativo contra sí mismo");
        nativo.digest
    } else {
        j.post_state_root
    };

    println!("\n=== KAT DE ARITMÉTICA DE CONSENSO — {nombre} ===");
    println!("corrió en           : {:?}", corrida.duration);

    if j.pre_state_root != repo_b_guest::kat::KAT_MAGIC {
        return Err(format!(
            "el magic no coincide: el modo KAT no corrió, o el ELF no es el nuestro\n             esperado {:#x}\nobtenido {:#x}",
            repo_b_guest::kat::KAT_MAGIC,
            j.pre_state_root
        )
        .into());
    }
    println!(
        "magic               : ok ({} casos)",
        repo_b_guest::kat::CASOS
    );

    // **Los dos chequeos se evalúan SIEMPRE, y recién después se falla.**
    //
    // La primera versión cortaba en el bitmask, y la mutación que deshace la
    // cuarentena lo demostró defectuoso: el bitmask disparó y el digest —que es
    // el chequeo MÁS ancho, el que caza un valor equivocado que ningún caso
    // sabe esperar— nunca llegó a ejercitarse. Un chequeo que solo corre cuando
    // el otro pasa no está probado por la corrida que encuentra el bug.
    let fallas = repo_b_common::primitives::U256::from_be_bytes(j.output_digest.0);
    let bitmask_mal = !fallas.is_zero();
    let digest_mal = digest_publicado != nativo.digest;

    if bitmask_mal {
        let cuales: Vec<String> = (0..repo_b_guest::kat::CASOS)
            .filter(|i| fallas.bit(*i))
            .map(|i| i.to_string())
            .collect();
        println!(
            "bitmask de fallas   : {fallas:#x} — CASOS FALLADOS: {}",
            cuales.join(", ")
        );
    } else {
        println!(
            "bitmask de fallas   : 0x0 (los {} casos)",
            repo_b_guest::kat::CASOS
        );
    }

    if digest_mal {
        println!("digest vs nativo    : NO COINCIDE");
        println!("  nativo            : {:#x}", nativo.digest);
        println!("  backend           : {digest_publicado:#x}");
    } else {
        println!("digest vs nativo    : {:#x} — coincide", nativo.digest);
    }

    if bitmask_mal || digest_mal {
        return Err(format!(
            "EL BACKEND COMPUTA MAL LA ARITMÉTICA DE CONSENSO \
             (bitmask {}, digest {}).\n\
             Esto NO es un backend que no prueba: es un backend que probaría OTRA COSA — \
             una prueba válida de una ejecución incorrecta.\n\
             La regla dura: un bug del zkVM te deja afuera, NO te forkea la cadena.\n\
             No se integra hasta que esté verde.",
            if bitmask_mal { "ROJO" } else { "ok" },
            if digest_mal { "ROJO" } else { "ok" },
        )
        .into());
    }

    println!("\nla aritmética de consenso de este ELF es correcta adentro del backend");
    Ok(())
}

/// Compila el guest del backend pedido con **su** toolchain, adentro de su
/// imagen.
fn compile(backend: Backend, out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let guest = root.join(backend.guest_dir());
    eprintln!("[zkvm] compilando {} …", guest.display());
    let t = Instant::now();
    let compiler = DockerizedCompiler::new(backend.kind(), backend.compiler(), &root)?;
    let elf = compiler.compile(&guest, &[])?;
    eprintln!(
        "[zkvm] ELF listo en {:?} — {} bytes",
        t.elapsed(),
        elf.len()
    );
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(out, elf.as_ref())?;
    eprintln!("[zkvm] escrito en {}", out.display());
    Ok(())
}

/// La configuración del backend, con **el arranque más holgado que el default**.
///
/// `ere` deja `health_timeout` en 300 s, que alcanza para SP1 y no para OpenVM:
/// sus imágenes no están en la misma escala —el server de OpenVM pesa 2,4 GB
/// contra 293 MB el de SP1— y bajo emulación el arranque medido acá fue de
/// **294 s**, o sea seis segundos por debajo del límite. Perder por eso da un
/// `ConnectionTimeout` que parece del guest y es del reloj: el contenedor
/// levanta bien, tarde, y queda huérfano.
///
/// El resto de los timeouts se dejan en `None` a propósito: acotar cuánto puede
/// tardar una ejecución o una prueba sería una decisión sobre el trabajo, y esto
/// es una decisión sobre el arranque.
pub(crate) fn config_backend() -> DockerizedzkVMConfig {
    DockerizedzkVMConfig {
        health_timeout: ARRANQUE_MAXIMO,
        ..DockerizedzkVMConfig::default()
    }
}

/// Cuánto se le da al backend para responder que está vivo. Ver
/// [`config_backend`].
const ARRANQUE_MAXIMO: Duration = Duration::from_secs(900);

/// Ejecuta el caso congelado adentro del zkVM y contrasta lo que publicó.
fn run(
    backend: Backend,
    elf_path: &Path,
    modo: Option<u8>,
    input_vacio: bool,
    input_nulo: bool,
    root_mutado: Option<&str>,
    firma_falsa: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let elf = Elf(std::fs::read(elf_path)?);
    let bloque = std::fs::read(root.join(CASO).join("block-input.bin"))?;
    let esperado = leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), root_mutado)?;

    eprintln!("[zkvm] levantando el zkVM…");
    let t = Instant::now();
    let zkvm = DockerizedzkVM::new(backend.kind(), elf, ProverResource::Cpu, config_backend())?;
    eprintln!(
        "[zkvm] arriba en {:?} — {} {}",
        t.elapsed(),
        zkvm.name(),
        zkvm.sdk_version()
    );
    let zkvm = Dockerizado(zkvm, backend);

    // **M1, desde el seam**: el input llega vacío. Si el guest ejecutara un
    // bloque vacío en silencio, acá saldría un journal en ceros en vez de un
    // error del backend.
    let bloque = if input_vacio { Vec::new() } else { bloque };

    // **M6, y es la única forma de preguntarlo bien.** Que `k256` aparezca en el
    // ELF no prueba que la recuperación esté adentro: ya entraba por el
    // precompile ECRECOVER. Lo que sí lo prueba es que el input **no lleva
    // sender** y el guest igual produce el root correcto — y que si se le
    // cambia la firma por otra válida, deje de producirlo. Si la recuperación
    // no corriera ADENTRO, cambiar la firma no cambiaría nada.
    let bloque = if firma_falsa {
        repo_b_prover::forjar_firma(&bloque)?
    } else {
        bloque
    };

    // **M1 en su forma exacta**: `read_input()` no devuelve NADA — ni el byte de
    // modo. Es el buffer de vuelta a `[u8; 0]`, visto desde el seam.
    if input_nulo {
        let r = zkvm.execute_raw(&repo_b_prover::Input::new());
        match r {
            Ok((pv, dur)) => {
                println!(
                    "el guest EJECUTÓ con el buffer vacío: {} bytes publicados en {dur:?}",
                    pv.as_ref().len(),
                );
                return Err("con el buffer vacío el guest tendría que HALTEAR".into());
            }
            Err(e) => {
                println!("con el buffer vacío el guest haltea, como corresponde:\n{e}");
                return Ok(());
            }
        }
    }

    if let Some(m) = modo {
        let mode = Mode::from_byte(m).ok_or("modo desconocido")?;
        let run = repo_b_prover::execute_block(&zkvm, mode, &bloque)?;
        println!("modo {mode:?}: ejecutado en {:?}", run.duration);
        println!("journal {:?}", run.journal);
        // Los bytes, además de los campos: es lo que se cruza entre backends,
        // y un `Debug` no se compara byte a byte contra el de otro backend.
        println!(
            "journal hex ({} B) {}",
            run.journal.encode().len(),
            prueba::hex(&run.journal.encode())
        );
        if mode == Mode::Full
            && let Some(falla) = politica_de_bloque(&run.journal.encode(), &root)?
        {
            return Err(falla.into());
        }
        return Ok(());
    }

    let desglose = cost::breakdown(&zkvm, &bloque)?;

    println!("\n=== EL BLOQUE REAL, ADENTRO DEL zkVM ===");
    // **La escalera separa dos cosas que se confunden: que los peldaños
    // EJECUTEN y que su costo se pueda medir.** Lo primero es del guest y es
    // portable; lo segundo depende de que el estimador del backend devuelva
    // algo. Si llega en cero en toda la escalera, las restas dan cero y la
    // tabla sale con cara de dato sin haber medido nada — eso se dice, no se
    // rellena.
    if desglose.rungs.iter().all(|(_, c)| *c == 0) {
        println!(
            "\n[!] este backend NO estima el costo: los {} peldaños EJECUTARON y\n    \
             publicaron su journal, pero su costo llega en cero y el desglose de\n    \
             abajo no mide nada. La escalera es portable en sus MODOS y no en su\n    \
             número: lo que le falta no es el guest, es lo que resta.",
            desglose.rungs.len()
        );
    }
    println!("costo total         : {} {}", desglose.total, desglose.unit);
    println!("peldaños de la escalera (crudos, en {}):", desglose.unit);
    for (mode, c) in &desglose.rungs {
        println!("  {mode:<12?} {c:>14}");
    }
    // **La escalera se verifica, no se cree.** Un estimador que no se llamara,
    // o que devolviera cero, daría una tabla entera de ceros que se lee como
    // una medición; sin esta línea el desglose no distingue los dos casos.
    match desglose.monotonia() {
        Ok(()) => println!(
            "monotonía           : ok — cada peldaño cuesta ≥ el de abajo, y el camino real \
             cuesta MÁS que el que no hace nada"
        ),
        Err(fallas) => {
            for f in &fallas {
                println!("monotonía           : FAIL {f}");
            }
            return Err("la escalera no es monótona: el desglose de abajo no mide nada".into());
        }
    }
    println!("componentes del backend (camino real, {}):", desglose.unit);
    for (nombre, c) in &desglose.components {
        println!("  {nombre:<12} {c:>14}");
    }
    println!("piezas (por diferencia, en {}):", desglose.unit);
    for p in &desglose.pieces {
        let pct = if desglose.total == 0 {
            0.0
        } else {
            100.0 * p.cost as f64 / desglose.total as f64
        };
        println!("  {:<52} {:>12}  ({pct:>5.1} %)", p.name, p.cost);
    }

    println!("\n=== EL RESULTADO ADENTRO ES EL DE AFUERA ===");
    let publicado = desglose.journal;
    // El estimador ya contrastó el modo; la política mira el resto. Re-encodear
    // no esconde nada: el journal decodificado ya pasó por la versión.
    if let Some(falla) = politica_de_bloque(&publicado.encode(), &root)? {
        return Err(falla.into());
    }
    println!(
        "journal hex ({} B) {}",
        publicado.encode().len(),
        prueba::hex(&publicado.encode())
    );
    let mut distintos = 0usize;
    for ((campo, a), (_, b)) in publicado.fields().into_iter().zip(esperado.fields()) {
        prueba::contrastar(publicado.mode, campo, &a, &b);
        if a != b {
            distintos = distintos.saturating_add(1);
        }
    }
    if distintos > 0 {
        return Err(
            "el guest adentro del zkVM produjo OTRO resultado que el harness afuera".into(),
        );
    }
    println!("todos los campos coinciden con lo que el harness computó afuera del zkVM");
    Ok(())
}

/// Lee el journal esperado del caso congelado.
///
/// `root_mutado` es **M4**: sustituye el root esperado por otro para verificar
/// que el contraste de arriba no pasa por vacuidad.
pub(crate) fn leer_journal_esperado(
    path: &Path,
    root_mutado: Option<&str>,
) -> Result<Journal, Box<dyn std::error::Error>> {
    let texto = std::fs::read_to_string(path)?;
    let crudo = |nombre: &str| -> Result<String, Box<dyn std::error::Error>> {
        let linea = texto
            .lines()
            .find_map(|l| l.strip_prefix(nombre).and_then(|r| r.strip_prefix(' ')))
            .ok_or_else(|| format!("falta {nombre} en el caso congelado"))?;
        // El primer token: la línea del fork lleva el nombre al lado.
        Ok(linea
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned())
    };
    let campo = |nombre: &str| -> Result<B256, Box<dyn std::error::Error>> {
        Ok(crudo(nombre)?.parse::<B256>()?)
    };
    let post = match root_mutado {
        Some(r) => r.parse::<B256>()?,
        None => campo("post_state_root")?,
    };
    let fork_id: u8 = crudo("fork")?.parse()?;
    Ok(Journal {
        mode: Mode::Full,
        chain_id: crudo("chain_id")?.parse()?,
        fork: Some(
            repo_b_guest::journal::fork_from_id(fork_id)
                .ok_or_else(|| format!("fork desconocido en el caso congelado: {fork_id}"))?,
        ),
        block_hash: campo("block_hash")?,
        parent_hash: campo("parent_hash")?,
        pre_state_root: campo("pre_state_root")?,
        post_state_root: post,
        output_digest: campo("output_digest")?,
    })
}

/// **Lo que el consumidor sabe del bloque** del caso congelado: cadena, fork,
/// hash y padre. Es la entrada de `repo_b_prover::require_full_block`, la
/// política única con la que se acepta una prueba de bloque.
///
/// **El hash y el padre se recomputan** de `block-input.bin`
/// (`keccak(rlp(header))` del bloque que viaja y su `parentHash`) y se
/// contrastan contra `block-journal.txt`: el archivo lo escribió el harness, y
/// si fuera la única fuente, un `block_hash` equivocado ahí se aceptaría contra
/// sí mismo. La cadena y el fork salen del input y también se contrastan contra
/// el archivo.
///
/// **KNOWN:** ni la cadena ni el fork son independientes del caso. En el CLI
/// no hay un chainspec del consumidor: los dos salen del input que se prueba y
/// del archivo que escribió el harness, y coinciden por construcción. Un
/// consumidor real los toma de su cadena; acá solo se verifica que el caso sea
/// coherente consigo mismo.
pub(crate) fn bloque_esperado(
    root: &Path,
) -> Result<repo_b_prover::ExpectedBlock, Box<dyn std::error::Error>> {
    let archivo = leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), None)?;
    let bytes = std::fs::read(root.join(CASO).join("block-input.bin"))?;
    esperado_de(&bytes, &archivo)
}

/// El contraste de [`bloque_esperado`], sin IO.
fn esperado_de(
    input: &[u8],
    archivo: &Journal,
) -> Result<repo_b_prover::ExpectedBlock, Box<dyn std::error::Error>> {
    let input = repo_b_guest::codec::decode_block_input(input)
        .map_err(|e| format!("el caso congelado no decodifica: {e:?}"))?;
    let bloque = repo_b_guest::block::decode_block(&input.block)
        .map_err(|e| format!("el bloque del caso congelado no decodifica: {e}"))?;
    let esperado = repo_b_prover::ExpectedBlock {
        chain_id: input.chain_id,
        fork: input.fork,
        block_hash: bloque.header.hash(),
        parent_hash: Some(bloque.header.parent_hash),
    };
    let del_archivo = repo_b_prover::ExpectedBlock {
        chain_id: archivo.chain_id,
        fork: archivo.fork.ok_or("el caso congelado no declara su fork")?,
        block_hash: archivo.block_hash,
        parent_hash: Some(archivo.parent_hash),
    };
    if esperado != del_archivo {
        return Err(format!(
            "block-journal.txt no es el del input congelado: el input da {esperado:?} y el 
             archivo dice {del_archivo:?}"
        )
        .into());
    }
    Ok(esperado)
}

/// La política de verificación sobre los bytes que publicó una corrida de
/// `Full`. Imprime el veredicto y devuelve el rechazo, si lo hay.
pub(crate) fn politica_de_bloque(
    publicos: &[u8],
    root: &Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let esperado = bloque_esperado(root)?;
    Ok(
        match repo_b_prover::require_full_block(publicos, &esperado) {
            Ok(_) => {
                println!(
                    "  ok   política de bloque: versión, modo Full, chain_id, fork, block_hash, \
                 parent_hash, roots y output_digest"
                );
                None
            }
            Err(e) => {
                println!("  FAIL política de bloque: {e}");
                Some(format!("política de bloque: {e}"))
            }
        },
    )
}

/// La raíz del repo, desde este manifiesto. No se adivina con el cwd: el
/// compilador de `ere` monta ESTE directorio adentro de Docker, y montar el
/// lugar equivocado da un error a los diez minutos.
pub(crate) fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` es `<root>/cmd/zkvm`, así que dos niveles arriba es
    // la raíz. Sin `expect`: si la ruta no tuviera dos padres, subir con
    // `join("../..")` da lo mismo y no hay nada que desempaquetar.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// El adaptador del backend por Docker al seam.
///
/// **Newtype y no un `impl` directo**: `DockerizedzkVM` es de `ere` y `Execute`
/// es de `repo-b-prover`, así que este crate no puede juntar dos tipos ajenos.
/// Que haga falta el newtype es consecuencia de que `ere` no implemente su
/// propio trait para su propio tipo dockerizado — ver el doc de `Execute`.
///
/// **Lleva el backend adentro** porque la unidad del costo es de él y no del
/// tipo dockerizado, que es dinámico sobre los tres.
pub(crate) struct Dockerizado(pub DockerizedzkVM, pub Backend);

impl Execute for Dockerizado {
    fn execute_raw(&self, input: &Input) -> Result<(PublicValues, Duration), String> {
        self.0.execute(input).map_err(|e| format!("{e:#}"))
    }
}

impl EstimateCost for Dockerizado {
    fn cost_unit(&self) -> &'static str {
        self.1.unidad_de_costo()
    }

    fn execute_estimated_cost_raw(
        &self,
        input: &Input,
    ) -> Result<(PublicValues, CostEstimation), String> {
        self.0
            .execute_estimated_cost(input)
            .map_err(|e| format!("{e:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Backend, SEGMENTO_OPENVM_POR_DEFAULT, SegmentoOpenVm, backend_del_cruce, segmento_openvm,
    };

    /// **Un nombre desconocido no cae en el default.** Sin esto, un typo en el
    /// flag correría SP1 y la corrida reportaría el backend equivocado con cara
    /// de haber medido el pedido.
    #[test]
    fn an_unknown_backend_is_refused() {
        assert_eq!(Backend::parse("sp1"), Some(Backend::Sp1));
        assert_eq!(Backend::parse("openvm"), Some(Backend::OpenVm));
        assert_eq!(Backend::parse("zisk"), Some(Backend::Zisk));
        assert_eq!(Backend::parse("SP1"), None);
        assert_eq!(Backend::parse("ZisK"), None);
        assert_eq!(Backend::parse(""), None);
        assert_eq!(Backend::parse("risc0"), None);
    }

    /// **Los flags del cruce aceptan exactamente los backends del orden.** Uno
    /// que el driver sabe levantar y no cruzara se anunciaría en
    /// `--sin-prueba-de` o en una mutación y no tocaría nada; y uno del orden
    /// que los flags rechazaran no se podría apagar ni mutar.
    #[test]
    fn the_cross_flags_accept_exactly_the_backends_of_the_order() {
        for b in TODOS {
            assert_eq!(backend_del_cruce(b.nombre()), Some(b), "{}", b.nombre());
        }
        assert_eq!(backend_del_cruce("risc0"), None);
    }

    const TODOS: [Backend; 3] = [Backend::Sp1, Backend::OpenVm, Backend::Zisk];

    /// **Cada backend tiene su crate y su ELF, y no los comparte.** Un nombre
    /// de ELF compartido haría que compilar el segundo pise al primero, y la
    /// corrida siguiente mediría un binario que no es el que cree estar
    /// midiendo.
    #[test]
    fn each_backend_has_its_own_guest_and_elf() {
        for (i, a) in TODOS.iter().enumerate() {
            for b in TODOS.iter().skip(i.saturating_add(1)) {
                assert_ne!(
                    a.guest_dir(),
                    b.guest_dir(),
                    "{} y {}: dos guests concretos no pueden ser el mismo directorio",
                    a.nombre(),
                    b.nombre()
                );
                assert_ne!(
                    a.elf_por_default(),
                    b.elf_por_default(),
                    "compilar {} pisaría el ELF de {}",
                    a.nombre(),
                    b.nombre()
                );
            }
        }
    }

    /// **La unidad del costo es del BACKEND, y los dos no cuentan lo mismo.**
    ///
    /// `ere` estima el costo con la unidad que define cada backend: SP1 pesa
    /// `3 · área de traza + complejidad` y OpenVM cuenta celdas de traza. Una
    /// unidad compartida —"ciclos", pongamos— sería falsa para los dos y
    /// volvería a habilitar la comparación entre columnas que no se pueden
    /// comparar.
    #[test]
    fn each_backend_counts_cost_in_its_own_unit() {
        for (i, a) in TODOS.iter().enumerate() {
            for b in TODOS.iter().skip(i.saturating_add(1)) {
                assert_ne!(
                    a.unidad_de_costo(),
                    b.unidad_de_costo(),
                    "{} y {} con la misma unidad invitan a restar sus números",
                    a.nombre(),
                    b.nombre()
                );
            }
        }
        for b in TODOS {
            assert!(
                !b.unidad_de_costo().is_empty(),
                "{} sin unidad: su costo no se puede leer",
                b.nombre()
            );
            assert!(
                !b.unidad_de_costo().contains("ciclo"),
                "{} declara ciclos, y lo que el estimador devuelve no lo es",
                b.nombre()
            );
        }
    }

    /// El default de SP1 es el que citan la receta de `prove` y el eje del
    /// nivel 3. Si cambiara, esos dos leerían un ELF que nadie escribió.
    #[test]
    fn the_sp1_elf_keeps_the_name_the_recipes_cite() {
        assert_eq!(Backend::Sp1.elf_por_default(), "target/guest-sp1.elf");
    }

    /// **Sin la variable, el segmento que corre es el valor medido.** Es el
    /// número que separa un `prove` de OpenVM que entra de uno que muere por
    /// OOM a los 33 minutos, y vive en UN solo lugar.
    #[test]
    fn without_the_variable_the_measured_segment_applies() {
        assert_eq!(
            segmento_openvm(None),
            SegmentoOpenVm::SinSetear(SEGMENTO_OPENVM_POR_DEFAULT)
        );
        assert_eq!(SEGMENTO_OPENVM_POR_DEFAULT, 4 * 1024 * 1024 * 1024);
    }

    /// **La constante es el default, no un valor forzado.** Una corrida futura
    /// ajusta el segmento por entorno y sin recompilar — y ahí manda el
    /// entorno, que es lo que `ere` va a leer.
    #[test]
    fn the_environment_wins_over_the_default() {
        assert_eq!(
            segmento_openvm(Some("1073741824")),
            SegmentoOpenVm::DelEntorno(1_073_741_824)
        );
        assert_eq!(
            segmento_openvm(Some("2147483648")),
            SegmentoOpenVm::DelEntorno(2_147_483_648)
        );
    }

    /// **Un valor que no es un número no cae en el default de la receta.**
    /// `ere` lo ignora **en silencio** y usa el suyo (14,5 GiB), que es
    /// justamente el que murió por OOM: reportar acá el valor medido diría que
    /// corre algo que no corre.
    #[test]
    fn a_non_numeric_value_is_not_read_as_the_default() {
        assert_eq!(segmento_openvm(Some("4GiB")), SegmentoOpenVm::Invalida);
        assert_eq!(segmento_openvm(Some("")), SegmentoOpenVm::Invalida);
        assert_eq!(segmento_openvm(Some("-1")), SegmentoOpenVm::Invalida);
    }

    /// **Un número rodeado de espacios NO es un número para `ere`.** Su
    /// resolutor es `value.parse().ok()` sobre el valor crudo: `" 4294967296 "`
    /// falla el parseo igual que `"4GiB"` y cae al default de 14,5 GiB. Tolerar
    /// los espacios acá sería una regla PROPIA, y el driver anunciaría "el
    /// entorno manda, corriendo esto" sobre una corrida que corre otra cosa —
    /// falso-verde en la única garantía que esta función da.
    #[test]
    fn a_number_with_spaces_is_treated_like_a_non_numeric_value() {
        assert_eq!(
            segmento_openvm(Some(" 2147483648 ")),
            segmento_openvm(Some("4GiB"))
        );
        assert_eq!(
            segmento_openvm(Some(" 2147483648 ")),
            SegmentoOpenVm::Invalida
        );
        assert_eq!(
            segmento_openvm(Some("4294967296 ")),
            SegmentoOpenVm::Invalida
        );
        assert_eq!(
            segmento_openvm(Some("\t4294967296")),
            SegmentoOpenVm::Invalida
        );
    }

    /// **El esperado sale del input y se contrasta contra el archivo.** Con el
    /// caso del árbol coinciden; con un `block_hash` corrido en el archivo, el
    /// contraste falla en vez de aceptar el archivo contra sí mismo.
    #[test]
    fn the_expected_block_is_recomputed_from_the_input() {
        let root = super::repo_root();
        let archivo = match super::leer_journal_esperado(
            &root.join(super::CASO).join("block-journal.txt"),
            None,
        ) {
            Ok(j) => j,
            Err(e) => panic!("el journal congelado se lee: {e}"),
        };
        let bytes = match std::fs::read(root.join(super::CASO).join("block-input.bin")) {
            Ok(b) => b,
            Err(e) => panic!("el input congelado se lee: {e}"),
        };
        let Ok(esperado) = super::esperado_de(&bytes, &archivo) else {
            panic!("el caso del árbol es coherente");
        };
        assert_eq!(esperado.block_hash, archivo.block_hash);
        assert_eq!(esperado.parent_hash, Some(archivo.parent_hash));
        for cambio in [
            (|j: &mut repo_b_prover::Journal| j.block_hash.0[0] ^= 1) as fn(&mut _),
            |j| j.parent_hash.0[0] ^= 1,
            |j| j.chain_id = j.chain_id.wrapping_add(1),
            |j| j.fork = Some(repo_b_common::spec::Spec::Prague),
        ] {
            let mut otro = archivo;
            cambio(&mut otro);
            let Err(e) = super::esperado_de(&bytes, &otro) else {
                panic!("un archivo que no es el del input se acepta: {otro:?}");
            };
            assert!(
                e.to_string()
                    .starts_with("block-journal.txt no es el del input congelado"),
                "{e}"
            );
        }
    }
}
