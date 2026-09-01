//! El driver que corre el guest **adentro de un zkVM de verdad**.
//!
//! # Qué hace y qué no
//!
//! `execute` corre el guest y cuenta ciclos; `prove` produce una prueba y
//! `verify` la verifica. Que estén separados fue deliberado: probar es lento y
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
//! # Un driver, dos backends
//!
//! `--backend sp1|openvm` elige el zkVM. El default es `sp1` porque es el que
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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ere_dockerized::{
    CompilerKind, DockerizedCompiler, DockerizedzkVM, DockerizedzkVMConfig, zkVMKind,
};
use repo_b_common::primitives::B256;
use repo_b_prover::{
    Compiler, Elf, Execute, Input, Journal, Mode, ProgramExecutionReport, ProverResource,
    PublicValues, cycles,
};

/// Dónde vive el caso congelado. Ver `cmd/conformance/src/blockchain/dump.rs`.
const CASO: &str = "cmd/conformance/fixtures/guest";

/// El registro público de imágenes de `ere`. Es el camino rápido: sin esto,
/// `ere-dockerized` construye las imágenes desde cero.
const REGISTRY: &str = "ghcr.io/eth-act/ere";

/// El peldaño que `prove` corre por default, y por qué éste.
///
/// Medido en esta máquina con 19,5 GiB de límite de Docker: `Nop` (9 284
/// ciclos) y `DecodeOnly` (52 285) prueban en ~133-135 s; `Recover`
/// (2 422 783) y `Full` (4 884 110) mueren por **OOM** con el pico pegado al
/// límite. Se elige el más grande que entra y que además hace trabajo real:
/// probar `Nop` probaría que la maquinaria anda, no que el guest hizo algo.
const MODO_QUE_ENTRA: Mode = Mode::DecodeOnly;

/// El techo medido, para el mensaje de error. No se adivina: se cita.
///
/// **Y el techo NO es una función del conteo de ciclos** — eso se creyó hasta
/// que se midió del otro lado. La primera sonda lo dejó acorralado entre 52 285
/// (`DecodeOnly`, prueba) y 2 422 783 (`Recover` sin acelerar, OOM), lo que
/// sugería un umbral en ciclos. Con `k256` parcheado, `Recover` baja a **105 146
/// ciclos y sigue sin entrar** (exit 137, OOM killed): un trace que contiene el
/// precompile de secp256k1 pide memoria que el doble de ciclos sin él no pide.
/// Lo que manda es **qué hay adentro del trace**, no cuántos ciclos tiene.
const TECHO_MEDIDO: &str = "\
medido en esta máquina (Docker con 19,5 GiB), y el techo NO es un umbral de
ciclos:
  `DecodeOnly`   52 285 ciclos (sin patch) → prueba en ~135 s, 1,27 MB
  `Recover`     105 146 ciclos (ECDSA ACELERADA) → OOM killed (exit 137)
  `Recover`   2 422 783 ciclos (sin acelerar)    → OOM, pico 19 395 MiB
  `Full`      2 566 473 / 4 884 110              → OOM, pico 19 507 MiB
Con la mitad de los ciclos de lo que ya fallaba, `Recover` acelerado igual no
entra: lo que pesa es que el trace contenga el chip de secp256k1, no su largo.
Y no hay una configuración que falte poner — `ere` pide SIEMPRE prueba
comprimida y `DockerizedzkVMConfig` expone solo timeouts, ningún knob de shard.

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
enum Backend {
    Sp1,
    OpenVm,
}

impl Backend {
    /// **Fail-closed**: un nombre desconocido no cae en el default.
    fn parse(nombre: &str) -> Option<Self> {
        match nombre {
            "sp1" => Some(Self::Sp1),
            "openvm" => Some(Self::OpenVm),
            _ => None,
        }
    }

    const fn kind(self) -> zkVMKind {
        match self {
            Self::Sp1 => zkVMKind::SP1,
            Self::OpenVm => zkVMKind::OpenVM,
        }
    }

    /// El toolchain con el que se compila el guest de este backend.
    ///
    /// **Los dos usan el customizado, y no es una coincidencia que convenga
    /// verificar cada vez.** `ere` ofrece dos: `Rust` compila con un nightly de
    /// stock a un target bare-metal y exige que el guest traiga su propio
    /// `_start`, su allocator y su panic handler a mano; `RustCustomized`
    /// compila con el toolchain que shipea el backend y con su target propio,
    /// que es el único camino por el que el arranque y el ABI de entrada/salida
    /// del backend entran solos. Nuestros dos guests dependen de la `Platform`
    /// del backend, así que los dos son del segundo caso — que es también el
    /// que `ere` ejercita para un guest con `Platform` en cada uno de sus tres
    /// backends.
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
        }
    }

    /// Dónde queda el ELF si nadie dice otra cosa. **Uno por backend**: con un
    /// nombre compartido, compilar el segundo pisaría al primero y la corrida
    /// siguiente mediría un ELF que no es el que cree.
    const fn elf_por_default(self) -> &'static str {
        match self {
            Self::Sp1 => "target/guest-sp1.elf",
            Self::OpenVm => "target/guest-openvm.elf",
        }
    }
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
                eprintln!("[zkvm] backend desconocido: `{n}` — son `sp1` o `openvm`.");
                std::process::exit(2);
            }
        },
    };
    eprintln!("[zkvm] backend: {}", backend.kind().name());

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
        Some("prove") => {
            let elf = elf_pedido();
            let modo = val("--mode").and_then(|m| m.parse::<u8>().ok());
            probar(backend, &elf, modo, has("--mutar-public-values"))
        }
        _ => {
            eprintln!("uso: zkvm compile [--backend sp1|openvm] --out <elf>");
            eprintln!("     zkvm run   [--backend sp1|openvm] --elf <elf> [--mode N]");
            eprintln!(
                "     zkvm prove [--backend sp1|openvm] --elf <elf> [--mode N]   (prueba Y verifica)"
            );
            std::process::exit(2);
        }
    }
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
fn config_backend() -> DockerizedzkVMConfig {
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
    let zkvm = Dockerizado(zkvm);

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
            Ok((pv, rep)) => {
                println!(
                    "el guest EJECUTÓ con el buffer vacío: {} bytes publicados, {} ciclos",
                    pv.as_ref().len(),
                    rep.total_num_cycles
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
        println!("modo {mode:?}: {} ciclos en {:?}", run.cycles, run.duration);
        println!("journal {:?}", run.journal);
        return Ok(());
    }

    let desglose = cycles::breakdown(&zkvm, &bloque)?;

    println!("\n=== EL BLOQUE REAL, ADENTRO DEL zkVM ===");
    // **La escalera separa dos cosas que se confunden: que los peldaños
    // EJECUTEN y que su costo se pueda medir.** Lo primero es del guest y es
    // portable; lo segundo depende de que el backend reporte
    // `total_num_cycles`, que es un campo que cada adaptador puebla o no. Si
    // llega en cero en toda la escalera, las restas dan cero y la tabla sale
    // con cara de dato sin haber medido nada — eso se dice, no se rellena.
    if desglose.rungs.iter().all(|(_, c)| *c == 0) {
        println!(
            "\n[!] este backend NO reporta el conteo de ciclos: los {} peldaños EJECUTARON\n    \
             y publicaron su journal, pero su costo llega en cero y el desglose de\n    \
             abajo no mide nada. La escalera es portable en sus MODOS y no en su\n    \
             número: lo que le falta no es el guest, es el campo que resta.",
            desglose.rungs.len()
        );
    }
    println!("ciclos totales      : {}", desglose.total);
    println!("peldaños de la escalera (crudos):");
    for (mode, c) in &desglose.rungs {
        println!("  {mode:<12?} {c:>12}");
    }
    println!(
        "duración de `execute` del camino real: {:?}",
        desglose.full_duration
    );
    println!("piezas (por diferencia):");
    for p in &desglose.pieces {
        let pct = if desglose.total == 0 {
            0.0
        } else {
            100.0 * p.cycles as f64 / desglose.total as f64
        };
        println!("  {:<52} {:>10}  ({pct:>5.1} %)", p.name, p.cycles);
    }

    println!("\n=== EL RESULTADO ADENTRO ES EL DE AFUERA ===");
    let publicado = desglose.journal;
    contrastar(
        "pre_state_root",
        publicado.pre_state_root,
        esperado.pre_state_root,
    );
    contrastar(
        "post_state_root",
        publicado.post_state_root,
        esperado.post_state_root,
    );
    contrastar(
        "output_digest",
        publicado.output_digest,
        esperado.output_digest,
    );
    if publicado.pre_state_root != esperado.pre_state_root
        || publicado.post_state_root != esperado.post_state_root
        || publicado.output_digest != esperado.output_digest
    {
        return Err(
            "el guest adentro del zkVM produjo OTRO resultado que el harness afuera".into(),
        );
    }
    println!("los tres campos coinciden con lo que el harness computó afuera del zkVM");
    Ok(())
}

/// Prueba el caso congelado y **verifica la prueba**, contrastando las tres
/// puntas.
///
/// # Por qué esto no pasa por el seam
///
/// `repo-b-prover` reexporta `zkVMProver` sin envolverlo, y `DockerizedzkVM`
/// tiene `prove`/`verify` como métodos inherentes. Envolverlos acá sería el
/// seam sobre el seam que el doc de `lib.rs` rechaza: una capa nuestra que no
/// agrega ninguna regla y que habría que mantener alineada con la de arriba.
/// El único adaptador que existe (`Execute`) está ahí porque `ere` no
/// implementa su propio trait para su propio tipo dockerizado — no porque
/// queramos una capa.
///
/// # La aserción, y por qué son TRES puntas y no dos
///
/// `execute` dice qué publica el guest cuando corre. `prove` dice qué publica
/// la prueba. `verify` dice qué acepta el verificador. Si solo se contrastaran
/// las dos últimas, una prueba de otro input pasaría siempre que fuera
/// internamente consistente; con `execute` adentro, lo que se afirma es que la
/// prueba es de ESTA corrida.
fn probar(
    backend: Backend,
    elf_path: &Path,
    modo: Option<u8>,
    mutar_pv: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let elf = Elf(std::fs::read(elf_path)?);
    let bloque = std::fs::read(root.join(CASO).join("block-input.bin"))?;
    let esperado = leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), None)?;

    let mode = match modo {
        Some(m) => Mode::from_byte(m).ok_or("modo desconocido")?,
        None => MODO_QUE_ENTRA,
    };

    eprintln!("[zkvm] levantando el zkVM…");
    let t = Instant::now();
    let zkvm = DockerizedzkVM::new(backend.kind(), elf, ProverResource::Cpu, config_backend())?;
    eprintln!(
        "[zkvm] arriba en {:?} — {} {}",
        t.elapsed(),
        zkvm.name(),
        zkvm.sdk_version()
    );

    let input = repo_b_prover::zkvm_input(mode, &bloque);

    println!("\n=== execute ===");
    let t = Instant::now();
    let (pv_execute, reporte) = zkvm.execute(&input)?;
    println!(
        "modo {mode:?}: {} ciclos en {:?} — {} bytes públicos",
        reporte.total_num_cycles,
        t.elapsed(),
        pv_execute.as_ref().len()
    );

    println!("\n=== prove ===");
    let t = Instant::now();
    let (pv_prove, prueba, reporte_prueba) = match zkvm.prove(&input) {
        Ok(x) => x,
        Err(e) => {
            // El techo va en el error, no en un panic críptico: quien corra
            // esto con `--mode 0` tiene que enterarse de POR QUÉ no entra y de
            // que no hay un flag que lo arregle.
            eprintln!(
                "\n[zkvm] `prove` falló en el modo {mode:?} ({} ciclos).",
                reporte.total_num_cycles
            );
            if backend == Backend::Sp1 {
                eprintln!("{TECHO_MEDIDO}");
            } else {
                eprintln!(
                    "El techo de memoria de abajo se midió con SP1 y NO vale acá: nadie\n\
                     midió el de este backend. Citarlo sería heredar un número de otra\n\
                     máquina virtual.\n{TECHO_MEDIDO}"
                );
            }
            return Err(format!("prove falló: {e:#}").into());
        }
    };
    println!(
        "prueba en {:?} (backend: {:?}) — {} bytes de prueba, {} bytes públicos",
        t.elapsed(),
        reporte_prueba.proving_time,
        prueba.as_ref().len(),
        pv_prove.as_ref().len()
    );

    println!("\n=== verify ===");
    let t = Instant::now();
    let pv_verify = zkvm.verify(&prueba)?;
    println!(
        "verificada en {:?} — {} bytes públicos",
        t.elapsed(),
        pv_verify.as_ref().len()
    );

    // **M4**: los public values de OTRA corrida. Si la aserción de abajo fuera
    // decorativa, esto pasaría igual.
    let pv_verify = if mutar_pv {
        let otro = if mode == Mode::Nop {
            Mode::DecodeOnly
        } else {
            Mode::Nop
        };
        eprintln!(
            "[M4] sustituyendo los public values de `verify` por los de una corrida en {otro:?}"
        );
        let (pv_otro, _) = zkvm.execute(&repo_b_prover::zkvm_input(otro, &bloque))?;
        pv_otro
    } else {
        pv_verify
    };

    println!("\n=== execute == prove == verify ===");
    let e = pv_execute.as_ref();
    let p = pv_prove.as_ref();
    let v = pv_verify.as_ref();
    let mut mal = false;
    for (a, b, nombre) in [(e, p, "execute vs prove"), (p, v, "prove vs verify")] {
        if a == b {
            println!("  ok   {nombre}: los mismos {} bytes", a.len());
        } else {
            println!("  FAIL {nombre}: {} bytes vs {} bytes", a.len(), b.len());
            println!("       {}", hex(a));
            println!("       {}", hex(b));
            mal = true;
        }
    }
    if mal {
        return Err("los public values de las tres puntas no son los mismos bytes".into());
    }

    println!("\n=== y esos bytes son el journal que el harness esperaba ===");
    let publicado = Journal::decode(v).ok_or("lo que se verificó no es un journal")?;
    // **Qué journal corresponde a este modo, y por qué se construye en vez de
    // compararse contra el del caso congelado.** Un modo ablacionado publica
    // ceros en los campos que no computó (`Journal::empty`), y `NoRoot`/`NoTxs`
    // publican el `pre_state_root` pero no el resto. Contrastar los tres campos
    // siempre daría un FAIL que no significa nada; no contrastar ninguno sería
    // el `verify` decorativo que este subcomando existe para evitar. Se
    // contrasta el journal ENTERO contra el que el modo debe producir — así el
    // chequeo tiene dientes en todos los peldaños, no solo en `Full`.
    let debido = match mode {
        Mode::Full => Journal { mode, ..esperado },
        Mode::NoRoot | Mode::NoTxs => Journal {
            mode,
            pre_state_root: esperado.pre_state_root,
            post_state_root: B256::ZERO,
            output_digest: esperado.output_digest,
        },
        _ => Journal::empty(mode),
    };
    if publicado.mode != mode {
        return Err(format!(
            "se probó el modo {mode:?} y el journal verificado dice {:?}",
            publicado.mode
        )
        .into());
    }
    println!("  ok   modo {:?} (el pedido)", publicado.mode);
    contrastar(
        "pre_state_root",
        publicado.pre_state_root,
        debido.pre_state_root,
    );
    contrastar(
        "post_state_root",
        publicado.post_state_root,
        debido.post_state_root,
    );
    contrastar(
        "output_digest",
        publicado.output_digest,
        debido.output_digest,
    );
    if publicado != debido {
        return Err(
            "la prueba verificada afirma otra cosa que la que este modo debe producir".into(),
        );
    }
    if mode != Mode::Full {
        println!(
            "  (modo ablacionado: los campos que este modo no computa se afirman en CERO, no se saltean)"
        );
    }
    println!("\nuna prueba de este guest VERIFICA, y afirma lo que el harness computó afuera.");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn contrastar(campo: &str, publicado: B256, esperado: B256) {
    let marca = if publicado == esperado {
        "ok  "
    } else {
        "FAIL"
    };
    println!("  {marca} {campo:<16} {publicado}");
    if publicado != esperado {
        println!("       esperado         {esperado}");
    }
}

/// Lee el journal esperado del caso congelado.
///
/// `root_mutado` es **M4**: sustituye el root esperado por otro para verificar
/// que el contraste de arriba no pasa por vacuidad.
fn leer_journal_esperado(
    path: &Path,
    root_mutado: Option<&str>,
) -> Result<Journal, Box<dyn std::error::Error>> {
    let texto = std::fs::read_to_string(path)?;
    let campo = |nombre: &str| -> Result<B256, Box<dyn std::error::Error>> {
        let raw = texto
            .lines()
            .find_map(|l| l.strip_prefix(nombre))
            .ok_or_else(|| format!("falta {nombre} en el caso congelado"))?
            .trim();
        Ok(raw.parse::<B256>()?)
    };
    let post = match root_mutado {
        Some(r) => r.parse::<B256>()?,
        None => campo("post_state_root ")?,
    };
    Ok(Journal {
        mode: Mode::Full,
        pre_state_root: campo("pre_state_root ")?,
        post_state_root: post,
        output_digest: campo("output_digest ")?,
    })
}

/// La raíz del repo, desde este manifiesto. No se adivina con el cwd: el
/// compilador de `ere` monta ESTE directorio adentro de Docker, y montar el
/// lugar equivocado da un error a los diez minutos.
fn repo_root() -> PathBuf {
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
struct Dockerizado(DockerizedzkVM);

impl Execute for Dockerizado {
    fn execute_raw(&self, input: &Input) -> Result<(PublicValues, ProgramExecutionReport), String> {
        self.0.execute(input).map_err(|e| format!("{e:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::Backend;

    /// **Un nombre desconocido no cae en el default.** Sin esto, un typo en el
    /// flag correría SP1 y la corrida reportaría el backend equivocado con cara
    /// de haber medido el pedido.
    #[test]
    fn an_unknown_backend_is_refused() {
        assert_eq!(Backend::parse("sp1"), Some(Backend::Sp1));
        assert_eq!(Backend::parse("openvm"), Some(Backend::OpenVm));
        assert_eq!(Backend::parse("SP1"), None);
        assert_eq!(Backend::parse(""), None);
        assert_eq!(Backend::parse("risc0"), None);
    }

    /// **Cada backend tiene su crate y su ELF, y no los comparte.** Un nombre
    /// de ELF compartido haría que compilar el segundo pise al primero, y la
    /// corrida siguiente mediría un binario que no es el que cree estar
    /// midiendo.
    #[test]
    fn each_backend_has_its_own_guest_and_elf() {
        assert_ne!(
            Backend::Sp1.guest_dir(),
            Backend::OpenVm.guest_dir(),
            "los dos guests concretos no pueden ser el mismo directorio"
        );
        assert_ne!(
            Backend::Sp1.elf_por_default(),
            Backend::OpenVm.elf_por_default(),
            "compilar un backend pisaría el ELF del otro"
        );
    }

    /// El default de SP1 es el que citan la receta de `prove` y el eje del
    /// nivel 3. Si cambiara, esos dos leerían un ELF que nadie escribió.
    #[test]
    fn the_sp1_elf_keeps_the_name_the_recipes_cite() {
        assert_eq!(Backend::Sp1.elf_por_default(), "target/guest-sp1.elf");
    }
}
