//! El driver que corre el guest **adentro de un zkVM de verdad**.
//!
//! # Qué hace y qué no
//!
//! No prueba nada todavía: `execute` sí, `prove` no. Es deliberado — probar es
//! lento y caro, y un guest que no ejecuta no prueba nada; juntar las dos cosas
//! haría imposible saber cuál de las dos falló.
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
//! # Uso
//!
//! ```sh
//! ERE_IMAGE_REGISTRY=ghcr.io/eth-act/ere cargo run --release -p zkvm -- compile --out /tmp/guest.elf
//! ERE_IMAGE_REGISTRY=ghcr.io/eth-act/ere cargo run --release -p zkvm -- run --elf /tmp/guest.elf [--mode N]
//! ```

use std::path::{Path, PathBuf};
use std::time::Instant;

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
            Ok(r) => format!("imágenes de {r} (amd64, emuladas en ARM)"),
            Err(_) => format!(
                "imágenes locales (se construyen si faltan; poné ERE_IMAGE_REGISTRY={REGISTRY} \
                 para usar las publicadas)"
            ),
        }
    );

    match args.first().map(String::as_str) {
        Some("compile") => {
            let out = PathBuf::from(val("--out").unwrap_or_else(|| "target/guest-sp1.elf".into()));
            compile(&out)
        }
        Some("run") => {
            let elf = PathBuf::from(val("--elf").unwrap_or_else(|| "target/guest-sp1.elf".into()));
            let modo = val("--mode").and_then(|m| m.parse::<u8>().ok());
            let corrupto = has("--mutar-input-vacio");
            let nulo = has("--mutar-input-nulo");
            let root_mutado = val("--mutar-root-esperado");
            run(&elf, modo, corrupto, nulo, root_mutado.as_deref())
        }
        _ => {
            eprintln!("uso: zkvm compile --out <elf>");
            eprintln!("     zkvm run --elf <elf> [--mode N]");
            std::process::exit(2);
        }
    }
}

/// Compila el guest de SP1 con **su** toolchain, adentro de su imagen.
fn compile(out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let guest = root.join("crates/guest-sp1");
    eprintln!("[zkvm] compilando {} …", guest.display());
    let t = Instant::now();
    let compiler = DockerizedCompiler::new(zkVMKind::SP1, CompilerKind::RustCustomized, &root)?;
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

/// Ejecuta el caso congelado adentro del zkVM y contrasta lo que publicó.
fn run(
    elf_path: &Path,
    modo: Option<u8>,
    input_vacio: bool,
    input_nulo: bool,
    root_mutado: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let elf = Elf(std::fs::read(elf_path)?);
    let bloque = std::fs::read(root.join(CASO).join("block-input.bin"))?;
    let esperado = leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), root_mutado)?;

    eprintln!("[zkvm] levantando el zkVM…");
    let t = Instant::now();
    let zkvm = DockerizedzkVM::new(
        zkVMKind::SP1,
        elf,
        ProverResource::Cpu,
        DockerizedzkVMConfig::default(),
    )?;
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
