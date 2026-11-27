//! Con qué prueba cada backend: CPU o GPU, pedido explícito y sin caída.
//!
//! `ere` elige la imagen por el recurso (`ProverResource::Gpu` ⇒ la imagen
//! `-cuda` del servidor, lanzada con `--gpus $ERE_GPU_DEVICES`, `all` por
//! default). Si la caja no tiene GPU, Docker no levanta el contenedor y `ere`
//! devuelve error: no hay caída a CPU en ese camino. Lo que el driver no puede
//! ver desde afuera es si el prover de adentro usó la GPU; eso lo mide la
//! receta con la VRAM ocupada durante la corrida.

use repo_b_prover::ProverResource;

use crate::Backend;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recurso {
    Cpu,
    Gpu,
}

const FLAG: &str = "--recurso";

/// Los backends a los que se les puede pedir GPU. `ere` arma la imagen
/// `-cuda` para los cuatro; acá entran solo los que se prueban por GPU, porque
/// un camino que nadie midió no se ofrece. Agregar uno es medirlo.
pub(crate) const CON_GPU: [Backend; 2] = [Backend::Zisk, Backend::Sp1];

impl Recurso {
    /// El recurso de `ere` para un backend. Un backend que solo ejecuta
    /// corre en CPU aunque se haya pedido GPU: `execute` no prueba nada.
    ///
    /// # Errors
    /// GPU pedida para probar con un backend fuera de [`CON_GPU`].
    pub(crate) fn para(self, backend: Backend, prueba: bool) -> Result<ProverResource, String> {
        match (self, prueba) {
            (Self::Gpu, true) if !CON_GPU.contains(&backend) => Err(format!(
                "{} no prueba por GPU en esta receta (solo {})",
                backend.nombre(),
                CON_GPU.map(Backend::nombre).join(", ")
            )),
            (Self::Gpu, true) => Ok(ProverResource::Gpu),
            _ => Ok(ProverResource::Cpu),
        }
    }
}

/// `--recurso cpu|gpu`. Ausente es CPU; repetido, sin valor, con otro valor
/// o en un subcomando que no prueba es un error de uso.
///
/// # Errors
/// El motivo, para imprimir con rc=2.
pub(crate) fn de_args(args: &[String]) -> Result<Recurso, String> {
    let Some(i) = args.iter().position(|a| a == FLAG) else {
        return Ok(Recurso::Cpu);
    };
    if args.iter().filter(|a| *a == FLAG).count() > 1 {
        return Err("--recurso aparece más de una vez".into());
    }
    if !matches!(
        args.first().map(String::as_str),
        Some("prove" | "multiproof")
    ) {
        return Err("--recurso solo existe en `prove` y `multiproof`".into());
    }
    match args.get(i.saturating_add(1)).map(String::as_str) {
        Some("cpu") => Ok(Recurso::Cpu),
        Some("gpu") => Ok(Recurso::Gpu),
        _ => Err("--recurso es `cpu` o `gpu`".into()),
    }
}

/// Cuántas GPUs lista `nvidia-smi -L`. Sin el comando, o sin ninguna, es un
/// error: GPU pedida y no disponible no cae a CPU.
///
/// # Errors
/// El motivo.
pub(crate) fn gpus_visibles() -> Result<usize, String> {
    let salida = std::process::Command::new("nvidia-smi")
        .arg("-L")
        .output()
        .map_err(|e| format!("se pidió GPU y `nvidia-smi` no corre: {e}"))?;
    let n = contar_gpus(
        salida.status.success(),
        &String::from_utf8_lossy(&salida.stdout),
    );
    if n == 0 {
        return Err("se pidió GPU y `nvidia-smi -L` no lista ninguna".into());
    }
    Ok(n)
}

fn contar_gpus(ok: bool, listado: &str) -> usize {
    if !ok {
        return 0;
    }
    listado.lines().filter(|l| l.starts_with("GPU ")).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn the_flag_is_explicit_and_fail_closed() {
        assert_eq!(de_args(&args("prove --mode 0")), Ok(Recurso::Cpu));
        assert_eq!(de_args(&args("prove --recurso gpu")), Ok(Recurso::Gpu));
        assert_eq!(
            de_args(&args("multiproof --recurso cpu --mode 0")),
            Ok(Recurso::Cpu)
        );
        for malo in [
            "prove --recurso",
            "prove --recurso GPU",
            "prove --recurso --mode",
            "prove --recurso gpu --recurso gpu",
            "run --recurso gpu",
            "verify --recurso cpu",
        ] {
            assert!(de_args(&args(malo)).is_err(), "{malo} se aceptó");
        }
    }

    #[test]
    fn gpu_goes_only_to_the_backends_that_prove_on_it() {
        assert_eq!(
            Recurso::Gpu.para(Backend::Zisk, true),
            Ok(ProverResource::Gpu)
        );
        assert_eq!(
            Recurso::Gpu.para(Backend::Sp1, true),
            Ok(ProverResource::Gpu)
        );
        assert!(Recurso::Gpu.para(Backend::OpenVm, true).is_err());
        assert!(Recurso::Gpu.para(Backend::Pico, true).is_err());
        // Solo ejecuta: CPU, con o sin GPU pedida.
        assert_eq!(
            Recurso::Gpu.para(Backend::Pico, false),
            Ok(ProverResource::Cpu)
        );
        assert_eq!(
            Recurso::Cpu.para(Backend::Zisk, true),
            Ok(ProverResource::Cpu)
        );
    }

    #[test]
    fn no_listed_gpu_is_no_gpu() {
        let l = "GPU 0: NVIDIA L4 (UUID: GPU-1)\nGPU 1: NVIDIA L4 (UUID: GPU-2)\n";
        assert_eq!(contar_gpus(true, l), 2);
        assert_eq!(contar_gpus(false, l), 0);
        assert_eq!(contar_gpus(true, "No devices were found\n"), 0);
        assert_eq!(contar_gpus(true, ""), 0);
    }

    /// La receta nombra los mismos backends con GPU y las imágenes `-cuda` que
    /// `ere` levanta para sp1 y zisk.
    #[test]
    fn the_recipe_names_the_gpu_backends_and_the_cuda_images_ere_runs() {
        use ere_dockerized::{DOCKER_IMAGE_TAG, image, zkVMKind};
        let leer = |r: &str| {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(r);
            std::fs::read_to_string(p).unwrap_or_default()
        };
        let receta = leer("../../scripts/prove-block.sh");
        let lista = CON_GPU.map(Backend::nombre).join(" ");
        let sp1 = format!("ere-server-sp1:{DOCKER_IMAGE_TAG}-cuda");
        assert!(image::server_zkvm_image(zkVMKind::SP1, true).ends_with(&sp1));
        assert!(image::server_zkvm_image(zkVMKind::Zisk, true).ends_with("-cuda"));
        for linea in [
            format!("BACKENDS_CON_GPU=\"{lista}\""),
            format!("SP1_SERVIDOR_CUDA_DE_ERE=\"{sp1}\""),
        ] {
            assert!(receta.lines().any(|l| l == linea), "falta `{linea}`");
        }
        let zisk = leer("../../scripts/zisk-image.sh");
        assert!(zisk.contains("ZISK_SUFIJO=\"-cuda\""));
    }

    /// El muestreo de la receta, con un `nvidia-smi` falso: falla, salida
    /// vacía, basura y dos GPUs, en un lazo bajo `set -euo pipefail`. Un tick
    /// fallido se cuenta y el lazo sigue; la base es la muestra de reposo.
    #[cfg(unix)]
    #[test]
    fn the_gpu_sampler_survives_bad_ticks_and_counts_them() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gpu-muestreo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(std::fs::create_dir_all(&dir).is_ok());
        let stub = dir.join("nvidia-smi");
        // Una salida por llamada, en orden; la primera es la de reposo.
        let guion = r#"#!/usr/bin/env bash
c=$(cat "$0.n" 2>/dev/null || echo 0); echo $((c + 1)) > "$0.n"
case $c in
  0) echo "300, 0" ;;
  1) exit 9 ;;
  2) printf '5000, 40\n7000, 90\n' ;;
  3) echo "N/A, N/A" ;;
  4) ;;
  5) printf '9000, 99\nbasura\n' ;;
  6) echo "1000, 5" ;;
  *) exit 1 ;;
esac
"#;
        assert!(std::fs::write(&stub, guion).is_ok());
        assert!(std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).is_ok());
        let muestreo =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/gpu-muestreo.sh");
        let script = format!(
            "set -euo pipefail; source '{}'; GPU_CONSULTA='{}'; d='{}'; \
             gpu_tick \"$d\" ''; for i in 1 2 3 4 5 6 7; do gpu_tick \"$d\" zisk; done; \
             cat \"$d/gpu-zisk\"",
            muestreo.display(),
            stub.display(),
            dir.display()
        );
        let salida = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        let Ok(salida) = salida else {
            panic!("no corre bash");
        };
        // 2 válidas (dos GPUs: 12000 MiB, 90 %; y 1000/5), 5 fallidas, base 300.
        assert_eq!(
            String::from_utf8_lossy(&salida.stdout),
            "2 5 300 12000 90\n"
        );
        assert!(salida.status.success());
    }
}
