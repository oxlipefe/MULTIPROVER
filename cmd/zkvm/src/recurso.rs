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
}
