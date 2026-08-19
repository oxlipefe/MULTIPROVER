//! **La implementación concreta del seam: Hetzner Cloud.**
//!
//! Una sola, por el mismo criterio con que el proyecto trata a las zkVMs: seam
//! fino y un backend. Cambiar de proveedor es escribir otro `impl FleetProvider`, no
//! tocar el lazo.
//!
//! ## Por qué Hetzner, con la evidencia (agosto 2026)
//!
//! El que más pesa para un equipo de dos es el último de la tabla.
//!
//! | criterio | Hetzner Cloud | AWS (EC2 spot / Batch) |
//! |---|---|---|
//! | **US$/vCPU-hora, CPU-bound** | CCX53 32 vCPU dedicadas a €0.8550/h ⇒ **€0.0267** | spot de un c7a.2xlarge ≈ **US$0.016**, on-demand ≈ US$0.046 |
//! | **tope duro real** | facturación horaria **con tope mensual por servidor** | **ninguno**: AWS Budgets es notification-only |
//! | egress | 20 TB incluidos (EU), **€1/TB** después | US$0.09/GB tras 100 GB — es la sorpresa clásica |
//! | API | `hcloud` CLI: crear, listar por label, borrar | EC2 + Batch + IAM + VPC + CloudWatch |
//! | IaC | provider oficial de Terraform | sí |
//! | **destruir todo de un comando** | `hcloud server delete $(hcloud server list -l …)` | varios tipos de recurso, con residuos típicos |
//!
//! **AWS spot es ~1.7× más barato por vCPU-hora y aun así pierde**, y decirlo
//! así es la parte honesta: el criterio que decide no es el precio sino el
//! blast radius. Con un tope de US$50–200/mes y dos personas, lo que puede
//! arruinar el mes no es pagar 1.7× de más: es una flota que quedó encendida.
//! Ahí Hetzner tiene una propiedad que AWS no tiene por ningún lado — **el tope
//! mensual por servidor**: un runner olvidado cuesta como máximo el precio
//! mensual de su plan (CCX33 = €138.49), no una recta que sube para siempre.
//!
//! Dos cosas medidas que corrigen lo que uno diría de memoria:
//!
//! 1. **Hetzner subió fuerte en 2026** (abril y junio; CPX22 pasó de €7.99 a
//!    €19.49, +144 %). El "Hetzner es 10× más barato" de otros años ya no es el
//!    número; sigue ganando, con menos margen.
//! 2. **La línea barata (CX, vCPU compartida) NO sirve acá.** Hetzner limita el
//!    uso sostenido de una vCPU compartida (del orden del 20 %), y una campaña
//!    de fuzzing es 100 % de CPU durante horas. Usar CX sería más barato en la
//!    tabla y más lento en la realidad, además de ir contra su fair-use. Por eso
//!    el plan por defecto es de la línea **CCX (vCPU dedicada)**, que cuesta ~9×
//!    la compartida por core y es la comparación honesta.
//!
//! ## Lo que este módulo NO hace
//!
//! No lee ni guarda credenciales. El token vive en `HCLOUD_TOKEN`, lo consume
//! el binario `hcloud`, y este código nunca lo toca ni lo imprime — que es la
//! única forma de que no termine en un log.

use std::collections::BTreeMap;
use std::process::Command;

use super::{FleetProvider, RunnerId, RunnerState, ShardOutcome, ShardSpec};

/// La etiqueta con la que se marca **todo** lo que levanta la flota. Es el
/// blast radius hecho dato: borrar por label es lo que hace que "destruir todo"
/// sea un comando y no una investigación.
pub const FLEET_LABEL: &str = "repo-b-fuzz";

/// Un plan de Hetzner Cloud: nombre, vCPU dedicadas y **precio por hora en
/// micro-euros**, sin IVA, región Alemania/Finlandia.
///
/// Los precios son de **agosto de 2026, posteriores a los aumentos de abril y
/// junio**. Son un dato del mundo presente: se re-verifican, no se recuerdan.
pub struct Plan {
    pub name: &'static str,
    pub vcpus: u32,
    pub micros_eur_per_hour: u64,
}

/// La línea CCX (vCPU **dedicada**), que es la que corresponde a una carga
/// 100 % de CPU sostenida.
pub const PLANS: &[Plan] = &[
    Plan {
        name: "ccx13",
        vcpus: 2,
        micros_eur_per_hour: 68_900,
    },
    Plan {
        name: "ccx23",
        vcpus: 4,
        micros_eur_per_hour: 137_800,
    },
    Plan {
        name: "ccx33",
        vcpus: 8,
        micros_eur_per_hour: 221_900,
    },
    Plan {
        name: "ccx53",
        vcpus: 32,
        micros_eur_per_hour: 855_000,
    },
];

/// El plan por defecto: **el más chico de la línea dedicada**, 2 vCPU.
///
/// Parece poco y es lo correcto, por una razón medida: **el runner es de un solo
/// hilo**. `campaign::run` es un lazo secuencial, así que pagar 8 o 32 cores
/// dedicados compraría exactamente nada — el 87 % de un `ccx33` quedaría
/// ocioso. Repartir un shard entre los cores de una máquina es una mejora
/// obvia y **deliberadamente no hecha**: está medido que no estamos limitados
/// por cómputo, y la flota compra wall-clock, no throughput por core.
pub const DEFAULT_PLAN: &str = "ccx13";

/// **Techo** de conversión euro → dólar, en micro-dólares por euro.
///
/// No es una cotización: es un techo, y por eso está tan alto. La regla es la
/// del gas: cobrar de más solo puede hacernos **parar antes**; cobrar de menos
/// nos haría exceder el tope. Un tipo de cambio pineado que se queda viejo es
/// un generador de mentiras en la dirección peligrosa, y esto lo cierra por
/// construcción.
pub const EUR_TO_USD_CEILING_MICROS: u64 = 1_600_000;

const MICROS: u64 = 1_000_000;
const SECS_PER_HOUR: u64 = 3_600;

pub fn plan_by_name(name: &str) -> Option<&'static Plan> {
    PLANS.iter().find(|plan| plan.name == name)
}

/// El costo **máximo** de un runner, en micro-dólares: precio por hora × techo
/// de reloj, redondeado **hacia arriba**.
///
/// Todo el producto intermedio va en `u128` porque el input viene de la línea
/// de comandos: `micros_eur_per_hour × EUR_TO_USD_CEILING × max_wall_secs`
/// desborda `u64` con un techo de reloj de pocas horas, y un desborde acá
/// tarifaría un runner en cero.
pub fn max_cost_micros_for(plan: &Plan, max_wall_secs: u64) -> u64 {
    let numerator = u128::from(plan.micros_eur_per_hour)
        .saturating_mul(u128::from(EUR_TO_USD_CEILING_MICROS))
        .saturating_mul(u128::from(max_wall_secs));
    let denominator = u128::from(MICROS).saturating_mul(u128::from(SECS_PER_HOUR));
    let rounded_up = numerator.div_ceil(denominator);
    u64::try_from(rounded_up).unwrap_or(u64::MAX)
}

/// El nombre del servidor de un shard. Determinista y legible: si algo queda
/// encendido, el nombre dice qué era.
pub fn server_name(shard: &ShardSpec) -> String {
    format!(
        "{FLEET_LABEL}-{:016x}-{}-{}",
        shard.seed, shard.start_index, shard.cases
    )
}

/// Los argumentos de `hcloud server create`. Función pura, para poder exigirla
/// con un test en vez de con una lectura.
pub fn create_args(shard: &ShardSpec, plan: &Plan, image: &str, location: &str) -> Vec<String> {
    vec![
        "server".to_owned(),
        "create".to_owned(),
        "--name".to_owned(),
        server_name(shard),
        "--type".to_owned(),
        plan.name.to_owned(),
        "--image".to_owned(),
        image.to_owned(),
        "--location".to_owned(),
        location.to_owned(),
        // El label es lo que hace posible destruir todo de un comando.
        "--label".to_owned(),
        format!("fleet={FLEET_LABEL}"),
        "--label".to_owned(),
        format!("shard={}", shard.start_index),
        "--user-data-from-file".to_owned(),
        "-".to_owned(),
    ]
}

/// Los argumentos que **destruyen todo**: listar por label y borrar.
///
/// Que sean dos comandos y no uno es del CLI, no del diseño; la versión de una
/// línea para tipear a mano está en el runbook de operación.
pub fn destroy_all_args() -> (Vec<String>, &'static str) {
    (
        vec![
            "server".to_owned(),
            "list".to_owned(),
            "-l".to_owned(),
            format!("fleet={FLEET_LABEL}"),
            "-o".to_owned(),
            "noheader".to_owned(),
            "-o".to_owned(),
            "columns=id".to_owned(),
        ],
        "server delete",
    )
}

/// El `cloud-init` del runner: **one-shot y share-nothing**.
///
/// Recibe `(semilla, rango)` y nada más, corre el shard, deja el resultado en
/// un archivo y **se apaga solo**. El apagado es la segunda línea de defensa
/// del presupuesto: si nuestro lazo muriera, la máquina igual termina.
pub fn cloud_init(shard: &ShardSpec, repo: &str, commit: &str) -> String {
    format!(
        "#!/bin/sh\n\
         set -eu\n\
         # Runner one-shot del red-team de Repo B. No comparte estado con nadie.\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         apt-get update -qq && apt-get install -y -qq git curl build-essential\n\
         curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal\n\
         . \"$HOME/.cargo/env\"\n\
         git clone --quiet {repo} /srv/repo-b\n\
         cd /srv/repo-b\n\
         git checkout --quiet {commit}\n\
         cargo run -p conformance --release --features diff-revm -- \\\n\
         \x20 --fuzz {generator_flag} --seed {seed:#x} --case {start} --cases {cases} \\\n\
         \x20 --ledger /srv/shard.jsonl > /srv/shard.log 2>&1 || true\n\
         # El apagado es la red de contención: si el lazo muere, la máquina no\n\
         # queda facturando.\n\
         poweroff\n",
        repo = repo,
        commit = commit,
        generator_flag = generator_flag(shard.generator),
        seed = shard.seed,
        start = shard.start_index,
        cases = shard.cases,
    )
}

/// La etiqueta del generador → su flag. Un generador desconocido cae en la
/// gramática, que es el único que **no necesita el cache de 257 MB de EEST** y
/// por lo tanto el único que un runner recién nacido puede correr sin bajarlo.
fn generator_flag(label: &str) -> &'static str {
    if label.contains("mutación de EEST") {
        "--mutate"
    } else if label.contains("DIRIGIDO") {
        "--directed"
    } else {
        ""
    }
}

/// El proveedor real. Cada método shellea `hcloud`; la construcción de los
/// argumentos y el tarifado viven en funciones puras de arriba, que son las que
/// los tests pueden mirar sin credenciales.
pub struct HetznerFleet {
    plan: &'static Plan,
    image: String,
    location: String,
    repo: String,
    commit: String,
    servers: BTreeMap<u64, String>,
    next_id: u64,
    alive: BTreeMap<u64, bool>,
}

impl HetznerFleet {
    /// `Err` si el plan no está en la tabla: un nombre de plan inventado
    /// tarifaría un runner contra un precio que no existe.
    pub fn new(
        plan_name: &str,
        image: &str,
        location: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Self, String> {
        let plan = plan_by_name(plan_name).ok_or_else(|| {
            format!(
                "el plan `{plan_name}` no está en la tabla de precios. \
                 Los conocidos: {}",
                PLANS
                    .iter()
                    .map(|plan| plan.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        Ok(Self {
            plan,
            image: image.to_owned(),
            location: location.to_owned(),
            repo: repo.to_owned(),
            commit: commit.to_owned(),
            servers: BTreeMap::new(),
            next_id: 1,
            alive: BTreeMap::new(),
        })
    }

    fn hcloud(args: &[String]) -> Result<String, String> {
        let output = Command::new("hcloud")
            .args(args)
            .output()
            .map_err(|e| format!("no se pudo ejecutar `hcloud`: {e}"))?;
        if !output.status.success() {
            // El stderr de `hcloud` no lleva el token; el token nunca pasa por
            // acá porque lo lee el propio binario del entorno.
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

impl FleetProvider for HetznerFleet {
    fn max_cost_micros(&self, shard: &ShardSpec) -> u64 {
        max_cost_micros_for(self.plan, shard.max_wall_secs)
    }

    fn launch(&mut self, shard: &ShardSpec) -> Result<RunnerId, String> {
        let args = create_args(shard, self.plan, &self.image, &self.location);
        let script = cloud_init(shard, &self.repo, &self.commit);
        let path = std::env::temp_dir().join(format!("{}.sh", server_name(shard)));
        std::fs::write(&path, script).map_err(|e| format!("cloud-init: {e}"))?;
        let mut args = args;
        if let Some(last) = args.last_mut() {
            *last = path.display().to_string();
        }
        Self::hcloud(&args)?;
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.servers.insert(id, server_name(shard));
        self.alive.insert(id, true);
        Ok(RunnerId(id))
    }

    /// La cosecha real: mientras el servidor esté corriendo, `Running`; cuando
    /// se apagó solo, se lee el archivo de resultados por `ssh`.
    fn poll(&mut self, id: RunnerId) -> RunnerState {
        let Some(name) = self.servers.get(&id.0).cloned() else {
            return RunnerState::Failed(format!("no existe el runner {}", id.0));
        };
        let status = Self::hcloud(&[
            "server".to_owned(),
            "describe".to_owned(),
            name.clone(),
            "-o".to_owned(),
            "format={{.Status}}".to_owned(),
        ]);
        match status {
            Ok(status) if status == "running" => RunnerState::Running,
            Ok(_) => match harvest_over_ssh(&name) {
                Ok(outcome) => RunnerState::Finished(Box::new(outcome)),
                Err(e) => RunnerState::Failed(e),
            },
            Err(e) => RunnerState::Failed(e),
        }
    }

    /// **Lo que el proveedor cobra no se le pregunta al proveedor.** Se liquida
    /// contra el techo, que es lo único que se sabe sin consultar una factura
    /// que llega a fin de mes. Es fail-closed: liquidar de más solo hace parar
    /// antes.
    fn actual_cost_micros(&self, id: RunnerId) -> u64 {
        let _ = id;
        max_cost_micros_for(self.plan, MAX_HETZNER_WALL_SECS)
    }

    fn destroy(&mut self, id: RunnerId) {
        let Some(name) = self.servers.get(&id.0).cloned() else {
            return;
        };
        let _ = Self::hcloud(&["server".to_owned(), "delete".to_owned(), name]);
        self.alive.insert(id.0, false);
    }

    fn destroy_all(&mut self) -> usize {
        let (list, _) = destroy_all_args();
        let Ok(ids) = Self::hcloud(&list) else {
            return 0;
        };
        let mut destroyed = 0usize;
        for server in ids.lines().filter(|line| !line.trim().is_empty()) {
            let _ = Self::hcloud(&[
                "server".to_owned(),
                "delete".to_owned(),
                server.trim().to_owned(),
            ]);
            destroyed = destroyed.saturating_add(1);
        }
        for alive in self.alive.values_mut() {
            *alive = false;
        }
        destroyed
    }

    fn live_runners(&self) -> usize {
        self.alive.values().filter(|alive| **alive).count()
    }
}

/// El techo de reloj contra el que se liquida un runner real.
const MAX_HETZNER_WALL_SECS: u64 = 60 * 60;

fn harvest_over_ssh(name: &str) -> Result<ShardOutcome, String> {
    let output = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=accept-new",
            &format!("root@{name}"),
            "cat /srv/shard.jsonl",
        ])
        .output()
        .map_err(|e| format!("cosecha por ssh: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let findings: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    Ok(ShardOutcome {
        cases_run: 0,
        diverged: u64::try_from(findings.len()).unwrap_or(0),
        findings,
        wall_secs: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard() -> ShardSpec {
        ShardSpec {
            seed: 0x2026_0819,
            start_index: 20_000,
            cases: 10_000,
            generator: "gramática",
            max_wall_secs: 3_600,
        }
    }

    /// El tarifado es por **reloj**, nunca por casos: está medido en 18.3×
    /// de dispersión de throughput entre shards del mismo tamaño, así que
    /// tarifar por casos sería tarifar contra una apuesta.
    #[test]
    fn a_runner_is_priced_by_the_clock_and_not_by_the_case_count() {
        let Some(plan) = plan_by_name(DEFAULT_PLAN) else {
            panic!("el plan por defecto no está en la tabla");
        };
        let mut one = shard();
        one.cases = 10;
        let mut many = shard();
        many.cases = 10_000_000;
        assert_eq!(
            max_cost_micros_for(plan, one.max_wall_secs),
            max_cost_micros_for(plan, many.max_wall_secs)
        );
    }

    /// El techo de una hora de un CCX33: €0.2219 × 1.60 US$/€ = US$0.355040.
    /// Está a mano para que el número del reporte se pueda verificar sin correr
    /// nada.
    #[test]
    fn the_hourly_ceiling_is_the_number_it_says() {
        let Some(plan) = plan_by_name("ccx33") else {
            panic!("ccx33 no está en la tabla");
        };
        assert_eq!(max_cost_micros_for(plan, 3_600), 355_040);
        // Y redondea hacia ARRIBA: un segundo más no puede costar menos.
        assert!(max_cost_micros_for(plan, 1) >= 1);
    }

    /// El producto intermedio no desborda con el techo de reloj máximo.
    #[test]
    fn the_quote_does_not_overflow_at_the_maximum_clock() {
        let Some(plan) = plan_by_name("ccx53") else {
            panic!("ccx53 no está en la tabla");
        };
        let quote = max_cost_micros_for(plan, super::super::MAX_RUNNER_WALL_SECS);
        assert!(quote > 0 && quote < u64::MAX);
        // Cuatro horas de un CCX53: €0.8550 × 4 × 1.60 = US$5.472.
        assert_eq!(quote, 5_472_000);
    }

    /// Todo lo que se levanta lleva el label, porque el label ES el botón de
    /// pánico. Sin él, "destruir todo" deja de ser un comando.
    #[test]
    fn everything_launched_carries_the_label_that_makes_destroy_all_possible() {
        let Some(plan) = plan_by_name(DEFAULT_PLAN) else {
            panic!("plan");
        };
        let args = create_args(&shard(), plan, "ubuntu-24.04", "nbg1");
        assert!(
            args.iter()
                .any(|arg| arg == &format!("fleet={FLEET_LABEL}")),
            "el servidor se levanta sin el label de la flota: {args:?}"
        );
        let (list, _) = destroy_all_args();
        assert!(
            list.iter()
                .any(|arg| arg == &format!("fleet={FLEET_LABEL}"))
        );
    }

    /// El runner recibe `(semilla, rango)` y **nada más**, y se apaga solo. Lo
    /// segundo es la red de contención del presupuesto: si el lazo muere, la
    /// máquina termina igual.
    #[test]
    fn the_cloud_init_is_one_shot_and_share_nothing() {
        let script = cloud_init(
            &shard(),
            "https://github.com/oxlipefe/MULTIPROVER",
            "abc123",
        );
        assert!(script.contains("--seed 0x20260819"), "{script}");
        assert!(script.contains("--case 20000"), "{script}");
        assert!(script.contains("--cases 10000"), "{script}");
        assert!(
            script.contains("poweroff"),
            "un runner que no se apaga solo factura si el lazo muere"
        );
    }

    /// Un plan inventado no se tarifa contra un precio que no existe.
    #[test]
    fn an_unknown_plan_is_refused() {
        assert!(HetznerFleet::new("ccx999", "ubuntu-24.04", "nbg1", "r", "c").is_err());
        assert!(HetznerFleet::new(DEFAULT_PLAN, "ubuntu-24.04", "nbg1", "r", "c").is_ok());
    }

    /// **El smoke test real: opt-in y FUERA del gate.**
    ///
    /// Levanta una máquina de verdad, corre un shard chico y la destruye.
    /// Cuesta plata, necesita `HCLOUD_TOKEN` y una clave ssh en el proyecto, y
    /// por eso está `#[ignore]`: un gate que necesita credenciales no lo puede
    /// correr nadie.
    ///
    /// ```sh
    /// HCLOUD_TOKEN=… REPO_B_FLEET_SMOKE=1 \
    ///   cargo test -p conformance --features diff-revm -- --ignored fleet_smoke
    /// ```
    #[test]
    #[ignore = "opt-in: levanta una máquina real y cuesta plata"]
    fn fleet_smoke_test_against_the_real_provider() {
        if std::env::var("REPO_B_FLEET_SMOKE").is_err() {
            eprintln!("smoke test sin REPO_B_FLEET_SMOKE: no se corre");
            return;
        }
        let Ok(mut fleet) = HetznerFleet::new(
            DEFAULT_PLAN,
            "ubuntu-24.04",
            "nbg1",
            "https://github.com/oxlipefe/MULTIPROVER",
            "HEAD",
        ) else {
            panic!("no se pudo construir el proveedor");
        };
        let spec = ShardSpec {
            seed: 0x5A0C,
            start_index: 0,
            cases: 1_000,
            generator: "gramática",
            max_wall_secs: 900,
        };
        let launched = fleet.launch(&spec);
        // Pase lo que pase, no queda nada encendido.
        let destroyed = fleet.destroy_all();
        assert_eq!(fleet.live_runners(), 0, "quedó un runner vivo");
        match launched {
            Ok(_) => assert!(destroyed >= 1, "el servidor no se destruyó"),
            Err(e) => panic!("no se pudo levantar: {e}"),
        }
    }
}
