//! El **proveedor falso**: la flota entera, in-memory, sin una credencial.
//!
//! No es andamiaje de test: es lo que gatea el repo. Un gate que necesita
//! credenciales no lo puede correr ni CI ni la próxima sesión, así que el
//! presupuesto, el deadline, la contabilidad, la cosecha y el share-nothing se
//! prueban acá — y la implementación real (`hetzner.rs`) tiene un smoke test
//! **opt-in y fuera del gate**.
//!
//! Lo que el falso puede simular y la nube de verdad no te deja provocar
//! barato: un runner que **nunca entrega** (el colgado que factura solo), uno
//! que falla a mitad de campaña, y un proveedor que **no avisa nada** — que no
//! es una simulación pesimista sino el caso normal, porque AWS Budgets y Azure
//! Budgets son notification-only.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::{Clock, FleetProvider, RunnerId, RunnerState, ShardOutcome, ShardSpec};

/// Cuánto cuesta un segundo de reloj en el proveedor falso, en micro-dólares.
/// Un número redondo a propósito: la contabilidad de los tests tiene que
/// poderse hacer de cabeza.
pub const FAKE_MICROS_PER_WALL_SEC: u64 = 100;

/// Un runner del proveedor falso.
struct Runner {
    shard: ShardSpec,
    outcome: Option<ShardOutcome>,
    alive: bool,
    harvested: bool,
    actual_micros: u64,
    hangs: bool,
    fails: bool,
}

/// El ejecutor de un shard: lo que el runner *hace*.
///
/// Es una función del `ShardSpec` **y de nada más**, y eso es el share-nothing
/// escrito como tipo: si el resultado dependiera de algo fuera del spec, el
/// reparto de la campaña en shards cambiaría el resultado.
type Executor = Box<dyn Fn(&ShardSpec) -> ShardOutcome>;

pub struct FakeProvider {
    executor: Executor,
    runners: BTreeMap<u64, Runner>,
    next_id: u64,
    /// `start_index` de los shards cuyo runner **nunca entrega**.
    hang_shards: BTreeSet<u64>,
    /// `start_index` de los shards cuyo runner falla.
    fail_shards: BTreeSet<u64>,
    /// Qué fracción del techo de reloj consume de verdad un runner que
    /// entrega, en porciento. Con menos de 100 la devolución es observable.
    used_percent: u64,
    /// Lo que el proveedor "avisa". **`None` por defecto**, que es el caso
    /// normal de la industria.
    alert: Option<String>,
    pub ever_launched: usize,
    pub ever_destroyed: usize,
}

impl FakeProvider {
    /// El proveedor con el ejecutor sintético: emite un hallazgo cada
    /// `FINDING_EVERY` índices, de forma determinista y direccionable.
    pub fn synthetic() -> Self {
        Self::with_executor(Box::new(synthetic_shard))
    }

    pub fn with_executor(executor: Executor) -> Self {
        Self {
            executor,
            runners: BTreeMap::new(),
            next_id: 1,
            hang_shards: BTreeSet::new(),
            fail_shards: BTreeSet::new(),
            used_percent: 50,
            alert: None,
            ever_launched: 0,
            ever_destroyed: 0,
        }
    }

    /// El shard que arranca en `start_index` levanta un runner que **nunca
    /// entrega**. Es el escenario que el deadline de cosecha existe para cortar.
    pub fn hang_shard(mut self, start_index: u64) -> Self {
        self.hang_shards.insert(start_index);
        self
    }

    /// El shard que arranca en `start_index` falla. Prueba que una campaña
    /// parcial es un resultado válido, no basura.
    pub fn fail_shard(mut self, start_index: u64) -> Self {
        self.fail_shards.insert(start_index);
        self
    }

    pub fn used_percent(mut self, percent: u64) -> Self {
        self.used_percent = percent.min(100);
        self
    }

    /// Un proveedor que sí avisa. Existe para poder probar que el aviso **no
    /// cambia nada**: el que corta es el gas.
    pub fn with_alert(mut self, alert: &str) -> Self {
        self.alert = Some(alert.to_owned());
        self
    }
}

/// El hallazgo sintético cae en los índices múltiplos de esto.
pub const FINDING_EVERY: u64 = 97;

/// El ejecutor sintético: **función pura del `ShardSpec`**.
fn synthetic_shard(shard: &ShardSpec) -> ShardOutcome {
    let mut findings = Vec::new();
    for offset in 0..shard.cases {
        let index = shard.start_index.saturating_add(offset);
        if index.is_multiple_of(FINDING_EVERY) {
            findings.push(json!({
                "cluster": format!("sintetico@{}", index % 7),
                "case_index": index,
                "seed": format!("{:#x}", shard.seed),
                "generator": shard.generator,
            }));
        }
    }
    ShardOutcome {
        cases_run: shard.cases,
        diverged: u64::try_from(findings.len()).unwrap_or(0),
        findings,
        wall_secs: shard.max_wall_secs,
    }
}

impl FleetProvider for FakeProvider {
    /// El techo: precio por segundo × techo de reloj. **Nunca depende de la
    /// cantidad de casos**, que es la lección de medir el throughput por shard.
    fn max_cost_micros(&self, shard: &ShardSpec) -> u64 {
        shard.max_wall_secs.saturating_mul(FAKE_MICROS_PER_WALL_SEC)
    }

    fn launch(&mut self, shard: &ShardSpec) -> Result<RunnerId, String> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let hangs = self.hang_shards.contains(&shard.start_index);
        let fails = self.fail_shards.contains(&shard.start_index);
        let outcome = if hangs || fails {
            None
        } else {
            Some((self.executor)(shard))
        };
        let actual_micros = self
            .max_cost_micros(shard)
            .saturating_mul(self.used_percent)
            / 100;
        self.runners.insert(
            id,
            Runner {
                shard: shard.clone(),
                outcome,
                alive: true,
                harvested: false,
                actual_micros,
                hangs,
                fails,
            },
        );
        self.ever_launched = self.ever_launched.saturating_add(1);
        Ok(RunnerId(id))
    }

    fn poll(&mut self, id: RunnerId) -> RunnerState {
        let Some(runner) = self.runners.get_mut(&id.0) else {
            return RunnerState::Failed(format!("no existe el runner {}", id.0));
        };
        if runner.fails {
            return RunnerState::Failed(format!(
                "el runner del shard {} falló",
                runner.shard.start_index
            ));
        }
        if runner.hangs {
            return RunnerState::Running;
        }
        if runner.harvested {
            return RunnerState::Failed("sondeado después de cosechar".to_owned());
        }
        match runner.outcome.take() {
            Some(outcome) => {
                runner.harvested = true;
                RunnerState::Finished(Box::new(outcome))
            }
            None => RunnerState::Running,
        }
    }

    fn actual_cost_micros(&self, id: RunnerId) -> u64 {
        self.runners
            .get(&id.0)
            .map_or(0, |runner| runner.actual_micros)
    }

    fn destroy(&mut self, id: RunnerId) {
        if let Some(runner) = self.runners.get_mut(&id.0)
            && runner.alive
        {
            runner.alive = false;
            self.ever_destroyed = self.ever_destroyed.saturating_add(1);
        }
    }

    fn destroy_all(&mut self) -> usize {
        let mut destroyed = 0usize;
        for runner in self.runners.values_mut() {
            if runner.alive {
                runner.alive = false;
                destroyed = destroyed.saturating_add(1);
            }
        }
        self.ever_destroyed = self.ever_destroyed.saturating_add(destroyed);
        destroyed
    }

    fn live_runners(&self) -> usize {
        self.runners.values().filter(|runner| runner.alive).count()
    }

    fn spend_alert(&self) -> Option<String> {
        self.alert.clone()
    }
}

/// El reloj falso: **avanza cuando se lo sondea**, en vez de dormir. Es lo que
/// hace que el test del runner colgado termine en microsegundos en vez de en el
/// deadline de verdad.
#[derive(Debug, Default)]
pub struct FakeClock {
    now: Cell<u64>,
}

impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.now.get()
    }

    fn wait_poll_interval(&self) {
        self.now
            .set(self.now.get().saturating_add(super::POLL_INTERVAL_SECS));
    }
}
