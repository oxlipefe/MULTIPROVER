//! **El loop de profundidad**: el segundo de los dos loops del red-team, y el
//! único pedazo que puede costar plata de verdad.
//!
//! ## El seam, y por qué hay uno solo
//!
//! Mismo criterio con el que el proyecto trata a las zkVMs: **seam fino y UNA
//! implementación concreta**. El trait `FleetProvider` es todo lo que el lazo
//! sabe de la nube; la elección de proveedor (Hetzner Cloud, ver `hetzner.rs`)
//! vive detrás y se cambia sin tocar una línea de acá.
//!
//! El seam vale además por una razón que no es de portabilidad: **el gate
//! corre con el proveedor falso** (`fake.rs`, in-memory). Un gate que necesita
//! credenciales no lo puede correr ni CI ni la próxima sesión, así que el
//! presupuesto, los dos loops, la contabilidad y la cosecha se prueban sin
//! nube — y sin la feature `diff-revm`, que CI hoy no compila.
//!
//! ## Un runner es one-shot y share-nothing
//!
//! Recibe `(semilla, rango de índices)` y **nada más**. No comparte estado con
//! los demás, no coordina, no se reusa. Eso es lo que hace que la campaña se
//! pueda partir en shards sin que el resultado dependa del reparto, y es
//! consecuencia directa de una decisión vieja: el lazo del fuzzer direcciona
//! por `(semilla, índice)` en vez de avanzar un RNG, justamente para esto.
//!
//! ## El dimensionamiento sale de medir
//!
//! Medido: **18.3× de dispersión** de throughput entre shards del MISMO tamaño
//! (785 a 14 352 casos/s sobre 20 shards de 500).
//! No es una tendencia por índice: es cola pesada, el costo del `state_test`
//! semilla. Por eso un shard **no se tarifa por cantidad de casos** sino por
//! **techo de reloj**, y ese techo es lo que se cobra por adelantado.

pub mod fake;
pub mod hetzner;

use std::path::PathBuf;

use serde_json::Value;

use crate::fuzz::budget::{Budget, micros_to_usd};
use crate::fuzz::ledger::{RunMetadata, append, record};

/// Cuántos shards puede planificar una campaña, como máximo. Acotar todo
/// recurso alimentado por configuración externa es regla del proyecto; acá
/// además el recurso es dinero.
pub const MAX_FLEET_SHARDS: u64 = 512;

/// Cada cuánto se sondea a un runner, en segundos.
pub const POLL_INTERVAL_SECS: u64 = 5;

/// El techo de reloj de un runner, en segundos, como máximo configurable.
/// Cuatro horas: más que eso no es una campaña nightly, es una flota olvidada.
pub const MAX_RUNNER_WALL_SECS: u64 = 4 * 60 * 60;

/// Lo que un runner recibe. **Es todo lo que recibe**: share-nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardSpec {
    pub seed: u64,
    pub start_index: u64,
    pub cases: u64,
    /// La etiqueta del generador, tal cual la escribe el libro mayor.
    pub generator: &'static str,
    /// El techo de reloj: lo que se cobra por adelantado y el punto en el que
    /// el runner se mata si no entregó.
    pub max_wall_secs: u64,
}

/// Lo que un runner entrega: sus líneas para el libro mayor y su contabilidad.
#[derive(Debug, Clone, Default)]
pub struct ShardOutcome {
    pub cases_run: u64,
    pub diverged: u64,
    /// Los hallazgos, ya como valores del libro mayor.
    pub findings: Vec<Value>,
    pub wall_secs: u64,
}

/// El identificador que el proveedor le da a un runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RunnerId(pub u64);

/// En qué anda un runner.
#[derive(Debug)]
pub enum RunnerState {
    Running,
    Finished(Box<ShardOutcome>),
    /// El proveedor falló. **Una campaña parcial es un resultado válido**, no
    /// basura: el libro mayor es append-only y lo que ya llegó ya está escrito.
    Failed(String),
}

/// El seam. Todo lo que el lazo sabe de la nube.
pub trait FleetProvider {
    /// **Cuánto puede costar COMO MÁXIMO este runner**, en micro-dólares.
    /// Se le pregunta ANTES de levantarlo y se cobra eso, no lo esperado.
    fn max_cost_micros(&self, shard: &ShardSpec) -> u64;

    fn launch(&mut self, shard: &ShardSpec) -> Result<RunnerId, String>;

    fn poll(&mut self, id: RunnerId) -> RunnerState;

    /// Lo que el runner costó de verdad. Se liquida contra lo cobrado.
    fn actual_cost_micros(&self, id: RunnerId) -> u64;

    /// Destruye un runner. One-shot: se llama **siempre**, haya entregado o no.
    fn destroy(&mut self, id: RunnerId);

    /// **El botón de pánico**: destruye todo lo que la flota levantó, de una.
    /// Devuelve cuántos destruyó. Es el criterio que más pesó en la elección de
    /// proveedor: blast radius.
    fn destroy_all(&mut self) -> usize;

    /// Cuántos runners siguen vivos. Al terminar tiene que dar 0, y va como
    /// test: un runner vivo después de la campaña factura solo.
    fn live_runners(&self) -> usize;

    /// Lo que el PROVEEDOR dice del gasto, si dice algo.
    ///
    /// **Existe para el reporte y NO para la decisión**, y esa asimetría es la
    /// regla hecha estructura: una alerta avisa, el gas corta. El lazo la
    /// imprime al lado de la contabilidad propia justamente para que se vea que
    /// no es la que manda — con un proveedor que nunca alerta (que es el caso
    /// normal: AWS Budgets y Azure Budgets son notification-only), la única
    /// cosa que frena el gasto es `Budget::charge`.
    fn spend_alert(&self) -> Option<String> {
        None
    }
}

/// El reloj, inyectable. Sin esto, probar el deadline de cosecha exigiría
/// esperar de verdad, y un test que tarda no se corre.
pub trait Clock {
    fn now_secs(&self) -> u64;
    /// Espera un intervalo de sondeo. El reloj falso **avanza el tiempo** en
    /// vez de dormir, que es lo que hace terminar el test del runner colgado.
    fn wait_poll_interval(&self);
}

/// El reloj de verdad.
pub struct SystemClock {
    started: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            started: std::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn wait_poll_interval(&self) {
        std::thread::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS));
    }
}

/// La configuración de una campaña de flota.
///
/// Los dos acotadores de recursos son `Option` **sin default**: es el patrón
/// `Option<Spec>` de 2.9b-3c. Un default de presupuesto contesta en silencio la
/// pregunta más cara del proyecto.
#[derive(Debug, Clone)]
pub struct FleetConfig {
    pub seed: u64,
    pub generator: &'static str,
    pub total_cases: u64,
    pub shard_cases: u64,
    /// El presupuesto, en micro-dólares. `None` ⇒ la campaña **no arranca**.
    pub budget_micros: Option<u64>,
    /// El deadline duro de cosecha, en segundos. `None` ⇒ no arranca.
    pub harvest_deadline_secs: Option<u64>,
    /// El corpus semilla que el runner va a usar, para el libro mayor.
    pub seed_corpus_tag: &'static str,
    pub ledger: Option<PathBuf>,
}

/// Por qué terminó la campaña.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Se corrieron todos los shards planificados.
    Completed,
    /// **No alcanzó el presupuesto para el siguiente runner, así que no se
    /// levantó.** Es el resultado normal de una campaña acotada por gas, no un
    /// error.
    BudgetExhausted { shards_left: u64 },
}

#[derive(Debug, Default)]
pub struct FleetReport {
    pub shards_planned: u64,
    pub shards_launched: u64,
    pub shards_harvested: u64,
    pub shards_killed_on_deadline: u64,
    pub shards_failed: u64,
    pub cases_run: u64,
    pub diverged: u64,
    /// Segundos de reloj que los runners declararon haber consumido. Va al lado
    /// del presupuesto porque es la magnitud que se tarifa.
    pub wall_secs: u64,
    pub findings: u64,
    pub budget_limit_micros: u64,
    pub budget_spent_micros: u64,
    pub budget_refunded_micros: u64,
    pub live_runners_at_exit: usize,
    pub provider_alert: Option<String>,
    pub ledger_lines: Vec<Value>,
    pub stop: Option<StopReason>,
}

impl FleetReport {
    /// El invariante que hay que poder afirmar de una campaña: nunca se gastó
    /// más que el tope, y no quedó nada encendido.
    pub const fn is_sound(&self) -> bool {
        self.budget_spent_micros <= self.budget_limit_micros && self.live_runners_at_exit == 0
    }
}

/// Parte la campaña en shards one-shot. Determinista y sin coordinación: el
/// shard `k` es `(semilla, [k·N, (k+1)·N))` y no depende de los demás.
pub fn plan_shards(config: &FleetConfig, max_wall_secs: u64) -> Result<Vec<ShardSpec>, String> {
    if config.shard_cases == 0 || config.total_cases == 0 {
        return Err("una campaña de 0 casos o shards de 0 casos no es una campaña".to_owned());
    }
    if max_wall_secs == 0 || max_wall_secs > MAX_RUNNER_WALL_SECS {
        return Err(format!(
            "techo de reloj de {max_wall_secs} s fuera del rango (1..={MAX_RUNNER_WALL_SECS})"
        ));
    }
    let count = config.total_cases.div_ceil(config.shard_cases);
    if count > MAX_FLEET_SHARDS {
        return Err(format!(
            "{count} shards: por encima del máximo de {MAX_FLEET_SHARDS}. \
             Subí `--fleet-shard-cases` en vez de levantar más máquinas"
        ));
    }
    let mut shards = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for k in 0..count {
        let start = k.saturating_mul(config.shard_cases);
        let cases = config
            .shard_cases
            .min(config.total_cases.saturating_sub(start));
        shards.push(ShardSpec {
            seed: config.seed,
            start_index: start,
            cases,
            generator: config.generator,
            max_wall_secs,
        });
    }
    Ok(shards)
}

/// Corre la campaña de profundidad.
///
/// El orden de las tres primeras líneas es el §3 entero: presupuesto
/// fail-closed, deadline fail-closed, plan. Nada se levanta antes.
pub fn run_fleet<P: FleetProvider, C: Clock>(
    config: &FleetConfig,
    provider: &mut P,
    clock: &C,
    max_wall_secs: u64,
) -> Result<FleetReport, String> {
    let mut budget = Budget::from_config(config.budget_micros)?;
    let Some(deadline_secs) = config.harvest_deadline_secs else {
        return Err(
            "la flota no arranca sin deadline de cosecha: un runner que no entrega y \
             nadie mata retiene la campaña para siempre y factura solo. \
             Pasá `--fleet-deadline <segundos>`."
                .to_owned(),
        );
    };
    let shards = plan_shards(config, max_wall_secs)?;

    let mut report = FleetReport {
        shards_planned: u64::try_from(shards.len()).unwrap_or(u64::MAX),
        budget_limit_micros: budget.limit_micros(),
        ..FleetReport::default()
    };

    // El lazo va aparte para que la destrucción total corra en TODOS los
    // caminos, incluido el de error. Un `?` suelto adentro dejaría runners
    // encendidos.
    let outcome = fleet_loop(
        config,
        provider,
        clock,
        &shards,
        &mut budget,
        &mut report,
        deadline_secs,
    );
    let _destroyed = provider.destroy_all();

    report.budget_spent_micros = budget.spent_micros();
    report.budget_refunded_micros = budget.refunded_micros();
    report.live_runners_at_exit = provider.live_runners();
    report.provider_alert = provider.spend_alert();
    outcome?;
    Ok(report)
}

fn fleet_loop<P: FleetProvider, C: Clock>(
    config: &FleetConfig,
    provider: &mut P,
    clock: &C,
    shards: &[ShardSpec],
    budget: &mut Budget,
    report: &mut FleetReport,
    deadline_secs: u64,
) -> Result<(), String> {
    for (position, shard) in shards.iter().enumerate() {
        let quote = provider.max_cost_micros(shard);
        // **Se cobra ANTES de gastar.** Si no alcanza, el runner NO se levanta
        // y la campaña termina parcial, que es un resultado válido.
        let Ok(charge) = budget.charge(quote) else {
            let left = u64::try_from(shards.len().saturating_sub(position)).unwrap_or(u64::MAX);
            report.stop = Some(StopReason::BudgetExhausted { shards_left: left });
            return Ok(());
        };
        let id = match provider.launch(shard) {
            Ok(id) => id,
            Err(e) => {
                // No se levantó nada: se devuelve el cobro entero.
                let _refund = charge.settle(budget, 0);
                report.shards_failed = report.shards_failed.saturating_add(1);
                eprintln!(
                    "[warn] shard {} no se pudo levantar: {e}",
                    shard.start_index
                );
                continue;
            }
        };
        report.shards_launched = report.shards_launched.saturating_add(1);
        // La liquidación sale de la cosecha: un runner muerto por deadline
        // liquida **al techo** —no devuelve nada, como el `OutOfGas` de un
        // frame—; el que entregó devuelve lo que no usó.
        let actual = match harvest(provider, clock, id, deadline_secs) {
            Harvest::Finished(outcome) => {
                report.shards_harvested = report.shards_harvested.saturating_add(1);
                report.cases_run = report.cases_run.saturating_add(outcome.cases_run);
                report.diverged = report.diverged.saturating_add(outcome.diverged);
                report.wall_secs = report.wall_secs.saturating_add(outcome.wall_secs);
                write_ledger(config, shard, &outcome, report)?;
                provider.actual_cost_micros(id)
            }
            Harvest::Failed(e) => {
                report.shards_failed = report.shards_failed.saturating_add(1);
                eprintln!("[warn] shard {} falló: {e}", shard.start_index);
                provider.actual_cost_micros(id)
            }
            Harvest::KilledOnDeadline => {
                report.shards_killed_on_deadline =
                    report.shards_killed_on_deadline.saturating_add(1);
                charge.reserved_micros()
            }
        };
        let _refund = charge.settle(budget, actual);
        provider.destroy(id);
    }
    report.stop = Some(StopReason::Completed);
    Ok(())
}

enum Harvest {
    Finished(ShardOutcome),
    Failed(String),
    KilledOnDeadline,
}

/// Sondea hasta que el runner entrega o **hasta el deadline duro**, que es
/// fail-closed en el tiempo: pasado el plazo se mata y su trabajo se pierde.
/// Perder una campaña es barato; una flota colgada que factura sola, no.
fn harvest<P: FleetProvider, C: Clock>(
    provider: &mut P,
    clock: &C,
    id: RunnerId,
    deadline_secs: u64,
) -> Harvest {
    let started = clock.now_secs();
    loop {
        match provider.poll(id) {
            RunnerState::Finished(outcome) => return Harvest::Finished(*outcome),
            RunnerState::Failed(e) => return Harvest::Failed(e),
            RunnerState::Running => {
                if clock.now_secs().saturating_sub(started) >= deadline_secs {
                    provider.destroy(id);
                    return Harvest::KilledOnDeadline;
                }
                clock.wait_poll_interval();
            }
        }
    }
}

/// Escribe las líneas del shard al libro mayor, **shard por shard**. Es lo que
/// hace que una campaña interrumpida siga siendo un resultado válido: lo que ya
/// llegó ya está en disco.
fn write_ledger(
    config: &FleetConfig,
    shard: &ShardSpec,
    outcome: &ShardOutcome,
    report: &mut FleetReport,
) -> Result<(), String> {
    let meta = RunMetadata::new(
        shard.seed,
        shard.start_index,
        shard.cases,
        shard.generator,
        config.seed_corpus_tag,
    );
    let lines: Vec<Value> = outcome
        .findings
        .iter()
        .map(|finding| record(&meta, finding))
        .collect();
    // **Un hallazgo que no se puede reproducir en la laptop no es un hallazgo.**
    // Se verifica acá, antes de escribirlo: un libro mayor con líneas
    // mutiladas es peor que uno vacío, porque parece que hay señal.
    for line in &lines {
        crate::fuzz::ledger::ReproSpec::from_ledger_line(line)?;
    }
    report.findings = report
        .findings
        .saturating_add(u64::try_from(lines.len()).unwrap_or(0));
    if let Some(path) = config.ledger.as_ref() {
        append(path, &lines)?;
    }
    report.ledger_lines.extend(lines);
    Ok(())
}

/// Volcado del reporte, con las dos contabilidades **una al lado de la otra**.
pub fn print_fleet_report(report: &FleetReport) {
    eprintln!();
    eprintln!("== flota — loop de PROFUNDIDAD ==");
    eprintln!(
        "shards: {} planificados, {} levantados, {} cosechados, {} muertos por deadline, {} fallidos",
        report.shards_planned,
        report.shards_launched,
        report.shards_harvested,
        report.shards_killed_on_deadline,
        report.shards_failed
    );
    eprintln!(
        "casos: {} corridos, {} divergencias crudas, {} hallazgos al libro mayor, \
         {} s de reloj cosechados",
        report.cases_run, report.diverged, report.findings, report.wall_secs
    );
    eprintln!(
        "presupuesto (NUESTRA contabilidad, la que corta): tope {}, gastado {}, devuelto {}",
        micros_to_usd(report.budget_limit_micros),
        micros_to_usd(report.budget_spent_micros),
        micros_to_usd(report.budget_refunded_micros)
    );
    match report.provider_alert.as_ref() {
        Some(alert) => eprintln!("el proveedor además avisa: {alert} (aviso, no corte)"),
        None => {
            eprintln!("el proveedor no avisa nada — y no importa: una alerta avisa, el gas corta");
        }
    }
    match report.stop.as_ref() {
        Some(StopReason::Completed) => eprintln!("terminó: campaña completa"),
        Some(StopReason::BudgetExhausted { shards_left }) => eprintln!(
            "terminó: PRESUPUESTO AGOTADO con {shards_left} shard(s) sin levantar — \
             campaña PARCIAL, que es un resultado válido (el libro mayor es append-only)"
        ),
        None => eprintln!("terminó: sin razón registrada"),
    }
    eprintln!("runners vivos al salir: {}", report.live_runners_at_exit);
}

#[cfg(test)]
mod tests;
