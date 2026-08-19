//! Los tests de la flota, **todos sin nube y todos sin la feature**.
//!
//! Que corran sin `diff-revm` no es un detalle de conveniencia: CI hoy no
//! compila esa feature, y un test que CI no corre no pinea nada.

use std::path::PathBuf;

use serde_json::Value;

use super::fake::{FAKE_MICROS_PER_WALL_SEC, FakeClock, FakeProvider};
use super::{FleetConfig, FleetProvider, StopReason, plan_shards, run_fleet};

/// El techo de reloj de los runners de test. Con el precio del proveedor falso
/// (100 micro-USD por segundo) cada runner cotiza **6 000 micro-USD**, y la
/// contabilidad de cada test se puede hacer de cabeza.
const WALL_SECS: u64 = 60;
const QUOTE_MICROS: u64 = WALL_SECS * FAKE_MICROS_PER_WALL_SEC;

fn config(budget_micros: Option<u64>, deadline: Option<u64>, shard_cases: u64) -> FleetConfig {
    FleetConfig {
        seed: 0x2026_0819,
        generator: "gramática",
        total_cases: 1_000,
        shard_cases,
        budget_micros,
        harvest_deadline_secs: deadline,
        seed_corpus_tag: "v5.4.0",
        ledger: None,
    }
}

fn findings_of(report: &super::FleetReport) -> Vec<Value> {
    report
        .ledger_lines
        .iter()
        .filter_map(|line| line.get("finding").cloned())
        .collect()
}

/// **M1 — el presupuesto es gas: se cobra ANTES de gastar.**
///
/// Con tope para poco más de tres runners y diez shards planificados, se
/// levantan cinco (la devolución de lo no usado deja lugar para dos más) y el
/// sexto **no se levanta**. Lo que el test afirma no es el 5: es que el gasto
/// **nunca** pasa del tope, que es lo que un contador que suma al terminar no
/// puede garantizar.
#[test]
fn charging_before_launching_is_what_keeps_a_campaign_inside_its_cap() {
    let mut provider = FakeProvider::synthetic().used_percent(50);
    let clock = FakeClock::default();
    let Ok(report) = run_fleet(
        &config(Some(20_000), Some(300), 100),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(report.shards_planned, 10);
    assert_eq!(
        report.shards_launched, 5,
        "cobro por adelantado con devolución"
    );
    assert_eq!(
        report.stop,
        Some(StopReason::BudgetExhausted { shards_left: 5 })
    );
    assert!(
        report.budget_spent_micros <= report.budget_limit_micros,
        "la campaña excedió el tope: {} > {}",
        report.budget_spent_micros,
        report.budget_limit_micros
    );
    assert!(report.is_sound());
}

/// **M6 — sin presupuesto configurado, la campaña no arranca.** Fail-closed sin
/// default silencioso: el patrón `Option<Spec>` de 2.9b-3c, aplicado a lo único
/// del proyecto que factura.
#[test]
fn a_fleet_without_a_configured_budget_does_not_start() {
    let mut provider = FakeProvider::synthetic();
    let clock = FakeClock::default();
    let Err(message) = run_fleet(
        &config(None, Some(300), 100),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("una flota sin presupuesto arrancó igual");
    };
    assert!(message.contains("sin presupuesto"), "{message}");
    assert_eq!(provider.ever_launched, 0, "se levantó algo sin presupuesto");
}

/// El deadline de cosecha es el otro acotador, y también fail-closed: es el que
/// acota el **tiempo**, y el tiempo es lo que el proveedor factura.
#[test]
fn a_fleet_without_a_harvest_deadline_does_not_start() {
    let mut provider = FakeProvider::synthetic();
    let clock = FakeClock::default();
    let Err(message) = run_fleet(
        &config(Some(20_000), None, 100),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("una flota sin deadline arrancó igual");
    };
    assert!(message.contains("deadline"), "{message}");
    assert_eq!(provider.ever_launched, 0);
}

/// **M2 — el deadline duro de cosecha.**
///
/// El runner del primer shard nunca entrega. Sin deadline, el lazo se queda
/// sondeándolo para siempre y la flota factura sola. Con deadline: se lo mata,
/// **su trabajo se pierde**, se liquida al techo (no devuelve nada, como el
/// `OutOfGas` de un frame) y la campaña sigue.
#[test]
fn a_hung_runner_is_killed_at_the_deadline_and_does_not_hold_the_campaign() {
    let mut provider = FakeProvider::synthetic().used_percent(50).hang_shard(0);
    let clock = FakeClock::default();
    let Ok(report) = run_fleet(
        &config(Some(60_000), Some(30), 250),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(report.shards_planned, 4);
    assert_eq!(report.shards_killed_on_deadline, 1);
    assert_eq!(
        report.shards_harvested, 3,
        "la campaña siguió después del colgado"
    );
    // El colgado liquida al techo; los tres que entregaron devuelven la mitad.
    assert_eq!(
        report.budget_spent_micros,
        QUOTE_MICROS + 3 * QUOTE_MICROS / 2
    );
    assert!(report.is_sound());
}

/// **M7 — el tope lo enforcea NUESTRA contabilidad, no una alerta del
/// proveedor.**
///
/// El proveedor falso **no avisa nada**, que no es un escenario pesimista sino
/// el normal: AWS Budgets y Azure Budgets son notification-only y no cortan
/// nada. Con el aviso en `None`, lo único que frena el gasto es `charge`.
#[test]
fn a_provider_that_never_alerts_cannot_move_our_cap() {
    let mut provider = FakeProvider::synthetic().used_percent(100);
    assert_eq!(
        provider.spend_alert(),
        None,
        "el falso no avisa, a propósito"
    );
    let clock = FakeClock::default();
    let Ok(report) = run_fleet(
        &config(Some(20_000), Some(300), 100),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(report.provider_alert, None);
    assert_eq!(report.shards_launched, 3, "sin devolución entran tres");
    assert_eq!(report.budget_spent_micros, 3 * QUOTE_MICROS);
    assert!(report.budget_spent_micros <= report.budget_limit_micros);
}

/// Un proveedor que **sí** avisa da exactamente el mismo veredicto. El aviso es
/// información del reporte, nunca una entrada de la decisión.
#[test]
fn a_provider_alert_changes_the_report_and_not_the_verdict() {
    let clock = FakeClock::default();
    let mut quiet = FakeProvider::synthetic().used_percent(100);
    let mut loud = FakeProvider::synthetic()
        .used_percent(100)
        .with_alert("80 % del presupuesto del proyecto");
    let (Ok(quiet_report), Ok(loud_report)) = (
        run_fleet(
            &config(Some(20_000), Some(300), 100),
            &mut quiet,
            &clock,
            WALL_SECS,
        ),
        run_fleet(
            &config(Some(20_000), Some(300), 100),
            &mut loud,
            &clock,
            WALL_SECS,
        ),
    ) else {
        panic!("las dos campañas tenían que arrancar");
    };
    assert_eq!(quiet_report.shards_launched, loud_report.shards_launched);
    assert_eq!(
        quiet_report.budget_spent_micros,
        loud_report.budget_spent_micros
    );
    assert!(loud_report.provider_alert.is_some());
}

/// **M5 — share-nothing: el resultado no depende del reparto.**
///
/// La misma campaña partida en 10 shards de 100 y en 4 shards de 250 produce
/// **los mismos hallazgos**. Es lo que hace que la flota sea una optimización
/// de wall-clock y no un experimento distinto: si un runner pudiera ver el
/// estado de otro, el reparto cambiaría el resultado y este test se pondría
/// rojo.
#[test]
fn the_findings_do_not_depend_on_how_the_campaign_is_sharded() {
    let clock = FakeClock::default();
    let mut fine = FakeProvider::synthetic();
    let mut coarse = FakeProvider::synthetic();
    let budget = Some(200_000);
    let (Ok(fine_report), Ok(coarse_report)) = (
        run_fleet(
            &config(budget, Some(300), 100),
            &mut fine,
            &clock,
            WALL_SECS,
        ),
        run_fleet(
            &config(budget, Some(300), 250),
            &mut coarse,
            &clock,
            WALL_SECS,
        ),
    ) else {
        panic!("las dos campañas tenían que arrancar");
    };
    assert_eq!(fine_report.shards_planned, 10);
    assert_eq!(coarse_report.shards_planned, 4);
    assert_eq!(fine_report.cases_run, coarse_report.cases_run);
    assert_eq!(
        findings_of(&fine_report),
        findings_of(&coarse_report),
        "el reparto en shards cambió los hallazgos: los runners no son share-nothing"
    );
    assert!(
        fine_report.findings > 0,
        "una campaña sin hallazgos no prueba nada acá"
    );
}

/// **El proveedor falla a mitad de campaña.**
///
/// Una campaña parcial es un resultado **válido**, no basura: el shard que
/// falló se cuenta, los demás se cosechan, el libro mayor queda con lo que
/// llegó, y no queda nada encendido.
#[test]
fn a_provider_failure_mid_campaign_is_a_partial_result_and_not_garbage() {
    let mut provider = FakeProvider::synthetic().fail_shard(250);
    let clock = FakeClock::default();
    let Ok(report) = run_fleet(
        &config(Some(60_000), Some(300), 250),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(report.shards_failed, 1);
    assert_eq!(report.shards_harvested, 3);
    assert_eq!(report.stop, Some(StopReason::Completed));
    assert!(
        report.findings > 0,
        "lo que llegó tiene que quedar registrado"
    );
    assert!(report.is_sound());
}

/// El libro mayor de una campaña interrumpida queda **en disco y legible**: se
/// escribe shard por shard, no al final. Un libro que se escribe al cerrar no
/// es append-only, es un buffer.
#[test]
fn an_interrupted_campaign_leaves_a_readable_ledger_on_disk() {
    let path = std::env::temp_dir().join(format!(
        "repo-b-fleet-ledger-{}-{:?}.jsonl",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    let mut config = config(Some(20_000), Some(300), 100);
    config.ledger = Some(PathBuf::from(&path));
    let mut provider = FakeProvider::synthetic().used_percent(100);
    let clock = FakeClock::default();
    let Ok(report) = run_fleet(&config, &mut provider, &clock, WALL_SECS) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(
        report.stop,
        Some(StopReason::BudgetExhausted { shards_left: 7 })
    );
    let Ok(text) = std::fs::read_to_string(&path) else {
        panic!("el libro no quedó en disco");
    };
    let _ = std::fs::remove_file(&path);
    let lines = text.lines().count();
    assert_eq!(
        u64::try_from(lines).unwrap_or(0),
        report.findings,
        "el libro en disco no tiene las líneas que el reporte declara"
    );
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            panic!("una línea del libro no es JSON: {line}");
        };
        assert!(value.get("finding").is_some());
    }
}

/// **La mitad barata de la regla: un hallazgo de la flota trae con qué
/// reproducirlo en la laptop.** La cara —volver a correrlo y comparar el
/// cluster— es el test de más abajo, detrás del oráculo.
#[test]
fn every_fleet_finding_carries_what_it_takes_to_reproduce_it_locally() {
    let mut provider = FakeProvider::synthetic();
    let clock = FakeClock::default();
    let Ok(report) = run_fleet(
        &config(Some(200_000), Some(300), 250),
        &mut provider,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert!(report.findings > 0);
    for line in &report.ledger_lines {
        let Ok(spec) = crate::fuzz::ledger::ReproSpec::from_ledger_line(line) else {
            panic!("un hallazgo de la flota no se puede reproducir: {line}");
        };
        assert_eq!(spec.seed, 0x2026_0819);
        assert_eq!(spec.generator, "gramática");
        assert!(!spec.engine_commit.is_empty());
    }
}

/// No queda nada encendido. Vale para el camino feliz y para el de error: la
/// destrucción total corre fuera del lazo justamente por eso.
#[test]
fn nothing_stays_alive_after_a_campaign() {
    let clock = FakeClock::default();
    let mut ok = FakeProvider::synthetic();
    let Ok(report) = run_fleet(
        &config(Some(200_000), Some(300), 250),
        &mut ok,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(report.live_runners_at_exit, 0);
    assert_eq!(ok.live_runners(), 0);

    let mut hung = FakeProvider::synthetic().hang_shard(0).hang_shard(250);
    let Ok(report) = run_fleet(
        &config(Some(200_000), Some(30), 250),
        &mut hung,
        &clock,
        WALL_SECS,
    ) else {
        panic!("la campaña tenía que arrancar");
    };
    assert_eq!(report.shards_killed_on_deadline, 2);
    assert_eq!(hung.live_runners(), 0, "un colgado quedó vivo");
}

/// El plan parte la campaña sin perder ni duplicar un caso, y el último shard
/// se queda con el resto. Un reparto que pierde casos haría que la flota
/// midiera menos de lo que dice.
#[test]
fn the_plan_covers_every_case_exactly_once() {
    let mut config = config(Some(20_000), Some(300), 250);
    config.total_cases = 900;
    let Ok(shards) = plan_shards(&config, WALL_SECS) else {
        panic!("el plan tenía que salir");
    };
    assert_eq!(shards.len(), 4);
    assert_eq!(shards.iter().map(|shard| shard.cases).sum::<u64>(), 900);
    assert_eq!(shards[0].start_index, 0);
    assert_eq!(shards[3].start_index, 750);
    assert_eq!(shards[3].cases, 150, "el último se queda con el resto");
    // Una campaña de cero no es una campaña.
    config.total_cases = 0;
    assert!(plan_shards(&config, WALL_SECS).is_err());
}

/// El máximo de shards corta antes de levantar nada: acotar un recurso que
/// alimenta la configuración externa es regla, y acá el recurso es dinero.
#[test]
fn too_many_shards_is_refused_before_launching_anything() {
    let mut config = config(Some(20_000), Some(300), 1);
    config.total_cases = super::MAX_FLEET_SHARDS.saturating_mul(2);
    assert!(plan_shards(&config, WALL_SECS).is_err());
    let mut provider = FakeProvider::synthetic();
    let clock = FakeClock::default();
    assert!(run_fleet(&config, &mut provider, &clock, WALL_SECS).is_err());
    assert_eq!(provider.ever_launched, 0);
}

/// Un techo de reloj fuera de rango no se acepta: es el otro lado del acotador
/// del tiempo.
#[test]
fn an_out_of_range_clock_ceiling_is_refused() {
    let config = config(Some(20_000), Some(300), 100);
    assert!(plan_shards(&config, 0).is_err());
    assert!(plan_shards(&config, super::MAX_RUNNER_WALL_SECS + 1).is_err());
}

/// **Un hallazgo de la flota reproduce en la laptop, SIN la flota.**
///
/// Es la cara cara de la regla, y por eso está detrás del oráculo: el runner
/// del proveedor falso corre la campaña **de verdad** (el mismo
/// `campaign::run` que corre local), el hallazgo va al libro mayor, y de ahí se
/// lee `(semilla, índice)` y se vuelve a producir **en proceso, sin proveedor
/// de ninguna clase**. Si no reprodujera, el libro no llevaría lo suficiente y
/// la flota estaría produciendo hallazgos que nadie puede investigar.
///
/// El caso que se usa no es artificial: el corpus dirigido trae una divergencia
/// **deliberada** del inventario (EIP-7610, la cuenta fantasma), que es lo único
/// que hoy diverge sobre un motor sano — y alcanza, porque lo que se prueba acá
/// es el camino del hallazgo, no el hallazgo.
#[cfg(feature = "diff-revm")]
#[test]
fn a_fleet_finding_reproduces_locally_from_the_ledger() {
    use crate::fuzz::campaign::{CampaignConfig, Generator, run};
    use crate::fuzz::ledger::ReproSpec;
    use crate::fuzz::site::site_of;
    use crate::fuzz::triage::cluster_key;

    fn campaign_for(seed: u64, start_index: u64, cases: u64) -> CampaignConfig {
        CampaignConfig {
            seed,
            start_index,
            cases,
            out_dir: None,
            generator: Generator::DirectedPassthrough,
            seed_corpus: false,
            stop_on_first: false,
            seed_root: None,
        }
    }

    // El runner: corre la campaña real del shard y no mira nada más que su
    // `ShardSpec`. Es literalmente lo que hace la máquina remota.
    let executor = Box::new(|shard: &super::ShardSpec| {
        let Ok(report) = run(
            &campaign_for(shard.seed, shard.start_index, shard.cases),
            None,
        ) else {
            panic!("la campaña del runner no arrancó");
        };
        super::ShardOutcome {
            cases_run: report.cases_run,
            diverged: report.diverged,
            findings: report
                .findings
                .iter()
                .map(crate::fuzz::finding::Finding::to_ledger_value)
                .collect(),
            wall_secs: shard.max_wall_secs,
        }
    });

    let mut provider = FakeProvider::with_executor(executor);
    let clock = FakeClock::default();
    let mut config = config(Some(200_000), Some(300), 4);
    config.total_cases = 12;
    config.generator = "PASS-THROUGH del corpus dirigido (contraste, sin operadores)";
    let Ok(report) = run_fleet(&config, &mut provider, &clock, WALL_SECS) else {
        panic!("la campaña de flota tenía que arrancar");
    };
    assert_eq!(report.shards_planned, 3, "12 casos en shards de 4");
    assert!(
        report.findings > 0,
        "la flota no encontró nada: sin hallazgo no hay nada que reproducir"
    );

    for line in &report.ledger_lines {
        let Ok(spec) = ReproSpec::from_ledger_line(line) else {
            panic!("un hallazgo de la flota no trae con qué reproducirlo: {line}");
        };
        // Acá abajo NO hay flota, ni proveedor, ni shards: solo la semilla y el
        // índice que salieron del libro.
        let Ok(local) = run(&campaign_for(spec.seed, spec.case_index, 1), None) else {
            panic!("la reproducción local no arrancó");
        };
        let clusters: Vec<String> = local
            .findings
            .iter()
            .map(|finding| finding.cluster.clone())
            .collect();
        assert!(
            clusters.contains(&spec.cluster),
            "el hallazgo `{}` de la flota no reproduce local desde `(semilla {:#x}, caso {})`: \
             local dio {clusters:?}",
            spec.cluster,
            spec.seed,
            spec.case_index
        );
        // Y el cluster no es un string suelto: se recomputa de la divergencia.
        let _ = (site_of, cluster_key);
    }
}
