//! El reporte de la campaña a stderr.
//!
//! Vive aparte del lazo por una razón de tamaño y una de fondo. La de tamaño:
//! `campaign.rs` ya pasaba el máximo de 800 líneas de las reglas de estilo y
//! este slice le agrega el clustering, así que lo que se podía sacar se sacó.
//! La de fondo: **el reporte es el producto del triage**, no un `eprintln!` de
//! cortesía — el titular de una campaña es una razón señal/ruido, y esa cuenta
//! merece su propio lugar donde mirarla.
//!
//! Tres reglas que el módulo sostiene:
//!
//! 1. **La cobertura va pegada al veredicto.** "0 divergencias" y "el fuzzer
//!    está roto" producen el mismo output; sin la cobertura al lado, el
//!    primero se lee mucho más fuerte de lo que es.
//! 2. **Una divergencia conocida se cuenta y se muestra**, etiquetada con la
//!    regla a la que pertenece. Lo que cambia es el exit code, no su
//!    existencia.
//! 3. **Las sub-firmas de un cluster se imprimen.** Es la única forma de ver
//!    una fusión: si un cluster junta dos bugs, el desglose es donde se nota
//!    (la lección de M4 de 029, que quedó muda hasta que se le dio
//!    granularidad propia).

use crate::fuzz::campaign::CampaignConfig;
use crate::fuzz::coverage::implemented_opcodes;
use crate::fuzz::finding::{CampaignReport, Finding};

/// **Cobertura por tema**: qué territorio de consenso tocó la campaña.
///
/// Va pegada a la cobertura de opcodes y no la reemplaza: aquélla mide
/// profundidad de ejecución (la métrica que 2.9d-2 midió que discrimina entre
/// un generador bueno y uno malo), ésta mide **dónde podía pegar el caso**. Un
/// generador puede ejecutar los 149 opcodes con toda profundidad sin haber
/// tocado jamás una access list, una blob tx ni una delegación — y eso es
/// exactamente lo que separa a los tres generadores.
///
/// **Los cruces se imprimen aparte**, incluso los que dieron cero: un cruce
/// ausente es el dato, y una lista que solo muestra lo que pasó no lo dice.
fn print_themes(report: &CampaignReport) {
    eprintln!();
    eprintln!(
        "cobertura por TEMA ({} casos, {} temas distintos):",
        report.themes.cases,
        report.themes.distinct()
    );
    for (theme, hits) in &report.themes.hits {
        if theme.starts_with("x:") {
            continue;
        }
        eprintln!("  · {theme}: {hits}");
    }
    let crossings = report.themes.crossings();
    if crossings.is_empty() {
        eprintln!("  · CRUCES entre EIPs: ninguno — el terreno donde los sets por tema no miran");
        return;
    }
    for (theme, hits) in crossings {
        eprintln!("  · CRUCE {theme}: {hits}");
    }
}

/// El reporte a stderr. La métrica de cobertura va **pegada** al veredicto,
/// por la misma razón que el inventario del oráculo va pegado al "0
/// divergencias": sin ella, "no encontré nada" se lee mucho más fuerte de lo
/// que es.
pub fn print_report(config: &CampaignConfig, report: &CampaignReport) {
    let implemented = implemented_opcodes(repo_b_evm::types::Spec::Prague);
    eprintln!();
    eprintln!(
        "campaña: semilla {:#018x}, casos {}..{}",
        config.seed,
        config.start_index,
        config.start_index.saturating_add(config.cases)
    );
    eprintln!("generador: {}", config.generator.label());
    if report.corpus_programs > 0 {
        eprintln!(
            "siembra: {} programas de fixtures/diff/",
            report.corpus_programs
        );
    }
    if report.seed_cases > 0 {
        eprintln!(
            "corpus semilla: {} casos `state_test` de EEST {}",
            report.seed_cases,
            crate::fuzz::seeds::PINNED_TAG,
        );
    }
    eprintln!(
        "corridas: {} casos, {} divergencias, {} skip, {:.1} s ⇒ {:.0} casos/s",
        report.cases_run,
        report.diverged,
        report.skipped_fork,
        report.elapsed_secs,
        rate(report.cases_run, report.elapsed_secs),
    );
    eprintln!(
        "  · de ésos, {} son txs que RECHAZAN los dos motores (acuerdo sin ejecutar \
         un opcode)",
        report.both_rejected,
    );
    if report.seeded_cases > 0 {
        // La métrica de VECINDAD. Va pegada al veredicto por la misma razón que
        // la cobertura: un generador de mutación con los operadores muertos
        // reportaría exactamente el mismo "0 divergencias".
        eprintln!(
            "  · vecindad: {} de {} casos quedaron distintos de su semilla ({:.1} %)",
            report.mutated_cases,
            report.seeded_cases,
            report.fraction_mutated() * 100.0,
        );
    }
    if report.code_mutations > 0 {
        eprintln!(
            "  · localidad: {} mutaciones de bytecode tocaron {} de {} instrucciones \
             del stream ({:.1} %)",
            report.code_mutations,
            report.stream_touched,
            report.stream_total,
            report.stream_locality() * 100.0,
        );
        eprintln!(
            "  · saltos que siguen cayendo en un JUMPDEST: {} de {} ({:.1} %)",
            report.jumps_after,
            report.jumps_before,
            report.fraction_jumps_kept() * 100.0,
        );
    }
    eprintln!();
    eprintln!(
        "cobertura MEDIDA (muestra de {} casos):",
        report.coverage.cases
    );
    eprintln!(
        "  · opcodes ejercitados: {}/{} del set implementado ({:.1} %)",
        implemented
            .iter()
            .filter(|op| report.coverage.executed_opcodes.contains(op))
            .count(),
        implemented.len(),
        report.coverage.fraction_of_opcodes(&implemented) * 100.0,
    );
    eprintln!(
        "  · casos que pasan del primer opcode: {:.1} % ({} mueren en el primero)",
        report.coverage.fraction_past_first_opcode() * 100.0,
        report.coverage.cases_dead_at_first_opcode,
    );
    eprintln!(
        "  · casos de la muestra cuya tx no llegó a ejecutar: {}",
        report.coverage.not_executed,
    );
    eprintln!(
        "  · pasos: {} en total, traza más larga {}, {} casos llegan a 10+",
        report.coverage.total_steps,
        report.coverage.longest_trace,
        report.coverage.cases_reaching_ten_steps,
    );
    let never = report.coverage.never_executed(&implemented);
    if !never.is_empty() {
        let names: Vec<String> = never.iter().map(|op| format!("{op:#04x}")).collect();
        eprintln!(
            "  · NUNCA ejecutados ({}): {}",
            never.len(),
            names.join(" ")
        );
    }
    print_themes(report);
    eprintln!();
    print_signal_to_noise(report);
    eprintln!();
    if report.findings.is_empty() {
        eprintln!("hallazgos: ninguno.");
        eprintln!(
            "  (leer junto a la cobertura de arriba: 'ninguno' es una afirmación sobre \
             lo que esta campaña EJECUTÓ)"
        );
    } else {
        for finding in &report.findings {
            print_finding(finding);
        }
    }
    if !report.divergent_indices.is_empty() {
        let shown: Vec<String> = report
            .divergent_indices
            .iter()
            .take(32)
            .map(u64::to_string)
            .collect();
        eprintln!();
        eprintln!(
            "índices divergentes ({}{}): {}",
            report.divergent_indices.len(),
            if report.divergent_indices.len()
                >= crate::fuzz::campaign::MAX_TRACKED_DIVERGENT_INDICES
            {
                "+"
            } else {
                ""
            },
            shown.join(" ")
        );
    }
    if let Some(index) = report.first_divergent_index {
        eprintln!();
        eprintln!(
            "primera divergencia en el caso {index} ({} casos corridos, {:.1} s)",
            index.saturating_sub(config.start_index).saturating_add(1),
            report.elapsed_secs
        );
    }
}

fn rate(cases: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        return 0.0;
    }
    cases as f64 / seconds
}

/// **El titular del slice**: divergencias crudas → clusters → clusters nuevos.
///
/// Los tres números en una línea porque la lectura es la razón entre ellos: un
/// triage que no deduplica los deja iguales, y uno que fusiona colapsa el
/// segundo sin que el tercero baje.
fn print_signal_to_noise(report: &CampaignReport) {
    let clusters = report.findings.len();
    let new = report.new_clusters();
    eprintln!(
        "señal/ruido: {} divergencias crudas → {} clusters → {} NUEVOS ({} ya explicados)",
        report.diverged,
        clusters,
        new,
        report.known_clusters(),
    );
    if report.diverged > 0 && clusters > 0 {
        let per_cluster = f64::from(u32::try_from(report.diverged).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(clusters).unwrap_or(1));
        eprintln!("  · {per_cluster:.1} divergencias por cluster");
    }
    if report.triage_secs > 0.0 {
        eprintln!(
            "  · el triage costó {:.2} s de los {:.1} s de la campaña ({:.1} %)",
            report.triage_secs,
            report.elapsed_secs,
            100.0 * report.triage_secs / report.elapsed_secs.max(f64::MIN_POSITIVE),
        );
    }
    if new == 0 && clusters > 0 {
        eprintln!(
            "  · ningún cluster NUEVO: todo lo que divergió cae contra una divergencia \
             deliberada del inventario, y se muestra igual"
        );
    }
}

/// Un cluster, con todo lo que hace falta para no creerle.
fn print_finding(finding: &Finding) {
    for line in finding_lines(finding) {
        eprintln!("{line}");
    }
}

/// Las líneas de un cluster, como función pura.
///
/// Pura para poder **exigir con un test** que una divergencia conocida se
/// muestre y se cuente en vez de desaparecer. Es la regla del §3.2 —
/// *clasificar, nunca excusar*— y el costo de romperla está medido en este
/// repo: excusar en vez de clasificar dejó pasar 2 545 casos con la razón
/// equivocada.
pub fn finding_lines(finding: &Finding) -> Vec<String> {
    let mut lines = Vec::new();
    let label = match finding.known {
        Some(rule) => format!("CONOCIDO — {rule}"),
        None => "**NUEVO**".to_owned(),
    };
    lines.push(format!(
        "  · [{}] {} — {} divergencias | semilla {:#x} caso {} | minimizado {} → {} ({} pasos probados, {} aceptados)",
        finding.cluster,
        label,
        finding.occurrences,
        finding.seed,
        finding.index,
        finding.shrink.size_before,
        finding.shrink.size_after,
        finding.shrink.steps_tried,
        finding.shrink.steps_accepted,
    ));
    // El desglose por sub-firma es lo ÚNICO que delata una fusión. Sin él, un
    // cluster que se tragó dos bugs se ve igual que uno que dedupliza bien.
    lines.push(format!(
        "        sub-firmas ({}): {}",
        finding.sub_signatures.len(),
        finding.sub_signatures.join(" | ")
    ));
    if let Some(origin) = finding.origin.as_ref() {
        lines.push(format!("        origen: {origin}"));
    }
    match finding.seed_already_diverged {
        Some(true) => lines.push(
            "        [YA DIVERGÍA SIN MUTAR] la mutación no lo creó — clasificar \
             contra el inventario de divergencias deliberadas"
                .to_owned(),
        ),
        Some(false) => lines.push("        la semilla sin mutar NO divergía".to_owned()),
        None => {}
    }
    for difference in finding.differences.iter().take(4) {
        lines.push(format!("        {difference}"));
    }
    if let Some(hypothesis) = finding.llm_root_cause.as_ref() {
        // Anotación al costado del libro mayor: hipótesis para el humano,
        // nunca dictamen. No decidió el cluster ni el exit code.
        lines.push(format!(
            "        [LLM, hipótesis no vinculante] {hypothesis}"
        ));
    }
    match (&finding.fixture, finding.fixture_reproduces) {
        (Some(path), Some(true)) => lines.push(format!("        trinquete: {}", path.display())),
        (Some(path), _) => lines.push(format!(
            "        [FAIL] el fixture {} NO reproduce: trinquete mentiroso",
            path.display()
        )),
        (None, _) => {}
    }
    lines
}
