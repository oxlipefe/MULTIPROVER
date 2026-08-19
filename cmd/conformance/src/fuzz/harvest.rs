//! Qué se hace con una divergencia una vez encontrada: minimizarla,
//! clasificarla y dejarla reproducible.
//!
//! Vive aparte del lazo de la campaña por dos razones, y la segunda es la que
//! manda: (a) `campaign.rs` ya pasaba el máximo de 800 líneas de las reglas de
//! estilo y no puede crecer; (b) el lazo y la cosecha son dos trabajos
//! distintos —uno decide QUÉ correr, el otro QUÉ hacer con lo que salió mal— y
//! el segundo es el que crece cada vez que entra un generador nuevo.

use crate::diff::{CaseOutcome, run_case};
use crate::fuzz::campaign::{CampaignCase, CampaignConfig};
use crate::fuzz::emit::write_fixture;
use crate::fuzz::finding::Finding;
use crate::fuzz::shrink::shrink;
use crate::fuzz::site::site_of;
use crate::fuzz::triage::{cluster_key, signature, signature_slug};
use crate::oracle::known_cluster;

/// Minimiza y trinquetea el representante de un cluster.
pub fn triage_finding<C: CampaignCase>(
    config: &CampaignConfig,
    case: &C,
    index: u64,
    cluster: &str,
    site: &str,
    differences: Vec<String>,
) -> Finding {
    // El predicado del shrinker es **el mismo CLUSTER**, no "cualquier
    // divergencia" ni "la misma sub-firma". Un shrinker guiado por "diverge" te
    // entrega el reproductor de otro bug minimizado con toda prolijidad; uno
    // guiado por la sub-firma puede terminar en otro SITIO, y entonces el
    // reproductor del cluster no reproduce el cluster.
    let target = cluster.to_owned();
    let (minimized, stats) = shrink(case, |candidate: &C| match candidate.with_parts(run_case) {
        CaseOutcome::Diverged { differences } => {
            let site = candidate.with_parts(|test, post| site_of(test, post, &differences));
            cluster_key(&differences, &site) == target
        }
        CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => false,
    });

    let signature_of_case = signature(&differences);
    let mut finding = Finding {
        cluster: target.clone(),
        site: site.to_owned(),
        occurrences: 1,
        sub_signatures: vec![signature_of_case.clone()],
        known: known_cluster(&target).map(|known| known.rule),
        llm_root_cause: None,
        signature: signature_of_case,
        seed: config.seed,
        index,
        differences,
        shrink: stats,
        fixture: None,
        fixture_reproduces: None,
        origin: minimized.origin(),
        seed_index: minimized.seed_index(),
        seed_already_diverged: None,
        reproducer: None,
    };

    let comment = finding_comment(&target, config.seed, index, finding.origin.as_deref());
    let name = format!("{}-{:016x}-{index}", signature_slug(&target), config.seed);
    // El reproductor viaja EMBEBIDO en el hallazgo, exista o no el directorio
    // del trinquete: el libro mayor no puede depender de un `--out`.
    finding.reproducer =
        Some(minimized.with_parts(|test, post| {
            crate::fuzz::emit::to_fixture_json(test, post, &name, &comment)
        }));

    let Some(dir) = config.out_dir.as_ref() else {
        return finding;
    };
    let written =
        minimized.with_parts(|test, post| write_fixture(dir, &name, test, post, &comment));
    match written {
        Ok(path) => {
            finding.fixture_reproduces = Some(fixture_still_diverges(&path, &target));
            finding.fixture = Some(path);
        }
        Err(e) => eprintln!("[warn] no se pudo escribir el fixture del hallazgo: {e}"),
    }
    finding
}

/// El comentario que viaja DENTRO del fixture emitido.
///
/// Lleva la semilla, el índice **y la identidad del fixture semilla**: sin lo
/// tercero, un hallazgo del generador de mutación no se puede volver a mirar
/// una vez que el corpus cambie de tamaño (el índice del caso semilla depende
/// del release de EEST; el nombre del caso no). Es función pura para poder
/// exigirlo con un test en vez de con una lectura.
fn finding_comment(cluster: &str, seed: u64, index: u64, origin: Option<&str>) -> String {
    let origin = origin.map_or_else(String::new, |origin| format!("; origen: {origin}"));
    format!(
        "fuzz diferencial — cluster [{cluster}] minimizado; reproducir con \
         `--fuzz --seed {seed:#x} --case {index}`{origin}"
    )
}

/// Re-lee el fixture del disco y lo vuelve a correr. Es la mitad del contrato
/// del trinquete que solo el oráculo puede verificar.
fn fixture_still_diverges(path: &std::path::Path, expected: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(tests) = crate::fixture::parse_file(&raw) else {
        return false;
    };
    tests.iter().any(|test| {
        test.posts.iter().any(|post| match run_case(test, post) {
            CaseOutcome::Diverged { differences } => {
                cluster_key(&differences, &site_of(test, post, &differences)) == expected
            }
            CaseOutcome::Same | CaseOutcome::SkippedFork | CaseOutcome::BothRejectedTx { .. } => {
                false
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::campaign::CampaignCase;

    /// El comentario del fixture emitido lleva **la identidad del fixture
    /// semilla**. Sin ella, un hallazgo del generador de mutación deja de ser
    /// reproducible en cuanto el corpus cambie de tamaño.
    #[test]
    fn the_emitted_comment_carries_the_seed_fixture_identity() {
        let corpus = crate::fuzz::mutate::synthetic_corpus();
        let Some(case) = crate::fuzz::mutate::mutate_case(0xABC, 3, &corpus, false) else {
            panic!("sin caso");
        };
        let Some(origin) = case.origin() else {
            panic!("un caso de mutación tiene que declarar su origen");
        };
        assert!(
            origin.contains("sintetico"),
            "el origen no nombra al fixture semilla: {origin}"
        );
        let comment = finding_comment("gas_used", 0xABC, 3, Some(&origin));
        assert!(comment.contains("--seed 0xabc"), "{comment}");
        assert!(comment.contains("--case 3"), "{comment}");
        assert!(comment.contains("sintetico"), "{comment}");
    }
}
