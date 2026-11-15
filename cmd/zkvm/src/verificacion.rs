//! **Verificar una prueba guardada, y su negativa: la misma prueba con el
//! journal alterado no verifica.**
//!
//! # Por qué existe, si `prove` ya verifica
//!
//! `prove` verifica la prueba que acaba de producir. Eso dice que el
//! verificador ACEPTA lo correcto; no dice que RECHACE lo incorrecto. La
//! negativa que falta es la del consumidor: alguien recibe una prueba cuyo
//! journal fue cambiado —otro `post_state_root`, otro bloque— y el
//! verificador tiene que decir que no. Si dijera que sí, el journal no estaría
//! atado a la prueba y el cruce entre backends compararía etiquetas.
//!
//! # Cómo se altera, y cuándo la mutación no se puede expresar
//!
//! Se busca el journal (los bytes públicos que `verify` devuelve sobre la
//! prueba intacta) **en claro** adentro de la prueba codificada, y se invierte
//! un bit de su `post_state_root`. Si el backend no lleva los bytes públicos
//! contiguos en su codificación, la mutación **no se puede expresar así** y se
//! falla diciendo eso: un "no verifica" obtenido rompiendo otro byte cualquiera
//! diría que la prueba es frágil, no que el journal está atado.

use std::path::Path;
use std::time::Instant;

use ere_dockerized::{DockerizedzkVM, EncodedProof};
use repo_b_prover::{Elf, Journal, ProverResource};

use crate::Backend;
use crate::prueba::hex;

/// La prueba con un bit del `post_state_root` del journal invertido.
///
/// Devuelve la prueba alterada y cuántas veces aparece el journal en claro
/// (se altera la primera).
///
/// # Errors
/// Si el journal no aparece contiguo en la prueba, o si es más corto que el
/// campo que se altera.
pub(crate) fn alterar_journal(prueba: &[u8], publicos: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let campo = repo_b_guest::journal::POST_STATE_ROOT_AT;
    if publicos.len() <= campo {
        return Err(format!(
            "los {} bytes públicos no llegan al post_state_root (byte {campo})",
            publicos.len()
        ));
    }
    let apariciones: Vec<usize> = prueba
        .windows(publicos.len())
        .enumerate()
        .filter(|(_, w)| *w == publicos)
        .map(|(i, _)| i)
        .collect();
    let Some(&inicio) = apariciones.first() else {
        return Err(
            "el journal no aparece en claro en la prueba codificada: la mutación no se puede \
             expresar alterando el journal"
                .into(),
        );
    };
    let objetivo = inicio
        .checked_add(campo)
        .ok_or("desborde al ubicar el post_state_root")?;
    let mut alterada = prueba.to_vec();
    let byte = alterada
        .get_mut(objetivo)
        .ok_or("el post_state_root queda fuera de la prueba")?;
    *byte ^= 0x01;
    Ok((alterada, apariciones.len()))
}

/// Verifica la prueba guardada y, con `mutar`, exige que la alterada NO
/// verifique.
///
/// # Errors
/// Si la prueba intacta no verifica, si no publica un journal, si la mutación
/// no se puede expresar, o si la prueba alterada verifica.
pub(crate) fn verificar_prueba(
    backend: Backend,
    elf_path: &Path,
    prueba_path: &Path,
    mutar: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let elf = Elf(std::fs::read(elf_path)?);
    let prueba = std::fs::read(prueba_path)?;
    eprintln!("[zkvm] levantando el zkVM…");
    let zkvm = DockerizedzkVM::new(
        backend.kind(),
        elf,
        ProverResource::Cpu,
        crate::config_backend(),
    )?;
    eprintln!("[zkvm] arriba — {} {}", zkvm.name(), zkvm.sdk_version());

    let t = Instant::now();
    let publicos = zkvm
        .verify(&EncodedProof(prueba.clone()))
        .map_err(|e| format!("la prueba INTACTA no verifica: {e:#}"))?;
    println!(
        "  ok   la prueba intacta verifica en {:?} ({} B de prueba, {} B públicos)",
        t.elapsed(),
        prueba.len(),
        publicos.as_ref().len()
    );
    let journal =
        Journal::decode(publicos.as_ref()).ok_or("los bytes públicos no son un journal")?;
    println!("  ok   journal {}", hex(&journal.encode()));

    if !mutar {
        return Ok(());
    }
    // Con relleno (OpenVM publica 256 B), la codificación puede llevar solo
    // los 171 del journal: se prueba primero lo publicado entero y después el
    // journal sin relleno.
    let (alterada, veces) = alterar_journal(&prueba, publicos.as_ref()).or_else(|e| {
        publicos
            .as_ref()
            .get(..repo_b_prover::JOURNAL_BYTES)
            .filter(|_| publicos.as_ref().len() > repo_b_prover::JOURNAL_BYTES)
            .map_or(Err(e), |j| alterar_journal(&prueba, j))
    })?;
    println!(
        "  --   el journal aparece {veces} vez/veces en claro en la prueba; se invierte un bit del \
         post_state_root de la primera"
    );
    match zkvm.verify(&EncodedProof(alterada)) {
        Ok(pv) => {
            println!(
                "  FAIL la prueba con el journal ALTERADO verifica y devuelve {}",
                hex(pv.as_ref())
            );
            Err(
                "el verificador aceptó un journal alterado: el journal no está atado a la prueba"
                    .into(),
            )
        }
        Err(e) => {
            println!(
                "  ok   la prueba con el journal alterado NO verifica: {}",
                format!("{e:#}").lines().next().unwrap_or_default()
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::alterar_journal;
    use repo_b_guest::journal::POST_STATE_ROOT_AT;

    #[test]
    fn the_journal_is_altered_inside_the_proof_at_the_post_state_root() {
        let publicos: Vec<u8> = (0u8..171).collect();
        let mut prueba = vec![0xee; 10];
        prueba.extend_from_slice(&publicos);
        prueba.extend_from_slice(&[0xdd; 5]);
        let r = alterar_journal(&prueba, &publicos);
        let Ok((alterada, veces)) = r else {
            panic!("tendría que alterarse: {r:?}");
        };
        assert_eq!(veces, 1);
        let distintos: Vec<usize> = prueba
            .iter()
            .zip(&alterada)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(distintos, vec![10 + POST_STATE_ROOT_AT]);
    }

    /// Si el journal no está en claro, la mutación no se inventa: se falla.
    #[test]
    fn a_journal_that_is_not_in_the_clear_is_an_error() {
        let publicos: Vec<u8> = (0u8..171).collect();
        let prueba = vec![0xee; 400];
        assert!(
            alterar_journal(&prueba, &publicos).is_err_and(|e| e.contains("no aparece en claro"))
        );
        assert!(alterar_journal(&prueba, &[1, 2]).is_err());
    }
}
