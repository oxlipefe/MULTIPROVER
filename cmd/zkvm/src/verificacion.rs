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
//! un bit de su `post_state_root`. OpenVM no lleva bytes sino celdas `u16`,
//! cada una codificada como un `u32` de 4 bytes, y ahí se busca esa forma (ver
//! [`alterar_journal_en_celdas`]). Si el journal no aparece en ninguna de las
//! formas conocidas, la mutación **no se puede expresar así** y se
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

/// Bytes por celda de public values en la codificación de una prueba OpenVM.
const BYTES_POR_CELDA_CODIFICADA: usize = 4;
/// Bytes del journal que lleva cada celda (una celda de memoria `u16`).
const BYTES_POR_CELDA: usize = 2;

/// **La misma mutación, sobre la forma en que OpenVM lleva el journal.**
///
/// OpenVM no publica bytes: publica un elemento de campo por celda `u16`
/// little-endian del output, y el codec de la prueba escribe cada elemento
/// como su `u32` canónico en 4 bytes little-endian. O sea que el byte `2k` y
/// el `2k+1` del journal viajan como `[b₂ₖ, b₂ₖ₊₁, 0, 0]`. Se busca esa forma
/// y se invierte el mismo bit del `post_state_root` adentro de su celda: el
/// valor sigue siendo un `u16` válido, así que si la prueba alterada no
/// verifica es por la atadura del journal y no porque el decoder lo rechace.
///
/// # Errors
/// Si los públicos no son pares de bytes, si la forma no aparece en la prueba,
/// o si el campo queda afuera.
pub(crate) fn alterar_journal_en_celdas(
    prueba: &[u8],
    publicos: &[u8],
) -> Result<(Vec<u8>, usize), String> {
    let campo = repo_b_guest::journal::POST_STATE_ROOT_AT;
    if publicos.len() <= campo || !publicos.len().is_multiple_of(BYTES_POR_CELDA) {
        return Err(format!(
            "los {} bytes públicos no son celdas u16 que lleguen al post_state_root",
            publicos.len()
        ));
    }
    let forma: Vec<u8> = publicos
        .chunks(BYTES_POR_CELDA)
        .flat_map(|c| c.iter().copied().chain([0, 0]))
        .collect();
    let apariciones: Vec<usize> = prueba
        .windows(forma.len())
        .enumerate()
        .filter(|(_, w)| *w == forma.as_slice())
        .map(|(i, _)| i)
        .collect();
    let Some(&inicio) = apariciones.first() else {
        return Err(
            "el journal no aparece como celdas u16 de 4 bytes en la prueba codificada".into(),
        );
    };
    let objetivo = (campo / BYTES_POR_CELDA)
        .checked_mul(BYTES_POR_CELDA_CODIFICADA)
        .and_then(|o| o.checked_add(campo % BYTES_POR_CELDA))
        .and_then(|o| o.checked_add(inicio))
        .ok_or("desborde al ubicar el post_state_root")?;
    let mut alterada = prueba.to_vec();
    let byte = alterada
        .get_mut(objetivo)
        .ok_or("el post_state_root queda fuera de la prueba")?;
    *byte ^= 0x01;
    Ok((alterada, apariciones.len()))
}

/// La mutación en la primera forma en que el journal aparece en la prueba:
/// los bytes públicos en claro, el journal sin relleno en claro, o las celdas
/// de OpenVM. Devuelve además el nombre de la forma, para el reporte.
fn alterar_en_alguna_forma(
    prueba: &[u8],
    publicos: &[u8],
) -> Result<(Vec<u8>, usize, &'static str), String> {
    let sin_relleno = publicos
        .get(..repo_b_prover::JOURNAL_BYTES)
        .filter(|_| publicos.len() > repo_b_prover::JOURNAL_BYTES);
    if let Ok((p, n)) = alterar_journal(prueba, publicos) {
        return Ok((p, n, "los bytes públicos en claro"));
    }
    if let Some(Ok((p, n))) = sin_relleno.map(|j| alterar_journal(prueba, j)) {
        return Ok((p, n, "el journal sin relleno en claro"));
    }
    alterar_journal_en_celdas(prueba, publicos)
        .map(|(p, n)| (p, n, "celdas u16 como u32 canónicos (OpenVM)"))
        .map_err(|e| {
            format!(
                "el journal no aparece ni en claro ni como celdas: la mutación no se puede \
                 expresar ({e})"
            )
        })
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
    let (alterada, veces, forma) = alterar_en_alguna_forma(&prueba, publicos.as_ref())?;
    println!(
        "  --   el journal aparece {veces} vez/veces en la prueba como {forma}; se invierte un \
         bit del post_state_root de la primera"
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
    use super::{alterar_journal, alterar_journal_en_celdas};
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

    /// **La forma de OpenVM**: cada par de bytes como `[b₀, b₁, 0, 0]`. Se
    /// altera el bit bajo del primer byte del `post_state_root` adentro de su
    /// celda, y nada más.
    #[test]
    fn the_journal_is_altered_inside_openvm_cells() {
        let publicos: Vec<u8> = (0u8..=255).map(|b| b | 1).collect();
        let celdas: Vec<u8> = publicos
            .chunks(2)
            .flat_map(|c| c.iter().copied().chain([0, 0]))
            .collect();
        let mut prueba = vec![0xee; 7];
        prueba.extend_from_slice(&celdas);
        prueba.extend_from_slice(&[0xdd; 3]);
        let r = alterar_journal_en_celdas(&prueba, &publicos);
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
        let at = POST_STATE_ROOT_AT;
        assert_eq!(distintos, vec![7 + (at / 2) * 4 + at % 2]);
        // La celda alterada sigue siendo un u16: los dos bytes altos, en cero.
        let celda = 7 + (at / 2) * 4;
        assert_eq!(alterada.get(celda + 2..celda + 4), Some(&[0u8, 0][..]));
    }

    /// Los públicos en claro NO son la forma de celdas, y al revés: cada
    /// buscador encuentra solo la suya.
    #[test]
    fn each_form_finds_only_its_own_layout() {
        let publicos: Vec<u8> = (0u8..=255).map(|b| b | 1).collect();
        let mut en_claro = vec![0xee; 7];
        en_claro.extend_from_slice(&publicos);
        assert!(alterar_journal_en_celdas(&en_claro, &publicos).is_err());
        let celdas: Vec<u8> = publicos
            .chunks(2)
            .flat_map(|c| c.iter().copied().chain([0, 0]))
            .collect();
        assert!(alterar_journal(&celdas, &publicos).is_err());
        assert!(alterar_journal_en_celdas(&celdas, &publicos[..255]).is_err());
    }
}
