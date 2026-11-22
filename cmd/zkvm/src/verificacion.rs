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
//! un bit de su `post_state_root`. OpenVM y ZisK no llevan bytes sino celdas
//! (u16 en 4 bytes y u32 en 8, respectivamente), y ahí se busca esa forma (ver
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

/// Cómo lleva un backend el journal adentro de la prueba codificada cuando no
/// lo lleva en claro: cada `bytes` del journal ocupan una celda de `ancho`
/// bytes little-endian, con el resto en cero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Celdas {
    pub bytes: usize,
    pub ancho: usize,
    pub nombre: &'static str,
}

/// OpenVM: un elemento de campo por celda `u16` del output, y el codec de
/// stark-backend escribe cada elemento como su `u32` canónico en 4 bytes LE.
pub(crate) const CELDAS_OPENVM: Celdas = Celdas {
    bytes: 2,
    ancho: 4,
    nombre: "celdas u16 como u32 canónicos (OpenVM)",
};

/// ZisK: un `u64` de Goldilocks por palabra `u32` del output, serializado por
/// bincode como 8 bytes LE.
pub(crate) const CELDAS_ZISK: Celdas = Celdas {
    bytes: 4,
    ancho: 8,
    nombre: "palabras u32 como u64 (ZisK)",
};

/// **La misma mutación, sobre la forma en que el backend lleva el journal.**
///
/// Se busca esa forma y se invierte el mismo bit del `post_state_root`
/// adentro de su celda: el valor sigue cabiendo en la celda, así que si la
/// prueba alterada no verifica es por la atadura del journal y no porque el
/// decoder lo rechace.
///
/// # Errors
/// Si los públicos no llenan celdas enteras, si la forma no aparece en la
/// prueba, o si el campo queda afuera.
pub(crate) fn alterar_journal_en_celdas(
    prueba: &[u8],
    publicos: &[u8],
    celdas: Celdas,
) -> Result<(Vec<u8>, usize), String> {
    let campo = repo_b_guest::journal::POST_STATE_ROOT_AT;
    let relleno = celdas
        .ancho
        .checked_sub(celdas.bytes)
        .filter(|_| celdas.bytes > 0)
        .ok_or("una celda tiene que ser más ancha que lo que lleva")?;
    if publicos.len() <= campo || !publicos.len().is_multiple_of(celdas.bytes) {
        return Err(format!(
            "los {} bytes públicos no llenan celdas de {} que lleguen al post_state_root",
            publicos.len(),
            celdas.bytes
        ));
    }
    let forma: Vec<u8> = publicos
        .chunks(celdas.bytes)
        .flat_map(|c| c.iter().copied().chain(std::iter::repeat_n(0, relleno)))
        .collect();
    let apariciones: Vec<usize> = prueba
        .windows(forma.len())
        .enumerate()
        .filter(|(_, w)| *w == forma.as_slice())
        .map(|(i, _)| i)
        .collect();
    let Some(&inicio) = apariciones.first() else {
        return Err(format!(
            "el journal no aparece como {} en la prueba codificada",
            celdas.nombre
        ));
    };
    let objetivo = (campo / celdas.bytes)
        .checked_mul(celdas.ancho)
        .and_then(|o| o.checked_add(campo % celdas.bytes))
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
/// de OpenVM o de ZisK. Devuelve además el nombre de la forma, para el reporte.
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
    let mut errores: Vec<String> = Vec::new();
    for celdas in [CELDAS_OPENVM, CELDAS_ZISK] {
        match alterar_journal_en_celdas(prueba, publicos, celdas) {
            Ok((p, n)) => return Ok((p, n, celdas.nombre)),
            Err(e) => errores.push(e),
        }
    }
    Err(format!(
        "el journal no aparece ni en claro ni como celdas: la mutación no se puede expresar ({})",
        errores.join("; ")
    ))
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
    use super::{
        CELDAS_OPENVM, CELDAS_ZISK, alterar_en_alguna_forma, alterar_journal,
        alterar_journal_en_celdas,
    };
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
        let r = alterar_journal_en_celdas(&prueba, &publicos, CELDAS_OPENVM);
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
        assert!(alterar_journal_en_celdas(&en_claro, &publicos, CELDAS_OPENVM).is_err());
        let celdas: Vec<u8> = publicos
            .chunks(2)
            .flat_map(|c| c.iter().copied().chain([0, 0]))
            .collect();
        assert!(alterar_journal(&celdas, &publicos).is_err());
        assert!(alterar_journal_en_celdas(&celdas, &publicos[..255], CELDAS_OPENVM).is_err());
    }

    /// **La forma de ZisK**: cada palabra de 4 bytes como un u64
    /// `[b₀, b₁, b₂, b₃, 0, 0, 0, 0]`. La búsqueda general la encuentra
    /// cuando no está en claro ni como celdas de OpenVM, y altera un solo byte
    /// adentro de la palabra del `post_state_root`.
    #[test]
    fn the_journal_is_altered_inside_zisk_words() {
        let publicos: Vec<u8> = (0u8..=255).map(|b| b | 1).collect();
        let palabras: Vec<u8> = publicos
            .chunks(4)
            .flat_map(|c| c.iter().copied().chain([0, 0, 0, 0]))
            .collect();
        let mut prueba = vec![0xee; 5];
        prueba.extend_from_slice(&palabras);
        assert!(alterar_journal_en_celdas(&prueba, &publicos, CELDAS_OPENVM).is_err());
        let r = alterar_en_alguna_forma(&prueba, &publicos);
        let Ok((alterada, veces, forma)) = r else {
            panic!("tendría que alterarse: {r:?}");
        };
        assert_eq!((veces, forma), (1, CELDAS_ZISK.nombre));
        let distintos: Vec<usize> = prueba
            .iter()
            .zip(&alterada)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        let at = POST_STATE_ROOT_AT;
        assert_eq!(distintos, vec![5 + (at / 4) * 8 + at % 4]);
    }

    /// Una prueba final de ZisK como la serializa bincode (legacy): `proof`
    /// (`Vec<u64>`), `public_values` (`Vec<u64>`), `compressed` y `hash`. Con
    /// `bandera`, las públicas llevan el flag de prueba final adelante (el
    /// formato viejo, sin comprimir); sin ella, `[vk(4) | palabras(64)]` (el
    /// comprimido que produce la versión actual).
    fn prueba_zisk(publicos: &[u8], bandera: bool) -> (Vec<u8>, usize) {
        let mut celdas: Vec<u64> = Vec::new();
        if bandera {
            celdas.push(1);
        }
        celdas.extend([0x1111, 0x2222, 0x3333, 0x4444]);
        celdas.extend(publicos.chunks(4).map(|c| {
            let mut w = [0u8; 4];
            w.copy_from_slice(c);
            u64::from(u32::from_le_bytes(w))
        }));
        let prueba: Vec<u64> = (0..50).map(|i| 0xdead_0000 + i).collect();
        let mut b = Vec::new();
        b.extend((prueba.len() as u64).to_le_bytes());
        prueba.iter().for_each(|x| b.extend(x.to_le_bytes()));
        b.extend((celdas.len() as u64).to_le_bytes());
        let inicio = b.len() + 8 * (celdas.len() - publicos.len() / 4);
        celdas.iter().for_each(|x| b.extend(x.to_le_bytes()));
        b.push(u8::from(!bandera));
        b.extend(6u64.to_le_bytes());
        b.extend(b"blake3");
        (b, inicio)
    }

    /// **El cambio de formato de la prueba de ZisK no mueve la mutación.** El
    /// layout de las públicas perdió el flag inicial; la mutación busca las
    /// palabras del journal y no indexa por posición, así que en los dos
    /// formatos altera el mismo byte del `post_state_root` y nada más.
    #[test]
    fn the_zisk_mutation_lands_on_the_post_state_root_in_both_proof_formats() {
        let publicos: Vec<u8> = (0u8..=255).map(|b| b | 1).collect();
        let at = POST_STATE_ROOT_AT;
        for bandera in [true, false] {
            let (prueba, inicio) = prueba_zisk(&publicos, bandera);
            let r = alterar_en_alguna_forma(&prueba, &publicos);
            let Ok((alterada, veces, forma)) = r else {
                panic!("tendría que alterarse (bandera {bandera}): {r:?}");
            };
            assert_eq!((veces, forma), (1, CELDAS_ZISK.nombre));
            let distintos: Vec<usize> = prueba
                .iter()
                .zip(&alterada)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(i, _)| i)
                .collect();
            assert_eq!(distintos, vec![inicio + (at / 4) * 8 + at % 4]);
        }
    }

    /// Y si las públicas de la prueba no son las que `verify` devolvió, no hay
    /// mutación que inventar: se falla.
    #[test]
    fn a_zisk_proof_of_other_public_values_is_not_mutated() {
        let publicos: Vec<u8> = (0u8..=255).map(|b| b | 1).collect();
        let (prueba, _) = prueba_zisk(&publicos, false);
        let mut otros = publicos.clone();
        if let Some(b) = otros.get_mut(POST_STATE_ROOT_AT) {
            *b ^= 0x80;
        }
        assert!(alterar_en_alguna_forma(&prueba, &otros).is_err());
    }
}
