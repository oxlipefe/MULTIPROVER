//! **Qué bloque corre el driver**: el caso congelado del harness, o un input
//! que escribió el importador (`conformance --import-block`) junto con el hash
//! que nombró el operador.
//!
//! Con el caso congelado, el oráculo es el journal que el harness computó
//! afuera con el estado completo, y lo esperado sale del input contrastado
//! contra ese archivo. Con un input importado no hay archivo: lo esperado lo
//! fija el CONSUMIDOR —el hash nombrado, y la cadena y el fork que el
//! calendario de mainnet le asigna al header ([`ExpectedBlock::mainnet`])—, y
//! el oráculo de cada campo es la corrida nativa del mismo input, afuera del
//! zkVM. El input nunca se cree a sí mismo: un header que no hashea al nombre,
//! o una cadena o un fork que no son los del calendario, son un rechazo antes
//! de levantar un backend.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use repo_b_common::primitives::B256;
use repo_b_prover::{ExpectedBlock, Journal, Mode};

use crate::{CASO, esperado_de, leer_journal_esperado};

type Error = Box<dyn std::error::Error>;

/// El bloque de esta corrida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entrada {
    /// `cmd/conformance/fixtures/guest`: el input y su journal congelado.
    Congelada,
    /// Un input del importador y el hash del bloque que el operador nombra.
    Importada { input: PathBuf, hash: B256 },
}

/// Se elige una vez, al leer los argumentos, y la consultan todos los
/// caminos (`run`, `prove`, `multiproof`) sin pasarla de mano en mano.
static ELEGIDA: OnceLock<Entrada> = OnceLock::new();

/// Los dos flags van juntos: un input sin el hash que lo nombra no tiene
/// contra qué verificarse, y un hash sin input no nombra nada que se corra.
pub(crate) fn de_args(input: Option<String>, hash: Option<String>) -> Result<Entrada, String> {
    match (input, hash) {
        (None, None) => Ok(Entrada::Congelada),
        (Some(input), Some(hash)) => Ok(Entrada::Importada {
            input: PathBuf::from(input),
            hash: hash_estricto(&hash)?,
        }),
        _ => Err("--input y --expect-block-hash van juntos".into()),
    }
}

/// `0x` + 64 hex. Sin prefijo opcional ni largo flexible: es el ancla.
fn hash_estricto(texto: &str) -> Result<B256, String> {
    let malo = || format!("--expect-block-hash: `{texto}` no es 0x + 64 hex");
    let hex = texto.strip_prefix("0x").ok_or_else(malo)?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(malo());
    }
    texto.parse::<B256>().map_err(|_| malo())
}

pub(crate) fn elegir(entrada: Entrada) -> Result<(), Error> {
    ELEGIDA
        .set(entrada)
        .map_err(|_| "la entrada se elige una sola vez".into())
}

fn elegida() -> &'static Entrada {
    ELEGIDA.get().unwrap_or(&Entrada::Congelada)
}

/// Una línea que dice qué bloque corre, para el log y la evidencia.
pub(crate) fn describir() -> String {
    match elegida() {
        Entrada::Congelada => format!("entrada|congelada|{CASO}"),
        Entrada::Importada { input, hash } => {
            format!("entrada|importada|{}|{hash}", input.display())
        }
    }
}

/// Los bytes que se le dan al guest.
pub(crate) fn bytes(root: &Path) -> Result<Vec<u8>, Error> {
    Ok(match elegida() {
        Entrada::Congelada => std::fs::read(root.join(CASO).join("block-input.bin"))?,
        Entrada::Importada { input, .. } => std::fs::read(input)?,
    })
}

/// El journal de `Full` que el bloque tiene que publicar: el oráculo.
/// `root_mutado` reemplaza el post-state root (la mutación del contraste).
pub(crate) fn journal(root: &Path, root_mutado: Option<&str>) -> Result<Journal, Error> {
    let journal = match elegida() {
        Entrada::Congelada => {
            return leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), root_mutado);
        }
        Entrada::Importada { .. } => journal_nativo(&bytes(root)?)?,
    };
    Ok(match root_mutado {
        Some(r) => Journal {
            post_state_root: r.parse::<B256>()?,
            ..journal
        },
        None => journal,
    })
}

/// Lo que el consumidor espera del bloque: la entrada de `require_full_block`.
pub(crate) fn esperado(root: &Path) -> Result<ExpectedBlock, Error> {
    match elegida() {
        Entrada::Congelada => {
            let archivo = leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), None)?;
            esperado_de(
                &std::fs::read(root.join(CASO).join("block-input.bin"))?,
                &archivo,
            )
        }
        Entrada::Importada { hash, .. } => Ok(esperado_importado(
            &bytes(root)?,
            *hash,
            ExpectedBlock::mainnet,
        )?),
    }
}

/// [`esperado`] de un input importado, sin IO. `del_consumidor` es el
/// calendario (mainnet en el binario).
fn esperado_importado(
    input: &[u8],
    nombrado: B256,
    del_consumidor: impl Fn(&repo_b_guest::Header) -> Option<ExpectedBlock>,
) -> Result<ExpectedBlock, String> {
    let input = repo_b_guest::codec::decode_block_input(input)
        .map_err(|e| format!("el input importado no decodifica: {e:?}"))?;
    let bloque = repo_b_guest::block::decode_block(&input.block)
        .map_err(|e| format!("el bloque del input importado no decodifica: {e}"))?;
    let calculado = bloque.header.hash();
    if calculado != nombrado {
        return Err(format!(
            "el input es el bloque {calculado} y se nombró {nombrado}"
        ));
    }
    let esperado = del_consumidor(&bloque.header).ok_or_else(|| {
        format!(
            "el calendario del consumidor no le asigna fork al bloque {} (timestamp {})",
            bloque.header.number, bloque.header.timestamp
        )
    })?;
    if (input.chain_id, input.fork) != (esperado.chain_id, esperado.fork) {
        return Err(format!(
            "el input declara cadena {} y fork {:?}; el consumidor espera {} y {:?}",
            input.chain_id, input.fork, esperado.chain_id, esperado.fork
        ));
    }
    Ok(esperado)
}

/// El oráculo de un input importado: el mismo input, corrido nativo.
fn journal_nativo(input: &[u8]) -> Result<Journal, String> {
    let input = repo_b_guest::codec::decode_block_input(input)
        .map_err(|e| format!("el input importado no decodifica: {e:?}"))?;
    repo_b_guest::run_block_input(Mode::Full, &input)
        .map_err(|e| format!("el input importado no ejecuta nativo: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn congelado() -> (Vec<u8>, Journal) {
        let root = crate::repo_root();
        let bytes = match std::fs::read(root.join(CASO).join("block-input.bin")) {
            Ok(b) => b,
            Err(e) => panic!("{e}"),
        };
        match leer_journal_esperado(&root.join(CASO).join("block-journal.txt"), None) {
            Ok(j) => (bytes, j),
            Err(e) => panic!("{e}"),
        }
    }

    /// El consumidor de la red del caso congelado (no es mainnet).
    fn del_caso(j: Journal) -> impl Fn(&repo_b_guest::Header) -> Option<ExpectedBlock> {
        move |h| {
            Some(ExpectedBlock {
                chain_id: j.chain_id,
                fork: j.fork?,
                block_hash: h.hash(),
                parent_hash: Some(h.parent_hash),
            })
        }
    }

    #[test]
    fn the_two_flags_go_together_and_the_hash_is_strict() {
        let h = format!("0x{}", "ab".repeat(32));
        assert_eq!(de_args(None, None), Ok(Entrada::Congelada));
        assert!(de_args(Some("x.bin".into()), None).is_err());
        assert!(de_args(None, Some(h.clone())).is_err());
        assert!(matches!(
            de_args(Some("x.bin".into()), Some(h.clone())),
            Ok(Entrada::Importada { .. })
        ));
        for malo in [&h[2..], &h[..65], "0xzz", &format!("{h}00")] {
            assert!(hash_estricto(malo).is_err(), "{malo}");
        }
    }

    /// El oráculo nativo de un input es el journal que el harness congeló.
    #[test]
    fn the_native_run_is_the_oracle_of_an_imported_input() {
        let (bytes, j) = congelado();
        assert_eq!(journal_nativo(&bytes), Ok(j));
        assert!(journal_nativo(&[]).is_err());
    }

    #[test]
    fn an_imported_input_is_judged_by_the_named_hash_and_the_schedule() {
        let (bytes, j) = congelado();
        let ok = esperado_importado(&bytes, j.block_hash, del_caso(j));
        assert_eq!(ok.map(|e| e.block_hash), Ok(j.block_hash));
        // Otro nombre: rechazo, con los dos hashes.
        let otro = B256::repeat_byte(0x11);
        let e = esperado_importado(&bytes, otro, del_caso(j));
        assert!(
            e.as_ref().is_err_and(|e| e.contains(&otro.to_string())),
            "{e:?}"
        );
        // El caso es de una red de pruebas: mainnet no le asigna fork.
        let e = esperado_importado(&bytes, j.block_hash, ExpectedBlock::mainnet);
        assert!(e.as_ref().is_err_and(|e| e.contains("calendario")), "{e:?}");
        // Un consumidor que espera otra cadena: el input no se cree a sí mismo.
        let otra_cadena = Journal {
            chain_id: j.chain_id.wrapping_add(1),
            ..j
        };
        let e = esperado_importado(&bytes, j.block_hash, del_caso(otra_cadena));
        assert!(
            e.as_ref().is_err_and(|e| e.contains("declara cadena")),
            "{e:?}"
        );
    }
}
