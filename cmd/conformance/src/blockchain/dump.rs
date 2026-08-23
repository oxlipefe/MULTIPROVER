//! Congela **un** bloque real del corpus como caso de zkVM.
//!
//! # Por qué existe
//!
//! Ejecutar el guest adentro de un backend cuesta una compilación de decenas de
//! minutos y una imagen de Docker de varios GB. Volver a moler los 42 017
//! bloques de EEST cada vez que se quiere correr ese camino sería absurdo — y
//! además el corpus de EEST no está vendoreado (son 257 MB con cache aparte),
//! así que un caso congelado es lo único que hace **reproducible** la corrida
//! del zkVM en un clon limpio.
//!
//! # Qué se congela, y qué NO
//!
//! Se congela el **input** (los bytes que entran al guest) y el **journal
//! esperado** (lo que el guest tiene que publicar). El journal esperado lo
//! computa el driver **con el estado completo**, que es exactamente lo que el
//! guest no tiene: si saliera del mismo camino que el guest recorre, compararlo
//! sería compararlo consigo mismo — el `[SAME]` que no prueba nada.
//!
//! # Cómo se repuebla
//!
//! ```sh
//! REPO_B_GUEST_DUMP_DIR=cmd/conformance/fixtures/guest \
//!   cargo run --release -p conformance -- --witness-blocks
//! ```
//!
//! Se queda con el **primer** bloque de Prague que tenga transacciones y system
//! calls de cierre — o sea el lifecycle completo, no un bloque vacío que
//! pasaría por vacuidad.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use repo_b_common::primitives::B256;
use repo_b_guest::journal::{Journal, Mode};

/// A dónde escribir, si es que hay que escribir. `None` = el modo está apagado,
/// que es el default de toda corrida del gate.
fn dump_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| std::env::var_os("REPO_B_GUEST_DUMP_DIR").map(PathBuf::from))
        .as_ref()
}

static YA: AtomicBool = AtomicBool::new(false);

/// El nombre del caso congelado. Un solo par de archivos: el camino del zkVM se
/// corre sobre UN bloque, no sobre un set.
pub const CASE_INPUT: &str = "block-input.bin";
pub const CASE_JOURNAL: &str = "block-journal.txt";

/// Escribe el caso si el modo está prendido y este bloque es el primero que
/// califica. No devuelve error: es instrumentación, no un veredicto.
pub fn offer(bytes: &[u8], journal: &Journal, identidad: &str) {
    let Some(dir) = dump_dir() else { return };
    // `swap` y no `load`+`store`: el driver es paralelo y dos bloques podrían
    // pasar el chequeo a la vez, dejando el par de archivos cruzado.
    if YA.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("[dump] no se pudo crear {}: {e}", dir.display());
        return;
    }
    let _ = std::fs::write(dir.join(CASE_INPUT), bytes);
    let _ = std::fs::write(
        dir.join(CASE_JOURNAL),
        format!(
            "# El bloque real que el guest ejecuta adentro del zkVM.\n\
             # Lo escribió `--witness-blocks` con REPO_B_GUEST_DUMP_DIR; el journal\n\
             # esperado lo computó el driver CON EL ESTADO COMPLETO, no por el\n\
             # camino del witness que el guest recorre.\n\
             case {identidad}\n\
             input_bytes {}\n\
             pre_state_root {}\n\
             post_state_root {}\n\
             output_digest {}\n",
            bytes.len(),
            journal.pre_state_root,
            journal.post_state_root,
            journal.output_digest,
        ),
    );
    eprintln!(
        "[dump] caso congelado en {} — {} ({} bytes de input)",
        dir.display(),
        identidad,
        bytes.len()
    );
}

/// ¿Vale la pena congelar este bloque? Ver el doc del módulo: un bloque sin
/// transacciones ni system calls de cierre pasaría por vacuidad.
#[must_use]
pub fn califica(txs: usize, closing: usize, opening: usize) -> bool {
    dump_dir().is_some() && txs > 0 && closing > 0 && opening > 0
}

/// El journal que el guest tiene que publicar para este bloque.
#[must_use]
pub fn journal_esperado(
    pre_state_root: B256,
    post_state_root: B256,
    output_digest: B256,
) -> Journal {
    Journal {
        mode: Mode::Full,
        pre_state_root,
        post_state_root,
        output_digest,
    }
}

#[cfg(test)]
mod tests {
    use repo_b_common::primitives::{B256, U256};
    use repo_b_guest::signature::{Signature, SignedTransaction};

    /// El caso congelado, tal cual lo consume `cmd/zkvm`.
    fn caso() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/guest")
            .join(super::CASE_INPUT);
        match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => panic!("no se pudo leer el caso congelado {}: {e}", path.display()),
        }
    }

    /// Re-firma la tx del bloque con una clave que NO es la del sender.
    ///
    /// El envelope queda **bien formado**: la firma es válida, recupera un punto
    /// de la curva y produce una dirección. Lo que cambia es **quién** — que es
    /// exactamente lo que un prover trataría de elegir.
    fn refirmar(input: &repo_b_guest::codec::OwnedInput) -> repo_b_guest::codec::OwnedInput {
        use k256::ecdsa::SigningKey;

        let Some(original) = input.txs.first() else {
            panic!("el caso congelado tiene que tener al menos una tx");
        };
        let Ok(key) = SigningKey::from_slice(B256::repeat_byte(0x11).as_slice()) else {
            panic!("la clave del atacante tiene que ser válida");
        };
        let tipada = original.chain_id().is_some();
        let relleno = Signature {
            v: if tipada {
                U256::ZERO
            } else {
                U256::from(input.env.chain_id) * U256::from(2u8) + U256::from(35u8)
            },
            r: U256::from(1u8),
            s: U256::from(1u8),
        };
        let armar = |sig: Signature| {
            SignedTransaction::new(
                original.payload().clone(),
                original.chain_id(),
                sig,
                original.authorization_signatures().to_vec(),
            )
        };
        let Ok(hash) = armar(relleno).signing_hash(input.env.chain_id) else {
            panic!("el envelope del caso congelado tiene que ser representable");
        };
        let Ok((firma, recid)) = key.sign_prehash_recoverable(hash.as_slice()) else {
            panic!("firmar no puede fallar");
        };
        let paridad = u64::from(recid.to_byte() & 1);
        let v = if tipada {
            U256::from(paridad)
        } else {
            U256::from(input.env.chain_id) * U256::from(2u8) + U256::from(35u8 + paridad as u8)
        };
        let mut mutado = input.clone();
        mutado.txs = vec![armar(Signature {
            v,
            r: U256::from_be_slice(&firma.r().to_bytes()),
            s: U256::from_be_slice(&firma.s().to_bytes()),
        })];
        mutado
    }

    /// **M2 — un sender falsificado NO puede pasar.**
    ///
    /// Es la mitad negativa del slice y la que de verdad lo prueba: M1 —confiar
    /// en el sender del input— sale en cero contra el corpus, porque un corpus
    /// honesto no contiene senders mentirosos (describe clientes correctos).
    ///
    /// La falsificación se hace por el ÚNICO canal que queda: el envelope se
    /// re-firma con otra clave. No hay campo `sender` que tocar — que es el
    /// punto—, así que el atacante tiene que cambiar la firma, y entonces el
    /// bloque que ejecuta ya no es este.
    #[test]
    fn a_forged_sender_cannot_produce_the_block() {
        let bytes = caso();
        let Ok(bueno) = repo_b_guest::codec::decode(&bytes) else {
            panic!("el caso congelado tiene que decodificar");
        };
        let Ok(esperado) = repo_b_guest::run_block(&bueno.as_input()) else {
            panic!("el caso congelado tiene que ejecutar");
        };

        let mutado = refirmar(&bueno);
        // El envelope sigue siendo válido y el input sigue decodificando: lo
        // único que cambió es quién firmó.
        let Ok(recodificado) = repo_b_guest::codec::encode(&mutado) else {
            panic!("el input mutado tiene que encodear");
        };
        let Ok(vuelto) = repo_b_guest::codec::decode(&recodificado) else {
            panic!("el input mutado tiene que decodificar: la firma es válida");
        };
        match repo_b_guest::run_block(&vuelto.as_input()) {
            Err(_) => {} // el motor rechaza la tx del impostor: es lo esperado
            Ok(otro) => assert_ne!(
                repo_b_guest::digest_of(&otro),
                repo_b_guest::digest_of(&esperado),
                "un sender falsificado produjo EL MISMO bloque: el guest no está \
                 derivando el sender de la firma"
            ),
        }
    }

    /// La recíproca, y sin ella lo de arriba no prueba nada: el caso **sin
    /// mutar** sí ejecuta y da el journal congelado.
    #[test]
    fn the_frozen_case_still_executes_to_its_journal() {
        let bytes = caso();
        let Ok(input) = repo_b_guest::codec::decode(&bytes) else {
            panic!("el caso congelado tiene que decodificar");
        };
        let Ok(salida) = repo_b_guest::run_block(&input.as_input()) else {
            panic!("el caso congelado tiene que ejecutar");
        };
        let texto = match std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/guest")
                .join(super::CASE_JOURNAL),
        ) {
            Ok(t) => t,
            Err(e) => panic!("no se pudo leer el journal congelado: {e}"),
        };
        let Some(linea) = texto.lines().find_map(|l| l.strip_prefix("output_digest ")) else {
            panic!("el journal congelado tiene que declarar el output_digest");
        };
        let Ok(esperado) = linea.trim().parse::<B256>() else {
            panic!("el output_digest congelado tiene que ser un hash");
        };
        assert_eq!(repo_b_guest::digest_of(&salida), esperado);
    }
}
