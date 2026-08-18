//! Siembra desde los fixtures que ya existen.
//!
//! La regla: sembrar desde los casos de `fixtures/diff/`, que son entradas de
//! las que ya se sabe que llegan lejos. Son programas escritos a mano para
//! ejercitar una regla de consenso puntual — un generador aleatorio
//! tarda mucho en inventar un `CALL` con el 63/64 justo en el borde, y esos
//! programas ya lo tienen.
//!
//! Lo que se toma es el **código**, no el caso: el escenario alrededor (env,
//! balances, tx) lo pone el generador. Un programa del corpus dentro de un
//! escenario nuevo es exactamente el splicing que hace un fuzzer de bytecode.

use std::collections::BTreeSet;
use std::path::Path;

use crate::fixture::parse_file;
use crate::fuzz::program::Program;

/// Los programas de siembra, deduplicados y en orden **determinista**: el
/// corpus entra al `(seed, índice)` que reproduce un caso, así que un orden
/// que dependa del sistema de archivos rompería la reproducibilidad.
#[derive(Debug, Clone, Default)]
pub struct Corpus {
    pub programs: Vec<Program>,
}

impl Corpus {
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }

    /// Junta el bytecode de todas las cuentas de todos los fixtures bajo
    /// `root` (un nivel de subdirectorios: la forma de `fixtures/diff/`).
    ///
    /// Un archivo ilegible o que no parsea **no aborta la carga**: la siembra
    /// es una optimización del generador, no una regla de consenso, y morir
    /// acá dejaría al fuzzer sin correr por un fixture roto. Se cuenta y se
    /// reporta.
    pub fn load(root: &Path) -> (Self, usize) {
        let mut codes: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut skipped = 0usize;
        for path in json_files(root) {
            let Ok(raw) = std::fs::read_to_string(&path) else {
                skipped = skipped.saturating_add(1);
                continue;
            };
            let Ok(tests) = parse_file(&raw) else {
                skipped = skipped.saturating_add(1);
                continue;
            };
            for test in &tests {
                for account in test.pre.values() {
                    if !account.code.is_empty() {
                        codes.insert(account.code.to_vec());
                    }
                }
            }
        }
        let programs = codes.iter().map(|code| Program::decode(code)).collect();
        (Self { programs }, skipped)
    }
}

/// Los `.json` bajo `root`, incluyendo un nivel de subdirectorios, ordenados.
///
/// `read_dir` no garantiza orden y el orden acá es parte del determinismo del
/// generador — el mismo defecto que `diff::run_dir` ya corrige a mano.
fn json_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return files;
    };
    let mut roots: Vec<std::path::PathBuf> = entries.flatten().map(|e| e.path()).collect();
    roots.sort();
    for path in roots {
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            files.push(path);
            continue;
        }
        if !path.is_dir() {
            continue;
        }
        let Ok(inner) = std::fs::read_dir(&path) else {
            continue;
        };
        let mut nested: Vec<std::path::PathBuf> = inner
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect();
        nested.sort();
        files.extend(nested);
    }
    files
}

/// El directorio de los sets diferenciales, junto al harness.
pub fn default_corpus_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/diff")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La siembra existe de verdad: los sets de `fixtures/diff/` tienen
    /// código y el corpus lo levanta. Si diera cero, la siembra estaría
    /// declarada y no implementada.
    #[test]
    fn the_corpus_loads_programs_from_the_existing_diff_sets() {
        let (corpus, skipped) = Corpus::load(&default_corpus_dir());
        assert_eq!(skipped, 0, "hay fixtures que no parsean");
        assert!(
            corpus.len() > 100,
            "el corpus de siembra quedó en {}",
            corpus.len()
        );
    }

    /// El orden es determinista: dos cargas dan el MISMO corpus. Sin esto,
    /// `(seed, índice)` dejaría de reproducir un caso en cuanto el corpus
    /// entre en la generación.
    #[test]
    fn loading_twice_gives_the_same_corpus_in_the_same_order() {
        let (first, _) = Corpus::load(&default_corpus_dir());
        let (second, _) = Corpus::load(&default_corpus_dir());
        assert_eq!(first.programs, second.programs);
    }

    /// Los programas del corpus se re-emiten idénticos: el decoder entendió
    /// el bytecode escrito a mano, incluidos sus `PUSH` y sus saltos.
    #[test]
    fn corpus_programs_survive_a_decode_round_trip() {
        let (corpus, _) = Corpus::load(&default_corpus_dir());
        for program in &corpus.programs {
            let code = program.assemble();
            assert_eq!(Program::decode(&code).assemble(), code);
        }
    }

    #[test]
    fn a_missing_directory_is_an_empty_corpus_and_not_a_panic() {
        let (corpus, skipped) = Corpus::load(Path::new("/no/existe/este/directorio"));
        assert!(corpus.is_empty());
        assert_eq!(skipped, 0);
    }
}
