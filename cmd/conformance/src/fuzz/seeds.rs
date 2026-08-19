//! El corpus semilla: los `state_test` reales de EEST.
//!
//! La diferencia con `corpus.rs` —el corpus de siembra de la gramática— es de
//! **granularidad y de origen**, y es la razón de que este generador exista:
//!
//! | | `corpus.rs` (siembra) | acá (mutación) |
//! |---|---|---|
//! | qué toma | el **bytecode** de `fixtures/diff/` | el **caso entero** de EEST |
//! | qué conserva | nada del escenario | `pre`, tx, env y fork |
//! | tamaño | ~300 programas escritos por nosotros | **39 025** casos del EF |
//!
//! Un programa spliceado corre en un escenario nuevo; un caso semilla corre en
//! **su** escenario, que es el borde que un humano del EF fue a buscar: el gas
//! justo, el límite del fork, el input degenerado de una precompile. Mutar
//! alrededor de ese punto llega a lugares que una gramática uniforme tarda
//! eones en encontrar — y, sobre todo, llega a **envelopes de tx** (access
//! list, blob, set-code) que la gramática no puede representar.
//!
//! ## El cache no está versionado, y la ausencia se reporta
//!
//! Son 257 MB gitignoreados que baja `scripts/fetch-eest.sh`. Si no están,
//! cargar el corpus **falla ruidoso con el comando para traerlo**. Un corpus
//! vacío no es un corpus chico: es la misma regla fail-closed que aplica
//! `run_dir` — un set vacío NO es verde.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::fixture::{PostCase, StateTest, parse_file, spec_for_fork};
use repo_b_common::primitives::B256;

/// El tag pineado del release de EEST. **Debe coincidir con
/// `scripts/fetch-eest.sh` y con `eest.rs`**: si tres lugares distintos
/// apuntaran a releases distintos, el "39 025" de un eje no hablaría del mismo
/// corpus que el otro.
pub const PINNED_TAG: &str = "v5.4.0";

/// Cuántos ancestros se sintetizan para `BLOCKHASH`. La ventana del protocolo
/// es `[number-256, number-1]`; acotarla acá es lo que impide que un fixture
/// con un `number` grande se convierta en una tabla de 256 hashes.
const BLOCKHASH_WINDOW: u64 = 256;

/// Un caso semilla: un `state_test` de EEST, ya normalizado y listo para
/// mutarse.
///
/// `name` es la **identidad del fixture semilla** y no un adorno: un hallazgo
/// se reproduce con `(semilla, índice)` **más** el nombre del caso del que
/// salió, porque el índice depende del tamaño del corpus y el nombre no.
#[derive(Debug, Clone)]
pub struct SeedCase {
    pub name: String,
    pub test: StateTest,
    pub post: PostCase,
}

/// El corpus, en orden determinista.
#[derive(Debug, Clone, Default)]
pub struct SeedCorpus {
    pub cases: Vec<SeedCase>,
    /// Casos que se leyeron y quedaron fuera por tener un fork fuera de scope.
    pub out_of_scope: usize,
    /// Archivos que no se pudieron leer o parsear. **Se cuentan y se
    /// reportan**: un corpus que perdió la mitad en silencio mediría otra cosa.
    pub unparsed: usize,
}

impl SeedCorpus {
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    /// Carga los `state_test` de EEST desde `root` (el directorio del release,
    /// p. ej. `.eest-cache/v5.4.0`).
    ///
    /// `Err` cuando el cache no está o cuando el corpus quedaría vacío: las dos
    /// son la misma regla. Un generador de mutación sin corpus no genera nada
    /// y reportaría "0 divergencias" con toda tranquilidad, que es el modo vacuo
    /// contra el que fail-closed existe.
    pub fn load(root: &Path) -> Result<Self, String> {
        let dir = root.join("fixtures/state_tests");
        if !dir.is_dir() {
            return Err(format!(
                "no encuentro el corpus semilla en {} — corré `bash scripts/fetch-eest.sh` \
                 primero (son 257 MB gitignoreados, no se vendorean)",
                dir.display()
            ));
        }
        let mut files = Vec::new();
        collect_json(&dir, &mut files).map_err(|e| format!("recorriendo el corpus: {e}"))?;
        // `read_dir` no garantiza orden y el orden ES parte del determinismo:
        // el índice del caso semilla sale de esta lista.
        files.sort();

        let mut corpus = Self::default();
        for path in &files {
            let Ok(raw) = std::fs::read_to_string(path) else {
                corpus.unparsed = corpus.unparsed.saturating_add(1);
                continue;
            };
            let Ok(tests) = parse_file(&raw) else {
                corpus.unparsed = corpus.unparsed.saturating_add(1);
                continue;
            };
            for test in tests {
                for post in &test.posts {
                    if spec_for_fork(&post.fork).is_none() {
                        corpus.out_of_scope = corpus.out_of_scope.saturating_add(1);
                        continue;
                    }
                    corpus.cases.push(normalize_seed(&test, post));
                }
            }
        }
        if corpus.cases.is_empty() {
            return Err(format!(
                "el corpus semilla quedó VACÍO tras leer {} archivos de {} \
                 (fail-closed: un corpus vacío no es un corpus chico)",
                files.len(),
                dir.display()
            ));
        }
        Ok(corpus)
    }
}

/// Un caso de EEST → un caso semilla listo para el diferencial.
///
/// Tres normalizaciones, y ninguna es cosmética:
///
/// 1. **Se descarta `expected_state`.** El juez del diferencial es revm
///    in-process, no el fixture (`fixtures/diff/README.md`). Medido: retenerlo
///    cuesta 1 123 MB contra 722 MB de pico para el mismo corpus.
/// 2. **Se sintetiza la ventana de `BLOCKHASH`.** Ningún `state_test` de EEST
///    declara ancestros (medido: 0 de 44 039) porque `blockHashes` es extensión
///    propia de `fixtures/diff/`. Sin ellos, `MemoryState` es fail-closed ante
///    un ancestro no declarado (y hace bien) mientras el `CacheDB` de revm
///    devuelve cero: **los dos motores recibirían información distinta** y una
///    mutación que introduzca `BLOCKHASH` produciría una divergencia del
///    harness, no del consenso. La primera campaña del generador por gramática
///    midió **587 falsos positivos** por exactamente esta asimetría.
/// 3. **`excess_blob_gas` se rellena con 0 si falta.** La mutación de fork
///    puede mover un caso de Paris a Cancun, donde el campo sí se lee; sin
///    esto, el caso mutado cambiaría dos cosas a la vez.
pub fn normalize_seed(test: &StateTest, post: &PostCase) -> SeedCase {
    let mut test = test.clone();
    test.env.block_hashes = ancestors(test.env.number);
    if test.env.excess_blob_gas.is_none() {
        test.env.excess_blob_gas = Some(0);
    }
    let mut post = post.clone();
    post.expected_state = None;
    // El caso semilla se queda con SU post y nada más: mutar el fork es un
    // operador, no un efecto colateral de arrastrar los otros posts.
    let name = format!("{} [{}]", test.name, post.fork);
    test.posts = vec![post.clone()];
    SeedCase { name, test, post }
}

/// El hash del ancestro `number`, determinista y distinto por bloque — dos
/// ancestros con el mismo hash harían indistinguible un `BLOCKHASH` que lee el
/// bloque equivocado. **Misma forma que la de `fuzz::generate`**, a propósito:
/// un fixture emitido por cualquiera de los dos generadores se lee igual.
pub fn ancestor_hash(number: u64) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xB1;
    bytes[24..].copy_from_slice(&number.to_be_bytes());
    B256::new(bytes)
}

/// La ventana completa `[number-256, number-1]`, acotada.
fn ancestors(number: u64) -> BTreeMap<u64, B256> {
    let low = number.saturating_sub(BLOCKHASH_WINDOW);
    (low..number).map(|n| (n, ancestor_hash(n))).collect()
}

fn collect_json(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_json(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    Ok(())
}

/// El directorio del release pineado. `EEST_CACHE_DIR` lo redirige, igual que
/// en `eest.rs`.
pub fn default_seed_root() -> PathBuf {
    std::env::var("EEST_CACHE_DIR")
        .map_or_else(
            |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.eest-cache"),
            PathBuf::from,
        )
        .join(PINNED_TAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La regla del §4.3, y la que M5 mide: **sin cache no se corre en vacío**.
    /// El mensaje trae el comando, porque un fail-closed que no dice cómo
    /// arreglarlo se rodea con `--force` a los diez minutos.
    #[test]
    fn a_missing_cache_is_a_loud_error_and_never_an_empty_corpus() {
        let error = match SeedCorpus::load(Path::new("/no/existe/este/release")) {
            Ok(corpus) => panic!(
                "cargó {} casos de un directorio que no existe",
                corpus.len()
            ),
            Err(error) => error,
        };
        assert!(
            error.contains("scripts/fetch-eest.sh"),
            "el error no dice cómo traer el cache: {error}"
        );
    }

    /// Un directorio de `state_tests` que existe pero está vacío tampoco es
    /// verde. Es la otra mitad de la misma regla que aplica `run_dir`.
    #[test]
    fn an_empty_state_tests_directory_is_also_an_error() {
        let base = std::env::temp_dir().join("repo-b-fuzz-seeds-empty");
        let dir = base.join("fixtures/state_tests");
        let Ok(()) = std::fs::create_dir_all(&dir) else {
            panic!("no se pudo preparar el directorio de prueba");
        };
        let result = SeedCorpus::load(&base);
        let _ = std::fs::remove_dir_all(&base);
        match result {
            Ok(corpus) => panic!("un directorio vacío cargó {} casos", corpus.len()),
            Err(error) => assert!(error.contains("VACÍO"), "{error}"),
        }
    }

    /// La ventana de `BLOCKHASH` que la normalización sintetiza es exactamente
    /// la del protocolo, y para el `number = 1` que traen los 44 039 casos de
    /// EEST es **un solo ancestro**.
    #[test]
    fn the_synthesised_blockhash_window_matches_the_protocol() {
        assert_eq!(ancestors(0).len(), 0);
        assert_eq!(ancestors(1).len(), 1);
        assert!(ancestors(1).contains_key(&0));
        assert_eq!(ancestors(300).len(), 256);
        assert!(ancestors(300).contains_key(&299));
        assert!(ancestors(300).contains_key(&44));
        assert!(!ancestors(300).contains_key(&43));
    }

    /// Dos ancestros distintos no comparten hash: si lo compartieran, un
    /// `BLOCKHASH` que lee el bloque equivocado sería indistinguible de uno
    /// correcto y la mutación que lo rompiera saldría muda.
    #[test]
    fn distinct_ancestors_get_distinct_hashes() {
        assert_ne!(ancestor_hash(0), ancestor_hash(1));
        assert_ne!(ancestor_hash(255), ancestor_hash(256));
    }
}
