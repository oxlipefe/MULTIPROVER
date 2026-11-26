//! Lo que el guest **publica**, y el techo que eso tiene.
//!
//! # Por qué el formato es fijo y chico
//!
//! El output público de un guest no es libre: **OpenVM y ZisK lo limitan a 256
//! bytes** (rellenados con ceros), y SP1 no lo limita porque lo hashea
//! internamente. O sea que el mínimo común denominador de los tres backends son
//! 256 bytes crudos, y esa es la restricción que manda. La decisión se toma
//! **una sola vez y acá** —no en el crate de un backend— porque un formato que
//! entra en SP1 y no en OpenVM haría que el multiproof dependa de con cuál se
//! empezó.
//!
//! # Qué se publica, y por qué exactamente eso
//!
//! La afirmación es *"el bloque `block_hash` es válido sobre su padre
//! `parent_hash` en la cadena `chain_id` bajo las reglas de `fork`, y lleva el
//! estado de `pre_state_root` a `post_state_root`"*. Cada campo está porque sin
//! él la afirmación es sobre otra cosa:
//!
//! - **`block_hash`** nombra el bloque. Es `keccak(rlp(header))` del header que
//!   el guest decodificó y validó, y el header compromete todo lo demás: txs,
//!   withdrawals, receipts, bloom, requests, gas y el `stateRoot`.
//! - **`parent_hash`** ancla el bloque en una cadena: es el hash del padre que
//!   el guest recibió en el witness y contra el que validó el header.
//! - **`chain_id`** y **`fork`** son reglas que el header no compromete: el
//!   mismo header es válido o no según el fork (los campos de cada fork, los
//!   parámetros de blob), y las firmas dependen de la cadena. El guest no ve el
//!   reloj de activación de cada fork; quien consume la prueba contrasta el
//!   `fork` contra el `timestamp` del bloque.
//! - **`pre_state_root`** y **`post_state_root`** son el `stateRoot` del padre
//!   y el del bloque. Están implicados por los dos hashes, y se publican igual
//!   para que un consumidor que solo sigue el estado no tenga que abrir headers.
//! - **`output_digest`** es el digest de lo que la ejecución produjo (el diff
//!   y los outputs de las system calls de cierre). En `Full` está implicado por
//!   `block_hash` —el header compromete el estado y los requests, y el guest los
//!   validó—, y se conserva por dos razones: es el **único** campo con
//!   contenido en los peldaños ablacionados que ejecutan sin validar
//!   (`NoRoot`, `NoTxs`), y es un contraste contra el oráculo del host que no
//!   pasa por el trie: el host lo computa del diff que produjo con el estado
//!   completo.
//!
//! # El layout (171 bytes, versionado)
//!
//! ```text
//! version u8 · mode u8 · chain_id u64 BE · fork u8 · block_hash ·
//! parent_hash · pre_state_root · post_state_root · output_digest
//! ```
//!
//! **Qué va en cero según el modo** (`fork` en cero es "ninguno": los ids de
//! fork empiezan en 1):
//!
//! | modo | chain_id · fork · pre | block_hash · parent_hash | post | digest |
//! |---|---|---|---|---|
//! | `Full` | sí | sí | sí | sí |
//! | `NoRoot`, `NoTxs` | sí | cero | cero | sí |
//! | `StateOnly`, `Recover`, `DecodeOnly` | sí | cero | cero | cero |
//! | `Nop` | cero | cero | cero | cero |
//! | `StateTest` | sí (`pre` declarado, sin ancla) | cero | sí | sí |
//! | `Kat` | cero; `pre` lleva la etiqueta del programa | cero | digest de la aritmética | bitmask de fallas |
//!
//! **Solo `Full` publica `block_hash` y `parent_hash`.** Los peldaños
//! ablacionados validan el bloque igual, pero son los dos campos que nombran
//! de qué bloque es la prueba, y un peldaño que no ejecutó el bloque entero no
//! puede coincidir con `Full` justo en lo que el consumidor compara.
//!
//! # Lo que el journal NO resuelve solo: la política de verificación
//!
//! El journal es lo que la prueba afirma; **aceptarlo es una decisión del
//! consumidor**, y es una sola (`repo_b_prover::require_full_block`): versión
//! 2, modo `Full`, `chain_id` y `fork` iguales a los del chainspec del
//! consumidor, `block_hash` y `parent_hash` distintos de cero e iguales a los
//! esperados, y los dos roots y el `output_digest` distintos de cero. Dos cosas
//! solo se cierran ahí:
//!
//! - **Prague y Osaka tienen el mismo header** (los mismos campos), así que el
//!   header no compromete cuál de los dos es el fork: la misma prueba de bytes
//!   puede salir bajo cualquiera de los dos, con otro `fork` en el journal. La
//!   ambigüedad la resuelve el consumidor contrastando el `fork` publicado
//!   contra el que su chainspec asigna al `timestamp` del bloque.
//! - **El header no compromete el `chain_id`.** Solo las firmas lo usan, y una
//!   tx legacy sin EIP-155 no lo nombra. El consumidor lo contrasta contra el
//!   de su cadena.
//!
//! **`Mode::StateTest` no tiene ancla**: su `pre_state_root` es el que el
//! input declara y no nombra ningún bloque. Un verificador de bloques lo
//! rechaza por el modo, antes de mirar ningún campo.
//!
//! # El `mode` viaja adentro del output, y no es decoración
//!
//! El guest acepta **modos ablacionados** para poder medir el costo por
//! diferencia (el backend desglosa por SUS tablas, no por nuestras piezas, así
//! que el desglose hay que producirlo restando corridas). Un guest que se puede
//! *pedir* que saltee la ejecución de las txs es un guest al que se le puede
//! pedir que mienta — a menos que **lo que salteó viaje en la afirmación**. Por
//! eso el modo viaja en el journal: un verificador que solo acepta `Mode::Full`
//! no puede ser engañado por una prueba de un modo ablacionado, y la ablación
//! deja de ser un agujero para pasar a ser un dato público.

use repo_b_common::primitives::B256;
use repo_b_common::spec::Spec;

/// El techo de output que los tres backends comparten. Ver el doc del módulo.
pub const MAX_PUBLIC_OUTPUT_BYTES: usize = 256;

/// La versión del formato. Un consumidor que lee otra versión no sabe qué
/// afirma la prueba, así que la rechaza.
pub const JOURNAL_VERSION: u8 = 2;

const HASH_BYTES: usize = 32;
const CHAIN_ID_BYTES: usize = 8;
const VERSION_AT: usize = 0;
const MODE_AT: usize = 1;
const CHAIN_ID_AT: usize = 2;
const FORK_AT: usize = CHAIN_ID_AT + CHAIN_ID_BYTES;
const BLOCK_HASH_AT: usize = FORK_AT + 1;
const PARENT_HASH_AT: usize = BLOCK_HASH_AT + HASH_BYTES;
const PRE_STATE_ROOT_AT: usize = PARENT_HASH_AT + HASH_BYTES;
pub const POST_STATE_ROOT_AT: usize = PRE_STATE_ROOT_AT + HASH_BYTES;
const OUTPUT_DIGEST_AT: usize = POST_STATE_ROOT_AT + HASH_BYTES;

/// El largo exacto del journal: `version` + `mode` + `chain_id` + `fork` +
/// cinco hashes.
pub const JOURNAL_BYTES: usize = OUTPUT_DIGEST_AT + HASH_BYTES;

// El techo no es un comentario: si el journal creciera por encima de lo que el
// backend más restrictivo acepta, esto no compila.
const _: () = assert!(JOURNAL_BYTES == 171);
const _: () = assert!(JOURNAL_BYTES <= MAX_PUBLIC_OUTPUT_BYTES);

/// El id de "ningún fork" en el journal: los modos que no ejecutan un bloque.
pub const NO_FORK: u8 = 0;

/// El id de un fork, en el input y en el journal. **Explícito y no `as`**: si
/// mañana entra un fork nuevo, esto no compila hasta que alguien decida su
/// número. Empiezan en 1 para que el cero sea "ninguno".
#[must_use]
pub const fn fork_id(spec: Spec) -> u8 {
    match spec {
        Spec::Paris => 1,
        Spec::Shanghai => 2,
        Spec::Cancun => 3,
        Spec::Prague => 4,
        Spec::Osaka => 5,
        Spec::Bpo1 => 6,
        Spec::Bpo2 => 7,
    }
}

/// La inversa de [`fork_id`]. **Fail-closed**: un id desconocido, y el cero,
/// no son un fork.
#[must_use]
pub const fn fork_from_id(id: u8) -> Option<Spec> {
    match id {
        1 => Some(Spec::Paris),
        2 => Some(Spec::Shanghai),
        3 => Some(Spec::Cancun),
        4 => Some(Spec::Prague),
        5 => Some(Spec::Osaka),
        6 => Some(Spec::Bpo1),
        7 => Some(Spec::Bpo2),
        _ => None,
    }
}

/// Qué corrió el guest. **Solo `Full` ejecuta y valida el bloque entero.**
///
/// Los peldaños de la escalera existen para medir por diferencia: cada uno
/// saca una pieza, y la resta del costo estimado entre dos modos consecutivos
/// da lo que esa pieza cuesta. Es mutation testing aplicado al costo, y es la
/// única vía portable a los tres backends — parsear el stdout de un backend
/// mide uno solo.
///
/// **La resta solo vale dentro de un mismo backend.** Cada uno estima en su
/// propia unidad, así que restar dos peldaños cancela la unidad y comparar dos
/// backends no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// El camino real: decodificar, validar el bloque contra su padre,
    /// verificar el witness, ejecutar el bloque completo, recomputar el
    /// post-state root y validar todo lo ejecutado contra el header.
    Full = 0,
    /// Todo menos la recomputación del root **y las validaciones posteriores a
    /// la ejecución**: sin el root no hay `stateRoot` que contrastar, y
    /// contrastar el resto sin él dejaría la pieza a medias.
    NoRoot = 1,
    /// El lifecycle del bloque **sin las txs** (system calls, withdrawals).
    NoTxs = 2,
    /// Solo construir el `WitnessState`: indexar los nodos por su hash y
    /// verificar la cadena de headers. **Incluye la recuperación** — la
    /// escalera es de prefijos y sacar una pieza de en medio daría restas sin
    /// sentido.
    StateOnly = 3,
    /// Decodificar y validar **y derivar los remitentes de sus firmas**. El
    /// peldaño existe para aislar la criptografía de firma, que es el camino
    /// que el roadmap estima dominante.
    Recover = 6,
    /// Decodificar el input **y validar el bloque antes de ejecutarlo**: el
    /// header contra el padre y el cuerpo contra el header. Lo segundo va en
    /// este peldaño y no en uno propio porque es casi todo hashing del mismo
    /// input que se acaba de decodificar.
    DecodeOnly = 4,
    /// La línea de base: leer el input y publicar. Todo lo de arriba se mide
    /// **contra esto**, porque leer el buffer y escribir el output tampoco es
    /// gratis y atribuirle ese costo al decoder sería mentir.
    Nop = 5,
    /// **La aritmética de consenso con respuesta conocida** (`kat`). No ejecuta
    /// ningún bloque: corre una batería de vectores y publica su digest.
    ///
    /// No es un peldaño de la escalera y **no va en `LADDER`**: la escalera es
    /// de prefijos del camino real, y esto no es un prefijo de nada. Vive acá
    /// porque tiene que compilarse adentro del MISMO ELF que prueba bloques —
    /// un KAT en otro binario probaría ese otro binario.
    Kat = 7,
    /// **Txs sueltas sobre un pre-state declarado, sin bloque.** Es el formato
    /// de un `state_test` de la EF: un `env` y una tx, sin header ni padre. Lo
    /// usa el corte de criptografía que corre adentro del zkVM contra la corrida
    /// nativa.
    ///
    /// **No afirma nada sobre un bloque**: `block_hash` y `parent_hash` van en
    /// cero y el `pre_state_root` es el que el input declara, sin ancla. Un
    /// verificador que solo acepta `Full` no lo confunde con una prueba de
    /// bloque; por eso es un modo y no un formato alternativo de `Full`. Tampoco
    /// va en `LADDER`.
    StateTest = 8,
}

impl Mode {
    /// **Fail-closed**: un byte que no es un modo conocido no se redondea al
    /// más cercano ni cae en `Full` por default.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Full,
            1 => Self::NoRoot,
            2 => Self::NoTxs,
            3 => Self::StateOnly,
            4 => Self::DecodeOnly,
            5 => Self::Nop,
            6 => Self::Recover,
            7 => Self::Kat,
            8 => Self::StateTest,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// ¿Este modo ejecuta las transacciones del bloque?
    #[must_use]
    pub const fn runs_txs(self) -> bool {
        matches!(self, Self::Full | Self::NoRoot | Self::StateTest)
    }
}

/// Lo que el guest afirma. Ver el doc del módulo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Journal {
    pub mode: Mode,
    /// Cero cuando el modo no ejecuta un bloque ni una tx.
    pub chain_id: u64,
    /// `None` cuando el modo no ejecuta un bloque ni una tx.
    pub fork: Option<Spec>,
    /// `keccak(rlp(header))` del bloque validado. `ZERO` en todo modo que no
    /// sea `Full`.
    pub block_hash: B256,
    /// El hash del padre contra el que se validó el header. `ZERO` en todo
    /// modo que no sea `Full`.
    pub parent_hash: B256,
    pub pre_state_root: B256,
    /// **`ZERO` cuando el modo no lo computó**, que es distinguible porque el
    /// modo viaja al lado.
    pub post_state_root: B256,
    /// Digest de lo que el bloque produjo. `ZERO` si el modo no ejecutó.
    pub output_digest: B256,
}

/// Copia `src` en `out[at..at + src.len()]`. Los rangos son constantes del
/// layout y caben por la aserción de compilación de arriba; un rango que no
/// cupiera se ignora en vez de entrar en pánico, y el round-trip lo delata.
fn put(out: &mut [u8; JOURNAL_BYTES], at: usize, src: &[u8]) {
    if let Some(dst) = at
        .checked_add(src.len())
        .and_then(|end| out.get_mut(at..end))
    {
        dst.copy_from_slice(src);
    }
}

fn hash_at(bytes: &[u8], at: usize) -> Option<B256> {
    let end = at.checked_add(HASH_BYTES)?;
    bytes.get(at..end).map(B256::from_slice)
}

impl Journal {
    /// El journal de un modo que no produjo nada: solo deja constancia de cuál
    /// fue.
    #[must_use]
    pub const fn empty(mode: Mode) -> Self {
        Self {
            mode,
            chain_id: 0,
            fork: None,
            block_hash: B256::ZERO,
            parent_hash: B256::ZERO,
            pre_state_root: B256::ZERO,
            post_state_root: B256::ZERO,
            output_digest: B256::ZERO,
        }
    }

    #[must_use]
    pub fn encode(&self) -> [u8; JOURNAL_BYTES] {
        let mut out = [0u8; JOURNAL_BYTES];
        put(&mut out, VERSION_AT, &[JOURNAL_VERSION]);
        put(&mut out, MODE_AT, &[self.mode.as_byte()]);
        put(&mut out, CHAIN_ID_AT, &self.chain_id.to_be_bytes());
        put(&mut out, FORK_AT, &[self.fork.map_or(NO_FORK, fork_id)]);
        put(&mut out, BLOCK_HASH_AT, self.block_hash.as_slice());
        put(&mut out, PARENT_HASH_AT, self.parent_hash.as_slice());
        put(&mut out, PRE_STATE_ROOT_AT, self.pre_state_root.as_slice());
        put(
            &mut out,
            POST_STATE_ROOT_AT,
            self.post_state_root.as_slice(),
        );
        put(&mut out, OUTPUT_DIGEST_AT, self.output_digest.as_slice());
        out
    }

    /// Los campos que afirman algo, como texto y **en el orden del layout**
    /// (sin la versión, que es constante, ni el modo, que se contrasta aparte).
    /// Es lo que imprimen los reportes y lo que la receta lee: una sola lista
    /// para que un campo nuevo no quede fuera de un contraste y dentro de otro.
    /// El fork va como su id decimal.
    #[must_use]
    pub fn fields(&self) -> [(&'static str, alloc::string::String); 7] {
        use alloc::string::ToString;
        [
            ("chain_id", self.chain_id.to_string()),
            ("fork", self.fork.map_or(NO_FORK, fork_id).to_string()),
            ("block_hash", alloc::format!("{}", self.block_hash)),
            ("parent_hash", alloc::format!("{}", self.parent_hash)),
            ("pre_state_root", alloc::format!("{}", self.pre_state_root)),
            (
                "post_state_root",
                alloc::format!("{}", self.post_state_root),
            ),
            ("output_digest", alloc::format!("{}", self.output_digest)),
        ]
    }

    /// Decodifica lo que un backend devolvió como public values.
    ///
    /// **El largo se exige exacto.** OpenVM rellena con ceros hasta 256, así
    /// que un decoder que aceptara "al menos 171" leería relleno como si fuera
    /// dato el día que el backend cambie; se acepta el largo exacto o el
    /// rellenado, y nada en el medio. **La versión también**: un journal de
    /// otra versión afirma otra cosa con los mismos bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != JOURNAL_BYTES && bytes.len() != MAX_PUBLIC_OUTPUT_BYTES {
            return None;
        }
        if bytes.get(JOURNAL_BYTES..)?.iter().any(|b| *b != 0) {
            // Relleno que no es relleno: hay algo más ahí y no sabemos qué.
            return None;
        }
        if *bytes.get(VERSION_AT)? != JOURNAL_VERSION {
            return None;
        }
        let chain_end = CHAIN_ID_AT.checked_add(CHAIN_ID_BYTES)?;
        let chain_id: [u8; CHAIN_ID_BYTES] = bytes.get(CHAIN_ID_AT..chain_end)?.try_into().ok()?;
        let fork = match *bytes.get(FORK_AT)? {
            NO_FORK => None,
            id => Some(fork_from_id(id)?),
        };
        Some(Self {
            mode: Mode::from_byte(*bytes.get(MODE_AT)?)?,
            chain_id: u64::from_be_bytes(chain_id),
            fork,
            block_hash: hash_at(bytes, BLOCK_HASH_AT)?,
            parent_hash: hash_at(bytes, PARENT_HASH_AT)?,
            pre_state_root: hash_at(bytes, PRE_STATE_ROOT_AT)?,
            post_state_root: hash_at(bytes, POST_STATE_ROOT_AT)?,
            output_digest: hash_at(bytes, OUTPUT_DIGEST_AT)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        JOURNAL_BYTES, JOURNAL_VERSION, Journal, MAX_PUBLIC_OUTPUT_BYTES, Mode, fork_from_id,
        fork_id,
    };
    use repo_b_common::primitives::B256;
    use repo_b_common::spec::Spec;

    fn sample() -> Journal {
        Journal {
            mode: Mode::Full,
            chain_id: 0x0102_0304_0506_0708,
            fork: Some(Spec::Prague),
            block_hash: B256::repeat_byte(0x44),
            parent_hash: B256::repeat_byte(0x55),
            pre_state_root: B256::repeat_byte(0x11),
            post_state_root: B256::repeat_byte(0x22),
            output_digest: B256::repeat_byte(0x33),
        }
    }

    #[test]
    fn the_journal_survives_a_round_trip() {
        let j = sample();
        assert_eq!(Journal::decode(&j.encode()), Some(j));
        let vacio = Journal::empty(Mode::Nop);
        assert_eq!(Journal::decode(&vacio.encode()), Some(vacio));
    }

    /// El layout, byte por byte: es lo que lee la receta y lo que cruzan los
    /// backends, así que un campo corrido de lugar no puede pasar por un
    /// round-trip que lo lea igual de corrido.
    #[test]
    fn the_layout_is_the_documented_one() {
        let bytes = sample().encode();
        assert_eq!(bytes.first(), Some(&JOURNAL_VERSION));
        assert_eq!(bytes.get(1), Some(&Mode::Full.as_byte()));
        assert_eq!(bytes.get(2..10), Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..]));
        assert_eq!(bytes.get(10), Some(&fork_id(Spec::Prague)));
        for (at, byte) in [(11, 0x44), (43, 0x55), (75, 0x11), (107, 0x22), (139, 0x33)] {
            assert_eq!(bytes.get(at..at + 32), Some(&[byte; 32][..]), "offset {at}");
        }
    }

    /// El techo de los tres backends, afirmado con un número y no con prosa.
    #[test]
    fn the_journal_fits_under_the_ceiling_of_every_backend() {
        assert_eq!(JOURNAL_BYTES, 171);
        assert_eq!(sample().encode().len(), JOURNAL_BYTES);
        assert_eq!(MAX_PUBLIC_OUTPUT_BYTES - JOURNAL_BYTES, 85);
    }

    /// Un backend que rellena con ceros hasta 256 se decodifica igual.
    #[test]
    fn zero_padding_up_to_the_ceiling_is_accepted() {
        let mut padded = [0u8; MAX_PUBLIC_OUTPUT_BYTES];
        padded[..JOURNAL_BYTES].copy_from_slice(&sample().encode());
        assert_eq!(Journal::decode(&padded), Some(sample()));
    }

    /// **Relleno que no es relleno se rechaza**: si hay bytes después del
    /// journal, no sabemos qué son y aceptarlos sería leer basura como dato.
    #[test]
    fn padding_that_is_not_padding_is_refused() {
        let mut padded = [0u8; MAX_PUBLIC_OUTPUT_BYTES];
        padded[..JOURNAL_BYTES].copy_from_slice(&sample().encode());
        padded[MAX_PUBLIC_OUTPUT_BYTES - 1] = 1;
        assert_eq!(Journal::decode(&padded), None);
    }

    /// Un largo cualquiera no se acepta "por si acaso". El 97 es el largo del
    /// formato anterior: un journal viejo no se lee como uno nuevo.
    #[test]
    fn a_length_that_is_neither_exact_nor_padded_is_refused() {
        assert_eq!(Journal::decode(&[]), None);
        assert_eq!(Journal::decode(&[0u8; 97]), None);
        assert_eq!(Journal::decode(&[0u8; JOURNAL_BYTES - 1]), None);
        assert_eq!(Journal::decode(&[0u8; JOURNAL_BYTES + 1]), None);
    }

    /// Otra versión afirma otra cosa con los mismos bytes.
    #[test]
    fn another_version_is_refused() {
        let mut bytes = sample().encode();
        bytes[0] = JOURNAL_VERSION.wrapping_add(1);
        assert_eq!(Journal::decode(&bytes), None);
        bytes[0] = 0;
        assert_eq!(Journal::decode(&bytes), None);
    }

    /// Un modo desconocido es un rechazo, no un `Full` silencioso.
    #[test]
    fn an_unknown_mode_is_refused() {
        let mut bytes = sample().encode();
        // 9 y no 8: desde que existe `Mode::StateTest`, el 8 ES un modo conocido.
        bytes[1] = 9;
        assert_eq!(Journal::decode(&bytes), None);
        assert_eq!(Mode::from_byte(255), None);
    }

    /// Los ids ya publicados no se mueven: una prueba vieja de Osaka tiene que
    /// seguir diciendo Osaka. Los forks de solo parámetros de blob van detrás.
    #[test]
    fn published_fork_ids_are_stable() {
        let ids = [
            (Spec::Paris, 1),
            (Spec::Shanghai, 2),
            (Spec::Cancun, 3),
            (Spec::Prague, 4),
            (Spec::Osaka, 5),
            (Spec::Bpo1, 6),
            (Spec::Bpo2, 7),
        ];
        for (spec, id) in ids {
            assert_eq!(fork_id(spec), id, "{spec:?}");
        }
    }

    /// Un id de fork desconocido es un rechazo; el cero es "ninguno".
    #[test]
    fn an_unknown_fork_is_refused_and_zero_is_none() {
        let mut bytes = sample().encode();
        bytes[10] = 8;
        assert_eq!(Journal::decode(&bytes), None);
        bytes[10] = 0;
        assert_eq!(Journal::decode(&bytes).map(|j| j.fork), Some(None));
        for spec in [
            Spec::Paris,
            Spec::Shanghai,
            Spec::Cancun,
            Spec::Prague,
            Spec::Osaka,
            Spec::Bpo1,
            Spec::Bpo2,
        ] {
            assert_eq!(fork_from_id(fork_id(spec)), Some(spec));
            assert_ne!(fork_id(spec), 0);
        }
    }

    /// Los modos ablacionados **no** ejecutan txs, y eso es lo que hace que un
    /// verificador pueda distinguirlos.
    #[test]
    fn only_the_full_modes_run_transactions() {
        assert!(Mode::Full.runs_txs());
        assert!(Mode::NoRoot.runs_txs());
        assert!(Mode::StateTest.runs_txs());
        for m in [Mode::NoTxs, Mode::StateOnly, Mode::DecodeOnly, Mode::Nop] {
            assert!(!m.runs_txs(), "{m:?} no debería ejecutar txs");
        }
    }
}
