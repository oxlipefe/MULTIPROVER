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
//! Una prueba sirve para afirmar algo, y lo que se quiere afirmar es:
//! *"partiendo del estado `pre_state_root`, este bloque ejecuta y deja el
//! estado en `post_state_root`"*. Las dos raíces tienen que estar adentro del
//! output: sin la de arranque la afirmación no está anclada a nada, y sin la de
//! llegada no afirma nada. El `output_digest` cierra lo que el bloque produjo
//! además del estado (los outputs de las system calls de cierre, que son la
//! fuente de dos de los tres tipos de request de EIP-7685).
//!
//! # El `mode` viaja adentro del output, y no es decoración
//!
//! El guest acepta **modos ablacionados** para poder medir ciclos por
//! diferencia (`ere` no puebla `region_cycles`, así que el desglose hay que
//! producirlo restando corridas). Un guest que se puede *pedir* que saltee la
//! ejecución de las txs es un guest al que se le puede pedir que mienta — a
//! menos que **lo que salteó viaje en la afirmación**. Por eso el modo es el
//! primer byte del journal: un verificador que solo acepta `Mode::Full` no
//! puede ser engañado por una prueba de un modo ablacionado, y la ablación deja
//! de ser un agujero para pasar a ser un dato público.

use repo_b_common::primitives::B256;

/// El techo de output que los tres backends comparten. Ver el doc del módulo.
pub const MAX_PUBLIC_OUTPUT_BYTES: usize = 256;

/// El largo exacto del journal: `mode` + tres hashes.
pub const JOURNAL_BYTES: usize = 1 + 32 * 3;

// El techo no es un comentario: si el journal creciera por encima de lo que el
// backend más restrictivo acepta, esto no compila.
const _: () = assert!(JOURNAL_BYTES <= MAX_PUBLIC_OUTPUT_BYTES);

/// Qué corrió el guest. **Solo `Full` ejecuta el bloque entero.**
///
/// Los demás existen para medir por diferencia: cada uno saca una pieza, y la
/// resta de `total_num_cycles` entre dos modos consecutivos da lo que esa pieza
/// cuesta. Es mutation testing aplicado a ciclos, y es la única vía portable a
/// los tres backends — parsear el stdout de un backend mide uno solo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// El camino real: decodificar, verificar el witness, ejecutar el bloque
    /// completo y recomputar el post-state root.
    Full = 0,
    /// Todo menos la recomputación del root.
    NoRoot = 1,
    /// El lifecycle del bloque **sin las txs** (system calls, withdrawals).
    NoTxs = 2,
    /// Solo construir el `WitnessState`: indexar los nodos por su hash y
    /// verificar la cadena de headers. **Incluye la recuperación** — la
    /// escalera es de prefijos y sacar una pieza de en medio daría restas sin
    /// sentido.
    StateOnly = 3,
    /// Decodificar el input **y derivar los remitentes de sus firmas**. El
    /// peldaño existe para aislar la criptografía de firma, que es el camino
    /// que el roadmap estima dominante y que nadie había medido acá.
    Recover = 6,
    /// Solo decodificar el input.
    DecodeOnly = 4,
    /// La línea de base: leer el input y publicar. Todo lo de arriba se mide
    /// **contra esto**, porque leer el buffer y escribir el output tampoco es
    /// gratis y atribuirle ese costo al decoder sería mentir.
    Nop = 5,
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
        matches!(self, Self::Full | Self::NoRoot)
    }
}

/// Lo que el guest afirma. Ver el doc del módulo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Journal {
    pub mode: Mode,
    pub pre_state_root: B256,
    /// **`ZERO` cuando el modo no lo computó**, que es distinguible porque el
    /// modo viaja al lado.
    pub post_state_root: B256,
    /// Digest de lo que el bloque produjo además del estado. `ZERO` si el modo
    /// no ejecutó.
    pub output_digest: B256,
}

impl Journal {
    /// El journal de un modo que no produjo nada: solo deja constancia de cuál
    /// fue.
    #[must_use]
    pub const fn empty(mode: Mode) -> Self {
        Self {
            mode,
            pre_state_root: B256::ZERO,
            post_state_root: B256::ZERO,
            output_digest: B256::ZERO,
        }
    }

    #[must_use]
    pub fn encode(&self) -> [u8; JOURNAL_BYTES] {
        let mut out = [0u8; JOURNAL_BYTES];
        out[0] = self.mode.as_byte();
        out[1..33].copy_from_slice(self.pre_state_root.as_slice());
        out[33..65].copy_from_slice(self.post_state_root.as_slice());
        out[65..97].copy_from_slice(self.output_digest.as_slice());
        out
    }

    /// Decodifica lo que un backend devolvió como public values.
    ///
    /// **El largo se exige exacto.** OpenVM rellena con ceros hasta 256, así
    /// que un decoder que aceptara "al menos 97" leería relleno como si fuera
    /// dato el día que el backend cambie; se acepta el largo exacto o el
    /// rellenado, y nada en el medio.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != JOURNAL_BYTES && bytes.len() != MAX_PUBLIC_OUTPUT_BYTES {
            return None;
        }
        if bytes.len() == MAX_PUBLIC_OUTPUT_BYTES && bytes[JOURNAL_BYTES..].iter().any(|b| *b != 0)
        {
            // Relleno que no es relleno: hay algo más ahí y no sabemos qué.
            return None;
        }
        Some(Self {
            mode: Mode::from_byte(bytes[0])?,
            pre_state_root: B256::from_slice(&bytes[1..33]),
            post_state_root: B256::from_slice(&bytes[33..65]),
            output_digest: B256::from_slice(&bytes[65..97]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{JOURNAL_BYTES, Journal, MAX_PUBLIC_OUTPUT_BYTES, Mode};
    use repo_b_common::primitives::B256;

    fn sample() -> Journal {
        Journal {
            mode: Mode::Full,
            pre_state_root: B256::repeat_byte(0x11),
            post_state_root: B256::repeat_byte(0x22),
            output_digest: B256::repeat_byte(0x33),
        }
    }

    #[test]
    fn the_journal_survives_a_round_trip() {
        let j = sample();
        assert_eq!(Journal::decode(&j.encode()), Some(j));
    }

    /// El techo de los tres backends, afirmado con un número y no con prosa.
    #[test]
    fn the_journal_fits_under_the_ceiling_of_every_backend() {
        assert_eq!(JOURNAL_BYTES, 97);
        assert_eq!(sample().encode().len(), JOURNAL_BYTES);
        // El techo lo afirma el `const _` del módulo — acá se afirma el
        // MARGEN, que es lo que un lector quiere saber: cuánto puede crecer el
        // journal antes de que un backend lo trunque.
        assert_eq!(MAX_PUBLIC_OUTPUT_BYTES - JOURNAL_BYTES, 159);
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

    /// Un largo cualquiera no se acepta "por si acaso".
    #[test]
    fn a_length_that_is_neither_exact_nor_padded_is_refused() {
        assert_eq!(Journal::decode(&[]), None);
        assert_eq!(Journal::decode(&[0u8; JOURNAL_BYTES - 1]), None);
        assert_eq!(Journal::decode(&[0u8; JOURNAL_BYTES + 1]), None);
    }

    /// Un modo desconocido es un rechazo, no un `Full` silencioso.
    #[test]
    fn an_unknown_mode_is_refused() {
        let mut bytes = sample().encode();
        bytes[0] = 7;
        assert_eq!(Journal::decode(&bytes), None);
        assert_eq!(Mode::from_byte(255), None);
    }

    /// Los modos ablacionados **no** ejecutan txs, y eso es lo que hace que un
    /// verificador pueda distinguirlos.
    #[test]
    fn only_the_full_modes_run_transactions() {
        assert!(Mode::Full.runs_txs());
        assert!(Mode::NoRoot.runs_txs());
        for m in [Mode::NoTxs, Mode::StateOnly, Mode::DecodeOnly, Mode::Nop] {
            assert!(!m.runs_txs(), "{m:?} no debería ejecutar txs");
        }
    }
}
