//! Un input `stateless-validator-reth` de `zisk-eth-client` (un `ZiskStdin`
//! guardado a disco) a los dos archivos que lee el importador.
//!
//! # El formato, tal como está en disco
//!
//! Una secuencia de tramos `[largo u64 LE][datos][ceros hasta múltiplo de 8]`.
//! Son exactamente dos, los dos en `bincode` 2 con la configuración estándar
//! (enteros varint: un byte < 251, o 251/252/253 seguidos de u16/u32/u64 LE):
//!
//! 1. el público, cuyo PRIMER campo es el bloque en RLP (`Vec<u8>`); lo que
//!    sigue (configuración de cadena y claves públicas) no se lee: la cadena
//!    y el fork los fija el calendario de mainnet del importador, y el bloque
//!    lo ancla el hash que nombra el operador;
//! 2. el witness: cuatro listas de byte strings, `state`, `codes`, `keys`,
//!    `headers`, que tienen que consumir el tramo entero.
//!
//! # Qué garantiza
//!
//! Nada sobre el bloque: es una reserialización, sin red y sin criptografía.
//! Lo que dice que el bloque es el nombrado y que el witness alcanza lo decide
//! el importador después. Acá solo se rechaza todo lo que no tiene la forma:
//! un largo que pasa el final, relleno que no es cero, un tramo de más o de
//! menos, un byte suelto al final.

use std::fmt::Write as _;
use std::path::Path;

use crate::import::{ImportError, MAX_FILE_BYTES, read_capped, write_atomic};

/// El tope del `.bin`: el mismo que el de cada JSON del importador, que en hex
/// pesa el doble, así que nada que pase de acá entraría allá.
const MAX_STDIN_BYTES: u64 = MAX_FILE_BYTES;

/// Los tramos de un `ZiskStdin` se alinean a esto.
const ALINEACION: usize = 8;

/// Las cuatro listas del witness, en el orden en que viajan y se escriben.
const LISTAS: [&str; 4] = ["state", "codes", "keys", "headers"];

const USO: &str = "uso: --zisk-stdin <entrada.bin> <bloque.json> <witness.json>";

/// El bloque y las cuatro listas del witness, sin interpretar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reth {
    pub bloque: Vec<u8>,
    pub listas: [Vec<Vec<u8>>; 4],
}

fn malo(detalle: String) -> ImportError {
    ImportError::Json {
        file: "zisk-stdin",
        detail: detalle,
    }
}

/// Un cursor que no lee más allá del final ni se desborda.
struct Cursor<'a> {
    datos: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn tomar(&mut self, n: usize) -> Result<&'a [u8], ImportError> {
        let fin = self
            .pos
            .checked_add(n)
            .filter(|&f| f <= self.datos.len())
            .ok_or_else(|| malo(format!("pide {n} bytes en {} y no están", self.pos)))?;
        let tramo = self.datos.get(self.pos..fin).unwrap_or_default();
        self.pos = fin;
        Ok(tramo)
    }

    fn fijo<const N: usize>(&mut self) -> Result<[u8; N], ImportError> {
        let mut b = [0u8; N];
        b.copy_from_slice(self.tomar(N)?);
        Ok(b)
    }

    /// Un entero varint de `bincode` 2, como `usize`.
    fn varint(&mut self) -> Result<usize, ImportError> {
        let [marca] = self.fijo::<1>()?;
        let valor = match marca {
            0..=250 => u64::from(marca),
            251 => u64::from(u16::from_le_bytes(self.fijo()?)),
            252 => u64::from(u32::from_le_bytes(self.fijo()?)),
            253 => u64::from_le_bytes(self.fijo()?),
            _ => return Err(malo(format!("marca de varint {marca} fuera de rango"))),
        };
        usize::try_from(valor).map_err(|_| malo(format!("largo {valor} no entra en usize")))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, ImportError> {
        let n = self.varint()?;
        Ok(self.tomar(n)?.to_vec())
    }

    fn terminado(&self) -> bool {
        self.pos == self.datos.len()
    }
}

/// Los tramos del archivo, sin su relleno.
fn tramos(archivo: &[u8]) -> Result<Vec<&[u8]>, ImportError> {
    let mut c = Cursor {
        datos: archivo,
        pos: 0,
    };
    let mut salida = Vec::new();
    while !c.terminado() {
        let largo = usize::try_from(u64::from_le_bytes(c.fijo()?))
            .map_err(|_| malo("largo de tramo no entra en usize".to_owned()))?;
        salida.push(c.tomar(largo)?);
        let relleno = largo.wrapping_neg() % ALINEACION;
        if c.tomar(relleno)?.iter().any(|&b| b != 0) {
            return Err(malo(format!("relleno no nulo antes de {}", c.pos)));
        }
    }
    Ok(salida)
}

/// Ver el doc del módulo.
///
/// # Errors
/// Lo primero que no tiene la forma.
pub fn decodificar(archivo: &[u8]) -> Result<Reth, ImportError> {
    let [publico, witness] = tramos(archivo)?[..] else {
        return Err(malo("no son exactamente dos tramos".to_owned()));
    };
    let bloque = Cursor {
        datos: publico,
        pos: 0,
    }
    .bytes()?;
    let mut c = Cursor {
        datos: witness,
        pos: 0,
    };
    let mut listas: [Vec<Vec<u8>>; 4] = Default::default();
    for lista in &mut listas {
        let n = c.varint()?;
        // Cada elemento ocupa al menos un byte (su largo): un conteo mayor que
        // lo que queda no se reserva.
        if n > witness.len().saturating_sub(c.pos) {
            return Err(malo(format!("una lista dice {n} elementos y no caben")));
        }
        *lista = (0..n).map(|_| c.bytes()).collect::<Result<_, _>>()?;
    }
    if !c.terminado() {
        return Err(malo(format!("sobran bytes en el witness desde {}", c.pos)));
    }
    Ok(Reth { bloque, listas })
}

fn hex0x(salida: &mut String, bytes: &[u8]) {
    salida.push_str("\"0x");
    salida.push_str(&alloy_primitives::hex::encode(bytes));
    salida.push('"');
}

/// Los dos JSON del importador, compactos: `"0x…"` y
/// `{"state":[…],"codes":[…],"keys":[…],"headers":[…]}`.
pub fn a_json(reth: &Reth) -> (String, String) {
    let mut bloque = String::new();
    hex0x(&mut bloque, &reth.bloque);
    let mut witness = String::from("{");
    for (i, (nombre, lista)) in LISTAS.iter().zip(&reth.listas).enumerate() {
        let coma = if i == 0 { "" } else { "," };
        let _ = write!(witness, "{coma}\"{nombre}\":[");
        for (j, item) in lista.iter().enumerate() {
            if j > 0 {
                witness.push(',');
            }
            hex0x(&mut witness, item);
        }
        witness.push(']');
    }
    witness.push('}');
    (bloque, witness)
}

/// `--zisk-stdin <entrada.bin> <bloque.json> <witness.json>`. Las salidas se
/// borran antes de leer nada: un rechazo no deja las de una corrida anterior.
///
/// # Errors
/// Uso, lectura, forma o escritura.
pub fn run_cli(args: &[String]) -> Result<Reth, ImportError> {
    let [entrada, bloque, witness] = args else {
        return Err(ImportError::Usage(USO));
    };
    for salida in [bloque, witness] {
        match std::fs::remove_file(salida) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(ImportError::File {
                    file: salida.clone(),
                    detail: e.to_string(),
                });
            }
            _ => {}
        }
    }
    let reth = decodificar(&read_capped(Path::new(entrada), MAX_STDIN_BYTES)?)?;
    let (b, w) = a_json(&reth);
    write_atomic(Path::new(bloque), b.as_bytes())?;
    write_atomic(Path::new(witness), w.as_bytes())?;
    Ok(reth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(n: usize) -> Vec<u8> {
        match u16::try_from(n) {
            Ok(v) if v < 251 => vec![u8::try_from(v).unwrap_or(0)],
            Ok(v) => [vec![251], v.to_le_bytes().to_vec()].concat(),
            Err(_) => [
                vec![252],
                u32::try_from(n).unwrap_or(0).to_le_bytes().to_vec(),
            ]
            .concat(),
        }
    }

    fn bytes(b: &[u8]) -> Vec<u8> {
        [varint(b.len()), b.to_vec()].concat()
    }

    fn tramo(datos: &[u8]) -> Vec<u8> {
        let mut t = (datos.len() as u64).to_le_bytes().to_vec();
        t.extend_from_slice(datos);
        t.resize(t.len().div_ceil(8) * 8, 0);
        t
    }

    fn muestra() -> (Reth, Vec<u8>) {
        let reth = Reth {
            bloque: vec![0xc0; 300],
            listas: [
                vec![vec![1, 2, 3], vec![0xaa; 260]],
                vec![vec![0x60]],
                vec![],
                vec![vec![0xf9, 0x02]],
            ],
        };
        // El público trae más campos después del bloque, que no se leen.
        let publico = [bytes(&reth.bloque), vec![7, 7, 7]].concat();
        let mut w = Vec::new();
        for lista in &reth.listas {
            w.extend(varint(lista.len()));
            for item in lista {
                w.extend(bytes(item));
            }
        }
        (reth, [tramo(&publico), tramo(&w)].concat())
    }

    #[test]
    fn a_well_formed_stdin_decodes_to_the_block_and_the_four_lists() {
        let (reth, archivo) = muestra();
        assert_eq!(decodificar(&archivo), Ok(reth));
    }

    #[test]
    fn the_json_has_the_shape_the_importer_reads() {
        let (reth, _) = muestra();
        let (b, w) = a_json(&reth);
        assert!(b.starts_with("\"0xc0c0") && b.ends_with('"'));
        assert!(w.starts_with("{\"state\":[\"0x010203\",\"0xaaaa"));
        assert!(w.ends_with(",\"codes\":[\"0x60\"],\"keys\":[],\"headers\":[\"0xf902\"]}"));
    }

    #[test]
    fn every_malformed_shape_is_refused() {
        let (_, bueno) = muestra();
        let mut casos: Vec<(&str, Vec<u8>)> = vec![
            ("vacío", vec![]),
            ("un byte de más", [bueno.clone(), vec![0]].concat()),
            (
                "truncado",
                bueno.get(..bueno.len() - 9).unwrap_or_default().to_vec(),
            ),
            ("tres tramos", [bueno.clone(), tramo(&[0])].concat()),
            ("un tramo", tramo(&bytes(&[0xc0]))),
            ("largo de tramo enorme", u64::MAX.to_le_bytes().to_vec()),
        ];
        // Relleno no nulo: el último byte del archivo es relleno del witness.
        let mut relleno = bueno.clone();
        if let Some(b) = relleno.last_mut() {
            *b = 1;
        }
        casos.push(("relleno no nulo", relleno));
        // Varint con marca 254 (u128) en el largo del bloque.
        let mut marca = bueno.clone();
        if let Some(b) = marca.get_mut(8) {
            *b = 254;
        }
        casos.push(("marca 254", marca));
        // Un witness con un byte suelto al final de sus cuatro listas.
        let (reth, _) = muestra();
        let mut w = Vec::new();
        for lista in &reth.listas {
            w.extend(varint(lista.len()));
            lista.iter().for_each(|i| w.extend(bytes(i)));
        }
        w.push(0);
        casos.push((
            "sobra en el witness",
            [tramo(&bytes(&reth.bloque)), tramo(&w)].concat(),
        ));
        // Un conteo de elementos mayor que lo que queda.
        let conteo = [
            tramo(&bytes(&[1])),
            tramo(&[253, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]),
        ]
        .concat();
        casos.push(("conteo imposible", conteo));
        for (nombre, archivo) in casos {
            assert!(decodificar(&archivo).is_err(), "{nombre} se aceptó");
        }
    }
}
