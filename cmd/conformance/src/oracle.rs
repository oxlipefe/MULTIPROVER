//! El **juez** del diferencial: qué se observa de una ejecución y qué cuenta
//! como divergencia — más el inventario de lo que este juez NO puede ver.
//!
//! Vive fuera de la feature `diff-revm` a propósito: comparar dos `Summary` no
//! necesita a revm, y dejarlo del lado gateado dejaba sus tests fuera de
//! `cargo test --workspace`. Un test que CI no corre no pinea nada.

// Sin la feature `diff-revm` nadie consume el juez en el binario — pero sus
// tests SÍ corren, que es exactamente el motivo de que viva fuera de la feature.
#![cfg_attr(not(feature = "diff-revm"), allow(dead_code))]

use std::collections::BTreeMap;

use repo_b_common::primitives::{Address, B256, Bytes};

use crate::fixture::FixtureAccount;

/// Post-state normalizado: la unidad de comparación.
pub type PostState = BTreeMap<Address, FixtureAccount>;

// ------------------------------------------------- inventario del oráculo
//
// Dos cosas distintas, modeladas distinto porque el diferencial hace lo
// contrario con cada una:
//
// | Categoría              | Qué significa                    | Qué hace el diferencial |
// |------------------------|----------------------------------|-------------------------|
// | Divergencia deliberada | nosotros tenemos razón, revm no  | **dispara** `[DIFF]`    |
// | Punto ciego            | el comparador **no puede** verlo  | **calla**               |
//
// Regla innegociable: **clasificar, nunca excusar.** Una divergencia
// deliberada se ETIQUETA acá para que el triage sepa qué está mirando; NO se
// suprime en `compare`. El costo de excusar está medido en este repo: un
// chequeo "excusable" dejó pasar 2 545 casos con la razón equivocada.
//
// Y cada punto ciego lleva **un test que demuestra que es ciego** (ver
// `mod tests`). Un punto ciego declarado en prosa y no demostrado es una
// creencia, no un dato.

/// Una regla donde el oráculo está equivocado y nosotros no. El diferencial
/// **sigue disparando** `[DIFF]` en la vecindad de estas reglas: el que
/// clasifica es el humano (o el triage del fuzzer), leyendo esta tabla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliberateDivergence {
    /// La regla de consenso en disputa.
    pub rule: &'static str,
    /// Qué hace revm =38.0.0 y por qué eso no nos hace falsos a nosotros.
    pub revm_behaviour: &'static str,
    /// Quién es el juez cuando el oráculo no lo es.
    pub judged_by: &'static str,
}

/// Algo que `compare` **no puede** ver. Su `[SAME]` no es evidencia: dos
/// motores pueden coincidir porque nadie está mirando.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleBlindSpot {
    /// Qué no ve.
    pub what: &'static str,
    /// Por qué no puede verlo. Siempre estructura, nunca olvido: si fuera un
    /// olvido, la respuesta es arreglarlo, no inventariarlo.
    pub why: &'static str,
    /// El otro oráculo que sí lo cubre. Tener dos oráculos existe justamente
    /// para que no compartan puntos ciegos: si uno calla, el otro habla.
    pub covered_by: &'static str,
}

/// Las reglas donde divergir de revm es lo correcto.
pub const DELIBERATE_DIVERGENCES: &[DeliberateDivergence] = &[DeliberateDivergence {
    rule: "EIP-7610: CREATE colisiona contra una cuenta con storage no vacío",
    revm_behaviour: "revm =38.0.0 no la implementa (decide la colisión con dos \
                     condiciones, nonce y código; `grep 7610` da cero en todos \
                     sus crates), así que crea encima de una cuenta fantasma",
    judged_by: "EEST: el root MPT recomputado (`--eest`, +50 casos medidos)",
}];

/// Lo que el diferencial no puede ver, con quién lo cubre.
pub const ORACLE_BLIND_SPOTS: &[OracleBlindSpot] = &[
    OracleBlindSpot {
        what: "EIP-161 state clearing: las cuentas vacías del post-state",
        why: "`normalize()` las descarta en LOS DOS lados antes de comparar, \
              así que una diferencia que solo esté ahí se cancela",
        covered_by: "EEST: el root MPT sí las cuenta (medido: borrar la regla \
                     cuesta −24 315 casos allá y 0 acá)",
    },
    OracleBlindSpot {
        what: "todo lo de nivel de BLOQUE: system calls (EIP-4788/2935/7002/\
               7251), encoding y validación del header, `requestsHash`, blob \
               gas acumulado, withdrawals, la cadena real de `BLOCKHASH`",
        why: "el diferencial es de UNA tx: corre `execute_tx` y nunca el \
              lifecycle de bloque del trait `Vm` (abrir, cerrar, disparar una \
              system call), así que un bug de bloque no puede producir una \
              diferencia acá",
        covered_by: "`--eest-blockchain` (42 017 casos) y los tests de \
                     integración de `crates/evm/tests/`",
    },
    OracleBlindSpot {
        what: "la RAZÓN por la que una tx INVÁLIDA se rechaza",
        why: "cuando los dos motores rechazan la tx, `run_case` dictamina \
              acuerdo sin comparar el motivo: las taxonomías de validación no \
              mapean 1:1 (la nuestra es `ConsensusError`, la de revm \
              `InvalidTransaction`) y compararlas produciría divergencias que \
              no son de consenso. Lo que SÍ se compara es el veredicto: que \
              uno la rechace y el otro la ejecute es divergencia",
        covered_by: "EEST: `expectException` compara el rechazo caso por caso \
                     y `AcceptedInvalidTx` es su propia categoría de falla \
                     (2.9b-1, 2.9b-3e)",
    },
    OracleBlindSpot {
        what: "la RAZÓN del halt",
        why: "`Status` colapsa `Halt { reason }` a `Status::Halt`, y a \
              propósito: las taxonomías de halt de los dos motores no mapean \
              1:1, así que compararlas produciría divergencias que no son de \
              consenso",
        covered_by: "parcial e indirecto: el gas consumido y el post-state \
                     suelen separar dos halts distintos, pero no siempre",
    },
];

/// Vuelca el inventario junto al veredicto del set.
///
/// Va pegado al "0 divergencias" a propósito: ese número es una afirmación
/// sobre lo que el oráculo MIRA, y sin la lista de lo que no mira se lee como
/// una afirmación más fuerte de la que es.
pub fn print_oracle_inventory() {
    eprintln!();
    eprintln!("divergencias deliberadas vs revm (se ETIQUETAN, no se suprimen):");
    for divergence in DELIBERATE_DIVERGENCES {
        eprintln!("  · {}", divergence.rule);
        eprintln!("      revm: {}", divergence.revm_behaviour);
        eprintln!("      juez: {}", divergence.judged_by);
    }
    eprintln!();
    eprintln!("puntos ciegos del oráculo (un [SAME] acá NO es evidencia):");
    for spot in ORACLE_BLIND_SPOTS {
        eprintln!("  · {}", spot.what);
        eprintln!("      por qué: {}", spot.why);
        eprintln!("      lo cubre: {}", spot.covered_by);
    }
}

/// La trichotomy, reducida a lo comparable entre los dos motores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    Revert,
    Halt,
}

/// Un log reducido a lo comparable entre los dos motores: la terna
/// `(address, topics, data)` del Yellow Paper. Los tres campos son consenso
/// —definen el `logs_hash` y el bloom del receipt— y el ORDEN de la lista
/// también, porque el hash se toma sobre la secuencia de emisión.
///
/// Existe porque los dos motores traen el log en tipos distintos (el nuestro
/// aplana `topics`/`data`; el de revm los mete en un `LogData`): comparar el
/// tipo de uno contra el del otro exigiría un `From` que se vuelve el lugar
/// donde alguien "arregla" una divergencia. Acá los dos lados se proyectan a
/// la MISMA terna y la comparación es de igualdad estructural.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

/// Todo lo observable de una ejecución. Dos `Summary` iguales = bit-idéntico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub status: Status,
    pub gas_used: u64,
    pub gas_refunded: u64,
    pub output: Bytes,
    /// Los logs emitidos, **en orden de emisión**.
    ///
    /// Vacío en Revert y en Halt: los dos descartan el frame y con él sus
    /// logs. Del lado nuestro eso es ESTRUCTURA DEL TIPO y no un hueco —
    /// `ExecutionResult::{Revert,Halt}` no llevan `logs` porque no hay nada
    /// que llevar—; del lado de revm el tipo sí tiene el campo en las tres
    /// ramas, y que venga vacío en dos de ellas es una afirmación sobre el
    /// motor: la pinean dos fixtures de `logs-env`, no un comentario.
    pub logs: Vec<LogRecord>,
    pub post: PostState,
}

/// Diferencias campo a campo. Vacío = bit-idéntico.
///
/// **No se debilita nunca**: el refund y el post-state entran enteros. Sacar
/// un campo para "pasar" sería mentirle al gate.
pub fn compare(ours: &Summary, oracle: &Summary) -> Vec<String> {
    let mut differences = Vec::new();
    if ours.status != oracle.status {
        differences.push(format!(
            "status: nuestro {:?} vs revm {:?}",
            ours.status, oracle.status
        ));
    }
    if ours.gas_used != oracle.gas_used {
        differences.push(format!(
            "gas_used: nuestro {} vs revm {} (delta {})",
            ours.gas_used,
            oracle.gas_used,
            i128::from(ours.gas_used) - i128::from(oracle.gas_used)
        ));
    }
    if ours.gas_refunded != oracle.gas_refunded {
        differences.push(format!(
            "refund: nuestro {} vs revm {}",
            ours.gas_refunded, oracle.gas_refunded
        ));
    }
    if ours.output != oracle.output {
        differences.push(format!(
            "output: nuestro 0x{} vs revm 0x{}",
            hex(&ours.output),
            hex(&oracle.output)
        ));
    }
    differences.extend(compare_logs(&ours.logs, &oracle.logs));
    differences.extend(compare_post(&ours.post, &oracle.post));
    differences
}

/// Logs, **en orden**. El orden de emisión define el `logs_hash` y por lo
/// tanto el `receiptTrie` del bloque: permutar dos logs es una divergencia de
/// consenso, no un detalle de presentación. Por eso se compara índice a
/// índice y no como conjunto.
pub fn compare_logs(ours: &[LogRecord], oracle: &[LogRecord]) -> Vec<String> {
    let mut differences = Vec::new();
    if ours.len() != oracle.len() {
        differences.push(format!(
            "logs: nuestro emitió {} vs revm {}",
            ours.len(),
            oracle.len()
        ));
    }
    for (index, (a, b)) in ours.iter().zip(oracle.iter()).enumerate() {
        if a.address != b.address {
            differences.push(format!(
                "log[{index}]: address nuestro {} vs revm {}",
                a.address, b.address
            ));
        }
        if a.topics != b.topics {
            differences.push(format!(
                "log[{index}]: topics nuestro {:?} vs revm {:?}",
                a.topics, b.topics
            ));
        }
        if a.data != b.data {
            differences.push(format!(
                "log[{index}]: data nuestro 0x{} vs revm 0x{}",
                hex(&a.data),
                hex(&b.data)
            ));
        }
    }
    differences
}

fn compare_post(ours: &PostState, oracle: &PostState) -> Vec<String> {
    let mut differences = Vec::new();
    let addresses: std::collections::BTreeSet<Address> =
        ours.keys().chain(oracle.keys()).copied().collect();
    for address in addresses {
        match (ours.get(&address), oracle.get(&address)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => {
                if a.balance != b.balance {
                    differences.push(format!(
                        "{address}: balance nuestro {} vs revm {}",
                        a.balance, b.balance
                    ));
                }
                if a.nonce != b.nonce {
                    differences.push(format!(
                        "{address}: nonce nuestro {} vs revm {}",
                        a.nonce, b.nonce
                    ));
                }
                if a.code != b.code {
                    differences.push(format!("{address}: el código difiere"));
                }
                if a.storage != b.storage {
                    differences.push(format!(
                        "{address}: storage nuestro {:?} vs revm {:?}",
                        a.storage, b.storage
                    ));
                }
            }
            (Some(_), None) => differences.push(format!("{address}: sobra en nuestro post-state")),
            (None, Some(_)) => differences.push(format!("{address}: falta en nuestro post-state")),
            (None, None) => {}
        }
    }
    differences
}

/// Normalización del post-state, idéntica en los dos lados:
/// - fuera los slots en cero (no existen en el trie),
/// - fuera las cuentas vacías (EIP-161 state clearing: `balance == 0 &&
///   nonce == 0 && sin código`).
///
/// Es válida porque los fixtures de `fixtures/diff/` no traen cuentas vacías
/// en el pre-state (ahí sí habría que distinguir "vacía y no tocada").
pub fn normalize(mut post: PostState) -> PostState {
    for account in post.values_mut() {
        account.storage.retain(|_, value| !value.is_zero());
    }
    post.retain(|_, account| {
        !(account.balance.is_zero() && account.nonce == 0 && account.code.is_empty())
    });
    post
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use repo_b_common::primitives::U256;

    const ALICE: Address = Address::new([0xAA; 20]);

    fn account(balance: u64, nonce: u64, slots: &[(u64, u64)]) -> FixtureAccount {
        FixtureAccount {
            balance: U256::from(balance),
            nonce,
            code: Bytes::new(),
            storage: slots
                .iter()
                .map(|(k, v)| (U256::from(*k), U256::from(*v)))
                .collect(),
        }
    }

    fn log(address: Address, topics: &[u8], data: &'static [u8]) -> LogRecord {
        LogRecord {
            address,
            topics: topics.iter().map(|t| B256::with_last_byte(*t)).collect(),
            data: Bytes::from_static(data),
        }
    }

    fn summary() -> Summary {
        Summary {
            status: Status::Success,
            gas_used: 43_106,
            gas_refunded: 4_800,
            output: Bytes::from_static(b"ok"),
            logs: vec![log(ALICE, &[1, 2], b"payload")],
            post: BTreeMap::from([(ALICE, account(10, 1, &[(0, 7)]))]),
        }
    }

    #[test]
    fn identical_summaries_have_no_differences() {
        assert!(compare(&summary(), &summary()).is_empty());
    }

    /// El comparador NO se debilita: cada campo observable dispara diferencia.
    #[test]
    fn every_observable_field_is_compared() {
        let cases: Vec<(&str, Summary)> = vec![
            (
                "status",
                Summary {
                    status: Status::Revert,
                    ..summary()
                },
            ),
            (
                "gas_used",
                Summary {
                    gas_used: 43_107,
                    ..summary()
                },
            ),
            (
                "refund",
                Summary {
                    gas_refunded: 0,
                    ..summary()
                },
            ),
            (
                "output",
                Summary {
                    output: Bytes::from_static(b"no"),
                    ..summary()
                },
            ),
            (
                "balance",
                Summary {
                    post: BTreeMap::from([(ALICE, account(11, 1, &[(0, 7)]))]),
                    ..summary()
                },
            ),
            (
                "nonce",
                Summary {
                    post: BTreeMap::from([(ALICE, account(10, 2, &[(0, 7)]))]),
                    ..summary()
                },
            ),
            (
                "storage",
                Summary {
                    post: BTreeMap::from([(ALICE, account(10, 1, &[(0, 8)]))]),
                    ..summary()
                },
            ),
            ("cuenta faltante", {
                Summary {
                    post: BTreeMap::new(),
                    ..summary()
                }
            }),
            (
                "log faltante",
                Summary {
                    logs: Vec::new(),
                    ..summary()
                },
            ),
            (
                "log de más",
                Summary {
                    logs: vec![log(ALICE, &[1, 2], b"payload"), log(ALICE, &[3], b"extra")],
                    ..summary()
                },
            ),
            (
                "address del log",
                Summary {
                    logs: vec![log(Address::new([0xBB; 20]), &[1, 2], b"payload")],
                    ..summary()
                },
            ),
            (
                "topics del log",
                Summary {
                    logs: vec![log(ALICE, &[1, 2, 3], b"payload")],
                    ..summary()
                },
            ),
            (
                "orden de los topics",
                Summary {
                    logs: vec![log(ALICE, &[2, 1], b"payload")],
                    ..summary()
                },
            ),
            (
                "data del log",
                Summary {
                    logs: vec![log(ALICE, &[1, 2], b"payloae")],
                    ..summary()
                },
            ),
        ];
        for (field, mutated) in cases {
            assert!(
                !compare(&summary(), &mutated).is_empty(),
                "una diferencia de {field} pasó desapercibida"
            );
        }
    }

    /// El ORDEN de emisión es consenso: define el `logs_hash` y por lo tanto
    /// el `receiptTrie`. Permutar dos logs no es una diferencia de
    /// presentación — un comparador que tratara la lista como conjunto sería
    /// ciego a un bug de consenso real.
    #[test]
    fn permuting_two_logs_is_a_difference() {
        let first = log(ALICE, &[1], b"a");
        let second = log(ALICE, &[2], b"b");
        let a = Summary {
            logs: vec![first.clone(), second.clone()],
            ..summary()
        };
        let b = Summary {
            logs: vec![second, first],
            ..summary()
        };

        assert!(
            !compare(&a, &b).is_empty(),
            "permutar dos logs pasó desapercibido: el comparador trata la \
             lista como conjunto"
        );
    }

    // -------------------------------------------- inventario del oráculo
    //
    // Un punto ciego declarado en prosa es una creencia. Cada entrada de
    // `ORACLE_BLIND_SPOTS` lleva acá un test que DEMUESTRA la ceguera, y que
    // exige además que el inventario la siga declarando: marcar una entrada
    // como cubierta sin cambiar el comparador pone rojo el test.

    fn blind_spot_listed(needle: &str) -> bool {
        ORACLE_BLIND_SPOTS
            .iter()
            .any(|spot| spot.what.contains(needle))
    }

    /// **Punto ciego 1 — EIP-161.** Demostración: dos post-states que difieren
    /// en una cuenta vacía comparan IGUAL, porque `normalize` la descarta de
    /// los dos lados. Lo caza el otro oráculo (M2 de 2.9b-1: −24 315 en EEST).
    #[test]
    fn empty_accounts_are_a_demonstrated_blind_spot() {
        let ghost = Address::new([0xEE; 20]);
        let with_ghost = Summary {
            post: normalize(BTreeMap::from([
                (ALICE, account(10, 1, &[(0, 7)])),
                (ghost, account(0, 0, &[])),
            ])),
            ..summary()
        };
        let without_ghost = Summary {
            post: normalize(BTreeMap::from([(ALICE, account(10, 1, &[(0, 7)]))])),
            ..summary()
        };

        assert!(
            compare(&with_ghost, &without_ghost).is_empty(),
            "el comparador YA VE las cuentas vacías: sacá la entrada del \
             inventario en vez de dejarla declarada"
        );
        assert!(
            blind_spot_listed("EIP-161"),
            "la ceguera a EIP-161 está demostrada pero no inventariada"
        );
    }

    /// **Punto ciego 2 — todo lo de bloque.** Demostración mecánica: el
    /// diferencial no menciona el lifecycle de bloque en ninguna línea, así
    /// que un bug de bloque no puede producir una diferencia acá. El día que
    /// alguien lo wiree, este test se pone rojo — que es exactamente el día
    /// en que la entrada deja de ser un punto ciego.
    #[test]
    fn the_block_lifecycle_is_a_demonstrated_blind_spot() {
        let source = include_str!("diff.rs");
        // Los nombres van partidos: escritos enteros aparecerían en el fuente
        // de este mismo test y la búsqueda se encontraría a sí misma.
        for method in [
            concat!("begin", "_block"),
            concat!("finish", "_block"),
            concat!("system_call", "_in_block"),
        ] {
            assert!(
                !source.contains(method),
                "el diferencial ahora corre `{method}`: dejó de ser ciego al \
                 nivel de bloque y la entrada del inventario sobra"
            );
        }
        assert!(
            blind_spot_listed("BLOQUE"),
            "la ceguera al nivel de bloque está demostrada pero no inventariada"
        );
    }

    /// **Punto ciego 3 — la razón del halt.** Demostración: `Summary` no
    /// tiene dónde ponerla; dos halts por causas distintas con el mismo gas y
    /// el mismo post-state son indistinguibles.
    #[test]
    fn the_halt_reason_is_a_demonstrated_blind_spot() {
        let halted = Summary {
            status: Status::Halt,
            logs: Vec::new(),
            output: Bytes::new(),
            ..summary()
        };

        assert!(
            compare(&halted, &halted.clone()).is_empty(),
            "sanity: dos halts idénticos no divergen"
        );
        assert!(
            blind_spot_listed("del halt"),
            "la ceguera a la razón del halt está demostrada pero no inventariada"
        );
    }

    /// **Clasificar, nunca excusar.** Una divergencia deliberada se etiqueta
    /// en el inventario, pero `compare` la sigue disparando: acá, la forma que
    /// tiene EIP-7610 (nosotros abortamos el CREATE, revm crea encima).
    #[test]
    fn deliberate_divergences_are_labelled_not_suppressed() {
        let ghost = Address::new([0xEE; 20]);
        let ours = Summary {
            status: Status::Halt,
            logs: Vec::new(),
            output: Bytes::new(),
            post: BTreeMap::from([(ghost, account(0, 0, &[(1, 9)]))]),
            ..summary()
        };
        let revm_side = Summary {
            post: BTreeMap::from([(ghost, account(0, 1, &[(1, 9)]))]),
            ..ours.clone()
        };

        assert!(
            !compare(&ours, &revm_side).is_empty(),
            "una divergencia deliberada quedó SUPRIMIDA: el inventario \
             clasifica, no excusa"
        );
        assert!(
            DELIBERATE_DIVERGENCES
                .iter()
                .any(|d| d.rule.contains("EIP-7610")),
            "la divergencia deliberada vs revm no está inventariada"
        );
    }

    /// El inventario es DATO para el triage, nunca un filtro. Si `compare` (o
    /// `run_case`) lo consultara, tendríamos un camino por el cual una
    /// divergencia real se suprime sola.
    #[test]
    fn the_inventory_is_never_consulted_by_the_comparator() {
        // El camino de comparación son dos tramos: el veredicto de un caso
        // (`run_case`, en `diff.rs`) y el juez propiamente dicho (`compare`,
        // acá). Los dos, porque suprimir se puede hacer en cualquiera.
        let path = [
            (include_str!("diff.rs"), concat!("pub fn ", "run_case")),
            (include_str!("oracle.rs"), concat!("pub fn ", "compare(")),
        ];
        for (source, entry_point) in path {
            let (_, from_entry) = source
                .split_once(entry_point)
                .unwrap_or_else(|| panic!("no se encontró `{entry_point}` en el fuente"));
            // Los tests SÍ pueden nombrar el inventario: son quienes lo pinean.
            let (body, _) = from_entry
                .split_once("\n#[cfg(test)]")
                .unwrap_or((from_entry, ""));
            assert!(
                !body.contains(concat!("DELIBERATE_", "DIVERGENCES")),
                "el camino de comparación consulta el inventario: eso es \
                 excusar, no clasificar"
            );
        }
    }

    #[test]
    fn normalize_drops_zero_slots_and_empty_accounts() {
        let post = BTreeMap::from([
            (ALICE, account(0, 0, &[(1, 0)])),
            (Address::new([0xBB; 20]), account(5, 0, &[(1, 0), (2, 9)])),
        ]);

        let normalized = normalize(post);

        // La cuenta vacía (balance 0, nonce 0, sin código) desaparece: EIP-161.
        assert!(!normalized.contains_key(&ALICE));
        let kept = normalized
            .get(&Address::new([0xBB; 20]))
            .unwrap_or_else(|| panic!("la cuenta no vacía sobrevive"));
        // Los slots en cero no existen en el trie.
        assert_eq!(kept.storage.len(), 1);
        assert_eq!(kept.storage.get(&U256::from(2u64)), Some(&U256::from(9u64)));
    }
}
