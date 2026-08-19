//! Triage: **qué** divergió, separado de **cuánto** divergió.
//!
//! El triage/dedupe es first-class, y la razón es operativa: sin él, una campaña larga ahoga la señal en miles de
//! divergencias que son el mismo bug. Acá la clave de deduplicación es el
//! conjunto de **campos** que difieren — no los valores, que cambian con cada
//! caso.
//!
//! La clave se deriva del texto que produce `oracle::compare`, y eso es
//! frágil por naturaleza: si alguien reescribe un mensaje, la taxonomía cambia
//! en silencio y dos bugs distintos pasan a contarse como uno. Por eso el test
//! de este módulo no inventa strings: **construye `Summary` que difieren en
//! cada campo, los pasa por `compare`, y exige que TODO mensaje producido caiga
//! en una categoría conocida**. Un mensaje nuevo sin categoría pone el test en
//! rojo, que es donde tiene que fallar.

/// La categoría de una diferencia. `&'static str` y no un enum abierto: se
/// imprime, se ordena y se compara, y no hay lógica que despache sobre ella.
pub const UNCLASSIFIED: &str = "sin-clasificar";

/// A qué campo del `Summary` corresponde el mensaje.
pub fn difference_kind(message: &str) -> &'static str {
    // El orden importa: `logs:` y `log[` comparten prefijo.
    if message.starts_with("status:") {
        return "status";
    }
    if message.starts_with("gas_used:") {
        return "gas_used";
    }
    if message.starts_with("refund:") {
        return "refund";
    }
    if message.starts_with("output:") {
        return "output";
    }
    if message.starts_with("logs:") {
        return "logs.count";
    }
    if message.starts_with("log[") {
        if message.contains(": address ") {
            return "log.address";
        }
        if message.contains(": topics ") {
            return "log.topics";
        }
        if message.contains(": data ") {
            return "log.data";
        }
        return UNCLASSIFIED;
    }
    // Los tres mensajes que sintetiza `diff::verdict` (no `compare`): el
    // veredicto sobre si cada motor produjo un `Summary`. Sin ellos, una tx
    // que un motor rechaza y el otro ejecuta cae en `sin-clasificar` y deja de
    // deduplicar — medido sobre EEST: 5 casos reales con esa firma.
    if message.starts_with(crate::oracle::VERDICT_OURS_INTERNAL) {
        return "ours.internal";
    }
    if message.starts_with(crate::oracle::VERDICT_TX_VALIDITY) {
        return "tx.validity";
    }
    // El resto son diferencias de post-state, prefijadas por la dirección.
    if message.contains(": balance ") {
        return "post.balance";
    }
    if message.contains(": nonce ") {
        return "post.nonce";
    }
    if message.contains(": el código difiere") {
        return "post.code";
    }
    if message.contains(": storage ") {
        return "post.storage";
    }
    if message.contains(": sobra en nuestro post-state") {
        return "post.extra";
    }
    if message.contains(": falta en nuestro post-state") {
        return "post.missing";
    }
    UNCLASSIFIED
}

/// La firma de una divergencia: el CONJUNTO ordenado de campos que difieren.
///
/// Deliberadamente insensible a los valores: dos casos que difieren en
/// `gas_used` por 3 y por 1 700 son el mismo bug hasta que se demuestre lo
/// contrario, y el reproductor mínimo es el que lo demuestra. Un dedupe por
/// valor no deduplicaría nada.
pub fn signature(differences: &[String]) -> String {
    let mut kinds: Vec<&'static str> = differences
        .iter()
        .map(|message| difference_kind(message))
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.is_empty() {
        return "vacia".to_owned();
    }
    kinds.join("+")
}

/// El orden de prioridad de las categorías: de la historia MÁS específica que
/// una divergencia puede contar a la menos.
///
/// **No es estético y la posición de `gas_used` es la decisión del slice.** El
/// gas es la sombra de casi todo lo que el motor hace mal: un bug de costo, uno
/// de semántica que cambia una rama, uno que haltea antes — los tres mueven el
/// gas. Si `status` ganara, un solo bug de gas se partiría en dos clusters (los
/// casos que se quedan sin gas y los que no), y eso es exactamente lo que M2
/// prohíbe. Con `gas_used` arriba, el **qué** queda grueso a propósito y el que
/// discrimina es el **dónde** — que es el diseño: dos bugs distintos casi nunca
/// comparten sitio, y el mismo bug casi siempre lo comparte.
///
/// Las categorías que NO son de ejecución van primero porque no son
/// comparables con las otras: un error interno del motor es su propia historia,
/// y que un motor rechace la tx mientras el otro la ejecuta también.
const KIND_PRIORITY: &[&str] = &[
    "ours.internal",
    "tx.validity",
    "gas_used",
    "status",
    "output",
    "logs.count",
    "log.address",
    "log.topics",
    "log.data",
    "refund",
    "post.storage",
    "post.code",
    "post.nonce",
    "post.balance",
    "post.extra",
    "post.missing",
];

/// La categoría dominante del conjunto: **una sola**, no el conjunto entero.
///
/// El conjunto completo sigue existiendo (`signature`) y se reporta como
/// sub-firma; lo que no puede es ser la clave, porque el mismo bug produce
/// conjuntos distintos según cuánto arrastre cada caso. Medido sobre la
/// campaña de 033: una sola causa (EIP-7610) generó **12** conjuntos distintos.
pub fn primary_kind(differences: &[String]) -> &'static str {
    let kinds: Vec<&'static str> = differences.iter().map(|m| difference_kind(m)).collect();
    if kinds.is_empty() {
        return "vacia";
    }
    for candidate in KIND_PRIORITY {
        if kinds.contains(candidate) {
            return candidate;
        }
    }
    // Un mensaje que `difference_kind` no sabe nombrar no se disuelve en un
    // balde conocido: se queda con su propia clave y el test lo exige.
    UNCLASSIFIED
}

/// Cuánto del motivo de un veredicto entra a la clave. Acotado y nombrado:
/// el motivo sale de un `Display` que nadie le prometió a nadie mantener
/// corto, y una clave sin tope es un recurso alimentado por input externo.
const MAX_VERDICT_SITE: usize = 120;

/// El sitio de una divergencia que **no es de ejecución**, derivado del
/// veredicto en vez de la traza.
///
/// Existe porque el sitio por traza ahí no significa nada, y está medido: una
/// mutación de fork llevó una tx de 9 blobs de Prague a Cancun, nosotros la
/// rechazamos por el tope y revm la ejecutó. Las dos trazas existen —la
/// nuestra porque `trace_tx` no valida— pero **una de las dos no debería estar
/// corriendo**, así que dónde se separan es una función de lo que el fee de
/// blob no descontado perturbó. La misma causa salía en tres sitios distintos
/// (`fuera-de-traza`, `op:SSTORE`, `op:POP`): fragmentación pura.
///
/// El motivo entra con los **valores borrados**: la forma sí, el valor no —
/// que es exactamente lo que M4 del §5 prohíbe meter. Sin el motivo, todo
/// rechazo caería en un solo balde y un rechazo INDEBIDO de una tx válida
/// —la dirección peligrosa— quedaría escondido detrás de una divergencia
/// deliberada.
pub fn verdict_site(differences: &[String]) -> Option<String> {
    let message = differences.first()?;
    let (direction, reason) = if message.starts_with(crate::oracle::VERDICT_OURS_INTERNAL) {
        ("error-interno", message.as_str())
    } else if message.starts_with(crate::oracle::VERDICT_TX_VALIDITY) {
        if message.contains("nuestro la RECHAZA") {
            ("rechazamos", message.as_str())
        } else {
            ("rechaza-el-oráculo", message.as_str())
        }
    } else {
        return None;
    };
    let shape = erase_values(reason_of(reason));
    Some(format!(
        "{direction}:{}",
        shape.chars().take(MAX_VERDICT_SITE).collect::<String>()
    ))
}

/// El motivo que viaja entre paréntesis en el mensaje del veredicto. Sin
/// paréntesis, el mensaje entero.
fn reason_of(message: &str) -> &str {
    let Some(open) = message.find('(') else {
        return message;
    };
    let Some(close) = message.rfind(')') else {
        return message;
    };
    message
        .get(open.saturating_add(1)..close)
        .unwrap_or(message)
}

/// Borra los VALORES y deja la FORMA: cada corrida de dígitos (y cada literal
/// hexadecimal) se colapsa a `#`.
///
/// Es la línea exacta que M4 del §5 dibuja: `gas_used: nuestro 1 vs revm 2` y
/// `gas_used: nuestro 9 vs revm 8` tienen que ser el mismo sitio, o un solo bug
/// se parte en tantos clusters como valores distintos produzca.
fn erase_values(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_value = false;
    while let Some(c) = chars.next() {
        let starts_hex = c == '0' && matches!(chars.peek(), Some('x' | 'X'));
        if starts_hex {
            let _ = chars.next();
            while chars.peek().is_some_and(char::is_ascii_hexdigit) {
                let _ = chars.next();
            }
            if !in_value {
                out.push('#');
                in_value = true;
            }
            continue;
        }
        if c.is_ascii_digit() {
            if !in_value {
                out.push('#');
                in_value = true;
            }
            continue;
        }
        in_value = false;
        out.push(c);
    }
    out
}

/// La clave de cluster: **qué** (grueso) + **dónde** (fino).
///
/// Las dos mitades son load-bearing y el §5 lo prueba por separado: sin el
/// sitio, tres bugs distintos caen en el mismo balde (fusión); con el valor
/// crudo de la diferencia adentro, un solo bug se parte en cientos
/// (fragmentación).
pub fn cluster_key(differences: &[String], site: &str) -> String {
    format!("{}@{}", primary_kind(differences), site)
}

/// Un nombre de archivo seguro para la firma (va a `fixtures/diff/`).
pub fn signature_slug(signature: &str) -> String {
    signature
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use repo_b_common::primitives::{Address, B256, Bytes, U256};

    use super::*;
    use crate::fixture::FixtureAccount;
    use crate::oracle::{LogRecord, Status, Summary, compare};

    const ALICE: Address = Address::new([0xAA; 20]);
    const BOB: Address = Address::new([0xBB; 20]);

    fn account(
        balance: u64,
        nonce: u64,
        code: &'static [u8],
        slots: &[(u64, u64)],
    ) -> FixtureAccount {
        FixtureAccount {
            balance: U256::from(balance),
            nonce,
            code: Bytes::from_static(code),
            storage: slots
                .iter()
                .map(|(k, v)| (U256::from(*k), U256::from(*v)))
                .collect(),
        }
    }

    fn base() -> Summary {
        let mut post = BTreeMap::new();
        post.insert(ALICE, account(10, 1, b"\x00", &[(1, 1)]));
        Summary {
            status: Status::Success,
            gas_used: 21_000,
            gas_refunded: 0,
            output: Bytes::new(),
            logs: vec![LogRecord {
                address: ALICE,
                topics: vec![B256::with_last_byte(1)],
                data: Bytes::from_static(b"\x01"),
            }],
            post,
        }
    }

    /// La prueba de que la taxonomía está ATADA al comparador y no a una
    /// creencia sobre cómo escribe sus mensajes: cada mutación de un campo
    /// pasa por `compare` de verdad, y el mensaje que sale tiene que caer en
    /// la categoría esperada. Si alguien reescribe un mensaje, esto se rompe.
    #[test]
    fn every_message_the_comparator_can_produce_has_a_category() {
        /// Una mutación de un campo del `Summary`, con la categoría que
        /// `difference_kind` tiene que devolver para el mensaje que produzca.
        type FieldMutation = (&'static str, Box<dyn Fn(&mut Summary)>);

        let mut mutations: Vec<FieldMutation> = Vec::new();
        mutations.push((
            "status",
            Box::new(|s: &mut Summary| s.status = Status::Halt),
        ));
        mutations.push(("gas_used", Box::new(|s: &mut Summary| s.gas_used = 1)));
        mutations.push(("refund", Box::new(|s: &mut Summary| s.gas_refunded = 7)));
        mutations.push((
            "output",
            Box::new(|s: &mut Summary| s.output = Bytes::from_static(b"\xff")),
        ));
        mutations.push(("logs.count", Box::new(|s: &mut Summary| s.logs.clear())));
        mutations.push((
            "log.address",
            Box::new(|s: &mut Summary| {
                if let Some(log) = s.logs.first_mut() {
                    log.address = BOB;
                }
            }),
        ));
        mutations.push((
            "log.topics",
            Box::new(|s: &mut Summary| {
                if let Some(log) = s.logs.first_mut() {
                    log.topics = vec![B256::with_last_byte(9)];
                }
            }),
        ));
        mutations.push((
            "log.data",
            Box::new(|s: &mut Summary| {
                if let Some(log) = s.logs.first_mut() {
                    log.data = Bytes::from_static(b"\x09");
                }
            }),
        ));
        mutations.push((
            "post.balance",
            Box::new(|s: &mut Summary| {
                if let Some(a) = s.post.get_mut(&ALICE) {
                    a.balance = U256::from(99u64);
                }
            }),
        ));
        mutations.push((
            "post.nonce",
            Box::new(|s: &mut Summary| {
                if let Some(a) = s.post.get_mut(&ALICE) {
                    a.nonce = 42;
                }
            }),
        ));
        mutations.push((
            "post.code",
            Box::new(|s: &mut Summary| {
                if let Some(a) = s.post.get_mut(&ALICE) {
                    a.code = Bytes::from_static(b"\x60\x01");
                }
            }),
        ));
        mutations.push((
            "post.storage",
            Box::new(|s: &mut Summary| {
                if let Some(a) = s.post.get_mut(&ALICE) {
                    a.storage.insert(U256::from(1u64), U256::from(5u64));
                }
            }),
        ));
        mutations.push((
            "post.extra",
            Box::new(|s: &mut Summary| {
                s.post.insert(BOB, account(1, 1, b"\x00", &[]));
            }),
        ));
        mutations.push((
            "post.missing",
            Box::new(|s: &mut Summary| {
                s.post.remove(&ALICE);
            }),
        ));

        for (expected, mutate) in mutations {
            let mut ours = base();
            mutate(&mut ours);
            let differences = compare(&ours, &base());
            assert!(
                !differences.is_empty(),
                "la mutación {expected} no produjo diferencia"
            );
            for message in &differences {
                assert_ne!(
                    difference_kind(message),
                    UNCLASSIFIED,
                    "mensaje sin categoría: {message}"
                );
            }
            assert!(
                signature(&differences).contains(expected),
                "firma {} sin {expected}",
                signature(&differences)
            );
        }
    }

    /// La firma es un CONJUNTO: el mismo bug visto en dos órdenes es el mismo
    /// bug, y un campo repetido no lo duplica.
    #[test]
    fn the_signature_is_an_order_free_set() {
        let a = vec![
            "gas_used: nuestro 1 vs revm 2 (delta -1)".to_owned(),
            "status: nuestro Halt vs revm Success".to_owned(),
        ];
        let b = vec![
            "status: nuestro Halt vs revm Success".to_owned(),
            "gas_used: nuestro 9 vs revm 8 (delta 1)".to_owned(),
            "gas_used: nuestro 9 vs revm 8 (delta 1)".to_owned(),
        ];
        assert_eq!(signature(&a), signature(&b));
        assert_eq!(signature(&a), "gas_used+status");
    }

    /// El otro productor de mensajes es `diff::verdict`, y sus mensajes NO
    /// pasan por `compare`. El test no repite los prefijos: los toma de la
    /// misma constante que escribe el veredicto, así que reescribir uno sin
    /// tocar el triage rompe acá en vez de degradarse a `sin-clasificar` en
    /// silencio (que es lo que estaba pasando: 5 casos de EEST medidos).
    #[test]
    fn every_verdict_message_has_a_category_too() {
        assert!(!crate::oracle::VERDICT_PREFIXES.is_empty());
        for prefix in crate::oracle::VERDICT_PREFIXES {
            let message = format!("{prefix}: lo que siga no cambia la categoría");
            assert_ne!(
                difference_kind(&message),
                UNCLASSIFIED,
                "el veredicto produce un mensaje sin categoría: {message}"
            );
        }
    }

    #[test]
    fn an_unknown_message_is_never_silently_folded_into_a_known_bucket() {
        assert_eq!(difference_kind("algo completamente nuevo"), UNCLASSIFIED);
        assert_eq!(signature(&[]), "vacia");
    }

    /// **La prioridad de `gas_used` sobre `status` es una decisión medida, no
    /// un gusto.** Un bug de gas hace que unos casos se queden sin gas y otros
    /// no; si `status` ganara, ese solo bug se partiría en dos clusters, que es
    /// lo que M2 del §5 prohíbe.
    #[test]
    fn gas_beats_status_so_one_gas_bug_is_one_cluster() {
        let with_oog = vec![
            "status: nuestro Halt vs revm Success".to_owned(),
            "gas_used: nuestro 1 vs revm 2 (delta -1)".to_owned(),
        ];
        let without_oog = vec!["gas_used: nuestro 9 vs revm 8 (delta 1)".to_owned()];
        assert_eq!(primary_kind(&with_oog), "gas_used");
        assert_eq!(primary_kind(&without_oog), "gas_used");
        assert_eq!(
            cluster_key(&with_oog, "op:ADD"),
            cluster_key(&without_oog, "op:ADD"),
        );
    }

    /// La clave lleva **las dos** mitades, y un cambio en cualquiera la mueve.
    /// Es la forma de M3 y M4 del §5 puesta como test: sin el sitio, dos bugs
    /// distintos comparten clave; sin la categoría, dos bugs en el mismo opcode
    /// también.
    #[test]
    fn both_halves_of_the_key_are_load_bearing() {
        let gas = vec!["gas_used: nuestro 1 vs revm 2 (delta -1)".to_owned()];
        let logs = vec!["log[0]: topics [a] vs [b]".to_owned()];
        assert_ne!(cluster_key(&gas, "op:ADD"), cluster_key(&gas, "op:MUL"));
        assert_ne!(cluster_key(&gas, "op:ADD"), cluster_key(&logs, "op:ADD"));
        assert!(cluster_key(&gas, "op:ADD").contains("gas_used"));
        assert!(cluster_key(&gas, "op:ADD").contains("op:ADD"));
    }

    /// **La forma sí, el valor no.** Dos rechazos por la misma regla con
    /// números distintos son el mismo sitio; con el número adentro, un solo bug
    /// daría un cluster por caso (M4 medido: 197 divergencias → 187 clusters).
    #[test]
    fn the_verdict_site_keeps_the_shape_and_drops_the_value() {
        let first = vec![format!(
            "{}: nuestro la RECHAZA (consensus error: intrinsic gas too low: \
             required 21000, available 20000) y revm la ejecuta",
            crate::oracle::VERDICT_TX_VALIDITY
        )];
        let second = vec![format!(
            "{}: nuestro la RECHAZA (consensus error: intrinsic gas too low: \
             required 53000, available 0x2f) y revm la ejecuta",
            crate::oracle::VERDICT_TX_VALIDITY
        )];
        let Some(a) = verdict_site(&first) else {
            panic!("un mensaje de validez tiene que tener sitio");
        };
        let Some(b) = verdict_site(&second) else {
            panic!("un mensaje de validez tiene que tener sitio");
        };
        assert_eq!(a, b, "el sitio cambió con el valor");
        assert!(a.starts_with("rechazamos:"), "{a}");
        assert!(a.contains("intrinsic gas too low"), "{a}");
        assert!(!a.contains("21000"), "{a}");
    }

    /// La dirección importa: que nosotros rechacemos una tx que revm ejecuta y
    /// que revm rechace una que nosotros ejecutamos son divergencias
    /// **opuestas**, y una de las dos es la peligrosa.
    #[test]
    fn the_verdict_site_separates_who_rejected() {
        let ours = vec![format!(
            "{}: nuestro la RECHAZA (consensus error: x) y revm la ejecuta",
            crate::oracle::VERDICT_TX_VALIDITY
        )];
        let theirs = vec![format!(
            "{}: nuestro la ejecuta y revm la RECHAZA (consensus error: x)",
            crate::oracle::VERDICT_TX_VALIDITY
        )];
        assert_ne!(verdict_site(&ours), verdict_site(&theirs));
    }

    /// Una divergencia de EJECUCIÓN no tiene sitio de veredicto: el sitio se lo
    /// da la traza. Sin este `None`, el camino caro nunca correría.
    #[test]
    fn an_execution_divergence_has_no_verdict_site() {
        let gas = vec!["gas_used: nuestro 1 vs revm 2 (delta -1)".to_owned()];
        assert_eq!(verdict_site(&gas), None);
        assert_eq!(verdict_site(&[]), None);
    }

    #[test]
    fn the_slug_is_a_safe_file_name() {
        assert_eq!(signature_slug("gas_used+log.topics"), "gas-used-log-topics");
    }
}
