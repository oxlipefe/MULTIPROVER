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

    #[test]
    fn the_slug_is_a_safe_file_name() {
        assert_eq!(signature_slug("gas_used+log.topics"), "gas-used-log-topics");
    }
}
