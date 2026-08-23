//! El caso diferencial completo: cuentas, tx y fork alrededor de un programa
//! de la gramática.
//!
//! El seam del juez es `diff::run_case(&StateTest, &PostCase)`, y
//! los dos tipos son `pub` con campos `pub`: **el generador construye casos en
//! memoria y no toca disco**. `FuzzCase` es la forma intermedia — la que el
//! shrinker reduce y el emisor serializa —, y `to_state_test` es el único
//! puente hacia el juez.

use std::collections::BTreeMap;

use repo_b_common::primitives::{Address, B256, U256};
use repo_b_evm::types::Spec;

use crate::fixture::{FixtureAccount, PostCase, RawEnv, RawTransaction, StateTest};
use crate::fuzz::corpus::Corpus;
use crate::fuzz::grammar::{AddressPool, MAX_PROGRAM_STEPS, generate_program};
use crate::fuzz::program::Program;
use crate::fuzz::rng::Rng;

/// El EOA que firma. Sin código: una tx desde una cuenta con código exige
/// EIP-3607/7702 y eso ya tiene su set (`set-code`).
pub const SENDER: Address = Address::new([0xA0; 20]);
/// El contrato al que apunta la tx por defecto.
pub const TARGET: Address = Address::new([0xB0; 20]);
/// Contratos auxiliares: destino de `CALL`/`EXTCODE*` con código propio.
pub const AUX_ONE: Address = Address::new([0xC0; 20]);
pub const AUX_TWO: Address = Address::new([0xD0; 20]);
/// Una dirección que NO está en el pre-state: cuenta inexistente para
/// `BALANCE`/`EXTCODEHASH`/`CALL` (EIP-161 y `G_newaccount` viven ahí).
pub const ABSENT: Address = Address::new([0xE0; 20]);
/// Precompile `IDENTITY`: la más barata de llamar de las que existen en los
/// cuatro forks del scope.
pub const IDENTITY_PRECOMPILE: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4]);
pub const COINBASE: Address = Address::new([0xCC; 20]);

/// Balance del sender. Grande, para que ninguna tx se caiga por fondos y el
/// caso pruebe lo que dice probar.
const SENDER_BALANCE: u128 = 1_000_000_000_000_000_000_000;
const CONTRACT_BALANCE: u128 = 1_000_000_000_000_000;
const GAS_PRICE: u128 = 10;
const BASE_FEE: u64 = 10;
const BLOCK_GAS_LIMIT: u64 = 30_000_000;
/// Número de bloque. Chico a propósito: la ventana de `BLOCKHASH` es
/// `[number-256, number-1]`, y el pre-state tiene que traer un hash por cada
/// ancestro de la ventana — con 256 el fixture emitido sería casi todo tabla
/// de hashes. Con 16, la ventana entera entra en 16 entradas y `BLOCKHASH`
/// se ejercita igual, adentro y afuera del rango.
const BLOCK_NUMBER: u64 = 16;
const BLOCK_TIMESTAMP: u64 = 1_000;
const CHAIN_ID: u64 = 1;
/// Presupuesto de gas de la tx. Generoso por default: un caso que muere de
/// OOG en el opcode 3 no ejercita los 60 siguientes.
const GENEROUS_GAS: u64 = 2_000_000;
/// Presupuesto apretado: el borde de OOG es donde una tabla de gas equivocada
/// cambia el *status* y no solo el `gas_used`.
const TIGHT_GAS_MIN: u64 = 21_000;
const TIGHT_GAS_MAX: u64 = 60_000;
const MAX_CALLDATA: usize = 64;

/// Una cuenta del pre-state generado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzAccount {
    pub address: Address,
    pub program: Program,
    pub balance: U256,
    pub nonce: u64,
    pub storage: BTreeMap<U256, U256>,
}

/// El caso, en la forma que el shrinker reduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCase {
    pub seed: u64,
    pub index: u64,
    pub spec: Spec,
    pub accounts: Vec<FuzzAccount>,
    /// `None` ⇒ tx de creación: el calldata es el initcode.
    pub to: Option<Address>,
    pub calldata: Vec<u8>,
    pub value: U256,
    pub gas_limit: u64,
}

/// El hash del ancestro `number`. Determinista y distinto para cada bloque:
/// dos ancestros con el mismo hash harían indistinguible un `BLOCKHASH` que
/// lee el bloque equivocado.
fn ancestor_hash(number: u64) -> B256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xB1;
    bytes[24..].copy_from_slice(&number.to_be_bytes());
    B256::new(bytes)
}

/// Nombre del fork tal como lo espera `spec_for_fork`.
pub const fn fork_name(spec: Spec) -> &'static str {
    match spec {
        Spec::Paris => "Paris",
        Spec::Shanghai => "Shanghai",
        Spec::Cancun => "Cancun",
        Spec::Prague => "Prague",
    }
}

const FORKS: &[(Spec, u32)] = &[
    // Prague y Cancun pesan más: son el fork objetivo del motor y el que más
    // reglas nuevas trae. Paris y Shanghai entran igual porque una regla
    // gateada por fork puede estar mal en el fork VIEJO (medido en su momento:
    // 60 casos exactamente así).
    (Spec::Prague, 10),
    (Spec::Cancun, 7),
    (Spec::Shanghai, 3),
    (Spec::Paris, 3),
];

impl FuzzCase {
    /// El puente al juez. Reconstruye el `StateTest` desde cero en cada
    /// llamada: el shrinker muta el `FuzzCase` y necesita que el `StateTest`
    /// sea función pura de él, no un caché que se pueda desincronizar.
    pub fn to_state_test(&self) -> StateTest {
        let mut pre: BTreeMap<Address, FixtureAccount> = BTreeMap::new();
        pre.insert(
            SENDER,
            FixtureAccount {
                balance: U256::from(SENDER_BALANCE),
                nonce: 0,
                code: repo_b_common::primitives::Bytes::new(),
                storage: BTreeMap::new(),
            },
        );
        for account in &self.accounts {
            pre.insert(
                account.address,
                FixtureAccount {
                    balance: account.balance,
                    nonce: account.nonce,
                    code: account.program.assemble().into(),
                    storage: account.storage.clone(),
                },
            );
        }
        StateTest {
            name: format!("fuzz/{:#018x}/{}", self.seed, self.index),
            chain_id: CHAIN_ID,
            env: RawEnv {
                coinbase: COINBASE,
                number: BLOCK_NUMBER,
                timestamp: BLOCK_TIMESTAMP,
                gas_limit: BLOCK_GAS_LIMIT,
                base_fee: Some(BASE_FEE),
                prevrandao: Some(B256::with_last_byte(0x42)),
                // Presente en los cuatro forks: `OwnVm` solo lo mira desde
                // Cancun, y pasarlo siempre mantiene el caso idéntico entre
                // forks salvo por la regla que se está probando.
                excess_blob_gas: Some(0),
                // La ventana COMPLETA de `BLOCKHASH`. Sin esto, los dos
                // motores no reciben la misma información: `MemoryState` es
                // fail-closed ante un ancestro que el fixture no declara
                // (y hace bien) mientras el `CacheDB` de revm devuelve cero
                // — la primera campaña midió 587 divergencias que eran
                // exactamente esa asimetría del harness, no del consenso.
                block_hashes: (0..BLOCK_NUMBER).map(|n| (n, ancestor_hash(n))).collect(),
            },
            pre,
            tx: RawTransaction {
                // El fuzzer no firma: sus casos no ejercitan la derivación del
                // sender, y el round-trip del codec los saltea contándolos.
                secret_key: None,
                authorization_signatures: None,
                sender: SENDER,
                to: self.to,
                nonce: 0,
                gas_price: Some(GAS_PRICE),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                data: vec![self.calldata.clone().into()],
                gas_limit: vec![self.gas_limit],
                value: vec![self.value],
                access_lists: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                authorization_list: None,
            },
            posts: vec![self.post_case()],
        }
    }

    /// El `PostCase` del caso. `hash`/`logs` en cero **no es un descuido**: el
    /// juez del diferencial es revm in-process, no el fixture — el mismo
    /// convenio que documenta `fixtures/diff/README.md`.
    pub fn post_case(&self) -> PostCase {
        PostCase {
            fork: fork_name(self.spec).to_owned(),
            data_index: 0,
            gas_index: 0,
            value_index: 0,
            state_root: B256::ZERO,
            logs_hash: B256::ZERO,
            expected_state: None,
            expect_exception: None,
        }
    }

    /// Tamaño del caso, para medir si el shrinker converge. Es la suma de
    /// todo lo que el shrinker puede reducir, no solo el bytecode.
    pub fn size(&self) -> usize {
        self.accounts
            .iter()
            .map(|account| account.program.len().saturating_add(account.storage.len()))
            .sum::<usize>()
            .saturating_add(self.calldata.len())
            .saturating_add(self.accounts.len())
    }
}

/// Cada cuántos casos se siembra el programa del target desde el corpus de
/// `fixtures/diff/` en vez de generarlo entero. Uno de cada cuatro: bastante
/// para llegar a las reglas que esos programas ya ejercitan, poco para no
/// convertir la campaña en un re-run del set que ya está en el gate.
const CORPUS_SPLICE_ODDS: u64 = 4;
/// Instrucciones de gramática que se le agregan a un programa del corpus. Sin
/// la cola, el caso sería el fixture original con otro escenario y el fuzzer
/// no estaría explorando nada nuevo.
const CORPUS_TAIL_STEPS: usize = 10;

/// El caso `index` de la campaña `seed`, **sin siembra**. Solo lo usan los
/// tests: la campaña siempre pasa el corpus (vacío o no) explícito, porque el
/// corpus es parte de lo que determina el caso.
#[cfg(test)]
pub fn generate_case(seed: u64, index: u64) -> FuzzCase {
    generate_case_with(seed, index, &Corpus::default())
}

/// El caso `index` de la campaña `seed`. **Función pura de los tres
/// argumentos**: es lo que hace que un hallazgo se reproduzca con
/// `--seed`/`--case`. El corpus entra como argumento y no como global
/// justamente por eso — un corpus que cambia sin que nadie lo note cambiaría
/// los casos en silencio.
pub fn generate_case_with(seed: u64, index: u64, corpus: &Corpus) -> FuzzCase {
    let mut rng = Rng::for_case(seed, index);

    let weights: Vec<u32> = FORKS.iter().map(|(_, weight)| *weight).collect();
    let spec = rng
        .weighted(&weights)
        .and_then(|i| FORKS.get(i))
        .map_or(Spec::Prague, |(spec, _)| *spec);

    // Las tres cuentas con código se generan SIEMPRE, aunque el programa de la
    // tx no llame a ninguna: que existan es lo que hace que un `CALL` a una
    // dirección del pool encuentre código en vez de una cuenta vacía.
    let pool_seed = AddressPool {
        addresses: vec![
            SENDER,
            TARGET,
            AUX_ONE,
            AUX_TWO,
            ABSENT,
            IDENTITY_PRECOMPILE,
            COINBASE,
        ],
    };
    let mut accounts = vec![
        contract(&mut rng, &pool_seed, spec, TARGET, MAX_PROGRAM_STEPS),
        contract(&mut rng, &pool_seed, spec, AUX_ONE, 12),
        contract(&mut rng, &pool_seed, spec, AUX_TWO, 8),
    ];

    // Siembra: un programa escrito a mano para ejercitar una regla puntual,
    // dentro de un escenario nuevo. Es splicing, la técnica estándar de un
    // fuzzer de bytecode — y el sorteo pasa por el mismo `rng`, así que el
    // caso sigue siendo función de `(seed, índice, corpus)`.
    if !corpus.is_empty() && rng.chance(1, CORPUS_SPLICE_ODDS) {
        let pick = usize::try_from(rng.below(corpus.len() as u64)).unwrap_or(0);
        if let Some(seeded) = corpus.programs.get(pick) {
            let mut spliced = seeded.clone();
            let mut tail = generate_program(&mut rng, &pool_seed, spec, CORPUS_TAIL_STEPS);
            // Los ids del sembrado son sus `pc` originales; los de la cola
            // arrancan en 0. Sin renumerar, un salto de la cola caería en una
            // etiqueta del cuerpo sembrado.
            tail.shift_labels(spliced.max_label().map_or(0, |max| max.saturating_add(1)));
            spliced.instructions.extend(tail.instructions);
            if let Some(target) = accounts.first_mut() {
                target.program = spliced;
            }
        }
    }

    // Una tx de creación cada 8: el frame raíz con initcode es una superficie
    // de consenso propia (EIP-3860/170/3541) y sin esto no se toca nunca.
    let to = if rng.chance(1, 8) { None } else { Some(TARGET) };

    let calldata = match to {
        // Tx de creación: el calldata ES el initcode, así que sale de la
        // gramática y no de bytes al azar — un initcode aleatorio moriría en
        // el primer byte y el caso probaría solamente el gas intrínseco.
        None => generate_program(&mut rng, &pool_seed, spec, 16).assemble(),
        Some(_) => {
            let len = rng.range(0, MAX_CALLDATA);
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                data.push(u8::try_from(rng.below(256)).unwrap_or(0));
            }
            data
        }
    };

    let gas_limit = if rng.chance(1, 6) {
        TIGHT_GAS_MIN.saturating_add(rng.below(TIGHT_GAS_MAX.saturating_sub(TIGHT_GAS_MIN)))
    } else {
        GENEROUS_GAS
    };

    let value = if rng.chance(1, 3) {
        U256::from(rng.below(1_000))
    } else {
        U256::ZERO
    };

    FuzzCase {
        seed,
        index,
        spec,
        accounts,
        to,
        calldata,
        value,
        gas_limit,
    }
}

fn contract(
    rng: &mut Rng,
    pool: &AddressPool,
    spec: Spec,
    address: Address,
    steps: usize,
) -> FuzzAccount {
    let program = generate_program(rng, pool, spec, steps);
    // Storage pre-poblado: sin esto, TODA transición de EIP-2200 arranca en
    // 0 y las ramas "x→y" y "x→0" (las que llevan refund) no se tocan nunca.
    let mut storage = BTreeMap::new();
    let slots = rng.range(0, 4);
    for _ in 0..slots {
        storage.insert(U256::from(rng.below(8)), U256::from(rng.below(4)));
    }
    FuzzAccount {
        address,
        program,
        balance: U256::from(CONTRACT_BALANCE),
        nonce: 1,
        storage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(seed, índice)` reproduce el caso **exacto**, y lo reproduce sin pasar
    /// por los anteriores. Es la regla dura del determinismo: sin esto, un
    /// hallazgo no es un hallazgo.
    #[test]
    fn seed_and_index_reproduce_the_exact_case() {
        for index in [0u64, 1, 17, 5_000, 1_000_000] {
            let first = generate_case(0xC0FFEE, index);
            let second = generate_case(0xC0FFEE, index);
            assert_eq!(first, second);
        }
    }

    /// Reproducir el caso N no depende de haber generado el N-1: la campaña se
    /// puede repartir por rangos sin coordinación.
    #[test]
    fn a_case_does_not_depend_on_the_ones_before_it() {
        let alone = generate_case(1, 999);
        let mut after_a_run = None;
        for index in 0..1_000 {
            after_a_run = Some(generate_case(1, index));
        }
        assert_eq!(Some(alone), after_a_run);
    }

    /// Distintas semillas producen campañas distintas. Sin esto, `--seed`
    /// sería decorativo.
    #[test]
    fn distinct_seeds_produce_distinct_campaigns() {
        let a = generate_case(1, 0);
        let b = generate_case(2, 0);
        assert_ne!(a, b);
    }

    /// El caso se materializa en un `StateTest` que el runner puede consumir:
    /// fork reconocido, tx con los tres índices en 0, pre-state con el sender.
    #[test]
    fn the_case_materializes_into_a_runnable_state_test() {
        let case = generate_case(7, 3);
        let test = case.to_state_test();
        assert!(crate::fixture::spec_for_fork(&case.post_case().fork).is_some());
        assert!(test.pre.contains_key(&SENDER));
        assert!(test.pre.contains_key(&TARGET));
        assert!(test.transaction_for(&case.post_case()).is_ok());
        assert!(test.require_post_merge_env().is_ok());
    }

    /// El pre-state NO trae la cuenta ausente: si la trajera, `BALANCE` sobre
    /// ella dejaría de probar la rama de cuenta inexistente.
    #[test]
    fn the_absent_address_is_absent() {
        let test = generate_case(11, 11).to_state_test();
        assert!(!test.pre.contains_key(&ABSENT));
    }

    /// Los cuatro forks del scope aparecen en una campaña corta. Un generador
    /// que solo produjera Prague dejaría tres cuartos del gating sin fuzzear.
    #[test]
    fn a_short_campaign_covers_the_four_forks() {
        let mut seen = std::collections::BTreeSet::new();
        for index in 0..200 {
            seen.insert(generate_case(5, index).spec);
        }
        assert_eq!(seen.len(), 4, "forks vistos: {seen:?}");
    }
}
