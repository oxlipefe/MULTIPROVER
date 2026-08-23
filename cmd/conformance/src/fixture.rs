//! Parsing de fixtures EF GeneralStateTests (formato `state_test`).
//!
//! Input hostil hasta validarse: todo campo se parsea con error explícito;
//! nada se asume bien formado. Sin `unwrap`/indexing crudo.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use repo_b_common::access_list::{AccessList, AccessListItem};
use repo_b_common::authorization::{Authorization, AuthorizationList};
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::types::{BlockEnv, Spec};
use repo_b_guest::signature::{Signature, SignedTransaction};
use serde_json::Value;

/// Una cuenta del pre/post-state del fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureAccount {
    pub balance: U256,
    pub nonce: u64,
    pub code: Bytes,
    pub storage: BTreeMap<U256, U256>,
}

/// Un caso de post-state: fork + indexes + hashes esperados.
#[derive(Debug, Clone)]
pub struct PostCase {
    pub fork: String,
    pub data_index: usize,
    pub gas_index: usize,
    pub value_index: usize,
    pub state_root: B256,
    pub logs_hash: B256,
    /// Post-state inline (si el fixture lo trae): permite diff cuenta-a-cuenta.
    pub expected_state: Option<BTreeMap<Address, FixtureAccount>>,
    /// `expectException` de EEST: el fixture declara que la tx es **inválida**
    /// y el cliente DEBE rechazarla. Cuando está, el post-state esperado es el
    /// pre-state intacto (verificado sobre el set: `pre == case.state` en los
    /// 1 863 casos en scope que lo traen) — la tx nunca entra a un bloque, así
    /// que no se cobra fee ni se bumpea nonce.
    ///
    /// El valor es el nombre de la excepción de EEST
    /// (`TransactionException.INTRINSIC_GAS_TOO_LOW`), y puede traer
    /// **alternativas separadas por `|`** cuando el spec admite más de una
    /// razón de rechazo. Se guarda crudo: hoy se usa como sub-clave de cluster
    /// para diagnóstico, no como aserción (ver `runner::run_case`).
    pub expect_exception: Option<String>,
}

/// Un state test parseado (un test-name dentro de un archivo).
#[derive(Debug, Clone)]
pub struct StateTest {
    pub name: String,
    pub chain_id: u64,
    pub env: RawEnv,
    pub pre: BTreeMap<Address, FixtureAccount>,
    pub tx: RawTransaction,
    pub posts: Vec<PostCase>,
}

#[derive(Debug, Clone)]
pub struct RawEnv {
    pub coinbase: Address,
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    /// `None` en fixtures **pre-London** (no existe el campo). Opcional para
    /// que un caso fuera de scope NO mate el parseo del archivo entero: un
    /// mismo `.json` de EEST trae casos de muchos forks, y antes un
    /// caso Berlin tiraba abajo los casos Cancun/Prague vecinos (6 622 casos
    /// invisibles, it.2). El scope lo filtra el fork, y
    /// `require_post_merge_env` falla ruidosamente si un caso EN scope llega
    /// sin estos campos — no hay default silencioso donde importa.
    pub base_fee: Option<u64>,
    /// `None` en fixtures **pre-Merge** (ahí venía `currentDifficulty`).
    pub prevrandao: Option<B256>,
    pub excess_blob_gas: Option<u64>,
    /// Hashes de bloques ancestros para `BLOCKHASH`. NO es campo
    /// EF: extensión propia de `fixtures/diff/` (opcional, `{}` si se omite —
    /// los fixtures vendoreados de `GeneralStateTests/` no lo traen).
    pub block_hashes: BTreeMap<u64, B256>,
}

#[derive(Debug, Clone)]
pub struct RawTransaction {
    pub sender: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub data: Vec<Bytes>,
    pub gas_limit: Vec<u64>,
    pub value: Vec<U256>,
    /// EIP-2930. `None` = el fixture no trae `accessLists` en
    /// absoluto (tx legacy/1559 clásica). `Some(lista)` = el campo está
    /// presente (aunque una entrada individual sea `[]`): eso es lo que
    /// distingue "tx 2930 con AL vacía" de "tx legacy sin AL" — mismo costo
    /// de gas, `tx_type` distinto.
    pub access_lists: Option<Vec<AccessList>>,
    /// EIP-4844. Campo escalar (NO indexado por `data_index`,
    /// igual que `gasPrice`/`maxFeePerGas`): así lo trae el fixture EF real
    /// para una tx de blob. `None` = el fixture no trae `maxFeePerBlobGas`
    /// (tx no-4844).
    pub max_fee_per_blob_gas: Option<u128>,
    /// EIP-4844. Igual que `max_fee_per_blob_gas`: escalar, no
    /// indexado. `None` = el fixture no trae `blobVersionedHashes` en
    /// absoluto (distinto de `Some(vec![])`, que sería una tx 4844 inválida
    /// por blobs vacíos — caso cubierto por unit test, no por el diferencial:
    /// ver `own_vm::tests::blob_tx_with_empty_hashes_is_rejected`).
    pub blob_versioned_hashes: Option<Vec<B256>>,
    /// EIP-7702. Escalar, no indexado. Su sola PRESENCIA marca la
    /// tx como `Eip7702`. Cada tupla trae el `authority` **ya recuperado**
    /// (`null` = firma inválida): el diferencial no hace ECDSA — se lo inyecta
    /// igual a los dos motores (revm acepta `RecoveredAuthorization`).
    pub authorization_list: Option<AuthorizationList>,
    /// **La clave privada con la que el fixture firmó.** Un `state_test` NO
    /// publica `v`/`r`/`s`: publica la clave y espera que el cliente firme. Es
    /// lo único que permite que este eje ejercite la derivación del sender, y
    /// el contraste sigue siendo independiente porque el `sender` declarado
    /// **no** sale de acá. `None` = no se puede construir un envelope firmado
    /// (los fixtures propios de `fixtures/diff/`); se saltea y se cuenta.
    pub secret_key: Option<B256>,
    /// Las MISMAS tuplas de `authorization_list`, con su firma cruda. Existen
    /// aparte por la misma razón que en el eje de bloques: el motor recibe el
    /// `authority` ya resuelto y nunca ve la firma, pero el envelope la lleva.
    pub authorization_signatures: Option<Vec<(U256, U256, U256)>>,
}

impl StateTest {
    /// Materializa la `Transaction` de un `PostCase` (indexes → data/gas/value).
    pub fn transaction_for(&self, case: &PostCase) -> Result<Transaction, String> {
        let input = self
            .tx
            .data
            .get(case.data_index)
            .cloned()
            .ok_or_else(|| format!("data index {} fuera de rango", case.data_index))?;
        let gas_limit = *self
            .tx
            .gas_limit
            .get(case.gas_index)
            .ok_or_else(|| format!("gas index {} fuera de rango", case.gas_index))?;
        let value = *self
            .tx
            .value
            .get(case.value_index)
            .ok_or_else(|| format!("value index {} fuera de rango", case.value_index))?;
        // La presencia del campo `accessLists` (no su contenido: una entrada
        // `[]` sigue siendo EIP-2930) es lo que distingue una tx 2930 de una
        // legacy clásica — EIP-2718 tipa esto a nivel de encoding, y acá no
        // hay decoder RLP que lo derive de otra forma. Igual con los campos
        // de blob: su sola PRESENCIA (no el contenido) es lo que
        // marca una tx `Eip4844`.
        let has_access_list = self.tx.access_lists.is_some();
        let has_blob_fields =
            self.tx.max_fee_per_blob_gas.is_some() || self.tx.blob_versioned_hashes.is_some();
        // EIP-7702: `authorizationList` presente ⇒ tx tipo 4. A
        // diferencia de 4844, SÍ puede venir con `accessLists` (revm cuenta la
        // AL de todo tipo no-legacy en el gas intrínseco).
        let tx_type = if self.tx.authorization_list.is_some() {
            if has_blob_fields {
                return Err("authorizationList con campos de blob: tx malformada".into());
            }
            match (self.tx.gas_price, self.tx.max_fee_per_gas) {
                (None, Some(_)) => TxType::Eip7702,
                _ => return Err("authorizationList sin maxFeePerGas: tx malformada".into()),
            }
        } else if has_blob_fields {
            // Una tx 4844 lleva access list como
            // cualquier tipo no-legacy, y revm cuenta su AL en el gas
            // intrínseco igual — así que no hay nada especial que gatear.
            match (self.tx.gas_price, self.tx.max_fee_per_gas) {
                (None, Some(_)) => TxType::Eip4844,
                _ => return Err("campos de blob sin maxFeePerGas: tx malformada".into()),
            }
        } else {
            match (self.tx.gas_price, self.tx.max_fee_per_gas, has_access_list) {
                (Some(_), None, false) => TxType::Legacy,
                (Some(_), None, true) => TxType::Eip2930,
                // Una tx tipo 2 CON access list es el caso estándar de
                // EIP-1559, no un borde: el rechazo anterior era un resto de
                // antes de que existiera el soporte de access lists.
                (None, Some(_), _) => TxType::Eip1559,
                _ => return Err("tx con gasPrice y maxFeePerGas inconsistentes".into()),
            }
        };
        let access_list = self
            .tx
            .access_lists
            .as_ref()
            .and_then(|lists| lists.get(case.data_index))
            .cloned()
            .unwrap_or_default();
        Ok(Transaction {
            tx_type,
            sender: self.tx.sender,
            nonce: self.tx.nonce,
            to: self.tx.to,
            value,
            input,
            gas_limit,
            gas_price: self.tx.gas_price,
            max_fee_per_gas: self.tx.max_fee_per_gas,
            max_priority_fee_per_gas: self.tx.max_priority_fee_per_gas,
            access_list,
            max_fee_per_blob_gas: self.tx.max_fee_per_blob_gas,
            blob_versioned_hashes: self.tx.blob_versioned_hashes.clone().unwrap_or_default(),
            authorization_list: self.tx.authorization_list.clone().unwrap_or_default(),
        })
    }

    /// `BlockEnv` para un fork dado.
    /// Los campos post-Merge que un fixture EN SCOPE debe traer sí o sí.
    /// `run_case` lo llama ANTES de ejecutar: un caso Paris+ sin `base_fee` o
    /// sin `prevrandao` es un fixture malformado y falla ruidosamente, en vez
    /// de correr con un default inventado.
    pub fn require_post_merge_env(&self) -> Result<(), String> {
        match (self.env.base_fee, self.env.prevrandao) {
            (Some(_), Some(_)) => Ok(()),
            (None, _) => Err("fixture en scope sin currentBaseFee".to_owned()),
            (_, None) => Err("fixture en scope sin currentRandom".to_owned()),
        }
    }

    pub fn block_env(&self, spec: Spec) -> BlockEnv {
        BlockEnv {
            spec,
            chain_id: self.chain_id,
            number: self.env.number,
            coinbase: self.env.coinbase,
            timestamp: self.env.timestamp,
            gas_limit: self.env.gas_limit,
            // `unwrap_or_default` es seguro acá porque todo caller ejecuta
            // solo casos en scope, y `require_post_merge_env` ya los validó.
            base_fee: self.env.base_fee.unwrap_or_default(),
            prevrandao: self.env.prevrandao.unwrap_or_default(),
            blob_excess_gas: self.env.excess_blob_gas,
            blob_base_fee: None,
            blob_base_fee_update_fraction: None,
        }
    }
}

/// Forks post-Merge soportados por el runner.
pub fn spec_for_fork(fork: &str) -> Option<Spec> {
    match fork {
        "Paris" | "Merge" => Some(Spec::Paris),
        "Shanghai" => Some(Spec::Shanghai),
        "Cancun" => Some(Spec::Cancun),
        "Prague" => Some(Spec::Prague),
        _ => None,
    }
}

/// Parsea todos los state tests de un archivo JSON.
pub fn parse_file(raw: &str) -> Result<Vec<StateTest>, String> {
    let root: Value = serde_json::from_str(raw).map_err(|e| format!("JSON inválido: {e}"))?;
    let map = root.as_object().ok_or("el fixture no es un objeto JSON")?;
    let mut tests = Vec::new();
    for (name, body) in map {
        tests.push(parse_test(name, body).map_err(|e| format!("{name}: {e}"))?);
    }
    Ok(tests)
}

fn parse_test(name: &str, body: &Value) -> Result<StateTest, String> {
    let env = body.get("env").ok_or("falta env")?;
    let chain_id = body
        .get("config")
        .and_then(|c| c.get("chainid"))
        .map(hex_u64)
        .transpose()?
        .unwrap_or(1);
    let raw_env = RawEnv {
        coinbase: hex_address(field(env, "currentCoinbase")?)?,
        number: hex_u64(field(env, "currentNumber")?)?,
        timestamp: hex_u64(field(env, "currentTimestamp")?)?,
        gas_limit: hex_u64(field(env, "currentGasLimit")?)?,
        base_fee: env.get("currentBaseFee").map(hex_u64).transpose()?,
        prevrandao: env.get("currentRandom").map(hex_b256).transpose()?,
        excess_blob_gas: env.get("currentExcessBlobGas").map(hex_u64).transpose()?,
        block_hashes: env
            .get("blockHashes")
            .map(parse_block_hashes)
            .transpose()?
            .unwrap_or_default(),
    };

    let pre = parse_accounts(body.get("pre").ok_or("falta pre")?)?;

    let tx = body.get("transaction").ok_or("falta transaction")?;
    let access_lists = match tx.get("accessLists") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_access_lists(value)?),
    };
    let blob_versioned_hashes = match tx.get("blobVersionedHashes") {
        None | Some(Value::Null) => None,
        Some(value) => Some(hex_array(value, hex_b256)?),
    };
    let authorization_list = match tx.get("authorizationList") {
        None | Some(Value::Null) => None,
        Some(value) => Some(hex_array(value, parse_authorization)?),
    };
    // **Tolerante a propósito, y solo acá.** Los fixtures propios de
    // `fixtures/diff/` publican el `authority` ya recuperado y NO la firma de
    // la tupla, porque se escribieron cuando la recuperación vivía en el
    // harness. Sin firma no hay envelope que construir: el caso se saltea y se
    // cuenta (`SIN_FIRMA`), que es distinto de aceptarlo con una firma
    // inventada. Un fixture de EEST que publique tuplas SIEMPRE trae `r`/`s`.
    let authorization_signatures = match tx.get("authorizationList") {
        None | Some(Value::Null) => None,
        Some(value) => hex_array(value, parse_authorization_signature).ok(),
    };
    let raw_tx = RawTransaction {
        sender: hex_address(field(tx, "sender")?)?,
        to: match field(tx, "to")? {
            v if v.as_str() == Some("") => None,
            v => Some(hex_address(v)?),
        },
        nonce: hex_u64(field(tx, "nonce")?)?,
        gas_price: tx.get("gasPrice").map(hex_gas_price).transpose()?,
        max_fee_per_gas: tx.get("maxFeePerGas").map(hex_gas_price).transpose()?,
        max_priority_fee_per_gas: tx
            .get("maxPriorityFeePerGas")
            .map(hex_gas_price)
            .transpose()?,
        data: hex_array(field(tx, "data")?, hex_bytes)?,
        gas_limit: hex_array(field(tx, "gasLimit")?, hex_u64)?,
        value: hex_array(field(tx, "value")?, hex_u256)?,
        access_lists,
        secret_key: tx.get("secretKey").map(hex_b256).transpose()?,
        authorization_signatures,
        max_fee_per_blob_gas: tx.get("maxFeePerBlobGas").map(hex_u128).transpose()?,
        blob_versioned_hashes,
        authorization_list,
    };

    let post = body
        .get("post")
        .and_then(Value::as_object)
        .ok_or("falta post")?;
    let mut posts = Vec::new();
    for (fork, cases) in post {
        let cases = cases.as_array().ok_or("post no es un array")?;
        for case in cases {
            let indexes = case.get("indexes").ok_or("falta indexes")?;
            posts.push(PostCase {
                fork: fork.clone(),
                data_index: hex_usize(field(indexes, "data")?)?,
                gas_index: hex_usize(field(indexes, "gas")?)?,
                value_index: hex_usize(field(indexes, "value")?)?,
                state_root: hex_b256(field(case, "hash")?)?,
                logs_hash: hex_b256(field(case, "logs")?)?,
                expected_state: case.get("state").map(parse_accounts).transpose()?,
                expect_exception: case
                    .get("expectException")
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or("expectException no es un string")
                    })
                    .transpose()?,
            });
        }
    }

    Ok(StateTest {
        name: name.to_owned(),
        chain_id,
        env: raw_env,
        pre,
        tx: raw_tx,
        posts,
    })
}

/// `accessLists`: array indexado por `data_index` (mismo convenio EF que
/// `data`/`gasLimit`/`value`). Cada entrada es un array de
/// `{address, storageKeys}` (o `null`, tratado como lista vacía — un fixture
/// puede declarar el campo sin poblar todas las variantes).
fn parse_access_lists(value: &Value) -> Result<Vec<AccessList>, String> {
    value
        .as_array()
        .ok_or("accessLists: se esperaba un array")?
        .iter()
        .map(parse_access_list_entry)
        .collect()
}

pub(crate) fn parse_access_list_entry(value: &Value) -> Result<AccessList, String> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let items = value
        .as_array()
        .ok_or("accessLists[i]: se esperaba un array o null")?;
    items
        .iter()
        .map(|item| {
            let storage_keys = field(item, "storageKeys")?
                .as_array()
                .ok_or("accessLists[i].storageKeys: se esperaba un array")?
                .iter()
                .map(hex_b256)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AccessListItem {
                address: hex_address(field(item, "address")?)?,
                storage_keys,
            })
        })
        .collect()
}

/// `secp256k1n / 2` — el bound de EIP-2 sobre `s`, que EIP-7702 hereda para las
/// tuplas de autorización. Mismo valor que
/// `alloy_eip7702::constants::SECP256K1N_HALF`.
const SECP256K1N_HALF: U256 = U256::from_limbs([
    0xdfe92f46681b20a0,
    0x5d576e7357a4501d,
    0xffffffffffffffff,
    0x7fffffffffffffff,
]);

/// Una tupla de `authorizationList` (EIP-7702):
/// `{chainId, address, nonce, authority}`. **`authority` es obligatorio** y
/// puede ser `null` = firma inválida (la tupla se saltea sin invalidar la tx):
/// omitirlo sería indistinguible de un typo, así que es error de parseo —
/// input hostil hasta validarse.
pub(crate) fn parse_authorization(value: &Value) -> Result<Authorization, String> {
    // EEST llama `signer` al authority YA RECUPERADO; los fixtures propios de
    // `fixtures/diff/` lo llaman `authority`. Mismo dato, dos nombres — se
    // aceptan los dos. **No hace falta recuperación ECDSA acá**: el fixture ya
    // trae la dirección, igual que trae `sender` para la tx (el KNOWN
    // sigue igual: la recuperación vive fuera del EVM).
    //
    // Campo AUSENTE = firma inválida (EEST omite `signer` cuando no hay nada
    // que recuperar, p.ej. `r=0`). Es exactamente la semántica de
    // `authority: None`: la tupla se saltea sin invalidar la tx.
    let mut authority = match value.get("authority").or_else(|| value.get("signer")) {
        None | Some(Value::Null) => None,
        Some(raw) => Some(hex_address(raw)?),
    };
    // EIP-2 aplicado a EIP-7702: una firma con `s > secp256k1n/2` **no
    // recupera**. EEST igual publica `signer` en esos casos (el valor es
    // aritméticamente recuperable), así que sin este chequeo la tupla se
    // aplicaría.
    //
    // **Va acá y no en el motor, y eso lo decide el oráculo, no la comodidad:**
    // en `alloy_eip7702::SignedAuthorization::recover_authority` el bound de
    // `s` vive DENTRO de la recuperación, y `into_recovered` mapea el fallo a
    // `RecoveredAuthority::Invalid` — que es exactamente nuestro
    // `authority: None`. La recuperación ECDSA vive fuera del EVM (seam fijado
    // en 2.7c, ECDSA real diferida a Fase 5) y este harness es quien la
    // representa, así que la regla es suya. Meter `r`/`s` en `Authorization`
    // habría metido una regla de recuperación dentro del motor.
    if let Some(raw_s) = value.get("s")
        && hex_u256(raw_s)? > SECP256K1N_HALF
    {
        authority = None;
    }
    Ok(Authorization {
        chain_id: hex_u256(field(value, "chainId")?)?,
        address: hex_address(field(value, "address")?)?,
        nonce: hex_u64(field(value, "nonce")?)?,
        authority,
    })
}

/// La firma cruda de una tupla de autorización, tal cual la publica el fixture.
/// `yParity` es el nombre canónico y `v` el alias; **ninguno se inventa si
/// faltan los dos**, y una firma ausente no es una firma en cero.
fn parse_authorization_signature(value: &Value) -> Result<(U256, U256, U256), String> {
    let y_parity = value
        .get("yParity")
        .or_else(|| value.get("v"))
        .ok_or("tupla de autorización sin yParity ni v")?;
    Ok((
        hex_u256(y_parity)?,
        hex_u256(field(value, "r")?)?,
        hex_u256(field(value, "s")?)?,
    ))
}

/// `blockHashes`: objeto `{ "<numero hex>": "<hash>" }` — extensión propia
/// para `BLOCKHASH` (no es campo EF; ver `RawEnv::block_hashes`).
fn parse_block_hashes(value: &Value) -> Result<BTreeMap<u64, B256>, String> {
    let map = value.as_object().ok_or("blockHashes: no es un objeto")?;
    let mut hashes = BTreeMap::new();
    for (number, hash) in map {
        let stripped = number.strip_prefix("0x").unwrap_or(number);
        let number = u64::from_str_radix(stripped, 16)
            .map_err(|e| format!("blockHashes: número inválido {number}: {e}"))?;
        hashes.insert(number, hex_b256(hash)?);
    }
    Ok(hashes)
}

pub(crate) fn parse_accounts(value: &Value) -> Result<BTreeMap<Address, FixtureAccount>, String> {
    let map = value.as_object().ok_or("cuentas: no es un objeto")?;
    let mut accounts = BTreeMap::new();
    for (addr, acc) in map {
        let mut storage = BTreeMap::new();
        if let Some(slots) = acc.get("storage").and_then(Value::as_object) {
            for (key, val) in slots {
                storage.insert(hex_u256_str(key)?, hex_u256(val)?);
            }
        }
        accounts.insert(
            hex_address_str(addr)?,
            FixtureAccount {
                balance: hex_u256(field(acc, "balance")?)?,
                nonce: hex_u64(field(acc, "nonce")?)?,
                code: hex_bytes(field(acc, "code")?)?,
                storage,
            },
        );
    }
    Ok(accounts)
}

// ---------------------------------------------------------------- helpers hex

pub(crate) fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("falta el campo {name}"))
}

fn as_hex_str(value: &Value) -> Result<&str, String> {
    let s = value.as_str().ok_or("se esperaba string hex")?;
    s.strip_prefix("0x")
        .ok_or_else(|| format!("hex sin prefijo 0x: {s}"))
}

pub(crate) fn hex_u64(value: &Value) -> Result<u64, String> {
    let s = as_hex_str(value)?;
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).map_err(|e| format!("u64 hex inválido {s}: {e}"))
}

pub(crate) fn hex_u128(value: &Value) -> Result<u128, String> {
    let s = as_hex_str(value)?;
    if s.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(s, 16).map_err(|e| format!("u128 hex inválido {s}: {e}"))
}

/// Precio de gas que puede **no entrar en `u128`**.
///
/// `Transaction::gas_price` es `u128` (alineado a revm, que usa el mismo tipo),
/// pero un fixture puede declarar un precio de 30 bytes. Hacer fallar el
/// PARSEO ahí mata el archivo entero y con él sus casos: el fixture
/// `HighGasPriceParis` escondía 2 casos detrás de un solo error de parseo.
///
/// **No se agranda el tipo: se satura, y la saturación preserva la decisión.**
/// El motor calcula `gas_limit · gas_price` en `U256`, así que con
/// `u128::MAX` el balance requerido queda en ~3.4·10^38 wei — unos **doce
/// órdenes de magnitud por encima de TODO el supply de ETH** (~1.2·10^26 wei).
/// Ningún pre-state posible lo cubre, así que la tx se rechaza por
/// `InsufficientBalance` igual que con el valor real, que es más grande
/// todavía. Es exactamente lo que declara el fixture:
/// `INSUFFICIENT_ACCOUNT_FUNDS|GASLIMIT_PRICE_PRODUCT_OVERFLOW`.
///
/// Deliberadamente **no** se usa para campos donde saturar cambiaría el
/// resultado (`value`, `maxFeePerBlobGas`): solo para el precio de gas, donde
/// el argumento de arriba cierra.
pub(crate) fn hex_gas_price(value: &Value) -> Result<u128, String> {
    match hex_u128(value) {
        Ok(price) => Ok(price),
        Err(_) => {
            let s = as_hex_str(value)?;
            // Que sea hex válido pero no entre: cualquier otra cosa es un
            // error de parseo de verdad y sigue fallando.
            if s.chars().all(|c| c.is_ascii_hexdigit()) && !s.is_empty() {
                Ok(u128::MAX)
            } else {
                Err(format!("gas price hex inválido {s}"))
            }
        }
    }
}

fn hex_usize(value: &Value) -> Result<usize, String> {
    // Los indexes de los fixtures son números JSON, no strings hex.
    value
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| format!("index inválido: {value}"))
}

pub(crate) fn hex_u256(value: &Value) -> Result<U256, String> {
    let s = value.as_str().ok_or("se esperaba string hex")?;
    hex_u256_str(s)
}

fn hex_u256_str(s: &str) -> Result<U256, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(stripped, 16).map_err(|e| format!("U256 hex inválido {s}: {e}"))
}

pub(crate) fn hex_b256(value: &Value) -> Result<B256, String> {
    let s = as_hex_str(value)?;
    let bytes: [u8; 32] = decode_hex(s)?
        .try_into()
        .map_err(|_| format!("B256 con longitud incorrecta: 0x{s}"))?;
    Ok(B256::new(bytes))
}

pub(crate) fn hex_address(value: &Value) -> Result<Address, String> {
    let s = value.as_str().ok_or("se esperaba string hex")?;
    hex_address_str(s)
}

fn hex_address_str(s: &str) -> Result<Address, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes: [u8; 20] = decode_hex(stripped)?
        .try_into()
        .map_err(|_| format!("address con longitud incorrecta: {s}"))?;
    Ok(Address::new(bytes))
}

pub(crate) fn hex_bytes(value: &Value) -> Result<Bytes, String> {
    let s = as_hex_str(value)?;
    Ok(Bytes::from(decode_hex(s)?))
}

pub(crate) fn hex_array<T>(
    value: &Value,
    parse: fn(&Value) -> Result<T, String>,
) -> Result<Vec<T>, String> {
    value
        .as_array()
        .ok_or("se esperaba un array")?
        .iter()
        .map(parse)
        .collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex de longitud impar: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i.saturating_add(2))
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("hex inválido: {s}"))
        })
        .collect()
}

/// **El envelope firmado de un `state_test`.**
///
/// Un `state_test` no publica `v`/`r`/`s`: publica `secretKey` y espera que el
/// cliente firme. O sea que acá **el firmante somos nosotros**, y por eso el
/// test se apoya en un oráculo que no lo es: el `sender` que el fixture declara,
/// contra el que se contrasta lo que la firma produce. Firmar es nuestro; el
/// contraste, no.
///
/// # Errors
/// Si el caso no trae `secretKey` (no hay envelope que construir), si la tx no
/// es representable como envelope, o si la clave no es una clave de secp256k1.
pub fn signed_transaction_for(
    test: &StateTest,
    case: &PostCase,
    chain_id: u64,
) -> Result<SignedTransaction, String> {
    let payload = test.transaction_for(case)?;
    let key = test.tx.secret_key.ok_or("el caso no trae secretKey")?;
    let signing =
        SigningKey::from_slice(key.as_slice()).map_err(|e| format!("secretKey inválida: {e}"))?;
    // **La clave tiene que ser la del sender declarado.** Algunos fixtures
    // propios arrastran una `secretKey` decorativa que no corresponde a su
    // `sender` (una dirección inventada, sin clave conocida): firmar con ella
    // produciría OTRA tx, no la del caso. Se saltea y se cuenta.
    //
    // El chequeo NO puede tapar un bug de la derivación de direcciones: si esa
    // derivación estuviera rota, esto fallaría en los 39 025 casos de EEST y el
    // contador de salteados lo gritaría.
    if address_of_key(&signing) != payload.sender {
        return Err("la secretKey no corresponde al sender declarado".to_owned());
    }

    let tuplas = test
        .tx
        .authorization_signatures
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(v, r, s)| Signature { v, r, s })
        .collect::<Vec<_>>();
    if tuplas.len() != payload.authorization_list.len() {
        return Err(format!(
            "{} tuplas de autorización y {} firmas: el fixture no las parea",
            payload.authorization_list.len(),
            tuplas.len()
        ));
    }
    let chain_opt = match payload.tx_type {
        TxType::Legacy => None,
        _ => Some(chain_id),
    };
    // **Dos pasadas y no una**: el `v` de una legacy lleva el `chain_id` y por
    // lo tanto decide QUÉ mensaje se firma, así que hay que fijarlo antes de
    // computar el hash. La primera pasada usa un `v` con la forma correcta y
    // una firma de relleno; solo se le pide el hash.
    let armar =
        |sig: Signature| SignedTransaction::new(payload.clone(), chain_opt, sig, tuplas.clone());
    let relleno = Signature {
        v: match payload.tx_type {
            TxType::Legacy => U256::from(chain_id) * U256::from(2u8) + U256::from(35u8),
            _ => U256::ZERO,
        },
        r: U256::from(1u8),
        s: U256::from(1u8),
    };
    let hash = armar(relleno)
        .signing_hash(chain_id)
        .map_err(|e| format!("la tx no es representable como envelope: {}", e.0))?;
    let (firma, recid) = signing
        .sign_prehash_recoverable(hash.as_slice())
        .map_err(|e| format!("no se pudo firmar: {e}"))?;
    // `k256` produce siempre `s` bajo, así que EIP-2 se cumple por
    // construcción y no por un chequeo que haya que acordarse de hacer.
    let paridad = u64::from(recid.to_byte() & 1);
    let v = match payload.tx_type {
        TxType::Legacy => {
            U256::from(chain_id) * U256::from(2u8) + U256::from(35u8 as u64 + paridad)
        }
        _ => U256::from(paridad),
    };
    Ok(armar(Signature {
        v,
        r: U256::from_be_slice(&firma.r().to_bytes()),
        s: U256::from_be_slice(&firma.s().to_bytes()),
    }))
}

/// La dirección de una clave privada: keccak de los 64 bytes del punto sin
/// comprimir, últimos 20.
fn address_of_key(key: &SigningKey) -> Address {
    let punto = key.verifying_key().to_encoded_point(false);
    let hash = repo_b_common::primitives::keccak256(&punto.as_bytes()[1..]);
    Address::from_slice(&hash.as_slice()[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(s: &str, signer: bool) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("chainId".into(), Value::String("0x01".into()));
        obj.insert(
            "address".into(),
            Value::String(format!("0x{}", "d0".repeat(20))),
        );
        obj.insert("nonce".into(), Value::String("0x00".into()));
        obj.insert("s".into(), Value::String(s.into()));
        if signer {
            obj.insert(
                "signer".into(),
                Value::String(format!("0x{}", "b0".repeat(20))),
            );
        }
        Value::Object(obj)
    }

    /// EIP-2 aplicado a EIP-7702: `s > secp256k1n/2` **no recupera**, así que la
    /// tupla llega al motor con `authority: None` y se saltea.
    ///
    /// Este test existe porque **el diferencial no puede cazar esta regla**: el
    /// harness le inyecta el MISMO `Authorization` ya recuperado a los dos
    /// motores, así que los dos aplican la tupla y coinciden. Solo EEST —que
    /// conoce el root esperado— lo ve, y borrar el chequeo le cuesta 3 casos.
    /// Sin este test, la regla queda sostenida por un número lejano.
    #[test]
    fn an_authorization_with_high_s_does_not_recover_even_if_the_fixture_names_a_signer() {
        // secp256k1n/2 exacto: el último valor VÁLIDO.
        let half = "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
        let Ok(parsed) = parse_authorization(&tuple(half, true)) else {
            panic!("la tupla es parseable: el test estaría midiendo otra cosa")
        };
        assert!(parsed.authority.is_some(), "s == n/2 todavía recupera");

        // n/2 + 1: el primero fuera de rango.
        let over = "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1";
        let Ok(parsed) = parse_authorization(&tuple(over, true)) else {
            panic!("la tupla es parseable: el test estaría midiendo otra cosa")
        };
        assert!(
            parsed.authority.is_none(),
            "s > n/2 no recupera, aunque el fixture publique `signer`"
        );
    }
}
