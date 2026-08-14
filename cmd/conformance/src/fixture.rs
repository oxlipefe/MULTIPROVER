//! Parsing de fixtures EF GeneralStateTests (formato `state_test`).
//!
//! Input hostil hasta validarse: todo campo se parsea con error explícito;
//! nada se asume bien formado. Sin `unwrap`/indexing crudo.

use std::collections::BTreeMap;

use repo_b_common::access_list::{AccessList, AccessListItem};
use repo_b_common::authorization::{Authorization, AuthorizationList};
use repo_b_common::primitives::{Address, B256, Bytes, U256};
use repo_b_common::transaction::{Transaction, TxType};
use repo_b_evm::types::{BlockEnv, Spec};
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
    let raw_tx = RawTransaction {
        sender: hex_address(field(tx, "sender")?)?,
        to: match field(tx, "to")? {
            v if v.as_str() == Some("") => None,
            v => Some(hex_address(v)?),
        },
        nonce: hex_u64(field(tx, "nonce")?)?,
        gas_price: tx.get("gasPrice").map(hex_u128).transpose()?,
        max_fee_per_gas: tx.get("maxFeePerGas").map(hex_u128).transpose()?,
        max_priority_fee_per_gas: tx.get("maxPriorityFeePerGas").map(hex_u128).transpose()?,
        data: hex_array(field(tx, "data")?, hex_bytes)?,
        gas_limit: hex_array(field(tx, "gasLimit")?, hex_u64)?,
        value: hex_array(field(tx, "value")?, hex_u256)?,
        access_lists,
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

fn parse_access_list_entry(value: &Value) -> Result<AccessList, String> {
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

/// Una tupla de `authorizationList` (EIP-7702):
/// `{chainId, address, nonce, authority}`. **`authority` es obligatorio** y
/// puede ser `null` = firma inválida (la tupla se saltea sin invalidar la tx):
/// omitirlo sería indistinguible de un typo, así que es error de parseo —
/// input hostil hasta validarse.
fn parse_authorization(value: &Value) -> Result<Authorization, String> {
    // EEST llama `signer` al authority YA RECUPERADO; los fixtures propios de
    // `fixtures/diff/` lo llaman `authority`. Mismo dato, dos nombres — se
    // aceptan los dos. **No hace falta recuperación ECDSA acá**: el fixture ya
    // trae la dirección, igual que trae `sender` para la tx (el KNOWN
    // sigue igual: la recuperación vive fuera del EVM).
    //
    // Campo AUSENTE = firma inválida (EEST omite `signer` cuando no hay nada
    // que recuperar, p.ej. `r=0`). Es exactamente la semántica de
    // `authority: None`: la tupla se saltea sin invalidar la tx.
    let authority = match value.get("authority").or_else(|| value.get("signer")) {
        None | Some(Value::Null) => None,
        Some(raw) => Some(hex_address(raw)?),
    };
    Ok(Authorization {
        chain_id: hex_u256(field(value, "chainId")?)?,
        address: hex_address(field(value, "address")?)?,
        nonce: hex_u64(field(value, "nonce")?)?,
        authority,
    })
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

fn parse_accounts(value: &Value) -> Result<BTreeMap<Address, FixtureAccount>, String> {
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

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("falta el campo {name}"))
}

fn as_hex_str(value: &Value) -> Result<&str, String> {
    let s = value.as_str().ok_or("se esperaba string hex")?;
    s.strip_prefix("0x")
        .ok_or_else(|| format!("hex sin prefijo 0x: {s}"))
}

fn hex_u64(value: &Value) -> Result<u64, String> {
    let s = as_hex_str(value)?;
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).map_err(|e| format!("u64 hex inválido {s}: {e}"))
}

fn hex_u128(value: &Value) -> Result<u128, String> {
    let s = as_hex_str(value)?;
    if s.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(s, 16).map_err(|e| format!("u128 hex inválido {s}: {e}"))
}

fn hex_usize(value: &Value) -> Result<usize, String> {
    // Los indexes de los fixtures son números JSON, no strings hex.
    value
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| format!("index inválido: {value}"))
}

fn hex_u256(value: &Value) -> Result<U256, String> {
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

fn hex_b256(value: &Value) -> Result<B256, String> {
    let s = as_hex_str(value)?;
    let bytes: [u8; 32] = decode_hex(s)?
        .try_into()
        .map_err(|_| format!("B256 con longitud incorrecta: 0x{s}"))?;
    Ok(B256::new(bytes))
}

fn hex_address(value: &Value) -> Result<Address, String> {
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

fn hex_bytes(value: &Value) -> Result<Bytes, String> {
    let s = as_hex_str(value)?;
    Ok(Bytes::from(decode_hex(s)?))
}

fn hex_array<T>(value: &Value, parse: fn(&Value) -> Result<T, String>) -> Result<Vec<T>, String> {
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
