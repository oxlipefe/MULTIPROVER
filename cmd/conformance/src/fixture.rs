//! Parsing de fixtures EF GeneralStateTests (formato `state_test`).
//!
//! Input hostil hasta validarse: todo campo se parsea con error explícito;
//! nada se asume bien formado. Sin `unwrap`/indexing crudo.

use std::collections::BTreeMap;

use repo_b_common::access_list::{AccessList, AccessListItem};
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
    pub base_fee: u64,
    pub prevrandao: B256,
    pub excess_blob_gas: Option<u64>,
    /// Hashes de bloques ancestros para `BLOCKHASH` (slice 2.3). NO es campo
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
    /// EIP-2930 (slice 2.7a). `None` = el fixture no trae `accessLists` en
    /// absoluto (tx legacy/1559 clásica). `Some(lista)` = el campo está
    /// presente (aunque una entrada individual sea `[]`): eso es lo que
    /// distingue "tx 2930 con AL vacía" de "tx legacy sin AL" — mismo costo
    /// de gas, `tx_type` distinto (task 009 spec ítem 6).
    pub access_lists: Option<Vec<AccessList>>,
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
        // hay decoder RLP que lo derive de otra forma.
        let has_access_list = self.tx.access_lists.is_some();
        let tx_type = match (self.tx.gas_price, self.tx.max_fee_per_gas, has_access_list) {
            (Some(_), None, false) => TxType::Legacy,
            (Some(_), None, true) => TxType::Eip2930,
            (None, Some(_), false) => TxType::Eip1559,
            (None, Some(_), true) => {
                return Err("accessLists con maxFeePerGas: tipo de tx fuera de scope (2.7b/2.7c)".into());
            }
            _ => return Err("tx con gasPrice y maxFeePerGas inconsistentes".into()),
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
        })
    }

    /// `BlockEnv` para un fork dado.
    pub fn block_env(&self, spec: Spec) -> BlockEnv {
        BlockEnv {
            spec,
            chain_id: self.chain_id,
            number: self.env.number,
            coinbase: self.env.coinbase,
            timestamp: self.env.timestamp,
            gas_limit: self.env.gas_limit,
            base_fee: self.env.base_fee,
            prevrandao: self.env.prevrandao,
            blob_excess_gas: self.env.excess_blob_gas,
            blob_base_fee: None,
            blob_base_fee_update_fraction: None,
        }
    }
}

/// Forks post-Merge soportados por el runner (ARCHITECTURE §11).
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
        base_fee: hex_u64(field(env, "currentBaseFee")?)?,
        prevrandao: hex_b256(field(env, "currentRandom")?)?,
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
