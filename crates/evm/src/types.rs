//! Tipos del seam (vendoreado de zeth, adaptado a `no_std`).
//! `BTreeMap` (no `HashMap`) por determinismo (regla dura del guest).

use alloc::collections::BTreeMap;

use repo_b_common::access_list::AccessList;
use repo_b_common::primitives::{Address, B256, Bytes, U256};

pub const SYSTEM_ADDRESS: Address = Address::new([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe,
]);

pub const SYSTEM_CALL_GAS_LIMIT: u64 = 30_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeMetadata {
    Regular,
    Eip7702Delegation { target: Address },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEnv {
    pub spec: Spec,
    pub chain_id: u64,
    pub number: u64,
    pub coinbase: Address,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub prevrandao: B256,
    pub blob_excess_gas: Option<u64>,
    pub blob_base_fee: Option<u64>,
    pub blob_base_fee_update_fraction: Option<u64>,
}

/// Reglas de fork en UN solo lugar (post-Merge-first; ARCHITECTURE §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Spec {
    Paris,
    Shanghai,
    Cancun,
    Prague,
}

impl Spec {
    pub fn is_enabled(&self, target: Spec) -> bool {
        *self >= target
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallRequest {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub gas: Option<u64>,
    pub gas_price: Option<u64>,
    pub max_fee_per_gas: Option<u64>,
    pub max_priority_fee_per_gas: Option<u64>,
    pub access_list: Option<AccessList>,
}

pub type StateOverrides = BTreeMap<Address, AccountOverride>;

#[derive(Debug, Clone, Default)]
pub struct AccountOverride {
    pub balance: Option<U256>,
    pub nonce: Option<u64>,
    pub code: Option<Bytes>,
    pub state: Option<BTreeMap<U256, U256>>,
    pub state_diff: Option<BTreeMap<U256, U256>>,
}
