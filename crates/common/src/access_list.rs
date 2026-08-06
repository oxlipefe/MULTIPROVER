//! EIP-2930 access list (mínimo vendoreado; reconciliar con zeth en Fase 5).

use alloc::vec::Vec;

use crate::primitives::{Address, B256};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

pub type AccessList = Vec<AccessListItem>;
