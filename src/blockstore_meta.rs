#![allow(dead_code)]
use {
    serde::{Deserialize, Serialize},
    super::DATA_SHREDS_PER_FEC_BLOCK,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ErasureConfig {
    pub(crate) num_data: usize,
    pub(crate) num_coding: usize,
}

impl ErasureConfig {
    pub(crate) fn is_fixed(&self) -> bool {
        self.num_data == DATA_SHREDS_PER_FEC_BLOCK && self.num_coding == DATA_SHREDS_PER_FEC_BLOCK
    }
}
