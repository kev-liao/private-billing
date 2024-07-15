use serde_derive::{Deserialize, Serialize};

use crate::dap::types::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueRequest {
    pub com: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IssueResponse {
    pub sig: SchnorrSig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedeemRequest {
    pub coins: Vec<Coin>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RedeemResponse {
    pub valid: bool,
}
