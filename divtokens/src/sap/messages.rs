use challenge_bypass_ristretto::voprf::*;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct IssueRequest {
    pub blinded_tokens: Vec<BlindedToken>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IssueResponse {
    pub signed_tokens: Vec<SignedToken>,
    pub public_key: PublicKey,    
    pub batch_proof: BatchDLEQProof,    
}

#[derive(Deserialize, Serialize)]
pub struct RedeemRequest {
    pub coins: Vec<UnblindedToken>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RedeemResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WinNotice {
    pub price: u16,
}
