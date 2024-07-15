use bloomfilter::Bloom;
use challenge_bypass_ristretto::voprf::{
    BatchDLEQProof,
    SignedToken,
    SigningKey,
    TokenPreimage,
};
//use parking_lot::RwLock;
use rand::rngs::OsRng;
use sha2::Sha512;
//use std::sync::Arc;

use crate::sap::messages::{
    IssueRequest,
    IssueResponse,
    RedeemRequest,
    RedeemResponse,
};

#[derive(Clone)]
pub struct Server {
    // XXX: Maybe move signing_key so it doesn't have to be cloned
    pub signing_key: SigningKey,
    // XXX: Change to bloom filter in future
    //pub spent_tokens: Arc<RwLock<Vec<TokenPreimage>>>,
    pub bloom: Bloom::<TokenPreimage>        
}

impl Server {
    pub fn issue(&self, req: IssueRequest) -> IssueResponse {
        let mut rng = OsRng;

        let public_key = self.signing_key.public_key;

        let signed_tokens: Vec<SignedToken> = req
            .blinded_tokens
            .iter()
            .filter_map(|t| self.signing_key.sign(t).ok())
            .collect();

        let batch_proof = BatchDLEQProof::new::<Sha512, OsRng>(
            &mut rng,
            &req.blinded_tokens,
            &signed_tokens,
            &self.signing_key,
        )
        .unwrap();

        IssueResponse {
            signed_tokens,
            public_key,
            batch_proof,
        }
    }

    pub fn redeem(&mut self, req: RedeemRequest) -> RedeemResponse {
        let mut valid = true;
        
        for coin in req.coins.iter() {
            // the exchange checks that the preimage has not previously been
            // spent
            if self.bloom.check_and_set(&coin.t) {
                valid = false;
                break;
            };

            // exchange derives the unblinded token using it's key and the clients token preimage
            let unblinded_token = self.signing_key.rederive_unblinded_token(&coin.t);

            if unblinded_token.W != coin.W {
                valid = false;
                break;
            }
        }
        
        return RedeemResponse { valid }
    }    
}
