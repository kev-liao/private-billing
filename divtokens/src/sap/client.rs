use challenge_bypass_ristretto::{errors::*, voprf::*};
use parking_lot::RwLock;
use rand::rngs::OsRng;
use sha2::Sha512;
use std::sync::Arc;

use crate::sap::messages::{
    IssueRequest,
    IssueResponse,
    RedeemRequest,
    WinNotice,
};

#[derive(Clone)]
pub struct Client {
    pub tokens: Arc<RwLock<Vec<Token>>>,
    pub blinded_tokens: Arc<RwLock<Vec<BlindedToken>>>,
    pub unblinded_tokens: Arc<RwLock<Vec<UnblindedToken>>>,
}

impl Client {
    pub fn reset_state(&mut self) {
        self.tokens =  Arc::new(RwLock::new(Vec::new()));
        self.blinded_tokens = Arc::new(RwLock::new(Vec::new()));
        self.unblinded_tokens = Arc::new(RwLock::new(Vec::new()));
    }
    
    // n: batch size
    pub fn issue_request(&mut self, n: u16) -> IssueRequest {
        let mut rng = OsRng;

        for _ in 0..n {
            // advertiser prepares a random token and blinding scalar
            let token = Token::random::<Sha512, OsRng>(&mut rng);

            // advertiser blinds the token
            let blinded_token = token.blind();

            // stores the token in it's local state
            self.tokens.write().push(token);
            self.blinded_tokens.write().push(blinded_token);
        }

        // and sends the blinded token to the server in a signing request
        IssueRequest {
            blinded_tokens: self.blinded_tokens.read().clone(),
        }
    }

    pub fn issue_process(&mut self,
                         resp: IssueResponse)
                         -> Result<(), TokenError> {
        // XXX
        // Make atomic?
        let tokens = self.tokens.read().clone();
        let blinded_tokens = self.blinded_tokens.read().clone();
        self.unblinded_tokens
            .write()
            .append(&mut resp.batch_proof.verify_and_unblind::<Sha512, _>(
                &tokens[..],
                &blinded_tokens[..],
                &resp.signed_tokens,
                &resp.public_key,
            )?);

        assert_eq!(self.tokens.read().len(), self.unblinded_tokens.read().len());
        Ok(())
    }

    pub fn redeem_request(&self, _req: &WinNotice) -> RedeemRequest {
        let mut coins = vec![];
        for unblinded_token in self.unblinded_tokens.read().iter() {
            coins.push(unblinded_token.clone());
        }

        RedeemRequest { coins }
    }    
}
