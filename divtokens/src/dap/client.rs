//use aes::cipher::generic_array::{GenericArray, typenum::U16, typenum::U32};
use ark_bls12_381::Fr;
use ark_crypto_primitives::SNARK;
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_ff::{
    Fp256,
    PrimeField,
    UniformRand
};
use ark_serialize::*;
use ark_std::test_rng;
use arkworks_native_gadgets::poseidon::FieldHasher;
use rand::Rng;


use crate::dap::{
    messages::{
        IssueRequest,
        IssueResponse,
        RedeemRequest,
    },
    types::*,
};
use crate::ggm::GGM;
use crate::schnorr::{Signature, SignatureScheme};


#[macro_export]
macro_rules! mk_client {
    ($wallet: ident, $smt: ident, $client: ident, $height: ident, $circ: ident) => {    
        pub struct $wallet {
            pub key: [u8; 32],
            pub leaves: Vec<Fp>,
            pub smt: $smt,
            pub root: Fp,
            pub com: Fp,
            pub open: Fp,
            pub sig: Option<Signature::<JubJub>>,
            pub coins: Vec<Coin>,
        }

        pub struct $client {
            pub pp: PP,
            pub wallet: Vec<$wallet>,
            pub coins: Vec<Coin>
        }

        impl $client {
            pub fn new(pp: PP) -> $client {
                $client { pp, wallet: vec![], coins: vec![] }
            }
            
            pub fn issue_request(&mut self) -> IssueRequest {
                let rng = &mut test_rng();
                
                // Generate master key
                let key = rand::thread_rng().gen::<[u8; 32]>();
                
                // Compute GGM-tree leaves
                let ggm = GGM::new();
                let leaves_bytes = ggm.expand(&key, ($height).try_into().unwrap());
                let mut leaves = Vec::new();
                for bytes in leaves_bytes {
                    leaves.push(Fp256::from_le_bytes_mod_order(&bytes));
                }

                // Construct Merkle tree and hash to root
                let smt = $smt::new_sequential(&leaves,
                                              &self.pp.hasher,
                                              &DEFAULT_LEAF).unwrap();
                let root = smt.root();

                // Compute commitment
                let open = Fr::rand(rng);
                let com = self.pp.hasher.hash(&[root, open]).unwrap();

                // Update wallet
                let entry = $wallet {
                    key,
                    leaves,
                    smt,
                    root,
                    com,
                    open,
                    sig: None,
                    coins: vec![]
                };
                self.wallet.push(entry);

                let mut com_bytes = vec![];
                com.serialize(&mut com_bytes).unwrap();
                
                IssueRequest { com: com_bytes }
            }

            pub fn issue_process(&mut self, rsp: IssueResponse) {
                // XXX: Pick out right entry
                let mut entry = &mut self.wallet[0];
                // XXX: Rename type
                let prover_response = FpEd::deserialize(&*rsp.sig.prover_response).unwrap();
                let sig = Signature::<JubJub> {
                    prover_response,
                    verifier_challenge: rsp.sig.verifier_challenge,
                };
                assert!(SchnorrJ::verify(&self.pp.sig_params,
                                         &self.pp.pk,
                                         &entry.com,
                                         &sig).unwrap());
                entry.sig = Some(sig);
            }
            
            pub fn precompute_proofs(&mut self) {
                let rng = &mut test_rng();
                let entry = &mut self.wallet[0];
                
                // Generate proof for leaf 0
                let path = entry.smt.generate_membership_proof(0);
                let circuit = $circ::new(self.pp.sig_params.clone(),
                                          self.pp.pk,
                                          entry.sig.clone().unwrap(),
                                          entry.root,
                                          entry.com,
                                          entry.open,
                                          entry.leaves[0],
                                          path,
                                          self.pp.hasher.clone());

                let proof = GrothSetup::prove(
                    &self.pp.groth_pks[$height],
                    circuit,
                    rng).unwrap();
                let mut proof_bytes = vec![];
                proof.serialize(&mut proof_bytes).unwrap();
                let mut instance_bytes = vec![];
                entry.leaves[0].serialize(&mut instance_bytes).unwrap();
                
                let coin = Coin {
                    denom: 0,
                    key: entry.key,
                    instance_bytes,
                    proof_bytes
                };
                entry.coins.push(coin);                
            }

            pub fn redeem_request(&mut self, _n: u16) -> RedeemRequest {
                // XXX: Uses preloaded coins
                let mut coins = vec![];        
                let coin = self.wallet[0].coins[0].clone();
                coins.push(coin);
                RedeemRequest { coins }
            }
        }
    }
}

mk_client![Entry, SMT, Client, HEIGHT, SpendC];
mk_client![Entry0 , SMT0 , Client0 , HEIGHT0 , C0 ];
mk_client![Entry1 , SMT1 , Client1 , HEIGHT1 , C1 ];
mk_client![Entry2 , SMT2 , Client2 , HEIGHT2 , C2 ];
mk_client![Entry3 , SMT3 , Client3 , HEIGHT3 , C3 ];
mk_client![Entry4 , SMT4 , Client4 , HEIGHT4 , C4 ];
mk_client![Entry5 , SMT5 , Client5 , HEIGHT5 , C5 ];
mk_client![Entry6 , SMT6 , Client6 , HEIGHT6 , C6 ];
mk_client![Entry7 , SMT7 , Client7 , HEIGHT7 , C7 ];
mk_client![Entry8 , SMT8 , Client8 , HEIGHT8 , C8 ];
mk_client![Entry9 , SMT9 , Client9 , HEIGHT9 , C9 ];
mk_client![Entry10, SMT10, Client10, HEIGHT10, C10];
mk_client![Entry11, SMT11, Client11, HEIGHT11, C11];
mk_client![Entry12, SMT12, Client12, HEIGHT12, C12];
