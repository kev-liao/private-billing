//use aes::cipher::generic_array::GenericArray;    
use ark_bls12_381::Fr;    
use ark_crypto_primitives::SNARK;
use ark_ff::{Fp256, PrimeField, UniformRand};
use ark_serialize::*;
use ark_std::test_rng;
use arkworks_native_gadgets::poseidon::{
    FieldHasher,
    Poseidon,
    PoseidonParameters,
    sbox::PoseidonSbox,
};    
use arkworks_utils::{
    bytes_matrix_to_f,
    bytes_vec_to_f,
    Curve,
    poseidon_params::setup_poseidon_params,
};
use bloomfilter::Bloom;
use rand::Rng;
use std::collections::HashSet;

use crate::dap::{
    messages::{
        IssueRequest,
        IssueResponse,
        RedeemRequest,
        RedeemResponse,
    },
    types::*,    
};
use crate::schnorr::SignatureScheme;
use crate::ggm::GGM;

pub fn setup_params<F: PrimeField>(curve: Curve,
                                   exp: i8,
                                   width: u8)
                                   -> PoseidonParameters<F> {
    let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    let pos = PoseidonParameters {
	mds_matrix: mds_f,
	round_keys: rounds_f,
	full_rounds: pos_data.full_rounds,
	partial_rounds: pos_data.partial_rounds,
	sbox: PoseidonSbox(pos_data.exp),
	width: pos_data.width,
    };

    pos
}

#[macro_export]
macro_rules! mk_server {
    ($smt: ident, $server: ident, $height: ident, $circ: ident) => {        
        pub struct $server {
            // TODO: Double-spend list
            pub pp: PP,
            pub sk: SigSecretKey,
            pub groth_vks: Vec<GrothVerifyingKey>,
            pub bloom: Bloom::<Fp>,
            pub hset: HashSet::<Fp>,
        }

        impl $server {
            pub fn new() -> Self {
                let rng = &mut test_rng();
                
                // Generate public parameters
                let sig_params = SchnorrJ::setup::<_>(rng).unwrap();
                let (pk, sk) = SchnorrJ::keygen(&sig_params, rng).unwrap();                
                let params = setup_params(Curve::Bls381,
                                          POSEIDON_EXP,
                                          POSEIDON_WIDTH);
                let hasher = Poseidon::<Fr> { params };

                let mut groth_pks = vec![];
                let mut groth_vks = vec![];                
                for lvl in 0..=$height {
                    // Expand constrained PRF to generate Merkle tree leaves
                    let key = rand::thread_rng().gen::<[u8; 32]>();
                    let ggm = GGM::new();
                    let leaves_bytes = ggm.expand(&key, lvl.try_into().unwrap());
                    let mut leaves: Vec<Fp> = Vec::new();
                    for bytes in leaves_bytes {
                        leaves.push(Fp256::from_le_bytes_mod_order(&bytes));
                    }
                    
                    macro_rules! setup {
                        ($smt2:ident, $circ2:ident) => {
                            {
                                // Construct Merkle tree and hash to root
                                let smt = $smt2::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
                                let root = smt.root();
                                // Generate path for membership proof of leaf with label 0
                                let path = smt.generate_membership_proof(0);
                                
                                // Generate commitment to the root

                                let open = Fr::rand(rng);
                                let com = hasher.hash(&[root, open]).unwrap();
                                
                                // Generate a signature on com under pk
                                let sig = SchnorrJ::sign(&sig_params, &sk, &com, rng).unwrap();
                                assert!(SchnorrJ::verify(&sig_params, &pk, &com, &sig).unwrap());
                                
                                // Run trusted setup for circuit
                                let setup_circuit = $circ2::new(sig_params.clone(),
                                                                pk,
                                                                sig.clone(),
                                                                root,
                                                                com,
                                                                open,
                                                                leaves[0],
                                                                path.clone(),
                                                                hasher.clone()); 
                                let (groth_pk, groth_vk) = GrothSetup::circuit_specific_setup(
                                    setup_circuit,
                                    &mut test_rng())
                                    .unwrap();
                                groth_pks.push(groth_pk);
                                groth_vks.push(groth_vk);
                            }
                        }
                    }
                    
                    match lvl {
                        0  => setup![SMT0 , C0 ],
                        1  => setup![SMT1 , C1 ],
                        2  => setup![SMT2 , C2 ],
                        3  => setup![SMT3 , C3 ],
                        4  => setup![SMT4 , C4 ],
                        5  => setup![SMT5 , C5 ],
                        6  => setup![SMT6 , C6 ],
                        7  => setup![SMT7 , C7 ],
                        8  => setup![SMT8 , C8 ],
                        9  => setup![SMT9 , C9 ],
                        10 => setup![SMT10, C10],
                        11 => setup![SMT11, C11],
                        12 => setup![SMT12, C12],
                        _ => panic!("Shouldn't reach this case!"),
                    };
                }
                
                let pp = PP { sig_params, hasher, pk, groth_pks };
                
                // For 100M items, 1/1000000 FP rate                
                let bloom: Bloom<Fp> = Bloom::new_for_fp_rate(100000000, 0.000001);
                let hset: HashSet<Fp> = HashSet::new();
                
                Self { pp, sk, groth_vks, bloom, hset }
            }

            pub fn setup(&self) -> PP {
                self.pp.clone()
            }

            pub fn issue(&mut self, req: IssueRequest) -> IssueResponse {
                let rng = &mut test_rng();
                let com = Fp::deserialize(&*req.com).unwrap();
                let sig = SchnorrJ::sign(&self.pp.sig_params, &self.sk, &com, rng).unwrap();
                //assert!(SchnorrJ::verify(&self.pp.sig_params, &self.pp.pk, &com, &sig).unwrap());        
                let mut prover_response = vec![];
                sig.prover_response.serialize(&mut prover_response).unwrap();
                
                IssueResponse {
                    sig: SchnorrSig {
                        prover_response,
                        verifier_challenge: sig.verifier_challenge,
                    }
                }
            }

            pub fn redeem(&mut self, req: RedeemRequest) -> RedeemResponse {
                const L: u8 = 12;
                for i in 0..req.coins.len() {
                    let instance = Fp::deserialize(&*req.coins[i].instance_bytes).unwrap();            
                    let proof = GrothProof::deserialize(&*req.coins[i].proof_bytes).unwrap();
                    let key = req.coins[i].key;
                    let denom = req.coins[i].denom;
                    
                    let ggm = GGM::new();                    
                    let leaves_bytes = ggm.expand(&key, denom);
                    let mut leaves: Vec<Fp> = vec![];
                    for (j, bytes) in leaves_bytes.iter().enumerate() {
                        let leaf = Fp256::from_le_bytes_mod_order(bytes);
                        if j == 0 && leaf != instance {
                            return RedeemResponse { valid: false};
                        }
                        // Check double-spend
                        //if self.bloom.check_and_set(&leaf) {
                        //    return RedeemResponse { valid: false };
                        //};
                        if self.hset.contains(&leaf) {
                            return RedeemResponse { valid: false };                            
                        }
                        self.hset.insert(leaf);
                        leaves.push(leaf);
                    }

                    //// Check hash to instance
                    //macro_rules! cases { 
                    //    ($smt2: ident) => {
                    //        {
                    //            let smt = $smt2::new_sequential(&leaves,
                    //                                            &self.pp.hasher,
                    //                                            &DEFAULT_LEAF).unwrap();
                    //            let root = smt.root();
                    //            if root != instance {
                    //                return RedeemResponse { valid: false };                        
                    //            }
                    //        }
                    //    }
                    //}
                    //
                    //match denom {
                    //    0  => cases![SMT0 ],
                    //    1  => cases![SMT1 ],
                    //    2  => cases![SMT2 ],
                    //    3  => cases![SMT3 ],
                    //    4  => cases![SMT4 ],
                    //    5  => cases![SMT5 ],
                    //    6  => cases![SMT6 ],
                    //    7  => cases![SMT7 ],
                    //    8  => cases![SMT8 ],
                    //    9  => cases![SMT9 ],
                    //    10 => cases![SMT10],
                    //    11 => cases![SMT11],
                    //    12 => cases![SMT12],
                    //    _ => panic!("Shouldn't reach this case"),
                    //}
                    
                    // Check proof
                    let res = GrothSetup::verify(
                        //&self.groth_vks[(L - req.coins[i].denom) as usize],
                        &self.groth_vks[HEIGHT12],
                        &vec![instance],
                        &proof)
                        .unwrap();
                    if !res {
                        return RedeemResponse { valid: false };
                    }
                }
                RedeemResponse { valid: true }
            }    
        }
    }
}

mk_server![SMT, Server, HEIGHT, SpendC];
mk_server![SMT0 , Server0 , HEIGHT0 , C0 ];
mk_server![SMT1 , Server1 , HEIGHT1 , C1 ];
mk_server![SMT2 , Server2 , HEIGHT2 , C2 ];
mk_server![SMT3 , Server3 , HEIGHT3 , C3 ];
mk_server![SMT4 , Server4 , HEIGHT4 , C4 ];
mk_server![SMT5 , Server5 , HEIGHT5 , C5 ];
mk_server![SMT6 , Server6 , HEIGHT6 , C6 ];
mk_server![SMT7 , Server7 , HEIGHT7 , C7 ];
mk_server![SMT8 , Server8 , HEIGHT8 , C8 ];
mk_server![SMT9 , Server9 , HEIGHT9 , C9 ];
mk_server![SMT10, Server10, HEIGHT10, C10];
mk_server![SMT11, Server11, HEIGHT11, C11];
mk_server![SMT12, Server12, HEIGHT12, C12];
