use ark_bls12_381::{
    Bls12_381,
    Parameters as Bls12Parameters,
    Fr,
    FrParameters,
};
use ark_ec::{
    bls12::Bls12,
    twisted_edwards_extended::{
        GroupAffine,
        GroupProjective
    },
};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar as JubJubVar,    
    EdwardsParameters,
    EdwardsProjective as JubJub,
};
use ark_ff::Fp256;
use ark_groth16::{
    Groth16,
    Proof,
    ProvingKey,
    VerifyingKey,
};
//use ark_serialize::*;
use arkworks_native_gadgets::{
    merkle_tree::SparseMerkleTree,
    poseidon::Poseidon,
};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use serde_derive::{Deserialize, Serialize};

use crate::dap::circuit::{RootCircuit, SpendCircuit};
use crate::schnorr::{
    Parameters as SchnorrParameters,
    Schnorr,
    SecretKey,
    constraints::SchnorrSignatureVerifyGadget,
};

// Signature scheme
pub type SigParams = SchnorrParameters<GroupProjective<EdwardsParameters>>;
pub type SigSecretKey = SecretKey<GroupProjective<EdwardsParameters>>;
pub type SigPublicKey = GroupAffine<EdwardsParameters>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchnorrSig {
    pub prover_response: Vec<u8>,
    pub verifier_challenge: [u8; 32],
}

// Finite field
pub type Fp = Fp256<FrParameters>;
pub type FpEd = Fp256<ark_ed_on_bls12_381::FrParameters>;

// Groth16
pub type GrothSetup = Groth16<Bls12_381>;
pub type GrothProvingKey = ProvingKey<Bls12<Bls12Parameters>>;
pub type GrothVerifyingKey = VerifyingKey<Bls12<Bls12Parameters>>;
pub type GrothProof = Proof<Bls12_381>;

// Circuit

pub const DEFAULT_LEAF: [u8; 32] = [0; 32];
pub const POSEIDON_EXP: i8 = 3;
pub const POSEIDON_WIDTH: u8 = 3;
pub type SchnorrJ = Schnorr<JubJub>;

pub const HEIGHT: usize = 10;
pub type SMT = SparseMerkleTree<Fr, Poseidon<Fr>, HEIGHT>;
pub type SpendC = SpendCircuit<Fr,
                               JubJub,
                               SchnorrJ,
                               SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
                               PoseidonGadget<Fr>,
                               HEIGHT>;

pub const HEIGHT0: usize = 0;
pub type SMT0 = SparseMerkleTree<Fr, Poseidon<Fr>, HEIGHT0>;
pub type C0 = RootCircuit<Fr,
                          JubJub,
                          SchnorrJ,
                          SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
                          PoseidonGadget<Fr>,
                          HEIGHT0>;

#[macro_export]
macro_rules! circ_types {
    ($height: ident, $n: literal, $smt:ident, $circ:ident) => {
        pub const $height: usize = $n;
        pub type $smt = SparseMerkleTree<Fr, Poseidon<Fr>, $height>;
        pub type $circ = SpendCircuit<Fr,
                                      JubJub,
                                      SchnorrJ,
                                      SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
                                      PoseidonGadget<Fr>,
                                      $height>;
    };
}

circ_types![HEIGHT1 , 1 , SMT1 , C1 ];
circ_types![HEIGHT2 , 2 , SMT2 , C2 ];
circ_types![HEIGHT3 , 3 , SMT3 , C3 ];
circ_types![HEIGHT4 , 4 , SMT4 , C4 ];
circ_types![HEIGHT5 , 5 , SMT5 , C5 ];
circ_types![HEIGHT6 , 6 , SMT6 , C6 ];
circ_types![HEIGHT7 , 7 , SMT7 , C7 ];
circ_types![HEIGHT8 , 8 , SMT8 , C8 ];
circ_types![HEIGHT9 , 9 , SMT9 , C9 ];
circ_types![HEIGHT10, 10, SMT10, C10];
circ_types![HEIGHT11, 11, SMT11, C11];
circ_types![HEIGHT12, 12, SMT12, C12];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Coin {
    pub denom: u8,
    pub key: [u8; 32],
    pub instance_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
}

// Public parameters
// TODO: Serialize
#[derive(Clone)]
pub struct PP {
    pub sig_params: SigParams,
    pub hasher: Poseidon::<Fr>,    
    pub pk: SigPublicKey,
    pub groth_pks: Vec<GrothProvingKey>,    
}
