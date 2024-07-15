use ark_crypto_primitives::Error;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{
    bytes::ToBytes,
    fields::{Field, PrimeField},
    to_bytes, ToConstraintField, UniformRand,
};
use ark_sponge::poseidon::{PoseidonParameters, PoseidonSponge};
use ark_sponge::CryptographicSponge;
use ark_std::io::{Result as IoResult, Write};
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use derivative::Derivative;
use serde_derive::{Deserialize, Serialize};

pub mod constraints;
pub mod params;

pub trait SignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: ToBytes + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: ToBytes + Clone + Default;
    type Signature: Clone + Default + Send + Sync;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign<R: Rng, F: PrimeField>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &F,
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;

    fn verify<F: PrimeField>(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &F,
        signature: &Self::Signature,
    ) -> Result<bool, Error>;
}

pub struct Schnorr<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve"), Debug)]
pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

#[derive(Clone, Default, Debug)]
pub struct SecretKey<C: ProjectiveCurve> {
    pub secret_key: C::ScalarField,
    pub public_key: PublicKey<C>,
}

impl<C: ProjectiveCurve> ToBytes for SecretKey<C> {
    #[inline]
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.secret_key.write(writer)
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Signature<C: ProjectiveCurve> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: [u8; 32]
}

impl<C: ProjectiveCurve + Hash> SignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // let setup_time = start_timer!(|| "SchnorrSig::Setup");

        let generator = C::prime_subgroup_generator().into();

        // end_timer!(setup_time);
        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // let keygen_time = start_timer!(|| "SchnorrSig::KeyGen");

        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        // end_timer!(keygen_time);
        Ok((
            public_key,
            SecretKey {
                secret_key,
                public_key,
            },
        ))
    }

    fn sign<R: Rng, F: PrimeField>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &F,
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        // let sign_time = start_timer!(|| "SchnorrSig::Sign");
        // (k, e);
        let (random_scalar, verifier_challenge) = {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(r || msg);
            let mut hash_input = Vec::new();
            hash_input.extend_from_slice(&to_bytes![prover_commitment]?);
            hash_input.extend_from_slice(&to_bytes![message]?);

            // XXX
            let sponge_params: PoseidonParameters<F> = params::poseidon();
            let mut sponge = PoseidonSponge::<F>::new(&sponge_params);
            sponge.absorb(&hash_input);
            let hash_digest = sponge.squeeze_bytes(32);
            let mut verifier_challenge = [0u8; 32];
            verifier_challenge.copy_from_slice(&hash_digest);

            (random_scalar, verifier_challenge)
        };

        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge_fe * sk.secret_key);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        // end_timer!(sign_time);
        Ok(signature)
    }

    fn verify<F: PrimeField>(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &F,
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        // let verify_time = start_timer!(|| "SchnorrSig::Verify");

        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge_fe);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(kG, msg)
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&to_bytes![claimed_prover_commitment]?);
        hash_input.extend_from_slice(&to_bytes![message]?);

        let sponge_params: PoseidonParameters<F> = params::poseidon();
        let mut sponge = PoseidonSponge::<F>::new(&sponge_params);
        sponge.absorb(&hash_input);
        
        // cast the hash output to get e
        let mut obtained_verifier_challenge = [0u8; 32];
        obtained_verifier_challenge.copy_from_slice(&sponge.squeeze_bytes(32));
        // end_timer!(verify_time);
        // The signature is valid iff the computed verifier challenge is the same as the one
        // provided in the signature
        Ok(verifier_challenge == &obtained_verifier_challenge)
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> (8 - i - 1)) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

impl<ConstraintF: Field, C: ProjectiveCurve + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<C>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.generator.into_projective().to_field_elements()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::G1Projective as G1P;
    use ark_std::{test_rng, UniformRand};
    use ark_bls12_381::Fr;    

    fn sign_and_verify<F: PrimeField, S: SignatureScheme>(message: &F) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, message, &sig).unwrap());
    }
    
    fn failed_verification<F: PrimeField, S: SignatureScheme>(message: &F, bad_message: &F) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }
    
    #[test]
    fn schnorr_signature_test() {
	let rng = &mut ark_std::test_rng();
	let message = Fr::rand(rng);
        let bad_message = Fr::rand(rng);        
        sign_and_verify::<Fr, Schnorr<G1P>>(&message);
        failed_verification::<Fr, Schnorr<G1P>>(
            &message,
            &bad_message,
        );
    }
}

