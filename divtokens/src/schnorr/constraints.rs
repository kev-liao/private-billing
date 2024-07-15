use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, Field};
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

use crate::schnorr::{Parameters, PublicKey, Schnorr, Signature,
                     SignatureScheme};
use crate::schnorr::params;

pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field + ark_ff::PrimeField> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    type SignatureVar: AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &FpVar<ConstraintF>,        
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    _curve: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    prover_response: Vec<UInt8<ConstraintF<C>>>,
    verifier_challenge: Vec<UInt8<ConstraintF<C>>>,
    #[doc(hidden)]
    _group: PhantomData<GC>,
}

pub struct SchnorrSignatureVerifyGadget<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SigVerifyGadget<Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &FpVar<ConstraintF<C>>,
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = parameters
            .generator
            .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key
            .pub_key
            .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(&message.to_bytes().unwrap());

        let sponge_params: PoseidonParameters<ConstraintF<C>> = params::poseidon();
        let mut sponge = PoseidonSpongeVar::<ConstraintF<C>>::new(ConstraintSystemRef::None, &sponge_params);
        sponge.absorb(&hash_input).unwrap();
        let obtained_verifier_challenge = sponge.squeeze_bytes(32).unwrap();
        
        obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec())
    }
}

impl<C, GC> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let generator = GC::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            Ok(Self {
                generator,
                _curve: PhantomData,
            })
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let response_bytes = to_bytes![val.borrow().prover_response].unwrap();
            let challenge_bytes = &val.borrow().verifier_challenge;
            let mut prover_response = Vec::<UInt8<ConstraintF<C>>>::new();
            let mut verifier_challenge = Vec::<UInt8<ConstraintF<C>>>::new();
            for i in 0..response_bytes.len() {
                prover_response.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(response_bytes[i].clone()),
                    mode,
                )?);
            }
            for i in 0..32 {
                verifier_challenge.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(challenge_bytes[i].clone()),
                    mode,
                )?);
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                _group: PhantomData,
            })
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}

#[cfg(test)]
mod test {
    use crate::schnorr;
    use super::*;
    use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, UniformRand};
    use ark_bls12_381::Fr;            

    fn sign_and_verify<F: PrimeField, S: SignatureScheme, SG: SigVerifyGadget<S, F>>(
        message: &F,
    ) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, message, &sig).unwrap());
    
        let cs = ConstraintSystem::<F>::new_ref();
    
        let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let msg_var = FpVar::<F>::new_input(cs.clone(), || Ok(message)).unwrap();
        let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();
        valid_sig_var.enforce_equal(&Boolean::<F>::TRUE).unwrap();
        println!("Signature verification constraints {:?}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
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
        sign_and_verify::<
            Fr,
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(&message);
        failed_verification::<Fr, schnorr::Schnorr<JubJub>>(
            &message,
            &bad_message,
        );
    }    
}
