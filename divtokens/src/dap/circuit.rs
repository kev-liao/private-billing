use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    prelude::*,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer,
    ConstraintSystemRef,
    SynthesisError};
//use crate::merkle_tree::Path;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{
    merkle_tree::PathVar,
    poseidon::FieldHasherGadget,
};
use core::{borrow::Borrow, marker::PhantomData};

use crate::schnorr::{
    Parameters,
    PublicKey,
    Signature,
    SignatureScheme,
};
use crate::schnorr::constraints::SigVerifyGadget;

// TODO: #[derive(Copy)]
pub struct SpendCircuit<F: PrimeField,
                    C: ProjectiveCurve,
                    S: SignatureScheme,
                    SG: SigVerifyGadget<S, F>,
                    HG: FieldHasherGadget<F>,
                    const N: usize> {
    pub params: Parameters<C>,
    pub pk: PublicKey<C>,
    pub sig: Signature<C>,
    pub root: F,
    pub com: F,
    pub open: F,
    pub leaf: F,
    pub path: Path<F, HG::Native, N>,
    pub hasher: HG::Native,
    _sig_scheme: PhantomData<S>,    
    _sig_gadget: PhantomData<SG>,
}

#[allow(dead_code)]
impl<F: PrimeField,
     C: ProjectiveCurve,
     S: SignatureScheme,
     SG: SigVerifyGadget<S, F>,
     HG: FieldHasherGadget<F>,
     const N: usize> SpendCircuit<F, C, S, SG, HG, N> {
    pub fn new(params: Parameters<C>,
               pk: PublicKey<C>,
               sig: Signature<C>,
               root: F,
               com: F,
               open: F,
               leaf: F,
               path: Path<F, HG::Native, N>,
               hasher: HG::Native)
               -> Self {
	Self { params,
               pk,
               sig,
               root,
               com,
               open,
               leaf,
               path,
               hasher,
               _sig_scheme: PhantomData,
               _sig_gadget: PhantomData }
    }
}

impl<F: PrimeField,
     C: ProjectiveCurve,
     S: SignatureScheme,
     SG: SigVerifyGadget<S, F>,
     HG: FieldHasherGadget<F>,
     const N: usize>
    ConstraintSynthesizer<F> for SpendCircuit<F, C, S, SG, HG, N>
where
    // TODO: Clean up this mess
    Parameters<C>: Borrow<<S as SignatureScheme>::Parameters>,
    for<'a> &'a Signature<C>: Borrow<<S as SignatureScheme>::Signature>,
    <C as ProjectiveCurve>::Affine: Borrow<<S as SignatureScheme>::PublicKey>
{
    fn generate_constraints(self,
                            cs: ConstraintSystemRef<F>)
                            -> Result<(), SynthesisError> {
        let params_var = SG::ParametersVar::new_constant(
            cs.clone(),
            self.params)
            .unwrap();
        let pk_var = SG::PublicKeyVar::new_constant(
            cs.clone(),
            self.pk)
            .unwrap();        
        let sig_var = SG::SignatureVar::new_witness(
            cs.clone(),
            || Ok(&self.sig))
            .unwrap();
	let root_var = FpVar::<F>::new_witness(
            cs.clone(),
            || Ok(self.root))
            .unwrap();
        let com_var = FpVar::<F>::new_witness(
            cs.clone(),
            || Ok(self.com))
            .unwrap();        
        let open_var = FpVar::<F>::new_witness(
            cs.clone(),
            || Ok(self.open))
            .unwrap();
	let leaf_var = FpVar::<F>::new_input(
            cs.clone(),
            || Ok(self.leaf))
            .unwrap();
	let path_var = PathVar::<F, HG, N>::new_witness(
            cs.clone(),
            || Ok(self.path))
            .unwrap();
        let hasher_gadget = HG::from_native(
            &mut cs.clone(),
            self.hasher)
            .unwrap();

        // Check sig is a valid signature of com under pk
        // sig.verify(pk, sig, com) = 1
        SG::verify(&params_var,
                   &pk_var,
                   &com_var,
                   &sig_var)
            .unwrap()
            .enforce_equal(&Boolean::<F>::TRUE)
            .unwrap();

        // Check com opens to root
        // verifycom(root, com, open) = 1, i.e., H(root, open) = com
        hasher_gadget
            .hash(&[root_var.clone(), open_var])
            .unwrap()
            .enforce_equal(&com_var)
            .unwrap();

        // Check leaf in the Merkle tree of root
        path_var
	    .check_membership(&root_var, &leaf_var, &hasher_gadget)
	    .unwrap()
            .enforce_equal(&Boolean::<F>::TRUE)
            .unwrap();

        //println!("Spend constraints: {:?}", cs.num_constraints());        
	Ok(())
    }
}

// TODO: #[derive(Copy)]
pub struct RootCircuit<F: PrimeField,
                    C: ProjectiveCurve,
                    S: SignatureScheme,
                    SG: SigVerifyGadget<S, F>,
                    HG: FieldHasherGadget<F>,
                    const N: usize> {
    pub params: Parameters<C>,
    pub pk: PublicKey<C>,
    pub sig: Signature<C>,
    pub root: F,
    pub com: F,
    pub open: F,
    pub hasher: HG::Native,
    _sig_scheme: PhantomData<S>,    
    _sig_gadget: PhantomData<SG>,
}

#[allow(dead_code)]
impl<F: PrimeField,
     C: ProjectiveCurve,
     S: SignatureScheme,
     SG: SigVerifyGadget<S, F>,
     HG: FieldHasherGadget<F>,
     const N: usize> RootCircuit<F, C, S, SG, HG, N> {
    pub fn new(params: Parameters<C>,
               pk: PublicKey<C>,
               sig: Signature<C>,
               root: F,
               com: F,
               open: F,
               _leaf: F,
               _path: Path<F, HG::Native, N>,
               hasher: HG::Native)
               -> Self {
	Self { params,
               pk,
               sig,
               root,
               com,
               open,
               hasher,
               _sig_scheme: PhantomData,
               _sig_gadget: PhantomData }
    }
}

impl<F: PrimeField,
     C: ProjectiveCurve,
     S: SignatureScheme,
     SG: SigVerifyGadget<S, F>,
     HG: FieldHasherGadget<F>,
     const N: usize>
    ConstraintSynthesizer<F> for RootCircuit<F, C, S, SG, HG, N>
where
    // TODO: Clean up this mess
    Parameters<C>: Borrow<<S as SignatureScheme>::Parameters>,
    for<'a> &'a Signature<C>: Borrow<<S as SignatureScheme>::Signature>,
    <C as ProjectiveCurve>::Affine: Borrow<<S as SignatureScheme>::PublicKey>
{
    fn generate_constraints(self,
                            cs: ConstraintSystemRef<F>)
                            -> Result<(), SynthesisError> {
        let params_var = SG::ParametersVar::new_constant(
            cs.clone(),
            self.params)
            .unwrap();
        let pk_var = SG::PublicKeyVar::new_constant(
            cs.clone(),
            self.pk)
            .unwrap();        
        let sig_var = SG::SignatureVar::new_witness(
            cs.clone(),
            || Ok(&self.sig))
            .unwrap();
	let root_var = FpVar::<F>::new_input(
            cs.clone(),
            || Ok(self.root))
            .unwrap();
        let com_var = FpVar::<F>::new_witness(
            cs.clone(),
            || Ok(self.com))
            .unwrap();        
        let open_var = FpVar::<F>::new_witness(
            cs.clone(),
            || Ok(self.open))
            .unwrap();
        let hasher_gadget = HG::from_native(
            &mut cs.clone(),
            self.hasher)
            .unwrap();

        // Check sig is a valid signature of com under pk
        // sig.verify(pk, sig, com) = 1
        SG::verify(&params_var,
                   &pk_var,
                   &com_var,
                   &sig_var)
            .unwrap()
            .enforce_equal(&Boolean::<F>::TRUE)
            .unwrap();

        // Check com opens to root
        // verifycom(root, com, open) = 1, i.e., H(root, open) = com
        hasher_gadget
            .hash(&[root_var.clone(), open_var])
            .unwrap()
            .enforce_equal(&com_var)
            .unwrap();

        //println!("Spend constraints: {:?}", cs.num_constraints());        
	Ok(())
    }
}

