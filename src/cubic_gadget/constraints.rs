use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

use super::{CubicRootTrait, ParamType, SolutionDemo};

// r1cs constraints

pub trait CubicRootGadgetTrait<S: CubicRootTrait, ConstraintF: Field> {
    type ParamTypeVar: AllocVar<S::ParamType, ConstraintF>;
    fn verify(&self, y: &Self::ParamTypeVar) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

#[derive(Clone)]
pub struct ParamTypeVar<ConstraintF: PrimeField> {
    pub inner: FpVar<ConstraintF>,
}

// TODO remove it
impl<F: PrimeField> ParamTypeVar<F> {
    pub fn new(inner: FpVar<F>) -> Self {
        Self { inner }
    }
}

impl<ConstraintF: PrimeField> AllocVar<ParamType<ConstraintF>, ConstraintF>
    for ParamTypeVar<ConstraintF>
{
    fn new_variable<T: Borrow<ParamType<ConstraintF>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let inner = FpVar::new_variable(
                ark_relations::ns!(cs, "inner"),
                || Ok(val.borrow().inner.clone()),
                mode,
            )?;
            Ok(ParamTypeVar { inner })
        })
    }
}
pub struct SolutionDemoGadget<ConstraintF: PrimeField> {
    x: ParamTypeVar<ConstraintF>,
}

impl<ConstraintF: PrimeField> CubicRootGadgetTrait<SolutionDemo<ConstraintF>, ConstraintF>
    for SolutionDemoGadget<ConstraintF>
{
    type ParamTypeVar = ParamTypeVar<ConstraintF>;

    fn verify(&self, y: &Self::ParamTypeVar) -> Result<Boolean<ConstraintF>, SynthesisError> {
        let x = &self.x.inner;
        let eval = x * x * x + x + ConstraintF::from(5u8);
        Ok(eval.is_eq(&y.inner)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr as BlsFr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_cubic_gadget() {
        let cs = ConstraintSystem::<BlsFr>::new_ref();
        let x_val = BlsFr::from(3u8);
        let x_val = FpVar::<BlsFr>::new_witness(cs.clone(), || Ok(&x_val)).unwrap();
        let x = ParamTypeVar::new(x_val);

        let y_val = BlsFr::from(35u8);
        let y_val = FpVar::<BlsFr>::new_witness(cs.clone(), || Ok(&y_val)).unwrap();
        let y = ParamTypeVar::new(y_val);

        let demo_gaget = SolutionDemoGadget { x };
        assert_eq!(true, demo_gaget.verify(&y).unwrap().value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
