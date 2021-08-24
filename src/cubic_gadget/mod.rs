use ark_crypto_primitives::Error;
use ark_ff::Field;

pub mod constraints;

// verifier wants to prove that she knows some x such that x^3 + x + 5 == 35
// or more general x^3 + x + 5 == y (a public value)
pub trait CubicRootTrait {
    type ParamType: Clone;
    fn verify(&self, y: &Self::ParamType) -> Result<bool, Error>;
}

#[derive(Clone)]
pub struct ParamType<F: Field> {
    pub inner: F,
}

impl<F: Field> ParamType<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

pub struct SolutionDemo<F: Field> {
    x: ParamType<F>,
}

impl<F: Field> CubicRootTrait for SolutionDemo<F> {
    type ParamType = ParamType<F>;

    fn verify(&self, y: &Self::ParamType) -> Result<bool, Error> {
        let x = self.x.inner;
        Ok((x * x * x + x + F::from(5u8)) == y.inner)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr as BlsFr;

    #[test]
    fn test_cubic_native() {
        let x = ParamType::new(BlsFr::from(3u8));
        let y = ParamType::new(BlsFr::from(35u8));
        let demo = SolutionDemo { x };
        assert_eq!(true, demo.verify(&y).unwrap());
    }
}
