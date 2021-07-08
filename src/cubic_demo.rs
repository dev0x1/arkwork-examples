use ark_ff::Field;
use ark_relations::{
	lc,
	r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};

// verifier wants to prove that she knows some x such that x^3 + x + 5 == 35
// or more general x^3 + x + 5 == (a public value)
struct CubicDemoCircuit<F: Field> {
	pub x: Option<F>
}

impl<F: Field> ConstraintSynthesizer<F> for CubicDemoCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {

        // With two intermediate variables sym_1, y,
        // sym_2, x^3 + x + 5 == out can be flattened into following equations:
        // x * x = tmp_1
        // tmp_1 * x = y
        // y + x = tmp_2
        // tmp_2 + 5 = out
        // so R1CS  w = [one, x, tmp_1, y, tmp_2, out]

        // allocate witness x
        let x_val = self.x;
        let x = cs.new_witness_variable(|| {
            x_val.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // x * x = tmp_1, allocate tmp_1
        let tmp_1_val = x_val.map(|e| {
            e.square()
        });
        let tmp_1 = cs.new_witness_variable(|| {
            tmp_1_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // enforce constraints x * x = tmp_1
        cs.enforce_constraint(
            lc!() + x,
            lc!() + x,
            lc!() + tmp_1
        )?;


        // tmp_1 * x = y, allocate y
        let x_cubed_val = tmp_1_val.map(|mut e| {
            e.mul_assign(&x_val.unwrap());
            e
        });
        let x_cubed = cs.new_witness_variable( || {
            x_cubed_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // enforce constraints tmp_1 * x = y
        cs.enforce_constraint(
            lc!() + tmp_1,
            lc!() + x,
            lc!() + x_cubed
        )?;

        // allocate the public output variable out
        let out = cs.new_input_variable(|| {
            let mut tmp = x_cubed_val.unwrap();
            tmp.add_assign(&x_val.unwrap());
            tmp.add_assign(F::from(5u32));
            Ok(tmp)
        })?;
        // enforce constraints tmp_2 + 5 = out
        cs.enforce_constraint(
            lc!() + x_cubed + x + (F::from(5u32), ConstraintSystem::<F>::one()),
            lc!() + ConstraintSystem::<F>::one(),
            lc!() + out
        )?;

        Ok(())

    }
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_groth16::Groth16;
	use ark_snark::SNARK;

	#[test]
	fn test_groth16() {
		let rng = &mut ark_std::test_rng();

        // generate the setup parameters
		let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
			CubicDemoCircuit::<BlsFr>{x: None},
			rng).unwrap();

        // calculate the proof by passing witness variable value
		let proof = Groth16::<Bls12_381>::prove(&pk,
            CubicDemoCircuit::<BlsFr> {
				x: Some(BlsFr::from(3)),
			},
            rng).unwrap();

        // validate the proof
		assert!(Groth16::<Bls12_381>::verify(&vk, &[BlsFr::from(35)], &proof).unwrap());
		assert!(!Groth16::<Bls12_381>::verify(&vk, &[BlsFr::from(30)], &proof).unwrap());
	}
}
