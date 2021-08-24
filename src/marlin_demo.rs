use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};

// verifier wants to prove that she knows some x such that x^3 + x + 5 == 35
// or more general x^3 + x + 5 == (a public value)
struct CubicDemoCircuit<F: Field> {
    pub x: Option<F>,
    num_constraints: usize,
    num_variables: usize,
}

impl<F: Field> ConstraintSynthesizer<F> for CubicDemoCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // With two intermediate variables sym_1, y,
        // sym_2, x^3 + x + 5 == out can be flattened into following equations:
        // x * x = tmp_1
        // tmp_1 * x = y
        // y + x = tmp_2
        // tmp_2 + 5 = out
        // so R1CS  w = [one, x, tmp_1, y, tmp_2, out]

        // allocate witness x
        let x_val = self.x;
        let x = cs.new_witness_variable(|| x_val.ok_or(SynthesisError::AssignmentMissing))?;

        // x * x = tmp_1, allocate tmp_1
        let tmp_1_val = x_val.map(|e| e.square());
        let tmp_1 =
            cs.new_witness_variable(|| tmp_1_val.ok_or(SynthesisError::AssignmentMissing))?;
        // enforce constraints x * x = tmp_1
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + tmp_1)?;

        // tmp_1 * x = y, allocate y
        let x_cubed_val = tmp_1_val.map(|mut e| {
            e.mul_assign(&x_val.unwrap());
            e
        });
        let x_cubed =
            cs.new_witness_variable(|| x_cubed_val.ok_or(SynthesisError::AssignmentMissing))?;
        // enforce constraints tmp_1 * x = y
        cs.enforce_constraint(lc!() + tmp_1, lc!() + x, lc!() + x_cubed)?;

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
            lc!() + out,
        )?;

        Ok(())
    }
}

// circuit: prover claims that she knows two factors a and b of some public value c
#[derive(Copy, Clone)]
struct MultiplyDemoCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
    num_constraints: usize,
    num_variables: usize,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MultiplyDemoCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..(self.num_constraints - 1) {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as BlsFr};
    use ark_marlin::Marlin;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly_commit::marlin_pc::MarlinKZG10;
    use ark_std::{ops::*, UniformRand};
    use blake2::Blake2s;

    #[test]
    fn test_marlin_universal_srs() {
        type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
        type MarlinInst = Marlin<BlsFr, MultiPC, Blake2s>;

        let num_constraints: usize = 24;
        let num_variables: usize = 24;
        let rng = &mut ark_std::test_rng();

        let universal_srs =
            MarlinInst::universal_setup(num_constraints, num_variables, num_variables, rng)
                .unwrap();

        let circuit_cubic = CubicDemoCircuit {
            x: None,
            num_variables,
            num_constraints,
        };

        // generate the setup parameters
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit_cubic).unwrap();

        // calculate the proof by passing witness variable value
        let x = BlsFr::from(3);
        let circuit_cubic_instance = CubicDemoCircuit {
            x: Some(x),
            num_variables,
            num_constraints,
        };
        let proof = MarlinInst::prove(&index_pk, circuit_cubic_instance, rng).unwrap();

        // validate the proof
        assert!(MarlinInst::verify(&index_vk, &[BlsFr::from(35)], &proof, rng).unwrap());

        // multiply circuit
        let circuit_mul = MultiplyDemoCircuit {
            a: None,
            b: None,
            num_variables,
            num_constraints,
        };

        // generate the setup parameters
        let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit_mul).unwrap();

        // calculate the proof by passing witness variable value
        let a = BlsFr::rand(rng);
        let b = BlsFr::rand(rng);
        let circuit_mul_instance = MultiplyDemoCircuit {
            a: Some(a),
            b: Some(b),
            num_variables,
            num_constraints,
        };
        let proof = MarlinInst::prove(&index_pk, circuit_mul_instance, rng).unwrap();

        // validate the proof
        let mut c = a;
        c.mul_assign(&b);
        assert!(MarlinInst::verify(&index_vk, &[c], &proof, rng).unwrap());
    }
}
