use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

// circuit: prover claims that she knows two factors a and b of some public value c
#[derive(Copy, Clone)]
struct MultiplyDemoCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
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

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as BlsFr};
    use ark_groth16::Groth16;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_snark::SNARK;
    use ark_std::{ops::*, UniformRand};

    #[test]
    fn test_groth16_circuit_multiply() {
        let rng = &mut ark_std::test_rng();

        // generate the setup parameters
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyDemoCircuit::<BlsFr> { a: None, b: None },
            rng,
        )
        .unwrap();
        for _ in 0..5 {
            let a = BlsFr::rand(rng);
            let b = BlsFr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            // calculate the proof by passing witness variable value
            let proof = Groth16::<Bls12_381>::prove(
                &pk,
                MultiplyDemoCircuit::<BlsFr> {
                    a: Some(a),
                    b: Some(b),
                },
                rng,
            )
            .unwrap();

            // validate the proof
            assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
            assert!(!Groth16::<Bls12_381>::verify(&vk, &[a], &proof).unwrap());
        }
    }

    #[test]
    fn test_serde_groth16() {
        let rng = &mut ark_std::test_rng();

        // generate the setup parameters
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyDemoCircuit::<BlsFr> { a: None, b: None },
            rng,
        )
        .unwrap();

        let a = BlsFr::rand(rng);
        let b = BlsFr::rand(rng);
        let mut c = a;
        c.mul_assign(&b);

        // calculate the proof by passing witness variable value
        let proof = Groth16::<Bls12_381>::prove(
            &pk,
            MultiplyDemoCircuit::<BlsFr> {
                a: Some(a),
                b: Some(b),
            },
            rng,
        )
        .unwrap();

        let mut serialized = vec![0; proof.serialized_size()];
        proof.serialize(&mut serialized[..]).unwrap();

        // println!("proof: {:?}", proof.serialized_size());
        // println!("proof: {:?}", serialized);

        let pr = <Groth16<Bls12_381> as SNARK<BlsFr>>::Proof::deserialize(&serialized[..]).unwrap();
        assert_eq!(proof, pr);

        let mut serialized = vec![0; pk.serialized_size()];
        pk.serialize(&mut serialized[..]).unwrap();

        // println!("pk-size: {:?}", pk.serialized_size());
        // println!("pk: {:?}", serialized);
        let p =
            <Groth16<Bls12_381> as SNARK<BlsFr>>::ProvingKey::deserialize(&serialized[..]).unwrap();
        assert_eq!(pk, p);

        let mut serialized = vec![0; vk.serialized_size()];
        vk.serialize(&mut serialized[..]).unwrap();

        // println!("vk-size: {:?}", vk.serialized_size());
        // println!("vk: {:?}", serialized);

        let v = <Groth16<Bls12_381> as SNARK<BlsFr>>::VerifyingKey::deserialize(&serialized[..])
            .unwrap();
        assert_eq!(vk, v);

        assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
        assert!(Groth16::<Bls12_381>::verify(&v, &[c], &pr).unwrap());
    }
}
