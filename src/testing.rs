#[cfg(not(feature = "std"))]
use ark_std::{vec, vec::Vec};

use crate::*;
use ark_std::{rand::RngCore, UniformRand};

pub const TEST_SEED: &[u8] = b"seed";

pub(crate) mod suite {
    use super::*;

    #[derive(Debug, Copy, Clone, PartialEq)]
    pub struct TestSuite;

    impl Suite for TestSuite {
        const SUITE_ID: u8 = 0xFF;
        const CHALLENGE_LEN: usize = 16;

        type Affine = ark_ed25519::EdwardsAffine;
        type Hasher = sha2::Sha256;
    }

    suite_types!(TestSuite);
}

#[allow(unused)]
pub fn random_vec<T: UniformRand>(n: usize, rng: Option<&mut dyn RngCore>) -> Vec<T> {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    (0..n).map(|_| T::rand(rng)).collect()
}

#[allow(unused)]
pub fn random_val<T: UniformRand>(rng: Option<&mut dyn RngCore>) -> T {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    T::rand(rng)
}

pub fn ietf_prove_verify<S: crate::ietf::IetfSuite>() {
    use crate::ietf::{IetfProver, IetfVerifier};

    let secret = Secret::<S>::from_seed(TEST_SEED);
    let public = secret.public();
    let input = Input::from(random_val(None));
    let output = secret.output(input);

    let mut buf = Vec::new();
    public.serialize_compressed(&mut buf).unwrap();
    println!("{}", buf.len());

    let proof = secret.prove(input, output, b"foo");
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    println!("{}", buf.len());

    let result = public.verify(input, output, b"foo", &proof);
    assert!(result.is_ok());
}

pub fn pedersen_prove_verify<S: crate::pedersen::PedersenSuite>() {
    use crate::pedersen::{PedersenProver, PedersenVerifier};

    let secret = Secret::<S>::from_seed(TEST_SEED);
    let input = Input::from(random_val(None));
    let output = secret.output(input);

    let (proof, blinding) = secret.prove(input, output, b"foo");
    let mut buf = Vec::new();
    secret.public().serialize_compressed(&mut buf).unwrap();
    println!("{}", buf.len());

    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    println!("{}", buf.len());

    let result = Public::verify(input, output, b"foo", &proof);
    assert!(result.is_ok());

    assert_eq!(
        proof.key_commitment(),
        (secret.public().0 + S::BLINDING_BASE * blinding).into()
    );
}

#[cfg(feature = "ring")]
pub fn ring_prove_verify<S: crate::ring::RingSuite>()
where
    S::Config: ark_ec::short_weierstrass::SWCurveConfig + Clone,
    <S::Config as ark_ec::CurveConfig>::BaseField: ark_ff::PrimeField,
{
    use crate::ring::{RingContext, RingProver, RingVerifier};

    let rng = &mut ark_std::test_rng();
    let domain_size = 1024;
    let ring_ctx = RingContext::<S>::new_random(domain_size, rng);

    let secret = Secret::<S>::from_seed(TEST_SEED);
    let public = secret.public();
    let input = Input::from(random_val(Some(rng)));
    let output = secret.output(input);

    let keyset_size = ring_ctx.piop_params.keyset_part_size;

    let prover_idx = 3;
    let mut pks = random_vec::<AffinePoint<S>>(keyset_size, Some(rng));
    pks[prover_idx] = public.0;

    let prover_key = ring_ctx.prover_key(pks.clone());
    let prover = ring_ctx.prover(prover_key, prover_idx);
    let proof = secret.prove(input, output, b"foo", &prover);
    let mut buf = Vec::new();
    proof.serialize_compressed(&mut buf).unwrap();
    println!("RING PROOF LEN: {}", buf.len());

    let verifier_key = ring_ctx.verifier_key(pks);
    let verifier = ring_ctx.verifier(verifier_key);
    let result = Public::verify(input, output, b"foo", &proof, &verifier);
    assert!(result.is_ok());
}
