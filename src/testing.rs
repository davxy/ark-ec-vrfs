#![allow(unused)]
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
        const SUITE_ID: &'static [u8] = b"ark-ec-vrfs-testing";
        const CHALLENGE_LEN: usize = 16;

        type Affine = ark_ed25519::EdwardsAffine;
        type Hasher = sha2::Sha256;
    }

    suite_types!(TestSuite);
}

pub fn random_vec<T: UniformRand>(n: usize, rng: Option<&mut dyn RngCore>) -> Vec<T> {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    (0..n).map(|_| T::rand(rng)).collect()
}

pub fn random_val<T: UniformRand>(rng: Option<&mut dyn RngCore>) -> T {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    T::rand(rng)
}

pub fn ietf_prove_verify<S: ietf::IetfSuite>() {
    use ietf::{Prover, Verifier};

    let secret = Secret::<S>::from_seed(TEST_SEED);
    let public = secret.public();
    let input = Input::from(random_val(None));
    let output = secret.output(input);

    let proof = secret.prove(input, output, b"foo");
    let result = public.verify(input, output, b"foo", &proof);
    assert!(result.is_ok());
}

pub fn pedersen_prove_verify<S: pedersen::PedersenSuite>() {
    use pedersen::{Prover, Verifier};

    let secret = Secret::<S>::from_seed(TEST_SEED);
    let input = Input::from(random_val(None));
    let output = secret.output(input);

    let (proof, blinding) = secret.prove(input, output, b"foo");
    let result = Public::verify(input, output, b"foo", &proof);
    assert!(result.is_ok());

    assert_eq!(
        proof.key_commitment(),
        (secret.public().0 + S::BLINDING_BASE * blinding).into()
    );
}

#[cfg(feature = "ring")]
pub fn ring_prove_verify<S: ring::RingSuite>()
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: ark_ec::short_weierstrass::SWCurveConfig + Clone,
    AffinePoint<S>: ring::IntoSW<CurveConfig<S>>,
{
    use ring::{Prover, RingContext, Verifier};

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

    let prover_key = ring_ctx.prover_key(&pks);
    let prover = ring_ctx.prover(prover_key, prover_idx);
    let proof = secret.prove(input, output, b"foo", &prover);

    let verifier_key = ring_ctx.verifier_key(&pks);
    let verifier = ring_ctx.verifier(verifier_key);
    let result = Public::verify(input, output, b"foo", &proof, &verifier);
    assert!(result.is_ok());
}

#[cfg(feature = "ring")]
pub fn check_complement_point<S: ring::RingSuite>()
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: ark_ec::short_weierstrass::SWCurveConfig + Clone,
    AffinePoint<S>: ring::IntoSW<CurveConfig<S>>,
{
    use ring::IntoSW;
    let pt = S::COMPLEMENT_POINT.into_sw();
    assert!(pt.is_on_curve());
    assert!(!pt.is_in_correct_subgroup_assuming_on_curve());
}

#[macro_export]
macro_rules! suite_tests {
    ($suite:ident, $build_ring:ident) => {
        suite_tests!($suite);
        ring_suite_tests!($suite, $build_ring);
    };
    ($suite:ident) => {
        #[test]
        fn ietf_prove_verify() {
            $crate::testing::ietf_prove_verify::<$suite>();
        }

        #[test]
        fn pedersen_prove_verify() {
            $crate::testing::pedersen_prove_verify::<$suite>();
        }
    };
}

#[macro_export]
macro_rules! ring_suite_tests {
    ($suite:ident, true) => {
        #[cfg(feature = "ring")]
        #[test]
        fn ring_prove_verify() {
            $crate::testing::ring_prove_verify::<$suite>()
        }

        #[cfg(feature = "ring")]
        #[test]
        fn check_complement_point() {
            $crate::testing::check_complement_point::<$suite>()
        }
    };
    ($suite:ident, false) => {};
}

use ietf::testing::{TestVector, TestVectorMap};

fn vec_to_ascii_string(buf: &[u8]) -> Option<String> {
    if buf.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
        Some(String::from_utf8(buf.to_vec()).unwrap())
    } else {
        None
    }
}

// Some aliases for built-in suites without a printable SUITE-ID
pub fn suite_alias(id: &[u8]) -> Option<String> {
    let alias_map: std::collections::BTreeMap<&[u8], &str> =
        vec![(&[0x01_u8][..], "secp256r1_sha256_tai")]
            .into_iter()
            .collect();
    alias_map.get(id).map(|s| s.to_string())
}

pub fn test_vectors_generate<S: ietf::IetfSuite + std::fmt::Debug>(file: &str) {
    use std::{fs::File, io::Write};
    // ("alpha", "ad"))
    let var_data: Vec<(&[u8], &[u8])> = vec![
        (b"", b""),
        (b"0a", b""),
        (b"", b"0b8c"),
        (b"73616D706C65", b""),
        (b"42616E646572736E6174636820766563746F72", b""),
        (b"42616E646572736E6174636820766563746F72", b"73616D706C65"),
    ];

    let mut vector_maps = Vec::with_capacity(var_data.len());

    for (i, var_data) in var_data.iter().enumerate() {
        let alpha = hex::decode(var_data.0).unwrap();
        let ad = hex::decode(var_data.1).unwrap();
        let suite_string =
            vec_to_ascii_string(S::SUITE_ID).unwrap_or_else(|| suite_alias(S::SUITE_ID).unwrap());
        let comment = format!("{} vector-{}", suite_string, i);
        let vector = TestVector::<S>::new(&comment, &[i as u8], &alpha, None, &ad, 0);
        println!("{:#?}", vector);
        vector.run();
        vector_maps.push(TestVectorMap::from(vector));
    }

    let mut file = File::create(file).unwrap();
    let json = serde_json::to_string_pretty(&vector_maps).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

pub fn test_vectors_process<S: ietf::IetfSuite + std::fmt::Debug>(file: &str) {
    use std::{fs::File, io::BufReader};

    let file = File::open(file).unwrap();
    let reader = BufReader::new(file);

    let vector_maps: Vec<TestVectorMap> = serde_json::from_reader(reader).unwrap();

    for vector_map in vector_maps {
        let vector = TestVector::<S>::from(vector_map);
        vector.run();
    }
}
