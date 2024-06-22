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

impl<S: Suite> core::fmt::Debug for TestVector<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sk = hex::encode(utils::encode_scalar::<S>(&self.sk));
        let pk = hex::encode(utils::encode_point::<S>(&self.pk));
        let alpha = hex::encode(&self.alpha);
        let ad = hex::encode(&self.ad);
        let h = hex::encode(utils::encode_point::<S>(&self.h));
        let gamma = hex::encode(utils::encode_point::<S>(&self.gamma));
        let beta = hex::encode(&self.beta);
        f.debug_struct("TestVector")
            .field("comment", &self.comment)
            .field("flags", &self.flags)
            .field("sk", &sk)
            .field("pk", &pk)
            .field("alpha", &alpha)
            .field("ad", &ad)
            .field("h", &h)
            .field("gamma", &gamma)
            .field("beta", &beta)
            .finish()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestVectorMap(pub indexmap::IndexMap<String, String>);

impl TestVectorMap {
    pub fn item_bytes(&self, field: &str) -> Vec<u8> {
        hex::decode(self.0.get(field).unwrap()).unwrap()
    }
}

pub trait TestVectorTrait {
    fn new(
        comment: &str,
        seed: &[u8],
        alpha: &[u8],
        salt: Option<&[u8]>,
        ad: &[u8],
        flags: u8,
    ) -> Self;

    fn from_map(map: &TestVectorMap) -> Self;

    fn to_map(&self) -> TestVectorMap;

    fn run(&self);
}

pub struct TestVector<S: Suite> {
    pub comment: String,
    pub flags: u8,
    pub sk: ScalarField<S>,
    pub pk: AffinePoint<S>,
    pub alpha: Vec<u8>,
    pub ad: Vec<u8>,
    pub h: AffinePoint<S>,
    pub gamma: AffinePoint<S>,
    pub beta: Vec<u8>,
}

pub const TEST_FLAG_SKIP_PROOF_CHECK: u8 = 1 << 0;

impl<S: Suite + std::fmt::Debug> TestVectorTrait for TestVector<S> {
    fn new(
        comment: &str,
        seed: &[u8],
        alpha: &[u8],
        salt: Option<&[u8]>,
        ad: &[u8],
        flags: u8,
    ) -> Self {
        let sk = Secret::<S>::from_seed(seed);
        let pk = sk.public().0;

        let salt = salt
            .map(|v| v.to_vec())
            .unwrap_or_else(|| utils::encode_point::<S>(&pk));

        let h2c_data = [&salt[..], alpha].concat();
        let h = <S as Suite>::data_to_point(&h2c_data).unwrap();
        let input = Input::from(h);

        let alpha = alpha.to_vec();
        let output = sk.output(input);
        let gamma = output.0;
        let beta = output.hash().to_vec();

        TestVector {
            comment: comment.to_string(),
            sk: sk.scalar,
            pk,
            alpha,
            ad: ad.to_vec(),
            h,
            gamma,
            beta,
            flags,
        }
    }

    fn from_map(map: &TestVectorMap) -> Self {
        let item_bytes = |field| hex::decode(map.0.get(field).unwrap()).unwrap();
        let comment = map.0.get("comment").unwrap().to_string();
        let flags = item_bytes("flags")[0];
        let sk = utils::decode_scalar::<S>(&item_bytes("sk"));
        let pk = utils::decode_point::<S>(&item_bytes("pk"));
        let alpha = item_bytes("alpha");
        let ad = item_bytes("ad");
        let h = utils::decode_point::<S>(&item_bytes("h"));
        let gamma = utils::decode_point::<S>(&item_bytes("gamma"));
        let beta = item_bytes("beta");
        Self {
            comment,
            flags,
            sk,
            pk,
            alpha,
            ad,
            h,
            gamma,
            beta,
        }
    }

    fn to_map(&self) -> TestVectorMap {
        let items = [
            ("comment", self.comment.clone()),
            ("flags", hex::encode([self.flags])),
            ("sk", hex::encode(utils::encode_scalar::<S>(&self.sk))),
            ("pk", hex::encode(utils::encode_point::<S>(&self.pk))),
            ("alpha", hex::encode(&self.alpha)),
            ("ad", hex::encode(&self.ad)),
            ("h", hex::encode(utils::encode_point::<S>(&self.h))),
            ("gamma", hex::encode(utils::encode_point::<S>(&self.gamma))),
            ("beta", hex::encode(&self.beta)),
            // ("proof_c", hex::encode(utils::encode_scalar::<S>(&v.c))),
            // ("proof_s", hex::encode(utils::encode_scalar::<S>(&v.s))),
        ];
        let map: indexmap::IndexMap<String, String> =
            items.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        TestVectorMap(map)
    }

    fn run(&self) {
        println!("Running test vector: {}", self.comment);

        let sk = Secret::<S>::from_scalar(self.sk);

        let pk = sk.public();
        assert_eq!(self.pk, pk.0, "public key ('pk') mismatch");

        // Prepare hash_to_curve data = salt || alpha
        // Salt is defined to be pk (adjust it to make the encoding to match)
        let pk_bytes = utils::encode_point::<S>(&pk.0);
        let h2c_data = [&pk_bytes[..], &self.alpha[..]].concat();

        let h = S::data_to_point(&h2c_data).unwrap();
        assert_eq!(self.h, h, "hash-to-curve ('h') mismatch");
        let input = Input::<S>::from(h);

        let output = sk.output(input);
        assert_eq!(self.gamma, output.0, "VRF pre-output ('gamma') mismatch");

        if self.flags & TEST_FLAG_SKIP_PROOF_CHECK != 0 {
            return;
        }

        let beta = output.hash().to_vec();
        assert_eq!(self.beta, beta, "VRF output ('beta') mismatch");
    }
}

pub fn test_vectors_generate<V: TestVectorTrait + std::fmt::Debug>(file: &str, identifier: &str) {
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
        let comment = format!("{} - vector-{}", identifier, i + 1);
        let vector = V::new(&comment, &[i as u8], &alpha, None, &ad, 0);
        vector.run();
        vector_maps.push(vector.to_map());
    }

    let mut file = File::create(file).unwrap();
    let json = serde_json::to_string_pretty(&vector_maps).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

pub fn test_vectors_process<V: TestVectorTrait>(file: &str) {
    use std::{fs::File, io::BufReader};

    let file = File::open(file).unwrap();
    let reader = BufReader::new(file);

    let vector_maps: Vec<TestVectorMap> = serde_json::from_reader(reader).unwrap();

    for vector_map in vector_maps.iter() {
        let vector = V::from_map(vector_map);
        vector.run();
    }
}
