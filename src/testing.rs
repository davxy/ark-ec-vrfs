#![allow(unused)]
#[cfg(not(feature = "std"))]
use ark_std::{vec, vec::Vec};

use crate::*;
use ark_std::{rand::RngCore, UniformRand};

pub const TEST_SEED: &[u8] = b"seed";

/// Generate a vector of random values.
pub fn random_vec<T: UniformRand>(n: usize, rng: Option<&mut dyn RngCore>) -> Vec<T> {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    (0..n).map(|_| T::rand(rng)).collect()
}

/// Generate a vector of random values.
pub fn random_val<T: UniformRand>(rng: Option<&mut dyn RngCore>) -> T {
    let mut local_rng = ark_std::test_rng();
    let rng = rng.unwrap_or(&mut local_rng);
    T::rand(rng)
}

#[macro_export]
macro_rules! suite_tests {
    ($suite:ident, $build_ring:ident) => {
        suite_tests!($suite);
        ring_suite_tests!($suite, $build_ring);
    };
    ($suite:ident) => {
        ietf_suite_tests!($suite);
        pedersen_suite_tests!($suite);
    };
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TestVectorMap(pub indexmap::IndexMap<String, String>);

impl TestVectorMap {
    pub fn item_bytes(&self, field: &str) -> Vec<u8> {
        hex::decode(self.0.get(field).unwrap()).unwrap()
    }
}

pub trait TestVectorTrait {
    fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: Option<&[u8]>, ad: &[u8]) -> Self;

    fn from_map(map: &TestVectorMap) -> Self;

    fn to_map(&self) -> TestVectorMap;

    fn run(&self);
}

pub struct TestVector<S: Suite> {
    pub comment: String,
    pub sk: ScalarField<S>,
    pub pk: AffinePoint<S>,
    pub alpha: Vec<u8>,
    pub ad: Vec<u8>,
    pub h: AffinePoint<S>,
    pub gamma: AffinePoint<S>,
    pub beta: Vec<u8>,
}

impl<S: Suite> core::fmt::Debug for TestVector<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sk = hex::encode(codec::scalar_encode::<S>(&self.sk));
        let pk = hex::encode(codec::point_encode::<S>(&self.pk));
        let alpha = hex::encode(&self.alpha);
        let ad = hex::encode(&self.ad);
        let h = hex::encode(codec::point_encode::<S>(&self.h));
        let gamma = hex::encode(codec::point_encode::<S>(&self.gamma));
        let beta = hex::encode(&self.beta);
        f.debug_struct("TestVector")
            .field("comment", &self.comment)
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

impl<S: Suite + std::fmt::Debug> TestVectorTrait for TestVector<S> {
    fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: Option<&[u8]>, ad: &[u8]) -> Self {
        let sk = Secret::<S>::from_seed(seed);
        let pk = sk.public().0;

        let salt = salt
            .map(|v| v.to_vec())
            .unwrap_or_else(|| codec::point_encode::<S>(&pk));

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
        }
    }

    fn from_map(map: &TestVectorMap) -> Self {
        let item_bytes = |field| hex::decode(map.0.get(field).unwrap()).unwrap();
        let comment = map.0.get("comment").unwrap().to_string();
        let sk = codec::scalar_decode::<S>(&item_bytes("sk"));
        let pk = codec::point_decode::<S>(&item_bytes("pk")).unwrap();
        let alpha = item_bytes("alpha");
        let ad = item_bytes("ad");
        let h = codec::point_decode::<S>(&item_bytes("h")).unwrap();
        let gamma = codec::point_decode::<S>(&item_bytes("gamma")).unwrap();
        let beta = item_bytes("beta");
        Self {
            comment,
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
            ("sk", hex::encode(codec::scalar_encode::<S>(&self.sk))),
            ("pk", hex::encode(codec::point_encode::<S>(&self.pk))),
            ("alpha", hex::encode(&self.alpha)),
            ("ad", hex::encode(&self.ad)),
            ("h", hex::encode(codec::point_encode::<S>(&self.h))),
            ("gamma", hex::encode(codec::point_encode::<S>(&self.gamma))),
            ("beta", hex::encode(&self.beta)),
        ];
        let map: indexmap::IndexMap<String, String> =
            items.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        TestVectorMap(map)
    }

    fn run(&self) {
        println!("Run test vector: {}", self.comment);

        let sk = Secret::<S>::from_scalar(self.sk);

        let pk = sk.public();
        assert_eq!(self.pk, pk.0, "public key ('pk') mismatch");

        // Prepare hash_to_curve data = salt || alpha
        // Salt is defined to be pk (adjust it to make the encoding to match)
        let pk_bytes = codec::point_encode::<S>(&pk.0);
        let h2c_data = [&pk_bytes[..], &self.alpha[..]].concat();

        let h = S::data_to_point(&h2c_data).unwrap();
        assert_eq!(self.h, h, "hash-to-curve ('h') mismatch");
        let input = Input::<S>::from(h);

        let output = sk.output(input);
        assert_eq!(self.gamma, output.0, "VRF pre-output ('gamma') mismatch");

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
        let vector = V::new(&comment, &[i as u8], &alpha, None, &ad);
        println!("Gen test vector: {}", comment);
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
