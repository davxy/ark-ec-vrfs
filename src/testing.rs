#![allow(unused)]
#[cfg(not(feature = "std"))]
use ark_std::{vec, vec::Vec};

use crate::*;
use ark_std::{rand::RngCore, UniformRand};

// The basis that hides the hidden light, which eludes the mind and creates darkness for those who see.
pub const PEDERSEN_BASE_SEED: &[u8] =
    b"basis caecans lucis occultae, quae mentem fugit et tenebras iis qui vident creat";

// "The substratum of the accumulator, which in the silence of time guards the hidden secret"
pub const ACCUMULATOR_BASE_SEED: &[u8] =
    b"substratum accumulatoris, quod in silentio temporis arcanum absconditum custodit";

// "A shadow that fills the void left by lost souls, echoing among the darkness"
pub const PADDING_SEED: &[u8] =
    b"umbra quae vacuum implet, ab animabus perditis relictum, inter tenebras resonans";

pub const TEST_SEED: &[u8] = b"seed";

// Zcash SRS file derived from (https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony).
pub const PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/zcash-bls12-381-srs-2-11-uncompressed.bin"
);

// Test vectors folder
pub const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/vectors");

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
    ($suite:ident, $build_ring:expr) => {
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
    pub fn get_bytes(&self, field: &str) -> Vec<u8> {
        hex::decode(self.0.get(field).unwrap()).unwrap()
    }

    pub fn set_bytes(&mut self, field: &str, buf: &[u8]) {
        self.0.insert(field.to_string(), hex::encode(buf));
    }

    pub fn get<T: CanonicalDeserialize>(&self, field: &str) -> T {
        let buf = self.get_bytes(field);
        T::deserialize_compressed(&buf[..]).unwrap()
    }

    pub fn set(&mut self, field: &str, value: &impl CanonicalSerialize) {
        let mut buf = Vec::new();
        value.serialize_compressed(&mut buf).unwrap();
        self.set_bytes(field, &buf);
    }
}

pub trait TestVectorTrait {
    fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self;

    fn from_map(map: &TestVectorMap) -> Self;

    fn to_map(&self) -> TestVectorMap;

    fn run(&self);
}

pub struct TestVector<S: Suite> {
    /// Useful info for the vector.
    pub comment: String,
    /// Secret key scalar.
    pub sk: ScalarField<S>,
    /// Public key point.
    pub pk: AffinePoint<S>,
    /// VRF input raw data.
    pub alpha: Vec<u8>,
    /// VRF input salt.
    pub salt: Vec<u8>,
    /// Signature additional raw data.
    pub ad: Vec<u8>,
    /// VRF input point.
    pub h: AffinePoint<S>,
    /// VRF output point.
    pub gamma: AffinePoint<S>,
    /// VRF output raw data
    pub beta: Vec<u8>,
}

impl<S: Suite> core::fmt::Debug for TestVector<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sk = hex::encode(codec::scalar_encode::<S>(&self.sk));
        let pk = hex::encode(codec::point_encode::<S>(&self.pk));
        let alpha = hex::encode(&self.alpha);
        let salt = hex::encode(&self.salt);
        let ad = hex::encode(&self.ad);
        let h = hex::encode(codec::point_encode::<S>(&self.h));
        let gamma = hex::encode(codec::point_encode::<S>(&self.gamma));
        let beta = hex::encode(&self.beta);
        f.debug_struct("TestVector")
            .field("comment", &self.comment)
            .field("sk", &sk)
            .field("pk", &pk)
            .field("alpha", &alpha)
            .field("salt", &salt)
            .field("ad", &ad)
            .field("h", &h)
            .field("gamma", &gamma)
            .field("beta", &beta)
            .finish()
    }
}

impl<S: Suite + std::fmt::Debug> TestVectorTrait for TestVector<S> {
    fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
        let sk = Secret::<S>::from_seed(seed);
        let pk = sk.public().0;

        let h2c_data = [salt, alpha].concat();
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
            salt: salt.to_vec(),
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
        let salt = item_bytes("salt");
        let ad = item_bytes("ad");
        let h = codec::point_decode::<S>(&item_bytes("h")).unwrap();
        let gamma = codec::point_decode::<S>(&item_bytes("gamma")).unwrap();
        let beta = item_bytes("beta");
        Self {
            comment,
            sk,
            pk,
            alpha,
            salt,
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
            ("salt", hex::encode(&self.salt)),
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

        let h2c_data = [&self.salt[..], &self.alpha[..]].concat();
        let h = S::data_to_point(&h2c_data).unwrap();
        assert_eq!(self.h, h, "hash-to-curve ('h') mismatch");
        let input = Input::<S>::from(h);

        let output = sk.output(input);
        assert_eq!(self.gamma, output.0, "VRF pre-output ('gamma') mismatch");

        let beta = output.hash().to_vec();
        assert_eq!(self.beta, beta, "VRF output ('beta') mismatch");
    }
}

fn vector_filename(identifier: &str) -> String {
    [VECTORS_DIR, "/", identifier, ".json"].concat()
}

pub fn test_vectors_generate<V: TestVectorTrait + std::fmt::Debug>(identifier: &str) {
    use std::{fs::File, io::Write};

    // ("secret_seed", "vrf raw input", "additional data"))
    let var_data: Vec<(u8, &[u8], &[u8])> = vec![
        (1, b"", b""),
        (2, b"0a", b""),
        (3, b"", b"0b8c"),
        (4, b"73616D706C65", b""),
        (5, b"42616E646572736E6174636820766563746F72", b""),
        (5, b"42616E646572736E6174636820766563746F72", b"1F42"),
        (6, b"42616E646572736E6174636820766563746F72", b"1F42"),
    ];

    let mut vector_maps = Vec::with_capacity(var_data.len());

    for (i, var_data) in var_data.iter().enumerate() {
        let alpha = hex::decode(var_data.1).unwrap();
        let ad = hex::decode(var_data.2).unwrap();
        let comment = format!("{} - vector-{}", identifier, i + 1);
        let vector = V::new(&comment, &[var_data.0], &alpha, b"", &ad);
        println!("Gen test vector: {}", comment);
        vector.run();
        vector_maps.push(vector.to_map());
    }

    let mut file = File::create(vector_filename(identifier)).unwrap();
    let json = serde_json::to_string_pretty(&vector_maps).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

pub fn test_vectors_process<V: TestVectorTrait>(identifier: &str) {
    use std::{fs::File, io::BufReader};

    let file = File::open(vector_filename(identifier)).unwrap();
    let reader = BufReader::new(file);

    let vector_maps: Vec<TestVectorMap> = serde_json::from_reader(reader).unwrap();

    for vector_map in vector_maps.iter() {
        let vector = V::from_map(vector_map);
        vector.run();
    }
}
