#![allow(unused)]
#[cfg(not(feature = "std"))]
use ark_std::{vec, vec::Vec};

use crate::*;
use ark_std::{rand::RngCore, UniformRand};

pub const TEST_SEED: &[u8] = b"seed";

/// Zcash SRS file.
///
/// Derived from <https://zfnd.org/conclusion-of-the-powers-of-tau-ceremony>.
/// Domain size: 2^11.
pub const BLS12_381_PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/srs/bls12-381-srs-2-11-uncompressed-zcash.bin"
);

/// Pure testing SRS file
///
/// Derived from seed `[0_u8; 32]`.
/// Domain size 2^9.
pub const BN254_PCS_SRS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/srs/bn254-testing-2-9-uncompressed.bin"
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

pub trait CheckPoint {
    fn check(&self, in_prime_subgroup: bool) -> Result<(), &'static str>;
}

use ark_ec::short_weierstrass::{Affine as SWAffine, SWCurveConfig};
impl<C> CheckPoint for SWAffine<C>
where
    C: SWCurveConfig,
{
    fn check(&self, in_prime_subgroup: bool) -> Result<(), &'static str> {
        if !self.is_on_curve() {
            return Err("Point out of curve group");
        }
        if self.is_in_correct_subgroup_assuming_on_curve() != in_prime_subgroup {
            return Err("Point outside the expected curve subgroup");
        }
        Ok(())
    }
}

use ark_ec::twisted_edwards::{Affine as TEAffine, TECurveConfig};
impl<C> CheckPoint for TEAffine<C>
where
    C: TECurveConfig,
{
    fn check(&self, in_prime_subgroup: bool) -> Result<(), &'static str> {
        if !self.is_on_curve() {
            return Err("Point out of curve group");
        }
        if self.is_in_correct_subgroup_assuming_on_curve() != in_prime_subgroup {
            return Err("Point outside the expected curve subgroup");
        }
        Ok(())
    }
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
    fn name() -> String;

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

pub trait SuiteExt: Suite {
    fn suite_name() -> String {
        std::str::from_utf8(Self::SUITE_ID)
            .ok()
            .filter(|s| s.chars().all(|c| c.is_ascii_graphic()))
            .map(|s| s.to_owned())
            .unwrap_or_else(|| hex::encode(Self::SUITE_ID))
            .to_lowercase()
    }
}

impl<S: SuiteExt + std::fmt::Debug> TestVectorTrait for TestVector<S> {
    fn name() -> String {
        S::suite_name() + "_base"
    }

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

#[macro_export]
macro_rules! test_vectors {
    ($vector_type:ty) => {
        #[allow(unused)]
        use $crate::testing::TestVectorTrait as _;
        $crate::test_vectors!($vector_type, &<$vector_type>::name());
    };
    ($vector_type:ty, $vector_name:expr) => {
        #[test]
        #[ignore = "test vectors generator"]
        fn vectors_generate() {
            $crate::testing::test_vectors_generate::<$vector_type>($vector_name);
        }

        #[test]
        fn vectors_process() {
            $crate::testing::test_vectors_process::<$vector_type>($vector_name);
        }
    };
}
