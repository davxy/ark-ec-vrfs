use crate::{AffinePoint, ScalarField, Suite};
use ark_ff::PrimeField;
use digest::{core_api::BlockSizeUser, Digest};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

#[macro_export]
macro_rules! suite_types {
    ($suite:ident) => {
        #[allow(dead_code)]
        pub type Secret = $crate::Secret<$suite>;
        #[allow(dead_code)]
        pub type Public = $crate::Public<$suite>;
        #[allow(dead_code)]
        pub type Input = $crate::Input<$suite>;
        #[allow(dead_code)]
        pub type Output = $crate::Output<$suite>;
        #[allow(dead_code)]
        pub type AffinePoint = $crate::AffinePoint<$suite>;
        #[allow(dead_code)]
        pub type ScalarField = $crate::ScalarField<$suite>;
        #[allow(dead_code)]
        pub type BaseField = $crate::BaseField<$suite>;
        #[allow(dead_code)]
        pub type Signature = $crate::ietf::Signature<$suite>;
    };
}

// Generic hash wrapper.
#[inline(always)]
pub(crate) fn hash<H: Digest>(data: &[u8]) -> digest::Output<H> {
    H::new().chain_update(data).finalize()
}

/// Generic HMAC wrapper.
#[inline(always)]
pub(crate) fn hmac<H: Digest + BlockSizeUser>(sk: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Mac, SimpleHmac};
    SimpleHmac::<H>::new_from_slice(sk)
        .expect("HMAC can take key of any size")
        .chain_update(data)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// Try-And-Increment (TAI) method as defined by RFC9381 section 5.4.1.1.
///
/// Implements ECVRF_encode_to_curve in a simple and generic way that works
/// for any elliptic curve.
///
/// To use this algorithm, hash length MUST be at least equal to the field length.
///
/// The running time of this algorithm depends on input string. For the
/// ciphersuites specified in Section 5.5, this algorithm is expected to
/// find a valid curve point after approximately two attempts on average.
///
/// The input `data` is defined to be `salt || alpha` according to the spec.
pub fn hash_to_curve_tai<S: Suite>(data: &[u8], point_be_encoding: bool) -> Option<AffinePoint<S>> {
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use ark_serialize::CanonicalDeserialize;

    const DOM_SEP_FRONT: u8 = 0x01;
    const DOM_SEP_BACK: u8 = 0x00;

    let mod_size = <<<S::Affine as AffineRepr>::BaseField as Field>::BasePrimeField as PrimeField>::MODULUS_BIT_SIZE as usize / 8;
    if S::Hasher::output_size() < mod_size {
        return None;
    }

    let mut buf = [&[S::SUITE_ID, DOM_SEP_FRONT], data, &[0x00, DOM_SEP_BACK]].concat();
    let ctr_pos = buf.len() - 2;

    for ctr in 0..256 {
        // Modify ctr value
        buf[ctr_pos] = ctr as u8;
        let hash = &hash::<S::Hasher>(&buf)[..];
        if hash.len() < mod_size {
            return None;
        }
        let mut hash = hash.to_vec();
        if point_be_encoding {
            hash.reverse();
        }
        hash.push(0x00);

        if let Ok(pt) = AffinePoint::<S>::deserialize_compressed_unchecked(&hash[..]) {
            let pt = pt.clear_cofactor();
            if !pt.is_zero() {
                return Some(pt);
            }
        }
    }
    None
}

/// Nonce generation according to RFC 9381 section 5.4.2.2.
///
/// This procedure is based on section 5.1.6 of RFC 8032: "Edwards-Curve Digital
/// Signature Algorithm (EdDSA)".
///
/// The algorithm generate the nonce value in a deterministic
/// pseudorandom fashion.
///
/// `Suite::Hash` is recommended to be be at least 64 bytes.
///
/// # Panics
///
/// This function panics if `Hash` is less than 32 bytes.
pub fn nonce_rfc_8032<S: Suite>(sk: &ScalarField<S>, input: &AffinePoint<S>) -> ScalarField<S> {
    let raw = encode_scalar::<S>(sk);
    let sk_hash = &hash::<S::Hasher>(&raw)[32..];

    let raw = encode_point::<S>(input);
    let v = [sk_hash, &raw[..]].concat();
    let h = &hash::<S::Hasher>(&v)[..];

    S::scalar_decode(h)
}

/// Nonce generation according to RFC 9381 section 5.4.2.1.
///
/// This procedure is based on section 3.2 of RFC 6979: "Deterministic Usage of
/// the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature
/// Algorithm (ECDSA)".
///
/// The algorithm generate the nonce value in a deterministic
/// pseudorandom fashion.
pub fn nonce_rfc_6979<S: Suite>(sk: &ScalarField<S>, input: &AffinePoint<S>) -> ScalarField<S>
where
    S::Hasher: BlockSizeUser,
{
    let raw = encode_point::<S>(input);
    let h1 = hash::<S::Hasher>(&raw);

    let v = [1; 32];
    let k = [0; 32];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let x = encode_scalar::<S>(sk);
    let raw = [&v[..], &[0x00], &x[..], &h1[..]].concat();
    let k = hmac::<S::Hasher>(&k, &raw);

    // V = HMAC_K(V)
    let v = hmac::<S::Hasher>(&k, &v);

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let raw = [&v[..], &[0x01], &x[..], &h1[..]].concat();
    let k = hmac::<S::Hasher>(&k, &raw);

    // V = HMAC_K(V)
    let v = hmac::<S::Hasher>(&k, &v);

    // TODO: loop until 1 < k < q
    let v = hmac::<S::Hasher>(&k, &v);

    S::scalar_decode(&v)
}

pub fn encode_point<S: Suite>(pt: &AffinePoint<S>) -> Vec<u8> {
    let mut buf = Vec::new();
    S::point_encode(pt, &mut buf);
    buf
}

pub fn encode_scalar<S: Suite>(sc: &ScalarField<S>) -> Vec<u8> {
    let mut buf = Vec::new();
    S::scalar_encode(sc, &mut buf);
    buf
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::*;
    use ark_std::{rand::RngCore, UniformRand};

    pub const TEST_SEED: &[u8] = b"seed";

    #[derive(Debug, Copy, Clone, PartialEq)]
    pub struct TestSuite;

    impl Suite for TestSuite {
        const SUITE_ID: u8 = 0xFF;
        const CHALLENGE_LEN: usize = 16;

        type Affine = ark_ed25519::EdwardsAffine;
        type Hasher = sha2::Sha256;
    }

    suite_types!(TestSuite);

    #[inline(always)]
    #[allow(unused)]
    pub fn random_vec<T: UniformRand>(n: usize, rng: Option<&mut dyn RngCore>) -> Vec<T> {
        let mut local_rng = ark_std::test_rng();
        let rng = rng.unwrap_or(&mut local_rng);
        (0..n).map(|_| T::rand(rng)).collect()
    }

    #[inline(always)]
    #[allow(unused)]
    pub fn random_val<T: UniformRand>(rng: Option<&mut dyn RngCore>) -> T {
        let mut local_rng = ark_std::test_rng();
        let rng = rng.unwrap_or(&mut local_rng);
        T::rand(rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::TestSuite;

    #[test]
    fn hash_to_curve_tai_works() {
        let pt = hash_to_curve_tai::<TestSuite>(b"hello world", false).unwrap();
        // Check that `pt` is in the prime subgroup
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }
}
