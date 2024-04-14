use crate::{AffinePoint, Suite};
use ark_ff::PrimeField;

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

/// SHA-256 hasher
#[inline(always)]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut h = [0u8; 32];
    h.copy_from_slice(&result);
    h
}

/// SHA-512 hasher
#[inline(always)]
pub fn sha512(input: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut h = [0u8; 64];
    h.copy_from_slice(&result);
    h
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
pub fn hash_to_curve_tai<S: Suite>(data: &[u8]) -> Option<AffinePoint<S>> {
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use ark_serialize::CanonicalDeserialize;

    const DOM_SEP_FRONT: u8 = 0x01;
    const DOM_SEP_BACK: u8 = 0x00;

    let mod_size = <<<S::Affine as AffineRepr>::BaseField as Field>::BasePrimeField as PrimeField>::MODULUS_BIT_SIZE as usize / 8;

    let mut buf = [&[S::SUITE_ID, DOM_SEP_FRONT], data, &[0x00, DOM_SEP_BACK]].concat();
    let ctr_pos = buf.len() - 2;

    for ctr in 0..256 {
        // Modify ctr value
        buf[ctr_pos] = ctr as u8;
        let hash = &S::hash(&buf)[..];
        if hash.len() < mod_size {
            return None;
        }
        // TODO This is specific for P256 (maybe we should add a method in Suite? Maybe another trait?)
        // E.g. TaiSuite: Suite { fn point_decode }
        // The differences are on the flags, the length of the data and endianess (e.g. secp decodes from big endian)
        let mut hash = hash.to_vec();
        hash.reverse();
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
        type Hash = [u8; 64];

        fn hash(data: &[u8]) -> Self::Hash {
            utils::sha512(data)
        }
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
        let pt = hash_to_curve_tai::<TestSuite>(b"hello world").unwrap();
        // Check that `pt` is in the prime subgroup
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }
}
