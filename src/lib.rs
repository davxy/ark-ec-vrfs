//! EC-VRF as specified by [RFC-9381](https://datatracker.ietf.org/doc/rfc9381).
//!
//! The implementation is built using Arkworks and is generic over the curve.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{vec, vec::Vec};

use core::ops::{Index, RangeFrom, RangeFull, RangeTo};

pub mod suites;
mod utils;

pub type ScalarField<S> = <<S as Suite>::Affine as AffineRepr>::ScalarField;
pub type AffinePoint<S> = <S as Suite>::Affine;

/// Verification error(s)
pub enum Error {
    VerificationFailure,
}

/// Defines a cipher suite as defined by RFC-9381 Section 5.5.
pub trait Suite: Copy + Clone {
    /// Suite identifier (aka `suite_string`)
    const SUITE_ID: u8;

    /// Challenge length.
    ///
    /// Must be at least equal to the Hash length.
    const CHALLENGE_LEN: usize;

    /// Affine point.
    ///
    /// The point is guaranteed to be in the correct prime order subgroup
    /// by the `AffineRepr` bound.
    type Affine: AffineRepr;

    /// Hash output.
    type Hash: Index<usize, Output = u8>
        + Index<RangeTo<usize>, Output = [u8]>
        + Index<RangeFrom<usize>, Output = [u8]>
        + Index<RangeFull, Output = [u8]>;

    /// Hasher
    fn hash(data: &[u8]) -> Self::Hash;

    /// Nonce generation as described by [RFC9381] section 5.4.2.
    ///
    /// In particular the default implementation provides the variant described
    /// by section 5.4.2.2 which is a derived from steps 2 and 3 in section 5.1.6
    /// of [RFC8032](https://tools.ietf.org/html/rfc8032).
    ///
    /// `Hash` MUST be be at least 64 bytes.
    ///
    /// # Panics
    ///
    /// This function panics if `Hash` is less than 32 bytes.
    fn nonce(sk: &ScalarField<Self>, pt: Input<Self>) -> ScalarField<Self> {
        let mut buf = Vec::new();
        sk.serialize_compressed(&mut buf).unwrap();
        let sk_hash = &Self::hash(&buf)[32..];
        buf.clear();
        pt.0.serialize_compressed(&mut buf).unwrap();
        let v = [sk_hash, &buf[..]].concat();
        let h = &Self::hash(&v)[..];
        ScalarField::<Self>::from_le_bytes_mod_order(h)
    }

    /// Challenge generation as described by [RCF9381] section 5.4.3.
    ///
    /// Hashes several points on the curve.
    ///
    /// RFC extension: implementation allows to hash some user additional data
    /// `ad` after the points and before the domain separation end.
    fn challenge(pts: &[&AffinePoint<Self>], ad: &[u8]) -> ScalarField<Self> {
        const DOM_SEP_START: u8 = 0x02;
        const DOM_SEP_END: u8 = 0x00;
        let mut buf = vec![Self::SUITE_ID, DOM_SEP_START];
        pts.iter().for_each(|p| {
            p.serialize_compressed(&mut buf).unwrap();
        });
        buf.extend_from_slice(ad);
        buf.push(DOM_SEP_END);
        let hash = &Self::hash(&buf)[..Self::CHALLENGE_LEN];
        ScalarField::<Self>::from_be_bytes_mod_order(hash)
    }
}

/// Secret key generic over the cipher suite.
// TODO: zeroize
#[derive(Debug, PartialEq)]
pub struct Secret<S: Suite> {
    // Secret scalar.
    scalar: ScalarField<S>,
    // Cached public point.
    public: Public<S>,
}

impl<S: Suite> CanonicalSerialize for Secret<S> {
    fn serialize_with_mode<W: ark_std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.scalar.serialized_size(compress)
    }
}

impl<S: Suite> CanonicalDeserialize for Secret<S> {
    fn deserialize_with_mode<R: ark_std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let scalar = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            reader, compress, validate,
        )?;
        Ok(Self::from_scalar(scalar))
    }
}

impl<S: Suite> Valid for Secret<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.check()
    }
}

impl<S: Suite> Secret<S> {
    /// Construct a `Secret` from the given scalar.
    pub fn from_scalar(scalar: ScalarField<S>) -> Self {
        let public = S::Affine::generator() * scalar;
        let public = Public(public.into_affine());
        Self { scalar, public }
    }

    /// Construct a `Secret` from the given seed.
    ///
    /// The `seed` is hashed using the `Suite::hash` to construct the secret scalar.
    pub fn from_seed(seed: &[u8]) -> Self {
        let bytes = S::hash(&seed);
        let scalar = ScalarField::<S>::from_le_bytes_mod_order(&bytes[..]);
        Self::from_scalar(scalar)
    }

    /// Construct an ephemeral `Secret` using system randomness.
    #[cfg(feature = "getrandom")]
    pub fn ephemeral() -> Self {
        use rand_core::RngCore;
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Get the associated public key.
    pub fn public(&self) -> Public<S> {
        self.public
    }

    /// Get the VRF `output` point relative to `input` without generating the signature.
    ///
    /// This is a relatively fast step that we may want to perform before generating
    /// the signature.
    pub fn output(&self, input: Input<S>) -> Output<S> {
        Output((input.0 * self.scalar).into_affine())
    }

    /// Sign the input and the user additional data `ad`.
    ///
    /// RFC extension: implementation allows to hash some user additional data
    /// `ad` after the points and before the domain separation end.
    pub fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S> {
        let gamma = self.output(input);
        let k = S::nonce(&self.scalar, input);
        let k_b = (S::Affine::generator() * k).into_affine();
        let k_h = (input.0 * k).into_affine();
        let c = S::challenge(
            &[&self.public.0, &input.0, &gamma.0, &k_b, &k_h],
            ad.as_ref(),
        );
        let s = k + c * self.scalar;
        Signature { gamma, c, s }
    }
}

/// Public key generic over the cipher suite.
#[derive(Debug, Copy, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Public<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Public<S> {
    /// Verify the VRF signature.
    pub fn verify(
        &self,
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        signature: &Signature<S>,
    ) -> Result<(), Error> {
        let Signature { gamma, c, s } = signature;

        let s_b = S::Affine::generator() * s;
        let c_y = self.0 * c;
        let u = (s_b - c_y).into_affine();

        let s_h = input.0 * s;
        let c_o = gamma.0 * c;
        let v = (s_h - c_o).into_affine();

        let c_exp = S::challenge(&[&self.0, &input.0, &gamma.0, &u, &v], ad.as_ref());
        (&c_exp == c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

/// VRF input point generic over the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Input<S: Suite>(pub S::Affine);

impl<S: Suite> Input<S> {
    pub fn from(value: <S as Suite>::Affine) -> Self {
        Input(value)
    }
}

/// VRF output point generic over the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output<S: Suite>(pub S::Affine);

/// VRF signature generic over the cipher suite.
///
/// An output point which can be used to derive the actual output together
/// with the actual signature of the input point and the associated data.
pub struct Signature<S: Suite> {
    gamma: Output<S>,
    c: ScalarField<S>,
    s: ScalarField<S>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;

    const TEST_SEED: &[u8] = b"test seed";

    #[derive(Debug, Copy, Clone, PartialEq)]
    struct TestSuite;
    impl Suite for TestSuite {
        const SUITE_ID: u8 = 0xFF;
        const CHALLENGE_LEN: usize = 16;
        type Affine = ark_ed25519::EdwardsAffine;
        type Hash = [u8; 64];

        fn hash(data: &[u8]) -> Self::Hash {
            utils::sha512(data)
        }
    }
    type Secret = super::Secret<TestSuite>;
    type Public = super::Public<TestSuite>;

    fn rand_point() -> AffinePoint<TestSuite> {
        let mut rng = ark_std::test_rng();
        AffinePoint::<TestSuite>::rand(&mut rng)
    }

    #[test]
    fn codec_works() {
        let secret = Secret::from_seed(TEST_SEED);

        let mut buf = Vec::new();
        secret.serialize_compressed(&mut buf).unwrap();
        let secret2 = Secret::deserialize_compressed(&mut &buf[..]).unwrap();
        assert_eq!(secret, secret2);

        let mut buf = Vec::new();
        let public = secret.public();
        public.serialize_compressed(&mut buf).unwrap();
        let public2 = Public::deserialize_compressed(&mut &buf[..]).unwrap();
        assert_eq!(public, public2);
    }

    #[test]
    fn sign_verify_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input(rand_point());

        let signature = secret.sign(input, b"foo");
        assert_eq!(signature.gamma, secret.output(input));

        let result = public.verify(input, b"foo", &signature);
        assert!(result.is_ok());
    }
}
