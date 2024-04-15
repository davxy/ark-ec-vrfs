//! # Elliptic Curve VRFs.
//!
//! Provides:
//! - IETF VRF as described by [RFC 9381](https://datatracker.ietf.org/doc/rfc9381).
//! - Pedersen VRF as described by [Burdges](https://eprint.iacr.org/2023/002).
//! - Ring VRF as described by [Vasilyev](https://eprint.iacr.org/2023/002).
//!
//! Primitives description is further elaborated in the
//! [technical spec](https://github.com/davxy/bandersnatch-vrfs-spec).
//!
//! The implementation is built using Arkworks and is quite flexible to further
//! customization.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use zeroize::Zeroize;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec, vec::Vec};

use digest::Digest;

pub mod ietf;
pub mod pedersen;
pub mod suites;
pub mod utils;

#[cfg(feature = "ring")]
pub mod ring;

pub mod prelude {
    pub use ark_serialize;
    pub use ark_std;
}

pub type ScalarField<S> = <<S as Suite>::Affine as AffineRepr>::ScalarField;
pub type BaseField<S> = <<S as Suite>::Affine as AffineRepr>::BaseField;
pub type AffinePoint<S> = <S as Suite>::Affine;

pub type HashOutput<S> = digest::Output<<S as Suite>::Hasher>;

/// Verification error(s)
pub enum Error {
    VerificationFailure,
}

/// Defines a cipher suite.
///
/// This trait can be used to implement a VRF which follows the guidelines
/// given by RFC-9381 section 5.5 for cipher-suite implementation.
pub trait Suite: Copy + Clone {
    /// Suite identifier (aka `suite_string` in RFC-9381)
    const SUITE_ID: u8;

    /// Challenge length.
    ///
    /// Must be at least equal to the Hash length.
    const CHALLENGE_LEN: usize;

    /// Curve point in affine representation.
    ///
    /// The point is guaranteed to be in the correct prime order subgroup
    /// by the `AffineRepr` bound.
    type Affine: AffineRepr;

    /// Hasher output.
    type Hasher: Digest;

    /// Nonce generation as described by RFC-9381 section 5.4.2.
    ///
    /// The default implementation provides the variant described
    /// by section 5.4.2.2 of RFC-9381 which in turn is a derived
    /// from steps 2 and 3 in section 5.1.6 of
    /// [RFC8032](https://tools.ietf.org/html/rfc8032).
    ///
    /// The algorithm generate the nonce value in a deterministic
    /// pseudorandom fashion.
    ///
    /// `Hash` **MUST** be be at least 64 bytes.
    ///
    /// # Panics
    ///
    /// This function panics if `Hash` is less than 32 bytes.
    fn nonce(sk: &ScalarField<Self>, pt: Input<Self>) -> ScalarField<Self> {
        utils::nonce_rfc_8032::<Self>(sk, &pt.0)
    }

    /// Challenge generation as described by RCF-9381 section 5.4.3.
    ///
    /// Hashes several points on the curve.
    ///
    /// This implementation extends the RFC procedure to allow adding
    /// some optional additional data too the hashing procedure.
    fn challenge(pts: &[&AffinePoint<Self>], ad: &[u8]) -> ScalarField<Self> {
        const DOM_SEP_START: u8 = 0x02;
        const DOM_SEP_END: u8 = 0x00;
        let mut buf = vec![Self::SUITE_ID, DOM_SEP_START];
        pts.iter().for_each(|p| {
            Self::point_encode(p, &mut buf);
        });
        buf.extend_from_slice(ad);
        buf.push(DOM_SEP_END);
        let hash = &utils::hash::<Self::Hasher>(&buf)[..Self::CHALLENGE_LEN];
        ScalarField::<Self>::from_be_bytes_mod_order(hash)
    }

    /// Hash data to a curve point.
    ///
    /// By default uses try and increment method.
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>> {
        utils::hash_to_curve_tai::<Self>(data, false)
    }

    fn point_to_hash(pt: &AffinePoint<Self>) -> HashOutput<Self> {
        const DOM_SEP_START: u8 = 0x03;
        const DOM_SEP_END: u8 = 0x00;
        let mut buf = vec![Self::SUITE_ID, DOM_SEP_START];
        Self::point_encode(pt, &mut buf);
        buf.push(DOM_SEP_END);
        utils::hash::<Self::Hasher>(&buf)
    }

    #[inline(always)]
    fn point_encode(pt: &AffinePoint<Self>, buf: &mut Vec<u8>) {
        pt.serialize_compressed(buf).unwrap();
    }

    #[inline(always)]
    fn scalar_encode(sc: &ScalarField<Self>, buf: &mut Vec<u8>) {
        sc.serialize_compressed(buf).unwrap();
    }

    #[inline(always)]
    fn scalar_decode(buf: &[u8]) -> ScalarField<Self> {
        <ScalarField<Self>>::from_le_bytes_mod_order(buf)
    }
}

/// Secret key.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret<S: Suite> {
    // Secret scalar.
    scalar: ScalarField<S>,
    // Cached public point.
    public: Public<S>,
}

impl<S: Suite> Drop for Secret<S> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<S: Suite> Zeroize for Secret<S> {
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
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

impl<S: Suite> ark_serialize::Valid for Secret<S> {
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
        let bytes = utils::hash::<S::Hasher>(seed);
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
}

/// Public key generic over the cipher suite.
#[derive(Debug, Copy, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Public<S: Suite>(pub AffinePoint<S>);

/// VRF input point generic over the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Input<S: Suite>(pub S::Affine);

impl<S: Suite> Input<S> {
    /// Construct from [`Suite::data_to_point`].
    pub fn new(data: &[u8]) -> Option<Self> {
        S::data_to_point(data).map(Input)
    }

    /// Construct from inner affine point.
    pub fn from(value: <S as Suite>::Affine) -> Self {
        Input(value)
    }
}

/// VRF output point generic over the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output<S: Suite>(pub S::Affine);

impl<S: Suite> Output<S> {
    /// Construct from inner affine point.
    pub fn from(value: <S as Suite>::Affine) -> Self {
        Output(value)
    }

    /// Hash using `[Suite::point_to_hash]`.
    pub fn hash(&self) -> HashOutput<S> {
        S::point_to_hash(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::testing::*;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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
    fn proof_to_hash_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_val(None));
        let output = secret.output(input);

        let expected = "08ffdc9d48f6553c0352b92a233a8101a69ac9f4dcb7f9e2c9c43d46a441c331";
        assert_eq!(expected, hex::encode(output.hash()));
    }
}
