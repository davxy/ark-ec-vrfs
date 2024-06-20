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
use ark_std::vec::Vec;

use digest::Digest;

pub mod ietf;
pub mod pedersen;
pub mod suites;
pub mod utils;

#[cfg(feature = "ring")]
pub mod ring;

mod arkworks;

#[cfg(test)]
mod testing;

pub mod prelude {
    pub use ark_ec;
    pub use ark_ff;
    pub use ark_serialize;
    pub use ark_std;
}

pub type AffinePoint<S> = <S as Suite>::Affine;

pub type BaseField<S> = <AffinePoint<S> as AffineRepr>::BaseField;
pub type ScalarField<S> = <AffinePoint<S> as AffineRepr>::ScalarField;
pub type CurveConfig<S> = <AffinePoint<S> as AffineRepr>::Config;

pub type HashOutput<S> = digest::Output<<S as Suite>::Hasher>;

/// Verification error(s)
#[derive(Debug)]
pub enum Error {
    VerificationFailure,
}

/// Defines a cipher suite.
///
/// This trait can be used to easily implement a VRF which follows the guidelines
/// given by RFC-9381 section 5.5.
///
/// Can be easily customized to implement more exotic VRF types by overwriting
/// the default methods implementations.
pub trait Suite: Copy + Clone {
    /// Suite identifier (aka `suite_string` in RFC-9381)
    const SUITE_ID: &'static [u8];

    /// Challenge encoded length.
    ///
    /// Must be at least equal to the Hash length.
    const CHALLENGE_LEN: usize;

    /// Curve point in affine representation.
    ///
    /// The point is guaranteed to be in the correct prime order subgroup
    /// by the `AffineRepr` bound.
    type Affine: AffineRepr;

    /// Overarching hasher.
    ///
    /// Used wherever an hash is required: nonce, challenge, MAC, etc.
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
    /// `Hasher` output **MUST** be be at least 64 bytes.
    ///
    /// # Panics
    ///
    /// This function panics if `Hasher` output is less than 32 bytes.
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
        utils::challenge_rfc_9381::<Self>(pts, ad)
    }

    /// Hash data to a curve point.
    ///
    /// By default uses "try and increment" method described by RFC 9381.
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data, false)
    }

    /// Map the point to a hash value using `Self::Hasher`.
    ///
    /// By default uses the algorithm described by RFC 9381.
    fn point_to_hash(pt: &AffinePoint<Self>) -> HashOutput<Self> {
        utils::point_to_hash_rfc_9381::<Self>(pt)
    }

    fn point_encode(pt: &AffinePoint<Self>, buf: &mut Vec<u8>) {
        pt.serialize_compressed(buf).unwrap();
    }

    fn point_decode(buf: &[u8]) -> AffinePoint<Self> {
        AffinePoint::<Self>::deserialize_compressed(buf).unwrap()
    }

    fn scalar_encode(sc: &ScalarField<Self>, buf: &mut Vec<u8>) {
        sc.serialize_compressed(buf).unwrap();
    }

    fn scalar_decode(buf: &[u8]) -> ScalarField<Self> {
        <ScalarField<Self>>::from_le_bytes_mod_order(buf)
    }
}

/// Secret key.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret<S: Suite> {
    // Secret scalar.
    pub scalar: ScalarField<S>,
    // Cached public point.
    pub public: Public<S>,
}

impl<S: Suite> Drop for Secret<S> {
    fn drop(&mut self) {
        self.scalar.zeroize()
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

    /// Get the VRF output point relative to input.
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
    use crate::testing::{
        random_val,
        suite::{Input, Public, Secret},
        TEST_SEED,
    };
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

        let expected = "2eaa1a349197bb2b6c455bc5554b331162f0e9b13aea0aab28283cc30e7c6482";
        assert_eq!(expected, hex::encode(output.hash()));
    }
}
