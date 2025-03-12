//! # Elliptic Curve VRFs.
//!
//! This library provides flexible and efficient implementations of Verifiable
//! Random Functions with Additional Data (VRF-AD), a cryptographic construct
//! that augments a standard VRF scheme by incorporating auxiliary information
//! into its signature.
//!
//! It leverages the [Arkworks](https://github.com/arkworks-rs) framework and
//! supports customization of scheme parameters.
//!
//! Supported VRFs:
//! - **IETF VRF**: Complies with ECVRF described in [RFC9381](https://datatracker.ietf.org/doc/rfc9381).
//! - **Pedersen VRF**: Described in [BCHSV23](https://eprint.iacr.org/2023/002).
//! - **Ring VRF**: A zero-knowledge-based inspired by [BCHSV23](https://eprint.iacr.org/2023/002).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use zeroize::Zeroize;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use digest::Digest;

pub mod codec;
pub mod ietf;
pub mod pedersen;
pub mod suites;
pub mod utils;

#[cfg(feature = "ring")]
pub mod ring;

#[cfg(test)]
mod testing;

// Re-export stuff that may be useful downstream.
#[doc(hidden)]
pub mod reexports {
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

pub use codec::Codec;

#[derive(Debug)]
pub enum Error {
    /// Verification error
    VerificationFailure,
    /// Bad input data
    InvalidData,
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(_err: ark_serialize::SerializationError) -> Self {
        Error::InvalidData
    }
}

/// Defines a cipher suite.
///
/// This trait can be used to easily implement a VRF which follows the guidelines
/// given by RFC-9381 section 5.5.
///
/// Can be easily customized to implement more exotic VRF types by overwriting
/// the default methods implementations.
pub trait Suite: Copy {
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

    /// Overarching codec.
    ///
    /// Used wherever we need to encode/decode points and scalars.
    type Codec: codec::Codec<Self>;

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
    /// This function panics if `Hasher` output is less than 64 bytes.
    #[inline(always)]
    fn nonce(sk: &ScalarField<Self>, pt: Input<Self>) -> ScalarField<Self> {
        utils::nonce_rfc_8032::<Self>(sk, &pt.0)
    }

    /// Challenge generation as described by RCF-9381 section 5.4.3.
    ///
    /// Hashes several points on the curve.
    ///
    /// This implementation extends the RFC procedure to allow adding
    /// some optional additional data too the hashing procedure.
    #[inline(always)]
    fn challenge(pts: &[&AffinePoint<Self>], ad: &[u8]) -> ScalarField<Self> {
        utils::challenge_rfc_9381::<Self>(pts, ad)
    }

    /// Hash data to a curve point.
    ///
    /// By default uses "try and increment" method described by RFC-9381.
    ///
    /// The input `data` is assumed to be `[salt||]alpha` according to the RFC-9381.
    /// In other words, salt is not applied by this function.
    #[inline(always)]
    fn data_to_point(data: &[u8]) -> Option<AffinePoint<Self>> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }

    /// Map the point to a hash value using `Self::Hasher`.
    ///
    /// By default uses the algorithm described by RFC-9381 without cofactor clearing.
    #[inline(always)]
    fn point_to_hash(pt: &AffinePoint<Self>) -> HashOutput<Self> {
        utils::point_to_hash_rfc_9381::<Self>(pt, false)
    }

    /// Generator used through all the suite.
    ///
    /// Defaults to Arkworks provided generator.
    #[inline(always)]
    fn generator() -> AffinePoint<Self> {
        Self::Affine::generator()
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
        let public = Public((S::generator() * scalar).into_affine());
        Self { scalar, public }
    }

    /// Construct a `Secret` from the given seed.
    ///
    /// The `seed` is hashed using the `Suite::hash` to construct the secret scalar.
    pub fn from_seed(seed: &[u8]) -> Self {
        let bytes = utils::hash::<S::Hasher>(seed);
        let mut scalar = ScalarField::<S>::from_le_bytes_mod_order(&bytes[..]);
        if scalar.is_zero() {
            scalar.set_one();
        }
        Self::from_scalar(scalar)
    }

    /// Construct an ephemeral `Secret` using the provided randomness source.
    pub fn from_rand(rng: &mut impl ark_std::rand::RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
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

impl<S: Suite> Public<S> {
    /// Construct from inner affine point.
    pub fn from(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

/// VRF input point generic over the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Input<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Input<S> {
    /// Construct from [`Suite::data_to_point`].
    pub fn new(data: &[u8]) -> Option<Self> {
        S::data_to_point(data).map(Input)
    }

    /// Construct from inner affine point.
    pub fn from(value: AffinePoint<S>) -> Self {
        Self(value)
    }
}

/// VRF output point generic over the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output<S: Suite>(pub AffinePoint<S>);

impl<S: Suite> Output<S> {
    /// Construct from inner affine point.
    pub fn from(value: AffinePoint<S>) -> Self {
        Self(value)
    }

    /// Hash using `[Suite::point_to_hash]`.
    pub fn hash(&self) -> HashOutput<S> {
        S::point_to_hash(&self.0)
    }
}

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
        pub type IetfProof = $crate::ietf::Proof<$suite>;
        #[allow(dead_code)]
        pub type PedersenProof = $crate::pedersen::Proof<$suite>;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::{Input, Secret};
    use testing::{random_val, TEST_SEED};

    #[test]
    fn vrf_output_check() {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_val(Some(&mut rng)));
        let output = secret.output(input);

        let expected = "71c1b2ee6e46c59e3bd0e2f0e2852b90ab56abb223180b00bd6c8ec6b11af18c";
        assert_eq!(expected, hex::encode(output.hash()));
    }
}
