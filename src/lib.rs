//! EC-VRF as specified by [RFC-9381](https://datatracker.ietf.org/doc/rfc9381).
//!
//! The implementation is built using Arkworks and is generic over the curve.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{vec, vec::Vec};

/// Secret key
// TODO: zeroize
#[derive(Debug, PartialEq)]
pub struct Secret<P: AffineRepr> {
    // Secret scalar.
    scalar: P::ScalarField,
    // Cached public point.
    public: Public<P>,
}

impl<P: AffineRepr> CanonicalSerialize for Secret<P> {
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

impl<P: AffineRepr> CanonicalDeserialize for Secret<P> {
    fn deserialize_with_mode<R: ark_std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let scalar = <P::ScalarField as CanonicalDeserialize>::deserialize_with_mode(
            reader, compress, validate,
        )?;
        Ok(Self::from_scalar(scalar))
    }
}

impl<P: AffineRepr> Valid for Secret<P> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.scalar.check()
    }
}

/// Public key
#[derive(Debug, Copy, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Public<P: AffineRepr>(pub P);

impl<P: AffineRepr> Public<P> {
    pub fn verify(
        &self,
        input: Input<P>,
        ad: impl AsRef<[u8]>,
        signature: &Signature<P>,
    ) -> Result<(), ()> {
        let Signature {
            output,
            proof: (c, s),
        } = signature;

        let s_b = P::generator() * s;
        let c_y = self.0 * c;
        let u = (s_b - c_y).into_affine();

        let s_h = input.0 * s;
        let c_o = signature.output.0 * c;
        let v = (s_h - c_o).into_affine();

        let c_exp = challenge_gen(&[&self.0, &input.0, &output.0, &u, &v], ad.as_ref());

        (&c_exp == c).then(|| ()).ok_or(())
    }
}

impl<P: AffineRepr> Secret<P> {
    pub fn from_scalar(scalar: <P as AffineRepr>::ScalarField) -> Self {
        let g = P::generator();
        let public = g * scalar;
        let public = Public(public.into_affine());
        Self { scalar, public }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let bytes = sha512(&seed);
        let scalar = <P::ScalarField as PrimeField>::from_le_bytes_mod_order(&bytes);
        Self::from_scalar(scalar)
    }

    /// Generate an ephemeral `Secret` with system randomness
    #[cfg(features = "getrandom")]
    pub fn ephemeral() -> Self {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    pub fn public(&self) -> Public<P> {
        self.public
    }

    pub fn vrf_output(&self, input: Input<P>) -> Output<P> {
        Output((input.0 * self.scalar).into_affine())
    }

    pub fn sign(&self, input: Input<P>, ad: impl AsRef<[u8]>) -> Signature<P> {
        let output = self.vrf_output(input);
        let k = nonce_gen(self, input);
        let k_b = (<P as AffineRepr>::generator() * k).into_affine();
        let k_h = (input.0 * k).into_affine();
        let c = challenge_gen(
            &[&self.public.0, &input.0, &output.0, &k_b, &k_h],
            ad.as_ref(),
        );
        let s = k + c * self.scalar;
        Signature {
            output,
            proof: (c, s),
        }
    }
}

/// ECVRF nonce generation according to Section 5.1.6 of [RFC8032](https://tools.ietf.org/html/rfc8032).
pub fn nonce_gen<P: AffineRepr>(sk: &Secret<P>, pt: Input<P>) -> <P as AffineRepr>::ScalarField {
    let mut sk_enc = Vec::new();
    sk.scalar.serialize_compressed(&mut sk_enc).unwrap();
    let key_hash: [u8; 32] = sha512(&sk_enc)[32..].try_into().unwrap();
    let mut pt_enc = Vec::new();
    pt.0.serialize_compressed(&mut pt_enc).unwrap();
    let v = [&key_hash[..], &pt_enc[..]].concat();
    let h = sha512(&v);
    <P as AffineRepr>::ScalarField::from_be_bytes_mod_order(&h)
}

// see RFC9381 Section 7.10
const SUITE_ID: u8 = 0x04;
// In typical case us qLen / 2
const CLEN: usize = 16;
const DOM_SEP_START: u8 = 0x02;
const DOM_SEP_END: u8 = 0x00;

fn encode_point<P: AffineRepr>(p: &P) -> Vec<u8> {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    buf
}

/// `ECVRF_challenge_generation` -- Hashes several points on the curve
pub fn challenge_gen<P: AffineRepr>(points: &[&P], ad: &[u8]) -> <P as AffineRepr>::ScalarField {
    let mut v = vec![SUITE_ID, DOM_SEP_START];
    points
        .into_iter()
        .for_each(|p| v.extend_from_slice(encode_point(*p).as_slice()));
    v.extend_from_slice(ad);
    v.push(DOM_SEP_END);
    let h = &sha512(&v)[..CLEN];
    <P as AffineRepr>::ScalarField::from_be_bytes_mod_order(h)
}

// TODO macro for point newtypes

/// VRF input point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Input<P: AffineRepr>(P);

impl<P: AffineRepr> From<P> for Input<P> {
    fn from(value: P) -> Self {
        Input(value)
    }
}

/// VRF output point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Output<P: AffineRepr>(P);

impl<P: AffineRepr> From<P> for Output<P> {
    fn from(value: P) -> Self {
        Output(value)
    }
}

/// VRF signature.
///
/// An output point which can be used to derive the actual output together
/// with the actual signature of the input point and the associated data.
pub struct Signature<P: AffineRepr> {
    #[allow(dead_code)]
    output: Output<P>,
    #[allow(dead_code)]
    proof: (
        // Well. This can be optimized as it is 16 bytes
        <P as AffineRepr>::ScalarField,
        <P as AffineRepr>::ScalarField,
    ),
}

fn sha512(input: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut h = [0u8; 64];
    h.copy_from_slice(&result);
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed25519 as curve;

    const TEST_SEED: [u8; 32] = [0u8; 32];

    type P = curve::EdwardsAffine;
    type Secret = super::Secret<P>;
    type Public = super::Public<P>;

    fn make_dummy_point(s: u32) -> P {
        let s = <P as AffineRepr>::ScalarField::from_be_bytes_mod_order(&s.to_be_bytes()[..]);
        (P::generator() * s).into_affine()
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
        let input = make_dummy_point(123).into();

        let signature = secret.sign(input, b"foo");
        assert_eq!(signature.output, secret.vrf_output(input));

        let result = public.verify(input, b"foo", &signature);
        assert!(result.is_ok());
    }
}
