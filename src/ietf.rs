//! EC-VRF as specified by [RFC-9381](https://datatracker.ietf.org/doc/rfc9381).
//!
//! The implementation extends RFC9381 to allow to sign additional user data together
//! with the VRF input. Refer to https://github.com/davxy/bandersnatch-vrfs-spec for
//! specification extension details.

use super::*;

pub trait IetfSuite: Suite {}

impl<T> IetfSuite for T where T: Suite {}

/// VRF signature generic over the cipher suite.
///
/// An output point which can be used to derive the actual output together
/// with the actual signature of the input point and the associated data.
// TODO: manually implement serialization to respect S::CHALLENGE_LEN value.
#[derive(Debug, Clone)]
pub struct Signature<S: IetfSuite> {
    pub gamma: Output<S>,
    pub c: ScalarField<S>,
    pub s: ScalarField<S>,
}

impl<S: IetfSuite + Sync> CanonicalSerialize for Signature<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.gamma.serialize_with_mode(&mut writer, compress)?;
        let buf = utils::encode_scalar::<S>(&self.c);
        if buf.len() < S::CHALLENGE_LEN {
            // Encoded scalar length must be at least S::CHALLENGE_LEN
            return Err(ark_serialize::SerializationError::NotEnoughSpace);
        }
        writer.write_all(&buf[..S::CHALLENGE_LEN])?;
        self.s.serialize_compressed(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.gamma.serialized_size(compress) + S::CHALLENGE_LEN + self.s.compressed_size()
    }
}

impl<S: IetfSuite + Sync> CanonicalDeserialize for Signature<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let gamma = <AffinePoint<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let c = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            ark_serialize::Compress::No,
            ark_serialize::Validate::Yes,
        )?;
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            ark_serialize::Compress::No,
            ark_serialize::Validate::Yes,
        )?;
        Ok(Signature {
            gamma: Output(gamma),
            c,
            s,
        })
    }
}

impl<S: IetfSuite + Sync> ark_serialize::Valid for Signature<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.gamma.check()?;
        self.c.check()?;
        self.s.check()?;
        Ok(())
    }
}

impl<S: Suite> Signature<S> {
    /// Proof to hash as defined by RFC9381 section 5.2
    pub fn hash(&self) -> HashOutput<S> {
        self.gamma.hash()
    }

    pub fn output(&self) -> Output<S> {
        self.gamma
    }
}

pub trait IetfSigner<S: Suite> {
    /// Sign the input and the user additional data `ad`.
    fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S>;
}

pub trait IetfVerifier<S: Suite> {
    /// Verify the VRF signature.
    fn verify(
        &self,
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        sig: &Signature<S>,
    ) -> Result<(), Error>;
}

impl<S: Suite> IetfSigner<S> for Secret<S> {
    fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S> {
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

impl<S: Suite> IetfVerifier<S> for Public<S> {
    fn verify(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::{
        random_val, AffinePoint, Input, ScalarField, Secret, TestSuite, TEST_SEED,
    };

    #[test]
    fn sign_verify_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(random_val::<AffinePoint>(None));

        let signature = secret.sign(input, b"foo");
        assert_eq!(signature.gamma, secret.output(input));

        let result = public.verify(input, b"foo", &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn signature_encode_decode() {
        let gamma = utils::hash_to_curve_tai::<TestSuite>(b"foobar", false).unwrap();
        let c = hex::decode("d091c00b0f5c3619d10ecea44363b5a5").unwrap();
        let c = ScalarField::from_be_bytes_mod_order(&c[..]);
        let s = hex::decode("99cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1")
            .unwrap();
        let s = ScalarField::from_be_bytes_mod_order(&s[..]);

        let signature = Signature::<TestSuite> {
            gamma: Output(gamma),
            c,
            s,
        };

        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        assert_eq!(buf.len(), TestSuite::CHALLENGE_LEN + 64);
    }
}
