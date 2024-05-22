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
#[derive(Debug, Clone)]
pub struct Signature<S: IetfSuite> {
    pub c: ScalarField<S>,
    pub s: ScalarField<S>,
}

impl<S: IetfSuite + Sync> CanonicalSerialize for Signature<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        _compress_always: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let buf = utils::encode_scalar::<S>(&self.c);
        if buf.len() < S::CHALLENGE_LEN {
            // Encoded scalar length must be at least S::CHALLENGE_LEN
            return Err(ark_serialize::SerializationError::NotEnoughSpace);
        }
        writer.write_all(&buf[..S::CHALLENGE_LEN])?;
        self.s.serialize_compressed(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self, _compress_always: ark_serialize::Compress) -> usize {
        S::CHALLENGE_LEN + self.s.compressed_size()
    }
}

impl<S: IetfSuite + Sync> CanonicalDeserialize for Signature<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        _compress_always: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let c = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            ark_serialize::Compress::No,
            validate,
        )?;
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            ark_serialize::Compress::No,
            validate,
        )?;
        Ok(Signature { c, s })
    }
}

impl<S: IetfSuite + Sync> ark_serialize::Valid for Signature<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.c.check()?;
        self.s.check()?;
        Ok(())
    }
}

pub trait IetfSigner<S: Suite> {
    /// Sign the input and the user additional data `ad`.
    fn sign(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Signature<S>;
}

pub trait IetfVerifier<S: Suite> {
    /// Verify the VRF signature.
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Signature<S>,
    ) -> Result<(), Error>;
}

impl<S: IetfSuite> IetfSigner<S> for Secret<S> {
    fn sign(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Signature<S> {
        let k = S::nonce(&self.scalar, input);
        let k_b = (S::Affine::generator() * k).into_affine();

        let k_h = (input.0 * k).into_affine();

        let c = S::challenge(
            &[&self.public.0, &input.0, &output.0, &k_b, &k_h],
            ad.as_ref(),
        );
        let s = k + c * self.scalar;
        Signature { c, s }
    }
}

impl<S: Suite> IetfVerifier<S> for Public<S> {
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        signature: &Signature<S>,
    ) -> Result<(), Error> {
        let Signature { c, s } = signature;

        let s_b = S::Affine::generator() * s;
        let c_y = self.0 * c;
        let u = (s_b - c_y).into_affine();

        let s_h = input.0 * s;
        let c_o = output.0 * c;
        let v = (s_h - c_o).into_affine();

        let c_exp = S::challenge(&[&self.0, &input.0, &output.0, &u, &v], ad.as_ref());
        (&c_exp == c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

#[cfg(test)]
pub mod testing {
    use crate::*;
    use ietf::IetfSigner;

    pub const TEST_FLAG_SKIP_SIGN_CHECK: u8 = 1 << 0;

    pub struct TestVector {
        pub flags: u8,
        pub sk: &'static str,
        pub pk: &'static str,
        pub alpha: &'static [u8],
        pub beta: &'static str,
        pub h: &'static str,
        pub gamma: &'static str,
        pub c: &'static str,
        pub s: &'static str,
    }

    pub fn run_test_vector<S: Suite>(v: &TestVector) {
        let sk_bytes = hex::decode(v.sk).unwrap();
        let s = S::scalar_decode(&sk_bytes);
        let sk = Secret::<S>::from_scalar(s);

        let pk_bytes = utils::encode_point::<S>(&sk.public.0);
        assert_eq!(v.pk, hex::encode(&pk_bytes));

        // Prepare hash_to_curve data = salt || alpha
        // Salt is defined to be pk (adjust it to make the encoding to match)
        let h2c_data = [&pk_bytes[..], v.alpha].concat();
        let h = S::data_to_point(&h2c_data).unwrap();
        let h_bytes = utils::encode_point::<S>(&h);
        assert_eq!(v.h, hex::encode(h_bytes));

        let input = Input::from(h);
        let output = sk.output(input);
        let signature = sk.sign(input, output, []);

        let gamma_bytes = utils::encode_point::<S>(&output.0);
        assert_eq!(v.gamma, hex::encode(gamma_bytes));

        if v.flags & TEST_FLAG_SKIP_SIGN_CHECK != 0 {
            return;
        }

        let c_bytes = utils::encode_scalar::<S>(&signature.c);
        assert_eq!(v.c, hex::encode(c_bytes));

        let s_bytes = utils::encode_scalar::<S>(&signature.s);
        assert_eq!(v.s, hex::encode(s_bytes));

        let beta = output.hash();
        assert_eq!(v.beta, hex::encode(beta));
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
        let output = secret.output(input);

        let signature = secret.sign(input, output, b"foo");

        let result = public.verify(input, output, b"foo", &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn signature_encode_decode() {
        let c = hex::decode("d091c00b0f5c3619d10ecea44363b5a5").unwrap();
        let c = ScalarField::from_be_bytes_mod_order(&c[..]);
        let s = hex::decode("99cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1")
            .unwrap();
        let s = ScalarField::from_be_bytes_mod_order(&s[..]);

        let signature = Signature::<TestSuite> { c, s };

        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        assert_eq!(buf.len(), TestSuite::CHALLENGE_LEN + 32);
    }
}
