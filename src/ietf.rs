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
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<S: Suite> {
    gamma: Output<S>,
    c: ScalarField<S>,
    s: ScalarField<S>,
}

impl<S: Suite> Signature<S> {
    /// Proof to hash as defined by RFC9381 section 5.2
    pub fn hash(&self) -> S::Hash {
        self.gamma.hash()
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
    use crate::utils::testing::{random_val, AffinePoint, Input, Secret, TEST_SEED};

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
}
