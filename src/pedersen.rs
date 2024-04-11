use crate::*;

pub trait PedersenSuite: Suite {
    const BLINDING_BASE: AffinePoint<Self>;
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<S: PedersenSuite> {
    gamma: Output<S>,
    pk_blind: AffinePoint<S>,
    r: AffinePoint<S>,
    ok: AffinePoint<S>,
    s: ScalarField<S>,
    sb: ScalarField<S>,
}

impl<S: PedersenSuite> Signature<S> {
    pub fn key_commitment(&self) -> AffinePoint<S> {
        self.pk_blind
    }

    pub fn output(&self) -> Output<S> {
        self.gamma
    }
}

pub trait PedersenSigner<S: PedersenSuite> {
    /// Sign the input and the user additional data `ad`.
    fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> (Signature<S>, ScalarField<S>);
}

pub trait PedersenVerifier<S: PedersenSuite> {
    /// Verify the VRF signature.
    fn verify(input: Input<S>, ad: impl AsRef<[u8]>, sig: &Signature<S>) -> Result<(), Error>;
}

impl<S: PedersenSuite> PedersenSigner<S> for Secret<S> {
    fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> (Signature<S>, ScalarField<S>) {
        let gamma = self.output(input);

        let k = S::nonce(&self.scalar, input);
        // Secret blinding factor
        // TODO: use something else
        let b = S::nonce(&self.scalar, input);
        // TODO: use something else
        let kb = S::nonce(&self.scalar, input);

        // Yb = k*G + b*B
        let pk_blind = (S::Affine::generator() * self.scalar + S::BLINDING_BASE * b).into_affine();

        // R = k*G + kb*B
        let r = (S::Affine::generator() * kb + S::BLINDING_BASE * kb).into_affine();

        // Ok = k*I
        let ok = (input.0 * k).into_affine();

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[&pk_blind, &input.0, &gamma.0, &r, &ok], ad.as_ref());

        // s = k + c*x
        let s = k + c * self.scalar;

        // sb = kb + c*b
        let sb = kb + c * b;

        let signature = Signature {
            gamma,
            pk_blind,
            r,
            ok,
            s,
            sb,
        };

        (signature, b)
    }
}

impl<S: PedersenSuite> PedersenVerifier<S> for Public<S> {
    fn verify(
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        signature: &Signature<S>,
    ) -> Result<(), Error> {
        let Signature {
            gamma,
            pk_blind,
            r,
            ok,
            s,
            sb,
        } = signature;

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[&pk_blind, &input.0, &gamma.0, &r, &ok], ad.as_ref());

        // z1 = Ok + c*O - s*I
        if gamma.0 * c + ok != input.0 * s {
            return Err(Error::VerificationFailure);
        }

        // z2 = R + c*Yb - s*G  - sb*B
        if *pk_blind * c + r != S::Affine::generator() * s + S::BLINDING_BASE * sb {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::{random_value, Input, Secret, TestSuite, TEST_SEED};

    #[test]
    fn sign_verify_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_value());

        let (signature, blinding) = secret.sign(input, b"foo");
        assert_eq!(signature.gamma, secret.output(input));

        let result = Public::verify(input, b"foo", &signature);
        assert!(result.is_ok());

        assert_eq!(
            signature.pk_blind,
            secret.public().0 + TestSuite::BLINDING_BASE * blinding
        );
    }
}
