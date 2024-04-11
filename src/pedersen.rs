use crate::*;

// pub const BLINDING_BASE: Jubjub = {
//     const X: bandersnatch::Fq =
//         MontFp!("4956610287995045830459834427365747411162584416641336688940534788579455781570");
//     const Y: bandersnatch::Fq =
//         MontFp!("52360910621642801549936840538960627498114783432181489929217988668068368626761");
//     Jubjub::new_unchecked(X, Y)
// };

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<S: Suite> {
    gamma: Output<S>,
    pk_blind: AffinePoint<S>,
    r: AffinePoint<S>,
    ok: AffinePoint<S>,
    s: ScalarField<S>,
    sb: ScalarField<S>,
}

pub trait PedersenSigner<S: Suite> {
    /// Sign the input and the user additional data `ad`.
    fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S>;
}

pub trait PedersenVerifier<S: Suite> {
    /// Verify the VRF signature.
    fn verify(input: Input<S>, ad: impl AsRef<[u8]>, sig: &Signature<S>) -> Result<(), Error>;
}

impl<S: Suite> PedersenSigner<S> for Secret<S> {
    fn sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S> {
        let gamma = self.output(input);

        let k = S::nonce(&self.scalar, input);
        // TODO: make b constant
        let b = S::nonce(&self.scalar, input);
        // TODO: use something else
        let kb = S::nonce(&self.scalar, input);

        // TODO make constant generic
        let blinding_base = S::Affine::generator();

        // Yb = k*G + b*B
        let pk_blind = (S::Affine::generator() * self.scalar + blinding_base * b).into_affine();

        // R = k*G + kb*B
        let r = (S::Affine::generator() * kb + blinding_base * kb).into_affine();

        // Ok = k*I
        let ok = (input.0 * k).into_affine();

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[&pk_blind, &input.0, &gamma.0, &r, &ok], ad.as_ref());

        // s = k + c*x
        let s = k + c * self.scalar;

        // sb = kb + c*b
        let sb = kb + c * b;

        Signature {
            gamma,
            pk_blind,
            r,
            ok,
            s,
            sb,
        }
    }
}

impl<S: Suite> PedersenVerifier<S> for Public<S> {
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

        // TODO: make constant
        let blinding_base = S::Affine::generator();

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[&pk_blind, &input.0, &gamma.0, &r, &ok], ad.as_ref());

        // z1 = Ok + c*O - s*I
        if gamma.0 * c + ok != input.0 * s {
            return Err(Error::VerificationFailure);
        }

        // z2 = R + c*Yb - s*G  - sb*B
        if *pk_blind * c + r != S::Affine::generator() * s + blinding_base * sb {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::{random_value, Input, Secret, TEST_SEED};

    #[test]
    fn sign_verify_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_value());

        let signature = secret.sign(input, b"foo");
        assert_eq!(signature.gamma, secret.output(input));

        let result = Public::verify(input, b"foo", &signature);
        assert!(result.is_ok());
    }
}
