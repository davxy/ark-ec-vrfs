use crate::ietf::IetfSuite;
use crate::*;

pub trait PedersenSuite: IetfSuite {
    const BLINDING_BASE: AffinePoint<Self>;
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: PedersenSuite> {
    pk_blind: AffinePoint<S>,
    r: AffinePoint<S>,
    ok: AffinePoint<S>,
    s: ScalarField<S>,
    sb: ScalarField<S>,
}

impl<S: PedersenSuite> Proof<S> {
    pub fn key_commitment(&self) -> AffinePoint<S> {
        self.pk_blind
    }
}

pub trait PedersenProver<S: PedersenSuite> {
    /// Generate a proof for the given input/output and user additional data.
    ///
    /// Returns the proof together with the associated blinding factor.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>);
}

pub trait PedersenVerifier<S: PedersenSuite> {
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: PedersenSuite> PedersenProver<S> for Secret<S> {
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>) {
        // Construct the nonces
        let k = S::nonce(&self.scalar, input);
        let b = S::nonce(&k, input);
        let kb = S::nonce(&b, input);

        // Yb = x*G + b*B
        let pk_blind = (S::Affine::generator() * self.scalar + S::BLINDING_BASE * b).into_affine();
        // R = k*G + kb*B
        let r = (S::Affine::generator() * k + S::BLINDING_BASE * kb).into_affine();
        // Ok = k*I
        let ok = (input.0 * k).into_affine();

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[&pk_blind, &input.0, &output.0, &r, &ok], ad.as_ref());

        // s = k + c*x
        let s = k + c * self.scalar;
        // sb = kb + c*b
        let sb = kb + c * b;

        let proof = Proof {
            pk_blind,
            r,
            ok,
            s,
            sb,
        };

        (proof, b)
    }
}

impl<S: PedersenSuite> PedersenVerifier<S> for Public<S> {
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof {
            pk_blind,
            r,
            ok,
            s,
            sb,
        } = proof;

        // c = Hash(Yb, I, O, R, Ok, ad)
        let c = S::challenge(&[pk_blind, &input.0, &output.0, r, ok], ad.as_ref());

        // z1 = Ok + c*O - s*I
        if output.0 * c + ok != input.0 * s {
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
    use crate::utils::testing::{
        random_val, AffinePoint, BaseField, Input, Secret, TestSuite, TEST_SEED,
    };
    use ark_ff::MontFp;

    impl PedersenSuite for TestSuite {
        const BLINDING_BASE: AffinePoint = {
            const X: BaseField = MontFp!(
                "1181072390894490040170698195029164902368238760122173135634802939739986120753"
            );
            const Y: BaseField = MontFp!(
                "16819438535150625131748701663066892288775529055803151482550035706857354997714"
            );
            AffinePoint::new_unchecked(X, Y)
        };
    }

    #[test]
    fn prove_verify_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_val(None));
        let output = secret.output(input);

        let (proof, blinding) = secret.prove(input, output, b"foo");

        let result = Public::verify(input, output, b"foo", &proof);
        assert!(result.is_ok());

        assert_eq!(
            proof.pk_blind,
            secret.public().0 + TestSuite::BLINDING_BASE * blinding
        );
    }
}
