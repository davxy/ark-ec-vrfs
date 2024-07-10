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

pub trait Prover<S: PedersenSuite> {
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

pub trait Verifier<S: PedersenSuite> {
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: PedersenSuite> Prover<S> for Secret<S> {
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
    ) -> (Proof<S>, ScalarField<S>) {
        // Construct the nonces
        let k = S::nonce(&self.scalar, input);
        let kb = S::nonce(&k, input);
        let b = S::nonce(&kb, input);

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

impl<S: PedersenSuite> Verifier<S> for Public<S> {
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

        // Ok + c*O = s*I
        if output.0 * c + ok != input.0 * s {
            return Err(Error::VerificationFailure);
        }

        // R + c*Yb = s*G + sb*B
        if *pk_blind * c + r != S::Affine::generator() * s + S::BLINDING_BASE * sb {
            return Err(Error::VerificationFailure);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        random_val,
        suite::{AffinePoint, BaseField, Input, Secret, TestSuite},
        TEST_SEED,
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

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::testing as common;

    pub struct TestVector<S: PedersenSuite> {
        pub base: common::TestVector<S>,
        pub blind: ScalarField<S>,
        pub proof: Proof<S>,
    }

    impl<S: PedersenSuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TestVector")
                .field("base", &self.base)
                .field("blinding", &self.blind)
                .field("proof_pkb", &self.proof.pk_blind)
                .field("proof_r", &self.proof.r)
                .field("proof_ok", &self.proof.ok)
                .field("proof_s", &self.proof.s)
                .field("proof_sb", &self.proof.sb)
                .finish()
        }
    }

    impl<S: PedersenSuite + std::fmt::Debug> common::TestVectorTrait for TestVector<S> {
        fn new(
            comment: &str,
            seed: &[u8],
            alpha: &[u8],
            salt: Option<&[u8]>,
            ad: &[u8],
            flags: u8,
        ) -> Self {
            use super::Prover;
            let base = common::TestVector::new(comment, seed, alpha, salt, ad, flags);
            let input = Input::<S>::from(base.h);
            let output = Output::from(base.gamma);
            let sk = Secret::from_scalar(base.sk);
            let (proof, blind) = sk.prove(input, output, ad);
            Self { base, blind, proof }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let base = common::TestVector::from_map(map);
            let blind = codec::scalar_decode::<S>(&map.item_bytes("blinding"));
            let pk_blind = codec::point_decode::<S>(&map.item_bytes("proof_pkb"));
            let r = codec::point_decode::<S>(&map.item_bytes("proof_r"));
            let ok = codec::point_decode::<S>(&map.item_bytes("proof_ok"));
            let s = codec::scalar_decode::<S>(&map.item_bytes("proof_s"));
            let sb = codec::scalar_decode::<S>(&map.item_bytes("proof_sb"));
            let proof = Proof {
                pk_blind,
                r,
                ok,
                s,
                sb,
            };
            Self { base, blind, proof }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let items = [
                (
                    "blinding",
                    hex::encode(codec::scalar_encode::<S>(&self.blind)),
                ),
                (
                    "proof_pkb",
                    hex::encode(codec::point_encode::<S>(&self.proof.pk_blind)),
                ),
                (
                    "proof_r",
                    hex::encode(codec::point_encode::<S>(&self.proof.r)),
                ),
                (
                    "proof_ok",
                    hex::encode(codec::point_encode::<S>(&self.proof.ok)),
                ),
                (
                    "proof_s",
                    hex::encode(codec::scalar_encode::<S>(&self.proof.s)),
                ),
                (
                    "proof_sb",
                    hex::encode(codec::scalar_encode::<S>(&self.proof.sb)),
                ),
            ];
            let mut map = self.base.to_map();
            items.into_iter().for_each(|(name, value)| {
                map.0.insert(name.to_string(), value);
            });
            map
        }

        fn run(&self) {
            self.base.run();
            if self.base.flags & common::TEST_FLAG_SKIP_PROOF_CHECK != 0 {
                return;
            }
            let input = Input::<S>::from(self.base.h);
            let output = Output::from(self.base.gamma);
            let sk = Secret::from_scalar(self.base.sk);
            let (proof, blind) = sk.prove(input, output, &self.base.ad);
            assert_eq!(self.blind, blind, "Blinding factor mismatch");
            assert_eq!(self.proof.pk_blind, proof.pk_blind, "Proof pkb mismatch");
            assert_eq!(self.proof.r, proof.r, "Proof r mismatch");
            assert_eq!(self.proof.ok, proof.ok, "Proof ok mismatch");
            assert_eq!(self.proof.s, proof.s, "Proof s mismatch");
            assert_eq!(self.proof.sb, proof.sb, "Proof sb mismatch");

            assert!(Public::verify(input, output, &self.base.ad, &proof).is_ok());
        }
    }
}
