use crate::*;
use pedersen::{PedersenSigner, PedersenVerifier, Signature as PedersenSignature};

use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ring_proof::ring_prover;

use ark_ed_on_bls12_381_bandersnatch::SWConfig;

type KZG = fflonk::pcs::kzg::KZG<Bls12_381>;

// TODO keep it generic

pub type RingProver = ring_prover::RingProver<Fr, KZG, SWConfig>;

pub struct Signature<S: Suite> {
    vrf_signature: PedersenSignature<S>,
}

pub trait RingSigner<S: Suite> {
    /// Sign the input and the user additional data `ad`.
    fn ring_sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S>;
}

pub trait RingVerifier<S: Suite> {
    /// Verify the VRF signature.
    fn ring_verify(input: Input<S>, ad: impl AsRef<[u8]>, sig: &Signature<S>) -> Result<(), Error>;
}

impl<S: Suite> RingSigner<S> for Secret<S>
where
    Self: PedersenSigner<S>,
{
    fn ring_sign(&self, input: Input<S>, ad: impl AsRef<[u8]>) -> Signature<S> {
        let vrf_signature = <Self as PedersenSigner<S>>::sign(self, input, ad);
        Signature { vrf_signature }
    }
}

impl<S: Suite> RingVerifier<S> for Public<S>
where
    Self: PedersenVerifier<S>,
{
    /// Verify the VRF signature.
    fn ring_verify(input: Input<S>, ad: impl AsRef<[u8]>, sig: &Signature<S>) -> Result<(), Error> {
        <Self as PedersenVerifier<S>>::verify(input, ad, &sig.vrf_signature)
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

        let signature = secret.ring_sign(input, b"foo");

        let result = Public::ring_verify(input, b"foo", &signature);
        assert!(result.is_ok());
    }
}
