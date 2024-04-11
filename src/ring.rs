use std::marker::PhantomData;

use crate::*;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveConfig;
// use fflonk::pcs::PcsParams;
use pedersen::{PedersenSigner, PedersenVerifier, Signature as PedersenSignature};

pub use fflonk::pcs::kzg::urs::URS;
pub use fflonk::pcs::kzg::KZG;

pub type BaseField<S> = <<S as Suite>::Affine as AffineRepr>::BaseField;

pub trait MyPairing<S: Suite>: Pairing<ScalarField = BaseField<S>> {}

type CurveConfigFor<S> = <AffinePoint<S> as AffineRepr>::Config;
type CurveAffine<S> = ark_ec::short_weierstrass::Affine<CurveConfigFor<S>>;

pub type ProverKey<S, P> = ring_proof::ProverKey<BaseField<S>, KZG<P>, CurveAffine<S>>;
pub type VerifierKey<S, P> = ring_proof::VerifierKey<BaseField<S>, KZG<P>>;
pub type RingProver<S, P> =
    ring_proof::ring_prover::RingProver<BaseField<S>, KZG<P>, CurveConfigFor<S>>;
pub type Verifier<S, P> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, KZG<P>, CurveConfigFor<S>>;
pub type RingProof<S, P> = ring_proof::RingProof<BaseField<S>, KZG<P>>;

pub type PiopParams<S> =
    ring_proof::PiopParams<BaseField<S>, <CurveAffine<S> as AffineRepr>::Config>;

pub struct Signature<S: Suite, P: MyPairing<S>>
where
    BaseField<S>: PrimeField,
{
    vrf_signature: PedersenSignature<S>,
    ring_proof: RingProof<S, P>,
}

pub trait RingSigner<S: Suite, P: MyPairing<S>>
where
    CurveConfigFor<S>: SWCurveConfig,
    BaseField<S>: PrimeField,
{
    /// Sign the input and the user additional data `ad`.
    fn ring_sign(
        &self,
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        prover: &RingProver<S, P>,
    ) -> Signature<S, P>;
}

pub trait RingVerifier<S: Suite, P: MyPairing<S>>
where
    CurveConfigFor<S>: SWCurveConfig,
    BaseField<S>: PrimeField,
{
    /// Verify a signature.
    fn ring_verify(
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        sig: &Signature<S, P>,
        verifier: &Verifier<S, P>,
    ) -> Result<(), Error>;
}

impl<S: Suite, P: MyPairing<S>> RingSigner<S, P> for Secret<S>
where
    Self: PedersenSigner<S>,
    CurveConfigFor<S>: SWCurveConfig,
    BaseField<S>: PrimeField,
{
    fn ring_sign(
        &self,
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &RingProver<S, P>,
    ) -> Signature<S, P> {
        let (vrf_signature, secret_blinding) = <Self as PedersenSigner<S>>::sign(self, input, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Signature {
            vrf_signature,
            ring_proof,
        }
    }
}

impl<S: Suite, P: MyPairing<S>> RingVerifier<S, P> for Public<S>
where
    Self: PedersenVerifier<S>,
    CurveConfigFor<S>: SWCurveConfig,
    BaseField<S>: PrimeField,
{
    /// Verify the VRF signature.
    fn ring_verify(
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        sig: &Signature<S, P>,
        verifier: &Verifier<S, P>,
    ) -> Result<(), Error> {
        <Self as PedersenVerifier<S>>::verify(input, ad, &sig.vrf_signature)?;
        let compk = *sig.vrf_signature.key_commitment();
        let mut key_commitment = CurveAffine::<S>::zero();
        key_commitment.x = *compk.x().unwrap();
        key_commitment.y = *compk.y().unwrap();
        key_commitment.infinity = false;

        if !verifier.verify_ring_proof(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

pub struct RingContext<S: Suite, P: MyPairing<S>>
where
    <CurveAffine<S> as AffineRepr>::Config: SWCurveConfig,
    CurveConfigFor<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
{
    pub pcs_params: URS<P>,
    pub piop_params: PiopParams<S>,
    pub domain_size: usize,
    _phantom: PhantomData<S>,
}

impl<S: Suite, P: MyPairing<S>> RingContext<S, P>
where
    <CurveAffine<S> as AffineRepr>::Config: SWCurveConfig,
    CurveConfigFor<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
{
    pub fn prover_key(&self, pks: Vec<CurveAffine<S>>) -> ProverKey<S, P> {
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: Vec<CurveAffine<S>>) -> VerifierKey<S, P> {
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    pub fn prover(&self, prover_key: ProverKey<S, P>, key_index: usize) -> RingProver<S, P> {
        <RingProver<S, P>>::init(
            prover_key,
            self.piop_params.clone(),
            key_index,
            merlin::Transcript::new(b"ring-vrf"),
        )
    }

    pub fn verifier(&self, verifier_key: VerifierKey<S, P>) -> Verifier<S, P> {
        <Verifier<S, P>>::init(
            verifier_key,
            self.piop_params.clone(),
            merlin::Transcript::new(b"ring-vrf"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::{random_value, TEST_SEED};

    use ark_bls12_381::Bls12_381;
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, Fq, SWAffine};
    use ark_std::rand::Rng;
    use ark_std::UniformRand;
    use fflonk::pcs::PCS;
    use ring_proof::{Domain, PiopParams};

    use crate::suites::bandersnatch::{BandersnatchBlake2, Input, Secret};

    type KZG = super::KZG<Bls12_381>;
    impl MyPairing<BandersnatchBlake2> for Bls12_381 {}

    fn setup<R: Rng>(
        rng: &mut R,
        domain_size: usize,
    ) -> (<KZG as PCS<Fq>>::Params, PiopParams<Fq, BandersnatchConfig>) {
        let setup_degree = 3 * domain_size;
        let pcs_params = KZG::setup(setup_degree, rng);

        let domain = Domain::new(domain_size, true);
        let h = SWAffine::rand(rng);
        let seed = ring_proof::find_complement_point::<BandersnatchConfig>();
        let piop_params = PiopParams::setup(domain, h, seed);

        (pcs_params, piop_params)
    }

    #[test]
    fn sign_verify_works() {
        let rng = &mut ark_std::test_rng();
        let domain_size = 1024;
        let (pcs_params, piop_params) = setup(rng, domain_size);

        let secret = Secret::from_seed(TEST_SEED);
        let input = Input::from(random_value());

        let keyset_size = piop_params.keyset_part_size;

        let ring_ctx = RingContext {
            pcs_params,
            piop_params,
            domain_size,
            _phantom: PhantomData,
        };

        let pks = random_vec::<SWAffine, _>(keyset_size, rng);

        let prover_key = ring_ctx.prover_key(pks.clone());
        let prover = ring_ctx.prover(prover_key, 0);
        let signature = secret.ring_sign(input, b"foo", &prover);

        let verifier_key = ring_ctx.verifier_key(pks);
        let verifier = ring_ctx.verifier(verifier_key);
        let result = Public::ring_verify(input, b"foo", &signature, &verifier);
        assert!(result.is_ok());
    }

    pub fn random_vec<X: UniformRand, R: Rng>(n: usize, rng: &mut R) -> Vec<X> {
        (0..n).map(|_| X::rand(rng)).collect()
    }
}
