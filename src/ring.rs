use std::marker::PhantomData;

use crate::*;
use ark_ec::short_weierstrass::SWCurveConfig;
use pedersen::{PedersenSigner, PedersenSuite, PedersenVerifier, Signature as PedersenSignature};

pub use fflonk::pcs::kzg::urs::URS;
pub use fflonk::pcs::kzg::KZG;

pub type ProverKey<S, P> = ring_proof::ProverKey<BaseField<S>, KZG<P>, SWAffine<S>>;

pub type VerifierKey<S, P> = ring_proof::VerifierKey<BaseField<S>, KZG<P>>;

pub type Prover<S, P> = ring_proof::ring_prover::RingProver<BaseField<S>, KZG<P>, CurveConfig<S>>;

pub type Verifier<S, P> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, KZG<P>, CurveConfig<S>>;

pub type RingProof<S, P> = ring_proof::RingProof<BaseField<S>, KZG<P>>;

pub type PiopParams<S> = ring_proof::PiopParams<BaseField<S>, <SWAffine<S> as AffineRepr>::Config>;

/// Ring proof library works:
/// 1. Over the whole curve group (not just the prime subgroup).
/// 2. With points in short weierstrass form.
pub type SWAffine<S> = ark_ec::short_weierstrass::Affine<CurveConfig<S>>;

pub trait Pairing<S: Suite>: ark_ec::pairing::Pairing<ScalarField = BaseField<S>> {}

pub struct Signature<S: PedersenSuite, P: Pairing<S>>
where
    BaseField<S>: PrimeField,
{
    vrf_signature: PedersenSignature<S>,
    ring_proof: RingProof<S, P>,
}

pub trait RingSigner<S: PedersenSuite, P: Pairing<S>>
where
    CurveConfig<S>: SWCurveConfig,
    BaseField<S>: PrimeField,
{
    /// Sign the input and the user additional data `ad`.
    fn ring_sign(
        &self,
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        prover: &Prover<S, P>,
    ) -> Signature<S, P>;
}

pub trait RingVerifier<S: PedersenSuite, P: Pairing<S>>
where
    CurveConfig<S>: SWCurveConfig,
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

impl<S: PedersenSuite, P: Pairing<S>> RingSigner<S, P> for Secret<S>
where
    Self: PedersenSigner<S>,
    CurveConfig<S>: SWCurveConfig,
    BaseField<S>: PrimeField,
{
    fn ring_sign(
        &self,
        input: Input<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &Prover<S, P>,
    ) -> Signature<S, P> {
        let (vrf_signature, secret_blinding) = <Self as PedersenSigner<S>>::sign(self, input, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Signature {
            vrf_signature,
            ring_proof,
        }
    }
}

impl<S: PedersenSuite, P: Pairing<S>> RingVerifier<S, P> for Public<S>
where
    Self: PedersenVerifier<S>,
    CurveConfig<S>: SWCurveConfig,
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
        let key_commitment = sig.vrf_signature.key_commitment();
        let (x, y) = key_commitment
            .xy()
            .map(|(x, y)| (*x, *y))
            .ok_or(Error::VerificationFailure)?;
        let key_commitment = SWAffine::<S>::new_unchecked(x, y);

        if !verifier.verify_ring_proof(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RingContext<S: PedersenSuite, P: Pairing<S>>
where
    CurveConfig<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
{
    pub pcs_params: URS<P>,
    pub piop_params: PiopParams<S>,
    pub domain_size: u32,
    _phantom: PhantomData<S>,
}

impl<S: PedersenSuite, P: Pairing<S>> RingContext<S, P>
where
    CurveConfig<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
{
    #[cfg(feature = "getrandom")]
    pub fn rand(domain_size: u32) -> Self {
        use fflonk::pcs::PCS;
        use ring_proof::Domain;
        let mut rng = ark_std::rand::thread_rng();
        let setup_degree = 3 * domain_size;
        let pcs_params = KZG::setup(setup_degree as usize, &mut rng);

        let domain = Domain::new(domain_size as usize, true);
        let h = S::BLINDING_BASE;
        let (x, y) = h.xy().unwrap();
        let h = SWAffine::<S>::new_unchecked(*x, *y);
        let seed = ring_proof::find_complement_point::<CurveConfig<S>>();
        println!(">>>>>>>> {}", seed);
        let piop_params = PiopParams::<S>::setup(domain, h, seed);

        Self {
            pcs_params,
            piop_params,
            domain_size,
            _phantom: PhantomData,
        }
    }

    pub fn max_keyset_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    pub fn prover_key(&self, pks: Vec<SWAffine<S>>) -> ProverKey<S, P> {
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: Vec<SWAffine<S>>) -> VerifierKey<S, P> {
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    pub fn prover(&self, prover_key: ProverKey<S, P>, key_index: usize) -> Prover<S, P> {
        <Prover<S, P>>::init(
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

use ark_serialize::{Compress, Read, SerializationError, Valid, Validate, Write};

impl<S: PedersenSuite + Sync, P: Pairing<S>> CanonicalSerialize for RingContext<S, P>
where
    <SWAffine<S> as AffineRepr>::Config: SWCurveConfig,
    CurveConfig<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
{
    // Required methods
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.domain_size.serialize_compressed(&mut writer)?;
        self.pcs_params.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.domain_size.compressed_size() + self.pcs_params.serialized_size(compress)
    }
}

impl<S: PedersenSuite + Sync, P: Pairing<S>> CanonicalDeserialize for RingContext<S, P>
where
    <SWAffine<S> as AffineRepr>::Config: SWCurveConfig,
    CurveConfig<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        _compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let _domain_size = <u32 as CanonicalDeserialize>::deserialize_compressed(&mut reader)?;
        // let piop_params = make_piop_params::<S>(domain_size as usize);
        // let pcs_params = <PcsParams as CanonicalDeserialize>::deserialize_with_mode(
        //     &mut reader,
        //     compress,
        //     validate,
        // )?;
        // Ok(KZG {
        //     domain_size,
        //     piop_params,
        //     pcs_params,
        // })
        todo!()
    }
}

// pub fn make_piop_params<S: PedersenSuite>(domain_size: usize) -> PiopParams<S>
// where
//     CurveConfig<S>: SWCurveConfig<BaseField = BaseField<S>>,
//     BaseField<S>: PrimeField,
// {
//     use ring_proof::Domain;
//     let domain = Domain::new(domain_size, true);
//     PiopParams::<S>::setup(domain, S::BLINDING_BASE, S::BLINDING_BASE)
// }

impl<S: PedersenSuite, P: Pairing<S>> Valid for RingContext<S, P>
where
    <SWAffine<S> as AffineRepr>::Config: SWCurveConfig,
    CurveConfig<S>: SWCurveConfig<BaseField = BaseField<S>>,
    BaseField<S>: PrimeField,
    PiopParams<S>: Clone,
    S: Sync,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.pcs_params.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suites::bandersnatch::{ring::RingContext, Input, Secret};
    use crate::utils::testing::{random_value, TEST_SEED};

    use ark_ed_on_bls12_381_bandersnatch::SWAffine;
    use ark_std::rand::Rng;
    use ark_std::UniformRand;

    fn random_vec<X: UniformRand, R: Rng>(n: usize, rng: &mut R) -> Vec<X> {
        (0..n).map(|_| X::rand(rng)).collect()
    }

    #[test]
    fn sign_verify_works() {
        let rng = &mut ark_std::test_rng();
        let domain_size = 1024;
        let ring_ctx = RingContext::rand(domain_size);

        let secret = Secret::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(random_value());

        let keyset_size = ring_ctx.piop_params.keyset_part_size;

        let prover_idx = 3;
        let mut pks = random_vec::<SWAffine, _>(keyset_size, rng);
        pks[prover_idx] = public.0;

        let prover_key = ring_ctx.prover_key(pks.clone());
        let prover = ring_ctx.prover(prover_key, prover_idx);
        let signature = secret.ring_sign(input, b"foo", &prover);

        let verifier_key = ring_ctx.verifier_key(pks);
        let verifier = ring_ctx.verifier(verifier_key);
        let result = Public::ring_verify(input, b"foo", &signature, &verifier);
        assert!(result.is_ok());
    }
}
