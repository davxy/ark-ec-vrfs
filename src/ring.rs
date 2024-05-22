use crate::*;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_serialize::{Compress, Read, SerializationError, Valid, Validate, Write};
use pedersen::{PedersenSigner, PedersenSuite, PedersenVerifier, Signature as PedersenSignature};

// Ring proof assumes:
// 1. Points over the whole curve group (not just the prime subgroup).
// 2. Short weierstrass form.
pub trait RingSuite:
    PedersenSuite<Affine = ark_ec::short_weierstrass::Affine<Self::Config>>
{
    type Config: SWCurveConfig;
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    const COMPLEMENT_POINT: AffinePoint<Self>;
}

type Curve<S> = <S as RingSuite>::Config;

/// KZG Polynomial Commitment Scheme.
type Pcs<S> = fflonk::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG Setup Parameters.
///
/// Basically the powers of tau URS.
type PcsParams<S> = fflonk::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

type PairingScalarField<S> = <<S as RingSuite>::Pairing as ark_ec::pairing::Pairing>::ScalarField;

pub type ProverKey<S> = ring_proof::ProverKey<PairingScalarField<S>, Pcs<S>, AffinePoint<S>>;

pub type VerifierKey<S> = ring_proof::VerifierKey<PairingScalarField<S>, Pcs<S>>;

pub type Prover<S> = ring_proof::ring_prover::RingProver<PairingScalarField<S>, Pcs<S>, Curve<S>>;

pub type Verifier<S> =
    ring_proof::ring_verifier::RingVerifier<PairingScalarField<S>, Pcs<S>, Curve<S>>;

pub type RingProof<S> = ring_proof::RingProof<PairingScalarField<S>, Pcs<S>>;

pub type PiopParams<S> = ring_proof::PiopParams<PairingScalarField<S>, Curve<S>>;

pub trait Pairing<S: RingSuite>: ark_ec::pairing::Pairing<ScalarField = BaseField<S>> {}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<S: RingSuite>
where
    <S::Config as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    pub vrf_signature: PedersenSignature<S>,
    pub ring_proof: RingProof<S>,
}

pub trait RingSigner<S: RingSuite>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    /// Sign the input and the user additional data `ad`.
    fn ring_sign(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &Prover<S>,
    ) -> Signature<S>;
}

pub trait RingVerifier<S: RingSuite>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    /// Verify a signature.
    fn ring_verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Signature<S>,
        verifier: &Verifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> RingSigner<S> for Secret<S>
where
    Self: PedersenSigner<S>,
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    fn ring_sign(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &Prover<S>,
    ) -> Signature<S> {
        let (vrf_signature, secret_blinding) =
            <Self as PedersenSigner<S>>::sign(self, input, output, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Signature {
            vrf_signature,
            ring_proof,
        }
    }
}

impl<S: RingSuite> RingVerifier<S> for Public<S>
where
    Self: PedersenVerifier<S>,
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    /// Verify the VRF signature.
    fn ring_verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Signature<S>,
        verifier: &Verifier<S>,
    ) -> Result<(), Error> {
        <Self as PedersenVerifier<S>>::verify(input, output, ad, &sig.vrf_signature)?;
        let key_commitment = sig.vrf_signature.key_commitment();
        if !verifier.verify_ring_proof(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RingContext<S: RingSuite>
where
    Curve<S>: SWCurveConfig + Clone,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    pub pcs_params: PcsParams<S>,
    pub piop_params: PiopParams<S>,
    pub domain_size: usize,
}

impl<S: RingSuite> RingContext<S>
where
    Curve<S>: SWCurveConfig + Clone,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    pub fn from_seed(domain_size: usize, seed: [u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::new_random(domain_size, &mut rng)
    }

    pub fn new_random<R: ark_std::rand::RngCore>(domain_size: usize, rng: &mut R) -> Self {
        use fflonk::pcs::PCS;

        let pcs_params = <Pcs<S>>::setup(3 * domain_size, rng);
        let piop_params = make_piop_params::<S>(domain_size);
        Self {
            pcs_params,
            piop_params,
            domain_size,
        }
    }

    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    pub fn keyset_max_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    pub fn prover_key(&self, pks: Vec<AffinePoint<S>>) -> ProverKey<S> {
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: Vec<AffinePoint<S>>) -> VerifierKey<S> {
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    pub fn prover(&self, prover_key: ProverKey<S>, key_index: usize) -> Prover<S> {
        <Prover<S>>::init(
            prover_key,
            self.piop_params.clone(),
            key_index,
            merlin::Transcript::new(b"ring-vrf"),
        )
    }

    pub fn verifier(&self, verifier_key: VerifierKey<S>) -> Verifier<S> {
        <Verifier<S>>::init(
            verifier_key,
            self.piop_params.clone(),
            merlin::Transcript::new(b"ring-vrf"),
        )
    }
}

impl<S: RingSuite + Sync> CanonicalSerialize for RingContext<S>
where
    Curve<S>: SWCurveConfig + Clone,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
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

impl<S: RingSuite + Sync> CanonicalDeserialize for RingContext<S>
where
    Curve<S>: SWCurveConfig + Clone,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let domain_size = <usize as CanonicalDeserialize>::deserialize_compressed(&mut reader)?;
        let piop_params = make_piop_params::<S>(domain_size);
        let pcs_params = <PcsParams<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        Ok(RingContext {
            piop_params,
            pcs_params,
            domain_size,
        })
    }
}

fn make_piop_params<S: RingSuite>(domain_size: usize) -> PiopParams<S>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    let domain = ring_proof::Domain::new(domain_size, true);
    PiopParams::<S>::setup(domain, S::BLINDING_BASE, S::COMPLEMENT_POINT)
}

pub fn make_ring_verifier<S: RingSuite>(
    verifier_key: VerifierKey<S>,
    domain_size: usize,
) -> Verifier<S>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    let piop_params = make_piop_params::<S>(domain_size);
    <Verifier<S>>::init(
        verifier_key,
        piop_params,
        merlin::Transcript::new(b"ring-vrf"),
    )
}

impl<S: RingSuite + Sync> Valid for RingContext<S>
where
    Curve<S>: SWCurveConfig + Clone,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.pcs_params.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suites::bandersnatch::{ring::RingContext, AffinePoint, Input, Secret};
    use crate::utils::testing::{random_val, random_vec, TEST_SEED};

    #[test]
    fn sign_verify_works() {
        let rng = &mut ark_std::test_rng();
        let domain_size = 1024;
        let ring_ctx = RingContext::new_random(domain_size, rng);

        let secret = Secret::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(random_val(Some(rng)));
        let output = secret.output(input);

        let keyset_size = ring_ctx.piop_params.keyset_part_size;

        let prover_idx = 3;
        let mut pks = random_vec::<AffinePoint>(keyset_size, Some(rng));
        pks[prover_idx] = public.0;

        let prover_key = ring_ctx.prover_key(pks.clone());
        let prover = ring_ctx.prover(prover_key, prover_idx);
        let signature = secret.ring_sign(input, output, b"foo", &prover);

        let verifier_key = ring_ctx.verifier_key(pks);
        let verifier = ring_ctx.verifier(verifier_key);
        let result = Public::ring_verify(input, output, b"foo", &signature, &verifier);
        assert!(result.is_ok());
    }
}
