use crate::*;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_serialize::{Compress, Read, SerializationError, Valid, Validate, Write};
use pedersen::{PedersenSuite, Proof as PedersenProof};

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
pub struct Proof<S: RingSuite>
where
    <S::Config as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    pub pedersen_proof: PedersenProof<S>,
    pub ring_proof: RingProof<S>,
}

pub trait RingProver<S: RingSuite>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    /// Generate a proof for the given input/output and user additional data.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &Prover<S>,
    ) -> Proof<S>;
}

pub trait RingVerifier<S: RingSuite>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &Verifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> RingProver<S> for Secret<S>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &Prover<S>,
    ) -> Proof<S> {
        use crate::pedersen::PedersenProver;
        let (pedersen_proof, secret_blinding) =
            <Self as PedersenProver<S>>::prove(self, input, output, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Proof {
            pedersen_proof,
            ring_proof,
        }
    }
}

impl<S: RingSuite> RingVerifier<S> for Public<S>
where
    Curve<S>: SWCurveConfig,
    <Curve<S> as CurveConfig>::BaseField: ark_ff::PrimeField,
{
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &Verifier<S>,
    ) -> Result<(), Error> {
        use crate::pedersen::PedersenVerifier;
        <Self as PedersenVerifier<S>>::verify(input, output, ad, &sig.pedersen_proof)?;
        let key_commitment = sig.pedersen_proof.key_commitment();
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
