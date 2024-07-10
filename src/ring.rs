use crate::utils::SWMapping;
use crate::*;
use ark_ec::short_weierstrass::SWCurveConfig;
use pedersen::{PedersenSuite, Proof as PedersenProof};

pub mod prelude {
    pub use fflonk;
    pub use ring_proof;
}

#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub trait RingSuite: PedersenSuite {
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    const COMPLEMENT_POINT: AffinePoint<Self>;
}

/// KZG Polynomial Commitment Scheme.
pub type Pcs<S> = fflonk::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG commitment.
pub type PcsCommitment<S> = fflonk::pcs::kzg::commitment::KzgCommitment<<S as RingSuite>::Pairing>;

/// KZG setup parameters.
///
/// Basically the powers of tau SRS.
pub type PcsParams<S> = fflonk::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

/// Ring proof application specific setup parameters.
pub type PiopParams<S> = ring_proof::PiopParams<BaseField<S>, CurveConfig<S>>;

/// Ring keys commitment.
pub type RingCommitment<S> = ring_proof::FixedColumnsCommitted<BaseField<S>, PcsCommitment<S>>;

/// Ring prover key.
pub type ProverKey<S> =
    ring_proof::ProverKey<BaseField<S>, Pcs<S>, ark_ec::short_weierstrass::Affine<CurveConfig<S>>>;

/// Ring verifier key.
pub type VerifierKey<S> = ring_proof::VerifierKey<BaseField<S>, Pcs<S>>;

/// Ring prover.
pub type RingProver<S> = ring_proof::ring_prover::RingProver<BaseField<S>, Pcs<S>, CurveConfig<S>>;

/// Ring verifier.
pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, Pcs<S>, CurveConfig<S>>;

/// Ring proof.
pub type RingProof<S> = ring_proof::RingProof<BaseField<S>, Pcs<S>>;

/// Ring proof.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
{
    pub pedersen_proof: PedersenProof<S>,
    pub ring_proof: RingProof<S>,
}

pub trait Prover<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
{
    /// Generate a proof for the given input/output and user additional data.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &RingProver<S>,
    ) -> Proof<S>;
}

impl<S: RingSuite> Prover<S> for Secret<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
{
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        ring_prover: &RingProver<S>,
    ) -> Proof<S> {
        use pedersen::Prover as PedersenProver;
        let (pedersen_proof, secret_blinding) =
            <Self as PedersenProver<S>>::prove(self, input, output, ad);
        let ring_proof = ring_prover.prove(secret_blinding);
        Proof {
            pedersen_proof,
            ring_proof,
        }
    }
}

pub trait Verifier<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
{
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error>;
}

impl<S: RingSuite> Verifier<S> for Public<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
{
    fn verify(
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
        verifier: &RingVerifier<S>,
    ) -> Result<(), Error> {
        use pedersen::Verifier as PedersenVerifier;
        <Self as PedersenVerifier<S>>::verify(input, output, ad, &sig.pedersen_proof)?;
        let key_commitment = sig.pedersen_proof.key_commitment().into_sw();
        if !verifier.verify_ring_proof(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RingContext<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
{
    pub pcs_params: PcsParams<S>,
    pub piop_params: PiopParams<S>,
}

fn domain_size(ring_size: usize) -> usize {
    const RING_DOMAIN_OVERHEAD: usize = 257;
    1 << ark_std::log2(ring_size + RING_DOMAIN_OVERHEAD)
}

impl<S: RingSuite> RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
{
    /// Construct a new ring context suitable to manage the given ring size.
    pub fn from_seed(ring_size: usize, seed: [u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::new_random(ring_size, &mut rng)
    }

    /// Construct a new random ring context suitable for the given ring size.
    pub fn new_random<R: ark_std::rand::RngCore>(ring_size: usize, rng: &mut R) -> Self {
        use fflonk::pcs::PCS;
        let domain_size = domain_size(ring_size);
        let pcs_params = Pcs::<S>::setup(3 * domain_size, rng);
        Self::from_srs(ring_size, pcs_params).expect("PCS params is correct")
    }

    pub fn from_srs(ring_size: usize, mut pcs_params: PcsParams<S>) -> Result<Self, Error> {
        let domain_size = domain_size(ring_size);
        if pcs_params.powers_in_g1.len() < 3 * domain_size + 1 || pcs_params.powers_in_g2.len() < 2
        {
            return Err(Error::InvalidData);
        }
        // Keep only the required powers of tau.
        pcs_params.powers_in_g1.truncate(3 * domain_size + 1);
        pcs_params.powers_in_g2.truncate(2);
        let piop_params = make_piop_params::<S>(domain_size);
        Ok(Self {
            pcs_params,
            piop_params,
        })
    }

    /// The max ring size this context is able to manage.
    pub fn max_ring_size(&self) -> usize {
        self.piop_params.keyset_part_size
    }

    pub fn prover_key(&self, pks: &[AffinePoint<S>]) -> ProverKey<S> {
        #[cfg(feature = "parallel")]
        let pks = pks.par_iter().map(|p| p.into_sw()).collect();
        #[cfg(not(feature = "parallel"))]
        let pks = pks.iter().map(|p| p.into_sw()).collect();
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> VerifierKey<S> {
        #[cfg(feature = "parallel")]
        let pks = pks.par_iter().map(|p| p.into_sw()).collect();
        #[cfg(not(feature = "parallel"))]
        let pks = pks.iter().map(|p| p.into_sw()).collect();
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    pub fn prover(&self, prover_key: ProverKey<S>, key_index: usize) -> RingProver<S> {
        RingProver::<S>::init(
            prover_key,
            self.piop_params.clone(),
            key_index,
            merlin::Transcript::new(b""),
        )
    }

    pub fn verifier(&self, verifier_key: VerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop_params.clone(),
            merlin::Transcript::new(b""),
        )
    }
}

impl<S: RingSuite> CanonicalSerialize for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.pcs_params.serialized_size(compress)
    }
}

impl<S: RingSuite> CanonicalDeserialize for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let pcs_params = <PcsParams<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            compress,
            validate,
        )?;
        let domain_size = (pcs_params.powers_in_g1.len() - 1) / 3;
        let piop_params = make_piop_params::<S>(domain_size);
        Ok(RingContext {
            piop_params,
            pcs_params,
        })
    }
}

impl<S: RingSuite> ark_serialize::Valid for RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pcs_params.check()
    }
}

pub(crate) fn make_piop_params<S: RingSuite>(domain_size: usize) -> PiopParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
    AffinePoint<S>: SWMapping<CurveConfig<S>>,
{
    let domain = ring_proof::Domain::new(domain_size, true);
    PiopParams::<S>::setup(
        domain,
        S::BLINDING_BASE.into_sw(),
        S::COMPLEMENT_POINT.into_sw(),
    )
}
