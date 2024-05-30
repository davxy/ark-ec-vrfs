use crate::*;
use ark_ec::short_weierstrass::SWCurveConfig;
use pedersen::{PedersenSuite, Proof as PedersenProof};

pub trait RingSuite: PedersenSuite {
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    const COMPLEMENT_POINT: AffinePoint<Self>;
}

/// KZG Polynomial Commitment Scheme.
type Pcs<S> = fflonk::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG Setup Parameters.
///
/// Basically the powers of tau URS.
type PcsParams<S> = fflonk::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

type PairingScalarField<S> = <<S as RingSuite>::Pairing as ark_ec::pairing::Pairing>::ScalarField;

pub type ProverKey<S> = ring_proof::ProverKey<
    PairingScalarField<S>,
    Pcs<S>,
    ark_ec::short_weierstrass::Affine<CurveConfig<S>>,
>;

pub type VerifierKey<S> = ring_proof::VerifierKey<PairingScalarField<S>, Pcs<S>>;

pub type RingProver<S> =
    ring_proof::ring_prover::RingProver<PairingScalarField<S>, Pcs<S>, CurveConfig<S>>;

pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<PairingScalarField<S>, Pcs<S>, CurveConfig<S>>;

pub type RingProof<S> = ring_proof::RingProof<PairingScalarField<S>, Pcs<S>>;

pub type PiopParams<S> = ring_proof::PiopParams<PairingScalarField<S>, CurveConfig<S>>;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
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
    AffinePoint<S>: IntoSW<CurveConfig<S>>,
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
    pub domain_size: usize,
}

impl<S: RingSuite> RingContext<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig + Clone,
    AffinePoint<S>: IntoSW<CurveConfig<S>>,
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

    pub fn prover_key(&self, pks: &[AffinePoint<S>]) -> ProverKey<S> {
        let pks = pks.iter().map(|p| p.into_sw()).collect();
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).0
    }

    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> VerifierKey<S> {
        let pks: Vec<_> = pks.iter().map(|p| p.into_sw()).collect();
        ring_proof::index(self.pcs_params.clone(), &self.piop_params, pks).1
    }

    pub fn prover(&self, prover_key: ProverKey<S>, key_index: usize) -> RingProver<S> {
        RingProver::<S>::init(
            prover_key,
            self.piop_params.clone(),
            key_index,
            merlin::Transcript::new(b"ring-vrf"),
        )
    }

    pub fn verifier(&self, verifier_key: VerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop_params.clone(),
            merlin::Transcript::new(b"ring-vrf"),
        )
    }
}

pub trait IntoSW<C: SWCurveConfig> {
    fn into_sw(self) -> ark_ec::short_weierstrass::Affine<C>;
}

impl<C: SWCurveConfig> IntoSW<C> for ark_ec::short_weierstrass::Affine<C> {
    fn into_sw(self) -> ark_ec::short_weierstrass::Affine<C> {
        self
    }
}

impl<C: utils::ark_next::MapConfig> IntoSW<C> for ark_ec::twisted_edwards::Affine<C> {
    fn into_sw(self) -> ark_ec::short_weierstrass::Affine<C> {
        const ERR_MSG: &str =
            "'IntoSW' is expected to be implemented only for curves supporting the mapping";
        utils::ark_next::map_te_to_sw(&self).expect(ERR_MSG)
    }
}

fn make_piop_params<S: RingSuite>(domain_size: usize) -> PiopParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
    AffinePoint<S>: IntoSW<CurveConfig<S>>,
{
    let domain = ring_proof::Domain::new(domain_size, true);
    PiopParams::<S>::setup(
        domain,
        S::BLINDING_BASE.into_sw(),
        S::COMPLEMENT_POINT.into_sw(),
    )
}
