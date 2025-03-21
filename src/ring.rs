//! Ring VRF.
//!
//! This module is gated by the `ring` feature.

use crate::*;
use ark_ec::{
    pairing::Pairing,
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_std::ops::Range;
use pedersen::{PedersenSuite, Proof as PedersenProof};
use utils::te_sw_map::TEMapping;

/// Magic spell for [RingSuite::ACCUMULATOR_BASE] generation in built-in implementations.
///
/// (en) *"The foundation of the accumulator which in the silence of time guards the hidden secret"*
pub const ACCUMULATOR_BASE_SEED: &[u8] =
    b"substratum accumulatoris quod in silentio temporis arcanum absconditum custodit";

/// Magic spell for [RingSuite::PADDING] generation in built-in implementations.
///
/// (en) *"A shadow that fills the void left by lost souls echoing among the darkness"*
pub const PADDING_SEED: &[u8] =
    b"umbra quae vacuum implet ab animabus perditis relictum inter tenebras resonans";

/// Max ring size that can be managed with the given PCS domain size.
pub const fn max_ring_size_from_pcs_domain_size<S: Suite>(pcs_domain_size: usize) -> usize {
    let piop_domain_size = piop_domain_size_from_pcs_domain_size(pcs_domain_size);
    max_ring_size_from_piop_domain_size::<S>(piop_domain_size)
}

/// PCS domain size required to manage the given ring size.
// This is the size required by the prover, verifier can just use piop_domain_size
pub const fn pcs_domain_size<S: Suite>(ring_size: usize) -> usize {
    3 * piop_domain_size::<S>(ring_size) + 1
}

/// Max ring size that can be managed with the given PIOP domain size.
const fn max_ring_size_from_piop_domain_size<S: Suite>(piop_domain_size: usize) -> usize {
    piop_domain_size - (4 + ScalarField::<S>::MODULUS_BIT_SIZE as usize)
}

/// PIOP domain size required to manage the given ring size.
///
/// Next power of two after accouting for 3 ZK + 1 extra point used internally.
const fn piop_domain_size<S: Suite>(ring_size: usize) -> usize {
    (ring_size + 4 + ScalarField::<S>::MODULUS_BIT_SIZE as usize).next_power_of_two()
}

/// A properly constructed PCS domain has size equal to 3*piop_domain_size+1,
/// with piop_domain_size a power of 2.
const fn piop_domain_size_from_pcs_domain_size(pcs_domain_size: usize) -> usize {
    1 << ((pcs_domain_size - 1) / 3).ilog2()
}

/// Ring suite.
pub trait RingSuite: PedersenSuite
where
    BaseField<Self>: ark_ff::PrimeField,
    CurveConfig<Self>: TECurveConfig,
    AffinePoint<Self>: TEMapping<CurveConfig<Self>>,
{
    /// Pairing type.
    type Pairing: ark_ec::pairing::Pairing<ScalarField = BaseField<Self>>;

    /// Accumulator base.
    ///
    /// In order for the ring-proof backend to work correctly, this is required to be
    /// in the prime order subgroup.
    const ACCUMULATOR_BASE: AffinePoint<Self>;

    /// Padding point with unknown discrete log.
    const PADDING: AffinePoint<Self>;
}

/// KZG Polinomial Commitment Scheme.
pub type Pcs<S> = ring_proof::pcs::kzg::KZG<<S as RingSuite>::Pairing>;

/// KZG commitment.
pub type PcsCommitment<S> =
    ring_proof::pcs::kzg::commitment::KzgCommitment<<S as RingSuite>::Pairing>;

/// KZG Polynomial Commitment Scheme parameters.
///
/// Basically powers of tau SRS.
pub type PcsParams<S> = ring_proof::pcs::kzg::urs::URS<<S as RingSuite>::Pairing>;

/// Polynomial Interactive Oracle Proof (IOP) parameters.
///
/// Basically all the application specific parameters required to construct and
/// verify the ring proof.
pub type PiopParams<S> = ring_proof::PiopParams<BaseField<S>, CurveConfig<S>>;

/// Ring keys commitment.
pub type RingCommitment<S> = ring_proof::FixedColumnsCommitted<BaseField<S>, PcsCommitment<S>>;

/// Ring prover key.
pub type RingProverKey<S> = ring_proof::ProverKey<BaseField<S>, Pcs<S>, TEAffine<CurveConfig<S>>>;

/// Ring verifier key.
pub type RingVerifierKey<S> = ring_proof::VerifierKey<BaseField<S>, Pcs<S>>;

/// Ring prover.
pub type RingProver<S> = ring_proof::ring_prover::RingProver<BaseField<S>, Pcs<S>, CurveConfig<S>>;

/// Ring verifier.
pub type RingVerifier<S> =
    ring_proof::ring_verifier::RingVerifier<BaseField<S>, Pcs<S>, CurveConfig<S>>;

/// Raw ring proof.
///
/// This is the primitive ring proof used in conjunction with Pedersen proof to
/// construct the actual ring vrf proof [`Proof`].
pub type RingBareProof<S> = ring_proof::RingProof<BaseField<S>, Pcs<S>>;

/// Ring VRF proof.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    pub pedersen_proof: PedersenProof<S>,
    pub ring_proof: RingBareProof<S>,
}

/// Ring VRF prover.
pub trait Prover<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// Generate a proof for the given input/output and additional data.
    fn prove(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        prover: &RingProver<S>,
    ) -> Proof<S>;
}

/// Ring VRF verifier.
pub trait Verifier<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
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

impl<S: RingSuite> Prover<S> for Secret<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
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

impl<S: RingSuite> Verifier<S> for Public<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
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
        let key_commitment = sig.pedersen_proof.key_commitment().into_te();
        if !verifier.verify(sig.ring_proof.clone(), key_commitment) {
            return Err(Error::VerificationFailure);
        }
        Ok(())
    }
}

/// Ring proof full parameters.
///
/// Wraps [`PcsParams`] and [`PiopParams`].
#[derive(Clone)]
pub struct RingProofParams<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// PCS parameters.
    pub pcs: PcsParams<S>,
    /// PIOP parameters.
    pub piop: PiopParams<S>,
}

pub(crate) fn piop_params<S: RingSuite>(domain_size: usize) -> PiopParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    PiopParams::<S>::setup(
        ring_proof::Domain::new(domain_size, true),
        S::BLINDING_BASE.into_te(),
        S::ACCUMULATOR_BASE.into_te(),
        S::PADDING.into_te(),
    )
}

impl<S: RingSuite> RingProofParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// Construct new ring proof params suitable for the given ring size.
    ///
    /// Calls into [`RingProofParams::from_rand`] with a `ChaCha20Rng` seeded with `seed`.
    pub fn from_seed(ring_size: usize, seed: [u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        Self::from_rand(ring_size, &mut rng)
    }

    /// Construct a new random ring context suitable for the given ring size.
    ///
    /// Calls into [`RingProofParams::from_srs`] with randomly generated [`PcsParams`]
    /// large enough to be used for the given `ring_size`.
    pub fn from_rand(ring_size: usize, rng: &mut impl ark_std::rand::RngCore) -> Self {
        use ring_proof::pcs::PCS;
        let max_degree = pcs_domain_size::<S>(ring_size) - 1;
        let pcs_params = Pcs::<S>::setup(max_degree, rng);
        Self::from_pcs_params(ring_size, pcs_params).expect("PCS params is correct")
    }

    /// Construct a new random ring context suitable for the given [`PcsParams`].
    ///
    /// Fails if the domain representable via the supplied `PcsParams` is not sufficiently
    /// large for the given `ring_size`.
    ///
    /// If the domain size of `PcsParams` exceeds the required limit, the extra items are truncated.
    pub fn from_pcs_params(ring_size: usize, mut pcs_params: PcsParams<S>) -> Result<Self, Error> {
        let pcs_domain_size = pcs_domain_size::<S>(ring_size);
        if pcs_params.powers_in_g1.len() < pcs_domain_size || pcs_params.powers_in_g2.len() < 2 {
            return Err(Error::InvalidData);
        }
        // Keep only the required powers of tau.
        pcs_params.powers_in_g1.truncate(pcs_domain_size);
        pcs_params.powers_in_g2.truncate(2);
        let piop_domain_size = piop_domain_size::<S>(ring_size);
        Ok(Self {
            pcs: pcs_params,
            piop: piop_params::<S>(piop_domain_size),
        })
    }

    /// The max ring size these parameters are able to handle.
    #[inline(always)]
    pub fn max_ring_size(&self) -> usize {
        self.piop.keyset_part_size
    }

    /// Construct [`RingProverKey`] for the given ring.
    ///
    /// Note: if `pks.len() > self.max_ring_size()` the extra keys in the tail are ignored.
    pub fn prover_key(&self, pks: &[AffinePoint<S>]) -> RingProverKey<S> {
        let pks = TEMapping::to_te_slice(&pks[..pks.len().min(self.max_ring_size())]);
        ring_proof::index(&self.pcs, &self.piop, &pks).0
    }

    /// Construct [`RingProver`] from [`RingProverKey`] for the prover implied by `key_index`.
    ///
    /// Key index is the prover index within the `pks` sequence passed to construct the
    /// [`RingProverKey`] via the `prover_key` method.
    pub fn prover(&self, prover_key: RingProverKey<S>, key_index: usize) -> RingProver<S> {
        RingProver::<S>::init(
            prover_key,
            self.piop.clone(),
            key_index,
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Construct a `RingVerifierKey` instance for the given ring.
    ///
    /// Note: if `pks.len() > self.max_ring_size()` the extra keys in the tail are ignored.
    pub fn verifier_key(&self, pks: &[AffinePoint<S>]) -> RingVerifierKey<S> {
        let pks = TEMapping::to_te_slice(&pks[..pks.len().min(self.max_ring_size())]);
        ring_proof::index(&self.pcs, &self.piop, &pks).1
    }

    /// Construct `RingVerifierKey` instance for the ring previously committed.
    ///
    /// The `RingCommitment` instance can be obtained via the `VerifierKey::commitment()` method.
    ///
    /// This allows to quickly reconstruct the verifier key without having to recompute the
    /// keys commitment.
    pub fn verifier_key_from_commitment(
        &self,
        commitment: RingCommitment<S>,
    ) -> RingVerifierKey<S> {
        use ring_proof::pcs::PcsParams;
        RingVerifierKey::<S>::from_commitment_and_kzg_vk(commitment, self.pcs.raw_vk())
    }

    /// Builder for incremental construction of the verifier key.
    ///
    /// This also returns a `RingBuilderPcsParams` which may be used to append new key items
    /// to the `RingVerifierKeyBuilder` instance its tne `SrsLookup` implementation.
    pub fn verifier_key_builder(&self) -> (RingVerifierKeyBuilder<S>, RingBuilderPcsParams<S>) {
        type RingBuilderKey<S> =
            ring_proof::ring::RingBuilderKey<BaseField<S>, <S as RingSuite>::Pairing>;
        let piop_domain_size = piop_domain_size::<S>(self.piop.keyset_part_size);
        let builder_key = RingBuilderKey::<S>::from_srs(&self.pcs, piop_domain_size);
        let builder_pcs_params = RingBuilderPcsParams(builder_key.lis_in_g1);
        let builder = RingVerifierKeyBuilder::new(self, &builder_pcs_params);
        (builder, builder_pcs_params)
    }

    /// Construct `RingVerifier` from `RingVerifierKey`.
    pub fn verifier(&self, verifier_key: RingVerifierKey<S>) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            self.piop.clone(),
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Constructs a `RingVerifier` from `RingVerifierKey` without no `RingProofParams`.
    ///
    /// While this approach is slightly less efficient than using pre-constructed `RingProofParams`,
    /// as some parameters need to be computed on-the-fly, it is beneficial in memory or
    /// storage constrained environments. This avoids the need to retain the full `RingProofParams` for
    /// ring signature verification. Instead, the `VerifierKey` contains only the essential information
    /// needed to verify ring proofs.
    pub fn verifier_no_context(
        verifier_key: RingVerifierKey<S>,
        ring_size: usize,
    ) -> RingVerifier<S> {
        RingVerifier::<S>::init(
            verifier_key,
            piop_params::<S>(piop_domain_size::<S>(ring_size)),
            ring_proof::ArkTranscript::new(S::SUITE_ID),
        )
    }

    /// Get the padding point.
    ///
    /// This is a point of unknown dlog that can be used in place of any key during
    /// ring construciton.
    #[inline(always)]
    pub const fn padding_point() -> AffinePoint<S> {
        S::PADDING
    }
}

impl<S: RingSuite> CanonicalSerialize for RingProofParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.pcs.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.pcs.serialized_size(compress)
    }
}

impl<S: RingSuite> CanonicalDeserialize for RingProofParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
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
        let piop_domain_size = piop_domain_size_from_pcs_domain_size(pcs_params.powers_in_g1.len());
        Ok(Self {
            pcs: pcs_params,
            piop: piop_params::<S>(piop_domain_size),
        })
    }
}

impl<S: RingSuite> ark_serialize::Valid for RingProofParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.pcs.check()
    }
}

/// Information required for incremental ring construction.
///
/// Basically the SRS in Lagrangian form.
/// Can be constructed via the `PcsParams::ck_with_lagrangian()` method.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingBuilderPcsParams<S: RingSuite>(pub Vec<G1Affine<S>>)
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>;

// Under construction ring commitment.
type PartialRingCommitment<S> =
    ring_proof::ring::Ring<BaseField<S>, <S as RingSuite>::Pairing, CurveConfig<S>>;

type RawVerifierKey<S> = <PcsParams<S> as ring_proof::pcs::PcsParams>::RVK;

/// Ring verifier key builder.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RingVerifierKeyBuilder<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    partial: PartialRingCommitment<S>,
    raw_vk: RawVerifierKey<S>,
}

pub type G1Affine<S> = <<S as RingSuite>::Pairing as Pairing>::G1Affine;
pub type G2Affine<S> = <<S as RingSuite>::Pairing as Pairing>::G2Affine;

/// Lagrangian form SRS entries lookup.
pub trait SrsLookup<S: RingSuite>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn lookup(&self, range: Range<usize>) -> Option<Vec<G1Affine<S>>>;
}

impl<S: RingSuite, F> SrsLookup<S> for F
where
    F: Fn(Range<usize>) -> Option<Vec<G1Affine<S>>>,
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn lookup(&self, range: Range<usize>) -> Option<Vec<G1Affine<S>>> {
        self(range)
    }
}

impl<S: RingSuite> SrsLookup<S> for &RingBuilderPcsParams<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    fn lookup(&self, range: Range<usize>) -> Option<Vec<G1Affine<S>>> {
        if range.end > self.0.len() {
            return None;
        }
        Some(self.0[range].to_vec())
    }
}

impl<S: RingSuite> RingVerifierKeyBuilder<S>
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: TECurveConfig + Clone,
    AffinePoint<S>: TEMapping<CurveConfig<S>>,
{
    /// Construct an empty ring verifier key builder.
    pub fn new(params: &RingProofParams<S>, lookup: impl SrsLookup<S>) -> Self {
        use ring_proof::pcs::PcsParams;
        let lookup = |range: Range<usize>| lookup.lookup(range).ok_or(());
        let raw_vk = params.pcs.raw_vk();
        let partial =
            PartialRingCommitment::<S>::empty(&params.piop, lookup, raw_vk.g1.into_group());
        RingVerifierKeyBuilder { partial, raw_vk }
    }

    /// Free public key slots.
    #[inline(always)]
    pub fn free_slots(&self) -> usize {
        self.partial.max_keys - self.partial.curr_keys
    }

    /// Append a new member to the ring verifier key.
    ///
    /// If the `pks` length is greater than the number of available slots in the ring
    /// then an error is returned with the available slots count.
    ///
    /// If the available free slots are not sufficient to append `pks` sequence, the
    /// number of available slots are returned in the error variant.
    /// If the supplied `lookup` returns `None`, then an error with `usize::MAX` is
    /// returned.
    pub fn append(
        &mut self,
        pks: &[AffinePoint<S>],
        lookup: impl SrsLookup<S>,
    ) -> Result<(), usize> {
        let avail_slots = self.free_slots();
        if avail_slots < pks.len() {
            return Err(avail_slots);
        }
        // Currently `ring-proof` backend panics if lookup fails.
        // This workaround makes lookup failures a bit less harsh.
        let segment = lookup
            .lookup(self.partial.curr_keys..self.partial.curr_keys + pks.len())
            .ok_or(usize::MAX)?;
        let lookup = |range: Range<usize>| {
            debug_assert_eq!(segment.len(), range.len());
            Ok(segment.clone())
        };
        let pks = TEMapping::to_te_slice(pks);
        self.partial.append(&pks, lookup);
        Ok(())
    }

    /// Build verifier key.
    pub fn finalize(self) -> RingVerifierKey<S> {
        RingVerifierKey::<S>::from_ring_and_kzg_vk(&self.partial, self.raw_vk)
    }
}

/// Type aliases for the given ring suite.
#[macro_export]
macro_rules! ring_suite_types {
    ($suite:ident) => {
        #[allow(dead_code)]
        pub type PcsParams = $crate::ring::PcsParams<$suite>;
        #[allow(dead_code)]
        pub type PiopParams = $crate::ring::PiopParams<$suite>;
        #[allow(dead_code)]
        pub type RingProofParams = $crate::ring::RingProofParams<$suite>;
        #[allow(dead_code)]
        pub type RingProverKey = $crate::ring::RingProverKey<$suite>;
        #[allow(dead_code)]
        pub type RingVerifierKey = $crate::ring::RingVerifierKey<$suite>;
        #[allow(dead_code)]
        pub type RingCommitment = $crate::ring::RingCommitment<$suite>;
        #[allow(dead_code)]
        pub type RingProver = $crate::ring::RingProver<$suite>;
        #[allow(dead_code)]
        pub type RingVerifier = $crate::ring::RingVerifier<$suite>;
        #[allow(dead_code)]
        pub type RingProof = $crate::ring::Proof<$suite>;
        #[allow(dead_code)]
        pub type RingVerifierKeyBuilder = $crate::ring::RingVerifierKeyBuilder<$suite>;
    };
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::pedersen;
    use crate::testing::{self as common, CheckPoint, TEST_SEED};
    use ark_ec::{
        short_weierstrass::{Affine as SWAffine, SWCurveConfig},
        twisted_edwards::{Affine as TEAffine, TECurveConfig},
    };

    pub const TEST_RING_SIZE: usize = 8;

    fn find_complement_point<C: SWCurveConfig>() -> SWAffine<C> {
        use ark_ff::{One, Zero};
        assert!(!C::cofactor_is_one());
        let mut x = C::BaseField::zero();
        loop {
            if let Some(p) = SWAffine::get_point_from_x_unchecked(x, false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
            {
                return p;
            }
            x += C::BaseField::one();
        }
    }

    pub trait FindAccumulatorBase<S: Suite>: Sized {
        const IN_PRIME_ORDER_SUBGROUP: bool;
        fn find_accumulator_base(data: &[u8]) -> Option<Self>;
    }

    impl<S, C> FindAccumulatorBase<S> for SWAffine<C>
    where
        C: SWCurveConfig,
        S: Suite<Affine = Self>,
    {
        const IN_PRIME_ORDER_SUBGROUP: bool = false;

        fn find_accumulator_base(data: &[u8]) -> Option<Self> {
            let p = S::data_to_point(data)?;
            let c = find_complement_point();
            let res = (p + c).into_affine();
            debug_assert!(!res.is_in_correct_subgroup_assuming_on_curve());
            Some(res)
        }
    }

    impl<S, C> FindAccumulatorBase<S> for TEAffine<C>
    where
        C: TECurveConfig,
        S: Suite<Affine = Self>,
    {
        const IN_PRIME_ORDER_SUBGROUP: bool = true;

        fn find_accumulator_base(data: &[u8]) -> Option<Self> {
            let res = S::data_to_point(data)?;
            debug_assert!(res.is_in_correct_subgroup_assuming_on_curve());
            Some(res)
        }
    }

    #[allow(unused)]
    pub fn prove_verify<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        let rng = &mut ark_std::test_rng();
        let params = RingProofParams::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(common::random_val(Some(rng)));
        let output = secret.output(input);

        let ring_size = params.max_ring_size();
        let pcs_dom_size = pcs_domain_size::<S>(ring_size);
        assert_eq!(pcs_dom_size, params.pcs.powers_in_g1.len());
        assert_eq!(pcs_dom_size / 3, piop_domain_size::<S>(ring_size));

        assert_eq!(
            max_ring_size_from_pcs_domain_size::<S>(pcs_dom_size),
            ring_size
        );

        let prover_idx = 3;
        let mut pks = common::random_vec::<AffinePoint<S>>(ring_size, Some(rng));
        pks[prover_idx] = public.0;

        let prover_key = params.prover_key(&pks);
        let prover = params.prover(prover_key, prover_idx);
        let proof = secret.prove(input, output, b"foo", &prover);

        let verifier_key = params.verifier_key(&pks);
        let verifier = params.verifier(verifier_key);
        let result = Public::verify(input, output, b"foo", &proof, &verifier);
        assert!(result.is_ok());
    }

    #[allow(unused)]
    pub fn padding_check<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>> + CheckPoint,
    {
        // Check that point has been computed using the magic spell.
        assert_eq!(S::PADDING, S::data_to_point(PADDING_SEED).unwrap());

        // Check that the point is on curve.
        assert!(S::PADDING.check(true).is_ok());
    }

    #[allow(unused)]
    pub fn accumulator_base_check<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>> + FindAccumulatorBase<S> + CheckPoint,
    {
        // Check that point has been computed using the magic spell.
        assert_eq!(
            S::ACCUMULATOR_BASE,
            AffinePoint::<S>::find_accumulator_base(ACCUMULATOR_BASE_SEED).unwrap()
        );

        // SW form requires accumulator seed to be outside prime order subgroup.
        // TE form requires accumulator seed to be in prime order subgroup.
        let in_prime_subgroup = <AffinePoint<S> as FindAccumulatorBase<S>>::IN_PRIME_ORDER_SUBGROUP;
        assert!(S::ACCUMULATOR_BASE.check(in_prime_subgroup).is_ok());
    }

    #[allow(unused)]
    pub fn verifier_key_builder<S: RingSuite>()
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        use crate::testing::{random_val, random_vec};

        let rng = &mut ark_std::test_rng();
        let params = RingProofParams::<S>::from_rand(TEST_RING_SIZE, rng);

        let secret = Secret::<S>::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(common::random_val(Some(rng)));
        let output = secret.output(input);

        let ring_size = params.max_ring_size();
        let prover_idx = random_val::<usize>(Some(rng)) % ring_size;
        let mut pks = random_vec::<AffinePoint<S>>(ring_size, Some(rng));
        pks[prover_idx] = public.0;

        let prover_key = params.prover_key(&pks);
        let prover = params.prover(prover_key, prover_idx);
        let proof = secret.prove(input, output, b"foo", &prover);

        // Incremental ring verifier key construction
        let (mut vk_builder, lookup) = params.verifier_key_builder();
        assert_eq!(vk_builder.free_slots(), pks.len());

        let extra_pk = random_val::<AffinePoint<S>>(Some(rng));
        assert_eq!(
            vk_builder.append(&[extra_pk], |_| None).unwrap_err(),
            usize::MAX
        );

        while !pks.is_empty() {
            let chunk_len = 1 + random_val::<usize>(Some(rng)) % 5;
            let chunk = pks.drain(..pks.len().min(chunk_len)).collect::<Vec<_>>();
            vk_builder.append(&chunk[..], &lookup).unwrap();
            assert_eq!(vk_builder.free_slots(), pks.len());
        }
        // No more space left
        let extra_pk = random_val::<AffinePoint<S>>(Some(rng));
        assert_eq!(vk_builder.append(&[extra_pk], &lookup).unwrap_err(), 0);
        let verifier_key = vk_builder.finalize();
        let verifier = params.verifier(verifier_key);
        let result = Public::verify(input, output, b"foo", &proof, &verifier);
        assert!(result.is_ok());
    }

    #[macro_export]
    macro_rules! ring_suite_tests {
        ($suite:ty) => {
            mod ring {
                use super::*;

                #[test]
                fn prove_verify() {
                    $crate::ring::testing::prove_verify::<$suite>()
                }

                #[test]
                fn padding_check() {
                    $crate::ring::testing::padding_check::<$suite>()
                }

                #[test]
                fn accumulator_base_check() {
                    $crate::ring::testing::accumulator_base_check::<$suite>()
                }

                #[test]
                fn verifier_key_builder() {
                    $crate::ring::testing::verifier_key_builder::<$suite>()
                }

                $crate::test_vectors!($crate::ring::testing::TestVector<$suite>);
            }
        };
    }

    pub trait RingSuiteExt: RingSuite + crate::testing::SuiteExt
    where
        BaseField<Self>: ark_ff::PrimeField,
        CurveConfig<Self>: TECurveConfig + Clone,
        AffinePoint<Self>: TEMapping<CurveConfig<Self>>,
    {
        const SRS_FILE: &str;

        fn params() -> &'static RingProofParams<Self>;

        #[allow(unused)]
        fn load_context() -> RingProofParams<Self> {
            use ark_serialize::CanonicalDeserialize;
            use std::{fs::File, io::Read};
            let mut file = File::open(Self::SRS_FILE).unwrap();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).unwrap();
            let pcs_params =
                PcsParams::<Self>::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
            RingProofParams::from_pcs_params(crate::ring::testing::TEST_RING_SIZE, pcs_params)
                .unwrap()
        }

        #[allow(unused)]
        fn write_context(params: &RingProofParams<Self>) {
            use ark_serialize::CanonicalSerialize;
            use std::{fs::File, io::Write};
            let mut file = File::create(Self::SRS_FILE).unwrap();
            let mut buf = Vec::new();
            params.pcs.serialize_uncompressed(&mut buf).unwrap();
            file.write_all(&buf).unwrap();
        }
    }

    pub struct TestVector<S: RingSuite>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        pub pedersen: pedersen::testing::TestVector<S>,
        pub ring_pks: [AffinePoint<S>; TEST_RING_SIZE],
        pub ring_pks_com: RingCommitment<S>,
        pub ring_proof: RingBareProof<S>,
    }

    impl<S: RingSuite> core::fmt::Debug for TestVector<S>
    where
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TestVector")
                .field("pedersen", &self.pedersen)
                .field("ring_proof", &"...")
                .finish()
        }
    }

    impl<S> common::TestVectorTrait for TestVector<S>
    where
        S: RingSuiteExt + std::fmt::Debug + 'static,
        BaseField<S>: ark_ff::PrimeField,
        CurveConfig<S>: TECurveConfig + Clone,
        AffinePoint<S>: TEMapping<CurveConfig<S>>,
    {
        fn name() -> String {
            S::suite_name() + "_ring"
        }

        fn new(comment: &str, seed: &[u8], alpha: &[u8], salt: &[u8], ad: &[u8]) -> Self {
            use super::Prover;
            let pedersen = pedersen::testing::TestVector::new(comment, seed, alpha, salt, ad);

            let secret = Secret::<S>::from_scalar(pedersen.base.sk);
            let public = secret.public();

            let input = Input::<S>::from(pedersen.base.h);
            let output = Output::from(pedersen.base.gamma);

            let params = <S as RingSuiteExt>::params();

            use ark_std::rand::SeedableRng;
            let rng = &mut rand_chacha::ChaCha20Rng::from_seed([0x11; 32]);
            let prover_idx = 3;
            let mut ring_pks = common::random_vec::<AffinePoint<S>>(TEST_RING_SIZE, Some(rng));
            ring_pks[prover_idx] = public.0;

            let prover_key = params.prover_key(&ring_pks);
            let prover = params.prover(prover_key, prover_idx);
            let proof = secret.prove(input, output, ad, &prover);

            let verifier_key = params.verifier_key(&ring_pks);
            let ring_pks_com = verifier_key.commitment();

            {
                // Just in case...
                let mut p = (Vec::new(), Vec::new());
                pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            // TODO: also dump the verifier pks commitment
            Self {
                pedersen,
                ring_pks: ring_pks.try_into().unwrap(),
                ring_pks_com,
                ring_proof: proof.ring_proof,
            }
        }

        fn from_map(map: &common::TestVectorMap) -> Self {
            let pedersen = pedersen::testing::TestVector::from_map(map);

            let ring_pks = map.get::<[AffinePoint<S>; TEST_RING_SIZE]>("ring_pks");
            let ring_pks_com = map.get::<RingCommitment<S>>("ring_pks_com");
            let ring_proof = map.get::<RingBareProof<S>>("ring_proof");

            Self {
                pedersen,
                ring_pks,
                ring_pks_com,
                ring_proof,
            }
        }

        fn to_map(&self) -> common::TestVectorMap {
            let mut map = self.pedersen.to_map();
            map.set("ring_pks", &self.ring_pks);
            map.set("ring_pks_com", &self.ring_pks_com);
            map.set("ring_proof", &self.ring_proof);
            map
        }

        fn run(&self) {
            self.pedersen.run();

            let input = Input::<S>::from(self.pedersen.base.h);
            let output = Output::from(self.pedersen.base.gamma);
            let secret = Secret::from_scalar(self.pedersen.base.sk);
            let public = secret.public();
            assert_eq!(public.0, self.pedersen.base.pk);

            let params = <S as RingSuiteExt>::params();

            let prover_idx = self.ring_pks.iter().position(|&pk| pk == public.0).unwrap();

            let prover_key = params.prover_key(&self.ring_pks);
            let prover = params.prover(prover_key, prover_idx);

            let verifier_key = params.verifier_key(&self.ring_pks);
            let verifier = params.verifier(verifier_key);

            let proof = secret.prove(input, output, &self.pedersen.base.ad, &prover);

            {
                // Check if Pedersen proof matches
                let mut p = (Vec::new(), Vec::new());
                self.pedersen.proof.serialize_compressed(&mut p.0).unwrap();
                proof.pedersen_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            #[cfg(feature = "test-vectors")]
            {
                // Verify if the ring-proof matches. This check is performed only when
                // deterministic proof generation is required for test vectors.
                let mut p = (Vec::new(), Vec::new());
                self.ring_proof.serialize_compressed(&mut p.0).unwrap();
                proof.ring_proof.serialize_compressed(&mut p.1).unwrap();
                assert_eq!(p.0, p.1);
            }

            assert!(
                Public::verify(input, output, &self.pedersen.base.ad, &proof, &verifier).is_ok()
            );
        }
    }
}
