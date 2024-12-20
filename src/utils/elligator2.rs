//! Elligator2 has been merged into arkworks upstream, still we're waiting
//! for new version on crates.io (v.0.4.3)
//!
//! Relevant PRs:
//! - Elligator2 hash-to-curve for Twisted Edwards curves: https://github.com/arkworks-rs/algebra/pull/659
//! - Elligator2 hash-to-curve for Bandersnatch: https://github.com/arkworks-rs/algebra/pull/758
//!
//! This is mostly a verbatim copy of such PRs contribution.

use ark_ec::{
    hashing::{curve_maps::swu::parity, map_to_curve_hasher::MapToCurve, HashToCurveError},
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
};
use ark_ff::{Field, One, Zero};
use core::marker::PhantomData;

/// Trait defining the necessary parameters for the Elligator2 hash-to-curve method
/// for twisted edwards curves form of:
/// `b * y² = x³ + a * x² + x`
/// from [\[BHKL13\]], according to [\[HSSWW23\]]
///
/// - [\[BHKL13\]] <http://dx.doi.org/10.1145/2508859.2516734>
/// - [\[HSSWW23\]] <https://datatracker.ietf.org/doc/html/rfc9380>
pub trait Elligator2Config: TECurveConfig + MontCurveConfig {
    /// An element of the base field that is not a square root see \[BHKL13, Section 5\].
    /// When `BaseField` is a prime field, [\[HSSWW23\]] mandates that `Z` is the
    /// non-square with lowest absolute value in the `BaseField` when its elements
    /// are represented as [-(q-1)/2, (q-1)/2]
    const Z: Self::BaseField;

    /// This must be equal to 1/(MontCurveConfig::COEFF_B)^2;
    const ONE_OVER_COEFF_B_SQUARE: Self::BaseField;

    /// This must be equal to MontCurveConfig::COEFF_A/MontCurveConfig::COEFF_B;
    const COEFF_A_OVER_COEFF_B: Self::BaseField;
}

/// Represents the Elligator2 hash-to-curve map defined by `P`.
pub struct Elligator2Map<P: TECurveConfig>(PhantomData<fn() -> P>);

impl<P: Elligator2Config> Elligator2Map<P> {
    /// Checks if `P` represents a valid Elligator2 map. Panics otherwise.
    fn check_parameters() -> Result<(), HashToCurveError> {
        // We assume that the Montgomery curve is correct and  as such we do
        // not verify the prerequisite for applicability of Elligator2 map to the TECurveConfing.

        // Verifying that Z is a non-square
        debug_assert!(
            !P::Z.legendre().is_qr(),
            "Z should be a quadratic non-residue for the Elligator2 map"
        );

        debug_assert_eq!(
            P::ONE_OVER_COEFF_B_SQUARE,
            <P as MontCurveConfig>::COEFF_B
                .square()
                .inverse()
                .expect("B coefficient cannot be zero in Montgomery form"),
            "ONE_OVER_COEFF_B_SQUARE is not equal to 1/COEFF_B^2 in Montgomery form"
        );

        debug_assert_eq!(
            P::COEFF_A_OVER_COEFF_B,
            <P as MontCurveConfig>::COEFF_A / <P as MontCurveConfig>::COEFF_B,
            "COEFF_A_OVER_COEFF_B is not equal to COEFF_A/COEFF_B in Montgomery form"
        );
        Ok(())
    }
}

impl<P: Elligator2Config> MapToCurve<Projective<P>> for Elligator2Map<P> {
    fn new() -> Result<Self, ark_ec::hashing::HashToCurveError> {
        Self::check_parameters()?;
        Ok(Elligator2Map(PhantomData))
    }

    fn map_to_curve(
        &self,
        element: <Projective<P> as ark_ec::CurveGroup>::BaseField,
    ) -> Result<<Projective<P> as ark_ec::CurveGroup>::Affine, ark_ec::hashing::HashToCurveError>
    {
        // 1. x1 = -(J / K) * inv0(1 + Z * u^2)
        // 2. If x1 == 0, set x1 = -(J / K)
        // 3. gx1 = x1^3 + (J / K) * x1^2 + x1 / K^2
        // 4. x2 = -x1 - (J / K)
        // 5. gx2 = x2^3 + (J / K) * x2^2 + x2 / K^2
        // 6. If is_square(gx1), set x = x1, y = sqrt(gx1) with sgn0(y) == 1.
        // 7. Else set x = x2, y = sqrt(gx2) with sgn0(y) == 0.
        // 8. s = x * K
        // 9. t = y * K
        // 10. return (s, t)

        // ark a is irtf J
        // ark b is irtf k
        let k = <P as MontCurveConfig>::COEFF_B;
        let j_on_k = P::COEFF_A_OVER_COEFF_B;
        let ksq_inv = P::ONE_OVER_COEFF_B_SQUARE;

        let den_1 = <P::BaseField as One>::one() + P::Z * element.square();

        let x1 = -j_on_k
            / (if den_1.is_zero() {
                <P::BaseField as One>::one()
            } else {
                den_1
            });
        let x1sq = x1.square();
        let x1cb = x1sq * x1;
        let gx1 = x1cb + j_on_k * x1sq + x1 * ksq_inv;

        let x2 = -x1 - j_on_k;
        let x2sq = x2.square();
        let x2cb = x2sq * x2;
        let gx2 = x2cb + j_on_k * x2sq + x2 * ksq_inv;

        let (x, mut y, sgn0) = if gx1.legendre().is_qr() {
            (
                x1,
                gx1.sqrt()
                    .expect("We have checked that gx1 is a quadratic residue. Q.E.D"),
                true,
            )
        } else {
            (
                x2,
                gx2.sqrt()
                    .expect("gx2 is a quadratic residue because gx1 is not. Q.E.D"),
                false,
            )
        };

        if parity(&y) != sgn0 {
            y = -y;
        }

        let s = x * k;
        let t = y * k;

        // `(s, t)` is an affine point on the Montgomery curve.
        // Ideally, the TECurve would come with a mapping to its Montgomery curve,
        // so we could just call that mapping here.
        // This is currently not supported in arkworks, so
        // we just implement the rational map here from [\[HSSWW23\]] Appendix D

        let tv1 = s + <P::BaseField as One>::one();
        let tv2 = tv1 * t;
        let (v, w) = if tv2.is_zero() {
            (<P::BaseField as Zero>::zero(), <P::BaseField as One>::one())
        } else {
            let tv2_inv = tv2
                .inverse()
                .expect("None zero element has inverse. Q.E.D.");
            let v = tv2_inv * tv1 * s;
            let w = tv2_inv * t * (s - <P::BaseField as One>::one());
            (v, w)
        };

        let point_on_curve = Affine::<P>::new_unchecked(v, w);
        debug_assert!(
            point_on_curve.is_on_curve(),
            "Elligator2 mapped to a point off the curve"
        );
        Ok(point_on_curve)
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_local_definitions)]

    use super::*;
    use ark_ec::hashing::{map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
    use ark_ff::{field_hashers::DefaultFieldHasher, Fp64, MontBackend, MontFp};
    use sha2::Sha256;

    #[derive(ark_ff::MontConfig)]
    #[modulus = "101"]
    #[generator = "2"]
    pub struct F101Config;
    pub type F101 = Fp64<MontBackend<F101Config, 1>>;

    #[derive(ark_ff::MontConfig)]
    #[modulus = "11"]
    #[generator = "2"]
    pub struct F11Config;
    pub type F11 = Fp64<MontBackend<F11Config, 1>>;

    struct TestElligator2MapToCurveConfig;

    impl ark_ec::CurveConfig for TestElligator2MapToCurveConfig {
        const COFACTOR: &'static [u64] = &[8];
        const COFACTOR_INV: F11 = MontFp!("7");

        type BaseField = F101;
        type ScalarField = F11;
    }

    /// sage: EnsureValidEdwards(F101,-1,12)
    /// sage: Curve_EdwardsToMontgomery(F101, -1, 12)
    /// (76, 23)
    /// sage: Curve_EdwardsToWeierstrass(F101, -1, 12)
    /// (11, 5)
    /// sage: EllipticCurve(F101,[11,5])
    /// Elliptic Curve defined by y^2 = x^3 + 11*x + 5 over Finite Field of size 101
    /// sage: EW = EllipticCurve(F101,[11,5])
    /// sage: EW.order().factor()
    /// 2^3 * 11
    /// sage: EW = EdwardsCurve(F101,-1,12)
    /// sage: EW.gens()[0] * 8
    /// (5 : 36 : 1)
    /// Point_WeierstrassToEdwards(F101, 11, 5, F101(5), F101(36), a_given=-1, d_given=12)
    /// (23, 24)
    impl TECurveConfig for TestElligator2MapToCurveConfig {
        /// COEFF_A = -1
        const COEFF_A: F101 = MontFp!("-1");

        /// COEFF_D = 12
        const COEFF_D: F101 = MontFp!("12");

        const GENERATOR: Affine<TestElligator2MapToCurveConfig> =
            Affine::<TestElligator2MapToCurveConfig>::new_unchecked(MontFp!("23"), MontFp!("24"));

        type MontCurveConfig = TestElligator2MapToCurveConfig;
    }

    impl MontCurveConfig for TestElligator2MapToCurveConfig {
        /// COEFF_A = 76
        const COEFF_A: F101 = MontFp!("76");

        /// COEFF_B = 23
        const COEFF_B: F101 = MontFp!("23");

        type TECurveConfig = TestElligator2MapToCurveConfig;
    }

    /// sage: find_z_ell2(F101)
    /// 2
    /// sage: F101 = FiniteField(101)
    /// sage: 1/F101("23")^2
    /// 80
    /// sage: F101("76")/F101("23")
    /// 56
    impl Elligator2Config for TestElligator2MapToCurveConfig {
        const Z: F101 = MontFp!("2");
        const ONE_OVER_COEFF_B_SQUARE: F101 = MontFp!("80");

        const COEFF_A_OVER_COEFF_B: F101 = MontFp!("56");
    }

    #[test]
    fn elligator2_works() {
        let hasher = MapToCurveBasedHasher::<
            Projective<TestElligator2MapToCurveConfig>,
            DefaultFieldHasher<Sha256, 128>,
            Elligator2Map<TestElligator2MapToCurveConfig>,
        >::new(b"domain")
        .unwrap();

        let point = hasher
            .hash(b"foo")
            .expect("fail to hash the string to curve");
        assert!(point.is_on_curve(),);
    }
}
