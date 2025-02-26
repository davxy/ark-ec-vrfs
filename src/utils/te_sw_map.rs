use ark_ec::{
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, MontCurveConfig, TECurveConfig},
    CurveConfig,
};
use ark_ff::{Field, One};
use ark_std::borrow::Cow;

// Constants used in mapping TE form to SW form and vice versa
pub trait MapConfig: TECurveConfig + SWCurveConfig + MontCurveConfig {
    const MONT_A_OVER_THREE: <Self as CurveConfig>::BaseField;
    const MONT_B_INV: <Self as CurveConfig>::BaseField;
}

/// Map a a point in Short Weierstrass form into its corresponding point in Twisted Edwards form.
pub fn sw_to_te<C: MapConfig>(point: &SWAffine<C>) -> Option<TEAffine<C>> {
    // First map the point from SW to Montgomery
    // (Bx - A/3, By)
    let mx = <C as MontCurveConfig>::COEFF_B * point.x - C::MONT_A_OVER_THREE;
    let my = <C as MontCurveConfig>::COEFF_B * point.y;

    // Then we map the TE point to Montgamory
    // (x,y) -> (x/y,(x−1)/(x+1))
    let v_denom = my.inverse()?;
    let x_p_1 = mx + <<C as CurveConfig>::BaseField as One>::one();
    let w_denom = x_p_1.inverse()?;
    let v = mx * v_denom;
    let w = (mx - <<C as CurveConfig>::BaseField as One>::one()) * w_denom;

    Some(TEAffine::new_unchecked(v, w))
}

/// Map a a point in Twisted Edwards form into its corresponding point in Short Weierstrass form.
pub fn te_to_sw<C: MapConfig>(point: &TEAffine<C>) -> Option<SWAffine<C>> {
    // Map from TE to Montgomery: (1+y)/(1-y), (1+y)/(x(1-y))
    let v_denom = <<C as CurveConfig>::BaseField as One>::one() - point.y;
    let w_denom = point.x - point.x * point.y;
    let v_denom_inv = v_denom.inverse()?;
    let w_denom_inv = w_denom.inverse()?;
    let v_w_num = <<C as CurveConfig>::BaseField as One>::one() + point.y;
    let v = v_w_num * v_denom_inv;
    let w = v_w_num * w_denom_inv;

    // Map Montgamory to SW: ((x+A/3)/B,y/B)
    let x = C::MONT_B_INV * (v + C::MONT_A_OVER_THREE);
    let y = C::MONT_B_INV * w;

    Some(SWAffine::new_unchecked(x, y))
}

pub trait SWMapping<C: SWCurveConfig> {
    fn from_sw(sw: SWAffine<C>) -> Self;

    fn into_sw(self) -> SWAffine<C>;

    fn to_sw_slice(slice: &[Self]) -> Cow<[SWAffine<C>]>
    where
        Self: Sized;
}

impl<C: SWCurveConfig> SWMapping<C> for SWAffine<C> {
    #[inline(always)]
    fn from_sw(sw: SWAffine<C>) -> Self {
        sw
    }

    #[inline(always)]
    fn into_sw(self) -> SWAffine<C> {
        self
    }

    #[inline(always)]
    fn to_sw_slice(slice: &[Self]) -> Cow<[SWAffine<C>]> {
        Cow::Borrowed(slice)
    }
}

impl<C: MapConfig> SWMapping<C> for TEAffine<C> {
    #[inline(always)]
    fn from_sw(sw: SWAffine<C>) -> Self {
        sw_to_te(&sw).unwrap_or_default()
    }

    #[inline(always)]
    fn into_sw(self) -> SWAffine<C> {
        te_to_sw(&self).unwrap_or_default()
    }

    #[inline(always)]
    fn to_sw_slice(slice: &[Self]) -> Cow<[SWAffine<C>]> {
        let pks;
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            pks = slice.par_iter().map(|p| p.into_sw()).collect();
        }
        #[cfg(not(feature = "parallel"))]
        {
            pks = slice.iter().map(|p| p.into_sw()).collect();
        }
        Cow::Owned(pks)
    }
}

pub trait TEMapping<C: TECurveConfig> {
    fn from_te(te: TEAffine<C>) -> Self;

    fn into_te(self) -> TEAffine<C>;

    fn to_te_slice(slice: &[Self]) -> Cow<[TEAffine<C>]>
    where
        Self: Sized;
}

impl<C: TECurveConfig> TEMapping<C> for TEAffine<C> {
    #[inline(always)]
    fn from_te(te: TEAffine<C>) -> Self {
        te
    }

    #[inline(always)]
    fn into_te(self) -> TEAffine<C> {
        self
    }

    #[inline(always)]
    fn to_te_slice(slice: &[Self]) -> Cow<[TEAffine<C>]> {
        Cow::Borrowed(slice)
    }
}

impl<C: MapConfig> TEMapping<C> for SWAffine<C> {
    #[inline(always)]
    fn from_te(te: TEAffine<C>) -> Self {
        te_to_sw(&te).unwrap_or_default()
    }

    #[inline(always)]
    fn into_te(self) -> TEAffine<C> {
        sw_to_te(&self).unwrap_or_default()
    }

    #[inline(always)]
    fn to_te_slice(slice: &[Self]) -> Cow<[TEAffine<C>]> {
        let pks;
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            pks = slice.par_iter().map(|p| p.into_te()).collect();
        }
        #[cfg(not(feature = "parallel"))]
        {
            pks = slice.iter().map(|p| p.into_te()).collect();
        }
        Cow::Owned(pks)
    }
}
