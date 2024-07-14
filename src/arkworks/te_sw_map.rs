use crate::*;
use ark_ec::{
    short_weierstrass::{Affine as WeierstrassAffine, SWCurveConfig},
    twisted_edwards::{Affine as EdwardsAffine, MontCurveConfig, TECurveConfig},
    CurveConfig,
};
use ark_ff::{Field, One};
use ark_std::borrow::Cow;

// Constants used in mapping TE form to SW form and vice versa
pub trait MapConfig: TECurveConfig + SWCurveConfig + MontCurveConfig {
    const MONT_A_OVER_THREE: <Self as CurveConfig>::BaseField;
    const MONT_B_INV: <Self as CurveConfig>::BaseField;
}

pub fn map_sw_to_te<C: MapConfig>(point: &WeierstrassAffine<C>) -> Option<EdwardsAffine<C>> {
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

    Some(EdwardsAffine::new_unchecked(v, w))
}

pub fn map_te_to_sw<C: MapConfig>(point: &EdwardsAffine<C>) -> Option<WeierstrassAffine<C>> {
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

    Some(WeierstrassAffine::new_unchecked(x, y))
}

pub trait SWMapping<C: SWCurveConfig> {
    fn from_sw(sw: WeierstrassAffine<C>) -> Self;

    fn into_sw(self) -> WeierstrassAffine<C>;

    fn to_sw_slice(slice: &[Self]) -> Cow<[WeierstrassAffine<C>]>
    where
        Self: Sized;
}

impl<C: SWCurveConfig> SWMapping<C> for WeierstrassAffine<C> {
    #[inline(always)]
    fn from_sw(sw: WeierstrassAffine<C>) -> Self {
        sw
    }

    #[inline(always)]
    fn into_sw(self) -> WeierstrassAffine<C> {
        self
    }

    #[inline(always)]
    fn to_sw_slice(slice: &[Self]) -> Cow<[WeierstrassAffine<C>]> {
        Cow::Borrowed(slice)
    }
}

impl<C: MapConfig> SWMapping<C> for EdwardsAffine<C> {
    #[inline(always)]
    fn from_sw(sw: WeierstrassAffine<C>) -> Self {
        const ERR_MSG: &str =
            "SW to TE is expected to be implemented only for curves supporting the mapping";
        map_sw_to_te(&sw).expect(ERR_MSG)
    }

    #[inline(always)]
    fn into_sw(self) -> WeierstrassAffine<C> {
        const ERR_MSG: &str =
            "TE to SW is expected to be implemented only for curves supporting the mapping";
        map_te_to_sw(&self).expect(ERR_MSG)
    }

    #[inline(always)]
    fn to_sw_slice(slice: &[Self]) -> Cow<[WeierstrassAffine<C>]> {
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
