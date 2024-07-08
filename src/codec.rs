use ark_ec::short_weierstrass::SWCurveConfig;

use super::*;

/// Defines points and scalars encoding format.
pub trait Codec<S: Suite> {
    const BIG_ENDIAN: bool;

    /// Point encode.
    fn point_encode(pt: &AffinePoint<S>, buf: &mut Vec<u8>);

    /// Point decode.
    fn point_decode(buf: &[u8]) -> AffinePoint<S>;

    /// Scalar encode
    fn scalar_encode(sc: &ScalarField<S>, buf: &mut Vec<u8>);

    /// Scalar decode.
    fn scalar_decode(buf: &[u8]) -> ScalarField<S>;
}

/// Arkworks codec.
///
/// Little endian. Points flags in MSB. Compression enabled.
pub struct ArkworksCodec;

impl<S: Suite> Codec<S> for ArkworksCodec {
    const BIG_ENDIAN: bool = false;

    fn point_encode(pt: &AffinePoint<S>, buf: &mut Vec<u8>) {
        pt.serialize_compressed(buf).unwrap();
    }

    fn point_decode(buf: &[u8]) -> AffinePoint<S> {
        AffinePoint::<S>::deserialize_compressed(buf).unwrap()
    }

    fn scalar_encode(sc: &ScalarField<S>, buf: &mut Vec<u8>) {
        sc.serialize_compressed(buf).unwrap();
    }

    fn scalar_decode(buf: &[u8]) -> ScalarField<S> {
        ScalarField::<S>::from_le_bytes_mod_order(buf)
    }
}

/// SEC 1 codec (https://www.secg.org/sec1-v2.pdf)
///
/// Big endian. Points flags in LSB. Compression enabled.
pub struct Sec1Codec;

impl<S: Suite> Codec<S> for Sec1Codec
where
    BaseField<S>: ark_ff::PrimeField,
    CurveConfig<S>: SWCurveConfig,
    AffinePoint<S>: utils::SWMapping<CurveConfig<S>>,
{
    const BIG_ENDIAN: bool = true;

    fn point_encode(pt: &AffinePoint<S>, buf: &mut Vec<u8>) {
        use ark_ff::biginteger::BigInteger;
        use utils::SWMapping;

        if pt.is_zero() {
            buf.push(0x00);
            return;
        }
        let mut tmp = Vec::new();
        let sw = pt.into_sw();

        let is_odd = sw.y.into_bigint().is_odd();
        buf.push(if is_odd { 0x03 } else { 0x02 });

        sw.x.serialize_compressed(&mut tmp).unwrap();
        tmp.reverse();
        buf.extend_from_slice(&tmp[..]);
    }

    fn point_decode(buf: &[u8]) -> AffinePoint<S> {
        use ark_ff::biginteger::BigInteger;
        use utils::SWMapping;
        type SWAffine<C> = ark_ec::short_weierstrass::Affine<C>;
        if buf.len() == 1 && buf[0] == 0x00 {
            return AffinePoint::<S>::zero();
        }
        let mut tmp = buf.to_vec();
        tmp.reverse();
        let y_flag = tmp.pop().unwrap();

        let x = BaseField::<S>::deserialize_compressed(&mut &tmp[..]).unwrap();
        let (y1, y2) = SWAffine::<CurveConfig<S>>::get_ys_from_x_unchecked(x).unwrap();
        let y = if ((y_flag & 0x01) != 0) == y1.into_bigint().is_odd() {
            y1
        } else {
            y2
        };
        let sw = SWAffine::<CurveConfig<S>>::new_unchecked(x, y);
        AffinePoint::<S>::from_sw(sw)
    }

    fn scalar_encode(sc: &ScalarField<S>, buf: &mut Vec<u8>) {
        let mut tmp = Vec::new();
        sc.serialize_compressed(&mut tmp).unwrap();
        tmp.reverse();
        buf.extend_from_slice(&tmp[..]);
    }

    fn scalar_decode(buf: &[u8]) -> ScalarField<S> {
        ScalarField::<S>::from_be_bytes_mod_order(buf)
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{
        suite::{Public, Secret},
        TEST_SEED,
    };
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    #[test]
    fn codec_works() {
        let secret = Secret::from_seed(TEST_SEED);

        let mut buf = Vec::new();
        secret.serialize_compressed(&mut buf).unwrap();
        let secret2 = Secret::deserialize_compressed(&mut &buf[..]).unwrap();
        assert_eq!(secret, secret2);

        let mut buf = Vec::new();
        let public = secret.public();
        public.serialize_compressed(&mut buf).unwrap();
        let public2 = Public::deserialize_compressed(&mut &buf[..]).unwrap();
        assert_eq!(public, public2);
    }
}
