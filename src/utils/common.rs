use crate::*;
use ark_ec::{
    hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map},
    AffineRepr,
};
use ark_ff::PrimeField;
use digest::{Digest, FixedOutputReset};

#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

// Generic hash wrapper.
pub fn hash<H: Digest>(data: &[u8]) -> digest::Output<H> {
    H::new().chain_update(data).finalize()
}

/// Generic HMAC wrapper.
#[cfg(feature = "rfc-6979")]
fn hmac<H: Digest + digest::core_api::BlockSizeUser>(sk: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Mac, SimpleHmac};
    SimpleHmac::<H>::new_from_slice(sk)
        .expect("HMAC can take key of any size")
        .chain_update(data)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// Try-And-Increment (TAI) method as defined by RFC 9381 section 5.4.1.1.
///
/// Implements ECVRF_encode_to_curve in a simple and generic way that works
/// for any elliptic curve.
///
/// To use this algorithm, hash length MUST be at least equal to the field length.
///
/// The running time of this algorithm depends on input string. For the
/// ciphersuites specified in Section 5.5, this algorithm is expected to
/// find a valid curve point after approximately two attempts on average.
///
/// May systematically fail if `Suite::Hasher` output is not sufficient to
/// construct a point according to the `Suite::Codec` in use.
pub fn hash_to_curve_tai_rfc_9381<S: Suite>(data: &[u8]) -> Option<AffinePoint<S>> {
    use ark_ec::AffineRepr;

    const DOM_SEP_FRONT: u8 = 0x01;
    const DOM_SEP_BACK: u8 = 0x00;

    let mut buf = [S::SUITE_ID, &[DOM_SEP_FRONT], data, &[0x00, DOM_SEP_BACK]].concat();
    let ctr_pos = buf.len() - 2;

    for ctr in 0..=255 {
        buf[ctr_pos] = ctr;
        let hash = hash::<S::Hasher>(&buf);
        if let Ok(pt) = codec::point_decode::<S>(&hash[..]) {
            let pt = pt.clear_cofactor();
            if !pt.is_zero() {
                return Some(pt);
            }
        }
    }
    None
}

/// Elligator2 method as defined by RFC-9380 and further refined in RFC-9381 section 5.4.1.2.
///
/// Implements ECVRF_encode_to_curve using one of the several hash-to-curve options defined
/// in RFC-9380.  The specific choice of the hash-to-curve option (called the Suite ID in RFC-9380)
/// is given by the h2c_suite_ID_string parameter.
///
/// The input `data` is defined to be `salt || alpha` according to the `RFC-9281`.
#[allow(unused)]
pub fn hash_to_curve_ell2_rfc_9380<S: Suite>(
    data: &[u8],
    h2c_suite_id: &[u8],
) -> Option<AffinePoint<S>>
where
    <S as Suite>::Hasher: Default + Clone + FixedOutputReset + 'static,
    CurveConfig<S>: ark_ec::twisted_edwards::TECurveConfig,
    CurveConfig<S>: Elligator2Config,
    Elligator2Map<CurveConfig<S>>:
        ark_ec::hashing::map_to_curve_hasher::MapToCurve<<AffinePoint<S> as AffineRepr>::Group>,
{
    use ark_ec::hashing::{map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
    use ark_ff::field_hashers::DefaultFieldHasher;

    // Domain Separation Tag := "ECVRF_" || h2c_suite_ID_string || suite_string
    let dst: Vec<_> = [b"ECVRF_", h2c_suite_id, S::SUITE_ID].concat();

    MapToCurveBasedHasher::<
        <AffinePoint<S> as AffineRepr>::Group,
        DefaultFieldHasher<<S as Suite>::Hasher, 128>,
        Elligator2Map<CurveConfig<S>>,
    >::new(&dst)
    .and_then(|hasher| hasher.hash(data))
    .ok()
}

/// Challenge generation according to RFC-9381 section 5.4.3.
pub fn challenge_rfc_9381<S: Suite>(pts: &[&AffinePoint<S>], ad: &[u8]) -> ScalarField<S> {
    const DOM_SEP_START: u8 = 0x02;
    const DOM_SEP_END: u8 = 0x00;
    let mut buf = [S::SUITE_ID, &[DOM_SEP_START]].concat();
    pts.iter().for_each(|p| {
        S::Codec::point_encode_into(p, &mut buf);
    });
    buf.extend_from_slice(ad);
    buf.push(DOM_SEP_END);
    let hash = &hash::<S::Hasher>(&buf)[..S::CHALLENGE_LEN];
    ScalarField::<S>::from_be_bytes_mod_order(hash)
}

/// Point to a hash according to RFC-9381 section 5.2.
///
/// According to the RFC, the input point `pt` should be multiplied by the cofactor
/// before being hashed. However, in typical usage, the hashed point is the result
/// of a scalar multiplication on a point produced by the `Suite::data_to_point`
/// (also referred to as the _hash-to-curve_ or _h2c_) algorithm, which is expected
/// to yield a point that already belongs to the prime order subgroup of the curve.
///
/// Therefore, assuming the `data_to_point` function is implemented correctly, the
/// input point `pt` will inherently reside in the prime order subgroup, making the
/// cofactor multiplication unnecessary and redundant in terms of security. The primary
/// purpose of multiplying by the cofactor is as a safeguard against potential issues
/// with an incorrect implementation of `data_to_point`.
///
/// Since multiplying by the cofactor changes the point being hashed, this step is
/// made optional to accommodate scenarios where strict compliance with the RFC's
/// prescribed procedure is not required.
pub fn point_to_hash_rfc_9381<S: Suite>(
    pt: &AffinePoint<S>,
    mul_by_cofactor: bool,
) -> HashOutput<S> {
    use ark_std::borrow::Cow::*;
    const DOM_SEP_START: u8 = 0x03;
    const DOM_SEP_END: u8 = 0x00;
    let mut buf = [S::SUITE_ID, &[DOM_SEP_START]].concat();
    let pt = match mul_by_cofactor {
        false => Borrowed(pt),
        true => Owned(pt.mul_by_cofactor()),
    };
    S::Codec::point_encode_into(&pt, &mut buf);
    buf.push(DOM_SEP_END);
    hash::<S::Hasher>(&buf)
}

/// Nonce generation according to RFC-9381 section 5.4.2.2.
///
/// This procedure is based on section 5.1.6 of RFC 8032: "Edwards-Curve Digital
/// Signature Algorithm (EdDSA)".
///
/// The algorithm generate the nonce value in a deterministic pseudorandom fashion.
///
/// # Panics
///
/// This function panics if `Suite::Hasher` output is less than 64 bytes.
pub fn nonce_rfc_8032<S: Suite>(sk: &ScalarField<S>, input: &AffinePoint<S>) -> ScalarField<S> {
    assert!(
        S::Hasher::output_size() >= 64,
        "Suite::Hasher output is required to be >= 64 bytes"
    );

    let raw = codec::scalar_encode::<S>(sk);
    let sk_hash = &hash::<S::Hasher>(&raw)[32..];

    let raw = codec::point_encode::<S>(input);
    let v = [sk_hash, &raw[..]].concat();
    let h = &hash::<S::Hasher>(&v)[..];

    S::Codec::scalar_decode(h)
}

/// Nonce generation according to RFC 9381 section 5.4.2.1.
///
/// This procedure is based on section 3.2 of RFC 6979: "Deterministic Usage of
/// the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature
/// Algorithm (ECDSA)".
///
/// The algorithm generate the nonce value in a deterministic pseudorandom fashion.
#[cfg(feature = "rfc-6979")]
pub fn nonce_rfc_6979<S: Suite>(sk: &ScalarField<S>, input: &AffinePoint<S>) -> ScalarField<S>
where
    S::Hasher: digest::core_api::BlockSizeUser,
{
    let raw = codec::point_encode::<S>(input);
    let h1 = hash::<S::Hasher>(&raw);

    let v = [1; 32];
    let k = [0; 32];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let x = codec::scalar_encode::<S>(sk);
    let raw = [&v[..], &[0x00], &x[..], &h1[..]].concat();
    let k = hmac::<S::Hasher>(&k, &raw);

    // V = HMAC_K(V)
    let v = hmac::<S::Hasher>(&k, &v);

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let raw = [&v[..], &[0x01], &x[..], &h1[..]].concat();
    let k = hmac::<S::Hasher>(&k, &raw);

    // V = HMAC_K(V)
    let v = hmac::<S::Hasher>(&k, &v);

    // TODO: loop until 1 < k < q
    let v = hmac::<S::Hasher>(&k, &v);

    S::Codec::scalar_decode(&v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use suites::testing::TestSuite;

    #[test]
    fn hash_to_curve_tai_works() {
        let pt = hash_to_curve_tai_rfc_9381::<TestSuite>(b"hello world").unwrap();
        // Check that `pt` is in the prime subgroup
        assert!(pt.is_on_curve());
        assert!(pt.is_in_correct_subgroup_assuming_on_curve())
    }
}
