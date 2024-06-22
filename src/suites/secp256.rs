//! `ECVRF-P256-SHA256-TAI` suite.
//!
//! Configuration (RFC-9381):
//!
//! *  suite_string = 0x01.
//!
//! *  The EC group G is the NIST P-256 elliptic curve, with the finite
//!    field and curve parameters as specified in Section 3.2.1.3 of
//!    [SP-800-186] and Section 2.6 of [RFC5114].  For this group, fLen =
//!    qLen = 32 and cofactor = 1.
//!
//! *  cLen = 16.
//!
//! *  The key pair generation primitive is specified in Section 3.2.1 of
//!    [SECG1] (q, B, SK, and Y in this document correspond to n, G, d,
//!    and Q in Section 3.2.1 of [SECG1]).  In this ciphersuite, the
//!    secret scalar x is equal to the secret key SK.
//!
//! *  encode_to_curve_salt = PK_string.
//!
//! *  The ECVRF_nonce_generation function is as specified in
//!    Section 5.4.2.1.
//!
//! *  The int_to_string function is the I2OSP function specified in
//!    Section 4.1 of [RFC8017].  (This is big-endian representation.)
//!
//! *  The string_to_int function is the OS2IP function specified in
//!    Section 4.2 of [RFC8017].  (This is big-endian representation.)
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string according to the encoding specified in Section 2.3.3 of
//!    [SECG1] with point compression on.  This implies that
//!    ptLen = fLen + 1 = 33.  (Note that certain software implementations do not
//!    introduce a separate elliptic curve point type and instead
//!    directly treat the EC point as an octet string per the above
//!    encoding.  When using such an implementation, the point_to_string
//!    function can be treated as the identity function.)
//!
//! *  The string_to_point function converts an octet string to a point
//!    on E according to the encoding specified in Section 2.3.4 of
//!    [SECG1].  This function MUST output "INVALID" if the octet string
//!    does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-256 as specified in [RFC6234], with
//!    hLen = 32.
//!
//! *  The ECVRF_encode_to_curve function is as specified in
//!    Section 5.4.1.1, with interpret_hash_value_as_a_point(s) =
//!    string_to_point(0x02 || s).

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone)]
pub struct P256Sha256Tai;

suite_types!(P256Sha256Tai);

#[cfg(test)]
suite_tests!(P256Sha256Tai);

impl Suite for P256Sha256Tai {
    const SUITE_ID: &'static [u8] = &[0x01];
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_secp256r1::Affine;
    type Hasher = sha2::Sha256;

    fn nonce(sk: &ScalarField, pt: Input) -> ScalarField {
        utils::nonce_rfc_6979::<Self>(sk, &pt.0)
    }

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data, true)
    }

    /// Encode point according to Section 2.3.3 "SEC 1: Elliptic Curve Cryptography",
    /// (https://www.secg.org/sec1-v2.pdf) with point compression on.
    fn point_encode(pt: &AffinePoint, buf: &mut Vec<u8>) {
        use ark_ff::biginteger::BigInteger;
        let mut tmp = Vec::new();

        if pt.is_zero() {
            buf.push(0x00);
            return;
        }
        let is_odd = pt.y.into_bigint().is_odd();
        buf.push(if is_odd { 0x03 } else { 0x02 });

        pt.x.serialize_compressed(&mut tmp).unwrap();
        tmp.reverse();
        buf.extend_from_slice(&tmp[..]);
    }

    /// Encode point according to Section 2.3.3 "SEC 1: Elliptic Curve Cryptography",
    /// (https://www.secg.org/sec1-v2.pdf) with point compression on.
    fn point_decode(buf: &[u8]) -> AffinePoint {
        use ark_ff::biginteger::BigInteger;
        if buf.len() == 1 && buf[0] == 0x00 {
            return AffinePoint::zero();
        }
        let mut tmp = buf.to_vec();
        tmp.reverse();
        let y_flag = tmp.pop().unwrap();

        let x = BaseField::deserialize_compressed(&mut &tmp[..]).unwrap();
        let (y1, y2) = AffinePoint::get_ys_from_x_unchecked(x).unwrap();
        let y = if ((y_flag & 0x01) != 0) == y1.into_bigint().is_odd() {
            y1
        } else {
            y2
        };
        AffinePoint::new_unchecked(x, y)
    }

    fn scalar_encode(sc: &ScalarField, buf: &mut Vec<u8>) {
        let mut tmp = Vec::new();
        sc.serialize_compressed(&mut tmp).unwrap();
        tmp.reverse();
        buf.extend_from_slice(&tmp[..]);
    }

    fn scalar_decode(buf: &[u8]) -> ScalarField {
        ScalarField::from_be_bytes_mod_order(buf)
    }
}

impl PedersenSuite for P256Sha256Tai {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "14043613715035732602742871684475452461130505690937359323850445130419175222977"
        );
        const Y: BaseField = MontFp!(
            "56943419272466863994763824717057516408187649339843987947344693936486947084336"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(test)]
mod test_vectors_ietf {
    use super::*;

    type V = crate::ietf::testing::TestVector<P256Sha256Tai>;

    const TEST_VECTORS_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/secp256_sha256_tai_ietf_vectors.json"
    );

    // Vectors from RFC-9381
    const TEST_VECTORS_FILE_RFC_9381: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/secp256_sha256_tai_ietf_vectors_rfc_9381.json"
    );

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(TEST_VECTORS_FILE, "secp256r1_SHA-256_TAI");
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE);
    }

    #[test]
    fn process_rfc_9381() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE_RFC_9381);
    }
}

#[cfg(test)]
mod test_vectors_pedersen {
    use super::*;

    type V = crate::pedersen::testing::TestVector<P256Sha256Tai>;

    const TEST_VECTORS_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/secp256r1_sha256_tai_pedersen_vectors.json"
    );

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(TEST_VECTORS_FILE, "secp256r1_SHA-256_TAI");
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE);
    }
}
