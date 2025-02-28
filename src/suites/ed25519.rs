//! `ECVRF-EDWARDS25519-SHA-512-TAI` suite.
//!
//! Configuration (RFC-9381 with some compromises):
//!
//! *  suite_string = b"ed25519-sha512-tai"
//!    We slightly deviate from the suite described in RFC-9381, thus
//!    we prefer to not use suite id `[0x03]`.
//!
//! *  The EC group G is the edwards25519 elliptic curve, with the finite
//!    field and curve parameters as defined in Table 1 in Section 5.1 of
//!    `[RFC8032]`.  For this group, fLen = qLen = 32 and cofactor = 8.
//!
//! *  cLen = 16.
//!
//! *  The secret key and generation of the secret scalar and the public
//!    key are specified in Section 5.1.5 of `[RFC8032]`.
//!
//! *  The ECVRF_nonce_generation function is as specified in
//!    Section 5.4.2.2.
//!
//! *  The int_to_string function is implemented as specified in the
//!    first paragraph of Section 5.1.2 of `[RFC8032]`.  (This is little-
//!    endian representation.)
//!
//! *  The string_to_int function interprets the string as an integer in
//!    little-endian representation.
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string according to the encoding specified in Section 5.1.2 of
//!    `[RFC8032]`.  This implies that ptLen = fLen = 32.  (Note that
//!    certain software implementations do not introduce a separate
//!    elliptic curve point type and instead directly treat the EC point
//!    as an octet string per the above encoding.  When using such an
//!    implementation, the point_to_string function can be treated as the
//!    identity function.)
//!
//! *  The string_to_point function converts an octet string to a point
//!    on E according to the encoding specified in Section 5.1.3 of
//!    `[RFC8032]`.  This function MUST output "INVALID" if the octet
//!    string does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-512 as specified in `[RFC6234]`, with
//!    `hLen = 64`.
//!
//! *  The ECVRF_encode_to_curve function is as specified in
//!    Section 5.4.1.1, with `interpret_hash_value_as_a_point(s) =
//!    string_to_point(s[0]...s[31])`.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

/// Ed25519_SHA-512_TAI Suite.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Ed25519Sha512Tai;

type ThisSuite = Ed25519Sha512Tai;

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"Ed25519_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed25519::EdwardsAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "52417091031015867055192825304177001039906336859819158874861527659737645967040"
        );
        const Y: BaseField = MontFp!(
            "24364467899048426341436922427697710961180476432856951893648702734568269272170"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(ThisSuite);

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {}

    ietf_suite_tests!(ThisSuite);
    pedersen_suite_tests!(ThisSuite);
}
