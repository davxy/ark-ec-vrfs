//! `ECVRF-P256-SHA256-TAI` suite.
//!
//! Configuration (RFC-9381):
//!
//! *  `suite_string = [0x01]`.
//!
//! *  The EC group G is the NIST P-256 elliptic curve, with the finite
//!    field and curve parameters as specified in Section 3.2.1.3 of
//!    [SP-800-186](https://csrc.nist.gov/pubs/sp/800/186/final) and
//!    Section 2.6 of [RFC-5114](https://www.rfc-editor.org/rfc/rfc5114).
//!    For this group, `fLen = qLen = 32` and `cofactor = 1`.
//!
//! *  `cLen = 16`.
//!
//! *  The key pair generation primitive is specified in Section 3.2.1 of
//!    [SECG1] (q, B, SK, and Y in this document correspond to n, G, d,
//!    and Q in Section 3.2.1 of [SECG1]).  In this ciphersuite, the
//!    secret scalar x is equal to the secret key SK.
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct P256Sha256Tai;

impl Suite for P256Sha256Tai {
    const SUITE_ID: &'static [u8] = &[0x01];
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_secp256r1::Affine;
    type Hasher = sha2::Sha256;
    type Codec = codec::Sec1Codec;

    fn nonce(sk: &ScalarField, pt: Input) -> ScalarField {
        utils::nonce_rfc_6979::<Self>(sk, &pt.0)
    }

    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        utils::hash_to_curve_tai_rfc_9381::<Self>(data)
    }
}

impl PedersenSuite for P256Sha256Tai {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "55516455597544811540149985232155473070193196202193483189274003004283034832642"
        );
        const Y: BaseField = MontFp!(
            "48580550536742846740990228707183741745344724157532839324866819111997786854582"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(P256Sha256Tai);

#[cfg(test)]
suite_tests!(P256Sha256Tai);

#[cfg(test)]
mod test_vectors_ietf {
    use super::*;

    type V = crate::ietf::testing::TestVector<P256Sha256Tai>;
    const VECTOR_ID: &str = "secp256_sha256_tai_ietf";
    // Vectors from RFC-9381
    const VECTOR_ID_RFC_9381: &str = "secp256_sha256_tai_ietf_rfc_9381";

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(VECTOR_ID);
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(VECTOR_ID);
    }

    #[test]
    fn process_rfc_9381() {
        testing::test_vectors_process::<V>(VECTOR_ID_RFC_9381);
    }
}

#[cfg(test)]
mod test_vectors_pedersen {
    use super::*;

    type V = crate::pedersen::testing::TestVector<P256Sha256Tai>;
    const VECTOR_ID: &str = "secp256r1_sha256_tai_pedersen";

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(VECTOR_ID);
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(VECTOR_ID);
    }
}
