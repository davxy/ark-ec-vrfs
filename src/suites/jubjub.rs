//! `ECVRF JubJub SHA-512 Try and Increment H2C` suite.
//!
//! Configuration:
//!
//! * `suite_string` = b"JubJub_SHA-512_TAI".
//!
//! - The EC group is the prime subgroup of the JubJub elliptic curve
//!   as defined by <https://github.com/zkcrypto/jubjub>.
//!   For this group, `fLen` = `qLen` = $32$ and `cofactor` = $8$.
//!
//! - The prime subgroup generator G is defined as follows:
//!   - G.x = 8076246640662884909881801758704306714034609987455869804520522091855516602923
//!   - G.y = 13262374693698910701929044844600465831413122818447359594527400194675274060458
//!
//! * `cLen` = 32.
//!
//! * The key pair generation primitive is `PK = sk * G`, with x the secret
//!   key scalar and `G` the group generator. In this ciphersuite, the secret
//!   scalar x is equal to the secret key scalar sk.
//!
//! * The ECVRF_nonce_generation function is as specified in Section 5.4.2.2
//!   of RFC-9381.
//!
//! * The int_to_string function encodes into the 32 bytes little endian
//!   representation.
//!
//! * The string_to_int function decodes from the 32 bytes little endian
//!   representation.
//!
//! * The point_to_string function converts a point in <G> to an octet
//!   string using compressed form. The y coordinate is encoded using
//!   int_to_string function and the most significant bit of the last
//!   octet is used to keep track of the x's sign. This implies that
//!   the point is encoded on 32 bytes.
//!
//! * The string_to_point function tries to decompress the point encoded
//!   according to `point_to_string` procedure. This function MUST outputs
//!   "INVALID" if the octet string does not decode to a point on G.
//!
//! * The hash function Hash is SHA-512 as specified in
//!   [RFC6234](https://www.rfc-editor.org/rfc/rfc6234), with hLen = 64.
//!
//! * The `ECVRF_encode_to_curve` function uses try and increment.
//!   as defined by RFC 9381 section 5.4.1.1.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct JubJubSha512Ell2;

type ThisSuite = JubJubSha512Ell2;

suite_types!(ThisSuite);

impl Suite for ThisSuite {
    const SUITE_ID: &'static [u8] = b"JubJub_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 32;

    type Affine = ark_ed_on_bls12_381::EdwardsAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;
}

impl PedersenSuite for ThisSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "42257337814662035284373945156525735092765968053982822992704750832078779438788"
        );
        const Y: BaseField = MontFp!(
            "47476395315228831116309413527962830333178159651930104661512857647213254194102"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
impl crate::ring::RingSuite for ThisSuite {
    type Pairing = ark_bls12_381::Bls12_381;

    const ACCUMULATOR_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "46194868970636137215665291958977045607402791989805288388161474094918623165215"
        );
        const Y: BaseField = MontFp!(
            "25076105280846228970329523770418275693120076470674973696258471026983323652479"
        );
        AffinePoint::new_unchecked(X, Y)
    };

    const PADDING: AffinePoint = {
        const X: BaseField = MontFp!(
            "29457445426702359580423699774559186616331674592397285916231493776142609373871"
        );
        const Y: BaseField = MontFp!(
            "35786798678243451862860591331740861701769099764458806489168460821196579577970"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

#[cfg(feature = "ring")]
ring_suite_types!(ThisSuite);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl crate::testing::SuiteExt for ThisSuite {}

    ietf_suite_tests!(ThisSuite);

    pedersen_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    ring_suite_tests!(ThisSuite);

    #[cfg(feature = "ring")]
    impl crate::ring::testing::RingSuiteExt for ThisSuite {
        const SRS_FILE: &str = crate::testing::BLS12_381_PCS_SRS_FILE;

        fn context() -> &'static RingContext {
            use std::sync::OnceLock;
            static RING_CTX: OnceLock<RingContext> = OnceLock::new();
            RING_CTX.get_or_init(Self::load_context)
        }
    }
}
