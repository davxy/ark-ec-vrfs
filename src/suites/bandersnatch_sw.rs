//! `ECVRF Bandersnatch SHA-512 Try and Increment` suite.
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_SW_SHA-512_TAI" for Short Weierstrass form.
//!
//! - The EC group <G> is the prime subgroup of the Bandersnatch elliptic curve,
//!   in Twisted Edwards form, with finite field and curve parameters as specified in
//!   [MSZ21](https://eprint.iacr.org/2021/1152).
//!   For this group, `fLen` = `qLen` = $32$ and `cofactor` = $4$.
//!
//! - The prime subgroup generator G in <G> is defined as follows:
//!   - G.x = 0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18
//!   - G.y = 0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166
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
//! * The `ECVRF_encode_to_curve` function uses *Try and Increment* method described in
//!   described in section 5.4.1.1 of [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//!   with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_TAI_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use crate::{pedersen::PedersenSuite, utils::te_sw_map::*, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Tai;

impl Suite for BandersnatchSha512Tai {
    const SUITE_ID: &'static [u8] = b"Bandersnatch_SW_SHA-512_TAI";
    const CHALLENGE_LEN: usize = 32;

    type Affine = ark_ed_on_bls12_381_bandersnatch::SWAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;
}

impl PedersenSuite for BandersnatchSha512Tai {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "43295201540795761503961631609120105078472641399392666499799525033203881929458"
        );
        const Y: BaseField = MontFp!(
            "47295792057744344182638225978402781315571475472700428341116949953237551542374"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(BandersnatchSha512Tai);

#[cfg(test)]
suite_tests!(BandersnatchSha512Tai);

#[cfg(feature = "ring")]
pub mod ring {
    use super::*;
    use crate::ring as ring_suite;

    impl ring_suite::RingSuite for BandersnatchSha512Tai {
        type Pairing = ark_bls12_381::Bls12_381;

        const ACCUMULATOR_BASE: AffinePoint = {
            const X: BaseField = MontFp!(
                "30949898125816428869319264729524491191916564825332948285337036537112581509345"
            );
            const Y: BaseField = MontFp!(
                "24710605179423906477527954697856492949547783869349655956135737181575131626699"
            );
            AffinePoint::new_unchecked(X, Y)
        };

        const PADDING: AffinePoint = {
            const X: BaseField = MontFp!(
                "8207061359626985806593416771596963300097557497392401672976542127083785954233"
            );
            const Y: BaseField = MontFp!(
                "45333580719994708944464512022272093444100012168218634411811045976720128467452"
            );
            AffinePoint::new_unchecked(X, Y)
        };
    }

    ring_suite_types!(BandersnatchSha512Tai);

    #[cfg(test)]
    ring_suite_tests!(BandersnatchSha512Tai);
}
#[cfg(feature = "ring")]
pub use ring::*;

// sage: q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
// sage: Fq = GF(q)
// sage: MONT_A = 29978822694968839326280996386011761570173833766074948509196803838190355340952
// sage: MONT_B = 25465760566081946422412445027709227188579564747101592991722834452325077642517
// sage: MONT_A/Fq(3) = 9992940898322946442093665462003920523391277922024982836398934612730118446984
// sage: Fq(1)/MONT_B = 41180284393978236561320365279764246793818536543197771097409483252169927600582
impl MapConfig for ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig {
    const MONT_A_OVER_THREE: ark_ed_on_bls12_381_bandersnatch::Fq =
        MontFp!("9992940898322946442093665462003920523391277922024982836398934612730118446984");
    const MONT_B_INV: ark_ed_on_bls12_381_bandersnatch::Fq =
        MontFp!("41180284393978236561320365279764246793818536543197771097409483252169927600582");
}

#[cfg(test)]
mod tests {
    use crate::{testing, utils::*};
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, SWAffine};

    #[test]
    fn sw_to_te_roundtrip() {
        let org_point = testing::random_val::<SWAffine>(None);

        let te_point = sw_to_te::<BandersnatchConfig>(&org_point).unwrap();
        assert!(te_point.is_on_curve());

        let sw_point = te_to_sw::<BandersnatchConfig>(&te_point).unwrap();
        assert!(sw_point.is_on_curve());

        assert_eq!(org_point, sw_point);
    }
}

#[cfg(test)]
mod test_vectors_ietf {
    use super::*;
    use crate::testing;

    type V = crate::ietf::testing::TestVector<BandersnatchSha512Tai>;
    const VECTOR_ID: &str = "bandersnatch_sw_sha512_tai_ietf";

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

#[cfg(test)]
mod test_vectors_pedersen {
    use super::*;
    use crate::testing;

    type V = crate::pedersen::testing::TestVector<BandersnatchSha512Tai>;
    const VECTOR_ID: &str = "bandersnatch_sw_sha512_tai_pedersen";

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

#[cfg(all(test, feature = "ring"))]
mod test_vectors_ring {
    use super::*;
    use crate::testing;

    type V = crate::ring::testing::TestVector<BandersnatchSha512Tai>;
    const VECTOR_ID: &str = "bandersnatch_sw_sha512_tai_ring";

    impl crate::ring::testing::RingSuiteExt for BandersnatchSha512Tai {
        fn ring_context() -> &'static RingContext {
            use ark_serialize::CanonicalDeserialize;
            use std::sync::OnceLock;
            static RING_CTX: OnceLock<RingContext> = OnceLock::new();
            RING_CTX.get_or_init(|| {
                use std::{fs::File, io::Read};
                let mut file = File::open(crate::testing::PCS_SRS_FILE).unwrap();
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).unwrap();
                let pcs_params =
                    PcsParams::deserialize_uncompressed_unchecked(&mut &buf[..]).unwrap();
                RingContext::from_srs(crate::ring::testing::TEST_RING_SIZE, pcs_params).unwrap()
            })
        }
    }

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

#[test]
fn generator_te_sw_roundtrip() {
    use crate::utils::*;
    let sw1 = AffinePoint::generator();
    let ed1 = sw_to_te(&sw1).unwrap();
    let ed2 = crate::suites::bandersnatch::AffinePoint::generator();
    assert_eq!(ed1, ed2);
    let sw2 = te_to_sw(&ed1).unwrap();
    assert_eq!(sw1, sw2);
}
