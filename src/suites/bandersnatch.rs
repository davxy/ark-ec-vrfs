//! `ECVRF Bandersnatch SHA-512 Elligator2` suite.
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_SHA-512_ELL2" for Twisted Edwards form.
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
//! * The `ECVRF_encode_to_curve` function uses *Elligator2* method described in
//!   section 6.8.2 of [RFC-9380](https://datatracker.ietf.org/doc/rfc9380) and is
//!   described in section 5.4.1.2 of [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//!   with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_ELL2_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BandersnatchSha512Ell2;

impl Suite for BandersnatchSha512Ell2 {
    const SUITE_ID: &'static [u8] = b"Bandersnatch_SHA-512_ELL2";
    const CHALLENGE_LEN: usize = 32;

    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Hasher = sha2::Sha512;
    type Codec = codec::ArkworksCodec;

    /// Hash data to a curve point using Elligator2 method described by RFC 9380.
    fn data_to_point(data: &[u8]) -> Option<AffinePoint> {
        // "XMD" for expand_message_xmd (Section 5.3.1).
        // "RO" for random oracle (Section 3 - hash_to_curve method)
        let h2c_suite_id = b"Bandersnatch_XMD:SHA-512_ELL2_RO_";
        utils::hash_to_curve_ell2_rfc_9380::<Self>(data, h2c_suite_id)
    }
}

impl PedersenSuite for BandersnatchSha512Ell2 {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("6150229251051246713677296363717454238956877613358614224171740096471278798312");
        const Y: BaseField = MontFp!(
            "28442734166467795856797249030329035618871580593056783094884474814923353898473"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(BandersnatchSha512Ell2);

#[cfg(test)]
suite_tests!(BandersnatchSha512Ell2);

#[cfg(test)]
fn check_point(p: AffinePoint) {
    assert!(p.is_on_curve());
    assert!(p.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn elligator2_hash_to_curve() {
    let p = BandersnatchSha512Ell2::data_to_point(b"foo").unwrap();
    check_point(p);
}

#[cfg(feature = "ring")]
pub mod ring {
    use super::*;
    use crate::ring as ring_suite;

    impl ring_suite::RingSuite for BandersnatchSha512Ell2 {
        type Pairing = ark_bls12_381::Bls12_381;

        const ACCUMULATOR_BASE: AffinePoint = {
            const X: BaseField = MontFp!(
                "37805570861274048643170021838972902516980894313648523898085159469000338764576"
            );
            const Y: BaseField = MontFp!(
                "14738305321141000190236674389841754997202271418876976886494444739226156422510"
            );
            AffinePoint::new_unchecked(X, Y)
        };

        const PADDING: AffinePoint = {
            const X: BaseField = MontFp!(
                "26287722405578650394504321825321286533153045350760430979437739593351290020913"
            );
            const Y: BaseField = MontFp!(
                "19058981610000167534379068105702216971787064146691007947119244515951752366738"
            );
            AffinePoint::new_unchecked(X, Y)
        };
    }

    ring_suite_types!(BandersnatchSha512Ell2);

    #[cfg(test)]
    ring_suite_tests!(BandersnatchSha512Ell2);

    #[test]
    fn check_assumptions() {
        use crate::ring::RingSuite;
        check_point(BandersnatchSha512Ell2::BLINDING_BASE);
        check_point(BandersnatchSha512Ell2::ACCUMULATOR_BASE);
        check_point(BandersnatchSha512Ell2::PADDING);
    }
}
#[cfg(feature = "ring")]
pub use ring::*;

#[cfg(test)]
mod test_vectors_ietf {
    use super::*;
    use crate::testing;

    type V = crate::ietf::testing::TestVector<BandersnatchSha512Ell2>;
    const VECTOR_ID: &str = "bandersnatch_sha512_ell2_ietf";

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

    type V = crate::pedersen::testing::TestVector<BandersnatchSha512Ell2>;
    const VECTOR_ID: &str = "bandersnatch_sha512_ell2_pedersen";

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

    type V = crate::ring::testing::TestVector<BandersnatchSha512Ell2>;
    const VECTOR_ID: &str = "bandersnatch_sha512_ell2_ring";

    impl crate::ring::testing::RingSuiteExt for BandersnatchSha512Ell2 {
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
