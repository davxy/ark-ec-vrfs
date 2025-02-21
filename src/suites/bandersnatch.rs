//! `ECVRF Bandersnatch SHA-512 Elligator2` suite.
//!
//! Configuration:
//!
//! * `suite_string` = b"Bandersnatch_SHA-512_ELL2" for Twisted Edwards form.
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
//! * The `ECVRF_encode_to_curve` function uses *Elligator2* method described in
//!   section 6.8.2 of [RFC-9380](https://datatracker.ietf.org/doc/rfc9380) and is
//!   described in section 5.4.1.2 of [RFC-9381](https://datatracker.ietf.org/doc/rfc9381),
//!   with `h2c_suite_ID_string` = `"Bandersnatch_XMD:SHA-512_ELL2_RO_"`
//!   and domain separation tag `DST = "ECVRF_" || h2c_suite_ID_string || suite_string`.

use crate::{pedersen::PedersenSuite, utils::te_sw_map::*, *};
use ark_ff::MontFp;

pub mod weierstrass {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    pub struct BandersnatchSha512Tai;

    suite_types!(BandersnatchSha512Tai);

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
                "2786133011787754314337355768726781346657410178846871760484458839259174143819"
            );
            const Y: BaseField = MontFp!(
                "45091380107337827264009149842055668325926237630986280293235738371137471984708"
            );
            AffinePoint::new_unchecked(X, Y)
        };
    }

    #[cfg(feature = "ring")]
    mod ring_defs {
        use super::*;
        use crate::ring as ring_suite;

        pub type PcsParams = ring_suite::PcsParams<BandersnatchSha512Tai>;
        pub type RingContext = ring_suite::RingContext<BandersnatchSha512Tai>;
        pub type RingCommitment = ring_suite::RingCommitment<BandersnatchSha512Tai>;
        pub type VerifierKey = ring_suite::VerifierKey<BandersnatchSha512Tai>;
        pub type RingProver = ring_suite::RingProver<BandersnatchSha512Tai>;
        pub type RingVerifier = ring_suite::RingVerifier<BandersnatchSha512Tai>;
        pub type Proof = ring_suite::Proof<BandersnatchSha512Tai>;

        impl ring_suite::RingSuite for BandersnatchSha512Tai {
            type Pairing = ark_bls12_381::Bls12_381;

            const ACCUMULATOR_BASE: AffinePoint = {
                const X: BaseField = MontFp!(
                    "48254995375637847364575048247607461744443247628042484657436772027212435529113"
                );
                const Y: BaseField = MontFp!(
                    "3224576081978774412520073113719553166447520787618456623424200075705218636234"
                );
                AffinePoint::new_unchecked(X, Y)
            };

            const PADDING: AffinePoint = {
                const X: weierstrass::BaseField = MontFp!(
                    "35708930000861830245548017565786725469855815091650767855130736125157313721963"
                );
                const Y: weierstrass::BaseField = MontFp!(
                    "6338347876957125643073931899147877399239458581517971209321056997700389681947"
                );
                AffinePoint::new_unchecked(X, Y)
            };
        }
    }
    #[cfg(feature = "ring")]
    pub use ring_defs::*;

    #[cfg(all(test, feature = "ring"))]
    ring_suite_tests!(BandersnatchSha512Tai);

    #[cfg(test)]
    suite_tests!(BandersnatchSha512Tai);
}

pub mod edwards {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    pub struct BandersnatchSha512Ell2;

    suite_types!(BandersnatchSha512Ell2);

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
            const X: BaseField = MontFp!(
                "18052262123084741752455948684150064373355593391329117224969085991125280703899"
            );
            const Y: BaseField = MontFp!(
                "18784055160076939116080959996226112562356442880134706822948812359863029976827"
            );
            AffinePoint::new_unchecked(X, Y)
        };
    }

    #[cfg(feature = "ring")]
    mod ring_defs {
        use super::*;
        use crate::ring as ring_suite;

        pub type PcsParams = ring_suite::PcsParams<BandersnatchSha512Ell2>;
        pub type RingContext = ring_suite::RingContext<BandersnatchSha512Ell2>;
        pub type RingCommitment = ring_suite::RingCommitment<BandersnatchSha512Ell2>;
        pub type VerifierKey = ring_suite::VerifierKey<BandersnatchSha512Ell2>;
        pub type RingProver = ring_suite::RingProver<BandersnatchSha512Ell2>;
        pub type RingVerifier = ring_suite::RingVerifier<BandersnatchSha512Ell2>;
        pub type Proof = ring_suite::Proof<BandersnatchSha512Ell2>;

        impl ring_suite::RingSuite for BandersnatchSha512Ell2 {
            type Pairing = ark_bls12_381::Bls12_381;

            const ACCUMULATOR_BASE: AffinePoint = {
                const X: BaseField = MontFp!(
                    "33870485529716508774519539584554309058480326151538172489903869946516174753586"
                );
                const Y: BaseField = MontFp!(
                    "22934609319023779541266115294616310383924028855106103977339848105082549291539"
                );
                AffinePoint::new_unchecked(X, Y)
            };

            const PADDING: AffinePoint = {
                const X: edwards::BaseField = MontFp!(
                    "28750114660840472435108695402615748045574467283805097196439027458114890954346"
                );
                const Y: edwards::BaseField = MontFp!(
                    "28681665303008045500432480596307870740664482088334198476809598411704602209439"
                );
                AffinePoint::new_unchecked(X, Y)
            };
        }

        #[test]
        fn check_assumptions() {
            use crate::ring::RingSuite;
            check_point(BandersnatchSha512Ell2::BLINDING_BASE);
            check_point(BandersnatchSha512Ell2::ACCUMULATOR_BASE);
            check_point(BandersnatchSha512Ell2::PADDING);
        }
    }
    #[cfg(feature = "ring")]
    pub use ring_defs::*;

    #[cfg(all(test, feature = "ring"))]
    ring_suite_tests!(BandersnatchSha512Ell2);

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
}

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
mod test_vectors_ietf_ed {
    use super::edwards::*;
    use crate::testing;

    type V = crate::ietf::testing::TestVector<BandersnatchSha512Ell2>;
    const VECTOR_ID: &str = "bandersnatch_ed_sha512_ell2_ietf";

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
mod test_vectors_pedersen_ed {
    use super::edwards::*;
    use crate::testing;

    type V = crate::pedersen::testing::TestVector<BandersnatchSha512Ell2>;
    const VECTOR_ID: &str = "bandersnatch_ed_sha512_ell2_pedersen";

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
mod test_vectors_ring_ed {
    use super::edwards::*;
    use crate::testing;

    type V = crate::ring::testing::TestVector<BandersnatchSha512Ell2>;
    const VECTOR_ID: &str = "bandersnatch_ed_sha512_ell2_ring";

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

#[cfg(test)]
mod test_vectors_ietf_sw {
    use super::weierstrass::*;
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
mod test_vectors_pedersen_sw {
    use super::weierstrass::*;
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
mod test_vectors_ring_sw {
    use super::weierstrass::*;
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
    let sw1 = weierstrass::AffinePoint::generator();
    let ed1 = sw_to_te(&sw1).unwrap();
    let ed2 = edwards::AffinePoint::generator();
    assert_eq!(ed1, ed2);
    let sw2 = te_to_sw(&ed1).unwrap();
    assert_eq!(sw1, sw2);
}
