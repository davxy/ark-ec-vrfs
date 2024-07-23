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
//! * encode_to_curve_salt = PS_string (point_to_string(PK)).
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

use crate::{arkworks::te_sw_map::*, pedersen::PedersenSuite, *};
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
                "4956610287995045830459834427365747411162584416641336688940534788579455781570"
            );
            const Y: BaseField = MontFp!(
                "52360910621642801549936840538960627498114783432181489929217988668068368626761"
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

            /// A point on the curve not belonging to the prime order subgroup.
            ///
            /// Found using `ring_proof::find_complement_point::<Self::Config>()` function.
            const COMPLEMENT_POINT: AffinePoint = {
                const X: BaseField = MontFp!("0");
                const Y: BaseField = MontFp!(
                    "11982629110561008531870698410380659621661946968466267969586599013782997959645"
                );
                AffinePoint::new_unchecked(X, Y)
            };
        }
    }
    #[cfg(feature = "ring")]
    pub use ring_defs::*;

    #[cfg(test)]
    suite_tests!(BandersnatchSha512Tai, true);
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
        /// Found mapping the `BLINDING_BASE` of `weierstrass` module using the `utils::map_sw_to_te`
        const BLINDING_BASE: AffinePoint = {
            const X: BaseField = MontFp!(
                "14576224270591906826192118712803723445031237947873156025406837473427562701854"
            );
            const Y: BaseField = MontFp!(
                "38436873314098705092845609371301773715650206984323659492499960072785679638442"
            );
            AffinePoint::new_unchecked(X, Y)
        };
    }

    impl arkworks::elligator2::Elligator2Config
        for ark_ed_on_bls12_381_bandersnatch::BandersnatchConfig
    {
        const Z: ark_ed_on_bls12_381_bandersnatch::Fq = MontFp!("5");

        /// This must be equal to 1/(MontCurveConfig::COEFF_B)^2;
        const ONE_OVER_COEFF_B_SQUARE: ark_ed_on_bls12_381_bandersnatch::Fq = MontFp!(
            "35484827650731063748396669747216844996598387089274032563585525486049249153249"
        );

        /// This must be equal to MontCurveConfig::COEFF_A/MontCurveConfig::COEFF_B;
        const COEFF_A_OVER_COEFF_B: ark_ed_on_bls12_381_bandersnatch::Fq = MontFp!(
            "22511181562295907836254750456843438087744031914659733450388350895537307167857"
        );
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

            /// A point on the curve not belonging to the prime order subgroup.
            ///
            /// Found mapping the `COMPLEMENT_POINT` of `weierstrass` module using the `utils::map_sw_to_te`
            const COMPLEMENT_POINT: AffinePoint = {
                const X: BaseField = MontFp!(
                    "3955725774225903122339172568337849452553276548604445833196164961773358506589"
                );
                const Y: BaseField = MontFp!(
                    "29870564530691725960104983716673293929719207405660860235233811770612192692323"
                );
                AffinePoint::new_unchecked(X, Y)
            };
        }
    }
    #[cfg(feature = "ring")]
    pub use ring_defs::*;

    #[cfg(test)]
    suite_tests!(BandersnatchSha512Ell2, true);

    #[test]
    fn elligator2_hash_to_curve() {
        let point = BandersnatchSha512Ell2::data_to_point(b"foo").unwrap();
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());
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
    use crate::{testing, utils::te_sw_map::*};
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, SWAffine};

    #[test]
    fn sw_to_te_roundtrip() {
        let org_point = testing::random_val::<SWAffine>(None);

        let te_point = map_sw_to_te::<BandersnatchConfig>(&org_point).unwrap();
        assert!(te_point.is_on_curve());

        let sw_point = map_te_to_sw::<BandersnatchConfig>(&te_point).unwrap();
        assert!(sw_point.is_on_curve());
    }
}

#[cfg(test)]
mod test_vectors_ietf_ed {
    use super::edwards::*;
    use crate::testing;

    type V = crate::ietf::testing::TestVector<BandersnatchSha512Ell2>;

    const TEST_VECTORS_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/bandersnatch_ed_sha512_ell2_ietf_vectors.json"
    );

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(TEST_VECTORS_FILE, "Bandersnatch_SHA-512_ELL2");
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE);
    }
}

#[cfg(test)]
mod test_vectors_pedersen_ed {
    use super::edwards::*;
    use crate::testing;

    type V = crate::pedersen::testing::TestVector<BandersnatchSha512Ell2>;

    const TEST_VECTORS_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/bandersnatch_ed_sha512_ell2_pedersen_vectors.json"
    );

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(TEST_VECTORS_FILE, "Bandersnatch_SHA-512_ELL2");
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE);
    }
}

#[cfg(test)]
mod test_vectors_ietf_sw {
    use super::weierstrass::*;
    use crate::testing;

    type V = crate::ietf::testing::TestVector<BandersnatchSha512Tai>;

    const TEST_VECTORS_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/bandersnatch_sw_sha512_tai_ietf_vectors.json"
    );

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(TEST_VECTORS_FILE, "Bandersnatch_SW_SHA-512_TAI");
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE);
    }
}

#[cfg(test)]
mod test_vectors_pedersen_sw {
    use super::weierstrass::*;
    use crate::testing;

    type V = crate::pedersen::testing::TestVector<BandersnatchSha512Tai>;

    const TEST_VECTORS_FILE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/data/bandersnatch_sw_sha512_tai_pedersen_vectors.json"
    );

    #[test]
    #[ignore = "test vectors generator"]
    fn generate() {
        testing::test_vectors_generate::<V>(TEST_VECTORS_FILE, "Bandersnatch_SHA-512_TAI");
    }

    #[test]
    fn process() {
        testing::test_vectors_process::<V>(TEST_VECTORS_FILE);
    }
}
