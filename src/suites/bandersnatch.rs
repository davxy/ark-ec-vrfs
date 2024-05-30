//! `ECVRF-BANDERSNATCH-BLAKE2-TAI` suite.
//!
//! Configuration:
//!
//! *  `suite_string` = 0x83.
//!
//! *  The EC group G is the Bandersnatch elliptic curve, in Twisted Edwards form,
//!    with the finite field and curve parameters as specified [here](https://neuromancer.sk/std/bls/Bandersnatch)
//!    For this group, `fLen` = `qLen` = 32 and `cofactor` = 4.
//!
//! *  `cLen` = 32.
//!
//! *  The key pair generation primitive is `PK = SK * g`, with SK the secret
//!    key scalar and `g` the group generator. In this ciphersuite, the secret
//!    scalar x is equal to the secret key SK.
//!
//! *  encode_to_curve_salt = PK_string.
//!
//! *  The ECVRF_nonce_generation function is as specified in
//!    Section 5.4.2.1.
//!
//! *  The int_to_string function encodes into the 32 bytes little endian
//!    representation.
//!
//! *  The string_to_int function decodes from the 32 bytes little endian
//!    representation.
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string using compressed form. The Y coordinate is encoded using
//!    int_to_string function and the most significant bit of the last
//!    octet is used to keep track of the X's sign. This implies that
//!    the point is encoded on 32 bytes.
//!
//! *  The string_to_point function tries to decompress the point encoded
//!    according to `point_to_string` procedure. This function MUST outputs
//!    "INVALID" if the octet string does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-512 as specified in
//!    [RFC6234](https://www.rfc-editor.org/rfc/rfc6234), with hLen = 64.
//!
//! *  The ECVRF_encode_to_curve function is as specified in
//!    Section 5.4.1.2, with `h2c_suite_ID_string` = `"BANDERSNATCH_XMD:BLAKE2b_ELL2_RO_"`.
//!    The suite is defined in Section 8.5 of [RFC9380](https://datatracker.ietf.org/doc/rfc9380/).
//!
//! *  The prime subgroup generator is generated following Zcash's fashion:
//     "The generators of G1 and G2 are computed by finding the lexicographically
//      smallest valid x-coordinate, and its lexicographically smallest
//      y-coordinate and scaling it by the cofactor such that the result is not
//      the point at infinity."
//
//     GENERATOR_X = 18886178867200960497001835917649091219057080094937609519140440539760939937304
//     GENERATOR_Y = 19188667384257783945677642223292697773471335439753913231509108946878080696678

use crate::{pedersen::PedersenSuite, utils::ark_next::*, *};
use ark_ff::MontFp;

pub mod weierstrass {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    pub struct BandersnatchSha512;

    suite_types!(BandersnatchSha512);

    impl Suite for BandersnatchSha512 {
        const SUITE_ID: u8 = CUSTOM_SUITE_ID_FLAG | 0x03;
        const CHALLENGE_LEN: usize = 32;

        type Affine = ark_ed_on_bls12_381_bandersnatch::SWAffine;
        type Hasher = sha2::Sha512;
    }

    impl PedersenSuite for BandersnatchSha512 {
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

        pub type RingContext = ring_suite::RingContext<BandersnatchSha512>;
        pub type VerifierKey = ring_suite::VerifierKey<BandersnatchSha512>;
        pub type RingProver = ring_suite::RingProver<BandersnatchSha512>;
        pub type RingVerifier = ring_suite::RingVerifier<BandersnatchSha512>;
        pub type Proof = ring_suite::Proof<BandersnatchSha512>;

        impl ring_suite::RingSuite for BandersnatchSha512 {
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
    suite_tests!(BandersnatchSha512, true);
}

pub mod edwards {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    pub struct BandersnatchSha512Edwards;

    suite_types!(BandersnatchSha512Edwards);

    impl Suite for BandersnatchSha512Edwards {
        const SUITE_ID: u8 = CUSTOM_SUITE_ID_FLAG | 0x04;
        const CHALLENGE_LEN: usize = 32;

        type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
        type Hasher = sha2::Sha512;
    }

    impl PedersenSuite for BandersnatchSha512Edwards {
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

    #[cfg(feature = "ring")]
    mod ring_defs {
        use super::*;
        use crate::ring as ring_suite;

        pub type RingContext = ring_suite::RingContext<BandersnatchSha512Edwards>;
        pub type VerifierKey = ring_suite::VerifierKey<BandersnatchSha512Edwards>;
        pub type RingProver = ring_suite::RingProver<BandersnatchSha512Edwards>;
        pub type RingVerifier = ring_suite::RingVerifier<BandersnatchSha512Edwards>;
        pub type Proof = ring_suite::Proof<BandersnatchSha512Edwards>;

        impl ring_suite::RingSuite for BandersnatchSha512Edwards {
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
    suite_tests!(BandersnatchSha512Edwards, true);
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
    use crate::{testing, utils::ark_next};
    use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, SWAffine};

    #[test]
    fn sw_to_te_roundtrip() {
        let org_point = testing::random_val::<SWAffine>(None);

        let te_point = ark_next::map_sw_to_te::<BandersnatchConfig>(&org_point).unwrap();
        assert!(te_point.is_on_curve());

        let sw_point = ark_next::map_te_to_sw::<BandersnatchConfig>(&te_point).unwrap();
        assert!(sw_point.is_on_curve());
    }
}
