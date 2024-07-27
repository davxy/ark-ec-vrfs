//! Suite for testing

use crate::testing as common;
use crate::{pedersen::PedersenSuite, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"ark-ec-vrfs-testing";
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_ed25519::EdwardsAffine;
    type Hasher = sha2::Sha256;
    type Codec = codec::ArkworksCodec;

    fn nonce(_sk: &ScalarField, _pt: Input) -> ScalarField {
        common::random_val(None)
    }
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField =
            MontFp!("1181072390894490040170698195029164902368238760122173135634802939739986120753");
        const Y: BaseField = MontFp!(
            "16819438535150625131748701663066892288775529055803151482550035706857354997714"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);
suite_tests!(TestSuite);
