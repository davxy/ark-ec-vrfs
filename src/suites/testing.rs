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
        const X: BaseField = MontFp!(
            "23381754219870345211944997019363192944850301843518160357628887563875244468334"
        );
        const Y: BaseField =
            MontFp!("488126047763725246325466163962855932252814319441050605319013534086514946237");
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);
suite_tests!(TestSuite);
