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
            "20870640245832614559435460659272399530811417054267810733865573336979009868811"
        );
        const Y: BaseField = MontFp!(
            "21341130365651426216304862251442826527876511149341376200039038224911826378113"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);
suite_tests!(TestSuite);
