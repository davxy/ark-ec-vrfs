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
            "56166678312616788007069565072535608368274441012407488217322349490274061293828"
        );
        const Y: BaseField = MontFp!(
            "55452291704810100370049689540036330133850202475722787526070685722371210180696"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);
suite_tests!(TestSuite);
