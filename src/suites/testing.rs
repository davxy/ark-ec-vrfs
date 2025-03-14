//! Suite for testing

use crate::{pedersen::PedersenSuite, utils::hash, *};
use ark_ff::MontFp;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TestSuite;

impl Suite for TestSuite {
    const SUITE_ID: &'static [u8] = b"Testing_SHA-256_TAI";
    const CHALLENGE_LEN: usize = 16;

    // TODO: babyjubjub?
    type Affine = ark_ed25519::EdwardsAffine;
    type Hasher = sha2::Sha256;
    type Codec = codec::ArkworksCodec;

    fn nonce(sk: &ScalarField, pt: Input) -> ScalarField
    where
        Self: Suite,
        Self::Codec: codec::Codec<Self>,
    {
        let mut buf = vec![];
        <Self::Codec as codec::Codec<Self>>::scalar_encode_into(sk, &mut buf);
        <Self::Codec as codec::Codec<Self>>::point_encode_into(&pt.0, &mut buf);
        let h = &hash::<Self::Hasher>(&buf)[..];
        <Self::Codec as codec::Codec<Self>>::scalar_decode(h)
    }
}

impl PedersenSuite for TestSuite {
    const BLINDING_BASE: AffinePoint = {
        const X: BaseField = MontFp!(
            "22908039810913044136917741489726647027277366293258891749889809241450460853949"
        );
        const Y: BaseField = MontFp!(
            "49264587079666684025030007335154795146762108024019949463673115011651474636151"
        );
        AffinePoint::new_unchecked(X, Y)
    };
}

suite_types!(TestSuite);

impl crate::testing::SuiteExt for TestSuite {}

#[cfg(test)]
mod tests {
    use super::*;
    ietf_suite_tests!(TestSuite);
    pedersen_suite_tests!(TestSuite);
}
