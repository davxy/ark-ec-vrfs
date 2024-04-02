macro_rules! suite_types {
    ($suite:ident) => {
        pub type Secret = crate::Secret<$suite>;
        pub type Public = crate::Public<$suite>;
        pub type Input = crate::Input<$suite>;
        pub type Output = crate::Output<$suite>;
        pub type AffinePoint = crate::AffinePoint<$suite>;
        pub type ScalarField = crate::ScalarField<$suite>;
    };
}

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use crate::*;

    /// ECVRF-EDWARDS25519-SHA512-TAI
    #[derive(Copy, Clone)]
    pub struct Ed25519Sha512;

    suite_types!(Ed25519Sha512);

    impl Suite for Ed25519Sha512 {
        const SUITE_ID: u8 = 0x04;
        const CHALLENGE_LEN: usize = 16;

        type Affine = ark_ed25519::EdwardsAffine;
        type Hash = [u8; 64];

        fn hash(data: &[u8]) -> Self::Hash {
            utils::sha512(data)
        }
    }
}

#[cfg(feature = "bandersnatch")]
pub mod bandersnatch {
    use crate::*;

    /// ECVRF-BANDESNATCH-BLAKE2-TAI
    #[derive(Copy, Clone)]
    pub struct BandersnatchBlake2;

    suite_types!(BandersnatchBlake2);

    impl Suite for BandersnatchBlake2 {
        const SUITE_ID: u8 = 0x10;
        const CHALLENGE_LEN: usize = 32;

        type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
        type Hash = [u8; 64];

        fn hash(data: &[u8]) -> Self::Hash {
            utils::blake2(data)
        }
    }
}
