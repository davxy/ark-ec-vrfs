#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use crate::*;

    /// ECVRF-EDWARDS25519-SHA512-*
    #[derive(Copy, Clone)]
    pub struct Ed25519Sha512;

    suite_types!(Ed25519Sha512);

    impl Suite for Ed25519Sha512 {
        const SUITE_ID: u8 = 0x03;
        const CHALLENGE_LEN: usize = 16;

        type Affine = ark_ed25519::EdwardsAffine;
        type Hash = [u8; 64];

        fn hash(data: &[u8]) -> Self::Hash {
            utils::sha512(data)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_vector() {
            // Appendix B.3. Example 17
            // Expanded form of: 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
            let sk_bytes =
                hex::decode("c799d106d5927970e5989f5671131fa27e6c6b3b7f821c5e259a24b02e502e01")
                    .unwrap();
            // Here the result is sk % order
            // With order = 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed
            let sk_scalar = ScalarField::from_le_bytes_mod_order(&sk_bytes);
            println!("SK = {}", sk_scalar);
            let sk = Secret::from_scalar(sk_scalar);

            let pk = sk.public();
            assert!(pk.0.is_on_curve());
            assert!(pk.0.is_in_correct_subgroup_assuming_on_curve());

            // The test vector reports PK to be:
            // 0x3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
            // ⚠️ DOESNT MATCH: we set the msb (0x0c -> 0x8c) !!!
            let mut bytes = vec![];
            println!("PK.X = {}", pk.0.x);
            println!("PK.Y = {}", pk.0.y);
            pk.0.serialize_compressed(&mut bytes).unwrap();
            println!("PK ENC: {}", hex::encode(bytes));
        }
    }
}

#[cfg(feature = "bandersnatch")]
pub mod bandersnatch {
    use crate::*;

    /// ECVRF-BANDERSNATCH-BLAKE2-*
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
