#[cfg(feature = "secp256r1")]
pub mod secp256 {
    use crate::{suite_types, *};

    /// ECVRF-P256-SHA256-TAI
    #[derive(Copy, Clone)]
    pub struct P256Sha256Tai;

    suite_types!(P256Sha256Tai);

    impl Suite for P256Sha256Tai {
        const SUITE_ID: u8 = 0x01;
        const CHALLENGE_LEN: usize = 16;

        type Affine = ark_secp256r1::Affine;
        type Hash = [u8; 32];

        fn hash(data: &[u8]) -> Self::Hash {
            utils::sha256(data)
        }
    }
}

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
}

#[cfg(feature = "bandersnatch")]
pub mod bandersnatch {
    /// ECVRF-BANDERSNATCH-BLAKE2-*
    ///
    ///
    use crate::*;

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

#[cfg(test)]
mod tests {
    use crate::utils;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    fn encode_value<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        value.serialize_compressed(&mut buf).unwrap();
        buf.reverse();
        buf
    }

    // RFC9381 - Appendix B.1 - Example 10
    //
    // Partial due to annoying incompatibility of points encoding between Arkworks
    // and [SECG1] section 2.3.3.
    #[test]
    fn secp256_test_vectors_ex10() {
        use crate::suites::secp256::*;

        let mut sk_bytes =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();
        sk_bytes.reverse();
        let sk = Secret::deserialize_compressed(&mut sk_bytes.as_slice()).unwrap();

        // Prepare hash_to_curve data = salt || alpha
        // Salt is defined to be pk (adjust it to make the encoding to match)
        let mut pk_bytes = encode_value(&sk.public);
        assert_eq!(
            "0060fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            hex::encode(&pk_bytes)
        );
        pk_bytes[0] = 0x03;

        let h2c_data = [&pk_bytes[..], b"sample"].concat();
        let h = utils::hash_to_curve_tai::<P256Sha256Tai>(&h2c_data).unwrap();
        let h_bytes = encode_value(&h);
        assert_eq!(
            "0072a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4",
            hex::encode(h_bytes)
        );

        let input = Input::from(h);
        let signature = sk.sign(input, []);

        let gamma_bytes = encode_value(&signature.gamma);
        assert_eq!(
            "005b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4",
            hex::encode(&gamma_bytes)
        );
    }
}
