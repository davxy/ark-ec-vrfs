//! EC-VRF as specified by [RFC-9381](https://datatracker.ietf.org/doc/rfc9381).
//!
//! The implementation extends RFC9381 to allow to sign additional user data together
//! with the VRF input. Refer to https://github.com/davxy/bandersnatch-vrfs-spec for
//! specification extension details.

use super::*;

pub trait IetfSuite: Suite {}

impl<T> IetfSuite for T where T: Suite {}

/// VRF proof generic over the cipher suite.
///
/// An output point which can be used to derive the actual output together
/// with the actual proof of the input point and the associated data.
#[derive(Debug, Clone)]
pub struct Proof<S: IetfSuite> {
    pub c: ScalarField<S>,
    pub s: ScalarField<S>,
}

impl<S: IetfSuite> CanonicalSerialize for Proof<S> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        _compress_always: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let buf = utils::encode_scalar::<S>(&self.c);
        if buf.len() < S::CHALLENGE_LEN {
            // Encoded scalar length must be at least S::CHALLENGE_LEN
            return Err(ark_serialize::SerializationError::NotEnoughSpace);
        }
        writer.write_all(&buf[..S::CHALLENGE_LEN])?;
        self.s.serialize_compressed(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self, _compress_always: ark_serialize::Compress) -> usize {
        S::CHALLENGE_LEN + self.s.compressed_size()
    }
}

impl<S: IetfSuite> CanonicalDeserialize for Proof<S> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        _compress_always: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let c = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            ark_serialize::Compress::No,
            validate,
        )?;
        let s = <ScalarField<S> as CanonicalDeserialize>::deserialize_with_mode(
            &mut reader,
            ark_serialize::Compress::No,
            validate,
        )?;
        Ok(Proof { c, s })
    }
}

impl<S: IetfSuite> ark_serialize::Valid for Proof<S> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.c.check()?;
        self.s.check()?;
        Ok(())
    }
}

pub trait Prover<S: IetfSuite> {
    /// Generate a proof for the given input/output and user additional data.
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S>;
}

pub trait Verifier<S: IetfSuite> {
    /// Verify a proof for the given input/output and user additional data.
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        sig: &Proof<S>,
    ) -> Result<(), Error>;
}

impl<S: IetfSuite> Prover<S> for Secret<S> {
    fn prove(&self, input: Input<S>, output: Output<S>, ad: impl AsRef<[u8]>) -> Proof<S> {
        let k = S::nonce(&self.scalar, input);
        let k_b = (S::Affine::generator() * k).into_affine();

        let k_h = (input.0 * k).into_affine();

        let c = S::challenge(
            &[&self.public.0, &input.0, &output.0, &k_b, &k_h],
            ad.as_ref(),
        );
        let s = k + c * self.scalar;
        Proof { c, s }
    }
}

impl<S: IetfSuite> Verifier<S> for Public<S> {
    fn verify(
        &self,
        input: Input<S>,
        output: Output<S>,
        ad: impl AsRef<[u8]>,
        proof: &Proof<S>,
    ) -> Result<(), Error> {
        let Proof { c, s } = proof;

        let s_b = S::Affine::generator() * s;
        let c_y = self.0 * c;
        let u = (s_b - c_y).into_affine();

        let s_h = input.0 * s;
        let c_o = output.0 * c;
        let v = (s_h - c_o).into_affine();

        let c_exp = S::challenge(&[&self.0, &input.0, &output.0, &u, &v], ad.as_ref());
        (&c_exp == c)
            .then_some(())
            .ok_or(Error::VerificationFailure)
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;

    pub const TEST_FLAG_SKIP_PROOF_CHECK: u8 = 1 << 0;

    pub struct TestVector<S: IetfSuite> {
        pub comment: String,
        pub sk: ScalarField<S>,
        pub pk: AffinePoint<S>,
        pub alpha: Vec<u8>,
        pub ad: Vec<u8>,
        pub h: AffinePoint<S>,
        pub gamma: AffinePoint<S>,
        pub beta: Vec<u8>,
        pub c: ScalarField<S>,
        pub s: ScalarField<S>,
        pub flags: u8,
    }

    impl<S: IetfSuite + std::fmt::Debug> TestVector<S> {
        pub fn new(
            comment: &str,
            seed: &[u8],
            alpha: &[u8],
            salt: Option<&[u8]>,
            ad: &[u8],
            flags: u8,
        ) -> Self {
            let sk = Secret::<S>::from_seed(seed);
            let pk = sk.public().0;

            let salt = salt
                .map(|v| v.to_vec())
                .unwrap_or_else(|| utils::encode_point::<S>(&pk));

            let h2c_data = [&salt[..], alpha].concat();
            let h = <S as Suite>::data_to_point(&h2c_data).unwrap();
            let input = Input::from(h);

            let alpha = alpha.to_vec();
            let output = sk.output(input);
            let gamma = output.0;
            let beta = output.hash().to_vec();

            let proof = sk.prove(input, output, ad);

            TestVector {
                comment: comment.to_string(),
                sk: sk.scalar,
                pk,
                alpha,
                ad: ad.to_vec(),
                h,
                gamma,
                beta,
                c: proof.c,
                s: proof.s,
                flags,
            }
        }

        pub fn run(&self) {
            println!("Running test vector: {}", self.comment);

            let sk = Secret::<S>::from_scalar(self.sk);

            let pk = sk.public();
            assert_eq!(self.pk, pk.0, "public key ('pk') mismatch");

            // Prepare hash_to_curve data = salt || alpha
            // Salt is defined to be pk (adjust it to make the encoding to match)
            let pk_bytes = utils::encode_point::<S>(&pk.0);
            let h2c_data = [&pk_bytes[..], &self.alpha[..]].concat();

            let h = S::data_to_point(&h2c_data).unwrap();
            assert_eq!(self.h, h, "hash-to-curve ('h') mismatch");
            let input = Input::<S>::from(h);

            let output = sk.output(input);
            assert_eq!(self.gamma, output.0, "VRF pre-output ('gamma') mismatch");

            if self.flags & TEST_FLAG_SKIP_PROOF_CHECK != 0 {
                return;
            }

            let beta = output.hash().to_vec();
            assert_eq!(self.beta, beta, "VRF output ('beta') mismatch");

            let proof = sk.prove(input, output, &self.ad);
            assert_eq!(self.c, proof.c, "VRF proof challenge ('c') mismatch");
            assert_eq!(self.s, proof.s, "VRF proof response ('s') mismatch");

            assert!(pk.verify(input, output, &self.ad, &proof).is_ok());
        }
    }

    impl<S: IetfSuite> core::fmt::Debug for TestVector<S> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let sk = hex::encode(utils::encode_scalar::<S>(&self.sk));
            let pk = hex::encode(utils::encode_point::<S>(&self.pk));
            let alpha = hex::encode(&self.alpha);
            let ad = hex::encode(&self.ad);
            let h = hex::encode(utils::encode_point::<S>(&self.h));
            let gamma = hex::encode(utils::encode_point::<S>(&self.gamma));
            let beta = hex::encode(&self.beta);
            let c = hex::encode(utils::encode_scalar::<S>(&self.c));
            let s = hex::encode(utils::encode_scalar::<S>(&self.s));
            f.debug_struct("TestVector")
                .field("comment", &self.comment)
                .field("sk", &sk)
                .field("pk", &pk)
                .field("alpha", &alpha)
                .field("ad", &ad)
                .field("h", &h)
                .field("gamma", &gamma)
                .field("beta", &beta)
                .field("proof_c", &c)
                .field("proof_s", &s)
                .field("flags", &self.flags)
                .finish()
        }
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct TestVectorMap(indexmap::IndexMap<String, String>);

    impl<S: IetfSuite> From<TestVector<S>> for TestVectorMap {
        fn from(v: TestVector<S>) -> Self {
            let items = [
                ("comment", v.comment),
                ("sk", hex::encode(utils::encode_scalar::<S>(&v.sk))),
                ("pk", hex::encode(utils::encode_point::<S>(&v.pk))),
                ("alpha", hex::encode(&v.alpha)),
                ("ad", hex::encode(&v.ad)),
                ("h", hex::encode(utils::encode_point::<S>(&v.h))),
                ("gamma", hex::encode(utils::encode_point::<S>(&v.gamma))),
                ("beta", hex::encode(&v.beta)),
                ("proof_c", hex::encode(utils::encode_scalar::<S>(&v.c))),
                ("proof_s", hex::encode(utils::encode_scalar::<S>(&v.s))),
                ("flags", hex::encode([v.flags])),
            ];
            let map: indexmap::IndexMap<String, String> =
                items.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
            Self(map)
        }
    }

    impl<S: IetfSuite> From<TestVectorMap> for TestVector<S> {
        fn from(map: TestVectorMap) -> Self {
            let item_bytes = |field| hex::decode(map.0.get(field).unwrap()).unwrap();
            let comment = map.0.get("comment").unwrap().to_string();
            let sk = utils::decode_scalar::<S>(&item_bytes("sk"));
            let pk = utils::decode_point::<S>(&item_bytes("pk"));
            let alpha = item_bytes("alpha");
            let ad = item_bytes("ad");
            let h = utils::decode_point::<S>(&item_bytes("h"));
            let gamma = utils::decode_point::<S>(&item_bytes("gamma"));
            let beta = item_bytes("beta");
            let c = utils::decode_scalar::<S>(&item_bytes("proof_c"));
            let s = utils::decode_scalar::<S>(&item_bytes("proof_s"));
            let flags = item_bytes("flags")[0];
            Self {
                comment,
                sk,
                pk,
                alpha,
                ad,
                h,
                gamma,
                beta,
                c,
                s,
                flags,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        random_val,
        suite::{AffinePoint, Input, ScalarField, Secret, TestSuite},
        TEST_SEED,
    };

    #[test]
    fn prove_verify_works() {
        let secret = Secret::from_seed(TEST_SEED);
        let public = secret.public();
        let input = Input::from(random_val::<AffinePoint>(None));
        let output = secret.output(input);

        let proof = secret.prove(input, output, b"foo");

        let result = public.verify(input, output, b"foo", &proof);
        assert!(result.is_ok());
    }

    #[test]
    fn proof_encode_decode() {
        let c = hex::decode("d091c00b0f5c3619d10ecea44363b5a5").unwrap();
        let c = ScalarField::from_be_bytes_mod_order(&c[..]);
        let s = hex::decode("99cadc5b2957e223fec62e81f7b4825fc799a771a3d7334b9186bdbee87316b1")
            .unwrap();
        let s = ScalarField::from_be_bytes_mod_order(&s[..]);

        let proof = Proof::<TestSuite> { c, s };

        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        assert_eq!(buf.len(), TestSuite::CHALLENGE_LEN + 32);
    }
}
