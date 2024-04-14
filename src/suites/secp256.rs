//! `ECVRF-P256-SHA256-TAI` suite.
//!
//! Configuration (RFC9381):
//!
//! *  suite_string = 0x01.
//!
//! *  The EC group G is the NIST P-256 elliptic curve, with the finite
//!    field and curve parameters as specified in Section 3.2.1.3 of
//!    [SP-800-186] and Section 2.6 of [RFC5114].  For this group, fLen =
//!    qLen = 32 and cofactor = 1.
//!
//! *  cLen = 16.
//!
//! *  The key pair generation primitive is specified in Section 3.2.1 of
//!    [SECG1] (q, B, SK, and Y in this document correspond to n, G, d,
//!    and Q in Section 3.2.1 of [SECG1]).  In this ciphersuite, the
//!    secret scalar x is equal to the secret key SK.
//!
//! *  encode_to_curve_salt = PK_string.
//!
//! *  The ECVRF_nonce_generation function is as specified in
//!    Section 5.4.2.1.
//!
//! *  The int_to_string function is the I2OSP function specified in
//!    Section 4.1 of [RFC8017].  (This is big-endian representation.)
//!
//! *  The string_to_int function is the OS2IP function specified in
//!    Section 4.2 of [RFC8017].  (This is big-endian representation.)
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string according to the encoding specified in Section 2.3.3 of
//!    [SECG1] with point compression on.  This implies that
//!    ptLen = fLen + 1 = 33.  (Note that certain software implementations do not
//!    introduce a separate elliptic curve point type and instead
//!    directly treat the EC point as an octet string per the above
//!    encoding.  When using such an implementation, the point_to_string
//!    function can be treated as the identity function.)
//!
//! *  The string_to_point function converts an octet string to a point
//!    on E according to the encoding specified in Section 2.3.4 of
//!    [SECG1].  This function MUST output "INVALID" if the octet string
//!    does not decode to a point on the curve E.
//!
//! *  The hash function Hash is SHA-256 as specified in [RFC6234], with
//!    hLen = 32.
//!
//! *  The ECVRF_encode_to_curve function is as specified in
//!    Section 5.4.1.1, with interpret_hash_value_as_a_point(s) =
//!    string_to_point(0x02 || s).

use crate::*;

#[derive(Copy, Clone)]
pub struct P256Sha256Tai;

suite_types!(P256Sha256Tai);

fn hmac(sk: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(sk).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    bytes.to_vec()
}

fn encode_point(pt: &AffinePoint) -> Vec<u8> {
    let mut buf = Vec::new();
    P256Sha256Tai::point_encode(pt, &mut buf);
    buf
}

fn encode_scalar(sc: &ScalarField) -> Vec<u8> {
    let mut buf = Vec::new();
    P256Sha256Tai::scalar_encode(sc, &mut buf);
    buf
}

impl Suite for P256Sha256Tai {
    const SUITE_ID: u8 = 0x01;
    const CHALLENGE_LEN: usize = 16;

    type Affine = ark_secp256r1::Affine;
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        utils::sha256(data)
    }

    fn nonce(sk: &ScalarField, pt: Input) -> ScalarField {
        let raw = encode_point(&pt.0);
        let h1 = Self::hash(&raw);

        let v = [1; 32];
        let k = [0; 32];

        // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
        let x = encode_scalar(sk);
        let raw = [&v[..], &[0x00], &x[..], &h1[..]].concat();
        let k = hmac(&k, &raw);

        // V = HMAC_K(V)
        let v = hmac(&k, &v);

        // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
        let raw = [&v[..], &[0x01], &x[..], &h1[..]].concat();
        let k = hmac(&k, &raw);

        // V = HMAC_K(V)
        let v = hmac(&k, &v);

        // TODO: loop until 1 < k < q
        let v = hmac(&k, &v);
        // NOTE: construct from BE byte order
        let k = ScalarField::from_be_bytes_mod_order(&v[..]);

        let test = encode_scalar(&k);
        println!("K: {}", hex::encode(test));

        k
    }

    #[inline(always)]
    fn point_encode(pt: &AffinePoint, buf: &mut Vec<u8>) {
        use ark_ff::biginteger::BigInteger;
        let mut tmp = Vec::new();

        let y = if pt.y.0.is_odd() { 0x03 } else { 0x02 };
        {
            let mut raw = Vec::new();
            pt.serialize_compressed(&mut raw).unwrap();
            println!("POINT: {}", pt);
            println!("ENCODING: {}", hex::encode(raw));
            println!("Y: {}", pt.y.0);
        }

        buf.push(y);
        pt.x.serialize_compressed(&mut tmp).unwrap();
        tmp.reverse();
        buf.extend_from_slice(&tmp[..]);
    }

    #[inline(always)]
    fn scalar_encode(sc: &ScalarField, buf: &mut Vec<u8>) {
        let mut tmp = Vec::new();
        sc.serialize_compressed(&mut tmp).unwrap();
        tmp.reverse();
        buf.extend_from_slice(&tmp[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ietf::IetfSigner;

    // RFC-9381 - Appendix B.1 - Example 10
    //
    // Partial due to annoying incompatibility of points encoding between Arkworks
    // and [SECG1] section 2.3.3.
    #[test]
    fn secp256_test_vectors_ex10() {
        let mut sk_bytes =
            hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
                .unwrap();
        sk_bytes.reverse();
        let sk = Secret::deserialize_compressed(&mut sk_bytes.as_slice()).unwrap();

        // Prepare hash_to_curve data = salt || alpha
        // Salt is defined to be pk (adjust it to make the encoding to match)

        let pk_bytes = encode_point(&sk.public.0);
        assert_eq!(
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            hex::encode(&pk_bytes)
        );

        let h2c_data = [&pk_bytes[..], b"sample"].concat();
        let h = P256Sha256Tai::data_to_point(&h2c_data).unwrap();
        let h_bytes = encode_point(&h);
        assert_eq!(
            "0272a877532e9ac193aff4401234266f59900a4a9e3fc3cfc6a4b7e467a15d06d4",
            hex::encode(h_bytes)
        );

        let input = Input::from(h);
        let signature = sk.sign(input, []);

        let gamma_bytes = encode_point(&signature.output().0);
        assert_eq!(
            "035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4",
            hex::encode(&gamma_bytes)
        );

        let bytes = encode_scalar(&signature.s);
        println!("S: {}", hex::encode(bytes));

        let bytes = encode_scalar(&signature.c);
        println!("S: {}", hex::encode(bytes));
    }
}

// gamma: 035b5c726e8c0e2c488a107c600578ee75cb702343c153cb1eb8dec77f4b5071b4
// c: a53f0a46f018bc2c56e58d383f2305e0
// s: 975972c26feea0eb122fe7893c15af376b33edf7de17c6ea056d4d82de6bc02f
