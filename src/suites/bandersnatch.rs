//! `ECVRF-BANDERSNATCH-BLAKE2-TAI` suite.
//!
//! Configuration (Custom):
//!
//! *  suite_string = 0x33.
//!
//! *  The EC group G is the Bandersnatch elliptic curve, with the finite
//!    field and curve parameters as specified [here](https://neuromancer.sk/std/bls/Bandersnatch).
//!    For this group, fLen = qLen = 32 and cofactor = 4.
//!
//! *  cLen = 32.
//!
//! *  The key pair generation primitive is PK = SK * g, with SK the secret
//!    key scalar and g the group generator. In this ciphersuite, the secret
//!    scalar x is equal to the secret key SK.
//!
//! *  encode_to_curve_salt = PK_string.
//!
//! *  The ECVRF_nonce_generation function is as specified in
//!    Section 5.4.2.1.
//!
//! *  The int_to_string function encodes into the 32 bytes little endian
//!    representation.
//!
//! *  The string_to_int function decodes from the 32 bytes little endian
//!    representation.
//!
//! *  The point_to_string function converts a point on E to an octet
//!    string using compressed form. The Y coordinate is encoded using
//!    int_to_string function and the most significant bit of the last
//!    octet is used to keep track of the X's sign. This implies that
//!    the point is encoded on 32 bytes.
//!
//! *  The string_to_point function tries to decompress the point encoded
//!    according to `point_to_string` procedure. This function MUST outputs
//!    "INVALID" if the octet string does not decode to a point on the curve E.
//!
//! *  The hash function Hash is BLAKE2b as specified in
//!    [RFC7693](https://www.rfc-editor.org/rfc/rfc7693), with hLen = 64.
//!    (TODO: is hLen = 32 sufficient)?
//!
//! *  The ECVRF_encode_to_curve function is as specified in
//!    Section 5.4.1.2, with h2c_suite_ID_string = BANDERSNATCH_XMD:BLAKE2b_ELL2_RO_
//!    (TODO: double check)
//!    (the suite is defined in Section 8.5 of [RFC9380]).

use crate::*;

#[derive(Copy, Clone)]
pub struct BandersnatchBlake2;

suite_types!(BandersnatchBlake2);

impl Suite for BandersnatchBlake2 {
    const SUITE_ID: u8 = 0x33;
    const CHALLENGE_LEN: usize = 32;

    type Affine = ark_ed_on_bls12_381_bandersnatch::EdwardsAffine;
    type Hash = [u8; 64];

    fn hash(data: &[u8]) -> Self::Hash {
        utils::blake2(data)
    }
}
