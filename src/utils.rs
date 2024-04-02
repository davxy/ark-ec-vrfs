/// SHA-512 hasher
#[inline(always)]
pub fn sha512(input: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut h = [0u8; 64];
    h.copy_from_slice(&result);
    h
}

/// Blake2b
#[inline(always)]
pub fn blake2(input: &[u8]) -> [u8; 64] {
    use blake2b_simd::blake2b;
    *blake2b(input).as_array()
}
