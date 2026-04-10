/// WOTS+ (Winternitz One-Time Signature) implementation per FIPS 205 §5.
///
/// WOTS+ signs a message digest using `len` hash chains of length `w`.
/// Each chain step applies the tweakable hash F.

use crate::core::address::{Adrs, WOTS_PK, WOTS_PRF};
use crate::hash;
use crate::params::types::ParameterSet;

/// Apply the chain function: starting from `input`, iterate F `steps` times
/// beginning at chain position `start`.
///
/// chain(input, start, steps) = F(F(...F(input)...)) applied `steps` times
fn chain(
    params: &ParameterSet,
    input: &[u8],
    start: u32,
    steps: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    let mut result = input.to_vec();
    for j in start..(start + steps) {
        adrs.set_hash_address(j);
        result = hash::hash_f(params, pk_seed, adrs, &result);
    }
    result
}

/// Return lg(w) for the supported Winternitz parameters {4, 16, 256}.
fn lg_w(w: usize) -> u32 {
    match w {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!("unsupported w={}", w),
    }
}

/// Convert a byte string to base-w representation per FIPS 205 Algorithm 2.
///
/// Given a byte string `msg` and Winternitz parameter `w`, produce `out_len`
/// base-w digits. Requires `out_len * lg(w) <= 8 * msg.len()`.
fn base_w(msg: &[u8], w: usize, out_len: usize) -> Vec<u32> {
    let lg_w = lg_w(w);
    let mut result = Vec::with_capacity(out_len);
    let mut in_idx = 0;
    let mut bits: u32 = 0;
    let mut total: u32 = 0;

    for _ in 0..out_len {
        if bits == 0 {
            total = msg[in_idx] as u32;
            in_idx += 1;
            bits = 8;
        }
        bits -= lg_w;
        result.push((total >> bits) & ((w as u32) - 1));
    }
    result
}

/// Generate WOTS+ public key from secret seed.
///
/// Algorithm 4 in FIPS 205.
pub fn wots_pk_gen(
    params: &ParameterSet,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    let len = params.len();
    let w = params.w as u32;

    // Generate each chain's secret key and compute its public value
    let mut sk_adrs = *adrs;
    sk_adrs.set_type(WOTS_PRF);
    sk_adrs.set_keypair_address(adrs.get_keypair_address());

    let mut wots_pk_adrs = *adrs;
    wots_pk_adrs.set_type(WOTS_PK);
    wots_pk_adrs.set_keypair_address(adrs.get_keypair_address());

    let mut tmp = Vec::with_capacity(len * params.n);

    for i in 0..len {
        sk_adrs.set_chain_address(i as u32);
        sk_adrs.set_hash_address(0);
        let sk = hash::prf(params, pk_seed, sk_seed, &sk_adrs);

        adrs.set_chain_address(i as u32);
        let pk_i = chain(params, &sk, 0, w - 1, pk_seed, adrs);
        tmp.extend_from_slice(&pk_i);
    }

    // Compress: T_len(PK.seed, ADRS_pk, pk_0 || ... || pk_{len-1})
    hash::hash_t(params, pk_seed, &wots_pk_adrs, &tmp)
}

/// Sign a message digest with WOTS+.
///
/// Algorithm 5 in FIPS 205.
/// `msg` is an n-byte message digest.
/// Returns the WOTS+ signature (len * n bytes).
pub fn wots_sign(
    params: &ParameterSet,
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    let len1 = params.len1();
    let len2 = params.len2();
    let len = params.len();
    let w = params.w as u32;

    // Convert message to base-w
    let msg_base_w = base_w(msg, params.w, len1);

    // Compute checksum
    let mut csum: u32 = 0;
    for &val in &msg_base_w {
        csum += (w - 1) - val;
    }

    // Convert checksum to base-w (FIPS 205 Algorithm 5 steps 5–8).
    // Shift csum left so its significant bits end on a byte boundary, then
    // take the last ceil(len2 * lg(w) / 8) bytes.
    let lg_w = lg_w(params.w);
    csum <<= (8 - ((len2 * lg_w as usize) % 8)) % 8;
    let csum_bytes = csum.to_be_bytes();
    let csum_byte_len = (len2 * lg_w as usize + 7) / 8;
    let csum_start = 4 - csum_byte_len;
    let csum_base_w = base_w(&csum_bytes[csum_start..], params.w, len2);

    // Combine message and checksum digits
    let mut digits = msg_base_w;
    digits.extend_from_slice(&csum_base_w);
    assert_eq!(digits.len(), len);

    // Sign: for each digit, chain from secret key to the digit value
    let mut sk_adrs = *adrs;
    sk_adrs.set_type(WOTS_PRF);
    sk_adrs.set_keypair_address(adrs.get_keypair_address());

    let mut sig = Vec::with_capacity(len * params.n);

    for i in 0..len {
        sk_adrs.set_chain_address(i as u32);
        sk_adrs.set_hash_address(0);
        let sk = hash::prf(params, pk_seed, sk_seed, &sk_adrs);

        adrs.set_chain_address(i as u32);
        let sig_i = chain(params, &sk, 0, digits[i], pk_seed, adrs);
        sig.extend_from_slice(&sig_i);
    }

    sig
}

/// Compute WOTS+ public key from signature.
///
/// Algorithm 6 in FIPS 205.
/// `sig` is the WOTS+ signature (len * n bytes).
/// `msg` is the n-byte message digest.
/// Returns the compressed WOTS+ public key (n bytes).
pub fn wots_pk_from_sig(
    params: &ParameterSet,
    sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    let len1 = params.len1();
    let len2 = params.len2();
    let len = params.len();
    let w = params.w as u32;

    let msg_base_w = base_w(msg, params.w, len1);

    let mut csum: u32 = 0;
    for &val in &msg_base_w {
        csum += (w - 1) - val;
    }

    let lg_w = lg_w(params.w);
    csum <<= (8 - ((len2 * lg_w as usize) % 8)) % 8;
    let csum_bytes = csum.to_be_bytes();
    let csum_byte_len = (len2 * lg_w as usize + 7) / 8;
    let csum_start = 4 - csum_byte_len;
    let csum_base_w = base_w(&csum_bytes[csum_start..], params.w, len2);

    let mut digits = msg_base_w;
    digits.extend_from_slice(&csum_base_w);

    let mut wots_pk_adrs = *adrs;
    wots_pk_adrs.set_type(WOTS_PK);
    wots_pk_adrs.set_keypair_address(adrs.get_keypair_address());

    let mut tmp = Vec::with_capacity(len * params.n);

    for i in 0..len {
        adrs.set_chain_address(i as u32);
        let sig_i = &sig[i * params.n..(i + 1) * params.n];
        let pk_i = chain(params, sig_i, digits[i], w - 1 - digits[i], pk_seed, adrs);
        tmp.extend_from_slice(&pk_i);
    }

    hash::hash_t(params, pk_seed, &wots_pk_adrs, &tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::WOTS_HASH;
    use crate::params::types::HashFamily;

    #[test]
    fn test_base_w_16() {
        // For w=16 (lg_w=4), each byte gives 2 digits
        let msg = vec![0xAB, 0xCD];
        let digits = base_w(&msg, 16, 4);
        assert_eq!(digits, vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_base_w_4() {
        // For w=4 (lg_w=2), each byte gives 4 digits
        let msg = vec![0b11_10_01_00]; // 3, 2, 1, 0
        let digits = base_w(&msg, 4, 4);
        assert_eq!(digits, vec![3, 2, 1, 0]);
    }

    #[test]
    fn test_wots_sign_verify_roundtrip() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let msg = vec![0xABu8; params.n]; // n-byte message digest

        let mut adrs = Adrs::new();
        adrs.set_type(WOTS_HASH);
        adrs.set_keypair_address(0);

        // Generate public key
        let pk = wots_pk_gen(&params, &sk_seed, &pk_seed, &mut adrs.clone());

        // Sign
        let sig = wots_sign(&params, &msg, &sk_seed, &pk_seed, &mut adrs.clone());
        assert_eq!(sig.len(), params.len() * params.n);

        // Verify: reconstruct public key from signature
        let pk_from_sig = wots_pk_from_sig(&params, &sig, &msg, &pk_seed, &mut adrs.clone());
        assert_eq!(pk, pk_from_sig);
    }

    #[test]
    fn test_wots_wrong_message_fails() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_type(WOTS_HASH);

        let pk = wots_pk_gen(&params, &sk_seed, &pk_seed, &mut adrs.clone());

        let msg = vec![0xABu8; params.n];
        let sig = wots_sign(&params, &msg, &sk_seed, &pk_seed, &mut adrs.clone());

        // Try verifying with wrong message
        let wrong_msg = vec![0xCDu8; params.n];
        let pk_wrong = wots_pk_from_sig(&params, &sig, &wrong_msg, &pk_seed, &mut adrs.clone());
        assert_ne!(pk, pk_wrong);
    }

    #[test]
    fn test_wots_w4_roundtrip() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 4, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![3u8; params.n];
        let pk_seed = vec![4u8; params.n];
        let msg = vec![0x55u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_type(WOTS_HASH);

        let pk = wots_pk_gen(&params, &sk_seed, &pk_seed, &mut adrs.clone());
        let sig = wots_sign(&params, &msg, &sk_seed, &pk_seed, &mut adrs.clone());
        let pk_from_sig = wots_pk_from_sig(&params, &sig, &msg, &pk_seed, &mut adrs.clone());
        assert_eq!(pk, pk_from_sig);
    }

    #[test]
    fn test_wots_w256_roundtrip() {
        // Regression: w=256 was added to the validator but base_w / lg_w
        // panicked at runtime. This test catches that.
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 256, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![5u8; params.n];
        let pk_seed = vec![6u8; params.n];
        let msg = vec![0x77u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_type(WOTS_HASH);

        let pk = wots_pk_gen(&params, &sk_seed, &pk_seed, &mut adrs.clone());
        let sig = wots_sign(&params, &msg, &sk_seed, &pk_seed, &mut adrs.clone());
        let pk_from_sig = wots_pk_from_sig(&params, &sig, &msg, &pk_seed, &mut adrs.clone());
        assert_eq!(pk, pk_from_sig);
    }

    #[test]
    fn test_base_w_256() {
        // For w=256 (lg_w=8), each byte gives 1 digit.
        let msg = vec![0x00, 0x7F, 0xFF];
        let digits = base_w(&msg, 256, 3);
        assert_eq!(digits, vec![0x00, 0x7F, 0xFF]);
    }

    #[test]
    fn test_wots_sha2_roundtrip() {
        // Exercise WOTS+ under the SHA-2 hash family.
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Sha2,
        };
        let sk_seed = vec![7u8; params.n];
        let pk_seed = vec![8u8; params.n];
        let msg = vec![0x99u8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_type(WOTS_HASH);

        let pk = wots_pk_gen(&params, &sk_seed, &pk_seed, &mut adrs.clone());
        let sig = wots_sign(&params, &msg, &sk_seed, &pk_seed, &mut adrs.clone());
        let pk_from_sig = wots_pk_from_sig(&params, &sig, &msg, &pk_seed, &mut adrs.clone());
        assert_eq!(pk, pk_from_sig);
    }
}
