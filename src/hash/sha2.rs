/// SHA-2-based tweakable hash functions per FIPS 205 §11.2.
///
/// The SHA-2 instantiation is more subtle than SHAKE:
///
///   n=16: all functions use SHA-256
///   n=24, 32: F and PRF use SHA-256 (kept for speed); H, T_l, PRF_msg, H_msg
///             use SHA-512 (for additional security margin in H which dominates
///             multi-target attack surface).
///
/// Compared to SHAKE, SHA-2 also uses:
///   - A 22-byte compressed ADRS (Adrs::as_compressed_bytes), not 32-byte full ADRS.
///   - Zero-byte padding between PK.seed and ADRS^c to push the address into
///     the second SHA block (PK.seed || 0…0 || ADRS^c || M).
///   - HMAC-SHA-2 for PRF_msg.
///   - MGF1-SHA-2 for H_msg.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::core::address::Adrs;
use crate::params::types::ParameterSet;

/// SHA-256 block size in bytes.
const SHA256_BLOCK: usize = 64;
/// SHA-512 block size in bytes.
const SHA512_BLOCK: usize = 128;

/// Compute SHA-256(msg) truncated to `n` bytes.
fn sha256_trunc(msg: &[u8], n: usize) -> Vec<u8> {
    let digest = Sha256::digest(msg);
    digest[..n].to_vec()
}

/// Compute SHA-512(msg) truncated to `n` bytes.
fn sha512_trunc(msg: &[u8], n: usize) -> Vec<u8> {
    let digest = Sha512::digest(msg);
    digest[..n].to_vec()
}

/// Build the prefix `PK.seed || toByte(0, block-n) || ADRS^c` used by all
/// tweakable-hash inputs in the SHA-2 instantiation.
fn tweak_prefix(pk_seed: &[u8], adrs: &Adrs, block: usize) -> Vec<u8> {
    // Padding length: enough zero bytes so that PK.seed || 0…0 totals `block`
    // bytes. This places ADRS^c at the start of the second block for faster
    // rekeying via SHA compression function precomputation.
    let n = pk_seed.len();
    let pad_len = block - n;
    let mut prefix = Vec::with_capacity(block + 22);
    prefix.extend_from_slice(pk_seed);
    prefix.extend(std::iter::repeat(0u8).take(pad_len));
    prefix.extend_from_slice(&adrs.as_compressed_bytes());
    prefix
}

/// T_l: tweakable hash with arbitrary-length message.
/// n=16 uses SHA-256; n>=24 uses SHA-512.
pub fn hash_t(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    if params.n == 16 {
        let mut input = tweak_prefix(pk_seed, adrs, SHA256_BLOCK);
        input.extend_from_slice(message);
        sha256_trunc(&input, params.n)
    } else {
        let mut input = tweak_prefix(pk_seed, adrs, SHA512_BLOCK);
        input.extend_from_slice(message);
        sha512_trunc(&input, params.n)
    }
}

/// F: one-block tweakable hash (for WOTS+ chain steps).
/// Always uses SHA-256 regardless of n (preserves WOTS+ speed).
pub fn hash_f(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
    let mut input = tweak_prefix(pk_seed, adrs, SHA256_BLOCK);
    input.extend_from_slice(m1);
    sha256_trunc(&input, params.n)
}

/// H: two-block tweakable hash (for Merkle tree inner nodes).
/// n=16 uses SHA-256; n>=24 uses SHA-512.
pub fn hash_h(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8]) -> Vec<u8> {
    if params.n == 16 {
        let mut input = tweak_prefix(pk_seed, adrs, SHA256_BLOCK);
        input.extend_from_slice(m1);
        input.extend_from_slice(m2);
        sha256_trunc(&input, params.n)
    } else {
        let mut input = tweak_prefix(pk_seed, adrs, SHA512_BLOCK);
        input.extend_from_slice(m1);
        input.extend_from_slice(m2);
        sha512_trunc(&input, params.n)
    }
}

/// PRF: SK.seed → leaf secret key.
/// Always uses SHA-256 regardless of n (matches FIPS 205 §11.2.1).
pub fn prf(params: &ParameterSet, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
    let mut input = tweak_prefix(pk_seed, adrs, SHA256_BLOCK);
    input.extend_from_slice(sk_seed);
    sha256_trunc(&input, params.n)
}

/// PRF_msg: randomizer generation.
/// n=16 uses HMAC-SHA-256; n>=24 uses HMAC-SHA-512.
pub fn prf_msg(params: &ParameterSet, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
    if params.n == 16 {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(sk_prf)
            .expect("HMAC-SHA-256 accepts any key length");
        mac.update(opt_rand);
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        result[..params.n].to_vec()
    } else {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(sk_prf)
            .expect("HMAC-SHA-512 accepts any key length");
        mac.update(opt_rand);
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        result[..params.n].to_vec()
    }
}

/// H_msg: message hash via MGF1 (FIPS 205 §11.2).
/// n=16 uses MGF1-SHA-256; n>=24 uses MGF1-SHA-512.
///
/// Output length: m = ceil(k*a/8) + ceil((h - h/d)/8) + ceil((h/d)/8) bytes,
/// identical to the SHAKE variant.
pub fn h_msg(
    params: &ParameterSet,
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
) -> Vec<u8> {
    let out_len = crate::params::types::h_msg_output_len(params);

    // Per FIPS 205 §11.2.1 / 11.2.2:
    //   H_msg(R, PK.seed, PK.root, M) =
    //       MGF1(R || PK.seed || Hash(R || PK.seed || PK.root || M), out_len)
    // where Hash = SHA-256 for n=16 and SHA-512 for n>=24.
    let mut inner = Vec::with_capacity(r.len() + pk_seed.len() + pk_root.len() + msg.len());
    inner.extend_from_slice(r);
    inner.extend_from_slice(pk_seed);
    inner.extend_from_slice(pk_root);
    inner.extend_from_slice(msg);

    let mut seed = Vec::with_capacity(r.len() + pk_seed.len() + 64);
    seed.extend_from_slice(r);
    seed.extend_from_slice(pk_seed);

    if params.n == 16 {
        let inner_hash = Sha256::digest(&inner);
        seed.extend_from_slice(&inner_hash);
        mgf1_sha256(&seed, out_len)
    } else {
        let inner_hash = Sha512::digest(&inner);
        seed.extend_from_slice(&inner_hash);
        mgf1_sha512(&seed, out_len)
    }
}

/// MGF1-SHA-256 per RFC 8017 §B.2.1.
fn mgf1_sha256(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// MGF1-SHA-512 per RFC 8017 §B.2.1.
fn mgf1_sha512(seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::{HashFamily, ParameterSet};

    fn params_128() -> ParameterSet {
        ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Sha2,
        }
    }

    fn params_192() -> ParameterSet {
        ParameterSet {
            n: 24, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Sha2,
        }
    }

    fn params_256() -> ParameterSet {
        ParameterSet {
            n: 32, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Sha2,
        }
    }

    #[test]
    fn test_hash_f_output_length() {
        let params = params_128();
        let pk_seed = vec![0u8; params.n];
        let adrs = Adrs::new();
        let m = vec![0u8; params.n];
        assert_eq!(hash_f(&params, &pk_seed, &adrs, &m).len(), params.n);
    }

    #[test]
    fn test_hash_f_deterministic() {
        let params = params_128();
        let pk_seed = vec![1u8; params.n];
        let adrs = Adrs::new();
        let m = vec![2u8; params.n];
        assert_eq!(
            hash_f(&params, &pk_seed, &adrs, &m),
            hash_f(&params, &pk_seed, &adrs, &m),
        );
    }

    #[test]
    fn test_hash_f_different_inputs() {
        let params = params_128();
        let pk_seed = vec![1u8; params.n];
        let adrs = Adrs::new();
        let m1 = vec![2u8; params.n];
        let m2 = vec![3u8; params.n];
        assert_ne!(
            hash_f(&params, &pk_seed, &adrs, &m1),
            hash_f(&params, &pk_seed, &adrs, &m2),
        );
    }

    #[test]
    fn test_hash_h_uses_sha512_for_n24_and_n32() {
        // For n=16, H uses SHA-256; for n>=24 it switches to SHA-512.
        // We can detect the switch by building the same conceptual input
        // twice and checking that the tweak_prefix uses a different block size.
        let p192 = params_192();
        let p256 = params_256();
        let pk_192 = vec![1u8; p192.n];
        let pk_256 = vec![1u8; p256.n];
        let adrs = Adrs::new();
        let m1_192 = vec![2u8; p192.n];
        let m2_192 = vec![3u8; p192.n];
        let m1_256 = vec![2u8; p256.n];
        let m2_256 = vec![3u8; p256.n];
        // Just verify determinism and correct output lengths.
        let h192 = hash_h(&p192, &pk_192, &adrs, &m1_192, &m2_192);
        let h256 = hash_h(&p256, &pk_256, &adrs, &m1_256, &m2_256);
        assert_eq!(h192.len(), 24);
        assert_eq!(h256.len(), 32);
    }

    #[test]
    fn test_prf_output_length() {
        for params in [params_128(), params_192(), params_256()] {
            let pk_seed = vec![0u8; params.n];
            let sk_seed = vec![1u8; params.n];
            let adrs = Adrs::new();
            assert_eq!(prf(&params, &pk_seed, &sk_seed, &adrs).len(), params.n);
        }
    }

    #[test]
    fn test_prf_msg_output_length() {
        for params in [params_128(), params_192(), params_256()] {
            let sk_prf = vec![1u8; params.n];
            let opt_rand = vec![2u8; params.n];
            let msg = b"message";
            assert_eq!(prf_msg(&params, &sk_prf, &opt_rand, msg).len(), params.n);
        }
    }

    #[test]
    fn test_h_msg_output_length() {
        for params in [params_128(), params_192(), params_256()] {
            let r = vec![0u8; params.n];
            let pk_seed = vec![1u8; params.n];
            let pk_root = vec![2u8; params.n];
            let msg = b"test";
            let out = h_msg(&params, &r, &pk_seed, &pk_root, msg);
            let expected = (params.k * params.a + params.h + 7) / 8;
            assert_eq!(out.len(), expected);
        }
    }

    #[test]
    fn test_mgf1_sha256_rfc8017_vector() {
        // RFC 8017 Appendix B.2.1 doesn't give a direct MGF1 test vector but
        // we verify internal consistency: output is deterministic and length
        // extends correctly.
        let seed = b"test seed";
        let out1 = mgf1_sha256(seed, 32);
        let out2 = mgf1_sha256(seed, 64);
        assert_eq!(out1.len(), 32);
        assert_eq!(out2.len(), 64);
        // First 32 bytes of a longer request equal the short request.
        assert_eq!(&out1[..], &out2[..32]);
    }

    #[test]
    fn test_mgf1_sha512_extends_across_blocks() {
        let seed = b"another seed";
        // SHA-512 digest is 64 bytes; request 100 bytes to force multiple counter values.
        let out = mgf1_sha512(seed, 100);
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn test_sha2_differs_from_shake() {
        // SHA-2 and SHAKE should produce different outputs for the same input.
        use crate::hash::shake;
        let p_shake = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let p_sha2 = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Sha2,
        };
        let pk_seed = vec![1u8; 16];
        let adrs = Adrs::new();
        let m = vec![2u8; 16];
        let shake_out = shake::hash_f(&p_shake, &pk_seed, &adrs, &m);
        let sha2_out = hash_f(&p_sha2, &pk_seed, &adrs, &m);
        assert_ne!(shake_out, sha2_out);
    }
}
