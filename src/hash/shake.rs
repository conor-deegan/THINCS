/// SHAKE256-based tweakable hash functions per FIPS 205 §10.1.
///
/// All functions use SHAKE256 with domain separation via the ADRS structure.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use crate::core::address::Adrs;
use crate::params::types::ParameterSet;

/// T_l: Tweakable hash — SHAKE256(PK.seed || ADRS || M) truncated to n bytes.
/// Used for WOTS+ chain steps, tree hashing, etc.
pub fn hash_t(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(pk_seed);
    hasher.update(adrs.as_bytes());
    hasher.update(message);
    let mut output = vec![0u8; params.n];
    hasher.finalize_xof().read(&mut output);
    output
}

/// F: One-block tweakable hash (alias for T with single n-byte input).
/// F(PK.seed, ADRS, M_1) = SHAKE256(PK.seed || ADRS || M_1), |M_1| = n bytes
pub fn hash_f(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
    hash_t(params, pk_seed, adrs, m1)
}

/// H: Two-block tweakable hash.
/// H(PK.seed, ADRS, M_1 || M_2) = SHAKE256(PK.seed || ADRS || M_1 || M_2)
pub fn hash_h(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(pk_seed);
    hasher.update(adrs.as_bytes());
    hasher.update(m1);
    hasher.update(m2);
    let mut output = vec![0u8; params.n];
    hasher.finalize_xof().read(&mut output);
    output
}

/// PRF: Pseudorandom function for secret key generation.
/// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed), n bytes
pub fn prf(params: &ParameterSet, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(pk_seed);
    hasher.update(adrs.as_bytes());
    hasher.update(sk_seed);
    let mut output = vec![0u8; params.n];
    hasher.finalize_xof().read(&mut output);
    output
}

/// PRF_msg: Pseudorandom function for randomized message hashing.
/// PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M), n bytes
pub fn prf_msg(params: &ParameterSet, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(sk_prf);
    hasher.update(opt_rand);
    hasher.update(msg);
    let mut output = vec![0u8; params.n];
    hasher.finalize_xof().read(&mut output);
    output
}

/// H_msg: Message hash function (FIPS 205 §9 / §11.1).
/// H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M)
///
/// Output length per FIPS 205 §9:
///   m = ceil(k*a / 8) + ceil((h - h/d) / 8) + ceil((h/d) / 8) bytes
///
/// The output is split into three byte-aligned sections:
///   - md:       first ceil(k*a/8) bytes → k FORS indices (a bits each)
///   - idx_tree: next ceil((h - h/d)/8) bytes → hypertree leaf tree index
///   - idx_leaf: next ceil((h/d)/8) bytes → XMSS leaf index within that tree
pub fn h_msg(
    params: &ParameterSet,
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(r);
    hasher.update(pk_seed);
    hasher.update(pk_root);
    hasher.update(msg);
    let output_len = crate::params::types::h_msg_output_len(params);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof().read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::{HashFamily, ParameterSet};

    fn test_params() -> ParameterSet {
        ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        }
    }

    #[test]
    fn test_hash_f_output_length() {
        let params = test_params();
        let pk_seed = vec![0u8; params.n];
        let adrs = Adrs::new();
        let m = vec![0u8; params.n];
        let output = hash_f(&params, &pk_seed, &adrs, &m);
        assert_eq!(output.len(), params.n);
    }

    #[test]
    fn test_hash_f_deterministic() {
        let params = test_params();
        let pk_seed = vec![1u8; params.n];
        let adrs = Adrs::new();
        let m = vec![2u8; params.n];
        let o1 = hash_f(&params, &pk_seed, &adrs, &m);
        let o2 = hash_f(&params, &pk_seed, &adrs, &m);
        assert_eq!(o1, o2);
    }

    #[test]
    fn test_hash_f_different_inputs() {
        let params = test_params();
        let pk_seed = vec![1u8; params.n];
        let adrs = Adrs::new();
        let m1 = vec![2u8; params.n];
        let m2 = vec![3u8; params.n];
        let o1 = hash_f(&params, &pk_seed, &adrs, &m1);
        let o2 = hash_f(&params, &pk_seed, &adrs, &m2);
        assert_ne!(o1, o2);
    }

    #[test]
    fn test_prf_output_length() {
        let params = test_params();
        let pk_seed = vec![0u8; params.n];
        let sk_seed = vec![1u8; params.n];
        let adrs = Adrs::new();
        let output = prf(&params, &pk_seed, &sk_seed, &adrs);
        assert_eq!(output.len(), params.n);
    }

    #[test]
    fn test_h_msg_output_length() {
        let params = test_params();
        let r = vec![0u8; params.n];
        let pk_seed = vec![1u8; params.n];
        let pk_root = vec![2u8; params.n];
        let msg = b"test message";
        let output = h_msg(&params, &r, &pk_seed, &pk_root, msg);
        let expected_len = (params.k * params.a + params.h + 7) / 8;
        assert_eq!(output.len(), expected_len);
    }
}
