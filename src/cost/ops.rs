use crate::params::types::ParameterSet;

/// Estimated hash calls for signing.
///
/// Cost model matches the naive reference-style implementation that computes
/// authentication path siblings by rebuilding the relevant subtrees from
/// scratch (as THINCS does). Optimised implementations using BDS tree
/// traversal amortise auth path extraction to O(h') per signature; this
/// model does not reflect those optimisations.
///
/// FORS (Algorithm 14):
///   each of k trees needs all auth path siblings, which requires building
///   ~2^a internal + leaf nodes per tree.
///   → k * 2^a hashes
///
/// Hypertree (Algorithm 10) per layer:
///   - 1 WOTS+ sign at the signed leaf: ~len * (w-1) / 2 chain F calls
///   - 2^h' - 1 auth path sibling subtrees, each ending in a WOTS+ pk gen
///     (~len * (w-1) F calls) and internal Merkle hashing (O(2^h') H calls)
///   - dominant term: ~2^h' * len * (w-1) hashes per layer
///
/// Total: k * 2^a  +  d * (len * (w-1)/2 + 2^h' * len * (w-1))
pub fn sign_hash_calls(params: &ParameterSet) -> u64 {
    let hp = params.hp();
    let len = params.len() as u64;
    let w = params.w as u64;
    let k = params.k as u64;
    let a = params.a as u64;
    let d = params.d as u64;

    // FORS: each tree requires building subtrees for auth path siblings.
    let fors_calls = k * (1u64 << a);

    // WOTS+ sign at the leaf: average (w-1)/2 chain steps per chain.
    let wots_sign_calls = len * (w - 1) / 2;

    // Auth path: 2^h' - 1 WOTS+ pk gens + internal Merkle tree hashes.
    // Each pk gen is len * (w-1) F calls. Internal hashes are +2^h' H calls.
    let leaves = 1u64 << hp;
    let auth_path_calls = leaves * len * (w - 1) + leaves;

    let ht_per_layer = wots_sign_calls + auth_path_calls;
    let ht_calls = d * ht_per_layer;

    fors_calls + ht_calls
}

/// Estimated hash calls for verification.
///
/// FORS (Algorithm 15): k trees, each with 1 leaf hash + a auth path nodes.
///   → k * (a + 1)
///
/// Hypertree (Algorithm 11) per layer:
///   - 1 WOTS+ pk_from_sig: average (w-1)/2 chain F calls per chain + 1 T_l
///   - h' auth path walks: 1 H call each
///
/// Total: k * (a + 1)  +  d * (len * (w-1)/2 + h')
pub fn verify_hash_calls(params: &ParameterSet) -> u64 {
    let hp = params.hp() as u64;
    let len = params.len() as u64;
    let w = params.w as u64;
    let k = params.k as u64;
    let a = params.a as u64;
    let d = params.d as u64;

    let fors_calls = k * (a + 1);
    let wots_per_layer = len * (w - 1) / 2;
    let xmss_per_layer = hp;
    let ht_calls = d * (wots_per_layer + xmss_per_layer);

    fors_calls + ht_calls
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::{HashFamily, ParameterSet};

    #[test]
    fn test_sign_calls_ordering() {
        // SLH-DSA-128f should be dramatically cheaper to sign than 128s
        // (smaller h', smaller k*2^a).
        let fast = ParameterSet {
            n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake,
        };
        let slow = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        assert!(sign_hash_calls(&fast) < sign_hash_calls(&slow));
    }

    #[test]
    fn test_128s_vs_128f_sign_ratio_realistic() {
        // Real SLH-DSA-128s signing is roughly 15-20x slower than 128f on
        // production hardware (eBACS/SUPERCOP). Our naive model should
        // capture at least an order-of-magnitude gap.
        let s = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let f = ParameterSet {
            n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake,
        };
        let ratio = sign_hash_calls(&s) as f64 / sign_hash_calls(&f) as f64;
        assert!(
            ratio > 10.0,
            "128s / 128f sign ratio = {:.1}, expected > 10", ratio
        );
    }

    #[test]
    fn test_verify_cheaper_than_sign() {
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        assert!(verify_hash_calls(&params) < sign_hash_calls(&params));
    }

    #[test]
    fn test_w256_sign_cost_higher_than_w16() {
        // With the same n/h/d/k/a, w=256 should cost much more to sign than
        // w=16 because chain length is 17x longer (255 vs 15 average steps).
        let w16 = ParameterSet {
            n: 16, h: 8, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let w256 = ParameterSet {
            n: 16, h: 8, d: 2, w: 256, k: 10, a: 8, hash: HashFamily::Shake,
        };
        assert!(sign_hash_calls(&w256) > sign_hash_calls(&w16));
    }

    #[test]
    fn test_256s_costlier_than_128s() {
        // SLH-DSA-256s has larger n, larger k, and the same h/d as 128s.
        // All three make signing more expensive.
        let p128s = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let p256s = ParameterSet {
            n: 32, h: 64, d: 8, w: 16, k: 22, a: 14, hash: HashFamily::Shake,
        };
        assert!(sign_hash_calls(&p256s) > sign_hash_calls(&p128s));
    }

    #[test]
    fn test_256f_costlier_than_128f() {
        let p128f = ParameterSet {
            n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake,
        };
        let p256f = ParameterSet {
            n: 32, h: 68, d: 17, w: 16, k: 35, a: 9, hash: HashFamily::Shake,
        };
        assert!(sign_hash_calls(&p256f) > sign_hash_calls(&p128f));
    }

    #[test]
    fn test_s_variants_verify_faster_than_f_variants() {
        // The `s` variants have larger FORS (k*a larger) but smaller d, so
        // verify cost can go either way. Actually per published benchmarks,
        // s-variants verify in roughly half the time of f-variants because
        // they have fewer hypertree layers (7 vs 22). Our model should show
        // this: verify cost of 128s should be lower than 128f.
        let p128s = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let p128f = ParameterSet {
            n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake,
        };
        assert!(
            verify_hash_calls(&p128s) < verify_hash_calls(&p128f),
            "s-variant should verify faster than f-variant (s={}, f={})",
            verify_hash_calls(&p128s),
            verify_hash_calls(&p128f),
        );
    }

    #[test]
    fn test_w4_sign_cheaper_than_w16() {
        // With w=4, chain length is (w-1)/2 = 1.5 steps average vs 7.5 for w=16.
        // But len doubles. Dominant term 2^h' * len * (w-1) works out smaller
        // for w=4 given the same hp.
        let w16 = ParameterSet {
            n: 16, h: 8, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let w4 = ParameterSet {
            n: 16, h: 8, d: 2, w: 4, k: 10, a: 8, hash: HashFamily::Shake,
        };
        // w=4 len=68, (w-1)=3 → cost ∝ 68*3 = 204
        // w=16 len=35, (w-1)=15 → cost ∝ 35*15 = 525
        assert!(sign_hash_calls(&w4) < sign_hash_calls(&w16));
    }
}
