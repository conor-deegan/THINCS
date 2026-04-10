/// Hypertree — d layers of XMSS trees.
///
/// Per FIPS 205 §7. The hypertree is a tree of XMSS trees.
/// Layer d-1 is the top (root), layer 0 is the bottom.
/// Each XMSS tree at layer i certifies the roots of trees at layer i-1.

use crate::core::address::Adrs;
use crate::core::xmss;
use crate::params::types::ParameterSet;

/// Hypertree signature: d XMSS signatures (each = WOTS+ sig + auth path).
pub struct HtSignature {
    /// One (WOTS+ signature, auth path) per layer, from bottom to top.
    pub layers: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
}

impl HtSignature {
    /// Serialize the hypertree signature to bytes.
    pub fn to_bytes(&self, params: &ParameterSet) -> Vec<u8> {
        let hp = params.hp();
        let wots_sig_len = params.len() * params.n;
        let auth_len = hp * params.n;
        let per_layer = wots_sig_len + auth_len;
        let mut bytes = Vec::with_capacity(params.d * per_layer);

        for (wots_sig, auth) in &self.layers {
            bytes.extend_from_slice(wots_sig);
            for node in auth {
                bytes.extend_from_slice(node);
            }
        }
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(params: &ParameterSet, bytes: &[u8]) -> Self {
        let hp = params.hp();
        let wots_sig_len = params.len() * params.n;
        let auth_len = hp * params.n;
        let per_layer = wots_sig_len + auth_len;
        let mut layers = Vec::with_capacity(params.d);

        for i in 0..params.d {
            let offset = i * per_layer;
            let wots_sig = bytes[offset..offset + wots_sig_len].to_vec();
            let mut auth = Vec::with_capacity(hp);
            for j in 0..hp {
                let auth_offset = offset + wots_sig_len + j * params.n;
                auth.push(bytes[auth_offset..auth_offset + params.n].to_vec());
            }
            layers.push((wots_sig, auth));
        }

        HtSignature { layers }
    }
}

/// Sign a message using the hypertree.
///
/// Algorithm 10 in FIPS 205.
/// `msg` is an n-byte root of the FORS tree.
/// `idx_tree` and `idx_leaf` specify the position in the hypertree.
pub fn ht_sign(
    params: &ParameterSet,
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
) -> HtSignature {
    let d = params.d;
    let hp = params.hp();
    let mut layers = Vec::with_capacity(d);

    let mut adrs = Adrs::new();

    // Bottom layer (layer 0)
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);
    let (sig_0, auth_0) = xmss::xmss_sign(params, msg, sk_seed, pk_seed, idx_leaf, &mut adrs);
    layers.push((sig_0.clone(), auth_0.clone()));

    // Compute the root of the bottom XMSS tree (= message for next layer)
    let mut root = xmss::xmss_pk_from_sig(params, &sig_0, msg, pk_seed, idx_leaf, &mut adrs, &auth_0);

    // Walk up the layers
    let mut current_tree = idx_tree;
    for layer in 1..d {
        // The leaf index in this layer = tree address of the layer below, mod 2^hp
        let leaf = (current_tree & ((1u64 << hp) - 1)) as u32;
        current_tree >>= hp;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(current_tree);

        let (sig_i, auth_i) = xmss::xmss_sign(params, &root, sk_seed, pk_seed, leaf, &mut adrs);
        root = xmss::xmss_pk_from_sig(params, &sig_i, &root, pk_seed, leaf, &mut adrs, &auth_i);
        layers.push((sig_i, auth_i));
    }

    HtSignature { layers }
}

/// Verify a hypertree signature.
///
/// Algorithm 11 in FIPS 205.
/// Returns true if the signature is valid.
pub fn ht_verify(
    params: &ParameterSet,
    msg: &[u8],
    ht_sig: &HtSignature,
    pk_seed: &[u8],
    pk_root: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
) -> bool {
    let d = params.d;
    let hp = params.hp();
    let mut adrs = Adrs::new();

    // Bottom layer
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);
    let (ref sig_0, ref auth_0) = ht_sig.layers[0];
    let mut node = xmss::xmss_pk_from_sig(params, sig_0, msg, pk_seed, idx_leaf, &mut adrs, auth_0);

    // Walk up
    let mut current_tree = idx_tree;
    for layer in 1..d {
        let leaf = (current_tree & ((1u64 << hp) - 1)) as u32;
        current_tree >>= hp;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(current_tree);

        let (ref sig_i, ref auth_i) = ht_sig.layers[layer];
        node = xmss::xmss_pk_from_sig(params, sig_i, &node, pk_seed, leaf, &mut adrs, auth_i);
    }

    node == pk_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::xmss;
    use crate::params::types::HashFamily;

    #[test]
    fn test_ht_sign_verify_small() {
        // Small params for fast testing: h=4, d=2, hp=2 (4 leaves per XMSS tree)
        let params = ParameterSet {
            n: 16, h: 4, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];

        // Compute the hypertree root (= top XMSS root)
        let mut adrs = Adrs::new();
        adrs.set_layer_address(1);
        adrs.set_tree_address(0);
        let hp = params.hp() as u32;
        let pk_root = xmss::xmss_node(&params, &sk_seed, &pk_seed, &mut adrs, hp, 0);

        // Sign
        let msg = vec![0xABu8; params.n];
        let idx_tree = 0u64;
        let idx_leaf = 1u32;
        let ht_sig = ht_sign(&params, &msg, &sk_seed, &pk_seed, idx_tree, idx_leaf);

        // Verify
        assert!(ht_verify(&params, &msg, &ht_sig, &pk_seed, &pk_root, idx_tree, idx_leaf));

        // Wrong message should fail
        let wrong_msg = vec![0xCDu8; params.n];
        assert!(!ht_verify(&params, &wrong_msg, &ht_sig, &pk_seed, &pk_root, idx_tree, idx_leaf));
    }

    #[test]
    fn test_ht_sign_verify_different_indices() {
        let params = ParameterSet {
            n: 16, h: 6, d: 3, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![3u8; params.n];
        let pk_seed = vec![4u8; params.n];

        // Compute root
        let mut adrs = Adrs::new();
        adrs.set_layer_address(2);
        adrs.set_tree_address(0);
        let hp = params.hp() as u32;
        let pk_root = xmss::xmss_node(&params, &sk_seed, &pk_seed, &mut adrs, hp, 0);

        let msg = vec![0x55u8; params.n];
        // Use different tree/leaf indices
        let idx_tree = 1u64;
        let idx_leaf = 3u32;
        let ht_sig = ht_sign(&params, &msg, &sk_seed, &pk_seed, idx_tree, idx_leaf);
        assert!(ht_verify(&params, &msg, &ht_sig, &pk_seed, &pk_root, idx_tree, idx_leaf));
    }

    #[test]
    fn test_ht_signature_serialization() {
        let params = ParameterSet {
            n: 16, h: 4, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let msg = vec![0xABu8; params.n];

        let ht_sig = ht_sign(&params, &msg, &sk_seed, &pk_seed, 0, 0);
        let bytes = ht_sig.to_bytes(&params);
        let expected_len = params.d * (params.len() * params.n + params.hp() * params.n);
        assert_eq!(bytes.len(), expected_len);

        let ht_sig2 = HtSignature::from_bytes(&params, &bytes);
        assert_eq!(ht_sig2.to_bytes(&params), bytes);
    }
}
