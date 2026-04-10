/// XMSS (eXtended Merkle Signature Scheme) — a single layer of the hypertree.
///
/// Per FIPS 205 §6. An XMSS tree of height hp = h/d with 2^hp WOTS+ keypairs
/// as leaves. The root is a Merkle hash of the WOTS+ public keys.

use crate::core::address::{Adrs, TREE, WOTS_HASH};
use crate::core::wots;
use crate::hash;
use crate::params::types::ParameterSet;

/// Compute a node in the XMSS Merkle tree.
///
/// Algorithm 7 in FIPS 205.
/// Computes the root of the subtree at (tree_height, tree_index) within
/// the XMSS tree. At height 0, leaves are WOTS+ public keys.
pub fn xmss_node(
    params: &ParameterSet,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    height: u32,
    index: u32,
) -> Vec<u8> {
    if height == 0 {
        // Leaf node: WOTS+ public key
        adrs.set_type(WOTS_HASH);
        adrs.set_keypair_address(index);
        return wots::wots_pk_gen(params, sk_seed, pk_seed, adrs);
    }

    // Internal node: hash of left and right children
    let left = xmss_node(params, sk_seed, pk_seed, adrs, height - 1, 2 * index);
    let right = xmss_node(params, sk_seed, pk_seed, adrs, height - 1, 2 * index + 1);

    adrs.set_type(TREE);
    adrs.set_tree_height(height);
    adrs.set_tree_index(index);
    hash::hash_h(params, pk_seed, adrs, &left, &right)
}

/// Sign a message digest using XMSS at a given leaf index.
///
/// Algorithm 8 in FIPS 205.
/// Returns (WOTS+ signature, authentication path).
/// The authentication path is hp nodes, each n bytes.
pub fn xmss_sign(
    params: &ParameterSet,
    msg: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx: u32,
    adrs: &mut Adrs,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let hp = params.hp();

    // WOTS+ sign at leaf idx
    adrs.set_type(WOTS_HASH);
    adrs.set_keypair_address(idx);
    let sig = wots::wots_sign(params, msg, sk_seed, pk_seed, adrs);

    // Build authentication path
    let mut auth = Vec::with_capacity(hp);
    for j in 0..hp {
        // Sibling of the node on the path at height j
        let sibling_idx = (idx >> j) ^ 1;
        let node = xmss_node(params, sk_seed, pk_seed, adrs, j as u32, sibling_idx);
        auth.push(node);
    }

    (sig, auth)
}

/// Compute XMSS root from a WOTS+ signature and authentication path.
///
/// Algorithm 9 in FIPS 205.
/// Used during verification to reconstruct the XMSS tree root.
pub fn xmss_pk_from_sig(
    params: &ParameterSet,
    wots_sig: &[u8],
    msg: &[u8],
    pk_seed: &[u8],
    idx: u32,
    adrs: &mut Adrs,
    auth: &[Vec<u8>],
) -> Vec<u8> {
    let hp = params.hp();

    // Reconstruct WOTS+ public key from signature
    adrs.set_type(WOTS_HASH);
    adrs.set_keypair_address(idx);
    let mut node = wots::wots_pk_from_sig(params, wots_sig, msg, pk_seed, adrs);

    // Walk up the authentication path
    adrs.set_type(TREE);
    for j in 0..hp {
        adrs.set_tree_height((j + 1) as u32);
        let parent_idx = idx >> (j + 1);
        adrs.set_tree_index(parent_idx);

        if (idx >> j) & 1 == 0 {
            // node is left child
            node = hash::hash_h(params, pk_seed, adrs, &node, &auth[j]);
        } else {
            // node is right child
            node = hash::hash_h(params, pk_seed, adrs, &auth[j], &node);
        }
    }

    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::HashFamily;

    #[test]
    fn test_xmss_node_leaf() {
        let params = ParameterSet {
            n: 16, h: 8, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let mut adrs = Adrs::new();

        let leaf = xmss_node(&params, &sk_seed, &pk_seed, &mut adrs, 0, 0);
        assert_eq!(leaf.len(), params.n);
    }

    #[test]
    fn test_xmss_sign_verify_roundtrip() {
        let params = ParameterSet {
            n: 16, h: 8, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let msg = vec![0xABu8; params.n];

        let mut adrs = Adrs::new();
        adrs.set_layer_address(0);
        adrs.set_tree_address(0);

        // Compute tree root
        let hp = params.hp() as u32;
        let root = xmss_node(&params, &sk_seed, &pk_seed, &mut adrs.clone(), hp, 0);

        // Sign at leaf index 2
        let idx = 2u32;
        let (sig, auth) = xmss_sign(&params, &msg, &sk_seed, &pk_seed, idx, &mut adrs.clone());

        // Verify
        let reconstructed = xmss_pk_from_sig(&params, &sig, &msg, &pk_seed, idx, &mut adrs.clone(), &auth);
        assert_eq!(root, reconstructed);
    }

    #[test]
    fn test_xmss_wrong_message_fails() {
        let params = ParameterSet {
            n: 16, h: 8, d: 2, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let msg = vec![0xABu8; params.n];

        let adrs = Adrs::new();
        let hp = params.hp() as u32;
        let root = xmss_node(&params, &sk_seed, &pk_seed, &mut adrs.clone(), hp, 0);

        let idx = 0u32;
        let (sig, auth) = xmss_sign(&params, &msg, &sk_seed, &pk_seed, idx, &mut adrs.clone());

        let wrong_msg = vec![0xCDu8; params.n];
        let reconstructed = xmss_pk_from_sig(&params, &sig, &wrong_msg, &pk_seed, idx, &mut adrs.clone(), &auth);
        assert_ne!(root, reconstructed);
    }
}
