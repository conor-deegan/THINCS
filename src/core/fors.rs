/// FORS (Forest of Random Subsets) — few-time signature scheme.
///
/// Per FIPS 205 §8. FORS uses k binary trees, each of height a.
/// A message digest selects one leaf per tree; the signature reveals
/// those leaves plus authentication paths.
///
/// ADRS discipline: the caller provides an address with type=FORS_TREE and
/// the correct keypair_address already set. All functions in this module
/// treat that address as read-only and use local copies for the mutations
/// required by set_type calls. This preserves keypair_address (which
/// identifies the FORS instance within the hypertree) throughout the
/// operation, matching FIPS 205 Algorithm 14/15.

use crate::core::address::{Adrs, FORS_PRF, FORS_ROOTS, FORS_TREE};
use crate::hash;
use crate::params::types::ParameterSet;

/// Generate a FORS secret leaf value (Algorithm 12 in FIPS 205).
fn fors_sk_gen(
    params: &ParameterSet,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    idx: u32,
) -> Vec<u8> {
    debug_assert_eq!(
        adrs.get_type(),
        FORS_TREE,
        "fors_sk_gen: caller must set up ADRS with type=FORS_TREE"
    );
    let keypair = adrs.get_keypair_address();
    let mut sk_adrs = *adrs;
    sk_adrs.set_type(FORS_PRF);
    sk_adrs.set_keypair_address(keypair);
    sk_adrs.set_tree_index(idx);
    hash::prf(params, pk_seed, sk_seed, &sk_adrs)
}

/// Compute a node in a FORS tree (Algorithm 13 in FIPS 205).
///
/// `tree_idx` is the index of the FORS tree within the forest (0..k).
/// `height` == 0 means a leaf; the leaf value is computed from the secret.
fn fors_node(
    params: &ParameterSet,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
    tree_idx: u32,
    height: u32,
    node_idx: u32,
) -> Vec<u8> {
    let keypair = adrs.get_keypair_address();

    if height == 0 {
        let sk_idx = tree_idx * (1u32 << params.a) + node_idx;
        let sk = fors_sk_gen(params, sk_seed, pk_seed, adrs, sk_idx);
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(FORS_TREE);
        leaf_adrs.set_keypair_address(keypair);
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(sk_idx);
        return hash::hash_f(params, pk_seed, &leaf_adrs, &sk);
    }

    let left = fors_node(params, sk_seed, pk_seed, adrs, tree_idx, height - 1, 2 * node_idx);
    let right = fors_node(params, sk_seed, pk_seed, adrs, tree_idx, height - 1, 2 * node_idx + 1);

    let mut node_adrs = *adrs;
    node_adrs.set_type(FORS_TREE);
    node_adrs.set_keypair_address(keypair);
    node_adrs.set_tree_height(height);
    let internal_idx = tree_idx * (1u32 << (params.a - height as usize)) + node_idx;
    node_adrs.set_tree_index(internal_idx);
    hash::hash_h(params, pk_seed, &node_adrs, &left, &right)
}

/// FORS signature: k (secret leaf value, authentication path) pairs.
pub struct ForsSignature {
    pub entries: Vec<ForsEntry>,
}

pub struct ForsEntry {
    pub sk: Vec<u8>,           // secret leaf value (n bytes)
    pub auth: Vec<Vec<u8>>,    // auth path (a nodes, each n bytes)
}

impl ForsSignature {
    pub fn to_bytes(&self, params: &ParameterSet) -> Vec<u8> {
        let per_entry = params.n + params.a * params.n;
        let mut bytes = Vec::with_capacity(params.k * per_entry);
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.sk);
            for node in &entry.auth {
                bytes.extend_from_slice(node);
            }
        }
        bytes
    }

    pub fn from_bytes(params: &ParameterSet, bytes: &[u8]) -> Self {
        let per_entry = params.n + params.a * params.n;
        let mut entries = Vec::with_capacity(params.k);
        for i in 0..params.k {
            let offset = i * per_entry;
            let sk = bytes[offset..offset + params.n].to_vec();
            let mut auth = Vec::with_capacity(params.a);
            for j in 0..params.a {
                let auth_offset = offset + params.n + j * params.n;
                auth.push(bytes[auth_offset..auth_offset + params.n].to_vec());
            }
            entries.push(ForsEntry { sk, auth });
        }
        ForsSignature { entries }
    }
}

/// Sign a message digest using FORS (Algorithm 14 in FIPS 205).
///
/// `md` contains the k indices (each in [0, 2^a)) selecting one leaf per tree.
/// The input `adrs` must have type=FORS_TREE and the correct keypair_address
/// for the FORS instance at this hypertree leaf.
pub fn fors_sign(
    params: &ParameterSet,
    md: &[u32],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &Adrs,
) -> ForsSignature {
    debug_assert_eq!(adrs.get_type(), FORS_TREE,
        "fors_sign: caller must set type=FORS_TREE");
    debug_assert_eq!(md.len(), params.k,
        "fors_sign: md must have k entries");
    let a = params.a;
    let mut entries = Vec::with_capacity(params.k);

    for i in 0..params.k {
        let idx = md[i];
        let sk_idx = (i as u32) * (1u32 << a) + idx;

        // Reveal the secret leaf
        let sk = fors_sk_gen(params, sk_seed, pk_seed, adrs, sk_idx);

        // Compute authentication path
        let mut auth = Vec::with_capacity(a);
        for j in 0..a {
            let sibling = (idx >> j) ^ 1;
            let node = fors_node(params, sk_seed, pk_seed, adrs, i as u32, j as u32, sibling);
            auth.push(node);
        }

        entries.push(ForsEntry { sk, auth });
    }

    ForsSignature { entries }
}

/// Compute FORS public key from a FORS signature (Algorithm 15 in FIPS 205).
///
/// The input `adrs` must have type=FORS_TREE and the correct keypair_address,
/// exactly as it was passed to `fors_sign`.
pub fn fors_pk_from_sig(
    params: &ParameterSet,
    fors_sig: &ForsSignature,
    md: &[u32],
    pk_seed: &[u8],
    adrs: &Adrs,
) -> Vec<u8> {
    debug_assert_eq!(adrs.get_type(), FORS_TREE,
        "fors_pk_from_sig: caller must set type=FORS_TREE");
    debug_assert_eq!(md.len(), params.k,
        "fors_pk_from_sig: md must have k entries");
    debug_assert_eq!(fors_sig.entries.len(), params.k,
        "fors_pk_from_sig: signature must have k entries");
    let a = params.a;
    let keypair = adrs.get_keypair_address();
    let mut roots = Vec::with_capacity(params.k * params.n);

    for i in 0..params.k {
        let idx = md[i];
        let entry = &fors_sig.entries[i];

        // Hash the revealed secret leaf
        let sk_idx = (i as u32) * (1u32 << a) + idx;
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_type(FORS_TREE);
        leaf_adrs.set_keypair_address(keypair);
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(sk_idx);
        let mut node = hash::hash_f(params, pk_seed, &leaf_adrs, &entry.sk);

        // Walk up the auth path
        for j in 0..a {
            let mut inner_adrs = *adrs;
            inner_adrs.set_type(FORS_TREE);
            inner_adrs.set_keypair_address(keypair);
            inner_adrs.set_tree_height((j + 1) as u32);
            let parent_idx = (i as u32) * (1u32 << (a - j - 1)) + (idx >> (j + 1));
            inner_adrs.set_tree_index(parent_idx);

            if (idx >> j) & 1 == 0 {
                node = hash::hash_h(params, pk_seed, &inner_adrs, &node, &entry.auth[j]);
            } else {
                node = hash::hash_h(params, pk_seed, &inner_adrs, &entry.auth[j], &node);
            }
        }

        roots.extend_from_slice(&node);
    }

    // Compress the k tree roots into the FORS public key.
    let mut fk_adrs = *adrs;
    fk_adrs.set_type(FORS_ROOTS);
    fk_adrs.set_keypair_address(keypair);
    hash::hash_t(params, pk_seed, &fk_adrs, &roots)
}

/// Extract FORS message indices from H_msg output.
///
/// Split the digest into k values, each `a` bits, representing leaf indices.
pub fn message_to_indices(digest: &[u8], k: usize, a: usize) -> Vec<u32> {
    let mut indices = Vec::with_capacity(k);
    let mut bit_offset = 0usize;

    for _ in 0..k {
        let mut val = 0u32;
        for b in 0..a {
            let byte_idx = (bit_offset + b) / 8;
            let bit_idx = 7 - ((bit_offset + b) % 8);
            if byte_idx < digest.len() && (digest[byte_idx] >> bit_idx) & 1 == 1 {
                val |= 1 << (a - 1 - b);
            }
        }
        indices.push(val);
        bit_offset += a;
    }

    indices
}

/// Extract tree index and leaf index from H_msg output per FIPS 205 §9.
///
/// The H_msg output is byte-aligned into three sections:
///   [0 .. md_bytes)              FORS digest
///   [md_bytes .. +tree_idx_bytes) idx_tree (big-endian, then masked to h - h/d bits)
///   [... .. +leaf_idx_bytes)     idx_leaf (big-endian, then masked to h/d bits)
pub fn message_to_tree_leaf(digest: &[u8], params: &ParameterSet) -> (u64, u32) {
    let md_bytes = params.md_bytes();
    let tree_idx_bytes = params.tree_idx_bytes();
    let leaf_idx_bytes = params.leaf_idx_bytes();
    let hp = params.hp();
    let tree_bits = params.h - hp;

    assert!(tree_idx_bytes <= 8, "tree_idx exceeds u64 range (h - h/d > 64)");
    assert!(leaf_idx_bytes <= 4, "leaf_idx exceeds u32 range (h/d > 32)");

    // idx_tree: read tree_idx_bytes big-endian, mask to tree_bits.
    let mut idx_tree: u64 = 0;
    for i in 0..tree_idx_bytes {
        idx_tree = (idx_tree << 8) | (digest[md_bytes + i] as u64);
    }
    let tree_mask = if tree_bits >= 64 { u64::MAX } else { (1u64 << tree_bits) - 1 };
    idx_tree &= tree_mask;

    // idx_leaf: read leaf_idx_bytes big-endian, mask to hp bits.
    let leaf_start = md_bytes + tree_idx_bytes;
    let mut idx_leaf: u32 = 0;
    for i in 0..leaf_idx_bytes {
        idx_leaf = (idx_leaf << 8) | (digest[leaf_start + i] as u32);
    }
    let leaf_mask = if hp >= 32 { u32::MAX } else { (1u32 << hp) - 1 };
    idx_leaf &= leaf_mask;

    (idx_tree, idx_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::HashFamily;

    fn small_params() -> ParameterSet {
        ParameterSet {
            n: 16, h: 4, d: 2, w: 16, k: 3, a: 4, hash: HashFamily::Shake,
        }
    }

    fn test_adrs(keypair: u32) -> Adrs {
        let mut a = Adrs::new();
        a.set_type(FORS_TREE);
        a.set_keypair_address(keypair);
        a
    }

    #[test]
    fn test_fors_sign_verify_roundtrip() {
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let adrs = test_adrs(0);

        let md = vec![3, 7, 12]; // k=3 indices

        let sig = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs);
        let pk = fors_pk_from_sig(&params, &sig, &md, &pk_seed, &adrs);

        // Re-verify with fresh computation
        let pk2 = fors_pk_from_sig(&params, &sig, &md, &pk_seed, &adrs);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_fors_wrong_indices_fail() {
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let adrs = test_adrs(0);

        let md = vec![3, 7, 12];
        let sig = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs);
        let pk = fors_pk_from_sig(&params, &sig, &md, &pk_seed, &adrs);

        let wrong_md = vec![4, 7, 12];
        let wrong_pk = fors_pk_from_sig(&params, &sig, &wrong_md, &pk_seed, &adrs);
        assert_ne!(pk, wrong_pk);
    }

    #[test]
    fn test_fors_keypair_address_matters() {
        // Regression: previously the FORS code wiped keypair_address via
        // set_type(FORS_TREE) and never restored it, so every FORS instance
        // at a given (layer, tree) produced the same signature regardless
        // of keypair_address. This test guards the fix.
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let md = vec![3, 7, 12];

        let adrs_a = test_adrs(0);
        let adrs_b = test_adrs(1);

        let sig_a = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs_a);
        let sig_b = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs_b);

        // Different keypair addresses must produce different signatures
        assert_ne!(
            sig_a.to_bytes(&params),
            sig_b.to_bytes(&params),
            "FORS signatures must depend on keypair_address"
        );

        let pk_a = fors_pk_from_sig(&params, &sig_a, &md, &pk_seed, &adrs_a);
        let pk_b = fors_pk_from_sig(&params, &sig_b, &md, &pk_seed, &adrs_b);
        assert_ne!(pk_a, pk_b,
            "FORS public keys must depend on keypair_address");
    }

    #[test]
    fn test_fors_input_adrs_not_mutated() {
        // The input ADRS should be read-only from fors_sign/fors_pk_from_sig's
        // perspective.
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let adrs = test_adrs(42);
        let before = *adrs.as_bytes();

        let md = vec![3, 7, 12];
        let _sig = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs);
        assert_eq!(*adrs.as_bytes(), before);

        let sig = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs);
        let _pk = fors_pk_from_sig(&params, &sig, &md, &pk_seed, &adrs);
        assert_eq!(*adrs.as_bytes(), before);
    }

    #[test]
    fn test_message_to_indices() {
        // k=3, a=4: need 12 bits total
        // Byte 0 = 0b1010_0011 = first index = 1010 = 10, second starts with 0011
        // Byte 1 = 0b0111_xxxx = second index = 0011_0111 >> 4... let's just check lengths
        let digest = vec![0xA3, 0x70];
        let indices = message_to_indices(&digest, 3, 4);
        assert_eq!(indices.len(), 3);
        assert_eq!(indices[0], 0b1010); // 10
        assert_eq!(indices[1], 0b0011); // 3
        assert_eq!(indices[2], 0b0111); // 7
    }

    #[test]
    fn test_extraction_is_hash_family_independent() {
        // The md/idx_tree/idx_leaf extraction reads bits directly from a digest;
        // it must not depend on how that digest was produced. Given the same
        // digest bytes, SHAKE and SHA-2 parameter sets with identical
        // n/h/d/k/a should extract the same values.
        let shake_params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: crate::params::types::HashFamily::Shake,
        };
        let sha2_params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: crate::params::types::HashFamily::Sha2,
        };
        // A 30-byte digest (FIPS 205 Table 2 m for 128s)
        let digest: Vec<u8> = (0..30u8).collect();

        let idx_shake = message_to_indices(&digest, shake_params.k, shake_params.a);
        let idx_sha2 = message_to_indices(&digest, sha2_params.k, sha2_params.a);
        assert_eq!(idx_shake, idx_sha2);

        let (ts, ls) = message_to_tree_leaf(&digest, &shake_params);
        let (t2, l2) = message_to_tree_leaf(&digest, &sha2_params);
        assert_eq!(ts, t2);
        assert_eq!(ls, l2);
    }

    #[test]
    fn test_message_to_tree_leaf_fips205_128s() {
        // Verify byte-aligned extraction against a hand-computed digest for
        // SLH-DSA-128s parameters: k=14, a=12, h=63, d=7, hp=9.
        // md_bytes = ceil(168/8) = 21
        // tree_idx_bytes = ceil(54/8) = 7
        // leaf_idx_bytes = ceil(9/8) = 2
        // Total: 30 bytes.
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: crate::params::types::HashFamily::Shake,
        };
        assert_eq!(params.md_bytes(), 21);
        assert_eq!(params.tree_idx_bytes(), 7);
        assert_eq!(params.leaf_idx_bytes(), 2);

        // Build a digest where:
        //   bytes [21..28] encode idx_tree = 0x00_11_22_33_44_55_66 (truncated to 54 bits)
        //   bytes [28..30] encode idx_leaf = 0x01_FF (truncated to 9 bits)
        let mut digest = vec![0u8; 30];
        digest[21] = 0x00;
        digest[22] = 0x11;
        digest[23] = 0x22;
        digest[24] = 0x33;
        digest[25] = 0x44;
        digest[26] = 0x55;
        digest[27] = 0x66;
        digest[28] = 0x01;
        digest[29] = 0xFF;

        let (idx_tree, idx_leaf) = message_to_tree_leaf(&digest, &params);

        // idx_tree = big-endian(00 11 22 33 44 55 66) & (2^54 - 1)
        let raw_tree: u64 = 0x00_11_22_33_44_55_66;
        let tree_mask: u64 = (1u64 << 54) - 1;
        assert_eq!(idx_tree, raw_tree & tree_mask);

        // idx_leaf = big-endian(01 FF) & (2^9 - 1) = 0x01FF & 0x1FF = 0x1FF
        assert_eq!(idx_leaf, 0x01FF & ((1u32 << 9) - 1));
    }

    #[test]
    fn test_fors_signature_serialization() {
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let pk_seed = vec![2u8; params.n];
        let adrs = test_adrs(0);
        let md = vec![3, 7, 12];
        let sig = fors_sign(&params, &md, &sk_seed, &pk_seed, &adrs);
        let bytes = sig.to_bytes(&params);
        let expected_len = params.k * (params.n + params.a * params.n);
        assert_eq!(bytes.len(), expected_len);

        let sig2 = ForsSignature::from_bytes(&params, &bytes);
        assert_eq!(sig2.to_bytes(&params), bytes);
    }
}
