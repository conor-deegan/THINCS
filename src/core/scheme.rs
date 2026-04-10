/// Top-level keygen, sign, verify for stateless hash-based signatures.
///
/// Construction follows the SPHINCS+ round-3 submission (Bernstein et al.):
/// WOTS+ / XMSS / FORS / hypertree composition. This is NOT FIPS 205 SLH-DSA
/// at the top level — FIPS 205 Algorithm 22/23 prepends a domain separation
/// frame (context byte + length + context + message) before hashing. THINCS
/// hashes the raw message directly, matching the SPHINCS+ round-3 behaviour.
///
/// The tweakable hash primitives DO match FIPS 205 §11 byte-for-byte (verified
/// against the SPHINCS+ reference C in `sphincs/sphincsplus/ref`).
///
/// Accepts arbitrary runtime parameters rather than a fixed set.

use rand::RngCore;

use crate::core::address::{Adrs, FORS_TREE};
use crate::core::fors;
use crate::core::hypertree;
use crate::core::xmss;
use crate::hash;
use crate::params::types::ParameterSet;

pub struct KeyPair {
    pub sk_seed: Vec<u8>,   // n bytes
    pub sk_prf: Vec<u8>,    // n bytes
    pub pk_seed: Vec<u8>,   // n bytes
    pub pk_root: Vec<u8>,   // n bytes
}

impl KeyPair {
    /// Serialize the secret key (SK.seed || SK.prf || PK.seed || PK.root)
    pub fn secret_key(&self) -> Vec<u8> {
        let mut sk = Vec::with_capacity(self.sk_seed.len() * 4);
        sk.extend_from_slice(&self.sk_seed);
        sk.extend_from_slice(&self.sk_prf);
        sk.extend_from_slice(&self.pk_seed);
        sk.extend_from_slice(&self.pk_root);
        sk
    }

    /// Serialize the public key (PK.seed || PK.root)
    pub fn public_key(&self) -> Vec<u8> {
        let mut pk = Vec::with_capacity(self.pk_seed.len() * 2);
        pk.extend_from_slice(&self.pk_seed);
        pk.extend_from_slice(&self.pk_root);
        pk
    }
}

/// Signature: randomizer R, FORS signature, hypertree signature.
pub struct Signature {
    pub r: Vec<u8>,                         // n bytes (randomizer)
    pub fors_sig: fors::ForsSignature,
    pub ht_sig: hypertree::HtSignature,
}

impl Signature {
    /// Serialize the signature to bytes.
    pub fn to_bytes(&self, params: &ParameterSet) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.fors_sig.to_bytes(params));
        bytes.extend_from_slice(&self.ht_sig.to_bytes(params));
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(params: &ParameterSet, bytes: &[u8]) -> Self {
        let n = params.n;
        let r = bytes[0..n].to_vec();

        let fors_sig_len = params.k * (n + params.a * n);
        let fors_sig = fors::ForsSignature::from_bytes(params, &bytes[n..n + fors_sig_len]);

        let ht_sig_offset = n + fors_sig_len;
        let ht_sig = hypertree::HtSignature::from_bytes(params, &bytes[ht_sig_offset..]);

        Signature { r, fors_sig, ht_sig }
    }
}

/// Key generation.
///
/// Based on Algorithm 17 in FIPS 205.
pub fn keygen(params: &ParameterSet) -> KeyPair {
    let mut rng = rand::thread_rng();

    let mut sk_seed = vec![0u8; params.n];
    let mut sk_prf = vec![0u8; params.n];
    let mut pk_seed = vec![0u8; params.n];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut sk_prf);
    rng.fill_bytes(&mut pk_seed);

    keygen_from_seed(params, &sk_seed, &sk_prf, &pk_seed)
}

/// Deterministic key generation from seeds.
pub fn keygen_from_seed(
    params: &ParameterSet,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> KeyPair {
    // Compute the hypertree root
    let mut adrs = Adrs::new();
    adrs.set_layer_address((params.d - 1) as u32);
    adrs.set_tree_address(0);
    let hp = params.hp() as u32;
    let pk_root = xmss::xmss_node(params, sk_seed, pk_seed, &mut adrs, hp, 0);

    KeyPair {
        sk_seed: sk_seed.to_vec(),
        sk_prf: sk_prf.to_vec(),
        pk_seed: pk_seed.to_vec(),
        pk_root,
    }
}

/// Sign a message.
///
/// Based on Algorithm 18 in FIPS 205.
pub fn sign(
    params: &ParameterSet,
    msg: &[u8],
    keypair: &KeyPair,
) -> Signature {
    // Generate randomizer R
    let opt_rand = &keypair.pk_seed; // deterministic signing uses PK.seed
    let r = hash::prf_msg(params, &keypair.sk_prf, opt_rand, msg);

    // Compute message digest
    let digest = hash::h_msg(params, &r, &keypair.pk_seed, &keypair.pk_root, msg);

    // Extract FORS indices, tree index, leaf index
    let md = fors::message_to_indices(&digest, params.k, params.a);
    let (idx_tree, idx_leaf) = fors::message_to_tree_leaf(&digest, params);

    // Build the FORS address for this hypertree leaf.
    // FORS operates at layer 0 (bottom of the hypertree); the type-specific
    // fields carry the keypair_address (which leaf = which FORS instance).
    let mut fors_adrs = Adrs::new();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(idx_tree);
    fors_adrs.set_type(FORS_TREE);
    fors_adrs.set_keypair_address(idx_leaf);

    let fors_sig = fors::fors_sign(params, &md, &keypair.sk_seed, &keypair.pk_seed, &fors_adrs);

    // Compute FORS public key (= message for hypertree)
    let fors_pk = fors::fors_pk_from_sig(params, &fors_sig, &md, &keypair.pk_seed, &fors_adrs);

    // Hypertree sign
    let ht_sig = hypertree::ht_sign(params, &fors_pk, &keypair.sk_seed, &keypair.pk_seed, idx_tree, idx_leaf);

    Signature { r, fors_sig, ht_sig }
}

/// Verify a signature.
///
/// Based on Algorithm 19 in FIPS 205.
pub fn verify(
    params: &ParameterSet,
    msg: &[u8],
    sig: &Signature,
    pk_seed: &[u8],
    pk_root: &[u8],
) -> bool {
    // Recompute message digest
    let digest = hash::h_msg(params, &sig.r, pk_seed, pk_root, msg);

    // Extract FORS indices, tree index, leaf index
    let md = fors::message_to_indices(&digest, params.k, params.a);
    let (idx_tree, idx_leaf) = fors::message_to_tree_leaf(&digest, params);

    // Reconstruct FORS public key from signature
    let mut fors_adrs = Adrs::new();
    fors_adrs.set_layer_address(0);
    fors_adrs.set_tree_address(idx_tree);
    fors_adrs.set_type(FORS_TREE);
    fors_adrs.set_keypair_address(idx_leaf);
    let fors_pk = fors::fors_pk_from_sig(params, &sig.fors_sig, &md, pk_seed, &fors_adrs);

    // Verify hypertree signature
    hypertree::ht_verify(params, &fors_pk, &sig.ht_sig, pk_seed, pk_root, idx_tree, idx_leaf)
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

    #[test]
    fn test_keygen() {
        let params = small_params();
        let kp = keygen(&params);
        assert_eq!(kp.sk_seed.len(), params.n);
        assert_eq!(kp.pk_root.len(), params.n);
        assert_eq!(kp.secret_key().len(), 4 * params.n);
        assert_eq!(kp.public_key().len(), 2 * params.n);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let params = small_params();
        let kp = keygen(&params);
        let msg = b"Hello, THINCS!";
        let sig = sign(&params, msg, &kp);

        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_wrong_message_fails() {
        let params = small_params();
        let kp = keygen(&params);
        let msg = b"Hello, THINCS!";
        let sig = sign(&params, msg, &kp);

        assert!(!verify(&params, b"Wrong message", &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_deterministic_keygen() {
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let sk_prf = vec![2u8; params.n];
        let pk_seed = vec![3u8; params.n];
        let kp1 = keygen_from_seed(&params, &sk_seed, &sk_prf, &pk_seed);
        let kp2 = keygen_from_seed(&params, &sk_seed, &sk_prf, &pk_seed);
        assert_eq!(kp1.pk_root, kp2.pk_root);
    }

    #[test]
    fn test_deterministic_sign() {
        let params = small_params();
        let sk_seed = vec![1u8; params.n];
        let sk_prf = vec![2u8; params.n];
        let pk_seed = vec![3u8; params.n];
        let kp = keygen_from_seed(&params, &sk_seed, &sk_prf, &pk_seed);
        let msg = b"test";
        let sig1 = sign(&params, msg, &kp);
        let sig2 = sign(&params, msg, &kp);
        assert_eq!(sig1.to_bytes(&params), sig2.to_bytes(&params));
    }

    #[test]
    fn test_signature_serialization() {
        let params = small_params();
        let kp = keygen(&params);
        let msg = b"test serialization";
        let sig = sign(&params, msg, &kp);
        let bytes = sig.to_bytes(&params);

        let sig2 = Signature::from_bytes(&params, &bytes);
        assert_eq!(sig2.to_bytes(&params), bytes);

        // Re-verify with deserialized sig
        assert!(verify(&params, msg, &sig2, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_signature_size_matches_formula() {
        let params = small_params();
        let kp = keygen(&params);
        let sig = sign(&params, b"test", &kp);
        let sig_bytes = sig.to_bytes(&params);
        let expected = crate::cost::size::signature_size(&params);
        assert_eq!(sig_bytes.len(), expected,
            "actual sig size {} != formula {}", sig_bytes.len(), expected);
    }

    #[test]
    fn test_larger_params_roundtrip() {
        let params = ParameterSet {
            n: 16, h: 6, d: 3, w: 16, k: 5, a: 6, hash: HashFamily::Shake,
        };
        let kp = keygen(&params);
        let msg = b"larger params test";
        let sig = sign(&params, msg, &kp);
        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_w4_roundtrip() {
        let params = ParameterSet {
            n: 16, h: 4, d: 2, w: 4, k: 3, a: 4, hash: HashFamily::Shake,
        };
        let kp = keygen(&params);
        let msg = b"w=4 test";
        let sig = sign(&params, msg, &kp);
        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_w256_roundtrip() {
        let params = ParameterSet {
            n: 16, h: 4, d: 2, w: 256, k: 3, a: 4, hash: HashFamily::Shake,
        };
        let kp = keygen(&params);
        let msg = b"w=256 test";
        let sig = sign(&params, msg, &kp);
        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_sha2_roundtrip_n16() {
        let params = ParameterSet {
            n: 16, h: 6, d: 3, w: 16, k: 5, a: 6, hash: HashFamily::Sha2,
        };
        let kp = keygen(&params);
        let msg = b"sha2 n16 test";
        let sig = sign(&params, msg, &kp);
        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
        // Size must match the formula regardless of hash family.
        let sig_bytes = sig.to_bytes(&params);
        assert_eq!(sig_bytes.len(), crate::cost::size::signature_size(&params));
    }

    #[test]
    fn test_sha2_roundtrip_n24_uses_sha512_branch() {
        let params = ParameterSet {
            n: 24, h: 6, d: 3, w: 16, k: 5, a: 6, hash: HashFamily::Sha2,
        };
        let kp = keygen(&params);
        let msg = b"sha2 n24 test";
        let sig = sign(&params, msg, &kp);
        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_sha2_roundtrip_n32() {
        let params = ParameterSet {
            n: 32, h: 6, d: 3, w: 16, k: 5, a: 6, hash: HashFamily::Sha2,
        };
        let kp = keygen(&params);
        let msg = b"sha2 n32 test";
        let sig = sign(&params, msg, &kp);
        assert!(verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root));
    }

    #[test]
    fn test_sha2_and_shake_differ() {
        // Same structural parameters, different hash families must produce
        // different signatures.
        let shake = ParameterSet {
            n: 16, h: 4, d: 2, w: 16, k: 3, a: 4, hash: HashFamily::Shake,
        };
        let sha2 = ParameterSet {
            n: 16, h: 4, d: 2, w: 16, k: 3, a: 4, hash: HashFamily::Sha2,
        };
        let sk_seed = vec![1u8; 16];
        let sk_prf = vec![2u8; 16];
        let pk_seed = vec![3u8; 16];
        let kp_shake = keygen_from_seed(&shake, &sk_seed, &sk_prf, &pk_seed);
        let kp_sha2 = keygen_from_seed(&sha2, &sk_seed, &sk_prf, &pk_seed);
        // Different hash → different pk_root from the same seeds
        assert_ne!(kp_shake.pk_root, kp_sha2.pk_root);

        let msg = b"family separation";
        let sig_shake = sign(&shake, msg, &kp_shake);
        let sig_sha2 = sign(&sha2, msg, &kp_sha2);
        assert_ne!(
            sig_shake.to_bytes(&shake),
            sig_sha2.to_bytes(&sha2),
            "SHA-2 and SHAKE signatures must differ"
        );
    }

    #[test]
    fn test_signature_depends_on_all_seeds() {
        let base_params = ParameterSet {
            n: 16, h: 4, d: 2, w: 16, k: 3, a: 4, hash: HashFamily::Shake,
        };
        let msg = b"x";

        let base = keygen_from_seed(&base_params, &vec![1u8; 16], &vec![2u8; 16], &vec![3u8; 16]);
        let diff_sk = keygen_from_seed(&base_params, &vec![9u8; 16], &vec![2u8; 16], &vec![3u8; 16]);
        let diff_pk = keygen_from_seed(&base_params, &vec![1u8; 16], &vec![2u8; 16], &vec![9u8; 16]);

        assert_ne!(base.pk_root, diff_sk.pk_root);
        assert_ne!(base.pk_root, diff_pk.pk_root);

        let sig_base = sign(&base_params, msg, &base);
        let sig_diff_prf = {
            let kp = keygen_from_seed(&base_params, &vec![1u8; 16], &vec![9u8; 16], &vec![3u8; 16]);
            // Note: sk_prf affects the randomizer R, so sig should differ
            sign(&base_params, msg, &kp)
        };
        assert_ne!(
            sig_base.to_bytes(&base_params),
            sig_diff_prf.to_bytes(&base_params),
            "SK.prf must affect the signature via the randomizer R"
        );
    }
}
