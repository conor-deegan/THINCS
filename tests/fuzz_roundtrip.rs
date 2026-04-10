//! Property-style fuzz of the sign/verify roundtrip.
//!
//! Generates many random-but-valid parameter sets (small enough to run fast)
//! and random messages, then asserts that sign/verify always roundtrips,
//! that a perturbed message fails to verify, and that signature sizes match
//! the formula. Catches regressions that hand-picked tests miss.

use thincs::core::scheme;
use thincs::cost::size::signature_size;
use thincs::params::types::{HashFamily, ParameterSet};

/// Deterministic LCG so tests are reproducible without pulling in `rand`
/// for the test crate.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn range(&mut self, hi: usize) -> usize {
        (self.next() as usize) % hi
    }
}

fn random_small_params(rng: &mut Lcg, hash: HashFamily) -> ParameterSet {
    // Small parameter ranges so each iteration runs in < 100ms even for
    // the worst case.
    let n = [16, 24, 32][rng.range(3)];
    let hp = 1 + rng.range(4); // 1..=4
    let d = 1 + rng.range(3);  // 1..=3
    let h = hp * d;
    let w = [4, 16, 256][rng.range(3)];
    let k = 1 + rng.range(5);  // 1..=5
    let a = 1 + rng.range(6);  // 1..=6
    ParameterSet { n, h, d, w, k, a, hash }
}

fn random_message(rng: &mut Lcg, max_len: usize) -> Vec<u8> {
    let len = 1 + rng.range(max_len);
    let mut m = Vec::with_capacity(len);
    for _ in 0..len {
        m.push((rng.next() & 0xFF) as u8);
    }
    m
}

#[test]
fn fuzz_shake_roundtrip() {
    let mut rng = Lcg(0xDEAD_BEEF_CAFE_BABE);
    let iterations = 30;
    for i in 0..iterations {
        let params = random_small_params(&mut rng, HashFamily::Shake);
        if params.validate().is_err() {
            continue;
        }
        let kp = scheme::keygen(&params);
        let msg = random_message(&mut rng, 256);
        let sig = scheme::sign(&params, &msg, &kp);
        assert!(
            scheme::verify(&params, &msg, &sig, &kp.pk_seed, &kp.pk_root),
            "iteration {}: sign/verify failed for {}", i, params
        );
        let sig_bytes = sig.to_bytes(&params);
        assert_eq!(
            sig_bytes.len(),
            signature_size(&params),
            "iteration {}: sig size mismatch for {}", i, params
        );
        // Tamper the message and verify fails.
        let mut tampered = msg.clone();
        tampered[0] ^= 0x01;
        assert!(
            !scheme::verify(&params, &tampered, &sig, &kp.pk_seed, &kp.pk_root),
            "iteration {}: tampered message verified for {}", i, params
        );
    }
}

#[test]
fn fuzz_sha2_roundtrip() {
    let mut rng = Lcg(0xFEED_FACE_DEAD_BEEF);
    let iterations = 30;
    for i in 0..iterations {
        let params = random_small_params(&mut rng, HashFamily::Sha2);
        if params.validate().is_err() {
            continue;
        }
        let kp = scheme::keygen(&params);
        let msg = random_message(&mut rng, 256);
        let sig = scheme::sign(&params, &msg, &kp);
        assert!(
            scheme::verify(&params, &msg, &sig, &kp.pk_seed, &kp.pk_root),
            "iteration {}: sign/verify failed for {}", i, params
        );
        let sig_bytes = sig.to_bytes(&params);
        assert_eq!(sig_bytes.len(), signature_size(&params));
    }
}

#[test]
fn fuzz_empty_and_long_messages() {
    let params = ParameterSet {
        n: 16, h: 4, d: 2, w: 16, k: 3, a: 4, hash: HashFamily::Shake,
    };
    let kp = scheme::keygen(&params);

    // Empty message
    let sig = scheme::sign(&params, b"", &kp);
    assert!(scheme::verify(&params, b"", &sig, &kp.pk_seed, &kp.pk_root));

    // 1-byte message
    let sig = scheme::sign(&params, b"x", &kp);
    assert!(scheme::verify(&params, b"x", &sig, &kp.pk_seed, &kp.pk_root));

    // Long message (10 KB)
    let long = vec![0xAAu8; 10_000];
    let sig = scheme::sign(&params, &long, &kp);
    assert!(scheme::verify(&params, &long, &sig, &kp.pk_seed, &kp.pk_root));
}
