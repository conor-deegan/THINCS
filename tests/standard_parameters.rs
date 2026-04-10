//! End-to-end sign/verify for all 12 standard SLH-DSA parameter sets.
//!
//! These tests are marked `#[ignore]` because keygen for the `s` variants
//! is slow with our naive implementation (~minutes per run). Run with:
//!
//!     cargo test --test standard_parameters -- --ignored --test-threads=1
//!
//! Each test asserts:
//!   - The produced signature matches FIPS 205 Table 1 for signature size
//!   - Sign/verify roundtrips on a fixed message
//!   - A second sign with the same seeds produces an identical signature (determinism)
//!   - Verification of a tampered message fails

use thincs::core::scheme;
use thincs::cost::size::signature_size;
use thincs::params::types::{HashFamily, ParameterSet};

fn fixed_seeds() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // n=32 so the same seeds work for every variant after truncation.
    let sk_seed = (0u8..32).collect::<Vec<_>>();
    let sk_prf = (32u8..64).collect::<Vec<_>>();
    let pk_seed = (64u8..96).collect::<Vec<_>>();
    (sk_seed.clone(), sk_prf, pk_seed, sk_seed)
}

fn run_standard_test(params: ParameterSet, expected_sig_size: usize) {
    let (mut sk_seed, mut sk_prf, mut pk_seed, _) = fixed_seeds();
    sk_seed.truncate(params.n);
    sk_prf.truncate(params.n);
    pk_seed.truncate(params.n);

    let kp = scheme::keygen_from_seed(&params, &sk_seed, &sk_prf, &pk_seed);
    assert_eq!(kp.pk_root.len(), params.n, "pk_root has wrong length");

    let msg = b"THINCS standard parameter set regression test";
    let sig = scheme::sign(&params, msg, &kp);
    let sig_bytes = sig.to_bytes(&params);

    assert_eq!(
        sig_bytes.len(),
        expected_sig_size,
        "{}: signature size mismatch",
        params
    );
    assert_eq!(
        sig_bytes.len(),
        signature_size(&params),
        "sig_bytes.len() != size::signature_size(...)"
    );

    assert!(
        scheme::verify(&params, msg, &sig, &kp.pk_seed, &kp.pk_root),
        "{}: verification failed",
        params
    );

    // Determinism
    let sig2 = scheme::sign(&params, msg, &kp);
    assert_eq!(
        sig.to_bytes(&params),
        sig2.to_bytes(&params),
        "{}: signature is not deterministic",
        params
    );

    // Tamper resistance
    assert!(
        !scheme::verify(&params, b"different", &sig, &kp.pk_seed, &kp.pk_root),
        "{}: tampered message was accepted",
        params
    );
}

// ---- Fast variants (f) — run in a few seconds ----

#[test]
#[ignore]
fn slh_dsa_shake_128f() {
    run_standard_test(
        ParameterSet { n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake },
        17088,
    );
}

#[test]
#[ignore]
fn slh_dsa_shake_192f() {
    run_standard_test(
        ParameterSet { n: 24, h: 66, d: 22, w: 16, k: 33, a: 8, hash: HashFamily::Shake },
        35664,
    );
}

#[test]
#[ignore]
fn slh_dsa_shake_256f() {
    run_standard_test(
        ParameterSet { n: 32, h: 68, d: 17, w: 16, k: 35, a: 9, hash: HashFamily::Shake },
        49856,
    );
}

#[test]
#[ignore]
fn slh_dsa_sha2_128f() {
    run_standard_test(
        ParameterSet { n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Sha2 },
        17088,
    );
}

#[test]
#[ignore]
fn slh_dsa_sha2_192f() {
    run_standard_test(
        ParameterSet { n: 24, h: 66, d: 22, w: 16, k: 33, a: 8, hash: HashFamily::Sha2 },
        35664,
    );
}

#[test]
#[ignore]
fn slh_dsa_sha2_256f() {
    run_standard_test(
        ParameterSet { n: 32, h: 68, d: 17, w: 16, k: 35, a: 9, hash: HashFamily::Sha2 },
        49856,
    );
}

// ---- Slow variants (s) — minutes each with the naive implementation ----

#[test]
#[ignore]
fn slh_dsa_shake_128s() {
    run_standard_test(
        ParameterSet { n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake },
        7856,
    );
}

#[test]
#[ignore]
fn slh_dsa_shake_192s() {
    run_standard_test(
        ParameterSet { n: 24, h: 63, d: 7, w: 16, k: 17, a: 14, hash: HashFamily::Shake },
        16224,
    );
}

#[test]
#[ignore]
fn slh_dsa_shake_256s() {
    run_standard_test(
        ParameterSet { n: 32, h: 64, d: 8, w: 16, k: 22, a: 14, hash: HashFamily::Shake },
        29792,
    );
}

#[test]
#[ignore]
fn slh_dsa_sha2_128s() {
    run_standard_test(
        ParameterSet { n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Sha2 },
        7856,
    );
}

#[test]
#[ignore]
fn slh_dsa_sha2_192s() {
    run_standard_test(
        ParameterSet { n: 24, h: 63, d: 7, w: 16, k: 17, a: 14, hash: HashFamily::Sha2 },
        16224,
    );
}

#[test]
#[ignore]
fn slh_dsa_sha2_256s() {
    run_standard_test(
        ParameterSet { n: 32, h: 64, d: 8, w: 16, k: 22, a: 14, hash: HashFamily::Sha2 },
        29792,
    );
}
