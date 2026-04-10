use crate::params::types::ParameterSet;

#[derive(Debug, Clone)]
pub struct SecurityEstimate {
    /// Classical security level in bits
    pub classical_bits: f64,
    /// Quantum security level in bits (Grover-adjusted)
    pub quantum_bits: f64,
    /// FORS security after Q signatures (bits)
    pub fors_bits_after_q: f64,
    /// WOTS+ security (bits, quantum)
    pub wots_bits: f64,
    /// Hash function generic security (bits, quantum)
    pub hash_bits: f64,
    /// Which component is the weakest link
    pub binding_component: String,
}

/// Estimate concrete security of a parameter set after `num_signatures` signing queries.
///
/// Simplified approximations of the bounds from:
///   - Bernstein et al., "SPHINCS+" submission, Sections 3–9
///     (https://sphincs.org/data/sphincs+-r3.1-specification.pdf)
///   - NIST FIPS 205, Section 9
///
/// These estimates are suitable for parameter comparison, not formal security proofs.
/// The full SPHINCS+ security reduction (Theorem 1) involves tighter multi-game
/// bounds than what is implemented here.
pub fn estimate_security(params: &ParameterSet, num_signatures: u64) -> SecurityEstimate {
    let n = params.n as f64;
    let h = params.h as f64;
    let d = params.d as f64;
    let k = params.k as f64;
    let a = params.a as f64;
    let w = params.w as f64;
    let len = params.len() as f64;

    // Hash function generic security.
    // Classical preimage resistance: 2^(n*8).
    // Quantum preimage via Grover: 2^(n*4).
    let hash_classical = n * 8.0;
    let hash_quantum = n * 4.0;

    // WOTS+ security (Bernstein et al., Section 3.3).
    // Single-instance classical: n*8 - lg(len*(w-1)) bits.
    // The len*(w-1) term accounts for the multi-target within one WOTS+ instance
    // (len chains, each offering up to w-1 inversion targets).
    //
    // Hypertree multi-target: the adversary can target any of d*2^h' WOTS+ positions
    // in the tree structure with a forged message, subtracting lg(d) + h'.
    //
    // Quantum: capped at hash_quantum (Grover on chain step inversion).
    let hp = h / d;
    let wots_single = n * 8.0 - (len * (w - 1.0)).log2();
    let wots_classical = wots_single - hp - d.log2();
    let wots_quantum = if wots_classical > 0.0 {
        wots_classical.min(hash_quantum)
    } else {
        0.0
    };

    // FORS security (Bernstein et al., Section 4).
    // Each FORS instance provides k*a bits of information-theoretic security.
    // After Q signing queries, the adversary observes Q random subsets of FORS
    // leaves. Security degrades by lg(Q): the adversary has Q chances to find
    // a message whose FORS indices land on already-revealed leaves.
    //
    // Quantum advantage is minimal because the attack is combinatorial
    // (requires the right leaves to have been revealed), not computational.
    let q = if num_signatures == 0 { 1.0 } else { num_signatures as f64 };
    let lg_q = q.log2();
    let fors_classical = k * a - lg_q;
    let fors_quantum = k * a - lg_q;

    // Combined: minimum across all components determines overall security.
    let classical_bits = fors_classical.min(wots_classical).min(hash_classical);
    let quantum_bits = fors_quantum.min(wots_quantum).min(hash_quantum);

    let binding_component = if quantum_bits == fors_quantum {
        "FORS".to_string()
    } else if quantum_bits == wots_quantum {
        "WOTS+".to_string()
    } else {
        "Hash".to_string()
    };

    SecurityEstimate {
        classical_bits,
        quantum_bits,
        fors_bits_after_q: fors_quantum,
        wots_bits: wots_quantum,
        hash_bits: hash_quantum,
        binding_component,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::{HashFamily, ParameterSet};

    // Standard SLH-DSA parameter sets from FIPS 205 Table 1.
    // At Q=2^64, quantum security should match NIST security levels:
    //   Level 1: 64 quantum bits (n=16)
    //   Level 3: 96 quantum bits (n=24)
    //   Level 5: 128 quantum bits (n=32)

    #[test]
    fn test_128s_security_at_design_target() {
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let est = estimate_security(&params, 1u64 << 40);
        // n=16 → hash_quantum = 64, should cap quantum security at 64
        assert!((est.quantum_bits - 64.0).abs() < 2.0,
            "128s quantum security {:.1} should be ~64 bits", est.quantum_bits);
        assert!(est.classical_bits > 100.0,
            "128s classical security {:.1} should exceed 100 bits", est.classical_bits);
    }

    #[test]
    fn test_192s_security_at_design_target() {
        let params = ParameterSet {
            n: 24, h: 63, d: 7, w: 16, k: 17, a: 14, hash: HashFamily::Shake,
        };
        let est = estimate_security(&params, 1u64 << 40);
        assert!((est.quantum_bits - 96.0).abs() < 2.0,
            "192s quantum security {:.1} should be ~96 bits", est.quantum_bits);
    }

    #[test]
    fn test_256s_security_at_design_target() {
        let params = ParameterSet {
            n: 32, h: 64, d: 8, w: 16, k: 22, a: 14, hash: HashFamily::Shake,
        };
        let est = estimate_security(&params, 1u64 << 40);
        assert!((est.quantum_bits - 128.0).abs() < 2.0,
            "256s quantum security {:.1} should be ~128 bits", est.quantum_bits);
    }

    #[test]
    fn test_security_decreases_with_more_signatures() {
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let est_few = estimate_security(&params, 1000);
        let est_many = estimate_security(&params, 1_000_000_000);
        // FORS security decreases with more signatures
        assert!(est_few.fors_bits_after_q > est_many.fors_bits_after_q);
        // Overall security should not increase
        assert!(est_few.quantum_bits >= est_many.quantum_bits);
    }

    #[test]
    fn test_larger_n_gives_more_security() {
        let small = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let large = ParameterSet {
            n: 32, h: 64, d: 8, w: 16, k: 22, a: 14, hash: HashFamily::Shake,
        };
        let est_small = estimate_security(&small, 1_000_000);
        let est_large = estimate_security(&large, 1_000_000);
        assert!(est_large.quantum_bits > est_small.quantum_bits);
    }

    #[test]
    fn test_binding_component_is_fors_for_small_ka() {
        // With small k*a and large Q, FORS should be the binding component
        let params = ParameterSet {
            n: 32, h: 64, d: 8, w: 16, k: 5, a: 5, hash: HashFamily::Shake,
        };
        let est = estimate_security(&params, 1u64 << 20);
        assert_eq!(est.binding_component, "FORS",
            "with k*a=25 and Q=2^20, FORS ({:.1}) should bind", est.fors_bits_after_q);
    }
}
