/// Analysis of collision probability for stateless hash-based signing.
///
/// In stateless mode, the leaf index is derived pseudorandomly.
/// The birthday paradox governs the probability of index collisions.
///
/// Note: this measures leaf index reuse in the hypertree (birthday bound over
/// 2^h leaf slots). FORS security (k*a - lg(Q)) separately accounts for the
/// multi-query degradation from observing multiple FORS signatures. Both
/// metrics contribute to overall scheme security.

#[derive(Debug, Clone)]
pub struct CollisionAnalysis {
    /// Expected number of collisions (Q^2 / (2 * 2^h))
    pub expected_collisions: f64,
    /// Probability of at least one collision: 1 - e^(-Q^2 / (2 * 2^h))
    pub collision_probability: f64,
    /// How far below the birthday bound: 2^h / Q^2
    pub safe_margin_factor: f64,
}

/// Analyse collision probability for `num_signatures` stateless signatures
/// with a hypertree of height `h` (2^h leaf slots).
pub fn analyse_collisions(h: usize, num_signatures: u64) -> CollisionAnalysis {
    let q = num_signatures as f64;
    let total_leaves = 2.0_f64.powi(h as i32);

    // Expected collisions = Q^2 / (2 * N) where N = 2^h
    let expected = (q * q) / (2.0 * total_leaves);

    // Probability of at least one collision ≈ 1 - e^(-expected)
    let probability = 1.0 - (-expected).exp();

    // Safety margin: how many times larger is N than Q^2/2
    let margin = if q > 0.0 {
        (2.0 * total_leaves) / (q * q)
    } else {
        f64::INFINITY
    };

    CollisionAnalysis {
        expected_collisions: expected,
        collision_probability: probability,
        safe_margin_factor: margin,
    }
}

/// Compute the minimum hypertree height `h` to achieve a target collision
/// probability after `num_signatures` signatures.
///
/// From P(collision) ≈ Q^2 / (2 * 2^h) < target:
///   2^h > Q^2 / (2 * target)
///   h > lg(Q^2 / (2 * target))
///   h > 2*lg(Q) - lg(2*target)
///   h > 2*lg(Q) - 1 - lg(target)
///
/// For target = 2^{-64}: h >= 2*lg(Q) + 64
pub fn minimum_h_for_collision_target(num_signatures: u64, target_probability: f64) -> usize {
    let q = num_signatures as f64;
    if q <= 1.0 {
        return 1;
    }
    let lg_q = q.log2();
    let lg_target = target_probability.log2();
    // h > 2*lg(Q) - 1 - lg(target)
    let h_min = 2.0 * lg_q - 1.0 - lg_target;
    (h_min.ceil() as usize).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_signatures_no_collisions() {
        let analysis = analyse_collisions(64, 0);
        assert_eq!(analysis.collision_probability, 0.0);
    }

    #[test]
    fn test_one_signature_negligible() {
        let analysis = analyse_collisions(64, 1);
        assert!(analysis.collision_probability < 1e-18);
    }

    #[test]
    fn test_birthday_bound() {
        // At Q = 2^32 with h=64, we're right at the birthday bound
        // Expected collisions ≈ 2^64 / (2 * 2^64) = 0.5
        let analysis = analyse_collisions(64, 1u64 << 32);
        assert!((analysis.expected_collisions - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_minimum_h_standard() {
        // For Q = 2^20 signatures with target 2^{-64}:
        // h_min = 2*20 + 64 = 104... but that seems high
        // Actually: h > 2*lg(Q) - 1 - lg(target)
        // = 2*20 - 1 - (-64) = 40 - 1 + 64 = 103
        let h = minimum_h_for_collision_target(1 << 20, 2.0_f64.powi(-64));
        assert_eq!(h, 103);
    }

    #[test]
    fn test_minimum_h_few_sigs() {
        // For Q = 1000, target 2^{-64}:
        // h > 2*lg(1000) - 1 + 64 ≈ 2*9.97 - 1 + 64 = 82.9
        let h = minimum_h_for_collision_target(1000, 2.0_f64.powi(-64));
        assert!(h >= 83 && h <= 84);
    }

    #[test]
    fn test_higher_h_means_lower_collision() {
        let low = analyse_collisions(40, 1_000_000);
        let high = analyse_collisions(80, 1_000_000);
        assert!(high.collision_probability < low.collision_probability);
    }
}
