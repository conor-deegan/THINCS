use crate::params::types::{HashFamily, ParameterSet};
use crate::params::security::{self, SecurityEstimate};
use crate::params::collision::{self, CollisionAnalysis};
use crate::cost::size;
use crate::cost::ops;

#[derive(Debug, Clone)]
pub struct RankedParameterSet {
    pub params: ParameterSet,
    pub sig_size: usize,
    pub pk_size: usize,
    pub sk_size: usize,
    pub security: SecurityEstimate,
    pub collision: CollisionAnalysis,
    pub sign_hash_calls: u64,
    pub verify_hash_calls: u64,
    pub rank: usize,
}

/// Find optimal stateless hash-based signature parameter sets for the given requirements.
///
/// Enumerates valid parameter combinations, filters by security target,
/// scores by signature size (primary) and signing cost (secondary),
/// and returns results sorted by rank.
/// Search bounds used by the optimizer, for display in CLI output.
#[derive(Debug, Clone, Copy)]
pub struct SearchBounds {
    pub h_min: usize,
    pub h_max: usize,
    pub hp_max: usize,
    pub k_max: usize,
    pub w_values: &'static [usize],
}

pub const HP_MAX: usize = 20;
pub const K_MAX: usize = 35;
pub const W_VALUES: &[usize] = &[256, 16, 4];

/// Additional constraints the user can place on the search.
#[derive(Debug, Clone, Copy, Default)]
pub struct Constraints {
    pub max_sig_size: Option<usize>,
    pub max_sign_cost: Option<u64>,
}

pub fn optimize(
    num_signatures: u64,
    security_bits: u16,
    collision_target: f64,
    hash: HashFamily,
) -> Vec<RankedParameterSet> {
    optimize_with(num_signatures, security_bits, collision_target, hash, Constraints::default()).0
}

/// Compute the search bounds used for a given (num_signatures, collision_target).
pub fn search_bounds(num_signatures: u64, collision_target: f64) -> SearchBounds {
    let q = if num_signatures == 0 { 1.0 } else { num_signatures as f64 };
    let lg_q = q.log2();
    let h_min_collision = collision::minimum_h_for_collision_target(num_signatures, collision_target);
    let h_min_search = if lg_q <= 20.0 { 4 } else { (lg_q * 0.7).ceil() as usize };
    let h_min = h_min_search.max(h_min_collision);
    let h_max = h_min + 40;
    SearchBounds {
        h_min,
        h_max,
        hp_max: HP_MAX,
        k_max: K_MAX,
        w_values: W_VALUES,
    }
}

/// Optimize with user-supplied constraints. Returns (results, bounds) so
/// callers can surface the search space to the user.
pub fn optimize_with(
    num_signatures: u64,
    security_bits: u16,
    collision_target: f64,
    hash: HashFamily,
    constraints: Constraints,
) -> (Vec<RankedParameterSet>, SearchBounds) {
    let bounds = search_bounds(num_signatures, collision_target);
    let results = optimize_inner(num_signatures, security_bits, collision_target, hash, constraints);
    (results, bounds)
}

fn optimize_inner(
    num_signatures: u64,
    security_bits: u16,
    collision_target: f64,
    hash: HashFamily,
    constraints: Constraints,
) -> Vec<RankedParameterSet> {
    // security_bits maps to NIST security levels:
    //   128 → Level 1 (AES-128 equivalent, 64 quantum bits)
    //   192 → Level 3 (AES-192 equivalent, 96 quantum bits)
    //   256 → Level 5 (AES-256 equivalent, 128 quantum bits)
    // The security parameter n determines: n*8 classical bits, n*4 quantum bits (Grover)
    let security_target = security_bits as f64;
    let quantum_target = security_target / 2.0;

    // n_min: n*8 >= security_bits → n >= security_bits/8
    let n_min = ((security_target / 8.0).ceil() as usize).max(1);
    // Use standard n values at or above n_min
    let n_values: Vec<usize> = [16, 24, 32]
        .iter()
        .copied()
        .filter(|&n| n >= n_min)
        .collect();

    if n_values.is_empty() {
        return vec![];
    }

    // Search bounds — shared with `search_bounds()` so users can see exactly
    // what the optimizer explored.
    let bounds = search_bounds(num_signatures, collision_target);
    let h_min = bounds.h_min;
    let h_max = bounds.h_max;
    let q = if num_signatures == 0 { 1.0 } else { num_signatures as f64 };
    let lg_q = q.log2();

    let mut candidates = Vec::new();

    for &n in &n_values {
        for h in h_min..=h_max {
            // d must divide h
            let divisors = divisors_of(h);
            for &d in &divisors {
                if d < 1 || d > h {
                    continue;
                }
                let hp = h / d;
                if hp > HP_MAX {
                    continue;
                }

                for &w in W_VALUES {
                    // Search k and a values
                    // FORS security ≈ k*a - lg(Q), need k*a >= quantum_target + lg(Q)
                    let min_ka = (quantum_target + lg_q).ceil() as usize;

                    for k in 1..=K_MAX {
                        // a_min from FORS security requirement
                        let a_min = if min_ka > 0 {
                            (min_ka + k - 1) / k // ceil(min_ka / k)
                        } else {
                            1
                        };
                        let a_min = a_min.max(1);
                        let a_max = 20_usize.min(a_min + 6); // don't search too far above minimum

                        for a in a_min..=a_max {
                            let params = ParameterSet {
                                n, h, d, w, k, a,
                                hash,
                            };

                            if params.validate().is_err() {
                                continue;
                            }

                            let est = security::estimate_security(&params, num_signatures);
                            if est.quantum_bits < quantum_target {
                                continue;
                            }

                            let col = collision::analyse_collisions(h, num_signatures);

                            // Filter by collision target
                            if col.collision_probability > collision_target {
                                continue;
                            }

                            let sig = size::signature_size(&params);
                            let pk = size::public_key_size(&params);
                            let sk = size::secret_key_size(&params);
                            let sign_calls = ops::sign_hash_calls(&params);
                            let verify_calls = ops::verify_hash_calls(&params);

                            // User constraints
                            if let Some(max_sig) = constraints.max_sig_size {
                                if sig > max_sig { continue; }
                            }
                            if let Some(max_sign) = constraints.max_sign_cost {
                                if sign_calls > max_sign { continue; }
                            }

                            candidates.push(RankedParameterSet {
                                params,
                                sig_size: sig,
                                pk_size: pk,
                                sk_size: sk,
                                security: est,
                                collision: col,
                                sign_hash_calls: sign_calls,
                                verify_hash_calls: verify_calls,
                                rank: 0,
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort: primary by sig_size ascending, secondary by sign_hash_calls ascending
    candidates.sort_by(|a, b| {
        a.sig_size
            .cmp(&b.sig_size)
            .then(a.sign_hash_calls.cmp(&b.sign_hash_calls))
            .then(a.verify_hash_calls.cmp(&b.verify_hash_calls))
    });

    // Deduplicate: keep only Pareto-optimal sets
    // A set is dominated if another set has both smaller sig_size AND fewer sign_hash_calls
    let pareto = pareto_frontier(&candidates);

    // Assign ranks
    let mut ranked: Vec<RankedParameterSet> = pareto;
    for (i, r) in ranked.iter_mut().enumerate() {
        r.rank = i + 1;
    }

    ranked
}

/// Analyse a specific parameter set
pub fn analyse(params: &ParameterSet, num_signatures: u64) -> RankedParameterSet {
    let est = security::estimate_security(params, num_signatures);
    let col = collision::analyse_collisions(params.h, num_signatures);
    let sig = size::signature_size(params);
    let pk = size::public_key_size(params);
    let sk = size::secret_key_size(params);
    let sign_calls = ops::sign_hash_calls(params);
    let verify_calls = ops::verify_hash_calls(params);

    RankedParameterSet {
        params: params.clone(),
        sig_size: sig,
        pk_size: pk,
        sk_size: sk,
        security: est,
        collision: col,
        sign_hash_calls: sign_calls,
        verify_hash_calls: verify_calls,
        rank: 1,
    }
}

fn divisors_of(n: usize) -> Vec<usize> {
    let mut divs = Vec::new();
    for i in 1..=n {
        if n % i == 0 {
            divs.push(i);
        }
    }
    divs
}

/// Extract the Pareto frontier: sets not dominated on (sig_size, sign_hash_calls)
fn pareto_frontier(candidates: &[RankedParameterSet]) -> Vec<RankedParameterSet> {
    if candidates.is_empty() {
        return vec![];
    }

    let mut frontier = Vec::new();

    for candidate in candidates {
        let dominated = frontier.iter().any(|f: &RankedParameterSet| {
            f.sig_size <= candidate.sig_size && f.sign_hash_calls <= candidate.sign_hash_calls
                && (f.sig_size < candidate.sig_size || f.sign_hash_calls < candidate.sign_hash_calls)
        });
        if !dominated {
            // Remove any existing frontier members dominated by this candidate
            frontier.retain(|f: &RankedParameterSet| {
                !(candidate.sig_size <= f.sig_size
                    && candidate.sign_hash_calls <= f.sign_hash_calls
                    && (candidate.sig_size < f.sig_size
                        || candidate.sign_hash_calls < f.sign_hash_calls))
            });
            frontier.push(candidate.clone());
        }
    }

    // Sort frontier by sig_size
    frontier.sort_by_key(|r| r.sig_size);
    frontier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimize_returns_results() {
        let results = optimize(1000, 128, 2.0_f64.powi(-20), HashFamily::Shake);
        assert!(!results.is_empty(), "optimizer should find valid parameter sets");
    }

    #[test]
    fn test_optimize_all_meet_security() {
        let results = optimize(1_000_000, 128, 2.0_f64.powi(-20), HashFamily::Shake);
        for r in &results {
            assert!(
                r.security.quantum_bits >= 64.0,
                "param set {} has only {:.1} quantum bits (need 64 for 128-bit security)",
                r.params,
                r.security.quantum_bits
            );
        }
    }

    #[test]
    fn test_optimize_all_meet_collision_target() {
        let target = 2.0_f64.powi(-20);
        let results = optimize(1000, 128, target, HashFamily::Shake);
        assert!(!results.is_empty(), "optimizer should find candidates");
        for r in &results {
            assert!(
                r.collision.collision_probability <= target,
                "param set {} has collision prob {:.2e} exceeding target {:.2e}",
                r.params, r.collision.collision_probability, target
            );
        }
    }

    #[test]
    fn test_optimize_sha2_hash_family() {
        let results = optimize(1000, 128, 2.0_f64.powi(-20), HashFamily::Sha2);
        assert!(!results.is_empty());
        for r in &results {
            assert_eq!(r.params.hash, HashFamily::Sha2);
        }
    }

    #[test]
    fn test_optimize_infeasible_returns_empty() {
        // Q=2^32 with collision target 2^{-64} requires h >= 127, exceeding
        // practical (d, hp) combinations under u64 tree_idx constraints.
        let results = optimize(1u64 << 32, 128, 2.0_f64.powi(-64), HashFamily::Shake);
        assert!(
            results.is_empty(),
            "expected no results for infeasible collision target"
        );
    }

    #[test]
    fn test_optimize_sorted_by_sig_size() {
        let results = optimize(1000, 128, 2.0_f64.powi(-20), HashFamily::Shake);
        for w in results.windows(2) {
            assert!(w[0].sig_size <= w[1].sig_size);
        }
    }

    #[test]
    fn test_optimize_relaxed_collision_finds_smaller_sigs() {
        // Relaxed collision target should find smaller parameter sets
        let strict = optimize(1000, 128, 2.0_f64.powi(-40), HashFamily::Shake);
        let relaxed = optimize(1000, 128, 2.0_f64.powi(-10), HashFamily::Shake);
        assert!(!strict.is_empty() && !relaxed.is_empty());
        // Relaxed allows smaller h → smaller signatures
        assert!(
            relaxed[0].sig_size <= strict[0].sig_size,
            "relaxed collision target should allow smaller or equal signatures"
        );
    }

    #[test]
    fn test_analyse_specific_params() {
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        let result = analyse(&params, 1_000_000);
        assert_eq!(result.sig_size, 7856);
        assert!(result.security.quantum_bits > 0.0);
    }
}
