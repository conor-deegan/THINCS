use crate::params::types::ParameterSet;

/// Check all parameter constraints for validity.
/// Returns Ok(()) if valid, Err with description if not.
pub fn check_constraints(params: &ParameterSet) -> Result<(), String> {
    params.validate()
}

/// Check if a parameter set meets a minimum classical security level
/// after `num_signatures` signing queries.
pub fn meets_security_target(
    params: &ParameterSet,
    num_signatures: u64,
    target_classical_bits: f64,
) -> bool {
    let est = crate::params::security::estimate_security(params, num_signatures);
    est.classical_bits >= target_classical_bits
}
