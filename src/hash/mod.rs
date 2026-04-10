/// Tweakable hash functions for stateless hash-based signatures.
///
/// Two instantiations are provided per FIPS 205 §11:
///   - SHAKE (§11.1): uses SHAKE256 with a 32-byte ADRS.
///   - SHA-2 (§11.2): uses SHA-256 (n=16) or SHA-256/SHA-512 mix (n>=24) with
///     a 22-byte compressed ADRS and block-aligned padding.
///
/// This module provides a single dispatch API. Callers use the functions
/// here (`hash::hash_f`, etc.) and the implementation is selected by
/// `params.hash` at runtime. Adding another hash family is purely additive.

pub mod shake;
pub mod sha2;

use crate::core::address::Adrs;
use crate::params::types::{HashFamily, ParameterSet};

/// T_l: tweakable hash with arbitrary-length input.
pub fn hash_t(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake::hash_t(params, pk_seed, adrs, message),
        HashFamily::Sha2 => sha2::hash_t(params, pk_seed, adrs, message),
    }
}

/// F: one-block tweakable hash (WOTS+ chain step).
pub fn hash_f(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake::hash_f(params, pk_seed, adrs, m1),
        HashFamily::Sha2 => sha2::hash_f(params, pk_seed, adrs, m1),
    }
}

/// H: two-block tweakable hash (Merkle internal nodes).
pub fn hash_h(params: &ParameterSet, pk_seed: &[u8], adrs: &Adrs, m1: &[u8], m2: &[u8]) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake::hash_h(params, pk_seed, adrs, m1, m2),
        HashFamily::Sha2 => sha2::hash_h(params, pk_seed, adrs, m1, m2),
    }
}

/// PRF: SK.seed → leaf secret.
pub fn prf(params: &ParameterSet, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake::prf(params, pk_seed, sk_seed, adrs),
        HashFamily::Sha2 => sha2::prf(params, pk_seed, sk_seed, adrs),
    }
}

/// PRF_msg: randomizer for message hashing.
pub fn prf_msg(params: &ParameterSet, sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake::prf_msg(params, sk_prf, opt_rand, msg),
        HashFamily::Sha2 => sha2::prf_msg(params, sk_prf, opt_rand, msg),
    }
}

/// H_msg: hash a message into FORS indices and tree/leaf coordinates.
pub fn h_msg(
    params: &ParameterSet,
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
) -> Vec<u8> {
    match params.hash {
        HashFamily::Shake => shake::h_msg(params, r, pk_seed, pk_root, msg),
        HashFamily::Sha2 => sha2::h_msg(params, r, pk_seed, pk_root, msg),
    }
}
