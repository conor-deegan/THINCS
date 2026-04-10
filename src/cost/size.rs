use crate::params::types::ParameterSet;

/// Signature size in bytes
/// Sig = R (n bytes) + FORS sig (k*(a+1)*n bytes) + HT sig ((h + d*len)*n bytes)
pub fn signature_size(params: &ParameterSet) -> usize {
    let fors_sig = params.k * (params.a + 1) * params.n;
    let ht_sig = (params.h + params.d * params.len()) * params.n;
    let randomizer = params.n;
    randomizer + fors_sig + ht_sig
}

/// Public key size in bytes (PK.seed || PK.root)
pub fn public_key_size(params: &ParameterSet) -> usize {
    2 * params.n
}

/// Secret key size in bytes (SK.seed || SK.prf || PK.seed || PK.root)
pub fn secret_key_size(params: &ParameterSet) -> usize {
    4 * params.n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::types::HashFamily;

    #[test]
    fn test_sphincs_shake_128s_sizes() {
        // SLH-DSA-SHAKE-128s: n=16, h=63, d=7, w=16, k=14, a=12
        // Expected signature size: 7,856 bytes
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        assert_eq!(signature_size(&params), 7856);
        assert_eq!(public_key_size(&params), 32);
        assert_eq!(secret_key_size(&params), 64);
    }

    #[test]
    fn test_sphincs_shake_128f_sizes() {
        // SLH-DSA-SHAKE-128f: n=16, h=66, d=22, w=16, k=33, a=6
        // Expected signature size: 17,088 bytes
        let params = ParameterSet {
            n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake,
        };
        assert_eq!(signature_size(&params), 17088);
    }

    #[test]
    fn test_sphincs_shake_192s_sizes() {
        // SLH-DSA-SHAKE-192s: n=24, h=63, d=7, w=16, k=17, a=14
        // Expected signature size: 16,224 bytes
        let params = ParameterSet {
            n: 24, h: 63, d: 7, w: 16, k: 17, a: 14, hash: HashFamily::Shake,
        };
        assert_eq!(signature_size(&params), 16224);
    }

    #[test]
    fn test_sphincs_shake_256s_sizes() {
        // SLH-DSA-SHAKE-256s: n=32, h=64, d=8, w=16, k=22, a=14
        // Expected signature size: 29,792 bytes
        let params = ParameterSet {
            n: 32, h: 64, d: 8, w: 16, k: 22, a: 14, hash: HashFamily::Shake,
        };
        assert_eq!(signature_size(&params), 29792);
    }

    #[test]
    fn test_sphincs_shake_192f_sizes() {
        // SLH-DSA-SHAKE-192f: n=24, h=66, d=22, w=16, k=33, a=8
        // Expected signature size: 35,664 bytes (FIPS 205 Table 1)
        let params = ParameterSet {
            n: 24, h: 66, d: 22, w: 16, k: 33, a: 8, hash: HashFamily::Shake,
        };
        assert_eq!(signature_size(&params), 35664);
        assert_eq!(public_key_size(&params), 48);
        assert_eq!(secret_key_size(&params), 96);
    }

    #[test]
    fn test_sphincs_shake_256f_sizes() {
        // SLH-DSA-SHAKE-256f: n=32, h=68, d=17, w=16, k=35, a=9
        // Expected signature size: 49,856 bytes (FIPS 205 Table 1)
        let params = ParameterSet {
            n: 32, h: 68, d: 17, w: 16, k: 35, a: 9, hash: HashFamily::Shake,
        };
        assert_eq!(signature_size(&params), 49856);
        assert_eq!(public_key_size(&params), 64);
        assert_eq!(secret_key_size(&params), 128);
    }
}
