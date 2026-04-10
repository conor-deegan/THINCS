use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashFamily {
    Shake,
    Sha2,
}

impl fmt::Display for HashFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashFamily::Shake => write!(f, "SHAKE"),
            HashFamily::Sha2 => write!(f, "SHA2"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParameterSet {
    pub n: usize,
    pub h: usize,
    pub d: usize,
    pub w: usize,
    pub k: usize,
    pub a: usize,
    pub hash: HashFamily,
}

impl ParameterSet {
    /// Height of each XMSS subtree
    pub fn hp(&self) -> usize {
        self.h / self.d
    }

    /// Integer log2 of the Winternitz parameter for the supported values.
    fn lg_w(&self) -> usize {
        match self.w {
            4 => 2,
            16 => 4,
            256 => 8,
            _ => unreachable!("validate() rejects other w values"),
        }
    }

    /// WOTS+ chains for message digits: ceil(8*n / lg(w)).
    pub fn len1(&self) -> usize {
        let lg_w = self.lg_w();
        (8 * self.n + lg_w - 1) / lg_w
    }

    /// WOTS+ checksum chains: floor(log_w(len1 * (w-1))) + 1.
    ///
    /// Computed with integer arithmetic to avoid floating-point edge cases
    /// when `len1 * (w-1)` is near a power of w.
    pub fn len2(&self) -> usize {
        let lg_w = self.lg_w();
        let max_checksum = self.len1() * (self.w - 1);
        if max_checksum == 0 {
            return 1;
        }
        // floor(log2(max_checksum)) via integer log2.
        let log2_floor = (max_checksum as u64).ilog2() as usize;
        log2_floor / lg_w + 1
    }

    /// Total WOTS+ chains
    pub fn len(&self) -> usize {
        self.len1() + self.len2()
    }

    /// Number of bytes for idx_tree in H_msg output (ceil((h - h/d) / 8)).
    pub fn tree_idx_bytes(&self) -> usize {
        (self.h - self.hp() + 7) / 8
    }

    /// Number of bytes for idx_leaf in H_msg output (ceil((h/d) / 8)).
    pub fn leaf_idx_bytes(&self) -> usize {
        (self.hp() + 7) / 8
    }

    /// Number of bytes for the FORS md section of H_msg output (ceil(k*a/8)).
    pub fn md_bytes(&self) -> usize {
        (self.k * self.a + 7) / 8
    }

    /// Validate the parameter set, returning an error message if invalid
    pub fn validate(&self) -> Result<(), String> {
        if self.h == 0 {
            return Err("h must be >= 1".into());
        }
        if self.d == 0 {
            return Err("d must be >= 1".into());
        }
        if self.d > self.h {
            return Err("d must be <= h".into());
        }
        if self.h % self.d != 0 {
            return Err(format!("h ({}) must be divisible by d ({})", self.h, self.d));
        }
        if self.w != 4 && self.w != 16 && self.w != 256 {
            return Err("w must be 4, 16, or 256".into());
        }
        if self.n == 0 {
            return Err("n must be >= 1".into());
        }
        if self.k == 0 {
            return Err("k must be >= 1".into());
        }
        if self.a == 0 {
            return Err("a must be >= 1".into());
        }
        // FORS index (a bits per tree) must fit in u32 per FIPS 205 ADRS layout.
        if self.a > 31 {
            return Err("a must be <= 31 (FORS index must fit in 32 bits)".into());
        }
        // Leaf index per XMSS tree (h/d bits) must fit in u32.
        if self.hp() > 32 {
            return Err(format!(
                "h/d = {} must be <= 32 (XMSS leaf index must fit in 32 bits)",
                self.hp()
            ));
        }
        // Tree index in the hypertree (h - h/d bits) must fit in u64.
        if self.h - self.hp() > 64 {
            return Err(format!(
                "h - h/d = {} must be <= 64 (hypertree tree index must fit in 64 bits)",
                self.h - self.hp()
            ));
        }
        // SHA-2 instantiation uses SHA-256 for F/PRF which outputs 32 bytes;
        // SHA-512 for H/T_l at n>=24 which outputs 64 bytes. n must fit both.
        if self.hash == HashFamily::Sha2 && self.n > 32 {
            return Err("n must be <= 32 for SHA-2 hash family".into());
        }
        Ok(())
    }
}

/// H_msg output length per FIPS 205 §9:
///   m = ceil(k*a/8) + ceil((h - h/d)/8) + ceil((h/d)/8)
pub fn h_msg_output_len(params: &ParameterSet) -> usize {
    params.md_bytes() + params.tree_idx_bytes() + params.leaf_idx_bytes()
}

impl fmt::Display for ParameterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "n={}, h={}, d={}, w={}, k={}, a={}, hash={}",
            self.n, self.h, self.d, self.w, self.k, self.a, self.hash
        )
    }
}

/// Parse a parameter set from a string like "n=16,h=40,d=8,w=16,k=14,a=12"
impl std::str::FromStr for ParameterSet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut n = None;
        let mut h = None;
        let mut d = None;
        let mut w = None;
        let mut k = None;
        let mut a = None;
        let mut hash = HashFamily::Shake;

        for part in s.split(',') {
            let part = part.trim();
            let (key, val) = part
                .split_once('=')
                .ok_or_else(|| format!("invalid key=value pair: '{}'", part))?;
            match key.trim() {
                "n" => n = Some(val.trim().parse::<usize>().map_err(|e| e.to_string())?),
                "h" => h = Some(val.trim().parse::<usize>().map_err(|e| e.to_string())?),
                "d" => d = Some(val.trim().parse::<usize>().map_err(|e| e.to_string())?),
                "w" => w = Some(val.trim().parse::<usize>().map_err(|e| e.to_string())?),
                "k" => k = Some(val.trim().parse::<usize>().map_err(|e| e.to_string())?),
                "a" => a = Some(val.trim().parse::<usize>().map_err(|e| e.to_string())?),
                "hash" => {
                    hash = match val.trim().to_lowercase().as_str() {
                        "shake" => HashFamily::Shake,
                        "sha2" => HashFamily::Sha2,
                        other => return Err(format!("unknown hash family: '{}'", other)),
                    }
                }
                other => return Err(format!("unknown parameter: '{}'", other)),
            }
        }

        let params = ParameterSet {
            n: n.ok_or("missing parameter 'n'")?,
            h: h.ok_or("missing parameter 'h'")?,
            d: d.ok_or("missing parameter 'd'")?,
            w: w.ok_or("missing parameter 'w'")?,
            k: k.ok_or("missing parameter 'k'")?,
            a: a.ok_or("missing parameter 'a'")?,
            hash,
        };
        params.validate()?;
        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_128s_derived_values() {
        // SLH-DSA-SHAKE-128s: n=16, h=63, d=7, w=16, k=14, a=12
        let params = ParameterSet {
            n: 16, h: 63, d: 7, w: 16, k: 14, a: 12, hash: HashFamily::Shake,
        };
        assert_eq!(params.hp(), 9);
        assert_eq!(params.len1(), 32); // ceil(8*16 / 4) = 32
        assert_eq!(params.len2(), 3);  // floor(lg(32*15)/4) + 1 = floor(lg(480)/4)+1 = floor(8.9/4)+1 = 3
        assert_eq!(params.len(), 35);
    }

    #[test]
    fn test_sphincs_128f_derived_values() {
        // SLH-DSA-SHAKE-128f: n=16, h=66, d=22, w=16, k=33, a=6
        let params = ParameterSet {
            n: 16, h: 66, d: 22, w: 16, k: 33, a: 6, hash: HashFamily::Shake,
        };
        assert_eq!(params.hp(), 3);
        assert_eq!(params.len1(), 32);
        assert_eq!(params.len2(), 3);
        assert_eq!(params.len(), 35);
    }

    #[test]
    fn test_w4_derived_values() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 4, k: 10, a: 8, hash: HashFamily::Shake,
        };
        assert_eq!(params.hp(), 5);
        assert_eq!(params.len1(), 64); // ceil(8*16 / 2) = 64
        // len2: floor(lg(64*3)/2) + 1 = floor(lg(192)/2)+1 = floor(7.58/2)+1 = 4
        assert_eq!(params.len2(), 4);
        assert_eq!(params.len(), 68);
    }

    #[test]
    fn test_validation_ok() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_validation_boundaries() {
        // a at the upper boundary
        let a31 = ParameterSet {
            n: 16, h: 4, d: 1, w: 16, k: 1, a: 31, hash: HashFamily::Shake,
        };
        assert!(a31.validate().is_ok(), "a=31 should be allowed (fits in u32)");

        let a32 = ParameterSet { a: 32, ..a31.clone() };
        assert!(a32.validate().is_err(), "a=32 should be rejected");

        // hp at the upper boundary
        let hp32 = ParameterSet {
            n: 16, h: 32, d: 1, w: 16, k: 1, a: 8, hash: HashFamily::Shake,
        };
        assert!(hp32.validate().is_ok(), "h/d=32 should be allowed");

        let hp33 = ParameterSet { h: 33, ..hp32.clone() };
        assert!(hp33.validate().is_err(), "h/d=33 should be rejected");

        // h - hp at the upper boundary: h=128, d=2 → hp=64, h-hp=64
        let tree64 = ParameterSet {
            n: 16, h: 128, d: 4, w: 16, k: 1, a: 8, hash: HashFamily::Shake,
        };
        // Actually h=128, d=4 gives hp=32, h-hp=96 (too big). Use d that makes hp=4: d=32, hp=4, h-hp=124 (too big).
        // Just test h=68, d=17 (256f-like): hp=4, h-hp=64. Should pass.
        let _ = tree64;
        let tree_at_limit = ParameterSet {
            n: 16, h: 68, d: 17, w: 16, k: 1, a: 8, hash: HashFamily::Shake,
        };
        assert!(tree_at_limit.validate().is_ok(), "h-hp=64 should be allowed");

        let tree_over = ParameterSet {
            n: 16, h: 130, d: 2, w: 16, k: 1, a: 8, hash: HashFamily::Shake,
        };
        // h=130, d=2 → hp=65. hp > 32 triggers first. This isn't the h-hp>64 path.
        // Use h=130, d=65 → hp=2, h-hp=128 > 64.
        let _ = tree_over;
        let tree_over = ParameterSet {
            n: 16, h: 130, d: 65, w: 16, k: 1, a: 8, hash: HashFamily::Shake,
        };
        assert!(tree_over.validate().is_err(), "h-hp=128 should be rejected");

        // n=0
        let n0 = ParameterSet { n: 0, ..a31.clone() };
        assert!(n0.validate().is_err());

        // h=0
        let h0 = ParameterSet { h: 0, d: 0, ..a31.clone() };
        assert!(h0.validate().is_err());

        // SHA-2 with n > 32
        let sha2_big = ParameterSet {
            n: 48, h: 8, d: 2, w: 16, k: 1, a: 8, hash: HashFamily::Sha2,
        };
        assert!(sha2_big.validate().is_err(), "SHA-2 rejects n > 32");
    }

    #[test]
    fn test_validation_h_not_divisible_by_d() {
        let params = ParameterSet {
            n: 16, h: 20, d: 3, w: 16, k: 10, a: 8, hash: HashFamily::Shake,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validation_bad_w() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 8, k: 10, a: 8, hash: HashFamily::Shake,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_validation_sha2_accepted() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 16, k: 10, a: 8, hash: HashFamily::Sha2,
        };
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_h_msg_output_len_matches_fips_205() {
        // FIPS 205 Table 2 m values for the six SHAKE parameter sets.
        let cases = [
            // (n, h, d, k, a, expected_m)
            (16, 63, 7,  14, 12, 30), // 128s
            (16, 66, 22, 33,  6, 34), // 128f
            (24, 63, 7,  17, 14, 39), // 192s
            (24, 66, 22, 33,  8, 42), // 192f
            (32, 64, 8,  22, 14, 47), // 256s
            (32, 68, 17, 35,  9, 49), // 256f
        ];
        for (n, h, d, k, a, expected_m) in cases {
            let p = ParameterSet {
                n, h, d, w: 16, k, a, hash: HashFamily::Shake,
            };
            assert_eq!(
                h_msg_output_len(&p),
                expected_m,
                "h_msg length for n={n}, h={h}, d={d}, k={k}, a={a}"
            );
        }
    }

    #[test]
    fn test_w256_derived_values() {
        let params = ParameterSet {
            n: 16, h: 20, d: 4, w: 256, k: 10, a: 8, hash: HashFamily::Shake,
        };
        assert_eq!(params.hp(), 5);
        assert_eq!(params.len1(), 16); // ceil(128 / 8) = 16
        // len2: max_checksum = 16*255=4080, floor(lg(4080)/8)+1 = floor(11.99/8)+1 = 2
        assert_eq!(params.len2(), 2);
        assert_eq!(params.len(), 18);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_parse_params() {
        let params: ParameterSet = "n=16,h=20,d=4,w=16,k=10,a=8".parse().unwrap();
        assert_eq!(params.n, 16);
        assert_eq!(params.h, 20);
        assert_eq!(params.d, 4);
        assert_eq!(params.w, 16);
        assert_eq!(params.k, 10);
        assert_eq!(params.a, 8);
        assert_eq!(params.hash, HashFamily::Shake);
    }

    #[test]
    fn test_parse_params_with_sha2() {
        let params: ParameterSet = "n=16,h=20,d=4,w=16,k=10,a=8,hash=sha2".parse().unwrap();
        assert_eq!(params.hash, HashFamily::Sha2);
    }
}
