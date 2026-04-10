# THINCS

THINCS is a research tool for finding optimal stateless hash-based signature schemes.

> Goes without saying, don't use this in production. It's a research tool.

Stateless hash-based signatures are the most conservative post-quantum signature construction we have. The security reduces to hash function properties and nothing else. SLH-DSA (the NIST standard, formerly SPHINCS+) is the most well-known instantiation, but it only defines twelve fixed parameter sets. Those parameter sets assume you might sign up to 2^64 messages with a single key. Most real systems will never get close to that number.

If you only need to sign a thousand messages, or a million, the standard parameter sets are dramatically oversized. You are paying for capacity you will never use, which impacts signature size and signing time.

THINCS lets you specify your actual requirements - how many signatures you need and what security level you want - and it finds the smallest valid parameter set that meets those constraints. It then instantiates a working stateless hash-based signature scheme with those parameters so you can keygen, sign, verify, and inspect it.

The instances THINCS produces are not SLH-DSA. SLH-DSA is a specific standard with specific parameter sets. What THINCS gives you is a custom stateless hash-based signature scheme built from the same underlying construction (WOTS+, XMSS, FORS, hypertrees) but tuned to your use case. Overall, THINCS:

- Let's you input your own constraints (number of signatures, security level) and it finds the smallest valid parameter set
- Estimates concrete security for each candidate (classical and quantum)
- Filters candidates by collision probability target (birthday bound over the hypertree leaf space)
- Instantiates a working signature scheme with any parameter set; keygen, sign, verify
- Supports Winternitz parameter w in {4, 16, 256} for the full size/speed trade-off range
- Supports both SHAKE256 and SHA-256/SHA-512 hash families with runtime selection
- Supports JSON output mode
- Is a from-scratch Rust implementation with runtime parameters (no compile-time generics, no existing crate dependency)

## What THINCS guarantees

**THINCS implements the SPHINCS+ round-3 submission construction (Bernstein et al.), not NIST FIPS 205 SLH-DSA.** The two are structurally identical at the primitive level; WOTS+, XMSS, hypertree, FORS, and the SHAKE256 / SHA-256 / SHA-512 tweakable hashes but FIPS 205 adds a message preprocessing step (Algorithm 22/23) that prepends a context byte and domain separation frame before hashing. THINCS does not do this.

**Byte-level cross-check against the SPHINCS+ reference C (`sphincs/sphincsplus/ref`).** The following primitives have been audited byte-for-byte against the reference:

- Compressed 22-byte ADRS layout (matches `sha2_offsets.h`)
- SHA-2 `tweak_prefix` block padding (`PK.seed || 0×(block − n) || ADRS^c`)
- F and PRF always use SHA-256 regardless of n (reference `thash_sha2_simple.c`)
- H, T_l, PRF_msg, H_msg switch to SHA-512 for n ≥ 24 (reference `hash_sha2.c`)
- FORS_PRF address field layout (keypair_address preserved, tree_height=0, tree_index = `i·2^a + leaf_idx`)
- WOTS+ checksum shift and big-endian serialization (reference `wots_checksum`)
- H_msg input ordering: SHAKE `R || PK.seed || PK.root || M`, SHA-2 via inner hash + MGF1 seed
- H_msg output length: `ceil(k·a/8) + ceil((h − h/d)/8) + ceil((h/d)/8)`

**What is verified:**

- ✓ Internal roundtrip (anything THINCS signs, THINCS verifies)
- ✓ Signature sizes for all 12 standard SLH-DSA parameter sets against FIPS 205 Table 1
- ✓ H_msg output lengths for all 6 standard SHAKE parameter sets against FIPS 205 Table 2
- ✓ Parameter-set derived values (`len`, `len1`, `len2`, `h'`) match FIPS 205 formulas
- ✓ Quantum security estimates reproduce NIST Level 1/3/5 for the standard parameter sets within 2 bits
- ✓ Primitive-level byte compatibility with SPHINCS+ reference C (per the audit above)

**What is not verified:**

- ✗ Byte-for-byte interop with NIST SLH-DSA KAT vectors - THINCS does not implement FIPS 205 M' preprocessing, so its signatures will not match.
- ✗ Byte-for-byte interop with SPHINCS+ round-3 KAT vectors - I didn't test this but I think it would just work.

## Usage

```
cargo build --release
```

### Find optimal parameters

Tell it how many signatures you need and what security level:

```
cargo run --release -- --signatures 1000 --security 128
```

It enumerates all valid parameter combinations, filters by your security target and collision probability bound, and returns the Pareto frontier ranked by signature size. The `--security` flag maps to NIST security levels: 128 is Level 1, 192 is Level 3, 256 is Level 5.

You can use `2^N` notation for large numbers:

```
cargo run --release -- --signatures 2^64 --security 128
```

Choose the hash family (SHAKE is the default; SHA-2 is also supported):

```
cargo run --release -- --signatures 1000 --security 128 --hash sha2
```

Constrain the search by signature size or signing cost:

```
cargo run --release -- --signatures 1000 --security 128 --max-sig-size 4096
cargo run --release -- --signatures 1000 --security 128 --max-sign-cost 1000000
```

### Analyse a specific parameter set

```
cargo run --release -- --params "n=16,h=63,d=7,w=16,k=14,a=12" --signatures 2^64
```

This prints the full breakdown: sizes, derived values, security estimate for each component, collision analysis, and hash call counts. You can use this to inspect the standard SLH-DSA parameter sets or to evaluate a custom set.

### Run a demo

```
cargo run --release -- --params "n=16,h=6,d=3,w=16,k=5,a=6" --demo
```

Generates a keypair, signs a message, verifies the signature, and prints the timings.

### Show the full Pareto frontier

```
cargo run --release -- --signatures 1000 --security 128 --enumerate
```

### Run the standard parameter set regression tests

The 12 standard SLH-DSA parameter sets are covered by an end-to-end test suite that is marked `#[ignore]` because the `s` variants take minutes per keygen with the naive implementation. Run them explicitly with:

```
cargo test --release --test standard_parameters -- --ignored --test-threads=1
```

The `f` variants complete in under a second each.

## How it works

The tool has two layers.

**The parameter engine** does not touch any cryptography. It takes your constraints, derives the minimum hash output size from your security target, searches over valid `(h, d, w, k, a)` combinations, estimates the concrete security of each one (FORS, WOTS+, and hash function security under both classical and quantum models), filters by collision probability, computes signature sizes from the formulas in the spec, and returns the Pareto frontier.

**The signature scheme implementation** is a from-scratch Rust implementation of the SPHINCS+ round-3 construction. It builds bottom-up: tweakable hash primitives (SHAKE256 with the 32-byte ADRS, and SHA-256/SHA-512 with the 22-byte compressed ADRS, both matching the FIPS 205 §11 primitive definitions), WOTS+ one-time signatures, XMSS Merkle trees, the hypertree (d layers of XMSS), FORS few-time signatures, and the top-level sign/verify that composes them. Everything takes `&ParameterSet` at runtime. There are no const generics.

## Parameters


| Parameter | What it controls                                                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `n`       | Hash output size in bytes. Determines the security level: n=16 for 128-bit, n=24 for 192-bit, n=32 for 256-bit.                                         |
| `h`       | Total hypertree height. There are 2^h possible leaf indices for stateless signing.                                                                      |
| `d`       | Number of hypertree layers. Each layer is an XMSS tree of height h/d. More layers means smaller trees but more signature overhead.                      |
| `w`       | Winternitz parameter (4, 16, or 256). Controls the size/speed trade-off within WOTS+ chains. Higher w gives smaller signatures but slower signing.      |
| `k`       | Number of FORS trees. More trees means more security margin against forgery after many signatures.                                                      |
| `a`       | Height of each FORS tree. Each tree has 2^a leaves. Together with k, determines FORS security: roughly k*a bits minus log2 of the number of signatures. |


The signature size formula is: `n + k*(a+1)*n + (h + d*len)*n` bytes, where `len` is the number of WOTS+ chains (derived from n and w).

## Caveats

**Security estimates are simplified.** They approximate the bounds from the SPHINCS+ submission (Bernstein et al.) and FIPS 205 §9, but the full security reduction (Theorem 1 in the SPHINCS+ paper) involves tighter multi-game bounds than what is implemented here. The estimates are suitable for parameter comparison and exploration, not as formal security proofs. Each formula is cited in `src/params/security.rs`. The model reproduces NIST Level 1/3/5 for the standard parameter sets within 2 bits.

**The implementation prioritises clarity over performance.** It uses `Vec<u8>` everywhere, recomputes Merkle trees from scratch during signing, and does not parallelise anything. The hash call estimates in the output table reflect tree construction costs, not optimised implementation costs. For research and parameter exploration this is fine but for production use it is not.

**Not FIPS 205 SLH-DSA.** THINCS implements the SPHINCS+ round-3 construction without FIPS 205 Algorithm 22/23 message preprocessing.

**Parameter limits.** The implementation enforces `a ≤ 31`, `h/d ≤ 32`, and `h − h/d ≤ 64` (the last two ensure leaf and tree indices fit in u32 and u64 respectively). The optimizer additionally caps `h/d ≤ 20` to keep the naive XMSS key generation tractable. SHA-2 requires `n ≤ 32` (SHA-256 provides 32 bytes for F/PRF regardless of n).

**This is not audited code.** Do not use it to protect anything that matters.

## License

MIT