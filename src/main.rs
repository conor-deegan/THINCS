use std::time::Instant;

use clap::Parser;
use comfy_table::{Table, ContentArrangement, presets::UTF8_FULL};

use thincs::params::types::{HashFamily, ParameterSet};
use thincs::params::optimizer;
use thincs::core::scheme;

#[derive(Parser)]
#[command(
    name = "thincs",
    about = "Find optimal stateless hash-based signature schemes for your use case"
)]
struct Cli {
    /// Number of signatures you expect to generate with a single key
    #[arg(short, long)]
    signatures: Option<String>,

    /// Target classical security level in bits (128=Level1, 192=Level3, 256=Level5)
    #[arg(long, default_value = "128")]
    security: u16,

    /// Show all valid parameter sets, not just the Pareto frontier
    #[arg(short, long)]
    enumerate: bool,

    /// Manually specify parameters: "n=16,h=40,d=8,w=16,k=14,a=12"
    #[arg(short, long)]
    params: Option<String>,

    /// Target collision probability exponent (default: -20, meaning 2^{-20}).
    /// FORS security separately accounts for multi-query degradation, so this
    /// is an additional safety margin — not a hard security requirement.
    #[arg(long, default_value = "-20")]
    collision_exp: i32,

    /// Hash family for the optimizer: "shake" or "sha2"
    #[arg(long, default_value = "shake")]
    hash: String,

    /// Only consider parameter sets whose signature is at most this many bytes
    #[arg(long)]
    max_sig_size: Option<usize>,

    /// Only consider parameter sets whose sign cost estimate is at most this many hashes
    #[arg(long)]
    max_sign_cost: Option<u64>,

    /// Output results as JSON on stdout (useful for scripting/plotting)
    #[arg(long)]
    json: bool,

    /// Run a keygen → sign → verify demo with the selected parameters
    #[arg(long)]
    demo: bool,
}

fn parse_hash_family(s: &str) -> Result<HashFamily, String> {
    match s.to_lowercase().as_str() {
        "shake" => Ok(HashFamily::Shake),
        "sha2" => Ok(HashFamily::Sha2),
        other => Err(format!("unknown hash family '{}' (expected 'shake' or 'sha2')", other)),
    }
}

fn parse_num_signatures(s: &str) -> Result<u64, String> {
    let s = s.trim().replace('_', "");
    // Handle 2^N notation
    if let Some(exp_str) = s.strip_prefix("2^") {
        let exp: u32 = exp_str
            .parse()
            .map_err(|_| format!("invalid exponent in '2^{}'", exp_str))?;
        if exp >= 64 {
            return Ok(u64::MAX);
        }
        return Ok(1u64 << exp);
    }
    // Handle scientific notation like 1e6
    if s.contains('e') || s.contains('E') {
        let val: f64 = s
            .parse()
            .map_err(|_| format!("invalid number: '{}'", s))?;
        return Ok(val as u64);
    }
    s.parse::<u64>()
        .map_err(|_| format!("invalid number: '{}'", s))
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn format_hash_calls(calls: u64) -> String {
    if calls >= 1_000_000_000 {
        format!("{:.1}G", calls as f64 / 1e9)
    } else if calls >= 1_000_000 {
        format!("{:.1}M", calls as f64 / 1e6)
    } else if calls >= 1_000 {
        format!("{:.1}K", calls as f64 / 1e3)
    } else {
        format!("{}", calls)
    }
}

fn print_analysis(result: &optimizer::RankedParameterSet) {
    println!("\n  Parameter Set Analysis");
    println!("  ═══════════════════════════════════════");
    println!("  Parameters: {}", result.params);
    println!();
    println!("  Sizes:");
    println!("    Signature:  {:>10} ({} bytes)", format_bytes(result.sig_size), result.sig_size);
    println!("    Public Key: {:>10} ({} bytes)", format_bytes(result.pk_size), result.pk_size);
    println!("    Secret Key: {:>10} ({} bytes)", format_bytes(result.sk_size), result.sk_size);
    println!();
    println!("  Derived Values:");
    println!("    h' (XMSS height):   {}", result.params.hp());
    println!("    len (WOTS+ chains): {}", result.params.len());
    println!("    len1:               {}", result.params.len1());
    println!("    len2:               {}", result.params.len2());
    println!();
    println!("  Security (simplified bounds — see src/params/security.rs for citations):");
    println!("    Classical:  {:.1} bits", result.security.classical_bits);
    println!("    Quantum:    {:.1} bits", result.security.quantum_bits);
    println!("    FORS:       {:.1} bits (after Q signatures)", result.security.fors_bits_after_q);
    println!("    WOTS+:      {:.1} bits", result.security.wots_bits);
    println!("    Hash:       {:.1} bits (quantum)", result.security.hash_bits);
    println!("    Binding:    {} (weakest component)", result.security.binding_component);
    println!();
    println!("  Collision Analysis (stateless signing):");
    println!("    Collision probability: {:.2e}", result.collision.collision_probability);
    println!("    Expected collisions:   {:.2e}", result.collision.expected_collisions);
    println!("    Safety margin:         {:.2e}x", result.collision.safe_margin_factor);
    println!("    Note: FORS security already accounts for multi-query degradation.");
    println!("    Collision probability is an additional metric for leaf index reuse");
    println!("    in the hypertree (birthday bound over 2^h leaf slots).");
    println!();
    println!("  Hash Call Estimates (tree construction cost):");
    println!("    Sign:   {}", format_hash_calls(result.sign_hash_calls));
    println!("    Verify: {}", format_hash_calls(result.verify_hash_calls));
    println!();
}

fn print_search_bounds(bounds: &optimizer::SearchBounds) {
    let w_list = bounds.w_values.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(", ");
    println!(
        "  Search space: h ∈ [{}, {}], d divisors of h, h/d ≤ {}, k ∈ [1, {}], w ∈ {{{}}}",
        bounds.h_min, bounds.h_max, bounds.hp_max, bounds.k_max, w_list
    );
    println!();
}

fn print_table(results: &[optimizer::RankedParameterSet], num_signatures: u64, security: u16, total_count: usize) {
    println!(
        "\n  THINCS — Q={} sigs, {}-bit security\n",
        num_signatures, security
    );

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "", "n", "h", "d", "w", "k", "a",
            "Sig Size", "Sign Cost", "Verify Cost",
            "Q-Security", "Binding",
        ]);

    for r in results {
        let marker = if r.rank == 1 { "★" } else { "" };
        table.add_row(vec![
            marker.to_string(),
            r.params.n.to_string(),
            r.params.h.to_string(),
            r.params.d.to_string(),
            r.params.w.to_string(),
            r.params.k.to_string(),
            r.params.a.to_string(),
            format!("{} ({}B)", format_bytes(r.sig_size), r.sig_size),
            format_hash_calls(r.sign_hash_calls),
            format_hash_calls(r.verify_hash_calls),
            format!("{:.1} bits", r.security.quantum_bits),
            r.security.binding_component.clone(),
        ]);
    }

    println!("{table}");

    if results.len() < total_count {
        println!("  Showing {} of {} Pareto-optimal sets. Use --enumerate to see all.\n", results.len(), total_count);
    }

    println!("  ★ = Optimal (smallest signature meeting all constraints)");
    println!("  Sign/Verify Cost = estimated hash calls (tree construction model)\n");
}

fn main() {
    let cli = Cli::parse();
    let collision_target = 2.0_f64.powi(cli.collision_exp);
    let hash = parse_hash_family(&cli.hash).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });

    // Mode 1: Analyse specific parameters
    if let Some(params_str) = &cli.params {
        let params: ParameterSet = params_str
            .parse()
            .unwrap_or_else(|e| {
                eprintln!("Error parsing parameters: {}", e);
                std::process::exit(1);
            });

        let num_sigs = match &cli.signatures {
            Some(s) => parse_num_signatures(s).unwrap_or_else(|e| {
                eprintln!("Error parsing signatures: {}", e);
                std::process::exit(1);
            }),
            None => 1,
        };

        let result = optimizer::analyse(&params, num_sigs);
        print_analysis(&result);

        if cli.demo {
            run_demo(&params);
        }
        return;
    }

    // Mode 2: Optimize
    let num_sigs = match &cli.signatures {
        Some(s) => parse_num_signatures(s).unwrap_or_else(|e| {
            eprintln!("Error parsing signatures: {}", e);
            std::process::exit(1);
        }),
        None => {
            eprintln!("Error: --signatures is required (unless using --params)");
            eprintln!("Usage: thincs --signatures 1000000 --security 128");
            std::process::exit(1);
        }
    };

    let constraints = optimizer::Constraints {
        max_sig_size: cli.max_sig_size,
        max_sign_cost: cli.max_sign_cost,
    };
    let (results, bounds) = optimizer::optimize_with(
        num_sigs, cli.security, collision_target, hash, constraints,
    );

    if cli.json {
        print_results_json(&results, num_sigs, cli.security, hash, &bounds);
        return;
    }

    if results.is_empty() {
        eprintln!("No valid parameter sets found for the given constraints.");
        eprintln!();
        eprintln!("Likely causes:");
        eprintln!("  - --collision-exp is too strict for --signatures (try a larger value,");
        eprintln!("    e.g., -10 or -20). FORS security already handles multi-query");
        eprintln!("    degradation, so tight collision targets are not a security");
        eprintln!("    requirement.");
        eprintln!("  - --security is too high for the remaining search space (try 128).");
        eprintln!();
        eprintln!("Implementation limits:");
        eprintln!("  - XMSS subtree height h/d capped at 20 (2^20 leaves) for speed");
        eprintln!("  - Hypertree tree index (h - h/d) capped at 64 bits");
        std::process::exit(1);
    }

    let total_count = results.len();

    print_search_bounds(&bounds);

    if cli.enumerate {
        print_table(&results, num_sigs, cli.security, total_count);
    } else {
        // Show top 10 from the Pareto frontier
        let top: Vec<_> = results.iter().take(10).cloned().collect();
        print_table(&top, num_sigs, cli.security, total_count);

        // Also print detailed analysis of the optimal set
        print_analysis(&results[0]);
    }

    if cli.demo {
        run_demo(&results[0].params);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn run_demo(params: &ParameterSet) {
    println!("  Demo: keygen → sign → verify");
    println!("  ═══════════════════════════════════════");
    println!("  Parameters: {}", params);
    println!();

    let start = Instant::now();
    let kp = scheme::keygen(params);
    let keygen_time = start.elapsed();
    println!("  Keygen:  {:.3?}", keygen_time);
    println!("    SK seed:  {}", hex(&kp.sk_seed));
    println!("    SK prf:   {}", hex(&kp.sk_prf));
    println!("    PK seed:  {}", hex(&kp.pk_seed));
    println!("    PK root:  {}", hex(&kp.pk_root));

    let msg = b"THINCS demo message";
    let start = Instant::now();
    let sig = scheme::sign(params, msg, &kp);
    let sign_time = start.elapsed();
    let sig_bytes = sig.to_bytes(params);
    println!("  Sign:    {:.3?}", sign_time);
    println!("    Signature: {} bytes", sig_bytes.len());
    let preview_len = sig_bytes.len().min(48);
    println!("    First {} bytes: {}{}",
        preview_len,
        hex(&sig_bytes[..preview_len]),
        if sig_bytes.len() > preview_len { "..." } else { "" }
    );
    println!("    Randomizer R: {}", hex(&sig.r));

    let start = Instant::now();
    let valid = scheme::verify(params, msg, &sig, &kp.pk_seed, &kp.pk_root);
    let verify_time = start.elapsed();
    println!("  Verify:  {:.3?} — {}", verify_time, if valid { "VALID" } else { "INVALID" });
    println!();
}

// ===== JSON output =====

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn hash_family_name(h: HashFamily) -> &'static str {
    match h {
        HashFamily::Shake => "shake",
        HashFamily::Sha2 => "sha2",
    }
}

fn json_params(params: &ParameterSet) -> String {
    format!(
        r#"{{"n":{},"h":{},"d":{},"w":{},"k":{},"a":{},"hash":"{}","len":{},"len1":{},"len2":{},"hp":{}}}"#,
        params.n, params.h, params.d, params.w, params.k, params.a,
        hash_family_name(params.hash),
        params.len(), params.len1(), params.len2(), params.hp(),
    )
}

fn json_security(s: &thincs::params::security::SecurityEstimate) -> String {
    format!(
        r#"{{"classical_bits":{},"quantum_bits":{},"fors_bits_after_q":{},"wots_bits":{},"hash_bits":{},"binding_component":"{}"}}"#,
        s.classical_bits, s.quantum_bits, s.fors_bits_after_q, s.wots_bits, s.hash_bits,
        json_escape(&s.binding_component),
    )
}

fn json_collision(c: &thincs::params::collision::CollisionAnalysis) -> String {
    format!(
        r#"{{"collision_probability":{},"expected_collisions":{},"safe_margin_factor":{}}}"#,
        c.collision_probability, c.expected_collisions,
        if c.safe_margin_factor.is_finite() {
            format!("{}", c.safe_margin_factor)
        } else {
            "null".to_string()
        },
    )
}

fn json_result(r: &optimizer::RankedParameterSet) -> String {
    format!(
        r#"{{"rank":{},"params":{},"sig_size":{},"pk_size":{},"sk_size":{},"sign_hash_calls":{},"verify_hash_calls":{},"security":{},"collision":{}}}"#,
        r.rank,
        json_params(&r.params),
        r.sig_size, r.pk_size, r.sk_size,
        r.sign_hash_calls, r.verify_hash_calls,
        json_security(&r.security),
        json_collision(&r.collision),
    )
}

fn json_bounds(b: &optimizer::SearchBounds) -> String {
    let w_list = b.w_values.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(",");
    format!(
        r#"{{"h_min":{},"h_max":{},"hp_max":{},"k_max":{},"w_values":[{}]}}"#,
        b.h_min, b.h_max, b.hp_max, b.k_max, w_list
    )
}

fn print_results_json(
    results: &[optimizer::RankedParameterSet],
    num_signatures: u64,
    security: u16,
    hash: HashFamily,
    bounds: &optimizer::SearchBounds,
) {
    let results_json = results
        .iter()
        .map(json_result)
        .collect::<Vec<_>>()
        .join(",");
    println!(
        r#"{{"num_signatures":{},"security_bits":{},"hash_family":"{}","search_bounds":{},"result_count":{},"results":[{}]}}"#,
        num_signatures, security,
        hash_family_name(hash),
        json_bounds(bounds),
        results.len(),
        results_json,
    );
}
