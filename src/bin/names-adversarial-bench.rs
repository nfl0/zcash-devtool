//! Calibrate the expensive Names checks an adversary can deliberately reach.
//!
//! This consumes the frozen replacement-protocol vector so both accepted and
//! rejected proof measurements use the deployment's real Halo2 verifier.

use std::{fs::File, hint::black_box, path::PathBuf, time::Instant};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use coppice::identity::CoreRuntimeId;
use coppice_names::{
    codec::{CodecParameters, Operation, decode},
    deployment::DeploymentParameters,
    proof::keygen,
    protocol::{Commitment, FieldElement, Network},
    reducer::ProofVerifier,
    statement::{RefreshStatement, RevealStatement},
};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "names-adversarial-bench",
    about = "Benchmark valid and adversarial Coppice Names proof paths"
)]
struct Cli {
    /// Frozen protocol.json vector.
    #[arg(long)]
    vector: PathBuf,

    /// Verification samples per proof and validity class.
    #[arg(long, default_value_t = 25)]
    iterations: u32,

    /// Malformed wire decode samples.
    #[arg(long, default_value_t = 10_000)]
    decode_iterations: u32,

    /// Persist JSON results without overwriting an existing file.
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.iterations > 0, "iterations must be positive");
    ensure!(
        cli.decode_iterations > 0,
        "decode iterations must be positive"
    );
    let document: Value = serde_json::from_reader(
        File::open(&cli.vector).with_context(|| format!("open {}", cli.vector.display()))?,
    )
    .with_context(|| format!("decode {}", cli.vector.display()))?;

    let keygen_started = Instant::now();
    let (_, verifier) = keygen();
    let keygen_elapsed = keygen_started.elapsed();
    let activation_height = u32_value(&document, "/parameters/activation_height")?;
    let core_runtime_id = bytes32(string_value(&document, "/identity/core_runtime_id_hex")?)?;
    let deployment = DeploymentParameters::candidate(
        CoreRuntimeId::from_bytes(core_runtime_id),
        activation_height,
        verifier.identity(),
    );
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive deployment: {error:?}"))?;
    ensure!(
        hex::encode(deployment_id) == string_value(&document, "/identity/deployment_id_hex")?,
        "vector deployment identity does not match current verifier"
    );
    let parameters = deployment.schedule(deployment_id);
    let codec = CodecParameters {
        reveal_proof_bytes: usize_value(&document, "/identity/reveal_proof_bytes")?,
        refresh_proof_bytes: usize_value(&document, "/identity/refresh_proof_bytes")?,
    };
    let commit = decode_operation(&document, "commit", codec)?;
    let reveal = decode_operation(&document, "reveal", codec)?;
    let refresh = decode_operation(&document, "refresh", codec)?;
    let commit_height = u32_value(&document, "/schedule/commit_height")?;
    let reveal_height = u32_value(&document, "/schedule/reveal_height")?;
    let refresh_height = u32_value(&document, "/schedule/refresh_height")?;

    let Operation::Commit { commitment } = commit else {
        anyhow::bail!("commit vector decoded as another operation");
    };
    let reveal_statement = reveal_statement(
        &reveal,
        commitment,
        deployment_id,
        parameters.epoch(reveal_height).map_err(debug_error)?,
        field_value(&document, "/fields/reveal_action_nullifier_hex")?,
        field_value(&document, "/fields/reveal_action_commitment_hex")?,
    )?;
    let refresh_statement = refresh_statement(
        &refresh,
        &reveal,
        deployment_id,
        parameters.epoch(reveal_height).map_err(debug_error)?,
        parameters.epoch(refresh_height).map_err(debug_error)?,
        field_value(&document, "/fields/reveal_action_commitment_hex")?,
        field_value(&document, "/fields/refresh_action_commitment_hex")?,
    )?;
    let reveal_proof = operation_proof(&reveal)?;
    let refresh_proof = operation_proof(&refresh)?;
    ensure!(
        verifier.verify_reveal(&reveal_statement, reveal_proof),
        "frozen REVEAL proof did not verify"
    );
    ensure!(
        verifier.verify_refresh(&refresh_statement, refresh_proof),
        "frozen REFRESH proof did not verify"
    );

    let mut invalid_reveal = reveal_proof.to_vec();
    let reveal_index = invalid_reveal.len() / 2;
    invalid_reveal[reveal_index] ^= 1;
    let mut invalid_refresh = refresh_proof.to_vec();
    let refresh_index = invalid_refresh.len() / 2;
    invalid_refresh[refresh_index] ^= 1;
    ensure!(
        !verifier.verify_reveal(&reveal_statement, &invalid_reveal),
        "mutated REVEAL proof unexpectedly verified"
    );
    ensure!(
        !verifier.verify_refresh(&refresh_statement, &invalid_refresh),
        "mutated REFRESH proof unexpectedly verified"
    );

    let valid_reveal = measure(cli.iterations, || {
        black_box(verifier.verify_reveal(&reveal_statement, reveal_proof))
    });
    let invalid_reveal_timing = measure(cli.iterations, || {
        black_box(verifier.verify_reveal(&reveal_statement, &invalid_reveal))
    });
    let valid_refresh = measure(cli.iterations, || {
        black_box(verifier.verify_refresh(&refresh_statement, refresh_proof))
    });
    let invalid_refresh_timing = measure(cli.iterations, || {
        black_box(verifier.verify_refresh(&refresh_statement, &invalid_refresh))
    });

    // A hostile routed payload that fails the wire magic must be rejected before
    // statement construction or proof verification.
    let mut malformed = operation_bytes(&document, "reveal")?;
    malformed[0] ^= 1;
    ensure!(
        decode(&malformed, Network::Regtest, codec).is_err(),
        "mutated wire operation unexpectedly decoded"
    );
    let malformed_decode = measure(cli.decode_iterations, || {
        black_box(decode(black_box(&malformed), Network::Regtest, codec).is_err())
    });

    let report = json!({
        "schema": "coppice-names-adversarial-calibration-v1",
        "source": {
            "vector": cli.vector,
            "vector_set_sha256": string_value(&document, "/vector_set_sha256")?,
            "commit_height": commit_height,
            "reveal_height": reveal_height,
            "refresh_height": refresh_height,
            "reveal_proof_bytes": reveal_proof.len(),
            "refresh_proof_bytes": refresh_proof.len()
        },
        "setup": {
            "key_generation_seconds_excluded_from_replay": keygen_elapsed.as_secs_f64()
        },
        "measurements": {
            "valid_reveal_proof": timing_json(valid_reveal, cli.iterations),
            "invalid_reveal_proof": timing_json(invalid_reveal_timing, cli.iterations),
            "valid_refresh_proof": timing_json(valid_refresh, cli.iterations),
            "invalid_refresh_proof": timing_json(invalid_refresh_timing, cli.iterations),
            "malformed_reveal_wire_decode": timing_json(malformed_decode, cli.decode_iterations)
        },
        "adversarial_reachability": {
            "malformed_wire": "An attacker can force exact-route trial decryption and full-transaction authentication, but a malformed Names operation is rejected before proof verification.",
            "invalid_reveal_proof": "To reach REVEAL verification, the attacker also needs a live matching COMMIT, the deterministic name window, canonical action selection, and a syntactically valid operation.",
            "invalid_refresh_proof": "To reach REFRESH verification, the attacker needs the exact current predecessor, a later deterministic name window, and an action spending the head future nullifier.",
            "unrelated_name": "ExactResolver removes other-name REVEAL and REFRESH payloads before proof verification, while retaining their public action effects for bond-spend detection.",
            "consensus_verification": "Excluded: the light wallet consumes transactions already admitted by Zcash consensus."
        },
        "security_interpretation": [
            "Invalid proofs retain the full cryptographic verification cost; this is the relevant proof-DoS calibration.",
            "Cheap structural gates precede proof verification and must remain ordered that way.",
            "Zcash transaction fees and block limits bound publication volume but do not eliminate light-wallet amplification."
        ]
    });
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &cli.output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create {} without overwriting", path.display()))?;
        use std::io::Write as _;
        file.write_all(rendered.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{rendered}");
    Ok(())
}

fn measure(mut iterations: u32, mut operation: impl FnMut() -> bool) -> Vec<f64> {
    let mut samples = Vec::with_capacity(iterations as usize);
    while iterations > 0 {
        let started = Instant::now();
        black_box(operation());
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
        iterations -= 1;
    }
    samples
}

fn timing_json(samples: Vec<f64>, iterations: u32) -> Value {
    let mut sorted = samples;
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / sorted.len() as f64;
    json!({
        "iterations": iterations,
        "min_milliseconds": sorted[0],
        "p50_milliseconds": quantile(&sorted, 0.50),
        "p95_milliseconds": quantile(&sorted, 0.95),
        "p99_milliseconds": quantile(&sorted, 0.99),
        "max_milliseconds": sorted[sorted.len() - 1],
        "mean_milliseconds": mean,
        "standard_deviation_milliseconds": variance.sqrt(),
        "operations_per_second_at_mean": 1_000.0 / mean
    })
}

fn quantile(sorted: &[f64], probability: f64) -> f64 {
    let index = (((sorted.len() - 1) as f64 * probability).round() as usize).min(sorted.len() - 1);
    sorted[index]
}

fn reveal_statement(
    operation: &Operation,
    commitment: Commitment,
    deployment_id: [u8; 32],
    inclusion_epoch: u32,
    action_nullifier: FieldElement,
    action_commitment: FieldElement,
) -> Result<RevealStatement> {
    let Operation::Reveal {
        name,
        commit,
        ua,
        action_index,
        successor_future_nf,
        ..
    } = operation
    else {
        anyhow::bail!("REVEAL vector decoded as another operation");
    };
    Ok(RevealStatement {
        deployment_id,
        name_id: name.id().map_err(debug_error)?,
        inclusion_epoch,
        commitment,
        commit_ref: *commit,
        ua: ua.clone(),
        action_index: *action_index,
        action_nullifier,
        action_commitment,
        successor_future_nf: *successor_future_nf,
    })
}

fn refresh_statement(
    operation: &Operation,
    reveal: &Operation,
    deployment_id: [u8; 32],
    predecessor_epoch: u32,
    inclusion_epoch: u32,
    predecessor_commitment: FieldElement,
    action_commitment: FieldElement,
) -> Result<RefreshStatement> {
    let Operation::Refresh {
        name,
        predecessor,
        ua,
        action_index,
        successor_future_nf,
        ..
    } = operation
    else {
        anyhow::bail!("REFRESH vector decoded as another operation");
    };
    let Operation::Reveal {
        successor_future_nf: predecessor_future_nf,
        ..
    } = reveal
    else {
        anyhow::bail!("predecessor vector is not REVEAL");
    };
    Ok(RefreshStatement {
        deployment_id,
        name_id: name.id().map_err(debug_error)?,
        predecessor_ref: *predecessor,
        predecessor_commitment,
        predecessor_future_nf: *predecessor_future_nf,
        predecessor_epoch,
        inclusion_epoch,
        ua: ua.clone(),
        action_index: *action_index,
        action_nullifier: *predecessor_future_nf,
        action_commitment,
        successor_future_nf: *successor_future_nf,
    })
}

fn operation_proof(operation: &Operation) -> Result<&[u8]> {
    match operation {
        Operation::Reveal { proof, .. } | Operation::Refresh { proof, .. } => Ok(proof),
        Operation::Commit { .. } => anyhow::bail!("COMMIT has no proof"),
    }
}

fn decode_operation(document: &Value, id: &str, codec: CodecParameters) -> Result<Operation> {
    let bytes = operation_bytes(document, id)?;
    decode(&bytes, Network::Regtest, codec)
        .map_err(|error| anyhow::anyhow!("decode {id} operation: {error:?}"))
}

fn operation_bytes(document: &Value, id: &str) -> Result<Vec<u8>> {
    let operation = document["operations"]
        .as_array()
        .context("operations is not an array")?
        .iter()
        .find(|operation| operation["id"].as_str() == Some(id))
        .with_context(|| format!("missing {id} operation"))?;
    hex::decode(
        operation["hex"]
            .as_str()
            .context("operation hex is not a string")?,
    )
    .context("decode operation hex")
}

fn field_value(document: &Value, pointer: &str) -> Result<FieldElement> {
    FieldElement::from_bytes(bytes32(string_value(document, pointer)?)?)
        .map_err(|error| anyhow::anyhow!("invalid field at {pointer}: {error:?}"))
}

fn string_value<'a>(document: &'a Value, pointer: &str) -> Result<&'a str> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string at {pointer}"))
}

fn u32_value(document: &Value, pointer: &str) -> Result<u32> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing integer at {pointer}"))?
        .try_into()
        .with_context(|| format!("integer at {pointer} exceeds u32"))
}

fn usize_value(document: &Value, pointer: &str) -> Result<usize> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing integer at {pointer}"))?
        .try_into()
        .with_context(|| format!("integer at {pointer} exceeds usize"))
}

fn bytes32(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .context("decode 32-byte hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

fn debug_error(error: impl std::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}
