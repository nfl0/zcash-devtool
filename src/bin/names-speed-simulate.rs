//! Replay a captured Orchard-family mainnet workload with synthetic Coppice Names traffic.
//!
//! The output is a derived, noncanonical performance workload. Synthetic transactions
//! reproduce compact transaction/action shapes; they are not consensus-valid Zcash data.

use std::{
    fs::File,
    hint::black_box,
    io::{BufReader, Read},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use prost::Message;
use serde_json::json;
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactOrchardAction, CompactTx};

#[derive(Debug, Parser)]
#[command(
    name = "names-speed-simulate",
    about = "Mix synthetic Coppice Names transactions into a captured mainnet workload"
)]
struct Cli {
    /// CNHS1 file produced by names-speed-sample --capture-dir.
    #[arg(long)]
    capture: PathBuf,

    /// Persist the JSON results without overwriting an existing file.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Optional JSON object containing separately measured verifier calibration.
    #[arg(long)]
    verification_calibration: Option<PathBuf>,

    /// Comma-separated simulated Names transactions per 1,152-block day.
    #[arg(long, default_value = "0,10,100,1000")]
    transactions_per_day: String,

    /// Compact Orchard-family actions per simulated Names transaction.
    #[arg(long, default_value_t = 13)]
    actions_per_transaction: u64,

    /// Blocks per protocol day/epoch.
    #[arg(long, default_value_t = 1_152)]
    epoch_blocks: u64,

    /// Blocks in each deterministic name-specific operation window.
    #[arg(long, default_value_t = 24)]
    window_blocks: u64,

    /// Mainnet Ironwood/NU6.3 activation; earlier proxy blocks use the Orchard field.
    #[arg(long, default_value_t = 3_428_143)]
    ironwood_activation_height: u64,

    /// Repeated local protobuf decode passes for each derived workload.
    #[arg(long, default_value_t = 3)]
    decode_passes: u32,

    /// Median measured endpoint protobuf payload throughput used for transfer projections.
    #[arg(long, default_value_t = 892_335.521_589_746_1)]
    network_bytes_per_second: f64,

    /// Estimated median latency added by each disjoint scheduled-window request.
    #[arg(long, default_value_t = 265.0)]
    request_overhead_milliseconds: f64,
}

#[derive(Debug)]
struct ScenarioMeasurement {
    transactions_per_day: u64,
    actions_per_transaction: u64,
    added_transactions: u64,
    added_actions: u64,
    derived_bytes: usize,
    added_bytes: usize,
    payload_growth_ratio: f64,
    workload_build_milliseconds: f64,
    decode_passes: u32,
    decode_wall_milliseconds: f64,
    decode_blocks_per_second: f64,
    decode_payload_bytes_per_second: f64,
    projected_remote_stream_seconds: f64,
}

impl ScenarioMeasurement {
    fn one_pass_decode_seconds(&self) -> f64 {
        self.decode_wall_milliseconds / 1_000.0 / f64::from(self.decode_passes)
    }

    fn as_json(&self) -> serde_json::Value {
        json!({
            "transactions_per_day": self.transactions_per_day,
            "actions_per_transaction": self.actions_per_transaction,
            "added_transactions": self.added_transactions,
            "added_actions": self.added_actions,
            "derived_protobuf_payload_bytes": self.derived_bytes,
            "added_protobuf_payload_bytes": self.added_bytes,
            "payload_growth_ratio": self.payload_growth_ratio,
            "workload_build_milliseconds": self.workload_build_milliseconds,
            "decode_passes": self.decode_passes,
            "decode_wall_milliseconds": self.decode_wall_milliseconds,
            "one_pass_decode_seconds": self.one_pass_decode_seconds(),
            "decode_blocks_per_second": self.decode_blocks_per_second,
            "decode_payload_bytes_per_second": self.decode_payload_bytes_per_second,
            "projected_remote_stream_seconds": self.projected_remote_stream_seconds
        })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(
        cli.actions_per_transaction > 0,
        "actions per transaction must be positive"
    );
    ensure!(cli.epoch_blocks > 0, "epoch blocks must be positive");
    ensure!(
        cli.window_blocks > 0 && cli.window_blocks <= cli.epoch_blocks,
        "window blocks must be positive and no greater than epoch blocks"
    );
    ensure!(cli.decode_passes > 0, "decode passes must be positive");
    ensure!(
        cli.network_bytes_per_second.is_finite() && cli.network_bytes_per_second > 0.0,
        "network bytes per second must be finite and positive"
    );
    ensure!(
        cli.request_overhead_milliseconds.is_finite() && cli.request_overhead_milliseconds >= 0.0,
        "request overhead must be finite and nonnegative"
    );
    let rates = parse_rates(&cli.transactions_per_day)?;
    let source = read_capture(&cli.capture)?;
    ensure!(!source.is_empty(), "capture contains no blocks");
    let source_bytes = source.iter().map(Vec::len).sum::<usize>();
    let source_shape = source
        .iter()
        .map(|encoded| {
            let block = CompactBlock::decode(encoded.as_slice())?;
            let actions = block
                .vtx
                .iter()
                .map(|tx| (tx.actions.len() + tx.ironwood_actions.len()) as u64)
                .sum::<u64>();
            Ok((block.height, encoded.len() as u64, actions))
        })
        .collect::<Result<Vec<_>>>()?;
    let first_height = source_shape[0].0;
    let last_height = source_shape[source_shape.len() - 1].0;
    let scheduled = scheduled_window_statistics(
        &source_shape,
        cli.epoch_blocks,
        cli.window_blocks,
        cli.network_bytes_per_second,
        cli.request_overhead_milliseconds,
    )?;
    let tails = tail_statistics(
        &source_shape,
        cli.network_bytes_per_second,
        &[1_152, 8_064, 34_560, 125_000, 250_000],
    );

    let mut scenarios = Vec::with_capacity(rates.len());
    for rate in rates {
        let build_started = Instant::now();
        let mut derived = Vec::with_capacity(source.len());
        let mut added_transactions = 0u64;
        let mut added_actions = 0u64;
        for (offset, encoded) in source.iter().enumerate() {
            let mut block = CompactBlock::decode(encoded.as_slice())?;
            let offset = offset as u64;
            let before = u128::from(offset) * u128::from(rate) / u128::from(cli.epoch_blocks);
            let after = u128::from(offset + 1) * u128::from(rate) / u128::from(cli.epoch_blocks);
            let block_transactions = u64::try_from(after - before)?;
            for ordinal in 0..block_transactions {
                let transaction_index = u64::try_from(block.vtx.len())?;
                let transaction = synthetic_names_transaction(
                    block.height,
                    ordinal,
                    transaction_index,
                    cli.actions_per_transaction,
                    block.height >= cli.ironwood_activation_height,
                );
                block.vtx.push(transaction);
            }
            added_transactions += block_transactions;
            added_actions = added_actions
                .saturating_add(block_transactions.saturating_mul(cli.actions_per_transaction));
            derived.push(block.encode_to_vec());
        }
        let build_elapsed = build_started.elapsed();
        let derived_bytes = derived.iter().map(Vec::len).sum::<usize>();

        let decode_started = Instant::now();
        let mut decoded_actions = 0u64;
        for _ in 0..cli.decode_passes {
            for encoded in &derived {
                let block = CompactBlock::decode(encoded.as_slice())?;
                decoded_actions += block
                    .vtx
                    .iter()
                    .map(|tx| (tx.actions.len() + tx.ironwood_actions.len()) as u64)
                    .sum::<u64>();
                black_box(&block);
            }
        }
        black_box(decoded_actions);
        let decode_elapsed = decode_started.elapsed();
        let decoded_blocks = source.len() as u64 * u64::from(cli.decode_passes);

        scenarios.push(ScenarioMeasurement {
            transactions_per_day: rate,
            actions_per_transaction: cli.actions_per_transaction,
            added_transactions,
            added_actions,
            derived_bytes,
            added_bytes: derived_bytes - source_bytes,
            payload_growth_ratio: derived_bytes as f64 / source_bytes as f64,
            workload_build_milliseconds: build_elapsed.as_secs_f64() * 1_000.0,
            decode_passes: cli.decode_passes,
            decode_wall_milliseconds: decode_elapsed.as_secs_f64() * 1_000.0,
            decode_blocks_per_second: decoded_blocks as f64 / decode_elapsed.as_secs_f64(),
            decode_payload_bytes_per_second: derived_bytes as f64 * f64::from(cli.decode_passes)
                / decode_elapsed.as_secs_f64(),
            projected_remote_stream_seconds: derived_bytes as f64 / cli.network_bytes_per_second,
        });
    }

    let solutions = solution_models(
        &scenarios,
        source_shape.iter().map(|entry| entry.2).sum(),
        &scheduled,
        cli.network_bytes_per_second,
    );

    let mut report = json!({
        "schema": "coppice-names-synthetic-mainnet-workload-v1",
        "source": {
            "capture": cli.capture,
            "blocks": source.len(),
            "start_height": first_height,
            "end_height": last_height,
            "protobuf_payload_bytes": source_bytes,
            "pool_model": "Orchard and Ironwood are treated as one equivalent Orchard-family compact workload."
        },
        "simulation": {
            "epoch_blocks": cli.epoch_blocks,
            "actions_per_transaction": cli.actions_per_transaction,
            "transaction_shape": "One synthetic compact transaction with the selected number of 32/32/32/52-byte Orchard-family actions. The 13-action default matches the qualified REVEAL/REFRESH transaction action count.",
            "semantics": "Derived noncanonical workload for byte-volume and protobuf processing measurements; no synthetic transaction is a valid Zcash or Coppice transaction.",
            "network_bytes_per_second": cli.network_bytes_per_second,
            "median_request_overhead_milliseconds": cli.request_overhead_milliseconds,
            "scheduled_window_statistics": scheduled,
            "tail_statistics": tails,
            "scenarios": scenarios.iter().map(ScenarioMeasurement::as_json).collect::<Vec<_>>(),
            "solution_models": solutions
        },
        "not_measured": [
            "canonical Core validation of the synthetic transactions",
            "CPV1 trial decryption and reassembly",
            "full-transaction RPC latency and bytes",
            "Names proof verification",
            "database persistence and reorg handling"
        ]
    });
    if let Some(path) = &cli.verification_calibration {
        let calibration: serde_json::Value = serde_json::from_reader(
            File::open(path).with_context(|| format!("open calibration {}", path.display()))?,
        )
        .with_context(|| format!("decode calibration {}", path.display()))?;
        ensure!(
            calibration.is_object(),
            "verification calibration must be a JSON object"
        );
        report["verification_calibration"] = calibration;
    }
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(path) = &cli.output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| {
                format!("create result file {} without overwriting", path.display())
            })?;
        use std::io::Write as _;
        file.write_all(rendered.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{rendered}");
    Ok(())
}

fn parse_rates(raw: &str) -> Result<Vec<u64>> {
    let mut rates = raw
        .split(',')
        .map(|value| {
            value
                .trim()
                .parse::<u64>()
                .with_context(|| format!("invalid transaction rate {value:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !rates.is_empty(),
        "at least one transaction rate is required"
    );
    rates.sort_unstable();
    rates.dedup();
    Ok(rates)
}

fn scheduled_window_statistics(
    source: &[(u64, u64, u64)],
    epoch_blocks: u64,
    window_blocks: u64,
    network_bytes_per_second: f64,
    request_overhead_milliseconds: f64,
) -> Result<serde_json::Value> {
    let offset_count = usize::try_from(epoch_blocks - window_blocks + 1)?;
    let mut byte_diff = vec![0i128; offset_count + 1];
    let mut action_diff = vec![0i128; offset_count + 1];
    for &(height, bytes, actions) in source {
        let position = height % epoch_blocks;
        let low = position.saturating_add(1).saturating_sub(window_blocks);
        let high = position.min(epoch_blocks - window_blocks);
        if low <= high {
            let low = usize::try_from(low)?;
            let high_after = usize::try_from(high + 1)?;
            byte_diff[low] += i128::from(bytes);
            byte_diff[high_after] -= i128::from(bytes);
            action_diff[low] += i128::from(actions);
            action_diff[high_after] -= i128::from(actions);
        }
    }
    let mut bytes = Vec::with_capacity(offset_count);
    let mut actions = Vec::with_capacity(offset_count);
    let mut current_bytes = 0i128;
    let mut current_actions = 0i128;
    for index in 0..offset_count {
        current_bytes += byte_diff[index];
        current_actions += action_diff[index];
        bytes.push(u64::try_from(current_bytes)?);
        actions.push(u64::try_from(current_actions)?);
    }
    let byte_distribution = integer_distribution(&bytes);
    let action_distribution = integer_distribution(&actions);
    let request_count = (source.len() as u64).div_ceil(epoch_blocks);
    let median_bytes = byte_distribution["p50"].as_u64().unwrap_or(0);
    Ok(json!({
        "possible_name_offsets": offset_count,
        "window_blocks": window_blocks,
        "epoch_blocks": epoch_blocks,
        "window_fraction": window_blocks as f64 / epoch_blocks as f64,
        "requests_if_each_epoch_is_queried_separately": request_count,
        "payload_bytes_across_all_name_offsets": byte_distribution,
        "actions_across_all_name_offsets": action_distribution,
        "median_remote_seconds_including_request_overhead": median_bytes as f64 / network_bytes_per_second + request_count as f64 * request_overhead_milliseconds / 1_000.0
    }))
}

fn tail_statistics(
    source: &[(u64, u64, u64)],
    network_bytes_per_second: f64,
    lengths: &[usize],
) -> serde_json::Value {
    let mut suffix_bytes = Vec::with_capacity(source.len() + 1);
    let mut suffix_actions = Vec::with_capacity(source.len() + 1);
    suffix_bytes.push(0u64);
    suffix_actions.push(0u64);
    for &(_, bytes, actions) in source.iter().rev() {
        suffix_bytes.push(
            suffix_bytes
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_add(bytes),
        );
        suffix_actions.push(
            suffix_actions
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_add(actions),
        );
    }
    let points = lengths
        .iter()
        .map(|&requested| {
            let blocks = requested.min(source.len());
            json!({
                "blocks": blocks,
                "payload_bytes": suffix_bytes[blocks],
                "actions": suffix_actions[blocks],
                "remote_seconds_at_median_throughput": suffix_bytes[blocks] as f64 / network_bytes_per_second
            })
        })
        .collect::<Vec<_>>();
    let uniform_remote = suffix_bytes
        .iter()
        .map(|bytes| *bytes as f64 / network_bytes_per_second)
        .collect::<Vec<_>>();
    json!({
        "points": points,
        "uniform_head_age_remote_seconds": float_distribution(&uniform_remote),
        "uniform_head_age_assumption": "Each head age from zero through the 250,000-block lease is equally likely; this is a sensitivity model, not observed name behavior."
    })
}

fn solution_models(
    scenarios: &[ScenarioMeasurement],
    source_actions: u64,
    scheduled: &serde_json::Value,
    network_bytes_per_second: f64,
) -> Vec<serde_json::Value> {
    let baseline_scheduled_bytes = scheduled["payload_bytes_across_all_name_offsets"]["p50"]
        .as_u64()
        .unwrap_or(0) as f64;
    let window_fraction = scheduled["window_fraction"].as_f64().unwrap_or(0.0);
    let scheduled_requests = scheduled["requests_if_each_epoch_is_queried_separately"]
        .as_u64()
        .unwrap_or(0) as f64;
    let baseline_scheduled_remote = scheduled["median_remote_seconds_including_request_overhead"]
        .as_f64()
        .unwrap_or(0.0);
    scenarios
        .iter()
        .map(|scenario| {
            let local_seconds = scenario.one_pass_decode_seconds();
            let local_bytes_per_second = scenario.derived_bytes as f64 / local_seconds;
            let total_actions = source_actions.saturating_add(scenario.added_actions);
            let effects_bytes = total_actions as f64 * 64.0;
            let added_scheduled_bytes = scenario.added_bytes as f64 * window_fraction;
            let scheduled_remote = baseline_scheduled_remote
                + added_scheduled_bytes / network_bytes_per_second;
            json!({
                "transactions_per_day": scenario.transactions_per_day,
                "current_activation_replay_remote_seconds": scenario.projected_remote_stream_seconds,
                "remote_exact_full_tail_seconds": scenario.projected_remote_stream_seconds,
                "rolling_canonical_evidence_local_seconds": local_seconds,
                "effects_only_plus_scheduled_refetch_seconds": effects_bytes / local_bytes_per_second + scheduled_remote,
                "seed_sealed_checkpoint_one_day_delta_seconds": local_seconds * 1_152.0 / 250_000.0,
                "storage": {
                    "rolling_compact_evidence_bytes": scenario.derived_bytes,
                    "effects_nf_cmx_lower_bound_bytes": effects_bytes
                },
                "scheduled_refetch": {
                    "baseline_median_bytes": baseline_scheduled_bytes,
                    "added_modeled_bytes": added_scheduled_bytes,
                    "separate_requests": scheduled_requests
                }
            })
        })
        .collect()
}

fn integer_distribution(values: &[u64]) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let sum = sorted.iter().map(|value| *value as f64).sum::<f64>();
    json!({
        "min": quantile_u64(&sorted, 0.0),
        "p05": quantile_u64(&sorted, 0.05),
        "p50": quantile_u64(&sorted, 0.50),
        "p95": quantile_u64(&sorted, 0.95),
        "max": quantile_u64(&sorted, 1.0),
        "mean": sum / sorted.len() as f64
    })
}

fn float_distribution(values: &[f64]) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let sum = sorted.iter().sum::<f64>();
    json!({
        "min": quantile_f64(&sorted, 0.0),
        "p05": quantile_f64(&sorted, 0.05),
        "p50": quantile_f64(&sorted, 0.50),
        "p95": quantile_f64(&sorted, 0.95),
        "max": quantile_f64(&sorted, 1.0),
        "mean": sum / sorted.len() as f64
    })
}

fn quantile_u64(sorted: &[u64], probability: f64) -> u64 {
    sorted[quantile_index(sorted.len(), probability)]
}

fn quantile_f64(sorted: &[f64], probability: f64) -> f64 {
    sorted[quantile_index(sorted.len(), probability)]
}

fn quantile_index(length: usize, probability: f64) -> usize {
    (((length - 1) as f64 * probability).round() as usize).min(length - 1)
}

fn read_capture(path: &PathBuf) -> Result<Vec<Vec<u8>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open capture {}", path.display()))?,
    );
    let mut magic = [0u8; 5];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == b"CNHS\x01", "capture has wrong CNHS1 magic");
    let mut blocks = Vec::new();
    loop {
        let mut length = [0u8; 4];
        match reader.read(&mut length[..1])? {
            0 => break,
            1 => reader
                .read_exact(&mut length[1..])
                .context("truncated CNHS1 frame length")?,
            _ => unreachable!("one-byte read returned more than one byte"),
        }
        let length = u32::from_le_bytes(length) as usize;
        ensure!(
            length <= 16 * 1024 * 1024,
            "capture block frame exceeds 16 MiB"
        );
        let mut block = vec![0u8; length];
        reader.read_exact(&mut block)?;
        CompactBlock::decode(block.as_slice()).context("decode captured CompactBlock")?;
        blocks.push(block);
    }
    Ok(blocks)
}

fn synthetic_names_transaction(
    height: u64,
    ordinal: u64,
    transaction_index: u64,
    action_count: u64,
    ironwood: bool,
) -> CompactTx {
    let mut txid = vec![0u8; 32];
    txid[..8].copy_from_slice(&height.to_le_bytes());
    txid[8..16].copy_from_slice(&ordinal.to_le_bytes());
    txid[16..24].copy_from_slice(b"CoppiceN");
    txid[24..32].copy_from_slice(b"amesLoad");
    let actions = (0..action_count)
        .map(|index| synthetic_action(height, ordinal, index))
        .collect::<Vec<_>>();
    CompactTx {
        index: transaction_index,
        txid,
        fee: 65_000,
        actions: if ironwood { vec![] } else { actions.clone() },
        ironwood_actions: if ironwood { actions } else { vec![] },
        ..Default::default()
    }
}

fn synthetic_action(height: u64, transaction: u64, action: u64) -> CompactOrchardAction {
    let seed = (height as u8)
        .wrapping_add(transaction as u8)
        .wrapping_add(action as u8);
    CompactOrchardAction {
        nullifier: vec![seed; 32],
        cmx: vec![seed.wrapping_add(1); 32],
        ephemeral_key: vec![seed.wrapping_add(2); 32],
        ciphertext: vec![seed.wrapping_add(3); 52],
    }
}
