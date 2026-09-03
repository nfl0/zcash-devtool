//! Measure mainnet Orchard-family compact-block characteristics for Coppice Names estimates.
//!
//! This deliberately measures only chain and lightwalletd properties. A chain with no
//! Coppice deployment cannot measure Names carrier frequency, proof verification, or
//! full-transaction acquisition, so those are reported as unmeasured rather than zero.

use std::{
    fs::{self, OpenOptions},
    hint::black_box,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use futures_util::StreamExt;
use prost::Message;
use serde_json::{Value, json};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{
        BlockId, BlockRange, ChainSpec, Empty, PoolType,
        compact_tx_streamer_client::CompactTxStreamerClient,
    },
};

#[derive(Debug, Parser)]
#[command(
    name = "names-speed-sample",
    about = "Sample mainnet Orchard/Ironwood compact blocks and estimate Coppice Names scan costs"
)]
struct Cli {
    /// TLS lightwalletd endpoint in host:port form.
    #[arg(long, default_value = "zec.rocks:443")]
    server: String,

    /// Number of recent blocks to sample.
    #[arg(long, default_value_t = 10_000)]
    sample_blocks: u64,

    /// Inclusive final height; defaults to the server tip.
    #[arg(long)]
    end_height: Option<u64>,

    /// Mainnet Ironwood/NU6.3 activation height. Earlier sampled blocks use Orchard as a proxy.
    #[arg(long, default_value_t = 3_428_143)]
    ironwood_activation_height: u64,

    /// Number of blocks per GetBlockRange request.
    #[arg(long, default_value_t = 2_000)]
    request_batch_blocks: u64,

    /// Production candidate lease horizon.
    #[arg(long, default_value_t = 250_000)]
    lease_blocks: u64,

    /// Production candidate daily epoch length.
    #[arg(long, default_value_t = 1_152)]
    epoch_blocks: u64,

    /// Production candidate name window length per epoch.
    #[arg(long, default_value_t = 24)]
    window_blocks: u64,

    /// In-memory protobuf decode passes used to estimate local replay throughput.
    #[arg(long, default_value_t = 3)]
    local_decode_passes: u32,

    /// Persist the filtered historical workload and JSON manifest in a new directory.
    #[arg(long)]
    capture_dir: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
enum HistoricalPool {
    Orchard,
    Ironwood,
}

impl HistoricalPool {
    fn proto(self) -> PoolType {
        match self {
            Self::Orchard => PoolType::Orchard,
            Self::Ironwood => PoolType::Ironwood,
        }
    }
}

#[derive(Default)]
struct Sample {
    blocks: u64,
    transactions: u64,
    orchard_blocks: u64,
    orchard_transactions: u64,
    orchard_encoded_bytes: u64,
    ironwood_transactions: u64,
    ironwood_blocks: u64,
    ironwood_encoded_bytes: u64,
    ironwood_actions: u64,
    orchard_actions: u64,
    sapling_spends: u64,
    sapling_outputs: u64,
    encoded_bytes: u64,
    block_bytes: Vec<u64>,
    actions_per_block: Vec<u64>,
    encoded_blocks: Vec<Vec<u8>>,
}

impl Sample {
    fn push(&mut self, block: CompactBlock, pool: HistoricalPool) -> Result<()> {
        let encoded = block.encode_to_vec();
        let mut block_actions = 0u64;

        self.blocks += 1;
        self.transactions += block.vtx.len() as u64;
        for tx in &block.vtx {
            ensure!(
                tx.spends.is_empty() && tx.outputs.is_empty(),
                "server returned Sapling contents for an Orchard-family-only request at height {}",
                block.height
            );
            match pool {
                HistoricalPool::Orchard => {
                    ensure!(
                        tx.ironwood_actions.is_empty(),
                        "server returned Ironwood contents for an Orchard-only request at height {}",
                        block.height
                    );
                    if !tx.actions.is_empty() {
                        self.orchard_transactions += 1;
                    }
                    block_actions += tx.actions.len() as u64;
                }
                HistoricalPool::Ironwood => {
                    ensure!(
                        tx.actions.is_empty(),
                        "server returned Orchard contents for an Ironwood-only request at height {}",
                        block.height
                    );
                    if !tx.ironwood_actions.is_empty() {
                        self.ironwood_transactions += 1;
                    }
                    block_actions += tx.ironwood_actions.len() as u64;
                }
            }
            self.orchard_actions += tx.actions.len() as u64;
            self.sapling_spends += tx.spends.len() as u64;
            self.sapling_outputs += tx.outputs.len() as u64;
        }
        match pool {
            HistoricalPool::Orchard => {
                self.orchard_blocks += 1;
                self.orchard_encoded_bytes += encoded.len() as u64;
            }
            HistoricalPool::Ironwood => {
                self.ironwood_blocks += 1;
                self.ironwood_actions += block_actions;
                self.ironwood_encoded_bytes += encoded.len() as u64;
            }
        }
        self.encoded_bytes += encoded.len() as u64;
        self.block_bytes.push(encoded.len() as u64);
        self.actions_per_block.push(block_actions);
        self.encoded_blocks.push(encoded);
        Ok(())
    }

    fn selected_actions(&self) -> u64 {
        self.orchard_actions + self.ironwood_actions
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.sample_blocks > 0, "--sample-blocks must be positive");
    ensure!(
        cli.request_batch_blocks > 0,
        "--request-batch-blocks must be positive"
    );
    ensure!(cli.lease_blocks > 0, "--lease-blocks must be positive");
    ensure!(cli.epoch_blocks > 0, "--epoch-blocks must be positive");
    ensure!(cli.window_blocks > 0, "--window-blocks must be positive");
    ensure!(
        cli.window_blocks <= cli.epoch_blocks,
        "window cannot exceed epoch"
    );
    ensure!(
        cli.local_decode_passes > 0,
        "--local-decode-passes must be positive"
    );

    let host = cli
        .server
        .rsplit_once(':')
        .map(|(host, _)| host)
        .filter(|host| !host.is_empty())
        .context("--server must use host:port form")?;
    let uri = format!("https://{}", cli.server);

    let connect_started = Instant::now();
    let channel = Endpoint::from_shared(uri.clone())?
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(host.to_owned())
                .assume_http2(true)
                .with_webpki_roots(),
        )?
        .connect()
        .await
        .with_context(|| format!("connect to {uri}"))?;
    let connect_elapsed = connect_started.elapsed();
    let mut client = CompactTxStreamerClient::<Channel>::new(channel);

    let metadata_started = Instant::now();
    let info = client.get_lightd_info(Empty {}).await?.into_inner();
    ensure!(
        info.chain_name == "main",
        "server reports chain {:?}, not mainnet",
        info.chain_name
    );
    let latest = client.get_latest_block(ChainSpec {}).await?.into_inner();
    let metadata_elapsed = metadata_started.elapsed();

    let end = cli.end_height.unwrap_or(latest.height);
    ensure!(
        end <= latest.height,
        "end height {end} exceeds server tip {}",
        latest.height
    );
    let start = end.saturating_add(1).saturating_sub(cli.sample_blocks);
    let expected_blocks = end - start + 1;

    let stream_started = Instant::now();
    let mut sample = Sample::default();
    let mut request_count = 0u64;
    let mut batch_start = start;
    while batch_start <= end {
        let pool = if batch_start < cli.ironwood_activation_height {
            HistoricalPool::Orchard
        } else {
            HistoricalPool::Ironwood
        };
        let batch_end = batch_start
            .saturating_add(cli.request_batch_blocks - 1)
            .min(end)
            .min(match pool {
                HistoricalPool::Orchard => cli.ironwood_activation_height.saturating_sub(1),
                HistoricalPool::Ironwood => end,
            });
        let request = BlockRange {
            start: Some(BlockId {
                height: batch_start,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: batch_end,
                hash: vec![],
            }),
            pool_types: vec![pool.proto() as i32],
        };
        request_count += 1;
        let mut stream = client.get_block_range(request).await?.into_inner();
        while let Some(block) = stream.next().await {
            sample.push(block.context("decode CompactBlock from stream")?, pool)?;
        }
        if batch_end == u64::MAX {
            break;
        }
        batch_start = batch_end + 1;
    }
    let stream_elapsed = stream_started.elapsed();
    ensure!(
        sample.blocks == expected_blocks,
        "server returned {} blocks for inclusive range {start}..={end} ({expected_blocks} expected)",
        sample.blocks
    );

    let filter_honored = sample.sapling_spends == 0 && sample.sapling_outputs == 0;

    let local_started = Instant::now();
    let mut decoded_actions = 0u64;
    for _ in 0..cli.local_decode_passes {
        for encoded in &sample.encoded_blocks {
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
    let local_elapsed = local_started.elapsed();

    let sampled_blocks = sample.blocks as f64;
    let mean_bytes_per_block = sample.encoded_bytes as f64 / sampled_blocks;
    let mean_actions_per_block = sample.selected_actions() as f64 / sampled_blocks;
    let estimated_window_bytes = mean_bytes_per_block * cli.lease_blocks as f64;
    let estimated_window_actions = mean_actions_per_block * cli.lease_blocks as f64;
    let stream_bytes_per_second = sample.encoded_bytes as f64 / stream_elapsed.as_secs_f64();
    let local_blocks_per_second =
        (sample.blocks * u64::from(cli.local_decode_passes)) as f64 / local_elapsed.as_secs_f64();
    let local_bytes_per_second = (sample.encoded_bytes * u64::from(cli.local_decode_passes)) as f64
        / local_elapsed.as_secs_f64();
    let scheduled_epochs = cli.lease_blocks.div_ceil(cli.epoch_blocks);
    let scheduled_blocks = scheduled_epochs.saturating_mul(cli.window_blocks);

    let mut report = json!({
        "schema": "coppice-names-mainnet-speed-sample-v2",
        "observed_at_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "measurement_scope": {
            "observed": [
                "lightwalletd connection and stream wall time",
                "Orchard-before-NU6.3 and Ironwood-after-NU6.3 CompactBlock protobuf payload bytes",
                "Orchard-family action and transaction density with explicit pool provenance",
                "in-memory protobuf decode throughput on this machine"
            ],
            "not_observable_without_coppice": [
                "Coppice carrier hit rate",
                "full transaction fetch count and bytes",
                "Names proof verification time",
                "accepted REFRESH lineage length"
            ]
        },
        "server": {
            "endpoint": uri,
            "chain_name": info.chain_name,
            "lightwalletd_version": info.version,
            "lightwallet_protocol_version": info.lightwallet_protocol_version,
            "zcashd_build": info.zcashd_build,
            "consensus_branch_id": info.consensus_branch_id,
            "reported_tip": latest.height,
            "connect_milliseconds": millis(connect_elapsed),
            "metadata_milliseconds": millis(metadata_elapsed),
            "requested_pool_filter_honored": filter_honored
        },
        "sample": {
            "start_height": start,
            "end_height": end,
            "ironwood_activation_height": cli.ironwood_activation_height,
            "blocks": sample.blocks,
            "range_requests": request_count,
            "transactions": sample.transactions,
            "orchard_proxy": {
                "blocks": sample.orchard_blocks,
                "transactions": sample.orchard_transactions,
                "actions": sample.orchard_actions,
                "protobuf_payload_bytes": sample.orchard_encoded_bytes
            },
            "ironwood": {
                "blocks": sample.ironwood_blocks,
                "transactions": sample.ironwood_transactions,
                "actions": sample.ironwood_actions,
                "protobuf_payload_bytes": sample.ironwood_encoded_bytes
            },
            "selected_orchard_family_actions": sample.selected_actions(),
            "protobuf_payload_bytes": sample.encoded_bytes,
            "stream_wall_milliseconds": millis(stream_elapsed),
            "stream_payload_bytes_per_second": stream_bytes_per_second,
            "mean_payload_bytes_per_block": mean_bytes_per_block,
            "payload_bytes_per_block": distribution(&mut sample.block_bytes),
            "mean_selected_actions_per_block": mean_actions_per_block,
            "selected_actions_per_block": distribution(&mut sample.actions_per_block)
        },
        "local_decode": {
            "passes": cli.local_decode_passes,
            "wall_milliseconds": millis(local_elapsed),
            "blocks_per_second": local_blocks_per_second,
            "payload_bytes_per_second": local_bytes_per_second
        },
        "model": {
            "lease_blocks": cli.lease_blocks,
            "epoch_blocks": cli.epoch_blocks,
            "window_blocks": cli.window_blocks,
            "scheduled_epochs_in_lease": scheduled_epochs,
            "scheduled_candidate_blocks_in_lease": scheduled_blocks,
            "scheduled_candidate_fraction": scheduled_blocks as f64 / cli.lease_blocks as f64,
            "estimated_orchard_family_compact_payload_bytes_for_lease": estimated_window_bytes,
            "estimated_orchard_family_actions_for_lease": estimated_window_actions,
            "estimated_stream_seconds_for_lease_at_observed_rate": estimated_window_bytes / stream_bytes_per_second,
            "estimated_local_decode_seconds_for_lease_at_observed_rate": cli.lease_blocks as f64 / local_blocks_per_second,
            "nf_plus_cmx_bytes_lower_bound_for_lease": estimated_window_actions * 64.0,
            "caveats": [
                "Pre-NU6.3 Orchard blocks are a structural workload proxy, not observed Ironwood traffic.",
                "Traffic and pool migration behavior can change after the measured range.",
                "Protobuf payload bytes exclude HTTP/2, TLS, and transport framing overhead.",
                "The nf+cmx figure is a lower bound and excludes block, branch, position, indexing, and database overhead.",
                "Local decode timing excludes disk/database access, canonical validation, route decryption, full transactions, and proofs.",
                "Scheduled-window work does not remove the compact nullifier tail required to establish currentness.",
                "No full-transaction or proof cost is assumed because mainnet has no Coppice deployment."
            ]
        }
    });

    if let Some(capture_dir) = &cli.capture_dir {
        let capture = write_capture(capture_dir, &sample.encoded_blocks)?;
        report["capture"] = capture;
        write_manifest(capture_dir, &report)?;
    }

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn write_capture(directory: &Path, blocks: &[Vec<u8>]) -> Result<Value> {
    fs::create_dir_all(directory)
        .with_context(|| format!("create capture directory {}", directory.display()))?;
    let data_path = directory.join("compact-blocks.cnhs");
    let manifest_path = directory.join("manifest.json");
    ensure!(
        !data_path.exists() && !manifest_path.exists(),
        "capture directory {} already contains compact-blocks.cnhs or manifest.json",
        directory.display()
    );
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&data_path)
        .with_context(|| {
            format!(
                "create {} without overwriting an existing capture",
                data_path.display()
            )
        })?;
    let mut writer = BufWriter::new(file);
    let mut hasher = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"CoppiceHistV1\0\0\0")
        .to_state();
    let magic = b"CNHS\x01";
    writer.write_all(magic)?;
    hasher.update(magic);
    let mut file_bytes = magic.len() as u64;
    for block in blocks {
        let length = u32::try_from(block.len()).context("CompactBlock exceeds capture framing")?;
        let frame = length.to_le_bytes();
        writer.write_all(&frame)?;
        writer.write_all(block)?;
        hasher.update(&frame);
        hasher.update(block);
        file_bytes += frame.len() as u64 + block.len() as u64;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;

    Ok(json!({
        "format": "CNHS1: magic CNHS\\x01 followed by repeated u32-le length and CompactBlock protobuf bytes",
        "data_file": "compact-blocks.cnhs",
        "manifest_file": "manifest.json",
        "blocks": blocks.len(),
        "file_bytes": file_bytes,
        "blake2b_256": hex::encode(hasher.finalize().as_bytes()),
        "semantics": "Canonical filtered source sample. Synthetic Coppice injection must produce a separate derived workload and must not retain the canonical label."
    }))
}

fn write_manifest(directory: &Path, report: &Value) -> Result<()> {
    let path = directory.join("manifest.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| {
            format!(
                "create {} without overwriting an existing manifest",
                path.display()
            )
        })?;
    serde_json::to_writer_pretty(&mut file, report)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn distribution(values: &mut [u64]) -> Value {
    values.sort_unstable();
    json!({
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": values.last().copied().unwrap_or(0)
    })
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let index = (values.len() - 1) * percentile / 100;
    values[index]
}
