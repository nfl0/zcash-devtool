//! Measure mainnet Ironwood compact-block characteristics for Coppice Names estimates.
//!
//! This deliberately measures only chain and lightwalletd properties. A chain with no
//! Coppice deployment cannot measure Names carrier frequency, proof verification, or
//! full-transaction acquisition, so those are reported as unmeasured rather than zero.

use std::{
    hint::black_box,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
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
    about = "Sample mainnet Ironwood compact blocks and estimate Coppice Names scan costs"
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
}

#[derive(Default)]
struct Sample {
    blocks: u64,
    transactions: u64,
    ironwood_transactions: u64,
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
    fn push(&mut self, block: CompactBlock) {
        let encoded = block.encode_to_vec();
        let mut block_actions = 0u64;

        self.blocks += 1;
        self.transactions += block.vtx.len() as u64;
        for tx in &block.vtx {
            if !tx.ironwood_actions.is_empty() {
                self.ironwood_transactions += 1;
            }
            block_actions += tx.ironwood_actions.len() as u64;
            self.orchard_actions += tx.actions.len() as u64;
            self.sapling_spends += tx.spends.len() as u64;
            self.sapling_outputs += tx.outputs.len() as u64;
        }
        self.ironwood_actions += block_actions;
        self.encoded_bytes += encoded.len() as u64;
        self.block_bytes.push(encoded.len() as u64);
        self.actions_per_block.push(block_actions);
        self.encoded_blocks.push(encoded);
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
        let batch_end = batch_start
            .saturating_add(cli.request_batch_blocks - 1)
            .min(end);
        let request = BlockRange {
            start: Some(BlockId {
                height: batch_start,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: batch_end,
                hash: vec![],
            }),
            pool_types: vec![PoolType::Ironwood as i32],
        };
        request_count += 1;
        let mut stream = client.get_block_range(request).await?.into_inner();
        while let Some(block) = stream.next().await {
            sample.push(block.context("decode CompactBlock from stream")?);
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

    let filter_honored =
        sample.orchard_actions == 0 && sample.sapling_spends == 0 && sample.sapling_outputs == 0;
    if !filter_honored {
        bail!(
            "server did not honor the Ironwood-only filter: saw {} Orchard actions, {} Sapling spends, and {} Sapling outputs",
            sample.orchard_actions,
            sample.sapling_spends,
            sample.sapling_outputs
        );
    }

    let local_started = Instant::now();
    let mut decoded_actions = 0u64;
    for _ in 0..cli.local_decode_passes {
        for encoded in &sample.encoded_blocks {
            let block = CompactBlock::decode(encoded.as_slice())?;
            decoded_actions += block
                .vtx
                .iter()
                .map(|tx| tx.ironwood_actions.len() as u64)
                .sum::<u64>();
            black_box(&block);
        }
    }
    black_box(decoded_actions);
    let local_elapsed = local_started.elapsed();

    let sampled_blocks = sample.blocks as f64;
    let mean_bytes_per_block = sample.encoded_bytes as f64 / sampled_blocks;
    let mean_actions_per_block = sample.ironwood_actions as f64 / sampled_blocks;
    let estimated_window_bytes = mean_bytes_per_block * cli.lease_blocks as f64;
    let estimated_window_actions = mean_actions_per_block * cli.lease_blocks as f64;
    let stream_bytes_per_second = sample.encoded_bytes as f64 / stream_elapsed.as_secs_f64();
    let local_blocks_per_second =
        (sample.blocks * u64::from(cli.local_decode_passes)) as f64 / local_elapsed.as_secs_f64();
    let local_bytes_per_second = (sample.encoded_bytes * u64::from(cli.local_decode_passes)) as f64
        / local_elapsed.as_secs_f64();
    let scheduled_epochs = cli.lease_blocks.div_ceil(cli.epoch_blocks);
    let scheduled_blocks = scheduled_epochs.saturating_mul(cli.window_blocks);

    let report = json!({
        "schema": "coppice-names-mainnet-speed-sample-v1",
        "observed_at_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "measurement_scope": {
            "observed": [
                "lightwalletd connection and stream wall time",
                "Ironwood-only CompactBlock protobuf payload bytes",
                "Ironwood action and transaction density",
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
            "ironwood_only_filter_honored": filter_honored
        },
        "sample": {
            "start_height": start,
            "end_height": end,
            "blocks": sample.blocks,
            "range_requests": request_count,
            "transactions": sample.transactions,
            "ironwood_transactions": sample.ironwood_transactions,
            "ironwood_actions": sample.ironwood_actions,
            "protobuf_payload_bytes": sample.encoded_bytes,
            "stream_wall_milliseconds": millis(stream_elapsed),
            "stream_payload_bytes_per_second": stream_bytes_per_second,
            "mean_payload_bytes_per_block": mean_bytes_per_block,
            "payload_bytes_per_block": distribution(&mut sample.block_bytes),
            "mean_ironwood_actions_per_block": mean_actions_per_block,
            "ironwood_actions_per_block": distribution(&mut sample.actions_per_block)
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
            "estimated_ironwood_compact_payload_bytes_for_lease": estimated_window_bytes,
            "estimated_ironwood_actions_for_lease": estimated_window_actions,
            "estimated_stream_seconds_for_lease_at_observed_rate": estimated_window_bytes / stream_bytes_per_second,
            "estimated_local_decode_seconds_for_lease_at_observed_rate": cli.lease_blocks as f64 / local_blocks_per_second,
            "ironwood_nf_plus_cmx_bytes_lower_bound_for_lease": estimated_window_actions * 64.0,
            "caveats": [
                "Estimates linearly extrapolate the sampled recent range; traffic can change.",
                "Protobuf payload bytes exclude HTTP/2, TLS, and transport framing overhead.",
                "The nf+cmx figure is a lower bound and excludes block, branch, position, indexing, and database overhead.",
                "Scheduled-window work does not remove the compact nullifier tail required to establish currentness.",
                "No full-transaction or proof cost is assumed because mainnet has no Coppice deployment."
            ]
        }
    });

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
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
