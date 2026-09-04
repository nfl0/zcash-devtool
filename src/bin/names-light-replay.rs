//! Measure the real Coppice/Core light-wallet replay boundary over a captured
//! Orchard-family compact-block history.
//!
//! Orchard-era actions are placed in the Ironwood compact field because this
//! tool measures the shared compact action work, not consensus-era differences.
//! The capture does not contain the historical pre-range frontier, so the
//! resulting tree is a zero-origin performance proxy and must not be used as a
//! canonical mainnet checkpoint.

use std::{
    convert::Infallible,
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use coppice::{
    carrier::CoreRendezvous,
    identity::{CoreRuntimeParameters, ZcashNetwork},
    replay::{
        CoreReplay, CoreReplayActivationCheckpoint, CoreReplayConfiguration, IronwoodFrontier,
    },
    runtime::CoreRuntime,
};
use coppice_librustzcash::{
    FullTransactionSource, prepare_canonical_block_with_additional_rendezvous,
    prepare_canonical_block_with_rendezvous_policy,
};
use coppice_names::{
    deployment::DeploymentParameters,
    names_application_id,
    proof::keygen,
    protocol::{Name, NameRoute, Network},
    resolver::ExactResolver,
    ruleset::ruleset_fingerprint,
    transport::inspect_exact_name_block,
};
use prost::Message;
use serde_json::json;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_devtool::names_config::REGTEST;
use zcash_protocol::consensus::MainNetwork;

#[derive(Debug, Parser)]
#[command(
    name = "names-light-replay",
    about = "Benchmark Core plus exact Coppice Names light-wallet replay"
)]
struct Cli {
    /// CNHS1 file produced by names-speed-sample --capture-dir.
    #[arg(long)]
    capture: PathBuf,

    /// Name whose exact public route and state are replayed.
    #[arg(long, default_value = "benchmark.zec")]
    name: String,

    /// Persist JSON results without overwriting an existing file.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Stop after this many blocks (useful for focused validation).
    #[arg(long)]
    max_blocks: Option<usize>,

    /// Core rewind history retained during replay.
    #[arg(long, default_value_t = 100)]
    rewind_blocks: u32,

    /// Carrier routes evaluated during replay.
    #[arg(long, value_enum, default_value_t = RoutePolicy::Current)]
    route_policy: RoutePolicy,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RoutePolicy {
    /// Generic Coppice rendezvous plus the scheduled exact-name route.
    Current,
    /// Scheduled exact-name route only; historical COMMITs are reference-fetched.
    Referenced,
    /// No carrier routes; calibrates compact/Core work alone.
    None,
}

#[derive(Default)]
struct Timings {
    decode: Duration,
    prepare: Duration,
    core: Duration,
    transport: Duration,
    reducer: Duration,
}

struct NoFullTransactions;

impl FullTransactionSource for NoFullTransactions {
    type Error = Infallible;

    fn full_transaction(&mut self, _txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.rewind_blocks > 0, "rewind retention must be positive");
    let raw = read_capture(&cli.capture, cli.max_blocks)?;
    ensure!(!raw.is_empty(), "capture contains no blocks");

    // Key generation is deployment setup, not per-resolution work.
    let keygen_started = Instant::now();
    let (_, verifier) = keygen();
    let keygen_elapsed = keygen_started.elapsed();

    let first = CompactBlock::decode(raw[0].as_slice()).context("decode first compact block")?;
    let activation_height = u32::try_from(first.height).context("activation height exceeds u32")?;
    let activation_parent_hash: [u8; 32] = first
        .prev_hash
        .as_slice()
        .try_into()
        .context("activation parent hash has wrong length")?;
    let runtime_parameters = CoreRuntimeParameters {
        zcash_network_domain: b"coppice-names-mainnet-performance-proxy".to_vec(),
        zcash_network: ZcashNetwork::Main,
        runtime_activation_height: activation_height,
        rendezvous_ivk: REGTEST.rendezvous.orchard_ivk,
        rendezvous_receiver: REGTEST.rendezvous.orchard_receiver,
    }
    .validate()
    .map_err(|error| anyhow::anyhow!("validate runtime parameters: {error:?}"))?;
    let configuration = CoreReplayConfiguration::new(activation_height, cli.rewind_blocks)
        .map_err(|error| anyhow::anyhow!("configure Core replay: {error:?}"))?;
    let replay = CoreReplay::new(
        configuration,
        CoreReplayActivationCheckpoint {
            height: activation_height - 1,
            block_hash: activation_parent_hash,
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .map_err(|error| anyhow::anyhow!("initialize Core replay: {error:?}"))?;
    let mut runtime = CoreRuntime::new(runtime_parameters.clone(), replay)
        .map_err(|error| anyhow::anyhow!("initialize Core runtime: {error:?}"))?;
    let deployment = DeploymentParameters::candidate(
        runtime_parameters.core_runtime_id(),
        activation_height,
        verifier.identity(),
    );
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive Names deployment: {error:?}"))?;
    let schedule = deployment.schedule(deployment_id);
    let name =
        Name::parse(&cli.name).map_err(|error| anyhow::anyhow!("parse exact name: {error:?}"))?;
    let name_id = name
        .id()
        .map_err(|error| anyhow::anyhow!("derive name id: {error:?}"))?;
    let route = NameRoute::derive(deployment_id, name_id)
        .map_err(|error| anyhow::anyhow!("derive name route: {error:?}"))?;
    let rendezvous = CoreRendezvous::try_new(&route.incoming_viewing_key(), &route.receiver())
        .map_err(|error| anyhow::anyhow!("construct exact rendezvous: {error:?}"))?;
    let mut resolver = ExactResolver::new(schedule, activation_parent_hash, name.clone(), verifier)
        .map_err(|error| anyhow::anyhow!("initialize exact resolver: {error:?}"))?;
    let mut source = NoFullTransactions;

    let wall_started = Instant::now();
    let mut timings = Timings::default();
    let mut compact_payload_bytes = 0u64;
    let mut transactions = 0u64;
    let mut actions = 0u64;
    let mut scheduled_blocks = 0u64;
    let mut accepted_operations = 0u64;
    let mut last_height = activation_height - 1;

    for encoded in &raw {
        compact_payload_bytes = compact_payload_bytes.saturating_add(encoded.len() as u64);

        let started = Instant::now();
        let mut compact =
            CompactBlock::decode(encoded.as_slice()).context("decode compact block")?;
        // Orchard and Ironwood share the action representation relevant here.
        for transaction in &mut compact.vtx {
            if transaction.ironwood_actions.is_empty() {
                transaction
                    .ironwood_actions
                    .append(&mut transaction.actions);
            } else {
                ensure!(
                    transaction.actions.is_empty(),
                    "block {} transaction {} unexpectedly carries both Orchard and Ironwood actions",
                    compact.height,
                    transaction.index
                );
            }
        }
        timings.decode += started.elapsed();

        let height = u32::try_from(compact.height).context("block height exceeds u32")?;
        let scheduled = schedule.accepts_operation(name_id, height);
        if scheduled {
            scheduled_blocks += 1;
        }
        let additional = if scheduled && !matches!(cli.route_policy, RoutePolicy::None) {
            std::slice::from_ref(&rendezvous)
        } else {
            &[]
        };
        transactions = transactions.saturating_add(compact.vtx.len() as u64);
        actions = actions.saturating_add(
            compact
                .vtx
                .iter()
                .map(|transaction| transaction.ironwood_actions.len() as u64)
                .sum::<u64>(),
        );

        let started = Instant::now();
        let canonical = match cli.route_policy {
            RoutePolicy::Current => prepare_canonical_block_with_additional_rendezvous(
                &MainNetwork,
                &runtime,
                &compact,
                &mut source,
                additional,
            ),
            RoutePolicy::Referenced | RoutePolicy::None => {
                prepare_canonical_block_with_rendezvous_policy(
                    &MainNetwork,
                    &runtime,
                    &compact,
                    &mut source,
                    false,
                    additional,
                )
            }
        }
        .map_err(|error| anyhow::anyhow!("prepare compact block {height}: {error:?}"))?;
        timings.prepare += started.elapsed();

        let started = Instant::now();
        let applied = runtime
            .apply_block(&canonical)
            .map_err(|error| anyhow::anyhow!("apply Core block {height}: {error:?}"))?;
        timings.core += started.elapsed();

        let started = Instant::now();
        let names_block = inspect_exact_name_block(
            applied.core(),
            &runtime_parameters,
            deployment,
            Network::Main,
            &name,
        )
        .map_err(|error| anyhow::anyhow!("inspect Names block {height}: {error:?}"))?;
        timings.transport += started.elapsed();

        let started = Instant::now();
        accepted_operations = accepted_operations.saturating_add(
            resolver
                .apply_block(&names_block)
                .map_err(|error| anyhow::anyhow!("apply Names block {height}: {error:?}"))?
                .len() as u64,
        );
        timings.reducer += started.elapsed();
        last_height = height;
    }
    let wall = wall_started.elapsed();
    let resolution = resolver
        .resolve(last_height)
        .map_err(|error| anyhow::anyhow!("resolve exact name at {last_height}: {error:?}"))?;
    let measured =
        timings.decode + timings.prepare + timings.core + timings.transport + timings.reducer;
    let seconds = |duration: Duration| duration.as_secs_f64();
    let report = json!({
        "schema": "coppice-names-light-replay-v1",
        "protocol_identity": {
            "deployment_id_hex": hex::encode(deployment_id),
            "application_id_hex": hex::encode(names_application_id(deployment_id).to_bytes()),
            "ruleset_fingerprint_hex": hex::encode(ruleset_fingerprint())
        },
        "source": {
            "capture": cli.capture,
            "blocks": raw.len(),
            "start_height": activation_height,
            "end_height": last_height,
            "compact_payload_bytes": compact_payload_bytes,
            "transactions": transactions,
            "orchard_family_actions": actions,
            "pool_model": "Orchard-era compact actions are processed as equivalent Ironwood actions.",
            "frontier_model": "Zero-origin range-local frontier; suitable for performance measurement, not a canonical mainnet checkpoint."
        },
        "workload": {
            "exact_name": name.as_str(),
            "route_policy": format!("{:?}", cli.route_policy),
            "scheduled_route_blocks": scheduled_blocks,
            "rewind_retention_blocks": cli.rewind_blocks,
            "full_transactions_fetched": 0,
            "accepted_names_operations": accepted_operations,
            "final_lifecycle": format!("{:?}", resolution.lifecycle),
            "authority_checks": [
                "compact shape and canonical action decoding",
                "sequential height and predecessor linkage",
                "canonical transaction and action ordering",
                "canonical nullifier and commitment encodings",
                "Ironwood frontier append and checkpoints",
                "exact-route trial decryption in scheduled blocks",
                "Names transport conversion and exact reducer rules"
            ]
        },
        "setup": {
            "proof_key_generation_seconds_excluded_from_replay": seconds(keygen_elapsed)
        },
        "timing_seconds": {
            "wall": seconds(wall),
            "measured_components": seconds(measured),
            "compact_decode_and_pool_normalization": seconds(timings.decode),
            "candidate_validation_and_trial_decryption": seconds(timings.prepare),
            "core_replay_frontier_and_checkpoints": seconds(timings.core),
            "names_transport": seconds(timings.transport),
            "names_exact_reducer": seconds(timings.reducer),
            "blocks_per_second": raw.len() as f64 / seconds(wall),
            "actions_per_second": actions as f64 / seconds(wall)
        },
        "not_measured_here": [
            "network transfer time",
            "full-transaction fetches because mainnet contains no Coppice deployment",
            "wallet database persistence and reorg integration",
            "Zcash consensus transaction verification"
        ]
    });
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

fn read_capture(path: &PathBuf, max_blocks: Option<usize>) -> Result<Vec<Vec<u8>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open capture {}", path.display()))?,
    );
    let mut magic = [0u8; 5];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == b"CNHS\x01", "capture has wrong CNHS1 magic");
    let mut blocks = Vec::new();
    while max_blocks.is_none_or(|limit| blocks.len() < limit) {
        let mut length = [0u8; 4];
        match reader.read(&mut length[..1])? {
            0 => break,
            1 => reader
                .read_exact(&mut length[1..])
                .context("truncated CNHS1 frame length")?,
            _ => unreachable!("one-byte read returned more than one byte"),
        }
        let length = u32::from_le_bytes(length) as usize;
        ensure!(length <= 16 * 1024 * 1024, "capture frame exceeds 16 MiB");
        let mut block = vec![0u8; length];
        reader.read_exact(&mut block)?;
        blocks.push(block);
    }
    Ok(blocks)
}
