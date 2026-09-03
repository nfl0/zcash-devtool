//! Isolate compact rendezvous trial-decryption cost over a CNHS1 history.

use std::{
    fs::File,
    hint::black_box,
    io::{BufReader, Read},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use coppice::{
    carrier::CoreRendezvous,
    identity::{CoreRuntimeParameters, ZcashNetwork},
};
use coppice_names::{
    deployment::DeploymentParameters,
    proof::keygen,
    protocol::{Name, NameRoute},
};
use orchard::note_encryption::CompactAction;
use prost::Message;
use serde_json::json;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_devtool::names_config::REGTEST;

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long)]
    capture: PathBuf,
    #[arg(long, default_value = "benchmark.zec")]
    name: String,
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let raw = read_capture(&cli.capture)?;
    ensure!(!raw.is_empty(), "capture contains no blocks");
    let first = CompactBlock::decode(raw[0].as_slice())?;
    let activation_height = u32::try_from(first.height)?;
    let runtime = CoreRuntimeParameters {
        runtime_protocol_id: b"coppice.runtime".to_vec(),
        runtime_protocol_version: 1,
        zcash_network_domain: b"coppice-names-mainnet-performance-proxy-v1".to_vec(),
        zcash_network: ZcashNetwork::Main,
        runtime_activation_height: activation_height,
        carrier_protocol_id: b"CPV1".to_vec(),
        rendezvous_ivk: REGTEST.rendezvous.orchard_ivk,
        rendezvous_receiver: REGTEST.rendezvous.orchard_receiver,
    }
    .validate()
    .map_err(|error| anyhow::anyhow!("validate Core parameters: {error:?}"))?;
    let (_, verifier) = keygen();
    let deployment = DeploymentParameters::candidate(
        runtime.core_runtime_id(),
        activation_height,
        verifier.identity(),
    );
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow::anyhow!("derive deployment: {error:?}"))?;
    let schedule = deployment.schedule(deployment_id);
    let name =
        Name::parse(&cli.name).map_err(|error| anyhow::anyhow!("parse exact name: {error:?}"))?;
    let name_id = name
        .id()
        .map_err(|error| anyhow::anyhow!("derive name ID: {error:?}"))?;
    let name_route = NameRoute::derive(deployment_id, name_id)
        .map_err(|error| anyhow::anyhow!("derive name route: {error:?}"))?;
    let exact = CoreRendezvous::try_new(&name_route.incoming_viewing_key(), &name_route.receiver())
        .map_err(|error| anyhow::anyhow!("construct exact route: {error:?}"))?;
    let generic = CoreRendezvous::from_validated(&runtime);

    let baseline = scan(&raw, schedule, name_id, None)?;
    let exact_scan = scan(&raw, schedule, name_id, Some((&exact, true)))?;
    let generic_scan = scan(&raw, schedule, name_id, Some((&generic, false)))?;
    ensure!(
        baseline.actions == exact_scan.actions && baseline.actions == generic_scan.actions,
        "route passes observed different action counts"
    );
    let report = json!({
        "schema": "coppice-names-route-history-v1",
        "source": {
            "capture": cli.capture,
            "blocks": raw.len(),
            "orchard_family_actions": baseline.actions,
            "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
            "pool_model": "Orchard-era compact actions are treated as Ironwood-equivalent compact actions."
        },
        "workload": {
            "exact_name": name.as_str(),
            "scheduled_blocks": exact_scan.scheduled_blocks,
            "generic_route_blocks": raw.len(),
            "route_hits": {
                "generic": generic_scan.hits,
                "exact": exact_scan.hits
            }
        },
        "timing_seconds": {
            "decode_and_validate_actions_only": baseline.seconds,
            "scheduled_exact_route_total": exact_scan.seconds,
            "continuous_generic_route_total": generic_scan.seconds,
            "scheduled_exact_route_incremental": (exact_scan.seconds - baseline.seconds).max(0.0),
            "continuous_generic_route_incremental": (generic_scan.seconds - baseline.seconds).max(0.0)
        },
        "interpretation": [
            "No Coppice deployment exists in the captured history, so every trial decryption is a miss.",
            "The exact route is evaluated only in the requested name's deterministic windows.",
            "The generic route is evaluated for every action and models the deprecated continuous acquisition policy."
        ]
    });
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(path) = cli.output {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("create {} without overwriting", path.display()))?;
        use std::io::Write as _;
        file.write_all(rendered.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    println!("{rendered}");
    Ok(())
}

struct ScanResult {
    seconds: f64,
    actions: u64,
    hits: u64,
    scheduled_blocks: u64,
}

fn scan(
    raw: &[Vec<u8>],
    schedule: coppice_names::schedule::Parameters,
    name_id: coppice_names::protocol::NameId,
    route: Option<(&CoreRendezvous, bool)>,
) -> Result<ScanResult> {
    let started = Instant::now();
    let mut actions = 0u64;
    let mut hits = 0u64;
    let mut scheduled_blocks = 0u64;
    for encoded in raw {
        let block = CompactBlock::decode(encoded.as_slice())?;
        let height = u32::try_from(block.height)?;
        let scheduled = schedule.accepts_operation(name_id, height);
        if scheduled {
            scheduled_blocks += 1;
        }
        for transaction in &block.vtx {
            for encoded_action in transaction
                .ironwood_actions
                .iter()
                .chain(&transaction.actions)
            {
                let action = CompactAction::try_from(encoded_action)
                    .map_err(|_| anyhow::anyhow!("invalid compact action at height {height}"))?;
                actions += 1;
                if let Some((rendezvous, exact_only)) = route {
                    if (!exact_only || scheduled)
                        && rendezvous.compact_action_is_rendezvous(&action)
                    {
                        hits += 1;
                    }
                }
                black_box(action);
            }
        }
    }
    Ok(ScanResult {
        seconds: started.elapsed().as_secs_f64(),
        actions,
        hits,
        scheduled_blocks,
    })
}

fn read_capture(path: &PathBuf) -> Result<Vec<Vec<u8>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut magic = [0u8; 5];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == b"CNHS\x01", "capture has wrong CNHS1 magic");
    let mut blocks = Vec::new();
    loop {
        let mut length = [0u8; 4];
        match reader.read(&mut length[..1])? {
            0 => break,
            1 => reader.read_exact(&mut length[1..])?,
            _ => unreachable!(),
        }
        let mut block = vec![0u8; u32::from_le_bytes(length) as usize];
        reader.read_exact(&mut block)?;
        blocks.push(block);
    }
    Ok(blocks)
}
