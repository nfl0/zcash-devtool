//! Measure light-wallet work caused by deliberate public-rendezvous hits.
//!
//! Transactions are structurally parseable Ironwood V6 transactions with
//! matching compact effects. Their dummy bundle proof makes them unsuitable
//! for broadcast; consensus verification is intentionally outside the light
//! wallet boundary being measured.

use std::{fs::File, hint::black_box, path::PathBuf, time::Instant};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use coppice::{
    carrier::CoreRendezvous,
    identity::{CoreRuntimeParameters, ValidatedCoreRuntimeParameters, ZcashNetwork},
    replay::{
        CoreReplay, CoreReplayActivationCheckpoint, CoreReplayConfiguration, IronwoodFrontier,
    },
    runtime::CoreRuntime,
};
use coppice_librustzcash::{
    FullTransactionSource, prepare_canonical_block_with_additional_rendezvous,
};
use coppice_names::{
    codec::{CodecParameters, Operation, decode},
    deployment::DeploymentParameters,
    proof::keygen,
    protocol::{Name, NameRoute, Network},
    publication::{PublicationRoute, prepare_publication},
    transport::inspect_exact_name_block,
};
use orchard::{
    Proof,
    builder::{Builder, BundleType},
    bundle::{Authorized as OrchardAuthorized, BundleVersion},
    keys::{FullViewingKey, Scope, SpendingKey},
    primitives::redpallas::{Binding, SigningKey, SpendAuth},
    value::NoteValue,
};
use serde_json::{Value, json};
use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactOrchardAction, CompactTx};
use zcash_primitives::transaction::{Authorized, TransactionData};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    local_consensus::LocalNetwork,
    value::ZatBalance,
};

#[derive(Debug, Parser)]
#[command(
    name = "names-route-bench",
    about = "Benchmark adversarial Coppice rendezvous hits in a light wallet"
)]
struct Cli {
    /// Frozen protocol.json vector.
    #[arg(long)]
    vector: PathBuf,

    /// Samples per route-hit scenario.
    #[arg(long, default_value_t = 250)]
    iterations: u32,

    /// Persist JSON results without overwriting an existing file.
    #[arg(long)]
    output: Option<PathBuf>,
}

struct Fixture {
    bytes: Vec<u8>,
    compact: Vec<CompactOrchardAction>,
    txid: [u8; 32],
}

struct Source {
    txid: [u8; 32],
    bytes: Vec<u8>,
    calls: usize,
}

impl FullTransactionSource for Source {
    type Error = &'static str;

    fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        if txid != self.txid {
            return Err("unexpected transaction id");
        }
        self.calls += 1;
        Ok(Some(self.bytes.clone()))
    }
}

#[derive(Default)]
struct Timing {
    prepare_ms: Vec<f64>,
    core_ms: Vec<f64>,
    names_transport_ms: Vec<f64>,
    fetched: u64,
    decoded_operations: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.iterations > 0, "iterations must be positive");
    let document: Value = serde_json::from_reader(
        File::open(&cli.vector).with_context(|| format!("open {}", cli.vector.display()))?,
    )?;
    let runtime_parameters = runtime_parameters(&document)?;
    let (_, verifier) = keygen();
    let deployment = DeploymentParameters::candidate(
        runtime_parameters.core_runtime_id(),
        u32_value(&document, "/parameters/activation_height")?,
        verifier.identity(),
    );
    ensure!(
        hex::encode(deployment.deployment_id().map_err(debug_error)?)
            == string_value(&document, "/identity/deployment_id_hex")?,
        "vector deployment identity mismatch"
    );
    let codec = CodecParameters {
        reveal_proof_bytes: usize_value(&document, "/identity/reveal_proof_bytes")?,
        refresh_proof_bytes: usize_value(&document, "/identity/refresh_proof_bytes")?,
    };
    let commit = decode_operation(&document, "commit", codec)?;
    let reveal = decode_operation(&document, "reveal", codec)?;
    let name = match &reveal {
        Operation::Reveal { name, .. } => name.clone(),
        _ => anyhow::bail!("REVEAL vector decoded as another operation"),
    };
    let deployment_id = deployment.deployment_id().map_err(debug_error)?;
    let route =
        NameRoute::derive(deployment_id, name.id().map_err(debug_error)?).map_err(debug_error)?;
    let exact_rendezvous =
        CoreRendezvous::try_new(&route.incoming_viewing_key(), &route.receiver())
            .map_err(debug_error)?;
    let generic_receiver = orchard::Address::from_raw_address_bytes(
        &runtime_parameters.parameters().rendezvous_receiver,
    )
    .into_option()
    .context("invalid generic receiver after validation")?;
    let exact_receiver = orchard::Address::from_raw_address_bytes(&route.receiver())
        .into_option()
        .context("invalid exact-name receiver")?;
    let decoy_key = SpendingKey::from_bytes([71; 32])
        .into_option()
        .context("decoy key")?;
    let decoy_receiver = FullViewingKey::from(&decoy_key).address_at(0u32, Scope::External);

    let commit_publication = prepare_publication(commit, deployment).map_err(debug_error)?;
    ensure!(
        commit_publication.route() == PublicationRoute::Generic,
        "COMMIT route drift"
    );
    let commit_fixture = full_transaction(
        commit_publication.frames(),
        generic_receiver,
        decoy_receiver,
        11,
    )?;
    let reveal_publication = prepare_publication(reveal, deployment).map_err(debug_error)?;
    ensure!(
        matches!(reveal_publication.route(), PublicationRoute::Name(_)),
        "REVEAL route drift"
    );
    let reveal_fixture = full_transaction(
        reveal_publication.frames(),
        exact_receiver,
        decoy_receiver,
        23,
    )?;
    let malformed_fixture = full_transaction(&[[0u8; 512]], exact_receiver, decoy_receiver, 37)?;

    let no_route = benchmark(
        cli.iterations,
        &runtime_parameters,
        deployment,
        &name,
        &reveal_fixture,
        &[],
    )?;
    let generic_commit = benchmark(
        cli.iterations,
        &runtime_parameters,
        deployment,
        &name,
        &commit_fixture,
        &[],
    )?;
    let exact_reveal = benchmark(
        cli.iterations,
        &runtime_parameters,
        deployment,
        &name,
        &reveal_fixture,
        std::slice::from_ref(&exact_rendezvous),
    )?;
    let malformed_exact = benchmark(
        cli.iterations,
        &runtime_parameters,
        deployment,
        &name,
        &malformed_fixture,
        std::slice::from_ref(&exact_rendezvous),
    )?;

    let report = json!({
        "schema": "coppice-names-route-adversarial-calibration-v1",
        "source": {
            "vector": cli.vector,
            "network": "Regtest with Ironwood active; cryptographic route and transaction parsing work are shared with mainnet",
            "transaction_validity": "Parseable V6 transactions with compact/full equality and dummy bundle proofs; not broadcastable consensus fixtures"
        },
        "fixtures": {
            "generic_commit": fixture_json(&commit_fixture),
            "exact_reveal": fixture_json(&reveal_fixture),
            "malformed_exact": fixture_json(&malformed_fixture)
        },
        "measurements": {
            "same_13_action_transaction_without_route_selection": timing_json(&no_route, cli.iterations),
            "generic_commit_route_hit": timing_json(&generic_commit, cli.iterations),
            "exact_name_reveal_route_hit": timing_json(&exact_reveal, cli.iterations),
            "malformed_single_action_exact_route_hit": timing_json(&malformed_exact, cli.iterations)
        },
        "adversarial_interpretation": [
            "The generic COMMIT rendezvous is continuously observable, so a deliberate hit can force selective full-transaction acquisition in any active block.",
            "An exact-name rendezvous is enabled only in that name's deterministic operation windows, bounding off-window attacker amplification.",
            "Core authenticates txid and compact/full Ironwood effects before Names parses any publication.",
            "Malformed routed publications retain their public action effects and become inert Names operations.",
            "Network transfer latency and bytes are modeled separately from these local CPU measurements."
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

fn benchmark(
    iterations: u32,
    parameters: &ValidatedCoreRuntimeParameters,
    deployment: DeploymentParameters,
    name: &Name,
    fixture: &Fixture,
    additional: &[CoreRendezvous],
) -> Result<Timing> {
    let mut total = Timing::default();
    for iteration in 0..iterations {
        let mut runtime = runtime(parameters.clone())?;
        let compact = CompactBlock {
            height: 10,
            hash: block_hash(iteration),
            prev_hash: vec![9; 32],
            vtx: vec![CompactTx {
                index: 0,
                txid: fixture.txid.to_vec(),
                ironwood_actions: fixture.compact.clone(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut source = Source {
            txid: fixture.txid,
            bytes: fixture.bytes.clone(),
            calls: 0,
        };
        let started = Instant::now();
        let canonical = prepare_canonical_block_with_additional_rendezvous(
            &local_consensus(),
            &runtime,
            &compact,
            &mut source,
            additional,
        )
        .map_err(|error| anyhow::anyhow!("prepare route fixture: {error:?}"))?;
        total
            .prepare_ms
            .push(started.elapsed().as_secs_f64() * 1_000.0);
        total.fetched += source.calls as u64;

        let started = Instant::now();
        let applied = runtime.apply_block(&canonical).map_err(debug_error)?;
        total
            .core_ms
            .push(started.elapsed().as_secs_f64() * 1_000.0);

        let started = Instant::now();
        let block = inspect_exact_name_block(
            applied.core(),
            parameters,
            deployment,
            Network::Regtest,
            name,
        )
        .map_err(debug_error)?;
        total
            .names_transport_ms
            .push(started.elapsed().as_secs_f64() * 1_000.0);
        total.decoded_operations += block
            .transactions
            .iter()
            .filter(|transaction| transaction.operation.is_some())
            .count() as u64;
        black_box(block);
    }
    Ok(total)
}

fn full_transaction(
    frames: &[[u8; 512]],
    route_receiver: orchard::Address,
    decoy_receiver: orchard::Address,
    seed: u8,
) -> Result<Fixture> {
    let version = BundleVersion::ironwood_v3();
    let mut builder = Builder::new(
        BundleType::UNPADDED,
        version,
        version.default_flags(),
        orchard::Anchor::empty_tree(),
    )
    .map_err(debug_error)?;
    for frame in frames {
        builder
            .add_output(None, route_receiver, NoteValue::from_raw(0), *frame)
            .map_err(debug_error)?;
    }
    // Match the qualified 13-action REVEAL/REFRESH shape without adding more
    // routed frames. A one-frame malformed fixture remains three actions.
    for _ in 0..2 {
        builder
            .add_output(None, decoy_receiver, NoteValue::from_raw(0), [0; 512])
            .map_err(debug_error)?;
    }
    let mut rng = rand::rng();
    let (unauthorized, _) = builder
        .build::<ZatBalance>(&mut rng)
        .map_err(debug_error)?
        .context("empty Orchard bundle")?;
    let count = unauthorized.actions().len();
    let spend_key = SigningKey::<SpendAuth>::try_from([seed.max(1); 32]).map_err(debug_error)?;
    let binding_key =
        SigningKey::<Binding>::try_from([seed.wrapping_add(1).max(1); 32]).map_err(debug_error)?;
    let proof = Proof::new(vec![0; Proof::expected_proof_size(count)]);
    let bundle = unauthorized.map_authorization(
        &mut rng,
        |rng, _, _| spend_key.sign(&mut *rng, b"CoppiceRouteBenchmarkSpend"),
        |rng, _| {
            OrchardAuthorized::from_parts(
                proof,
                binding_key.sign(&mut *rng, b"CoppiceRouteBenchmarkBinding"),
            )
        },
    );
    let transaction = TransactionData::<Authorized>::from_parts_v6(
        BranchId::Nu6_3,
        0,
        BlockHeight::from_u32(10),
        None,
        None,
        None,
        Some(bundle),
    )
    .freeze()
    .map_err(debug_error)?;
    let compact = transaction
        .ironwood_bundle()
        .context("missing Ironwood bundle")?
        .actions()
        .iter()
        .map(|action| CompactOrchardAction {
            nullifier: action.nullifier().to_bytes().to_vec(),
            cmx: action.cmx().to_bytes().to_vec(),
            ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
            ciphertext: action.encrypted_note().enc_ciphertext[..52].to_vec(),
        })
        .collect();
    let txid = transaction.txid().into();
    let mut bytes = Vec::new();
    transaction.write(&mut bytes)?;
    Ok(Fixture {
        bytes,
        compact,
        txid,
    })
}

fn runtime(parameters: ValidatedCoreRuntimeParameters) -> Result<CoreRuntime> {
    let replay = CoreReplay::new(
        CoreReplayConfiguration::new(10, 1).map_err(debug_error)?,
        CoreReplayActivationCheckpoint {
            height: 9,
            block_hash: [9; 32],
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    )
    .map_err(debug_error)?;
    CoreRuntime::new(parameters, replay).map_err(debug_error)
}

fn runtime_parameters(document: &Value) -> Result<ValidatedCoreRuntimeParameters> {
    let input = &document["identity"];
    let parameters = CoreRuntimeParameters {
        zcash_network_domain: b"coppice-runtime-regtest".to_vec(),
        zcash_network: ZcashNetwork::Regtest,
        runtime_activation_height: 10,
        rendezvous_ivk: hex::decode(
            "65deb2b3ee7ac69020543f40f21122cb6dc1f4201a329fcdf9d5e3bb2dfbbabe29d542352fe36c3c7b24c2989dc9d0000b9e04f444e05dc4538bde395c0e6008",
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid rendezvous IVK length"))?,
        rendezvous_receiver: hex::decode(
            "9ec59e4d447ba285086cc3456cadf62004a19b6a7989c726daaa9944a6cdbf25f7bfa51afa15b66da53881",
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid rendezvous receiver length"))?,
    }
    .validate()
    .map_err(debug_error)?;
    ensure!(
        hex::encode(parameters.core_runtime_id().to_bytes())
            == input["core_runtime_id_hex"]
                .as_str()
                .context("core runtime id")?,
        "runtime identity does not match vector"
    );
    Ok(parameters)
}

fn local_consensus() -> LocalNetwork {
    let active = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: active,
        sapling: active,
        blossom: active,
        heartwood: active,
        canopy: active,
        nu5: active,
        nu6: active,
        nu6_1: active,
        nu6_2: active,
        nu6_3: active,
    }
}

fn fixture_json(fixture: &Fixture) -> Value {
    json!({
        "serialized_transaction_bytes": fixture.bytes.len(),
        "compact_actions": fixture.compact.len(),
        "compact_action_bytes": fixture.compact.len() * 148
    })
}

fn timing_json(timing: &Timing, iterations: u32) -> Value {
    let total = timing
        .prepare_ms
        .iter()
        .zip(&timing.core_ms)
        .zip(&timing.names_transport_ms)
        .map(|((prepare, core), transport)| prepare + core + transport)
        .collect::<Vec<_>>();
    json!({
        "iterations": iterations,
        "full_transactions_fetched": timing.fetched,
        "decoded_names_operations": timing.decoded_operations,
        "prepare_trial_decrypt_and_in_memory_fetch_ms": distribution(&timing.prepare_ms),
        "core_replay_and_full_transaction_authentication_ms": distribution(&timing.core_ms),
        "names_transport_ms": distribution(&timing.names_transport_ms),
        "total_local_ms": distribution(&total)
    })
}

fn distribution(values: &[f64]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / sorted.len() as f64;
    json!({
        "min": sorted[0],
        "p50": quantile(&sorted, 0.50),
        "p95": quantile(&sorted, 0.95),
        "p99": quantile(&sorted, 0.99),
        "max": sorted[sorted.len() - 1],
        "mean": mean,
        "standard_deviation": variance.sqrt()
    })
}

fn quantile(sorted: &[f64], probability: f64) -> f64 {
    let index = (((sorted.len() - 1) as f64 * probability).round() as usize).min(sorted.len() - 1);
    sorted[index]
}

fn block_hash(iteration: u32) -> Vec<u8> {
    let mut hash = [7; 32];
    hash[..4].copy_from_slice(&iteration.to_le_bytes());
    hash.to_vec()
}

fn decode_operation(document: &Value, id: &str, codec: CodecParameters) -> Result<Operation> {
    let operation = document["operations"]
        .as_array()
        .context("operations is not an array")?
        .iter()
        .find(|operation| operation["id"].as_str() == Some(id))
        .with_context(|| format!("missing {id} operation"))?;
    let bytes = hex::decode(operation["hex"].as_str().context("operation hex")?)?;
    decode(&bytes, Network::Regtest, codec).map_err(debug_error)
}

fn string_value<'a>(document: &'a Value, pointer: &str) -> Result<&'a str> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| pointer.to_owned())
}

fn u32_value(document: &Value, pointer: &str) -> Result<u32> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .with_context(|| pointer.to_owned())?
        .try_into()
        .with_context(|| pointer.to_owned())
}

fn usize_value(document: &Value, pointer: &str) -> Result<usize> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .with_context(|| pointer.to_owned())?
        .try_into()
        .with_context(|| pointer.to_owned())
}

fn debug_error(error: impl std::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}
