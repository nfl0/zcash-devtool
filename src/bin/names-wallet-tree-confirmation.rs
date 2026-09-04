//! Narrow confirmation of the wallet-owned-tree Coppice boundary.
//!
//! The authority pass advances both today's Core commitment tree and the same
//! in-memory `ShardTree` shape used by the light-wallet stack, requiring root,
//! size, and every global action position to agree. The consumer pass then
//! replays the same canonical compact history without maintaining a second
//! tree: it consumes the wallet-produced checkpoints, validates all compact
//! effects and positions, and applies the exact Names reducer. This is a
//! qualification harness, not a production Core or wallet API.

use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use blake2b_simd::{Params as Blake2bParams, State as Blake2bState};
use clap::Parser;
use coppice::{
    carrier::CoreRendezvous,
    identity::{CoreRuntimeParameters, ValidatedCoreRuntimeParameters, ZcashNetwork},
    replay::{
        CoreCanonicalBlockInput, CoreReplay, CoreReplayActivationCheckpoint,
        CoreReplayConfiguration, CoreReplayPositionCheckpoint, CoreReplayTip,
        FullTransactionAcquisition, IronwoodFrontier,
    },
    runtime::{CanonicalRuntime, CorePositionRuntime, CoreRuntime},
};
use coppice_librustzcash::{FullTransactionSource, prepare_canonical_block_with_rendezvous_policy};
use coppice_names::{
    deployment::DeploymentParameters,
    proof::keygen,
    protocol::{FieldElement, Name, NameRoute, Network},
    reducer::{Action, Block, Transaction},
    resolver::ExactResolver,
    ruleset::{RULESET_REVISION, ruleset_fingerprint},
    transport::{
        authenticated_action_position, inspect_exact_name_block,
        inspect_exact_name_positioned_block, positioned_action_position,
    },
};
use incrementalmerkletree::{Marking, Position, Retention};
use orchard::{note::Nullifier, tree::MerkleHashOrchard};
use prost::Message;
use serde_json::json;
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_devtool::names_config::REGTEST;
use zcash_protocol::consensus::MainNetwork;

type WalletTree = ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16>;

#[derive(Debug, Parser)]
#[command(
    name = "names-wallet-tree-confirmation",
    about = "Confirm a tree-free Coppice consumer against wallet-owned checkpoints"
)]
struct Cli {
    /// CNHS1 file produced by names-speed-sample --capture-dir.
    #[arg(long)]
    capture: PathBuf,

    /// Name whose scheduled exact route is replayed.
    #[arg(long, default_value = "benchmark.zec")]
    name: String,

    /// Persist JSON results without overwriting an existing file.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Stop after this many blocks for focused validation.
    #[arg(long)]
    max_blocks: Option<usize>,

    /// Retained rollback checkpoints in both reference paths.
    #[arg(long, default_value_t = 100)]
    rewind_blocks: u32,

    /// Fail confirmation when tree-free consumer replay exceeds this bound.
    #[arg(long, default_value_t = 10.0)]
    maximum_consumer_seconds: f64,

    /// Compare wallet and Core roots at this block interval and at the final tip.
    #[arg(long, default_value_t = 1_000)]
    root_check_interval: usize,
}

struct NoFullTransactions;

impl FullTransactionSource for NoFullTransactions {
    type Error = Infallible;

    fn full_transaction(&mut self, _txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug)]
struct WalletCheckpoint {
    height: u32,
    block_hash: [u8; 32],
    prev_block_hash: [u8; 32],
    root: Option<[u8; 32]>,
    tree_size: u32,
    action_count: u32,
}

#[derive(Default)]
struct AuthorityTimings {
    decode: Duration,
    prepare: Duration,
    core_tree: Duration,
    wallet_tree: Duration,
    transport: Duration,
    reducer: Duration,
}

#[derive(Default)]
struct ConsumerTimings {
    decode: Duration,
    prepare: Duration,
    validate_and_apply: Duration,
    reducer: Duration,
}

#[derive(Clone)]
struct ConsumerState {
    tip: CoreReplayTip,
    root: [u8; 32],
    tree_size: u32,
    position_digest: Blake2bState,
}

#[derive(Clone)]
struct WalletCheckpointConsumer {
    parameters: ValidatedCoreRuntimeParameters,
    rendezvous: CoreRendezvous,
    checkpoints: Arc<[WalletCheckpoint]>,
    state: ConsumerState,
    history: BTreeMap<u32, ConsumerState>,
    next_checkpoint: usize,
    retention_blocks: u32,
}

impl WalletCheckpointConsumer {
    fn new(
        parameters: ValidatedCoreRuntimeParameters,
        activation_parent: CoreReplayTip,
        activation_root: [u8; 32],
        activation_tree_size: u32,
        checkpoints: Arc<[WalletCheckpoint]>,
        retention_blocks: u32,
    ) -> Self {
        let rendezvous = CoreRendezvous::from_validated(&parameters);
        Self {
            parameters,
            rendezvous,
            checkpoints,
            state: ConsumerState {
                tip: activation_parent,
                root: activation_root,
                tree_size: activation_tree_size,
                position_digest: position_digest_state(),
            },
            history: BTreeMap::new(),
            next_checkpoint: 0,
            retention_blocks,
        }
    }

    fn root(&self) -> [u8; 32] {
        self.state.root
    }

    fn tree_size(&self) -> u32 {
        self.state.tree_size
    }

    fn position_digest(&self) -> [u8; 32] {
        digest_bytes(&self.state.position_digest)
    }
}

impl CanonicalRuntime for WalletCheckpointConsumer {
    type BlockOutput = Block;
    type ApplyError = anyhow::Error;
    type RewindError = anyhow::Error;

    fn core_parameters(&self) -> &ValidatedCoreRuntimeParameters {
        &self.parameters
    }

    fn rendezvous(&self) -> &CoreRendezvous {
        &self.rendezvous
    }

    fn tip(&self) -> CoreReplayTip {
        self.state.tip
    }

    fn oldest_rewind_height(&self) -> u32 {
        self.history
            .first_key_value()
            .map_or(self.state.tip.height, |(_, state)| state.tip.height)
    }

    fn retained_tip_at(&self, height: u32) -> Option<CoreReplayTip> {
        if height == self.state.tip.height {
            Some(self.state.tip)
        } else {
            self.history
                .values()
                .find(|state| state.tip.height == height)
                .map(|state| state.tip)
        }
    }

    fn full_transaction_acquisition(
        &self,
        _summary: &coppice::application::CanonicalCompactTransactionSummary<'_>,
    ) -> FullTransactionAcquisition {
        FullTransactionAcquisition::None
    }

    fn apply_canonical_block(
        &mut self,
        block: &CoreCanonicalBlockInput,
    ) -> Result<Self::BlockOutput, Self::ApplyError> {
        let checkpoint = self
            .checkpoints
            .get(self.next_checkpoint)
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "wallet checkpoint trace ended before block {}",
                    block.height
                )
            })?;
        ensure!(
            block.height
                == self
                    .state
                    .tip
                    .height
                    .checked_add(1)
                    .context("height overflow")?,
            "nonsequential consumer block {}",
            block.height
        );
        ensure!(
            block.prev_block_hash == self.state.tip.block_hash,
            "consumer predecessor mismatch at {}",
            block.height
        );
        ensure!(
            checkpoint.height == block.height
                && checkpoint.block_hash == block.block_hash
                && checkpoint.prev_block_hash == block.prev_block_hash,
            "wallet checkpoint branch mismatch at {}",
            block.height
        );
        ensure!(
            block
                .transactions
                .windows(2)
                .all(|pair| pair[0].tx_index < pair[1].tx_index),
            "noncanonical transaction order at {}",
            block.height
        );

        let prior = self.state.clone();
        let mut position = prior.tree_size;
        let mut names_transactions = Vec::with_capacity(block.transactions.len());
        for transaction in &block.transactions {
            ensure!(
                transaction.ironwood_nullifiers.len() == transaction.ironwood_commitments.len(),
                "effect length mismatch at {}:{}",
                block.height,
                transaction.tx_index
            );
            ensure!(
                transaction.full_transaction.is_none()
                    && !transaction
                        .full_transaction_acquisition
                        .requires_full_transaction(),
                "confirmation capture unexpectedly requires a full transaction at {}:{}",
                block.height,
                transaction.tx_index
            );
            let mut actions = Vec::with_capacity(transaction.ironwood_commitments.len());
            for (action_index, (nullifier, commitment)) in transaction
                .ironwood_nullifiers
                .iter()
                .zip(&transaction.ironwood_commitments)
                .enumerate()
            {
                Option::<Nullifier>::from(Nullifier::from_bytes(nullifier))
                    .context("noncanonical nullifier")?;
                Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(commitment))
                    .context("invalid commitment")?;
                let action_index = u32::try_from(action_index).context("action index overflow")?;
                update_position_digest(
                    &mut self.state.position_digest,
                    block.height,
                    transaction.tx_index,
                    action_index,
                    position,
                    nullifier,
                    commitment,
                );
                actions.push(Action {
                    action_index,
                    nullifier: FieldElement::from_bytes(*nullifier)
                        .map_err(|_| anyhow!("invalid Names nullifier field"))?,
                    commitment: FieldElement::from_bytes(*commitment)
                        .map_err(|_| anyhow!("invalid Names commitment field"))?,
                });
                position = position.checked_add(1).context("tree size overflow")?;
            }
            names_transactions.push(Transaction {
                tx_index: transaction.tx_index,
                txid: transaction.txid,
                actions,
                operation: None,
            });
        }
        let observed_actions = position - prior.tree_size;
        ensure!(
            observed_actions == checkpoint.action_count,
            "wallet checkpoint action-count mismatch at {}",
            block.height
        );
        ensure!(
            position == checkpoint.tree_size,
            "wallet checkpoint tree-size mismatch at {}",
            block.height
        );

        self.history.insert(block.height, prior);
        let oldest = block
            .height
            .saturating_sub(self.retention_blocks)
            .saturating_add(1);
        self.history.retain(|height, _| *height >= oldest);
        self.state.tip = CoreReplayTip {
            height: block.height,
            block_hash: block.block_hash,
        };
        if let Some(root) = checkpoint.root {
            self.state.root = root;
        }
        self.state.tree_size = checkpoint.tree_size;
        self.next_checkpoint += 1;

        Ok(Block {
            height: block.height,
            hash: block.block_hash,
            prev_hash: block.prev_block_hash,
            transactions: names_transactions,
        })
    }

    fn rewind_canonical_to(&mut self, height: u32) -> Result<(), Self::RewindError> {
        ensure!(
            height <= self.state.tip.height,
            "rewind beyond consumer tip"
        );
        while self.state.tip.height > height {
            let applied_height = self.state.tip.height;
            self.state = self
                .history
                .remove(&applied_height)
                .ok_or_else(|| anyhow!("consumer rewind snapshot missing at {applied_height}"))?;
            self.next_checkpoint = self
                .next_checkpoint
                .checked_sub(1)
                .context("checkpoint cursor underflow")?;
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.rewind_blocks > 0, "rewind retention must be positive");
    ensure!(
        cli.maximum_consumer_seconds.is_finite() && cli.maximum_consumer_seconds > 0.0,
        "consumer time bound must be finite and positive"
    );
    ensure!(
        cli.root_check_interval > 0,
        "root check interval must be positive"
    );
    let raw = read_capture(&cli.capture, cli.max_blocks)?;
    ensure!(!raw.is_empty(), "capture contains no blocks");

    let first = CompactBlock::decode(raw[0].as_slice()).context("decode first compact block")?;
    let activation_height = u32::try_from(first.height).context("activation height exceeds u32")?;
    let activation_parent_hash: [u8; 32] = first
        .prev_hash
        .as_slice()
        .try_into()
        .context("activation parent hash has wrong length")?;
    let runtime_parameters = CoreRuntimeParameters {
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
    .map_err(|error| anyhow!("validate runtime parameters: {error:?}"))?;
    let configuration = CoreReplayConfiguration::new(activation_height, cli.rewind_blocks)
        .map_err(|error| anyhow!("configure Core replay: {error:?}"))?;
    let activation_frontier = IronwoodFrontier::empty();
    let activation_root = activation_frontier.root().to_bytes();
    let replay = CoreReplay::new(
        configuration,
        CoreReplayActivationCheckpoint {
            height: activation_height - 1,
            block_hash: activation_parent_hash,
            ironwood_frontier: activation_frontier,
            ironwood_tree_size: 0,
        },
    )
    .map_err(|error| anyhow!("initialize Core replay: {error:?}"))?;
    let mut runtime = CoreRuntime::new(runtime_parameters.clone(), replay)
        .map_err(|error| anyhow!("initialize Core runtime: {error:?}"))?;
    let (_, verifier) = keygen();
    let verifier = Arc::new(verifier);
    let deployment = DeploymentParameters::candidate(
        runtime_parameters.core_runtime_id(),
        activation_height,
        verifier.identity(),
    );
    let deployment_id = deployment
        .deployment_id()
        .map_err(|error| anyhow!("derive Names deployment: {error:?}"))?;
    let schedule = deployment.schedule(deployment_id);
    let name = Name::parse(&cli.name).map_err(|error| anyhow!("parse name: {error:?}"))?;
    let name_id = name
        .id()
        .map_err(|error| anyhow!("derive name ID: {error:?}"))?;
    let route = NameRoute::derive(deployment_id, name_id)
        .map_err(|error| anyhow!("derive name route: {error:?}"))?;
    let exact_rendezvous =
        CoreRendezvous::try_new(&route.incoming_viewing_key(), &route.receiver())
            .map_err(|error| anyhow!("construct exact rendezvous: {error:?}"))?;

    let authority_started = Instant::now();
    let mut authority_timings = AuthorityTimings::default();
    let mut authority_resolver = ExactResolver::new(
        schedule,
        activation_parent_hash,
        name.clone(),
        verifier.clone(),
    )
    .map_err(|error| anyhow!("initialize authority resolver: {error:?}"))?;
    let mut wallet_tree = WalletTree::new(MemoryShardStore::empty(), cli.rewind_blocks as usize);
    let mut checkpoints = Vec::with_capacity(raw.len());
    let mut authority_position_digest = position_digest_state();
    let mut source = NoFullTransactions;
    let mut authority_operations = 0u64;
    let mut actions = 0u64;
    let mut checked_roots = 0u64;
    let mut last_wallet_leaves = Vec::new();
    let mut last_height = activation_height - 1;

    for (block_offset, encoded) in raw.iter().enumerate() {
        let started = Instant::now();
        let compact = decode_normalized(encoded)?;
        authority_timings.decode += started.elapsed();
        let height = u32::try_from(compact.height).context("block height exceeds u32")?;
        let additional = if schedule.accepts_operation(name_id, height) {
            std::slice::from_ref(&exact_rendezvous)
        } else {
            &[]
        };

        let started = Instant::now();
        let canonical = prepare_canonical_block_with_rendezvous_policy(
            &MainNetwork,
            &runtime,
            &compact,
            &mut source,
            false,
            additional,
        )
        .map_err(|error| anyhow!("prepare authority block {height}: {error:?}"))?;
        authority_timings.prepare += started.elapsed();

        let started = Instant::now();
        let applied = runtime
            .apply_block(&canonical)
            .map_err(|error| anyhow!("apply authority block {height}: {error:?}"))?;
        authority_timings.core_tree += started.elapsed();
        let core = applied.core();
        let core_checkpoint = core.ironwood_checkpoint();
        let pre_block_size = core_checkpoint
            .tree_size
            .checked_sub(
                core.transactions()
                    .iter()
                    .try_fold(0u32, |count, transaction| {
                        count.checked_add(
                            u32::try_from(transaction.ironwood_effects().commitments().len())
                                .ok()?,
                        )
                    })
                    .context("authority action count overflow")?,
            )
            .context("authority pre-block size underflow")?;
        let mut ordinal = 0u32;
        let mut wallet_leaves = Vec::new();
        for transaction in core.transactions() {
            ensure!(
                transaction.ironwood_effects().nullifiers().len()
                    == transaction.ironwood_effects().commitments().len(),
                "authority effect length mismatch at {height}:{}",
                transaction.tx_index()
            );
            for (action_index, (nullifier, commitment)) in transaction
                .ironwood_effects()
                .nullifiers()
                .iter()
                .zip(transaction.ironwood_effects().commitments())
                .enumerate()
            {
                let action_index = u32::try_from(action_index).context("action index overflow")?;
                let expected_position = pre_block_size
                    .checked_add(ordinal)
                    .context("position overflow")?;
                let actual_position =
                    authenticated_action_position(core, transaction.tx_index(), action_index)
                        .map_err(|error| anyhow!("authenticate action position: {error:?}"))?;
                ensure!(
                    actual_position == expected_position,
                    "Core action-position mismatch at {height}:{}:{action_index}",
                    transaction.tx_index()
                );
                update_position_digest(
                    &mut authority_position_digest,
                    height,
                    transaction.tx_index(),
                    action_index,
                    actual_position,
                    nullifier,
                    commitment,
                );
                wallet_leaves.push(
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(commitment))
                        .context("Core emitted an invalid commitment")?,
                );
                ordinal = ordinal.checked_add(1).context("action count overflow")?;
            }
        }
        actions = actions.saturating_add(u64::from(ordinal));

        let started = Instant::now();
        append_wallet_block(
            &mut wallet_tree,
            height,
            pre_block_size,
            core_checkpoint.tree_size,
            &wallet_leaves,
        )?;
        last_wallet_leaves = wallet_leaves;
        let check_root =
            (block_offset + 1) % cli.root_check_interval == 0 || block_offset + 1 == raw.len();
        let wallet_root = if check_root {
            let root = wallet_tree
                .root_at_checkpoint_id(&height)?
                .context("wallet checkpoint has no root")?
                .to_bytes();
            ensure!(
                root == core_checkpoint.root,
                "wallet/Core root mismatch at {height}"
            );
            checked_roots += 1;
            Some(root)
        } else {
            None
        };
        authority_timings.wallet_tree += started.elapsed();

        checkpoints.push(WalletCheckpoint {
            height,
            block_hash: core.block_hash(),
            prev_block_hash: core.prev_block_hash(),
            root: wallet_root,
            tree_size: core_checkpoint.tree_size,
            action_count: ordinal,
        });

        let started = Instant::now();
        let names_block =
            inspect_exact_name_block(core, &runtime_parameters, deployment, Network::Main, &name)
                .map_err(|error| anyhow!("inspect authority Names block {height}: {error:?}"))?;
        authority_timings.transport += started.elapsed();
        let started = Instant::now();
        authority_operations = authority_operations.saturating_add(
            authority_resolver
                .apply_block(&names_block)
                .map_err(|error| anyhow!("apply authority Names block {height}: {error:?}"))?
                .len() as u64,
        );
        authority_timings.reducer += started.elapsed();
        last_height = height;
    }
    let authority_wall = authority_started.elapsed();
    let authority_resolution = authority_resolver
        .resolve(last_height)
        .map_err(|error| anyhow!("resolve authority name at {last_height}: {error:?}"))?;
    let authority_tip = runtime.tip();
    let authority_final_checkpoint = runtime
        .ironwood_checkpoints()
        .get(&last_height)
        .copied()
        .context("authority final checkpoint missing")?;
    let authority_position_digest = digest_bytes(&authority_position_digest);

    let prior_height = last_height
        .checked_sub(1)
        .context("confirmation capture contains no rewindable final block")?;
    let prior_checkpoint = runtime
        .ironwood_checkpoints()
        .get(&prior_height)
        .copied()
        .context("authority penultimate checkpoint missing")?;
    ensure!(
        wallet_tree.truncate_to_checkpoint(&prior_height)?,
        "wallet tree could not rewind to penultimate checkpoint"
    );
    ensure!(
        wallet_tree
            .root_at_checkpoint_id(&prior_height)?
            .context("rewound wallet checkpoint has no root")?
            .to_bytes()
            == prior_checkpoint.root,
        "rewound wallet root mismatch"
    );
    append_wallet_block(
        &mut wallet_tree,
        last_height,
        prior_checkpoint.tree_size,
        authority_final_checkpoint.tree_size,
        &last_wallet_leaves,
    )?;
    ensure!(
        wallet_tree
            .root_at_checkpoint_id(&last_height)?
            .context("reapplied wallet checkpoint has no root")?
            .to_bytes()
            == authority_final_checkpoint.root,
        "reapplied wallet root mismatch"
    );

    let checkpoints: Arc<[WalletCheckpoint]> = checkpoints.into();
    let mut consumer = WalletCheckpointConsumer::new(
        runtime_parameters.clone(),
        CoreReplayTip {
            height: activation_height - 1,
            block_hash: activation_parent_hash,
        },
        activation_root,
        0,
        checkpoints.clone(),
        cli.rewind_blocks,
    );
    let mut consumer_resolver = ExactResolver::new(
        schedule,
        activation_parent_hash,
        name.clone(),
        verifier.clone(),
    )
    .map_err(|error| anyhow!("initialize consumer resolver: {error:?}"))?;
    let consumer_started = Instant::now();
    let mut consumer_timings = ConsumerTimings::default();
    let mut consumer_operations = 0u64;
    let mut source = NoFullTransactions;

    for encoded in &raw {
        let started = Instant::now();
        let compact = decode_normalized(encoded)?;
        consumer_timings.decode += started.elapsed();
        let height = u32::try_from(compact.height).context("block height exceeds u32")?;
        let additional = if schedule.accepts_operation(name_id, height) {
            std::slice::from_ref(&exact_rendezvous)
        } else {
            &[]
        };
        let started = Instant::now();
        let canonical = prepare_canonical_block_with_rendezvous_policy(
            &MainNetwork,
            &consumer,
            &compact,
            &mut source,
            false,
            additional,
        )
        .map_err(|error| anyhow!("prepare consumer block {height}: {error:?}"))?;
        consumer_timings.prepare += started.elapsed();
        let started = Instant::now();
        let names_block = consumer.apply_canonical_block(&canonical)?;
        consumer_timings.validate_and_apply += started.elapsed();
        let started = Instant::now();
        consumer_operations = consumer_operations.saturating_add(
            consumer_resolver
                .apply_block(&names_block)
                .map_err(|error| anyhow!("apply consumer Names block {height}: {error:?}"))?
                .len() as u64,
        );
        consumer_timings.reducer += started.elapsed();
    }
    let consumer_wall = consumer_started.elapsed();
    let consumer_resolution = consumer_resolver
        .resolve(last_height)
        .map_err(|error| anyhow!("resolve consumer name at {last_height}: {error:?}"))?;

    ensure!(consumer.tip() == authority_tip, "final tip parity failed");
    ensure!(
        consumer.root() == authority_final_checkpoint.root,
        "final root parity failed"
    );
    ensure!(
        consumer.tree_size() == authority_final_checkpoint.tree_size,
        "final tree-size parity failed"
    );
    ensure!(
        consumer.position_digest() == authority_position_digest,
        "action-position parity failed"
    );
    ensure!(
        consumer_resolution == authority_resolution,
        "Names resolution parity failed"
    );
    ensure!(
        consumer_operations == authority_operations,
        "accepted-operation parity failed"
    );

    let mut rewind_consumer = consumer.clone();
    let mut rewind_resolver = consumer_resolver.clone();
    rewind_consumer.rewind_canonical_to(last_height - 1)?;
    rewind_resolver
        .rollback_tip(authority_tip.block_hash)
        .map_err(|error| anyhow!("rollback Names tip: {error:?}"))?;
    let final_compact = decode_normalized(raw.last().context("capture unexpectedly empty")?)?;
    let final_additional = if schedule.accepts_operation(name_id, last_height) {
        std::slice::from_ref(&exact_rendezvous)
    } else {
        &[]
    };
    let final_canonical = prepare_canonical_block_with_rendezvous_policy(
        &MainNetwork,
        &rewind_consumer,
        &final_compact,
        &mut source,
        false,
        final_additional,
    )
    .map_err(|error| anyhow!("prepare replayed final block: {error:?}"))?;
    let final_names_block = rewind_consumer.apply_canonical_block(&final_canonical)?;
    rewind_resolver
        .apply_block(&final_names_block)
        .map_err(|error| anyhow!("reapply Names final block: {error:?}"))?;
    ensure!(
        rewind_consumer.tip() == authority_tip,
        "reapplied tip mismatch"
    );
    ensure!(
        rewind_consumer.root() == authority_final_checkpoint.root,
        "reapplied root mismatch"
    );
    ensure!(
        rewind_consumer.tree_size() == authority_final_checkpoint.tree_size,
        "reapplied tree-size mismatch"
    );
    ensure!(
        rewind_consumer.position_digest() == authority_position_digest,
        "reapplied position digest mismatch"
    );
    ensure!(
        rewind_resolver
            .resolve(last_height)
            .map_err(|error| anyhow!("resolve reapplied name at {last_height}: {error:?}"))?
            == authority_resolution,
        "reapplied Names resolution mismatch"
    );

    // Replay the same capture through the production Core position runtime,
    // not only the independent confirmation consumer above.
    let mut production = CorePositionRuntime::new(
        runtime_parameters.clone(),
        configuration,
        CoreReplayPositionCheckpoint {
            height: activation_height - 1,
            block_hash: activation_parent_hash,
            ironwood_tree_size: 0,
        },
    )
    .map_err(|error| anyhow!("initialize production position runtime: {error:?}"))?;
    let mut production_resolver = ExactResolver::new(
        schedule,
        activation_parent_hash,
        name.clone(),
        verifier.clone(),
    )
    .map_err(|error| anyhow!("initialize production position resolver: {error:?}"))?;
    let production_started = Instant::now();
    let mut production_timings = ConsumerTimings::default();
    let mut production_position_digest = position_digest_state();
    let mut production_operations = 0u64;
    let mut source = NoFullTransactions;
    for (encoded, checkpoint) in raw.iter().zip(checkpoints.iter()) {
        let started = Instant::now();
        let compact = decode_normalized(encoded)?;
        production_timings.decode += started.elapsed();
        let height = u32::try_from(compact.height).context("block height exceeds u32")?;
        let additional = if schedule.accepts_operation(name_id, height) {
            std::slice::from_ref(&exact_rendezvous)
        } else {
            &[]
        };
        let started = Instant::now();
        let canonical = prepare_canonical_block_with_rendezvous_policy(
            &MainNetwork,
            &production,
            &compact,
            &mut source,
            false,
            additional,
        )
        .map_err(|error| anyhow!("prepare production position block {height}: {error:?}"))?;
        production_timings.prepare += started.elapsed();
        let started = Instant::now();
        let positioned = production
            .apply_canonical_block(&canonical)
            .map_err(|error| anyhow!("apply production position block {height}: {error:?}"))?;
        ensure!(
            positioned.core().post_ironwood_tree_size() == checkpoint.tree_size,
            "production position runtime disagrees with wallet tree at {height}"
        );
        for transaction in positioned.core().transactions() {
            for (action_index, (nullifier, commitment)) in transaction
                .ironwood_effects()
                .nullifiers()
                .iter()
                .zip(transaction.ironwood_effects().commitments())
                .enumerate()
            {
                let action_index = u32::try_from(action_index).context("action index overflow")?;
                let position = positioned_action_position(
                    positioned.core(),
                    transaction.tx_index(),
                    action_index,
                )
                .map_err(|error| anyhow!("derive production position: {error:?}"))?;
                update_position_digest(
                    &mut production_position_digest,
                    height,
                    transaction.tx_index(),
                    action_index,
                    position,
                    nullifier,
                    commitment,
                );
            }
        }
        let names_block = inspect_exact_name_positioned_block(
            positioned.core(),
            &runtime_parameters,
            deployment,
            Network::Main,
            &name,
        )
        .map_err(|error| anyhow!("inspect production Names block {height}: {error:?}"))?;
        production_timings.validate_and_apply += started.elapsed();
        let started = Instant::now();
        production_operations = production_operations.saturating_add(
            production_resolver
                .apply_block(&names_block)
                .map_err(|error| anyhow!("apply production Names block {height}: {error:?}"))?
                .len() as u64,
        );
        production_timings.reducer += started.elapsed();
    }
    let production_wall = production_started.elapsed();
    ensure!(
        production.tip() == authority_tip,
        "production final tip parity failed"
    );
    ensure!(
        production.ironwood_tree_size() == authority_final_checkpoint.tree_size,
        "production final tree-size parity failed"
    );
    ensure!(
        digest_bytes(&production_position_digest) == authority_position_digest,
        "production action-position parity failed"
    );
    ensure!(
        production_resolver
            .resolve(last_height)
            .map_err(|error| anyhow!("resolve production name at {last_height}: {error:?}"))?
            == authority_resolution,
        "production Names resolution parity failed"
    );
    ensure!(
        production_operations == authority_operations,
        "production accepted-operation parity failed"
    );

    ensure!(
        consumer_wall.as_secs_f64() <= cli.maximum_consumer_seconds,
        "tree-free consumer took {:.3}s, above {:.3}s confirmation bound",
        consumer_wall.as_secs_f64(),
        cli.maximum_consumer_seconds
    );

    let seconds = |duration: Duration| duration.as_secs_f64();
    let authority_coppice_components = authority_timings.decode
        + authority_timings.prepare
        + authority_timings.core_tree
        + authority_timings.transport
        + authority_timings.reducer;
    let report = json!({
        "schema": "coppice-names-wallet-tree-confirmation-v1",
        "protocol_identity": {
            "deployment_id_hex": hex::encode(deployment_id),
            "ruleset_revision": RULESET_REVISION,
            "ruleset_fingerprint_hex": hex::encode(ruleset_fingerprint())
        },
        "source": {
            "capture": cli.capture,
            "blocks": raw.len(),
            "start_height": activation_height,
            "end_height": last_height,
            "orchard_family_actions": actions,
            "pool_model": "Orchard-era compact actions are processed as equivalent Ironwood actions."
        },
        "authority_pass": {
            "wall_seconds_including_both_trees": seconds(authority_wall),
            "coppice_components_seconds": seconds(authority_coppice_components),
            "timing_seconds": {
                "decode": seconds(authority_timings.decode),
                "prepare_exact_route": seconds(authority_timings.prepare),
                "current_core_tree": seconds(authority_timings.core_tree),
                "wallet_shardtree_and_root_parity": seconds(authority_timings.wallet_tree),
                "names_transport": seconds(authority_timings.transport),
                "names_reducer": seconds(authority_timings.reducer)
            }
        },
        "tree_free_consumer_pass": {
            "wall_seconds": seconds(consumer_wall),
            "maximum_confirmation_seconds": cli.maximum_consumer_seconds,
            "timing_seconds": {
                "decode": seconds(consumer_timings.decode),
                "prepare_exact_route": seconds(consumer_timings.prepare),
                "validate_effects_positions_and_apply_checkpoint": seconds(consumer_timings.validate_and_apply),
                "names_reducer": seconds(consumer_timings.reducer)
            },
            "reduction_vs_authority_coppice_components_percent":
                100.0 * (1.0 - seconds(consumer_wall) / seconds(authority_coppice_components))
        },
        "production_position_runtime_pass": {
            "wall_seconds": seconds(production_wall),
            "timing_seconds": {
                "decode": seconds(production_timings.decode),
                "prepare_exact_route": seconds(production_timings.prepare),
                "validate_effects_positions_and_transport": seconds(production_timings.validate_and_apply),
                "names_reducer": seconds(production_timings.reducer)
            },
            "reduction_vs_authority_coppice_components_percent":
                100.0 * (1.0 - seconds(production_wall) / seconds(authority_coppice_components))
        },
        "parity": {
            "sampled_wallet_roots_equal_core_root": true,
            "root_check_interval_blocks": cli.root_check_interval,
            "checked_wallet_roots": checked_roots,
            "every_block_tree_size_equals_ordered_action_count": true,
            "every_action_global_position_matches": true,
            "final_tip_matches": true,
            "final_root_matches": true,
            "final_tree_size_matches": true,
            "final_names_resolution_matches": true,
            "accepted_names_operations_match": true,
            "rollback_and_final_block_reapply_matches": true,
            "wallet_shardtree_rollback_and_reapply_matches": true,
            "production_position_runtime_matches": true,
            "final_root": hex::encode(authority_final_checkpoint.root),
            "final_tree_size": authority_final_checkpoint.tree_size,
            "position_digest": hex::encode(authority_position_digest),
            "final_lifecycle": format!("{:?}", authority_resolution.lifecycle)
        },
        "qualification": {
            "confirmed": true,
            "boundary": "An actual wallet-shaped in-memory ShardTree produced every supplied tree size and authenticated roots at fixed batch boundaries plus the final tip. The consumer retained canonical compact validation, exact-route scanning, global position derivation, nullifier effects, Names reduction, and rollback, but maintained no second commitment tree.",
            "not_measured_here": [
                "wallet SQLite persistence and transaction overhead",
                "network transfer time",
                "routed full transactions because mainnet contains no Coppice deployment",
                "Names proof verification",
                "multi-block replacement-branch reorg"
            ]
        }
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

fn decode_normalized(encoded: &[u8]) -> Result<CompactBlock> {
    let mut compact = CompactBlock::decode(encoded).context("decode compact block")?;
    for transaction in &mut compact.vtx {
        if transaction.ironwood_actions.is_empty() {
            transaction
                .ironwood_actions
                .append(&mut transaction.actions);
        } else {
            ensure!(
                transaction.actions.is_empty(),
                "block {} transaction {} carries both Orchard and Ironwood actions",
                compact.height,
                transaction.index
            );
        }
    }
    Ok(compact)
}

fn position_digest_state() -> Blake2bState {
    Blake2bParams::new()
        .hash_length(32)
        .personal(b"CNWT_CONFIRM_V1")
        .to_state()
}

fn append_wallet_block(
    tree: &mut WalletTree,
    height: u32,
    pre_block_size: u32,
    expected_tree_size: u32,
    leaves: &[MerkleHashOrchard],
) -> Result<()> {
    if leaves.is_empty() {
        ensure!(
            tree.checkpoint(height)?,
            "wallet checkpoint was not inserted"
        );
        ensure!(
            pre_block_size == expected_tree_size,
            "empty wallet block changed tree size at {height}"
        );
    } else {
        let last = leaves.len() - 1;
        let values = leaves.iter().cloned().enumerate().map(|(index, leaf)| {
            let retention = if index == last {
                Retention::Checkpoint {
                    id: height,
                    marking: Marking::None,
                }
            } else {
                Retention::Ephemeral
            };
            (leaf, retention)
        });
        let result = tree
            .batch_insert(Position::from(u64::from(pre_block_size)), values)?
            .context("nonempty wallet block inserted no leaves")?;
        ensure!(
            u64::from(result.0) + 1 == u64::from(expected_tree_size),
            "wallet final position mismatch at {height}"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_position_digest(
    state: &mut Blake2bState,
    height: u32,
    tx_index: u32,
    action_index: u32,
    position: u32,
    nullifier: &[u8; 32],
    commitment: &[u8; 32],
) {
    state.update(&height.to_le_bytes());
    state.update(&tx_index.to_le_bytes());
    state.update(&action_index.to_le_bytes());
    state.update(&position.to_le_bytes());
    state.update(nullifier);
    state.update(commitment);
}

fn digest_bytes(state: &Blake2bState) -> [u8; 32] {
    let digest = state.clone().finalize();
    let mut bytes = [0; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
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
