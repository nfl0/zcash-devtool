//! Disposable live qualification for the replacement Coppice Names protocol.

use std::{
    num::NonZeroU32,
    num::NonZeroUsize,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use bip0039::{English, Mnemonic};
use clap::{Args, Parser, Subcommand};
use coppice::{
    carrier::CoreRendezvous,
    identity::{CoreRuntimeId, CoreRuntimeParameters, ZcashNetwork},
    replay::{
        CoreReplay, CoreReplayActivationCheckpoint, CoreReplayConfiguration, IronwoodFrontier,
    },
    runtime::CoreRuntime,
};
use coppice_librustzcash::{CanonicalBlockSource, apply_compact_block_with_additional_rendezvous};
use coppice_names::{
    codec::Operation,
    deployment::DeploymentParameters,
    proof::{OrchardProofVerifier, keygen},
    protocol::{BOND_ZATOSHIS, CanonicalUa, CommitRef, Name, NameRoute, Network},
    publication::PublicationRoute,
    reducer::{Block, Lifecycle},
    resolver::ExactResolver,
    transport::inspect_exact_name_block,
};
use coppice_names_wallet::{
    builder::{
        ChangeOutput, FundingSpend, NamesIronwoodSigningKey, NamesIronwoodWitness, NamesPcztPlan,
        NamesSigningPlan, NamesWitnessPlan, build_names_bundle, build_names_pczt,
        extract_names_transaction, finalize_names_pczt_io, install_names_ironwood_witnesses,
        names_ironwood_shape_from_counts, prove_names_ironwood_pczt, required_zip317_fee_for_names,
        sign_names_ironwood_pczt,
    },
    replacement::{RevealInputs, prepare_commit, prepare_reveal},
};
use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey},
    note::Note,
    value::NoteValue,
};
use rand::rngs::ThreadRng;
use zcash_client_backend::{
    data_api::wallet::{
        ConfirmationsPolicy, SpendingKeys, create_proposed_transactions,
        input_selection::{GreedyInputSelector, GreedyInputSelectorError, SpendPolicy},
        propose_transfer,
    },
    data_api::{WalletCommitmentTrees, WalletRead},
    fees::{DustOutputPolicy, SplitPolicy, StandardFeeRule, standard::MultiOutputChangeStrategy},
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{WalletDb, error::SqliteClientError, util::SystemClock};
use zcash_devtool::names_config::REGTEST;
use zcash_keys::{address::UnifiedAddress, keys::UnifiedSpendingKey};
use zcash_primitives::transaction::TxVersion as TransactionVersion;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, BranchId, NetworkType},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

const NAME: &str = "footprint";
const RUNTIME_ACTIVATION_HEIGHT: u32 = 1;
const EPOCH_BLOCKS: u32 = 1_152;
const WINDOW_BLOCKS: u32 = 24;
const COMMIT_MATURITY_BLOCKS: u32 = 24;
const COMMIT_TTL_BLOCKS: u32 = 192;
const LEASE_BLOCKS: u32 = 250_000;
const COOLDOWN_BLOCKS: u32 = 1_152;

#[derive(Parser)]
#[command(name = "names-live", about = "Replacement Names live qualification")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Target(TargetArgs),
    Commit(CommitArgs),
    Reveal(RevealArgs),
    Verify(VerifyArgs),
}

#[derive(Args)]
struct TargetArgs {
    #[arg(long)]
    from_height: u32,
}

#[derive(Args, Clone)]
struct WalletArgs {
    #[arg(long)]
    wallet_dir: PathBuf,
    #[arg(long)]
    rpc_url: String,
}

#[derive(Args)]
struct CommitArgs {
    #[command(flatten)]
    common: WalletArgs,
    #[arg(long)]
    reveal_height: u32,
}

#[derive(Args)]
struct RevealArgs {
    #[command(flatten)]
    common: WalletArgs,
    #[arg(long)]
    reveal_height: u32,
    #[arg(long)]
    commit_txid: String,
    #[arg(long)]
    ua: String,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    ua: String,
}

type LiveSource =
    coppice_zcash_rpc::RpcCanonicalBlockSource<LocalNetwork, coppice_zcash_rpc::HttpTransport>;
type LiveWallet = WalletDb<rusqlite::Connection, LocalNetwork, SystemClock, ThreadRng>;

fn debug_result<T, E: std::fmt::Debug>(result: std::result::Result<T, E>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!("{error:?}"))
}

fn local_consensus() -> LocalNetwork {
    let one = Some(BlockHeight::from_u32(1));
    let two = Some(BlockHeight::from_u32(2));
    LocalNetwork {
        overwinter: one,
        sapling: one,
        blossom: one,
        heartwood: one,
        canopy: one,
        nu5: two,
        nu6: two,
        nu6_1: two,
        nu6_2: two,
        nu6_3: two,
        #[cfg(zcash_unstable = "nu7")]
        nu7: two,
    }
}

fn runtime_parameters() -> Result<coppice::identity::ValidatedCoreRuntimeParameters> {
    CoreRuntimeParameters {
        runtime_protocol_id: b"coppice.runtime".to_vec(),
        runtime_protocol_version: 1,
        zcash_network_domain: b"coppice-runtime-regtest-v1".to_vec(),
        zcash_network: ZcashNetwork::Regtest,
        runtime_activation_height: RUNTIME_ACTIVATION_HEIGHT,
        carrier_protocol_id: b"CPV1".to_vec(),
        rendezvous_ivk: REGTEST.rendezvous.orchard_ivk,
        rendezvous_receiver: REGTEST.rendezvous.orchard_receiver,
    }
    .validate()
    .map_err(|error| anyhow::anyhow!("validate live Core runtime: {error:?}"))
}

fn deployment(
    core_runtime_id: CoreRuntimeId,
    verifier: &OrchardProofVerifier,
) -> DeploymentParameters {
    DeploymentParameters {
        core_runtime_id,
        activation_height: RUNTIME_ACTIVATION_HEIGHT,
        epoch_blocks: EPOCH_BLOCKS,
        window_blocks: WINDOW_BLOCKS,
        commit_maturity_blocks: COMMIT_MATURITY_BLOCKS,
        commit_ttl_blocks: COMMIT_TTL_BLOCKS,
        lease_blocks: LEASE_BLOCKS,
        cooldown_blocks: COOLDOWN_BLOCKS,
        proof: verifier.identity(),
    }
}

fn wallet_seed() -> Result<[u8; 64]> {
    let phrase = std::env::var("NAMES_LIVE_MNEMONIC")
        .context("NAMES_LIVE_MNEMONIC is required by the disposable live flow")?;
    let mnemonic = <Mnemonic<English>>::from_phrase(&phrase)
        .context("NAMES_LIVE_MNEMONIC is not a valid English mnemonic")?;
    Ok(mnemonic.to_seed(""))
}

fn wallet_usk(params: &LocalNetwork) -> Result<UnifiedSpendingKey> {
    UnifiedSpendingKey::from_seed(params, &wallet_seed()?, zip32::AccountId::ZERO)
        .map_err(anyhow::Error::from)
        .context("derive deterministic live wallet spending key")
}

fn open_wallet(wallet_dir: &Path, params: LocalNetwork) -> Result<LiveWallet> {
    WalletDb::for_path(
        wallet_dir.join("data.sqlite"),
        params,
        SystemClock,
        rand::rng(),
    )
    .context("open live wallet database")
}

fn source_for(rpc_url: &str) -> Result<LiveSource> {
    let transport =
        coppice_zcash_rpc::HttpTransport::new(coppice_zcash_rpc::ZcashRpcConfig::new(rpc_url))
            .map_err(|error| anyhow::anyhow!("construct RPC transport: {error:?}"))?;
    Ok(coppice_zcash_rpc::RpcCanonicalBlockSource::new(
        local_consensus(),
        coppice_zcash_rpc::ZcashRpcClient::new(transport),
        coppice_zcash_rpc::RpcAdapterConfig::new(NetworkType::Regtest, 1),
    ))
}

fn submit_raw(rpc_url: &str, bytes: &[u8]) -> Result<[u8; 32]> {
    let transport =
        coppice_zcash_rpc::HttpTransport::new(coppice_zcash_rpc::ZcashRpcConfig::new(rpc_url))
            .map_err(|error| anyhow::anyhow!("construct RPC transport: {error:?}"))?;
    let mut client = coppice_zcash_rpc::ZcashRpcClient::new(transport);
    client
        .submit_raw_transaction(bytes)
        .map_err(|error| anyhow::anyhow!("sendrawtransaction: {error:?}"))
}

fn generic_zcash_address() -> Result<zcash_address::ZcashAddress> {
    let recipient = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(
        &REGTEST.rendezvous.orchard_receiver,
    ))
    .context("configured generic rendezvous receiver is invalid")?;
    UnifiedAddress::from_receivers(Some(recipient), None, None)
        .context("construct generic rendezvous unified address")
        .map(|address| address.to_zcash_address(NetworkType::Regtest))
}

fn build_commit_request(frames: &[[u8; 512]]) -> Result<TransactionRequest> {
    let recipient = generic_zcash_address()?;
    let payments = frames
        .iter()
        .map(|frame| {
            Payment::new(
                recipient.clone(),
                Some(Zatoshis::ZERO),
                Some(MemoBytes::from_bytes(frame).context("encode CPV1 COMMIT memo")?),
                None,
                None,
                vec![],
            )
            .map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    TransactionRequest::new(payments).map_err(anyhow::Error::from)
}

fn build_wallet_transaction(wallet_dir: &Path, request: TransactionRequest) -> Result<Vec<u8>> {
    let params = local_consensus();
    let mut db = open_wallet(wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let usk = wallet_usk(&params)?;
    let change_strategy = MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(1).unwrap(),
            Zatoshis::from_u64(10_000_000)?,
        ),
    );
    let proposal = propose_transfer::<_, _, _, _, SqliteClientError>(
        &mut db,
        &params,
        account_id,
        &GreedyInputSelector::new(),
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &SpendPolicy::default(),
        None,
        Some(TransactionVersion::V6),
    )
    .map_err(|error| anyhow::anyhow!("propose COMMIT transaction: {error:?}"))?;
    let prover = LocalTxProver::bundled();
    let txids = create_proposed_transactions::<
        _,
        _,
        GreedyInputSelectorError,
        StandardFeeRule,
        zcash_primitives::transaction::fees::zip317::FeeError,
        _,
    >(
        &mut db,
        &params,
        &prover,
        &prover,
        &SpendingKeys::from_unified_spending_key(usk),
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(|error| anyhow::anyhow!("authorize COMMIT transaction: {error:?}"))?;
    ensure!(
        txids.len() == 1,
        "COMMIT unexpectedly split into transactions"
    );
    let transaction = db
        .get_transaction(txids[0])?
        .context("stored COMMIT transaction is unavailable")?;
    let mut bytes = Vec::new();
    transaction.write(&mut bytes)?;
    Ok(bytes)
}

fn selected_notes(
    db: &LiveWallet,
    height: u32,
    account_id: zcash_client_sqlite::AccountUuid,
) -> Result<Vec<(Note, Scope, incrementalmerkletree::Position, u64)>> {
    let mut selected = Vec::new();
    for received in db.get_unspent_ironwood_notes_at_historical_height(
        account_id,
        BlockHeight::from_u32(height),
    )? {
        let Some(mined_height) = received.mined_height() else {
            continue;
        };
        if u32::from(mined_height) <= height {
            let note = *received.note();
            selected.push((
                note,
                received.spending_key_scope(),
                received.note_commitment_tree_position(),
                note.value().inner(),
            ));
        }
    }
    Ok(selected)
}

fn wallet_witnesses(
    db: &mut LiveWallet,
    anchor_height: BlockHeight,
    positions: [incrementalmerkletree::Position; 2],
) -> Result<(orchard::Anchor, [orchard::tree::MerklePath; 2])> {
    let (anchor, paths) = db
        .with_ironwood_tree_mut::<_, _, SqliteClientError>(|tree| {
            let anchor = tree.root_at_checkpoint_id(&anchor_height)?;
            let paths = positions
                .map(|position| tree.witness_at_checkpoint_id_caching(position, &anchor_height));
            Ok((anchor, paths))
        })?
        .context("wallet does not expose an Ironwood tree")?;
    let [path0, path1] = paths;
    Ok((
        anchor.context("wallet has no Ironwood anchor")?.into(),
        [
            path0
                .map_err(|error| anyhow::anyhow!("read bond witness: {error:?}"))?
                .context("wallet has no bond witness")?
                .into(),
            path1
                .map_err(|error| anyhow::anyhow!("read funding witness: {error:?}"))?
                .context("wallet has no funding witness")?
                .into(),
        ],
    ))
}

fn parse_txid(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .context("transaction id is not hexadecimal")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("transaction id must contain 32 bytes"))
}

fn scan_exact(rpc_url: &str, deployment: DeploymentParameters, name: &Name) -> Result<Vec<Block>> {
    let params = local_consensus();
    let runtime_parameters = runtime_parameters()?;
    ensure!(
        runtime_parameters.core_runtime_id() == deployment.core_runtime_id,
        "live deployment/runtime mismatch"
    );
    let mut source = source_for(rpc_url)?;
    let tip = source
        .canonical_tip()
        .map_err(|error| anyhow::anyhow!("get canonical tip: {error:?}"))?;
    let first = source
        .compact_block(RUNTIME_ACTIVATION_HEIGHT)
        .map_err(|error| anyhow::anyhow!("get activation block: {error:?}"))?
        .context("activation block was not returned")?;
    let activation_parent_hash: [u8; 32] = first
        .prev_hash
        .as_slice()
        .try_into()
        .context("activation parent hash has wrong length")?;
    let replay = debug_result(CoreReplay::new(
        debug_result(CoreReplayConfiguration::new(
            RUNTIME_ACTIVATION_HEIGHT,
            tip.height.max(1),
        ))?,
        CoreReplayActivationCheckpoint {
            height: RUNTIME_ACTIVATION_HEIGHT - 1,
            block_hash: activation_parent_hash,
            ironwood_frontier: IronwoodFrontier::empty(),
            ironwood_tree_size: 0,
        },
    ))?;
    let mut runtime = debug_result(CoreRuntime::new(runtime_parameters.clone(), replay))?;
    let deployment_id = debug_result(deployment.deployment_id())?;
    let name_id = debug_result(name.id())?;
    let route = debug_result(NameRoute::derive(deployment_id, name_id))?;
    let rendezvous = debug_result(CoreRendezvous::try_new(
        &route.incoming_viewing_key(),
        &route.receiver(),
    ))?;
    let schedule = deployment.schedule(deployment_id);
    let mut blocks = Vec::new();
    for height in RUNTIME_ACTIVATION_HEIGHT..=tip.height {
        let compact = if height == RUNTIME_ACTIVATION_HEIGHT {
            first.clone()
        } else {
            source
                .compact_block(height)
                .map_err(|error| anyhow::anyhow!("get block {height}: {error:?}"))?
                .context("canonical block was not returned")?
        };
        let additional = if schedule.accepts_operation(name_id, height) {
            std::slice::from_ref(&rendezvous)
        } else {
            &[]
        };
        let applied = apply_compact_block_with_additional_rendezvous(
            &params,
            &mut runtime,
            &compact,
            &mut source,
            additional,
        )
        .map_err(|error| anyhow::anyhow!("apply canonical block {height}: {error:?}"))?;
        blocks.push(
            inspect_exact_name_block(
                applied.core(),
                &runtime_parameters,
                deployment,
                Network::Regtest,
                name,
            )
            .map_err(|error| anyhow::anyhow!("decode Names block {height}: {error:?}"))?,
        );
    }
    Ok(blocks)
}

fn print_target(args: TargetArgs) -> Result<()> {
    let runtime = runtime_parameters()?;
    let (_, verifier) = keygen();
    let deployment = deployment(runtime.core_runtime_id(), &verifier);
    let name = debug_result(Name::parse(NAME))?;
    let name_id = debug_result(name.id())?;
    let schedule = deployment.schedule(debug_result(deployment.deployment_id())?);
    let earliest = args
        .from_height
        .checked_add(1 + COMMIT_MATURITY_BLOCKS)
        .context("target height overflow")?;
    let reveal_height = (earliest..)
        .find(|height| schedule.accepts_operation(name_id, *height))
        .context("no representable REVEAL window")?;
    println!("TARGET_REVEAL_HEIGHT={reveal_height}");
    println!("COMMIT_MATURITY_BLOCKS={COMMIT_MATURITY_BLOCKS}");
    println!("COMMIT_TTL_BLOCKS={COMMIT_TTL_BLOCKS}");
    Ok(())
}

fn commit(args: CommitArgs) -> Result<()> {
    let runtime = runtime_parameters()?;
    let (_, verifier) = keygen();
    let deployment = deployment(runtime.core_runtime_id(), &verifier);
    let name = debug_result(Name::parse(NAME))?;
    let prepared = prepare_commit(&wallet_seed()?, deployment, &name, args.reveal_height)?;
    ensure!(
        prepared.publication().route() == PublicationRoute::Generic,
        "COMMIT publication is not on the generic route"
    );
    let raw = build_wallet_transaction(
        &args.common.wallet_dir,
        build_commit_request(prepared.publication().frames())?,
    )?;
    let txid = submit_raw(&args.common.rpc_url, &raw)?;
    println!("COMMIT_TXID={}", hex::encode(txid));
    println!("COMMIT_TARGET_EPOCH={}", prepared.target_epoch());
    println!(
        "COMMIT_CPV1_FRAMES={}",
        prepared.publication().frames().len()
    );
    println!("COMMIT_CARRIER_VALUE=0");
    Ok(())
}

fn reveal(args: RevealArgs) -> Result<()> {
    let params = local_consensus();
    let runtime = runtime_parameters()?;
    let (prover, verifier) = keygen();
    let deployment = deployment(runtime.core_runtime_id(), &verifier);
    let name = debug_result(Name::parse(NAME))?;
    let commit_txid = parse_txid(&args.commit_txid)?;
    let blocks = scan_exact(&args.common.rpc_url, deployment, &name)?;
    let (commit_ref, commitment) = blocks
        .iter()
        .flat_map(|block| {
            block.transactions.iter().filter_map(move |transaction| {
                if transaction.txid != commit_txid {
                    return None;
                }
                match transaction.operation.as_ref() {
                    Some(Operation::Commit { commitment }) => Some((
                        CommitRef {
                            height: block.height,
                            tx_index: transaction.tx_index,
                            txid: transaction.txid,
                        },
                        *commitment,
                    )),
                    _ => None,
                }
            })
        })
        .next()
        .context("canonical COMMIT was not decoded")?;

    let mut source = source_for(&args.common.rpc_url)?;
    let tip = source
        .canonical_tip()
        .map_err(|error| anyhow::anyhow!("get canonical tip: {error:?}"))?;
    ensure!(
        tip.height.checked_add(1) == Some(args.reveal_height),
        "REVEAL must be built for the next canonical height"
    );
    let usk = wallet_usk(&params)?;
    let wallet_fvk = FullViewingKey::from(usk.orchard());
    let wallet_ask = SpendAuthorizingKey::from(usk.orchard());
    let mut db = open_wallet(&args.common.wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let notes = selected_notes(&db, tip.height, account_id)?;
    let registration = notes
        .iter()
        .find(|(_, scope, _, value)| *scope == Scope::External && *value == BOND_ZATOSHIS)
        .cloned()
        .context("wallet has no exact external one-ZEC bond note")?;
    let funding = notes
        .into_iter()
        .filter(|(_, _, position, _)| *position != registration.2)
        .max_by_key(|(_, _, _, value)| *value)
        .context("wallet has no separate fee-funding note")?;
    let registration_nf = registration.0.nullifier(&wallet_fvk).to_bytes();
    let funding_nf = funding.0.nullifier(&wallet_fvk).to_bytes();
    let ua = debug_result(CanonicalUa::parse(Network::Regtest, &args.ua))?;
    let prepared = prepare_reveal(
        RevealInputs {
            wallet_seed: &wallet_seed()?,
            deployment,
            name: name.clone(),
            commit_ref,
            ua: ua.clone(),
            operation_height: args.reveal_height,
            designated_action_index: 0,
            registration_fvk: &wallet_fvk,
            registration_note: registration.0,
        },
        &prover,
        rand::rng(),
    )?;
    ensure!(
        prepared.statement().commitment == commitment,
        "REVEAL opening does not match canonical COMMIT"
    );
    let shape = names_ironwood_shape_from_counts(2, prepared.publication().frames().len(), 1, 0)?;
    let fee =
        required_zip317_fee_for_names(&params, BlockHeight::from_u32(args.reveal_height), shape)?;
    let change_value = funding
        .3
        .checked_sub(fee.into_u64())
        .context("funding note cannot cover the Names fee")?;
    let plan = prepared.ironwood_plan(
        wallet_fvk.clone(),
        registration.0,
        vec![FundingSpend {
            fvk: wallet_fvk.clone(),
            note: funding.0,
        }],
        vec![ChangeOutput {
            fvk: wallet_fvk.clone(),
            ovk: None,
            recipient: wallet_fvk.address_at(0u32, Scope::Internal),
            value: NoteValue::from_raw(change_value),
            memo: [0; 512],
        }],
    )?;
    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(&mut db, anchor_height, [registration.2, funding.2])?;
    let built = build_names_bundle(plan, rand::rng())?;
    ensure!(
        built.ironwood_value_balance == i64::try_from(fee.into_u64())?,
        "built REVEAL value balance differs from ZIP-317 fee"
    );
    let pczt = build_names_pczt(NamesPcztPlan {
        ironwood: built,
        params,
        consensus_branch_id: BranchId::Nu6_3,
        expiry_height: BlockHeight::from_u32(args.reveal_height),
        fallback_lock_time: 0,
    })?;
    let finalized = finalize_names_pczt_io(pczt)?;
    let witnessed = install_names_ironwood_witnesses(
        finalized,
        NamesWitnessPlan {
            anchor,
            spends: vec![
                NamesIronwoodWitness {
                    nullifier: registration_nf,
                    merkle_path: paths[0].clone(),
                },
                NamesIronwoodWitness {
                    nullifier: funding_nf,
                    merkle_path: paths[1].clone(),
                },
            ],
        },
    )?;
    let consensus_key = orchard::circuit::ProvingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let proved = prove_names_ironwood_pczt(witnessed, &consensus_key)?;
    let signed = sign_names_ironwood_pczt(
        proved,
        NamesSigningPlan {
            spends: vec![
                NamesIronwoodSigningKey {
                    nullifier: registration_nf,
                    ask: wallet_ask.clone(),
                },
                NamesIronwoodSigningKey {
                    nullifier: funding_nf,
                    ask: wallet_ask,
                },
            ],
        },
    )?;
    let extracted = extract_names_transaction(signed)?;
    let mut raw = Vec::new();
    extracted.transaction.write(&mut raw)?;
    let submitted = submit_raw(&args.common.rpc_url, &raw)?;
    let expected: [u8; 32] = extracted.txid.into();
    ensure!(
        submitted == expected,
        "node returned a different REVEAL txid"
    );
    println!("REVEAL_TXID={}", hex::encode(submitted));
    println!("REVEAL_HEIGHT={}", args.reveal_height);
    println!(
        "REVEAL_CPV1_FRAMES={}",
        prepared.publication().frames().len()
    );
    println!("REVEAL_CARRIER_VALUE=0");
    println!("REVEAL_FEE={}", fee.into_u64());
    println!("REVEAL_UA={}", ua.as_str());
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let runtime = runtime_parameters()?;
    let (_, verifier) = keygen();
    let deployment = deployment(runtime.core_runtime_id(), &verifier);
    let name = debug_result(Name::parse(NAME))?;
    let reveal_txid = parse_txid(&args.reveal_txid)?;
    let expected_ua = debug_result(CanonicalUa::parse(Network::Regtest, &args.ua))?;
    let blocks = scan_exact(&args.rpc_url, deployment, &name)?;
    let parent_hash = blocks
        .first()
        .map(|block| block.prev_hash)
        .context("canonical scan returned no blocks")?;
    let mut resolver = debug_result(ExactResolver::new(
        deployment.schedule(debug_result(deployment.deployment_id())?),
        parent_hash,
        name,
        verifier,
    ))?;
    let mut found_reveal = false;
    for block in &blocks {
        found_reveal |= block.transactions.iter().any(|transaction| {
            transaction.txid == reveal_txid
                && matches!(transaction.operation, Some(Operation::Reveal { .. }))
        });
        debug_result(resolver.apply_block(block))?;
    }
    ensure!(found_reveal, "canonical replacement REVEAL was not decoded");
    let tip = blocks.last().unwrap().height;
    let resolution = resolver.resolve(tip);
    ensure!(
        resolution.lifecycle == Lifecycle::Active,
        "name is not active"
    );
    ensure!(
        resolution.ua.as_ref() == Some(&expected_ua),
        "resolved UA mismatch"
    );
    let head = resolution.head.context("active resolution has no head")?;
    ensure!(
        head.producer.txid == reveal_txid,
        "resolved producer txid mismatch"
    );
    println!("NAMES_EXACT_STATUS=Active");
    println!("NAMES_RESOLVED_UA={}", expected_ua.as_str());
    println!("NAMES_HEAD_TXID={}", hex::encode(head.producer.txid));
    println!("NAMES_TIP_HEIGHT={tip}");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Target(args) => print_target(args),
        Command::Commit(args) => commit(args),
        Command::Reveal(args) => reveal(args),
        Command::Verify(args) => verify(args),
    }
}
