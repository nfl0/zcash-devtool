//! One disposable live Names v2 COMMIT -> REVEAL qualification flow.
//!
//! This binary intentionally owns only the narrow orchestration needed by the
//! live qualification script. It uses ordinary wallet construction for the
//! COMMIT, the existing designated-pair builder for the REVEAL, and ordinary
//! JSON-RPC acquisition for canonical producer positions and replay.

use std::{
    collections::BTreeMap,
    io::Cursor,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Instant,
};

use anyhow::{Context, Result, bail, ensure};
use bip0039::{English, Mnemonic};
use clap::{Args, Parser, Subcommand, ValueEnum};
use coppice::{carrier::CoreRendezvous, transport::reconstruct_frames};
use coppice_librustzcash::{CanonicalBlockSource, FullTransactionSource};
use coppice_names::{
    carrier::bulletin_address,
    config::REGTEST,
    names_application::names_application_id,
    v2::{
        AppliedOperationKind, AppliedOperationResult, CanonicalBlock, CanonicalTransaction,
        CommitRef, FreshResolver, IronwoodActionRef, NameState, OrchardV2ProofProver,
        OrchardV2ProofVerifier, ProducerPosition, RegistrationIntent, ResolutionStatus, StateRef,
        StateStatus, V2Operation, V2Parameters, V2StateMachine, decode_operation,
    },
};
use orchard::{
    circuit::state_note_binding::spend_auth_owner_key_bytes,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
    value::NoteValue,
};
use rand::rngs::OsRng;
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
use zcash_keys::{address::UnifiedAddress, keys::UnifiedSpendingKey};
use zcash_primitives::transaction::{Transaction, TxVersion as TransactionVersion};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, BranchId, NetworkType},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

use zcash_devtool::names_v2_builder::{
    ChangeOutput, FundingSpend, NamesV2IronwoodPlan, NamesV2IronwoodWitness, NamesV2PcztPlan,
    NamesV2SigningPlan, NamesV2WitnessPlan, build_names_v2_bundle, build_names_v2_pczt,
    extract_names_v2_transaction, finalize_names_v2_pczt_io, install_names_v2_ironwood_witnesses,
    names_v2_ironwood_shape, names_v2_ironwood_shape_from_counts, prove_names_v2_ironwood_pczt,
    required_zip317_fee_for_names_v2, sign_names_v2_ironwood_pczt, verify_designated_action,
};
use zcash_devtool::names_v2_operation::{
    CarrierPlan, FinalizedOperation, OperationFunding, RevealInputs, StateOperationPlan,
    SuccessorTransport, TransitionInputs, plan_state_operation,
    planned_state_operation_shape_and_fee, prepare_commit, prepare_release, prepare_renew,
    prepare_reveal, prepare_update,
};

const NAME: &str = "footprint";
const ACTION_INDEX: u32 = 4;
const RECORD: [u8; 64] = [9; 64];
const SECRET: [u8; 32] = [8; 32];
const SUCCESSOR_SEED: u8 = 3;
const UPDATE_ACTION_INDEX: u32 = 4;
const UPDATE_RECORD: [u8; 64] = [10; 64];
const UPDATE_SUCCESSOR_SEED: u8 = 4;
const RENEW_ACTION_INDEX: u32 = 4;
const RENEW_SUCCESSOR_SEED: u8 = 5;
const RELEASE_ACTION_INDEX: u32 = 4;
const RELEASE_SUCCESSOR_SEED: u8 = 6;
const RECLAIM_RECORD: [u8; 64] = [11; 64];
const RECLAIM_SECRET: [u8; 32] = [11; 32];
const RECLAIM_SUCCESSOR_SEED: u8 = 7;

#[derive(Parser)]
#[command(name = "names-v2-live")]
#[command(about = "Disposable live Names v2 COMMIT -> REVEAL qualification")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build, authorize, and submit the one-frame v2 COMMIT transaction.
    Commit(CommonArgs),
    /// Print the next legal v2 anchor height for the deterministic name.
    Target(TargetArgs),
    /// Build, authorize, and submit the real v2 REVEAL at the current target height.
    Reveal(RevealArgs),
    /// Replay the canonical chain and verify the initial active state.
    Verify(VerifyArgs),
    /// Build, authorize, and submit one real v2 UPDATE for the accepted name.
    Update(UpdateArgs),
    /// Replay the canonical chain and verify one real v2 UPDATE.
    VerifyUpdate(VerifyUpdateArgs),
    /// Spend the accepted state note without publishing a Names operation.
    Abandon(AbandonArgs),
    /// Replay and independently resolve an out-of-band state-note spend.
    VerifyAbandon(VerifyAbandonArgs),
    /// Build, authorize, and submit one real v2 RENEW for the accepted name.
    Renew(RenewArgs),
    /// Replay the canonical chain and verify one real v2 RENEW.
    VerifyRenew(VerifyRenewArgs),
    /// Build, authorize, and submit one real v2 RELEASE for the accepted name.
    Release(ReleaseArgs),
    /// Replay the canonical chain and verify one real v2 RELEASE.
    VerifyRelease(VerifyReleaseArgs),
    /// Verify the exact Released -> Expired claimability boundary.
    VerifyReleaseBoundary(VerifyReleaseBoundaryArgs),
    /// Build, authorize, and submit the replacement COMMIT for the claimable fixture name.
    ReclaimCommit(CommonArgs),
    /// Build, authorize, and submit the replacement REVEAL for the claimable fixture name.
    ReclaimReveal(ReclaimRevealArgs),
    /// Build, authorize, and submit a no-predecessor reset REVEAL.
    ReclaimResetReveal(RevealArgs),
    /// Validate the canonical replacement lineage and COMMIT without proving.
    ReclaimCheck(ReclaimRevealArgs),
    /// Replay and independently resolve the accepted explicit replacement registration.
    VerifyReclaim(VerifyReclaimArgs),
    /// Replay and independently resolve stale-to-active replacement RENEW recovery.
    VerifyReclaimRenew(VerifyReclaimRenewArgs),
}

#[derive(Args, Clone)]
struct CommonArgs {
    #[arg(long)]
    wallet_dir: PathBuf,
    #[arg(long)]
    rpc_url: String,
}

#[derive(Args)]
struct TargetArgs {
    #[arg(long)]
    from_height: u32,
}

#[derive(Args)]
struct RevealArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    commit_txid: String,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    commit_txid: String,
    #[arg(long)]
    reveal_txid: String,
}

#[derive(Args)]
struct UpdateArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    reveal_txid: String,
    /// Optional preceding RENEW, used by the retained-lineage fork probe.
    #[arg(long)]
    renew_txid: Option<String>,
    /// Use a deterministic 64-byte replacement record for a fork probe.
    #[arg(long)]
    record_byte: Option<u8>,
    /// Use a deterministic successor seed for a fork probe.
    #[arg(long)]
    successor_seed: Option<u8>,
    /// Preserve the extracted transaction at this path instead of only submitting it.
    #[arg(long)]
    raw_path: Option<PathBuf>,
    /// Build and extract without submitting; requires --raw-path.
    #[arg(long)]
    no_submit: bool,
}

#[derive(Args)]
struct VerifyUpdateArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    /// Optional accepted RENEW immediately preceding this UPDATE.
    #[arg(long)]
    renew_txid: Option<String>,
    #[arg(long)]
    update_txid: String,
    /// Expected deterministic record byte for the successor state.
    #[arg(long)]
    record_byte: Option<u8>,
}

#[derive(Args)]
struct AbandonArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
}

#[derive(Args)]
struct VerifyAbandonArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
    #[arg(long)]
    abandon_txid: String,
    #[arg(long, default_value_t = 13)]
    record_byte: u8,
    #[arg(long, value_enum)]
    expected_status: AbandonResolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "lower")]
enum AbandonResolution {
    Abandoned,
    Expired,
}

#[derive(Args)]
struct RenewArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: Option<String>,
}

#[derive(Args)]
struct VerifyRenewArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
    #[arg(long)]
    renew_txid: String,
}

#[derive(Args)]
struct ReleaseArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
    #[arg(long)]
    renew_txid: String,
}

#[derive(Args)]
struct VerifyReleaseArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
    #[arg(long)]
    renew_txid: String,
    #[arg(long)]
    release_txid: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "lower")]
enum ReleaseBoundaryStatus {
    Released,
    Expired,
}

#[derive(Args)]
struct VerifyReleaseBoundaryArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
    #[arg(long)]
    renew_txid: String,
    #[arg(long)]
    release_txid: String,
    #[arg(long, value_enum)]
    expected_status: ReleaseBoundaryStatus,
}

#[derive(Args)]
struct ReclaimRevealArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long)]
    commit_txid: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    update_txid: String,
    #[arg(long)]
    renew_txid: String,
    #[arg(long)]
    release_txid: String,
}

#[derive(Args)]
struct VerifyReclaimArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long, value_enum, default_value_t = ReclaimResolution::Active)]
    expected_status: ReclaimResolution,
}

#[derive(Args)]
struct VerifyReclaimRenewArgs {
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    reveal_txid: String,
    #[arg(long)]
    renew_txid: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "lower")]
enum ReclaimResolution {
    Active,
    Stale,
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

fn v2_parameters() -> V2Parameters {
    V2Parameters::testing()
}

fn registration_intent(
    ask: &SpendAuthorizingKey,
    record: [u8; 64],
    secret: [u8; 32],
) -> Result<RegistrationIntent> {
    Ok(RegistrationIntent {
        name: NAME.to_owned(),
        owner_pk: spend_auth_owner_key_bytes(ask),
        record: record.to_vec(),
        secret,
    })
}

fn wallet_usk(params: &LocalNetwork) -> Result<UnifiedSpendingKey> {
    let phrase = std::env::var("NAMES_V2_LIVE_MNEMONIC")
        .context("NAMES_V2_LIVE_MNEMONIC is required by the disposable live flow")?;
    let mnemonic = <Mnemonic<English>>::from_phrase(&phrase)
        .context("NAMES_V2_LIVE_MNEMONIC is not a valid English mnemonic")?;
    let seed = mnemonic.to_seed("");
    UnifiedSpendingKey::from_seed(params, &seed, zip32::AccountId::ZERO)
        .map_err(anyhow::Error::from)
        .context("derive deterministic live wallet spending key")
}

fn open_wallet(
    wallet_dir: &PathBuf,
    params: LocalNetwork,
) -> Result<WalletDb<rusqlite::Connection, LocalNetwork, SystemClock, OsRng>> {
    WalletDb::for_path(wallet_dir.join("data.sqlite"), params, SystemClock, OsRng)
        .context("open live wallet database")
}

fn names_recipient() -> Result<orchard::Address> {
    bulletin_address(REGTEST.rendezvous)
        .map_err(|error| anyhow::anyhow!("Names rendezvous: {error:?}"))
}

fn names_zcash_address() -> Result<zcash_address::ZcashAddress> {
    let recipient = names_recipient()?;
    UnifiedAddress::from_receivers(Some(recipient), None, None)
        .context("construct configured Names rendezvous unified address")
        .map(|address| address.to_zcash_address(NetworkType::Regtest))
}

fn build_carrier_request(frames: &[[u8; 512]]) -> Result<TransactionRequest> {
    let recipient = names_zcash_address()?;
    let payments = frames
        .iter()
        .map(|frame| {
            let memo = MemoBytes::from_bytes(frame).context("encode CPV1 carrier memo")?;
            Payment::new(
                recipient.clone(),
                Some(Zatoshis::from_u64(1).expect("one zatoshi is valid")),
                Some(memo),
                None,
                None,
                vec![],
            )
            .map_err(anyhow::Error::from)
            .context("construct Names COMMIT carrier payment")
        })
        .collect::<Result<Vec<_>>>()?;
    TransactionRequest::new(payments).map_err(anyhow::Error::from)
}

fn build_wallet_carrier_transaction(
    wallet_dir: &PathBuf,
    request: TransactionRequest,
) -> Result<Vec<u8>> {
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
            NonZeroUsize::new(1).expect("one is nonzero"),
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
    .map_err(|error| anyhow::anyhow!("propose Names COMMIT transaction: {error:?}"))
    .context("propose Names COMMIT transaction")?;
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
    .map_err(|error| anyhow::anyhow!("authorize Names COMMIT transaction: {error:?}"))
    .context("authorize Names COMMIT transaction")?;
    ensure!(
        txids.len() == 1,
        "Names COMMIT unexpectedly split into multiple transactions"
    );
    let transaction = db
        .get_transaction(*txids.first())?
        .context("stored Names COMMIT transaction is unavailable")?;
    let mut bytes = Vec::new();
    transaction.write(&mut bytes)?;
    Ok(bytes)
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

/// The qualified live funding policy: one funding note, one internal change
/// output, one-zatoshi carriers, and no outgoing ciphertexts. Production
/// wallets make their own funding and outgoing-recovery decisions directly
/// through the reusable library API; only this disposable harness fixes them.
fn plan_qualified_funding(
    params: &LocalNetwork,
    target_height: BlockHeight,
    finalized_operation: &FinalizedOperation,
    carrier_recipient: orchard::Address,
    names_fvk: &FullViewingKey,
    funding_note: &Note,
) -> Result<StateOperationPlan> {
    let (planned_shape, required_fee) =
        planned_state_operation_shape_and_fee(params, target_height, finalized_operation, 1, 1)?;
    let carrier_value_total = u64::try_from(finalized_operation.frames().len())
        .context("carrier count does not fit u64")?;
    let change_value = funding_note
        .value()
        .inner()
        .checked_sub(carrier_value_total)
        .and_then(|value| value.checked_sub(required_fee.into_u64()))
        .context("funding note cannot cover the carrier outputs and the ZIP-317 fee")?;
    let planned = plan_state_operation(
        params,
        target_height,
        finalized_operation,
        CarrierPlan {
            recipient: carrier_recipient,
            value: NoteValue::from_raw(1),
        },
        SuccessorTransport {
            ovk: None,
            memo: [0; 512],
        },
        OperationFunding {
            funding_spends: vec![FundingSpend {
                fvk: names_fvk.clone(),
                note: funding_note.clone(),
            }],
            change_outputs: vec![ChangeOutput {
                fvk: names_fvk.clone(),
                ovk: None,
                recipient: names_fvk.address_at(0u32, Scope::Internal),
                value: NoteValue::from_raw(change_value),
                memo: [0; 512],
            }],
        },
    )?;
    ensure!(
        planned.planned_shape == planned_shape,
        "Names v2 plan shape changed after fee planning"
    );
    Ok(planned)
}

fn build_commit(args: CommonArgs) -> Result<()> {
    build_commit_for(args, RECORD, SECRET, "COMMIT")
}

fn build_reclaim_commit(args: CommonArgs) -> Result<()> {
    build_commit_for(args, RECLAIM_RECORD, RECLAIM_SECRET, "RECLAIM_COMMIT")
}

fn build_commit_for(
    args: CommonArgs,
    record: [u8; 64],
    secret: [u8; 32],
    label: &str,
) -> Result<()> {
    let params = local_consensus();
    let usk = wallet_usk(&params)?;
    let ask = SpendAuthorizingKey::from(usk.orchard());
    let intent = registration_intent(&ask, record, secret)?;
    let prepared = prepare_commit(&intent)?;
    let commitment = prepared.commitment();
    let operation_bytes = prepared.encoded().len();
    let frame_count = prepared.frames().len();
    let raw = build_wallet_carrier_transaction(
        &args.wallet_dir,
        build_carrier_request(prepared.frames())?,
    )?;
    let txid = submit_raw(&args.rpc_url, &raw)?;
    println!("{label}_TXID={}", hex::encode(txid));
    println!("{label}_COMMITMENT={}", hex::encode(commitment));
    println!("{label}_OPERATION_BYTES={operation_bytes}");
    println!("{label}_CPV1_FRAMES={frame_count}");
    println!(
        "NAMES_APPLICATION_ID={}",
        hex::encode(names_application_id().to_bytes())
    );
    println!(
        "RENDEZVOUS_RECEIVER={}",
        hex::encode(REGTEST.rendezvous.orchard_receiver)
    );
    Ok(())
}

fn print_target(args: TargetArgs) -> Result<()> {
    let params = v2_parameters();
    // The name schedule depends only on the canonical name identifier, not on
    // the owner or hidden COMMIT preimage.
    let name_id = coppice_names::v2::state::name_id(NAME)
        .map_err(|error| anyhow::anyhow!("derive Names v2 name id: {error:?}"))?;
    let target = coppice_names::v2::schedule::next_anchor_height(name_id, args.from_height, params)
        .context("no future Names v2 anchor height exists")?;
    println!("TARGET_REVEAL_HEIGHT={target}");
    println!("COMMIT_TTL_BLOCKS={}", params.commit_ttl_blocks);
    println!("REFRESH_DEADLINE_BLOCKS={}", params.refresh_deadline_blocks);
    println!("LEASE_DURATION_BLOCKS={}", params.lease_duration_blocks);
    Ok(())
}

fn parse_txid_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("transaction id is not hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("transaction id must contain 32 bytes"))
}

fn parse_raw_transaction(raw: &[u8], params: &LocalNetwork, height: u32) -> Result<Transaction> {
    let branch = BranchId::for_height(params, BlockHeight::from_u32(height));
    let mut cursor = Cursor::new(raw);
    let transaction =
        Transaction::read(&mut cursor, branch).context("parse canonical transaction")?;
    ensure!(
        cursor.position() == raw.len() as u64,
        "canonical transaction has trailing bytes"
    );
    Ok(transaction)
}

fn source_for(
    rpc_url: &str,
) -> Result<
    coppice_zcash_rpc::RpcCanonicalBlockSource<LocalNetwork, coppice_zcash_rpc::HttpTransport>,
> {
    let transport =
        coppice_zcash_rpc::HttpTransport::new(coppice_zcash_rpc::ZcashRpcConfig::new(rpc_url))
            .map_err(|error| anyhow::anyhow!("construct RPC transport: {error:?}"))?;
    Ok(coppice_zcash_rpc::RpcCanonicalBlockSource::new(
        local_consensus(),
        coppice_zcash_rpc::ZcashRpcClient::new(transport),
        coppice_zcash_rpc::RpcAdapterConfig::new(NetworkType::Regtest, 1),
    ))
}

fn canonical_block(
    source: &mut coppice_zcash_rpc::RpcCanonicalBlockSource<
        LocalNetwork,
        coppice_zcash_rpc::HttpTransport,
    >,
    height: u32,
    params: &LocalNetwork,
    rendezvous: &CoreRendezvous,
    app_id: [u8; 32],
) -> Result<CanonicalBlock> {
    let compact = source
        .compact_block(height)
        .map_err(|error| anyhow::anyhow!("get canonical block {height}: {error:?}"))?
        .context("canonical block was not returned")?;
    let block_hash: [u8; 32] = compact
        .hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("canonical block hash has the wrong length"))?;
    let prev_block_hash: [u8; 32] = compact
        .prev_hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("canonical previous block hash has the wrong length"))?;
    let mut transactions = Vec::with_capacity(compact.vtx.len());
    for compact_tx in compact.vtx {
        let raw_txid: [u8; 32] = compact_tx
            .txid
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("canonical transaction id has the wrong length"))?;
        let raw = source
            .full_transaction(raw_txid)
            .map_err(|error| anyhow::anyhow!("get canonical transaction: {error:?}"))?
            .context("canonical transaction body was not cached")?;
        let transaction = parse_raw_transaction(&raw, params, height)?;
        let txid: [u8; 32] = transaction.txid().into();
        ensure!(
            txid == raw_txid,
            "canonical transaction id does not match its body"
        );
        let actions = transaction
            .ironwood_bundle()
            .map(|bundle| {
                bundle
                    .actions()
                    .iter()
                    .enumerate()
                    .map(|(index, action)| {
                        Ok(IronwoodActionRef {
                            action_index: u32::try_from(index)
                                .context("Ironwood action index exceeds u32")?,
                            nullifier: action.nullifier().to_bytes(),
                            commitment: action.cmx().to_bytes(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let frames = transaction
            .ironwood_bundle()
            .map(|bundle| {
                bundle
                    .actions()
                    .iter()
                    .filter_map(|action| rendezvous.action_memo(action))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let operations = if frames.is_empty() {
            Vec::new()
        } else {
            let payload = reconstruct_frames(&frames, app_id)
                .map_err(|error| anyhow::anyhow!("reconstruct canonical CPV1 frames: {error:?}"))?;
            let operation = decode_operation(&payload)
                .map_err(|error| anyhow::anyhow!("decode canonical Names operation: {error:?}"))?;
            vec![operation]
        };
        transactions.push(CanonicalTransaction {
            tx_index: u32::try_from(compact_tx.index).context("transaction index exceeds u32")?,
            txid,
            actions,
            operations,
        });
    }
    Ok(CanonicalBlock {
        height,
        block_hash,
        prev_block_hash,
        transactions,
    })
}

fn canonical_chain(
    source: &mut coppice_zcash_rpc::RpcCanonicalBlockSource<
        LocalNetwork,
        coppice_zcash_rpc::HttpTransport,
    >,
    params: &LocalNetwork,
    rendezvous: &CoreRendezvous,
    app_id: [u8; 32],
) -> Result<BTreeMap<u32, CanonicalBlock>> {
    let tip = source
        .canonical_tip()
        .map_err(|error| anyhow::anyhow!("get canonical tip: {error:?}"))?;
    let mut blocks = BTreeMap::new();
    for height in 1..=tip.height {
        blocks.insert(
            height,
            canonical_block(source, height, params, rendezvous, app_id)?,
        );
    }
    Ok(blocks)
}

struct ReplayedNamesLineage {
    blocks: BTreeMap<u32, CanonicalBlock>,
    tip_height: u32,
    activation_height: u32,
    activation_parent_hash: [u8; 32],
    name_id: [u8; 32],
    machine: V2StateMachine,
    full_status: ResolutionStatus,
    full_head: NameState,
    fresh_status: ResolutionStatus,
    fresh_head: NameState,
    fresh_anchor: Option<StateRef>,
    /// A stale state can be beyond the bounded fresh-discovery lookback while
    /// still being renewable by its wallet owner. Construction must then rely
    /// on authenticated full replay, not pretend a fresh lookup succeeded.
    fresh_available: bool,
}

/// Reconstructs the supplied registration and, optionally, requires canonical
/// state transitions to be accepted by both independent replay paths.
fn replay_names_lineage(
    source: &mut coppice_zcash_rpc::RpcCanonicalBlockSource<
        LocalNetwork,
        coppice_zcash_rpc::HttpTransport,
    >,
    params: &LocalNetwork,
    rendezvous: &CoreRendezvous,
    app_id: [u8; 32],
    reveal_txid: [u8; 32],
    update_txid: Option<[u8; 32]>,
    renew_txid: Option<[u8; 32]>,
    release_txid: Option<[u8; 32]>,
    verifier: &OrchardV2ProofVerifier,
) -> Result<ReplayedNamesLineage> {
    let blocks = canonical_chain(source, params, rendezvous, app_id)?;
    let canonical_tip_height = blocks
        .keys()
        .next_back()
        .copied()
        .context("canonical replay source contains no blocks")?;
    let reveal = blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == reveal_txid)
        .context("canonical REVEAL transaction is absent from replay source")?;
    ensure!(
        reveal.operations.len() == 1,
        "canonical REVEAL does not expose exactly one operation"
    );
    let V2Operation::Reveal {
        intent,
        commit,
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &reveal.operations[0]
    else {
        bail!("canonical REVEAL operation kind mismatch");
    };
    ensure!(
        intent.name == NAME,
        "canonical REVEAL name does not match the live qualification name"
    );
    let name_id = intent
        .name_id()
        .map_err(|error| anyhow::anyhow!("derive replay name id: {error:?}"))?;
    ensure!(
        state.name_id == name_id,
        "canonical REVEAL state name id differs from its intent"
    );
    let reveal_operation_index = reveal
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Reveal { .. }))
        .context("canonical REVEAL operation index missing")
        .and_then(|index| {
            u32::try_from(index).context("canonical REVEAL operation index exceeds u32")
        })?;
    let reveal_action = reveal
        .action(*action_index)
        .context("canonical REVEAL designated action is absent")?;
    ensure!(
        reveal_action.commitment == *state_commitment,
        "canonical REVEAL designated CMX mismatch"
    );

    let commit_txid = commit.position.txid;
    ensure!(
        commit_txid != reveal_txid,
        "canonical COMMIT and REVEAL txids must differ"
    );
    let commit_transaction = blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == commit_txid)
        .context("canonical COMMIT transaction referenced by REVEAL is absent")?;
    ensure!(
        commit_transaction.operations.len() == 1,
        "canonical COMMIT does not expose exactly one operation"
    );
    let V2Operation::Commit {
        commitment: canonical_commitment,
    } = &commit_transaction.operations[0]
    else {
        bail!("canonical COMMIT operation kind mismatch");
    };
    let commit_block = blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == commit_txid))
        .context("COMMIT block missing")?;
    ensure!(
        commit.position
            == ProducerPosition::new(
                commit_block.height,
                commit_transaction.tx_index,
                commit_txid
            ),
        "REVEAL CommitRef position does not match canonical COMMIT location"
    );
    ensure!(
        *canonical_commitment == commit.commitment,
        "REVEAL CommitRef commitment does not match canonical COMMIT"
    );

    let update_transaction = if let Some(update_txid) = update_txid {
        ensure!(
            update_txid != commit_txid && update_txid != reveal_txid,
            "UPDATE txid must differ from the registration transactions"
        );
        let transaction = blocks
            .values()
            .flat_map(|block| block.transactions.iter())
            .find(|transaction| transaction.txid == update_txid)
            .context("canonical UPDATE transaction is absent from replay source")?;
        ensure!(
            transaction.operations.len() == 1,
            "canonical UPDATE does not expose exactly one operation"
        );
        ensure!(
            matches!(transaction.operations[0], V2Operation::Update { .. }),
            "canonical UPDATE operation kind mismatch"
        );
        Some(transaction)
    } else {
        None
    };
    let update_operation_index = if let Some(transaction) = update_transaction {
        let index = transaction
            .operations
            .iter()
            .position(|operation| matches!(operation, V2Operation::Update { .. }))
            .expect("UPDATE operation was checked above");
        Some(u32::try_from(index).context("canonical UPDATE operation index exceeds u32")?)
    } else {
        None
    };
    let renew_transaction = if let Some(renew_txid) = renew_txid {
        ensure!(
            renew_txid != commit_txid
                && renew_txid != reveal_txid
                && Some(renew_txid) != update_txid,
            "RENEW txid must differ from the registration and UPDATE transactions"
        );
        let transaction = blocks
            .values()
            .flat_map(|block| block.transactions.iter())
            .find(|transaction| transaction.txid == renew_txid)
            .context("canonical RENEW transaction is absent from replay source")?;
        ensure!(
            transaction.operations.len() == 1,
            "canonical RENEW does not expose exactly one operation"
        );
        ensure!(
            matches!(transaction.operations[0], V2Operation::Renew { .. }),
            "canonical RENEW operation kind mismatch"
        );
        Some(transaction)
    } else {
        None
    };
    let renew_operation_index = if let Some(transaction) = renew_transaction {
        let index = transaction
            .operations
            .iter()
            .position(|operation| matches!(operation, V2Operation::Renew { .. }))
            .expect("RENEW operation was checked above");
        Some(u32::try_from(index).context("canonical RENEW operation index exceeds u32")?)
    } else {
        None
    };
    let release_transaction = if let Some(release_txid) = release_txid {
        ensure!(
            release_txid != commit_txid
                && release_txid != reveal_txid
                && Some(release_txid) != update_txid
                && Some(release_txid) != renew_txid,
            "RELEASE txid must differ from the registration, UPDATE, and RENEW transactions"
        );
        let transaction = blocks
            .values()
            .flat_map(|block| block.transactions.iter())
            .find(|transaction| transaction.txid == release_txid)
            .context("canonical RELEASE transaction is absent from replay source")?;
        ensure!(
            transaction.operations.len() == 1,
            "canonical RELEASE does not expose exactly one operation"
        );
        ensure!(
            matches!(transaction.operations[0], V2Operation::Release { .. }),
            "canonical RELEASE operation kind mismatch"
        );
        Some(transaction)
    } else {
        None
    };
    let release_operation_index = if let Some(transaction) = release_transaction {
        let index = transaction
            .operations
            .iter()
            .position(|operation| matches!(operation, V2Operation::Release { .. }))
            .expect("RELEASE operation was checked above");
        Some(u32::try_from(index).context("canonical RELEASE operation index exceeds u32")?)
    } else {
        None
    };

    let v2 = v2_parameters();
    let activation_height = v2.activation_height;
    let activation_block = blocks
        .get(&activation_height)
        .context("canonical replay source is missing the v2 activation block")?;
    let activation_parent_hash = activation_block.prev_block_hash;
    let mut machine = V2StateMachine::from_activation_parent(v2, activation_parent_hash)
        .map_err(|error| anyhow::anyhow!("construct Names v2 replay machine: {error:?}"))?;
    let mut commit_seen = false;
    let mut reveal_seen = false;
    let mut update_seen = false;
    let mut renew_seen = false;
    let mut release_seen = false;
    for height in activation_height..=canonical_tip_height {
        let block = blocks
            .get(&height)
            .context("canonical replay source is missing a sequential block")?;
        let applied = machine.apply_block(block, verifier).map_err(|error| {
            anyhow::anyhow!("Names v2 full replay failed at h{height}: {error:?}")
        })?;
        for transaction in &block.transactions {
            if transaction.txid == commit_txid {
                ensure!(!commit_seen, "canonical COMMIT was replayed more than once");
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index && operation.operation_index == 0
                    })
                    .context("full replay did not return the canonical COMMIT result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(None) => {}
                    AppliedOperationResult::Accepted(other) => {
                        bail!("full replay COMMIT result was not Accepted(None): {other:?}")
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay COMMIT was rejected: {error:?}")
                    }
                }
                commit_seen = true;
            }
            if transaction.txid == reveal_txid {
                ensure!(!reveal_seen, "canonical REVEAL was replayed more than once");
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index
                            && operation.operation_index == reveal_operation_index
                    })
                    .context("full replay did not return the canonical REVEAL result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(Some((accepted_name_id, kind))) => {
                        ensure!(
                            *accepted_name_id == name_id,
                            "full replay REVEAL accepted the wrong name id"
                        );
                        ensure!(
                            *kind == AppliedOperationKind::Reveal,
                            "full replay REVEAL returned the wrong operation kind"
                        );
                    }
                    AppliedOperationResult::Accepted(other) => {
                        bail!("full replay REVEAL result was not Accepted(name, Reveal): {other:?}")
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay REVEAL was rejected: {error:?}")
                    }
                }
                reveal_seen = true;
            }
            if Some(transaction.txid) == update_txid {
                ensure!(!update_seen, "canonical UPDATE was replayed more than once");
                let operation_index =
                    update_operation_index.context("canonical UPDATE operation index missing")?;
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index
                            && operation.operation_index == operation_index
                    })
                    .context("full replay did not return the canonical UPDATE result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(Some((accepted_name_id, kind))) => {
                        ensure!(
                            *accepted_name_id == name_id,
                            "full replay UPDATE accepted the wrong name id"
                        );
                        ensure!(
                            *kind == AppliedOperationKind::Update,
                            "full replay UPDATE returned the wrong operation kind"
                        );
                    }
                    AppliedOperationResult::Accepted(other) => {
                        bail!("full replay UPDATE result was not Accepted(name, Update): {other:?}")
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay UPDATE was rejected: {error:?}")
                    }
                }
                update_seen = true;
            }
            if Some(transaction.txid) == renew_txid {
                ensure!(!renew_seen, "canonical RENEW was replayed more than once");
                let operation_index =
                    renew_operation_index.context("canonical RENEW operation index missing")?;
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index
                            && operation.operation_index == operation_index
                    })
                    .context("full replay did not return the canonical RENEW result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(Some((accepted_name_id, kind))) => {
                        ensure!(
                            *accepted_name_id == name_id,
                            "full replay RENEW accepted the wrong name id"
                        );
                        ensure!(
                            *kind == AppliedOperationKind::Renew,
                            "full replay RENEW returned the wrong operation kind"
                        );
                    }
                    AppliedOperationResult::Accepted(other) => {
                        bail!("full replay RENEW result was not Accepted(name, Renew): {other:?}")
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay RENEW was rejected: {error:?}")
                    }
                }
                renew_seen = true;
            }
            if Some(transaction.txid) == release_txid {
                ensure!(
                    !release_seen,
                    "canonical RELEASE was replayed more than once"
                );
                let operation_index =
                    release_operation_index.context("canonical RELEASE operation index missing")?;
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index
                            && operation.operation_index == operation_index
                    })
                    .context("full replay did not return the canonical RELEASE result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(Some((accepted_name_id, kind))) => {
                        ensure!(
                            *accepted_name_id == name_id,
                            "full replay RELEASE accepted the wrong name id"
                        );
                        ensure!(
                            *kind == AppliedOperationKind::Release,
                            "full replay RELEASE returned the wrong operation kind"
                        );
                    }
                    AppliedOperationResult::Accepted(other) => {
                        bail!(
                            "full replay RELEASE result was not Accepted(name, Release): {other:?}"
                        )
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay RELEASE was rejected: {error:?}")
                    }
                }
                release_seen = true;
            }
        }
    }
    ensure!(
        commit_seen,
        "full replay did not process the canonical COMMIT"
    );
    ensure!(
        reveal_seen,
        "full replay did not process the canonical REVEAL"
    );
    ensure!(
        update_txid.is_none() || update_seen,
        "full replay did not process the canonical UPDATE"
    );
    ensure!(
        renew_txid.is_none() || renew_seen,
        "full replay did not process the canonical RENEW"
    );
    ensure!(
        release_txid.is_none() || release_seen,
        "full replay did not process the canonical RELEASE"
    );

    let full_status = machine.resolution_at(name_id, canonical_tip_height);
    let full_head = machine
        .head(name_id)
        .context("full replay returned no accepted Names state")?
        .clone();
    if update_txid.is_none() && renew_txid.is_none() && release_txid.is_none() {
        ensure!(
            full_head.commitment == *state_commitment,
            "full replay registration commitment mismatch"
        );
        ensure!(
            full_head.state_ref.nullifier == *state_nullifier,
            "full replay registration future nullifier mismatch"
        );
    }
    let resolver = FreshResolver::new(v2)
        .map_err(|error| anyhow::anyhow!("construct Names v2 fresh resolver: {error:?}"))?;
    let (fresh_status, fresh_anchor, fresh_head, fresh_available) =
        match resolver.resolve(NAME, &blocks, verifier) {
            Ok(fresh_result) => {
                let Some(fresh_head) = fresh_result.state else {
                    if full_status == ResolutionStatus::Stale {
                        return Ok(ReplayedNamesLineage {
                            blocks,
                            tip_height: canonical_tip_height,
                            activation_height,
                            activation_parent_hash,
                            name_id,
                            machine,
                            full_status,
                            full_head: full_head.clone(),
                            fresh_status: full_status,
                            fresh_head: full_head,
                            fresh_anchor: fresh_result.anchor,
                            fresh_available: false,
                        });
                    }
                    bail!("FreshResolver returned no accepted Names state");
                };
                ensure!(
                    full_status == fresh_result.status,
                    "full replay and FreshResolver returned different statuses"
                );
                ensure!(
                    full_head == fresh_head,
                    "full replay and FreshResolver returned different NameState values"
                );
                (fresh_result.status, fresh_result.anchor, fresh_head, true)
            }
            Err(_) if full_status == ResolutionStatus::Stale => {
                (full_status, None, full_head.clone(), false)
            }
            Err(error) => bail!("Names v2 FreshResolver failed: {error:?}"),
        };

    Ok(ReplayedNamesLineage {
        blocks,
        tip_height: canonical_tip_height,
        activation_height,
        activation_parent_hash,
        name_id,
        machine,
        full_status,
        full_head,
        fresh_status,
        fresh_head,
        fresh_anchor,
        fresh_available,
    })
}

fn find_canonical_commit(
    source: &mut coppice_zcash_rpc::RpcCanonicalBlockSource<
        LocalNetwork,
        coppice_zcash_rpc::HttpTransport,
    >,
    params: &LocalNetwork,
    rendezvous: &CoreRendezvous,
    app_id: [u8; 32],
    expected_txid: [u8; 32],
    expected_commitment: [u8; 32],
) -> Result<(CommitRef, u32)> {
    let tip = source
        .canonical_tip()
        .map_err(|error| anyhow::anyhow!("get canonical tip: {error:?}"))?;
    let mut match_found = None;
    for height in 1..=tip.height {
        let block = canonical_block(source, height, params, rendezvous, app_id)?;
        for transaction in block.transactions {
            if transaction.txid != expected_txid {
                continue;
            }
            ensure!(
                match_found.is_none(),
                "COMMIT transaction appears twice canonically"
            );
            let matches = transaction
                .operations
                .iter()
                .enumerate()
                .map(|(index, operation)| -> Result<Option<u32>> {
                    match operation {
                        V2Operation::Commit { commitment }
                            if *commitment == expected_commitment =>
                        {
                            Ok(Some(
                                u32::try_from(index)
                                    .context("canonical operation index exceeds u32")?,
                            ))
                        }
                        _ => Ok(None),
                    }
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1,
                "canonical COMMIT transaction does not contain exactly one intended operation"
            );
            let operation_index = matches[0];
            match_found = Some((
                CommitRef::new(
                    ProducerPosition::new(height, transaction.tx_index, transaction.txid),
                    operation_index,
                    expected_commitment,
                ),
                height,
            ));
        }
    }
    match_found.context("submitted COMMIT transaction is not in the canonical chain")
}

fn selected_notes(
    db: &WalletDb<rusqlite::Connection, LocalNetwork, SystemClock, OsRng>,
    height: u32,
    account_id: zcash_client_sqlite::AccountUuid,
) -> Result<Vec<(Note, Scope, incrementalmerkletree::Position, u64)>> {
    let notes = db.get_unspent_ironwood_notes_at_historical_height(
        account_id,
        BlockHeight::from_u32(height),
    )?;
    let mut selected = Vec::new();
    for received in notes {
        let Some(mined_height) = received.mined_height() else {
            continue;
        };
        if u32::from(mined_height) > height {
            continue;
        }
        let note = *received.note();
        selected.push((
            note,
            received.spending_key_scope(),
            received.note_commitment_tree_position(),
            note.value().inner(),
        ));
    }
    Ok(selected)
}

fn wallet_witnesses(
    db: &mut WalletDb<rusqlite::Connection, LocalNetwork, SystemClock, OsRng>,
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
        .context("wallet does not expose an Ironwood commitment tree")?;
    let anchor = anchor
        .context("wallet has no Ironwood root at its anchor height")?
        .into();
    let [path0, path1] = paths;
    let path0 = path0
        .map_err(|error| anyhow::anyhow!("read Ironwood witness: {error:?}"))?
        .context("wallet has no Ironwood witness at its anchor height")?
        .into();
    let path1 = path1
        .map_err(|error| anyhow::anyhow!("read Ironwood witness: {error:?}"))?
        .context("wallet has no Ironwood witness at its anchor height")?
        .into();
    Ok((anchor, [path0, path1]))
}

fn reveal(args: RevealArgs) -> Result<()> {
    reveal_with_replacement(args, RECORD, SECRET, SUCCESSOR_SEED, None, "REVEAL")
}

fn reveal_with_replacement(
    args: RevealArgs,
    record: [u8; 64],
    secret: [u8; 32],
    successor_seed: u8,
    replacement_predecessor: Option<StateRef>,
    flow_label: &str,
) -> Result<()> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let commit_txid = parse_txid_hex(&args.commit_txid)?;
    let mut source = source_for(&args.common.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let usk = wallet_usk(&params)?;
    let names_fvk = FullViewingKey::from(usk.orchard());
    let names_ask = SpendAuthorizingKey::from(usk.orchard());
    let intent = registration_intent(&names_ask, record, secret)?;
    let intent_commitment = intent
        .commitment()
        .map_err(|error| anyhow::anyhow!("derive REVEAL commitment: {error:?}"))?;
    let (commit, commit_height) = find_canonical_commit(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        commit_txid,
        intent_commitment,
    )?;
    let tip = source
        .canonical_tip()
        .map_err(|error| anyhow::anyhow!("get canonical tip: {error:?}"))?;
    let construction_height = tip
        .height
        .checked_add(1)
        .context("live chain height overflow")?;
    let name_id = intent
        .name_id()
        .map_err(|error| anyhow::anyhow!("derive REVEAL name id: {error:?}"))?;
    let target_height =
        coppice_names::v2::schedule::next_anchor_height(name_id, construction_height, v2)
            .context("no future legal Names v2 reveal height exists")?;
    ensure!(
        construction_height == target_height,
        "REVEAL must be constructed at its scheduled anchor height; current height is {construction_height}, target is {target_height}"
    );
    ensure!(
        construction_height > commit_height,
        "REVEAL cannot be in the COMMIT block"
    );
    ensure!(
        construction_height - commit_height <= v2.commit_ttl_blocks,
        "canonical COMMIT is outside its v2 lifetime"
    );

    let mut db = open_wallet(&args.common.wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let notes = selected_notes(&db, tip.height, account_id)?;
    let mut candidates = notes
        .into_iter()
        .filter(|(_, scope, _, value)| {
            *scope == Scope::External && *value >= v2.minimum_bond_zatoshis
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() >= 2,
        "live wallet has fewer than two spendable external Ironwood notes at height {height}",
        height = tip.height
    );
    let registration = candidates.remove(0);
    let funding = candidates.remove(0);
    let registration_note = registration.0;
    let funding_note = funding.0;
    let registration_nf = registration_note.nullifier(&names_fvk).to_bytes();
    let preparation = prepare_reveal(
        RevealInputs {
            intent,
            commit,
            replacement_predecessor,
            registration_note,
            scope: registration.1,
            fvk: names_fvk.clone(),
            ask: names_ask.clone(),
            designated_action_index: ACTION_INDEX,
            operation_height: construction_height,
            successor_seed: [successor_seed; 32],
        },
        v2,
    )?;
    let successor_commitment = preparation.statement().commitment;
    let successor_future_nf = preparation.statement().state_nullifier;
    let lease_expiry = preparation.statement().lease_expiry;
    let names_prover = OrchardV2ProofProver::new();
    let proof_started = Instant::now();
    let genesis_proof = names_prover
        .prove_genesis(
            preparation.statement(),
            preparation.witness().clone(),
            OsRng,
        )
        .map_err(|error| anyhow::anyhow!("create Names genesis proof: {error:?}"))?;
    let proof_elapsed = proof_started.elapsed();
    let finalized_operation = preparation.finalize(genesis_proof.clone())?;

    let carrier_recipient = names_recipient()?;
    let funding_nf = funding_note.nullifier(&names_fvk).to_bytes();
    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no synchronized target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(&mut db, anchor_height, [registration.2, funding.2])?;
    let planned = plan_qualified_funding(
        &params,
        BlockHeight::from_u32(construction_height),
        &finalized_operation,
        carrier_recipient,
        &names_fvk,
        &funding_note,
    )?;
    let built = build_names_v2_bundle(planned.plan, OsRng)?;
    ensure!(
        built.action_count == planned.planned_shape.action_count,
        "built Names v2 action count differs from fee-planned shape"
    );
    ensure!(
        built.ironwood_value_balance
            == i64::try_from(planned.required_fee.into_u64())
                .context("ZIP-317 fee does not fit signed balance")?,
        "built Names v2 value balance differs from required ZIP-317 fee"
    );
    let complete = build_names_v2_pczt(NamesV2PcztPlan {
        ironwood: built,
        params,
        consensus_branch_id: BranchId::Nu6_3,
        expiry_height: BlockHeight::from_u32(construction_height),
        fallback_lock_time: 0,
    })?;
    let finalized = finalize_names_v2_pczt_io(complete)?;
    let witnessed = install_names_v2_ironwood_witnesses(
        finalized,
        NamesV2WitnessPlan {
            anchor,
            spends: vec![
                NamesV2IronwoodWitness {
                    nullifier: registration_nf,
                    merkle_path: paths[0].clone(),
                },
                NamesV2IronwoodWitness {
                    nullifier: funding_nf,
                    merkle_path: paths[1].clone(),
                },
            ],
        },
    )?;
    let consensus_proving_key = orchard::circuit::ProvingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let consensus_proof_started = Instant::now();
    let proved = prove_names_v2_ironwood_pczt(witnessed, &consensus_proving_key)?;
    let consensus_proof_elapsed = consensus_proof_started.elapsed();
    let signed = sign_names_v2_ironwood_pczt(
        proved,
        NamesV2SigningPlan {
            spends: vec![
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: registration_nf,
                    ask: names_ask,
                },
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: funding_nf,
                    ask: SpendAuthorizingKey::from(usk.orchard()),
                },
            ],
        },
    )?;
    let extracted = extract_names_v2_transaction(signed)?;
    let mut raw = Vec::new();
    extracted.transaction.write(&mut raw)?;
    let reveal_txid = submit_raw(&args.common.rpc_url, &raw)?;
    let final_txid: [u8; 32] = extracted.txid.into();
    ensure!(
        reveal_txid == final_txid,
        "node returned a different REVEAL txid"
    );

    println!("REGISTRATION_FLOW={flow_label}");
    println!("COMMIT_TXID={}", hex::encode(commit.position.txid));
    println!("COMMITMENT={}", hex::encode(commit.commitment));
    println!("COMMIT_HEIGHT={}", commit.position.height);
    println!("COMMIT_TX_INDEX={}", commit.position.tx_index);
    println!("COMMIT_OPERATION_INDEX={}", commit.operation_index);
    println!("COMMIT_REF_POSITION_HEIGHT={}", commit.position.height);
    println!("COMMIT_REF_POSITION_TX_INDEX={}", commit.position.tx_index);
    println!(
        "COMMIT_REF_POSITION_TXID={}",
        hex::encode(commit.position.txid)
    );
    println!("COMMIT_REF_OPERATION_INDEX={}", commit.operation_index);
    println!("TARGET_REVEAL_HEIGHT={target_height}");
    println!("REVEAL_CONSTRUCTION_HEIGHT={construction_height}");
    println!("LEASE_EXPIRY={lease_expiry}");
    println!("NAMES_PROOF_BYTES={}", genesis_proof.len());
    println!("NAMES_PROOF_ELAPSED_MS={}", proof_elapsed.as_millis());
    println!("CNV2_REVEAL_BYTES={}", finalized_operation.encoded().len());
    println!("CPV1_FRAMES={}", finalized_operation.frames().len());
    println!("REVEAL_TXID={}", hex::encode(final_txid));
    println!("REVEAL_ACTION_INDEX={ACTION_INDEX}");
    println!("REVEAL_ACTION_COUNT={}", extracted.action_count);
    println!("REVEAL_REAL_SPENDS={}", extracted.real_spend_count);
    println!("REVEAL_CARRIER_OUTPUTS={}", extracted.carrier_output_count);
    println!("REVEAL_CHANGE_OUTPUTS={}", extracted.change_output_count);
    println!("REVEAL_VALUE_BALANCE={}", extracted.ironwood_value_balance);
    println!("REVEAL_ANCHOR={}", hex::encode(anchor.to_bytes()));
    println!("REGISTRATION_NF={}", hex::encode(registration_nf));
    println!("SUCCESSOR_CMX={}", hex::encode(successor_commitment));
    println!("SUCCESSOR_FUTURE_NF={}", hex::encode(successor_future_nf));
    println!(
        "REPLACEMENT_PREDECESSOR={}",
        replacement_predecessor
            .map(|reference| hex::encode(reference.digest()))
            .unwrap_or_else(|| "none".to_owned())
    );
    println!(
        "CONSENSUS_PROOF_BYTES={}",
        extracted.ironwood_proof_byte_len
    );
    println!(
        "CONSENSUS_PROOF_ELAPSED_MS={}",
        consensus_proof_elapsed.as_millis()
    );
    println!("REVEAL_TX_BYTES={}", raw.len());
    println!("NAMES_APPLICATION_ID={}", hex::encode(app_id));
    println!(
        "RENDEZVOUS_RECEIVER={}",
        hex::encode(REGTEST.rendezvous.orchard_receiver)
    );
    Ok(())
}

struct ReclaimContext {
    terminal: NameState,
    claimable_height: u32,
    commit: CommitRef,
}

fn reclaim_context(args: &ReclaimRevealArgs) -> Result<ReclaimContext> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let renew_txid = parse_txid_hex(&args.renew_txid)?;
    let release_txid = parse_txid_hex(&args.release_txid)?;
    let mut source = source_for(&args.common.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        Some(renew_txid),
        Some(release_txid),
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Expired
            && lineage.fresh_status == ResolutionStatus::Expired
            && lineage.full_head == lineage.fresh_head,
        "replacement requires the exact canonical terminal lineage to be claimable"
    );
    let terminal = lineage.full_head.clone();
    ensure!(
        terminal.data.status == StateStatus::Released,
        "replacement predecessor is not an explicitly released terminal state"
    );
    let claimable_height = v2
        .claimable_from(
            terminal.data.status,
            terminal.data.lease_expiry,
            terminal.data.terminal_height,
        )
        .context("derive terminal claimability height")?;
    ensure!(
        lineage.tip_height >= claimable_height,
        "canonical tip is before the released lineage claimability boundary"
    );

    let usk = wallet_usk(&params)?;
    let ask = SpendAuthorizingKey::from(usk.orchard());
    let reclaim_intent = registration_intent(&ask, RECLAIM_RECORD, RECLAIM_SECRET)?;
    let reclaim_commitment = reclaim_intent
        .commitment()
        .map_err(|error| anyhow::anyhow!("derive replacement COMMIT commitment: {error:?}"))?;
    let (commit, _) = find_canonical_commit(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        parse_txid_hex(&args.commit_txid)?,
        reclaim_commitment,
    )?;
    ensure!(
        commit.position.height >= claimable_height,
        "replacement COMMIT predates the canonical claimability boundary"
    );
    Ok(ReclaimContext {
        terminal,
        claimable_height,
        commit,
    })
}

fn print_reclaim_context(context: &ReclaimContext) {
    println!(
        "RECLAIM_PREDECESSOR_HEIGHT={}",
        context.terminal.state_ref.position().height
    );
    println!(
        "RECLAIM_PREDECESSOR_TXID={}",
        hex::encode(context.terminal.state_ref.position().txid)
    );
    println!("RECLAIM_CLAIMABLE_HEIGHT={}", context.claimable_height);
    println!("RECLAIM_COMMIT_HEIGHT={}", context.commit.position.height);
    println!("RECLAIM_PRECONDITIONS=yes");
}

fn reclaim_check(args: ReclaimRevealArgs) -> Result<()> {
    let context = reclaim_context(&args)?;
    print_reclaim_context(&context);
    Ok(())
}

fn reclaim_reveal(args: ReclaimRevealArgs) -> Result<()> {
    let context = reclaim_context(&args)?;
    print_reclaim_context(&context);
    reveal_with_replacement(
        RevealArgs {
            common: args.common,
            commit_txid: args.commit_txid,
        },
        RECLAIM_RECORD,
        RECLAIM_SECRET,
        RECLAIM_SUCCESSOR_SEED,
        Some(context.terminal.state_ref),
        "EXPLICIT_REPLACEMENT_REVEAL",
    )
}

fn verify_reclaim(args: VerifyReclaimArgs) -> Result<()> {
    let params = local_consensus();
    let mut source = source_for(&args.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        None,
        None,
        None,
        &names_verifier,
    )?;
    let expected_status = match args.expected_status {
        ReclaimResolution::Active => ResolutionStatus::Active,
        ReclaimResolution::Stale => ResolutionStatus::Stale,
    };
    ensure!(
        lineage.full_status == expected_status
            && lineage.fresh_status == expected_status
            && lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver did not agree on the expected replacement status"
    );
    let replacement = lineage.full_head;
    ensure!(
        replacement.data.sequence == 0
            && replacement.data.record.as_slice() == RECLAIM_RECORD.as_slice()
            && replacement.data.status == StateStatus::Active
            && replacement.data.terminal_height == 0
            && replacement.data.lease_expiry == 79,
        "replacement head does not have the expected sequence-zero active state"
    );
    let transaction = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == reveal_txid)
        .context("canonical replacement REVEAL is absent")?;
    let block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == reveal_txid))
        .context("canonical replacement REVEAL block is absent")?;
    let V2Operation::Reveal {
        replacement_predecessor,
        action_index,
        state_commitment,
        state_nullifier,
        ..
    } = &transaction.operations[0]
    else {
        bail!("canonical replacement transaction has the wrong operation kind");
    };
    let expected_terminal = StateRef::new(
        ProducerPosition::new(
            28,
            1,
            parse_txid_hex("d2df7d9769643c8d6255d63a65a2c49bbd0f4a878a5db8cb00f68188fe563b13")?,
        ),
        4,
        0,
        hex::decode("e3411a420eb53dfe20bd6a774a8f6cfd9050ae7e4748953086c96aa110435a1e")
            .context("decode qualified RELEASE commitment")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("qualified RELEASE commitment has wrong length"))?,
        hex::decode("4c64584fe56e56e963579f810ec59cb7355ef054a1190dc79fcb98ca9a7d5511")
            .context("decode qualified RELEASE future nullifier")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("qualified RELEASE nullifier has wrong length"))?,
    );
    ensure!(
        *replacement_predecessor == Some(expected_terminal),
        "replacement REVEAL did not carry the exact canonical RELEASE predecessor"
    );
    ensure!(
        replacement.state_ref.position()
            == ProducerPosition::new(block.height, transaction.tx_index, reveal_txid)
            && replacement.state_ref.producer_action_index == *action_index
            && replacement.commitment == *state_commitment
            && replacement.state_ref.nullifier == *state_nullifier,
        "replacement state ref does not match its canonical producer"
    );
    println!("NAMES_FULL_REPLAY_STATUS={:?}", expected_status);
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", expected_status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("RECLAIM_EXPLICIT_PREDECESSOR=yes");
    println!("RECLAIM_SEQUENCE={}", replacement.data.sequence);
    println!("RECLAIM_LEASE_EXPIRY={}", replacement.data.lease_expiry);
    println!("RECLAIM_CANONICAL_HEIGHT={}", block.height);
    println!("RECLAIM_CANONICAL_TX_INDEX={}", transaction.tx_index);
    println!("RECLAIM_ACTION_INDEX={action_index}");
    println!(
        "RECLAIM_STATE_COMMITMENT={}",
        hex::encode(replacement.commitment)
    );
    println!(
        "RECLAIM_STATE_FUTURE_NF={}",
        hex::encode(replacement.state_ref.nullifier)
    );
    Ok(())
}

fn verify_reclaim_renew(args: VerifyReclaimRenewArgs) -> Result<()> {
    let params = local_consensus();
    let mut source = source_for(&args.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let renew_txid = parse_txid_hex(&args.renew_txid)?;
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        parse_txid_hex(&args.reveal_txid)?,
        None,
        Some(renew_txid),
        None,
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Active
            && lineage.fresh_status == ResolutionStatus::Active
            && lineage.full_head == lineage.fresh_head
            && lineage.fresh_available,
        "full replay and FreshResolver did not restore the same active renewed head"
    );
    let renewed = lineage.full_head;
    ensure!(
        renewed.data.sequence == 1
            && renewed.data.record.as_slice() == RECLAIM_RECORD.as_slice()
            && renewed.data.lease_expiry == 98
            && renewed.data.status == StateStatus::Active
            && renewed.data.terminal_height == 0,
        "renewed replacement state has unexpected lifecycle fields"
    );
    ensure!(
        lineage.fresh_anchor == Some(renewed.state_ref),
        "FreshResolver did not replace its discovery anchor with the accepted RENEW StateRef"
    );
    let renew_transaction = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == renew_txid)
        .context("canonical replacement RENEW is absent")?;
    let renew_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == renew_txid))
        .context("canonical replacement RENEW block is absent")?;
    ensure!(
        renewed.state_ref.position()
            == ProducerPosition::new(renew_block.height, renew_transaction.tx_index, renew_txid),
        "renewed state does not retain its canonical producer position"
    );
    println!("NAMES_FULL_REPLAY_STATUS=Active");
    println!("NAMES_FRESH_RESOLVER_STATUS=Active");
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("STALE_RENEW_RECOVERY=yes");
    println!("RENEW_CANONICAL_HEIGHT={}", renew_block.height);
    println!("RENEW_SEQUENCE={}", renewed.data.sequence);
    println!("RENEW_LEASE_EXPIRY={}", renewed.data.lease_expiry);
    println!("RENEW_FRESH_ANCHOR_MATCH=yes");
    println!("RENEW_STATE_COMMITMENT={}", hex::encode(renewed.commitment));
    println!(
        "RENEW_STATE_FUTURE_NF={}",
        hex::encode(renewed.state_ref.nullifier)
    );
    Ok(())
}

fn update(args: UpdateArgs) -> Result<()> {
    let params = local_consensus();
    let label = if args.no_submit {
        "FORK_UPDATE"
    } else {
        "UPDATE"
    };
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let renew_txid = args.renew_txid.as_deref().map(parse_txid_hex).transpose()?;
    let update_record = args.record_byte.map_or(UPDATE_RECORD, |byte| [byte; 64]);
    let successor_seed = args.successor_seed.unwrap_or(UPDATE_SUCCESSOR_SEED);
    ensure!(
        !args.no_submit || args.raw_path.is_some(),
        "--no-submit requires --raw-path"
    );
    let mut source = source_for(&args.common.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (transition_prover, transition_verifier, genesis_prover, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_prover = OrchardV2ProofProver::from_parts(transition_prover, genesis_prover);
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        None,
        renew_txid,
        None,
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Active,
        "current Names v2 state is not active: {:?}",
        lineage.full_status
    );
    ensure!(
        lineage.fresh_status == ResolutionStatus::Active,
        "FreshResolver did not find an active current state: {:?}",
        lineage.fresh_status
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree before UPDATE construction"
    );
    let predecessor = lineage.full_head;
    if renew_txid.is_none() {
        ensure!(
            predecessor.data.sequence == 0,
            "qualified UPDATE fixture requires the sequence-zero REVEAL head"
        );
        ensure!(
            predecessor.data.record.as_slice() == RECORD.as_slice(),
            "qualified UPDATE fixture has an unexpected predecessor record"
        );
        let v2 = v2_parameters();
        ensure!(
            predecessor.data.lease_expiry
                == v2
                    .lease_expiry(predecessor.state_ref.producer_height)
                    .context("Names v2 predecessor lease expiry overflow")?,
            "UPDATE predecessor lease does not match its reveal-height schedule"
        );
    }
    ensure!(
        predecessor.data.status == StateStatus::Active && predecessor.data.terminal_height == 0,
        "qualified UPDATE fixture predecessor is not active"
    );
    let construction_height = lineage
        .tip_height
        .checked_add(1)
        .context("live UPDATE construction height overflow")?;
    ensure!(
        lineage.tip_height < predecessor.data.lease_expiry
            && construction_height < predecessor.data.lease_expiry,
        "qualified Names v2 lineage is at or beyond its exclusive lease expiry"
    );

    let usk = wallet_usk(&params)?;
    let names_fvk = FullViewingKey::from(usk.orchard());
    let names_ask = SpendAuthorizingKey::from(usk.orchard());
    let mut db = open_wallet(&args.common.wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_matches = notes
        .iter()
        .enumerate()
        .filter(|(_, (note, _, _, _))| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        predecessor_matches.len() == 1,
        "wallet must contain exactly one unspent note for the accepted Names predecessor (found {})",
        predecessor_matches.len()
    );
    let (predecessor_note, predecessor_scope, predecessor_position, predecessor_value) = notes
        .into_iter()
        .enumerate()
        .find_map(|(index, note)| (index == predecessor_matches[0]).then_some(note))
        .context("wallet predecessor note disappeared during selection")?;
    let predecessor_nf = predecessor_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        predecessor_nf == predecessor.state_ref.nullifier,
        "wallet predecessor nullifier differs from the accepted Names StateRef"
    );

    let mut notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_index = notes
        .iter()
        .position(|(note, _, _, _)| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .context("wallet predecessor note is not available for funding selection")?;
    notes.swap_remove(predecessor_index);
    let funding_index = notes
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, _, _, value))| *value)
        .map(|(index, _)| index)
        .context("live wallet has no separate Ironwood funding note")?;
    let (funding_note, _funding_scope, funding_position, _) = notes.swap_remove(funding_index);
    let funding_nf = funding_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        funding_nf != predecessor_nf,
        "UPDATE funding note must differ from the predecessor note"
    );
    ensure!(
        funding_position != predecessor_position,
        "UPDATE funding position must differ from the predecessor position"
    );

    let preparation = prepare_update(
        TransitionInputs {
            predecessor: predecessor.clone(),
            predecessor_note,
            scope: predecessor_scope,
            fvk: names_fvk.clone(),
            ask: names_ask.clone(),
            operation_height: construction_height,
            designated_action_index: UPDATE_ACTION_INDEX,
            successor_seed: [successor_seed; 32],
        },
        update_record.to_vec(),
    )?;
    let successor_commitment = preparation.statement().successor_commitment;
    let successor_future_nf = preparation.statement().successor_nullifier;
    let names_proof_started = Instant::now();
    let transition_proof = names_prover
        .prove_transition(
            preparation.statement(),
            preparation.witness().clone(),
            OsRng,
        )
        .map_err(|error| anyhow::anyhow!("create Names UPDATE proof: {error:?}"))?;
    let names_proof_elapsed = names_proof_started.elapsed();
    let finalized_operation = preparation.finalize(transition_proof.clone())?;

    let carrier_recipient = names_recipient()?;
    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no synchronized target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(
        &mut db,
        anchor_height,
        [predecessor_position, funding_position],
    )?;
    let planned = plan_qualified_funding(
        &params,
        BlockHeight::from_u32(construction_height),
        &finalized_operation,
        carrier_recipient,
        &names_fvk,
        &funding_note,
    )?;
    let built = build_names_v2_bundle(planned.plan, OsRng)?;
    ensure!(
        built.action_count == planned.planned_shape.action_count,
        "UPDATE built action count differs from fee-planned shape"
    );
    ensure!(
        built.ironwood_value_balance
            == i64::try_from(planned.required_fee.into_u64())
                .context("UPDATE ZIP-317 fee does not fit balance")?,
        "UPDATE built value balance differs from ZIP-317 fee"
    );
    let complete = build_names_v2_pczt(NamesV2PcztPlan {
        ironwood: built,
        params,
        consensus_branch_id: BranchId::Nu6_3,
        expiry_height: BlockHeight::from_u32(construction_height),
        fallback_lock_time: 0,
    })?;
    let finalized = finalize_names_v2_pczt_io(complete)?;
    let witnessed = install_names_v2_ironwood_witnesses(
        finalized,
        NamesV2WitnessPlan {
            anchor,
            spends: vec![
                NamesV2IronwoodWitness {
                    nullifier: predecessor_nf,
                    merkle_path: paths[0].clone(),
                },
                NamesV2IronwoodWitness {
                    nullifier: funding_nf,
                    merkle_path: paths[1].clone(),
                },
            ],
        },
    )?;
    let consensus_proving_key = orchard::circuit::ProvingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let consensus_proof_started = Instant::now();
    let proved = prove_names_v2_ironwood_pczt(witnessed, &consensus_proving_key)?;
    let consensus_proof_elapsed = consensus_proof_started.elapsed();
    let signed = sign_names_v2_ironwood_pczt(
        proved,
        NamesV2SigningPlan {
            spends: vec![
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: predecessor_nf,
                    ask: SpendAuthorizingKey::from(usk.orchard()),
                },
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: funding_nf,
                    ask: SpendAuthorizingKey::from(usk.orchard()),
                },
            ],
        },
    )?;
    let extracted = extract_names_v2_transaction(signed)?;
    ensure!(
        extracted.action_count == planned.planned_shape.action_count
            && extracted.ironwood_value_balance
                == i64::try_from(planned.required_fee.into_u64())
                    .context("UPDATE ZIP-317 fee does not fit balance")?,
        "extracted UPDATE metadata differs from the planned shape or fee"
    );
    let mut raw = Vec::new();
    extracted.transaction.write(&mut raw)?;
    let final_txid: [u8; 32] = extracted.txid.into();
    if let Some(raw_path) = &args.raw_path {
        std::fs::write(raw_path, &raw)
            .with_context(|| format!("write extracted {label} transaction"))?;
    }
    if args.no_submit {
        println!("{label}_SUBMITTED=no");
    } else {
        let submitted_txid = submit_raw(&args.common.rpc_url, &raw)?;
        ensure!(
            submitted_txid == final_txid,
            "node returned a different {label} txid"
        );
        println!("{label}_SUBMITTED=yes");
    }

    println!("{label}_REVEAL_TXID={}", hex::encode(reveal_txid));
    if let Some(renew_txid) = renew_txid {
        println!("{label}_RENEW_TXID={}", hex::encode(renew_txid));
    }
    println!("{label}_CONSTRUCTION_HEIGHT={construction_height}");
    println!("{label}_NAMES_PROOF_BYTES={}", transition_proof.len());
    println!(
        "{label}_NAMES_PROOF_ELAPSED_MS={}",
        names_proof_elapsed.as_millis()
    );
    println!("CNV2_{label}_BYTES={}", finalized_operation.encoded().len());
    println!("CPV1_{label}_FRAMES={}", finalized_operation.frames().len());
    println!("{label}_TXID={}", hex::encode(final_txid));
    println!("{label}_ACTION_INDEX={UPDATE_ACTION_INDEX}");
    println!("{label}_PREDECESSOR_VALUE={predecessor_value}");
    println!("{label}_ACTION_COUNT={}", extracted.action_count);
    println!("{label}_REAL_SPENDS={}", extracted.real_spend_count);
    println!("{label}_CARRIER_OUTPUTS={}", extracted.carrier_output_count);
    println!("{label}_CHANGE_OUTPUTS={}", extracted.change_output_count);
    println!("{label}_VALUE_BALANCE={}", extracted.ironwood_value_balance);
    println!("{label}_ANCHOR_HEIGHT={anchor_height}");
    println!("{label}_ANCHOR={}", hex::encode(anchor.to_bytes()));
    println!("{label}_PREDECESSOR_NF={}", hex::encode(predecessor_nf));
    println!(
        "{label}_SUCCESSOR_CMX={}",
        hex::encode(successor_commitment)
    );
    println!(
        "{label}_SUCCESSOR_FUTURE_NF={}",
        hex::encode(successor_future_nf)
    );
    println!(
        "{label}_CONSENSUS_PROOF_BYTES={}",
        extracted.ironwood_proof_byte_len
    );
    println!(
        "{label}_CONSENSUS_PROOF_ELAPSED_MS={}",
        consensus_proof_elapsed.as_millis()
    );
    println!("{label}_TX_BYTES={}", raw.len());
    if let Some(raw_path) = args.raw_path {
        println!("{label}_RAW_PATH={}", raw_path.display());
    }
    println!("NAMES_APPLICATION_ID={}", hex::encode(app_id));
    println!(
        "RENDEZVOUS_RECEIVER={}",
        hex::encode(REGTEST.rendezvous.orchard_receiver)
    );
    Ok(())
}

/// Builds one ordinary Ironwood spend of the accepted Names state note.  It
/// deliberately publishes no Names carrier: the resulting canonical action
/// is the live out-of-band-spend/abandonment fixture.
fn abandon(args: AbandonArgs) -> Result<()> {
    let params = local_consensus();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let mut source = source_for(&args.common.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        None,
        None,
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Active
            && lineage.fresh_status == ResolutionStatus::Active
            && lineage.full_head == lineage.fresh_head,
        "accepted Names state is not independently active before abandonment"
    );
    let predecessor = lineage.full_head;
    ensure!(
        predecessor.data.status == StateStatus::Active
            && predecessor.data.terminal_height == 0
            && lineage.tip_height < predecessor.data.lease_expiry,
        "out-of-band spend predecessor is not currently payable"
    );
    let usk = wallet_usk(&params)?;
    let names_fvk = FullViewingKey::from(usk.orchard());
    let names_ask = SpendAuthorizingKey::from(usk.orchard());
    let mut db = open_wallet(&args.common.wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_matches = notes
        .iter()
        .enumerate()
        .filter(|(_, (note, _, _, _))| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        predecessor_matches.len() == 1,
        "wallet must contain exactly one unspent accepted state note (found {})",
        predecessor_matches.len()
    );
    let predecessor_index = predecessor_matches[0];
    let (predecessor_note, predecessor_scope, predecessor_position, predecessor_value) = notes
        .iter()
        .enumerate()
        .find_map(|(index, note)| (index == predecessor_index).then_some(*note))
        .context("wallet predecessor note disappeared during selection")?;
    let predecessor_nf = predecessor_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        predecessor_nf == predecessor.state_ref.nullifier,
        "wallet predecessor nullifier differs from accepted state reference"
    );

    let mut funding_notes = notes;
    funding_notes.swap_remove(predecessor_index);
    let funding_index = funding_notes
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, _, _, value))| *value)
        .map(|(index, _)| index)
        .context("live wallet has no separate Ironwood funding note")?;
    let (funding_note, _funding_scope, funding_position, funding_value) =
        funding_notes.swap_remove(funding_index);
    let funding_nf = funding_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        funding_nf != predecessor_nf && funding_position != predecessor_position,
        "out-of-band funding note must be distinct from the state note"
    );

    let predecessor_rho = Option::<Rho>::from(Rho::from_bytes(&predecessor_nf))
        .context("accepted predecessor nullifier is not a valid successor rho")?;
    let successor_rseed =
        Option::<RandomSeed>::from(RandomSeed::from_bytes([10; 32], &predecessor_rho))
            .context("construct deterministic out-of-band successor seed")?;
    let successor_note = Option::<Note>::from(Note::from_parts(
        names_fvk.address_at(0u32, predecessor_scope),
        predecessor_note.value(),
        predecessor_rho,
        successor_rseed,
        NoteVersion::V3,
    ))
    .context("construct out-of-band successor note")?;
    ensure!(
        successor_note.value() == predecessor_note.value()
            && successor_note.value().inner() == predecessor_value,
        "out-of-band successor changed the state bond value"
    );
    let successor_commitment =
        ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes();
    let successor_future_nf = successor_note.nullifier(&names_fvk).to_bytes();
    let carrier_outputs = Vec::new();
    let planned_shape = names_v2_ironwood_shape_from_counts(2, 0, 1, 0)?;
    let required_fee = required_zip317_fee_for_names_v2(
        &params,
        BlockHeight::from_u32(
            lineage
                .tip_height
                .checked_add(1)
                .context("out-of-band spend height overflow")?,
        ),
        planned_shape,
    )?;
    let required_fee_value = required_fee.into_u64();
    let change_value = funding_value
        .checked_sub(required_fee_value)
        .context("funding note cannot cover the out-of-band spend fee")?;
    let plan = NamesV2IronwoodPlan {
        designated_fvk: names_fvk.clone(),
        designated_spend: predecessor_note,
        successor_note,
        successor_ovk: None,
        successor_memo: [0; 512],
        carrier_outputs,
        funding_spends: vec![FundingSpend {
            fvk: names_fvk.clone(),
            note: funding_note,
        }],
        change_outputs: vec![ChangeOutput {
            fvk: names_fvk.clone(),
            ovk: None,
            recipient: names_fvk.address_at(0u32, Scope::Internal),
            value: orchard::value::NoteValue::from_raw(change_value),
            memo: [0; 512],
        }],
        designated_action_index: 0,
    };
    ensure!(
        names_v2_ironwood_shape(&plan)? == planned_shape,
        "out-of-band plan shape changed after fee planning"
    );
    let built = build_names_v2_bundle(plan, OsRng)?;
    ensure!(
        built.action_count == planned_shape.action_count
            && built.ironwood_value_balance
                == i64::try_from(required_fee_value)
                    .context("out-of-band ZIP-317 fee does not fit balance")?,
        "out-of-band bundle shape or fee differs from planning"
    );
    verify_designated_action(
        &built.bundle,
        built.designated_action_index,
        predecessor_nf,
        successor_commitment,
    )?;
    let construction_height = lineage
        .tip_height
        .checked_add(1)
        .context("out-of-band construction height overflow")?;
    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no synchronized target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(
        &mut db,
        anchor_height,
        [predecessor_position, funding_position],
    )?;
    let complete = build_names_v2_pczt(NamesV2PcztPlan {
        ironwood: built,
        params,
        consensus_branch_id: BranchId::Nu6_3,
        expiry_height: BlockHeight::from_u32(construction_height),
        fallback_lock_time: 0,
    })?;
    let finalized = finalize_names_v2_pczt_io(complete)?;
    let witnessed = install_names_v2_ironwood_witnesses(
        finalized,
        NamesV2WitnessPlan {
            anchor,
            spends: vec![
                NamesV2IronwoodWitness {
                    nullifier: predecessor_nf,
                    merkle_path: paths[0].clone(),
                },
                NamesV2IronwoodWitness {
                    nullifier: funding_nf,
                    merkle_path: paths[1].clone(),
                },
            ],
        },
    )?;
    let consensus_proving_key = orchard::circuit::ProvingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let proof_started = Instant::now();
    let proved = prove_names_v2_ironwood_pczt(witnessed, &consensus_proving_key)?;
    let proof_elapsed = proof_started.elapsed();
    let signed = sign_names_v2_ironwood_pczt(
        proved,
        NamesV2SigningPlan {
            spends: vec![
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: predecessor_nf,
                    ask: names_ask,
                },
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: funding_nf,
                    ask: SpendAuthorizingKey::from(usk.orchard()),
                },
            ],
        },
    )?;
    let extracted = extract_names_v2_transaction(signed)?;
    let mut raw = Vec::new();
    extracted.transaction.write(&mut raw)?;
    let txid = submit_raw(&args.common.rpc_url, &raw)?;
    let final_txid: [u8; 32] = extracted.txid.into();
    ensure!(txid == final_txid, "node returned a different ABANDON txid");
    println!("ABANDON_TXID={}", hex::encode(final_txid));
    println!("ABANDON_CONSTRUCTION_HEIGHT={construction_height}");
    println!("ABANDON_PREDECESSOR_VALUE={predecessor_value}");
    println!("ABANDON_PREDECESSOR_NF={}", hex::encode(predecessor_nf));
    println!(
        "ABANDON_SUCCESSOR_CMX={}",
        hex::encode(successor_commitment)
    );
    println!(
        "ABANDON_SUCCESSOR_FUTURE_NF={}",
        hex::encode(successor_future_nf)
    );
    println!("ABANDON_ANCHOR_HEIGHT={anchor_height}");
    println!("ABANDON_ANCHOR={}", hex::encode(anchor.to_bytes()));
    println!("ABANDON_ACTION_COUNT={}", extracted.action_count);
    println!("ABANDON_VALUE_BALANCE={}", extracted.ironwood_value_balance);
    println!(
        "ABANDON_CONSENSUS_PROOF_BYTES={}",
        extracted.ironwood_proof_byte_len
    );
    println!(
        "ABANDON_CONSENSUS_PROOF_ELAPSED_MS={}",
        proof_elapsed.as_millis()
    );
    println!("ABANDON_TX_BYTES={}", raw.len());
    Ok(())
}

fn renew(args: RenewArgs) -> Result<()> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = args
        .update_txid
        .as_deref()
        .map(parse_txid_hex)
        .transpose()?;
    let mut source = source_for(&args.common.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (transition_prover, transition_verifier, genesis_prover, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_prover = OrchardV2ProofProver::from_parts(transition_prover, genesis_prover);
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        update_txid,
        None,
        None,
        &names_verifier,
    )?;
    ensure!(
        matches!(
            lineage.full_status,
            ResolutionStatus::Active | ResolutionStatus::Stale
        ),
        "current Names v2 state is not renewable: {:?}",
        lineage.full_status
    );
    ensure!(
        !lineage.fresh_available || lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree before RENEW construction"
    );
    let predecessor = lineage.full_head;
    ensure!(
        predecessor.data.status == StateStatus::Active && predecessor.data.terminal_height == 0,
        "RENEW predecessor is not an active non-terminal state"
    );

    let predecessor_txid = update_txid.unwrap_or(reveal_txid);
    let predecessor_transaction = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == predecessor_txid)
        .context("canonical RENEW predecessor transaction disappeared")?;
    let predecessor_block = lineage
        .blocks
        .values()
        .find(|block| {
            block
                .transactions
                .iter()
                .any(|tx| tx.txid == predecessor_txid)
        })
        .context("canonical RENEW predecessor block disappeared")?;
    let predecessor_operation_index = predecessor_transaction
        .operations
        .iter()
        .position(|operation| {
            if update_txid.is_some() {
                matches!(operation, V2Operation::Update { .. })
            } else {
                matches!(operation, V2Operation::Reveal { .. })
            }
        })
        .context("canonical RENEW predecessor operation index missing")?;
    let predecessor_action_index = predecessor_transaction.operations[predecessor_operation_index]
        .action_index()
        .context("canonical RENEW predecessor has no designated action")?;
    ensure!(
        predecessor.state_ref.position()
            == ProducerPosition::new(
                predecessor_block.height,
                predecessor_transaction.tx_index,
                predecessor_txid
            )
            && predecessor.state_ref.producer_action_index == predecessor_action_index
            && predecessor.state_ref.producer_operation_index
                == u32::try_from(predecessor_operation_index)
                    .context("RENEW predecessor operation index exceeds u32")?,
        "current Names head is not the exact canonical predecessor successor"
    );

    let construction_height = lineage
        .tip_height
        .checked_add(1)
        .context("live RENEW construction height overflow")?;
    let renew_height =
        coppice_names::v2::schedule::next_anchor_height(lineage.name_id, construction_height, v2)
            .context("no future scheduled Names v2 RENEW height exists")?;
    ensure!(
        coppice_names::v2::schedule::is_anchor_height(lineage.name_id, renew_height, v2),
        "derived RENEW height is not a Names v2 anchor"
    );
    ensure!(
        renew_height == construction_height,
        "RENEW must be constructed at the next scheduled height; current next height is {construction_height}, scheduled height is {renew_height}"
    );
    ensure!(
        renew_height > predecessor.state_ref.producer_height,
        "RENEW must follow the accepted predecessor anchor"
    );
    ensure!(
        renew_height < predecessor.data.lease_expiry,
        "next scheduled RENEW height is at or beyond the predecessor lease expiry"
    );

    let usk = wallet_usk(&params)?;
    let names_fvk = FullViewingKey::from(usk.orchard());
    let names_ask = SpendAuthorizingKey::from(usk.orchard());
    let mut db = open_wallet(&args.common.wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_matches = notes
        .iter()
        .enumerate()
        .filter(|(_, (note, _, _, _))| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        predecessor_matches.len() == 1,
        "wallet must contain exactly one unspent note for the accepted Names predecessor (found {})",
        predecessor_matches.len()
    );
    let (predecessor_note, predecessor_scope, predecessor_position, predecessor_value) = notes
        .into_iter()
        .enumerate()
        .find_map(|(index, note)| (index == predecessor_matches[0]).then_some(note))
        .context("wallet predecessor note disappeared during selection")?;
    let predecessor_nf = predecessor_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        predecessor_nf == predecessor.state_ref.nullifier,
        "wallet predecessor nullifier differs from the accepted Names StateRef"
    );

    let mut notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_index = notes
        .iter()
        .position(|(note, _, _, _)| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .context("wallet predecessor note is not available for funding selection")?;
    notes.swap_remove(predecessor_index);
    let funding_index = notes
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, _, _, value))| *value)
        .map(|(index, _)| index)
        .context("live wallet has no separate Ironwood funding note")?;
    let (funding_note, _funding_scope, funding_position, _) = notes.swap_remove(funding_index);
    let funding_nf = funding_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        funding_nf != predecessor_nf,
        "RENEW funding note must differ from the predecessor note"
    );
    ensure!(
        funding_position != predecessor_position,
        "RENEW funding position must differ from the predecessor position"
    );

    let preparation = prepare_renew(
        TransitionInputs {
            predecessor: predecessor.clone(),
            predecessor_note,
            scope: predecessor_scope,
            fvk: names_fvk.clone(),
            ask: names_ask.clone(),
            operation_height: construction_height,
            designated_action_index: RENEW_ACTION_INDEX,
            successor_seed: [if update_txid.is_some() {
                RENEW_SUCCESSOR_SEED
            } else {
                RENEW_SUCCESSOR_SEED + 3
            }; 32],
        },
        v2,
    )?;
    let successor_commitment = preparation.statement().successor_commitment;
    let successor_future_nf = preparation.statement().successor_nullifier;
    let successor_lease_expiry = preparation.statement().successor_lease_expiry;
    let names_proof_started = Instant::now();
    let transition_proof = names_prover
        .prove_transition(
            preparation.statement(),
            preparation.witness().clone(),
            OsRng,
        )
        .map_err(|error| anyhow::anyhow!("create Names RENEW proof: {error:?}"))?;
    let names_proof_elapsed = names_proof_started.elapsed();
    let finalized_operation = preparation.finalize(transition_proof.clone())?;

    let carrier_recipient = names_recipient()?;
    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no synchronized target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(
        &mut db,
        anchor_height,
        [predecessor_position, funding_position],
    )?;
    let planned = plan_qualified_funding(
        &params,
        BlockHeight::from_u32(construction_height),
        &finalized_operation,
        carrier_recipient,
        &names_fvk,
        &funding_note,
    )?;
    let built = build_names_v2_bundle(planned.plan, OsRng)?;
    ensure!(
        built.action_count == planned.planned_shape.action_count,
        "RENEW built action count differs from fee-planned shape"
    );
    ensure!(
        built.ironwood_value_balance
            == i64::try_from(planned.required_fee.into_u64())
                .context("RENEW ZIP-317 fee does not fit balance")?,
        "RENEW built value balance differs from ZIP-317 fee"
    );
    let complete = build_names_v2_pczt(NamesV2PcztPlan {
        ironwood: built,
        params,
        consensus_branch_id: BranchId::Nu6_3,
        expiry_height: BlockHeight::from_u32(construction_height),
        fallback_lock_time: 0,
    })?;
    let finalized = finalize_names_v2_pczt_io(complete)?;
    let witnessed = install_names_v2_ironwood_witnesses(
        finalized,
        NamesV2WitnessPlan {
            anchor,
            spends: vec![
                NamesV2IronwoodWitness {
                    nullifier: predecessor_nf,
                    merkle_path: paths[0].clone(),
                },
                NamesV2IronwoodWitness {
                    nullifier: funding_nf,
                    merkle_path: paths[1].clone(),
                },
            ],
        },
    )?;
    let consensus_proving_key = orchard::circuit::ProvingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let consensus_proof_started = Instant::now();
    let proved = prove_names_v2_ironwood_pczt(witnessed, &consensus_proving_key)?;
    let consensus_proof_elapsed = consensus_proof_started.elapsed();
    let signed = sign_names_v2_ironwood_pczt(
        proved,
        NamesV2SigningPlan {
            spends: vec![
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: predecessor_nf,
                    ask: names_ask,
                },
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: funding_nf,
                    ask: SpendAuthorizingKey::from(usk.orchard()),
                },
            ],
        },
    )?;
    let extracted = extract_names_v2_transaction(signed)?;
    ensure!(
        extracted.action_count == planned.planned_shape.action_count
            && extracted.ironwood_value_balance
                == i64::try_from(planned.required_fee.into_u64())
                    .context("RENEW ZIP-317 fee does not fit balance")?,
        "extracted RENEW metadata differs from the planned shape or fee"
    );
    let mut raw = Vec::new();
    extracted.transaction.write(&mut raw)?;
    let renew_txid = submit_raw(&args.common.rpc_url, &raw)?;
    let final_txid: [u8; 32] = extracted.txid.into();
    ensure!(
        renew_txid == final_txid,
        "node returned a different RENEW txid"
    );

    println!("RENEW_PREDECESSOR_TXID={}", hex::encode(predecessor_txid));
    println!("RENEW_CURRENT_TIP={}", lineage.tip_height);
    println!("RENEW_SCHEDULED_HEIGHT={renew_height}");
    println!("RENEW_CONSTRUCTION_HEIGHT={construction_height}");
    println!("RENEW_NAMES_PROOF_BYTES={}", transition_proof.len());
    println!(
        "RENEW_NAMES_PROOF_ELAPSED_MS={}",
        names_proof_elapsed.as_millis()
    );
    println!("CNV2_RENEW_BYTES={}", finalized_operation.encoded().len());
    println!("CPV1_RENEW_FRAMES={}", finalized_operation.frames().len());
    println!("RENEW_TXID={}", hex::encode(final_txid));
    println!("RENEW_ACTION_INDEX={RENEW_ACTION_INDEX}");
    println!("RENEW_PREDECESSOR_VALUE={predecessor_value}");
    println!("RENEW_SUCCESSOR_LEASE_EXPIRY={successor_lease_expiry}");
    println!("RENEW_ACTION_COUNT={}", extracted.action_count);
    println!("RENEW_REAL_SPENDS={}", extracted.real_spend_count);
    println!("RENEW_CARRIER_OUTPUTS={}", extracted.carrier_output_count);
    println!("RENEW_CHANGE_OUTPUTS={}", extracted.change_output_count);
    println!("RENEW_VALUE_BALANCE={}", extracted.ironwood_value_balance);
    println!("RENEW_ANCHOR_HEIGHT={anchor_height}");
    println!("RENEW_ANCHOR={}", hex::encode(anchor.to_bytes()));
    println!("RENEW_PREDECESSOR_NF={}", hex::encode(predecessor_nf));
    println!("RENEW_SUCCESSOR_CMX={}", hex::encode(successor_commitment));
    println!(
        "RENEW_SUCCESSOR_FUTURE_NF={}",
        hex::encode(successor_future_nf)
    );
    println!(
        "CONSENSUS_PROOF_BYTES={}",
        extracted.ironwood_proof_byte_len
    );
    println!(
        "CONSENSUS_PROOF_ELAPSED_MS={}",
        consensus_proof_elapsed.as_millis()
    );
    println!("RENEW_TX_BYTES={}", raw.len());
    println!("NAMES_APPLICATION_ID={}", hex::encode(app_id));
    println!(
        "RENDEZVOUS_RECEIVER={}",
        hex::encode(REGTEST.rendezvous.orchard_receiver)
    );
    Ok(())
}

fn release(args: ReleaseArgs) -> Result<()> {
    let params = local_consensus();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let renew_txid = parse_txid_hex(&args.renew_txid)?;
    let mut source = source_for(&args.common.rpc_url)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let (transition_prover, transition_verifier, genesis_prover, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_prover = OrchardV2ProofProver::from_parts(transition_prover, genesis_prover);
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        Some(renew_txid),
        None,
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Active,
        "current Names v2 state is not active: {:?}",
        lineage.full_status
    );
    ensure!(
        lineage.fresh_status == ResolutionStatus::Active,
        "FreshResolver did not find an active current state: {:?}",
        lineage.fresh_status
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree before RELEASE construction"
    );
    let predecessor = lineage.full_head;
    {
        let v2 = v2_parameters();
        ensure!(
            predecessor.data.sequence == 2
                && predecessor.data.record.as_slice() == UPDATE_RECORD.as_slice()
                && predecessor.data.lease_expiry
                    == v2
                        .lease_expiry(predecessor.state_ref.producer_height)
                        .context("Names v2 predecessor lease expiry overflow")?
                && predecessor.data.status == StateStatus::Active
                && predecessor.data.terminal_height == 0,
            "qualified RELEASE fixture does not have the expected active sequence-two predecessor"
        );
    }

    let renew_transaction = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == renew_txid)
        .context("canonical RENEW transaction disappeared before RELEASE construction")?;
    let renew_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == renew_txid))
        .context("canonical RENEW block disappeared before RELEASE construction")?;
    let renew_operation_index = renew_transaction
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Renew { .. }))
        .context("canonical RENEW operation index missing")?;
    let V2Operation::Renew {
        action_index: renew_action_index,
        ..
    } = &renew_transaction.operations[renew_operation_index]
    else {
        bail!("canonical RENEW operation kind mismatch");
    };
    ensure!(
        predecessor.state_ref.position()
            == ProducerPosition::new(renew_block.height, renew_transaction.tx_index, renew_txid,)
            && predecessor.state_ref.producer_action_index == *renew_action_index
            && predecessor.state_ref.producer_operation_index
                == u32::try_from(renew_operation_index)
                    .context("RENEW operation index exceeds u32")?,
        "current Names head is not the exact canonical RENEW successor"
    );

    let construction_height = lineage
        .tip_height
        .checked_add(1)
        .context("live RELEASE construction height overflow")?;
    ensure!(
        lineage.tip_height < predecessor.data.lease_expiry
            && construction_height < predecessor.data.lease_expiry,
        "qualified Names v2 lineage is at or beyond its exclusive lease expiry"
    );
    let release_height = construction_height;

    let usk = wallet_usk(&params)?;
    let names_fvk = FullViewingKey::from(usk.orchard());
    let names_ask = SpendAuthorizingKey::from(usk.orchard());
    let mut db = open_wallet(&args.common.wallet_dir, params)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .context("live wallet has no spending account")?;
    let notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_matches = notes
        .iter()
        .enumerate()
        .filter(|(_, (note, _, _, _))| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        predecessor_matches.len() == 1,
        "wallet must contain exactly one unspent note for the accepted Names predecessor (found {})",
        predecessor_matches.len()
    );
    let (predecessor_note, predecessor_scope, predecessor_position, predecessor_value) = notes
        .into_iter()
        .enumerate()
        .find_map(|(index, note)| (index == predecessor_matches[0]).then_some(note))
        .context("wallet predecessor note disappeared during selection")?;
    let predecessor_nf = predecessor_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        predecessor_nf == predecessor.state_ref.nullifier,
        "wallet predecessor nullifier differs from the accepted Names StateRef"
    );

    let mut notes = selected_notes(&db, lineage.tip_height, account_id)?;
    let predecessor_index = notes
        .iter()
        .position(|(note, _, _, _)| {
            ExtractedNoteCommitment::from(note.commitment()).to_bytes() == predecessor.commitment
        })
        .context("wallet predecessor note is not available for funding selection")?;
    notes.swap_remove(predecessor_index);
    let funding_index = notes
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, _, _, value))| *value)
        .map(|(index, _)| index)
        .context("live wallet has no separate Ironwood funding note")?;
    let (funding_note, _funding_scope, funding_position, _) = notes.swap_remove(funding_index);
    let funding_nf = funding_note.nullifier(&names_fvk).to_bytes();
    ensure!(
        funding_nf != predecessor_nf,
        "RELEASE funding note must differ from the predecessor note"
    );
    ensure!(
        funding_position != predecessor_position,
        "RELEASE funding position must differ from the predecessor position"
    );

    let preparation = prepare_release(TransitionInputs {
        predecessor: predecessor.clone(),
        predecessor_note,
        scope: predecessor_scope,
        fvk: names_fvk.clone(),
        ask: names_ask.clone(),
        operation_height: construction_height,
        designated_action_index: RELEASE_ACTION_INDEX,
        successor_seed: [RELEASE_SUCCESSOR_SEED; 32],
    })?;
    let successor_commitment = preparation.statement().successor_commitment;
    let successor_future_nf = preparation.statement().successor_nullifier;
    let names_proof_started = Instant::now();
    let transition_proof = names_prover
        .prove_transition(
            preparation.statement(),
            preparation.witness().clone(),
            OsRng,
        )
        .map_err(|error| anyhow::anyhow!("create Names RELEASE proof: {error:?}"))?;
    let names_proof_elapsed = names_proof_started.elapsed();
    let finalized_operation = preparation.finalize(transition_proof.clone())?;

    let carrier_recipient = names_recipient()?;
    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no synchronized target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(
        &mut db,
        anchor_height,
        [predecessor_position, funding_position],
    )?;
    let planned = plan_qualified_funding(
        &params,
        BlockHeight::from_u32(construction_height),
        &finalized_operation,
        carrier_recipient,
        &names_fvk,
        &funding_note,
    )?;
    let built = build_names_v2_bundle(planned.plan, OsRng)?;
    ensure!(
        built.action_count == planned.planned_shape.action_count,
        "RELEASE built action count differs from fee-planned shape"
    );
    ensure!(
        built.ironwood_value_balance
            == i64::try_from(planned.required_fee.into_u64())
                .context("RELEASE ZIP-317 fee does not fit balance")?,
        "RELEASE built value balance differs from ZIP-317 fee"
    );
    let complete = build_names_v2_pczt(NamesV2PcztPlan {
        ironwood: built,
        params,
        consensus_branch_id: BranchId::Nu6_3,
        expiry_height: BlockHeight::from_u32(construction_height),
        fallback_lock_time: 0,
    })?;
    let finalized = finalize_names_v2_pczt_io(complete)?;
    let witnessed = install_names_v2_ironwood_witnesses(
        finalized,
        NamesV2WitnessPlan {
            anchor,
            spends: vec![
                NamesV2IronwoodWitness {
                    nullifier: predecessor_nf,
                    merkle_path: paths[0].clone(),
                },
                NamesV2IronwoodWitness {
                    nullifier: funding_nf,
                    merkle_path: paths[1].clone(),
                },
            ],
        },
    )?;
    let consensus_proving_key = orchard::circuit::ProvingKey::build(
        orchard::bundle::BundleVersion::ironwood_v3().circuit_version(),
    );
    let consensus_proof_started = Instant::now();
    let proved = prove_names_v2_ironwood_pczt(witnessed, &consensus_proving_key)?;
    let consensus_proof_elapsed = consensus_proof_started.elapsed();
    let signed = sign_names_v2_ironwood_pczt(
        proved,
        NamesV2SigningPlan {
            spends: vec![
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: predecessor_nf,
                    ask: names_ask,
                },
                zcash_devtool::names_v2_builder::NamesV2IronwoodSigningKey {
                    nullifier: funding_nf,
                    ask: SpendAuthorizingKey::from(usk.orchard()),
                },
            ],
        },
    )?;
    let extracted = extract_names_v2_transaction(signed)?;
    ensure!(
        extracted.action_count == planned.planned_shape.action_count
            && extracted.ironwood_value_balance
                == i64::try_from(planned.required_fee.into_u64())
                    .context("RELEASE ZIP-317 fee does not fit balance")?,
        "extracted RELEASE metadata differs from the planned shape or fee"
    );
    let mut raw = Vec::new();
    extracted.transaction.write(&mut raw)?;
    let release_txid = submit_raw(&args.common.rpc_url, &raw)?;
    let final_txid: [u8; 32] = extracted.txid.into();
    ensure!(
        release_txid == final_txid,
        "node returned a different RELEASE txid"
    );

    println!("RENEW_TXID={}", hex::encode(renew_txid));
    println!("RELEASE_CURRENT_TIP={}", lineage.tip_height);
    println!("RELEASE_CONSTRUCTION_HEIGHT={construction_height}");
    println!("RELEASE_NAMES_PROOF_BYTES={}", transition_proof.len());
    println!(
        "RELEASE_NAMES_PROOF_ELAPSED_MS={}",
        names_proof_elapsed.as_millis()
    );
    println!("CNV2_RELEASE_BYTES={}", finalized_operation.encoded().len());
    println!("CPV1_RELEASE_FRAMES={}", finalized_operation.frames().len());
    println!("RELEASE_TXID={}", hex::encode(final_txid));
    println!("RELEASE_ACTION_INDEX={RELEASE_ACTION_INDEX}");
    println!("RELEASE_PREDECESSOR_VALUE={predecessor_value}");
    println!("RELEASE_SUCCESSOR_SEQUENCE=3");
    println!("RELEASE_SUCCESSOR_LEASE_EXPIRY=59");
    println!("RELEASE_TERMINAL_HEIGHT={release_height}");
    println!("RELEASE_ACTION_COUNT={}", extracted.action_count);
    println!("RELEASE_REAL_SPENDS={}", extracted.real_spend_count);
    println!("RELEASE_CARRIER_OUTPUTS={}", extracted.carrier_output_count);
    println!("RELEASE_CHANGE_OUTPUTS={}", extracted.change_output_count);
    println!("RELEASE_VALUE_BALANCE={}", extracted.ironwood_value_balance);
    println!("RELEASE_ANCHOR_HEIGHT={anchor_height}");
    println!("RELEASE_ANCHOR={}", hex::encode(anchor.to_bytes()));
    println!("RELEASE_PREDECESSOR_NF={}", hex::encode(predecessor_nf));
    println!(
        "RELEASE_SUCCESSOR_CMX={}",
        hex::encode(successor_commitment)
    );
    println!(
        "RELEASE_SUCCESSOR_FUTURE_NF={}",
        hex::encode(successor_future_nf)
    );
    println!(
        "CONSENSUS_PROOF_BYTES={}",
        extracted.ironwood_proof_byte_len
    );
    println!(
        "CONSENSUS_PROOF_ELAPSED_MS={}",
        consensus_proof_elapsed.as_millis()
    );
    println!("RELEASE_TX_BYTES={}", raw.len());
    println!("NAMES_APPLICATION_ID={}", hex::encode(app_id));
    println!(
        "RENDEZVOUS_RECEIVER={}",
        hex::encode(REGTEST.rendezvous.orchard_receiver)
    );
    Ok(())
}

fn verify_release(args: VerifyReleaseArgs) -> Result<()> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let renew_txid = parse_txid_hex(&args.renew_txid)?;
    let release_txid = parse_txid_hex(&args.release_txid)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let mut source = source_for(&args.rpc_url)?;
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        Some(renew_txid),
        Some(release_txid),
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Released,
        "full replay did not leave the name released: {:?}",
        lineage.full_status
    );
    ensure!(
        lineage.fresh_status == ResolutionStatus::Released,
        "FreshResolver did not find a released current state: {:?}",
        lineage.fresh_status
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree after RELEASE"
    );
    ensure!(
        lineage
            .machine
            .resolution_at(lineage.name_id, lineage.tip_height)
            == ResolutionStatus::Released,
        "full replay machine did not classify the terminal state as Released"
    );

    let renew = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == renew_txid)
        .context("canonical RENEW transaction disappeared during RELEASE verification")?;
    let renew_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == renew_txid))
        .context("canonical RENEW block missing during RELEASE verification")?;
    let renew_operation_index = renew
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Renew { .. }))
        .context("canonical RENEW operation index missing")?;
    let V2Operation::Renew {
        state_commitment,
        state_nullifier,
        action_index: renew_action_index,
        ..
    } = &renew.operations[renew_operation_index]
    else {
        bail!("canonical RENEW operation kind mismatch");
    };
    let renew_state_ref = StateRef::new(
        ProducerPosition::new(renew_block.height, renew.tx_index, renew.txid),
        *renew_action_index,
        u32::try_from(renew_operation_index).context("RENEW operation index exceeds u32")?,
        *state_commitment,
        *state_nullifier,
    );
    ensure!(
        lineage.fresh_anchor == Some(renew_state_ref),
        "FreshResolver changed its scheduled anchor to the RELEASE state"
    );

    let release = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == release_txid)
        .context("canonical RELEASE transaction disappeared during verification")?;
    let release_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == release_txid))
        .context("canonical RELEASE block missing")?;
    let release_operation_index = release
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Release { .. }))
        .context("canonical RELEASE operation index missing")?;
    let V2Operation::Release {
        predecessor,
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &release.operations[release_operation_index]
    else {
        bail!("canonical RELEASE operation kind mismatch");
    };
    ensure!(
        *predecessor == renew_state_ref,
        "canonical RELEASE predecessor is not the exact accepted RENEW state"
    );
    let release_action = release
        .action(*action_index)
        .context("canonical RELEASE designated action is absent")?;
    ensure!(
        release_action.nullifier == predecessor.nullifier,
        "canonical RELEASE predecessor NF does not match its designated action"
    );
    ensure!(
        release_action.commitment == *state_commitment,
        "canonical RELEASE successor CMX does not match its designated action"
    );
    ensure!(
        release_block.height == renew_block.height + 1,
        "canonical RELEASE was not mined in the block immediately after RENEW"
    );
    ensure!(
        release_block.height < state.lease_expiry,
        "canonical RELEASE was mined at or beyond its predecessor lease expiry"
    );
    let accepted = &lineage.full_head;
    let expected_position =
        ProducerPosition::new(release_block.height, release.tx_index, release.txid);
    ensure!(
        accepted.state_ref.position() == expected_position
            && accepted.state_ref.producer_action_index == *action_index
            && accepted.state_ref.producer_operation_index
                == u32::try_from(release_operation_index)
                    .context("RELEASE operation index exceeds u32")?
            && accepted.commitment == *state_commitment
            && accepted.state_ref.nullifier == *state_nullifier,
        "accepted RELEASE state reference does not match the canonical transaction"
    );
    ensure!(
        accepted.data.name_id == lineage.name_id
            && accepted.data.owner_pk == state.owner_pk
            && accepted.data.sequence == 3
            && accepted.data.record.as_slice() == UPDATE_RECORD.as_slice()
            && accepted.data.lease_expiry
                == v2
                    .lease_expiry(renew_block.height)
                    .context("canonical RENEW lease expiry overflow")?
            && accepted.data.status == StateStatus::Released
            && accepted.data.terminal_height == release_block.height,
        "accepted RELEASE state values are not the expected terminal successor"
    );
    let claimable_height = v2
        .claimable_from(
            accepted.data.status,
            accepted.data.lease_expiry,
            accepted.data.terminal_height,
        )
        .context("RELEASE claimable height overflow")?;
    ensure!(
        lineage.tip_height < claimable_height
            && lineage
                .machine
                .resolution_at(lineage.name_id, lineage.tip_height)
                == ResolutionStatus::Released,
        "post-RELEASE tip crossed the reuse-delay claimability boundary"
    );
    ensure!(
        lineage.fresh_anchor != Some(accepted.state_ref),
        "FreshResolver incorrectly replaced its anchor with RELEASE"
    );

    println!("ACTIVATION_HEIGHT={}", lineage.activation_height);
    println!(
        "ACTIVATION_PARENT_HASH={}",
        hex::encode(lineage.activation_parent_hash)
    );
    println!("NAMES_FULL_COMMIT_ACCEPTED=yes");
    println!("NAMES_FULL_REVEAL_ACCEPTED=yes");
    println!("NAMES_FULL_UPDATE_ACCEPTED=yes");
    println!("NAMES_FULL_RENEW_ACCEPTED=yes");
    println!("NAMES_FULL_RELEASE_ACCEPTED=yes");
    println!("NAMES_FULL_REPLAY_STATUS={:?}", lineage.full_status);
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", lineage.fresh_status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("RELEASE_CANONICAL_HEIGHT={}", release_block.height);
    println!("RELEASE_CANONICAL_TX_INDEX={}", release.tx_index);
    println!("RELEASE_OPERATION_INDEX={release_operation_index}");
    println!("RELEASE_ACTION_INDEX={action_index}");
    println!("RELEASE_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!("RELEASE_TERMINAL_HEIGHT={}", accepted.data.terminal_height);
    println!("CLAIMABLE_HEIGHT={claimable_height}");
    println!(
        "RELEASE_FRESH_ANCHOR_HEIGHT={}",
        renew_state_ref.producer_height
    );
    println!(
        "RELEASE_FRESH_ANCHOR_TX_INDEX={}",
        renew_state_ref.producer_tx_index
    );
    println!(
        "RELEASE_FRESH_ANCHOR_TXID={}",
        hex::encode(renew_state_ref.producer_txid)
    );
    println!(
        "RELEASE_FRESH_ANCHOR_ACTION_INDEX={}",
        renew_state_ref.producer_action_index
    );
    println!(
        "RELEASE_FRESH_ANCHOR_OPERATION_INDEX={}",
        renew_state_ref.producer_operation_index
    );
    println!("ACCEPTED_NAME_ID={}", hex::encode(accepted.data.name_id));
    println!("ACCEPTED_OWNER_PK={}", hex::encode(accepted.data.owner_pk));
    println!("ACCEPTED_SEQUENCE={}", accepted.data.sequence);
    println!("ACCEPTED_RECORD_BYTES={}", accepted.data.record.len());
    println!("ACCEPTED_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!("ACCEPTED_TERMINAL_HEIGHT={}", accepted.data.terminal_height);
    println!(
        "ACCEPTED_STATE_COMMITMENT={}",
        hex::encode(accepted.commitment)
    );
    println!(
        "ACCEPTED_STATE_FUTURE_NF={}",
        hex::encode(accepted.state_ref.nullifier)
    );
    Ok(())
}

fn verify_release_boundary(args: VerifyReleaseBoundaryArgs) -> Result<()> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let renew_txid = parse_txid_hex(&args.renew_txid)?;
    let release_txid = parse_txid_hex(&args.release_txid)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let mut source = source_for(&args.rpc_url)?;
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        Some(renew_txid),
        Some(release_txid),
        &names_verifier,
    )?;
    let expected_status = match args.expected_status {
        ReleaseBoundaryStatus::Released => ResolutionStatus::Released,
        ReleaseBoundaryStatus::Expired => ResolutionStatus::Expired,
    };
    ensure!(
        lineage.full_status == expected_status,
        "full replay status was {:?}, expected {:?}",
        lineage.full_status,
        expected_status
    );
    ensure!(
        lineage.fresh_status == expected_status,
        "FreshResolver status was {:?}, expected {:?}",
        lineage.fresh_status,
        expected_status
    );
    ensure!(
        lineage.full_status == lineage.fresh_status,
        "full replay and FreshResolver returned different statuses"
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree at the RELEASE boundary"
    );
    ensure!(
        lineage
            .machine
            .resolution_at(lineage.name_id, lineage.tip_height)
            == expected_status,
        "full replay machine status differs from the recorded boundary status"
    );

    let renew = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == renew_txid)
        .context("canonical RENEW transaction disappeared during boundary verification")?;
    let renew_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == renew_txid))
        .context("canonical RENEW block missing during boundary verification")?;
    let renew_operation_index = renew
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Renew { .. }))
        .context("canonical RENEW operation index missing")?;
    let V2Operation::Renew {
        state_commitment: renew_commitment,
        state_nullifier: renew_nullifier,
        action_index: renew_action_index,
        ..
    } = &renew.operations[renew_operation_index]
    else {
        bail!("canonical RENEW operation kind mismatch");
    };
    let renew_state_ref = StateRef::new(
        ProducerPosition::new(renew_block.height, renew.tx_index, renew.txid),
        *renew_action_index,
        u32::try_from(renew_operation_index).context("RENEW operation index exceeds u32")?,
        *renew_commitment,
        *renew_nullifier,
    );

    let release = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == release_txid)
        .context("canonical RELEASE transaction disappeared during boundary verification")?;
    let release_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == release_txid))
        .context("canonical RELEASE block missing during boundary verification")?;
    let release_operation_index = release
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Release { .. }))
        .context("canonical RELEASE operation index missing")?;
    let V2Operation::Release {
        predecessor,
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &release.operations[release_operation_index]
    else {
        bail!("canonical RELEASE operation kind mismatch");
    };
    ensure!(
        *predecessor == renew_state_ref,
        "canonical RELEASE predecessor is not the exact h27 RENEW state"
    );
    let release_action = release
        .action(*action_index)
        .context("canonical RELEASE designated action is absent")?;
    ensure!(
        release_action.nullifier == predecessor.nullifier
            && release_action.commitment == *state_commitment,
        "canonical RELEASE designated action does not match its operation"
    );
    let release_state_ref = StateRef::new(
        ProducerPosition::new(release_block.height, release.tx_index, release.txid),
        *action_index,
        u32::try_from(release_operation_index).context("RELEASE operation index exceeds u32")?,
        *state_commitment,
        *state_nullifier,
    );
    ensure!(
        coppice_names::v2::schedule::is_anchor_height(lineage.name_id, renew_block.height, v2)
            && renew_state_ref.producer_action_index == 4
            && renew_state_ref.producer_operation_index == 0
            && release_block.height == renew_block.height + 1
            && release_state_ref.producer_action_index == 4
            && release_state_ref.producer_operation_index == 0,
        "canonical RELEASE lineage is not a scheduled-RENEW -> next-block RELEASE chain"
    );
    ensure!(
        lineage.fresh_anchor == Some(renew_state_ref),
        "FreshResolver anchor changed away from the h27 RENEW state"
    );
    ensure!(
        lineage.fresh_anchor != Some(release_state_ref),
        "FreshResolver incorrectly used RELEASE as its discovery anchor"
    );

    let accepted = &lineage.full_head;
    ensure!(
        accepted.state_ref == release_state_ref,
        "accepted RELEASE state reference does not match the canonical RELEASE"
    );
    ensure!(
        accepted.data.name_id == lineage.name_id
            && accepted.data.owner_pk == state.owner_pk
            && accepted.data.sequence == 3
            && accepted.data.record.as_slice() == UPDATE_RECORD.as_slice()
            && accepted.data.lease_expiry
                == v2
                    .lease_expiry(renew_block.height)
                    .context("canonical RENEW lease expiry overflow")?
            && accepted.data.status == StateStatus::Released
            && accepted.data.terminal_height == release_block.height
            && accepted.commitment == *state_commitment
            && accepted.state_ref.nullifier == *state_nullifier,
        "terminal RELEASE NameState changed across the claimability boundary"
    );
    let claimable_height = v2
        .claimable_from(
            accepted.data.status,
            accepted.data.lease_expiry,
            accepted.data.terminal_height,
        )
        .context("RELEASE claimable height overflow")?;
    let last_blocked_height = claimable_height
        .checked_sub(1)
        .context("RELEASE claimable height has no preceding blocked height")?;
    let expected_claimable_height = accepted
        .data
        .terminal_height
        .checked_add(v2.reuse_delay_blocks)
        .context("RELEASE claimability height overflow")?;
    ensure!(
        claimable_height == expected_claimable_height,
        "RELEASE claimability boundary changed: terminal {} plus the reuse delay must be {expected_claimable_height}, got {claimable_height}",
        accepted.data.terminal_height
    );
    match expected_status {
        ResolutionStatus::Released => ensure!(
            lineage.tip_height == last_blocked_height
                && lineage.tip_height.checked_add(1) == Some(claimable_height),
            "Released boundary verification must run at h{last_blocked_height}"
        ),
        ResolutionStatus::Expired => ensure!(
            lineage.tip_height == claimable_height,
            "Expired boundary verification must run at h{claimable_height}"
        ),
        _ => unreachable!("boundary verifier only admits Released or Expired"),
    }

    println!("ACTIVATION_HEIGHT={}", lineage.activation_height);
    println!(
        "ACTIVATION_PARENT_HASH={}",
        hex::encode(lineage.activation_parent_hash)
    );
    println!("RELEASE_BOUNDARY_TIP={}", lineage.tip_height);
    println!("RELEASE_CLAIMABLE_HEIGHT={claimable_height}");
    println!("RELEASE_LAST_BLOCKED_HEIGHT={last_blocked_height}");
    println!("NAMES_FULL_COMMIT_ACCEPTED=yes");
    println!("NAMES_FULL_REVEAL_ACCEPTED=yes");
    println!("NAMES_FULL_UPDATE_ACCEPTED=yes");
    println!("NAMES_FULL_RENEW_ACCEPTED=yes");
    println!("NAMES_FULL_RELEASE_ACCEPTED=yes");
    println!("NAMES_FULL_REPLAY_STATUS={:?}", lineage.full_status);
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", lineage.fresh_status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("RELEASE_STATE_UNCHANGED=yes");
    println!("RELEASE_FRESH_ANCHOR_UNCHANGED=yes");
    println!("RELEASE_CANONICAL_HEIGHT={}", release_block.height);
    println!("RELEASE_CANONICAL_TX_INDEX={}", release.tx_index);
    println!("RELEASE_OPERATION_INDEX={release_operation_index}");
    println!("RELEASE_ACTION_INDEX={action_index}");
    println!("RELEASE_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!("RELEASE_TERMINAL_HEIGHT={}", accepted.data.terminal_height);
    println!(
        "RELEASE_FRESH_ANCHOR_HEIGHT={}",
        renew_state_ref.producer_height
    );
    println!(
        "RELEASE_FRESH_ANCHOR_TX_INDEX={}",
        renew_state_ref.producer_tx_index
    );
    println!(
        "RELEASE_FRESH_ANCHOR_TXID={}",
        hex::encode(renew_state_ref.producer_txid)
    );
    println!(
        "RELEASE_FRESH_ANCHOR_ACTION_INDEX={}",
        renew_state_ref.producer_action_index
    );
    println!(
        "RELEASE_FRESH_ANCHOR_OPERATION_INDEX={}",
        renew_state_ref.producer_operation_index
    );
    println!("ACCEPTED_NAME_ID={}", hex::encode(accepted.data.name_id));
    println!("ACCEPTED_OWNER_PK={}", hex::encode(accepted.data.owner_pk));
    println!("ACCEPTED_SEQUENCE={}", accepted.data.sequence);
    println!("ACCEPTED_RECORD_BYTES={}", accepted.data.record.len());
    println!("ACCEPTED_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!("ACCEPTED_TERMINAL_HEIGHT={}", accepted.data.terminal_height);
    println!(
        "ACCEPTED_STATE_COMMITMENT={}",
        hex::encode(accepted.commitment)
    );
    println!(
        "ACCEPTED_STATE_FUTURE_NF={}",
        hex::encode(accepted.state_ref.nullifier)
    );
    Ok(())
}

fn verify_update(args: VerifyUpdateArgs) -> Result<()> {
    let params = local_consensus();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let renew_txid = args.renew_txid.as_deref().map(parse_txid_hex).transpose()?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let expected_record = args.record_byte.map_or(UPDATE_RECORD, |byte| [byte; 64]);
    let expected_sequence = if renew_txid.is_some() { 2 } else { 1 };
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let mut source = source_for(&args.rpc_url)?;
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        renew_txid,
        None,
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Active,
        "full replay did not leave the name active: {:?}",
        lineage.full_status
    );
    ensure!(
        lineage.fresh_status == ResolutionStatus::Active,
        "FreshResolver did not leave the name active: {:?}",
        lineage.fresh_status
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree after UPDATE"
    );
    ensure!(
        lineage
            .machine
            .resolution_at(lineage.name_id, lineage.tip_height)
            == lineage.full_status,
        "full replay machine status does not match its recorded final status"
    );
    let update = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == update_txid)
        .context("canonical UPDATE transaction disappeared during verification")?;
    let update_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == update_txid))
        .context("canonical UPDATE block missing")?;
    let update_operation_index = update
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Update { .. }))
        .context("canonical UPDATE operation index missing")?;
    let V2Operation::Update {
        predecessor,
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &update.operations[update_operation_index]
    else {
        bail!("canonical UPDATE operation kind mismatch");
    };
    let update_action = update
        .action(*action_index)
        .context("canonical UPDATE designated action is absent")?;
    ensure!(
        update_action.nullifier == predecessor.nullifier,
        "canonical UPDATE predecessor NF does not match its designated action"
    );
    ensure!(
        update_action.commitment == *state_commitment,
        "canonical UPDATE successor CMX does not match its designated action"
    );
    let expected_position =
        ProducerPosition::new(update_block.height, update.tx_index, update.txid);
    let accepted = &lineage.full_head;
    ensure!(
        accepted.state_ref.position() == expected_position
            && accepted.state_ref.producer_action_index == *action_index
            && accepted.state_ref.producer_operation_index
                == u32::try_from(update_operation_index)
                    .context("UPDATE operation index exceeds u32")?
            && accepted.commitment == *state_commitment
            && accepted.state_ref.nullifier == *state_nullifier,
        "accepted UPDATE state reference does not match the canonical transaction"
    );
    ensure!(
        accepted.data.name_id == lineage.name_id
            && accepted.data.owner_pk == state.owner_pk
            && accepted.data.sequence == expected_sequence
            && accepted.data.record.as_slice() == expected_record.as_slice()
            && accepted.data.status == StateStatus::Active
            && accepted.data.terminal_height == 0,
        "accepted UPDATE state values are not the expected successor"
    );
    println!("ACTIVATION_HEIGHT={}", lineage.activation_height);
    println!(
        "ACTIVATION_PARENT_HASH={}",
        hex::encode(lineage.activation_parent_hash)
    );
    println!("NAMES_FULL_COMMIT_ACCEPTED=yes");
    println!("NAMES_FULL_REVEAL_ACCEPTED=yes");
    println!("NAMES_FULL_UPDATE_ACCEPTED=yes");
    println!("NAMES_FULL_REPLAY_STATUS={:?}", lineage.full_status);
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", lineage.fresh_status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("UPDATE_CANONICAL_HEIGHT={}", update_block.height);
    println!("UPDATE_CANONICAL_TX_INDEX={}", update.tx_index);
    println!("UPDATE_OPERATION_INDEX={update_operation_index}");
    println!("UPDATE_ACTION_INDEX={action_index}");
    println!("ACCEPTED_NAME_ID={}", hex::encode(accepted.data.name_id));
    println!("ACCEPTED_OWNER_PK={}", hex::encode(accepted.data.owner_pk));
    println!("ACCEPTED_SEQUENCE={}", accepted.data.sequence);
    println!("ACCEPTED_RECORD_BYTES={}", accepted.data.record.len());
    println!("ACCEPTED_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!(
        "ACCEPTED_STATE_COMMITMENT={}",
        hex::encode(accepted.commitment)
    );
    println!(
        "ACCEPTED_STATE_FUTURE_NF={}",
        hex::encode(accepted.state_ref.nullifier)
    );
    Ok(())
}

fn verify_abandon(args: VerifyAbandonArgs) -> Result<()> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let abandon_txid = parse_txid_hex(&args.abandon_txid)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let mut source = source_for(&args.rpc_url)?;
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        None,
        None,
        &names_verifier,
    )?;
    let expected_status = match args.expected_status {
        AbandonResolution::Abandoned => ResolutionStatus::Abandoned,
        AbandonResolution::Expired => ResolutionStatus::Expired,
    };
    ensure!(
        lineage.full_status == expected_status && lineage.fresh_status == expected_status,
        "out-of-band spend resolution mismatch: full={:?}, fresh={:?}, expected={expected_status:?}",
        lineage.full_status,
        lineage.fresh_status
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree after out-of-band spend"
    );
    ensure!(
        lineage
            .machine
            .resolution_at(lineage.name_id, lineage.tip_height)
            == expected_status,
        "full replay machine status does not match its recorded abandonment status"
    );
    let abandon = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == abandon_txid)
        .context("canonical out-of-band spend disappeared during verification")?;
    ensure!(
        abandon.operations.is_empty(),
        "out-of-band abandonment transaction unexpectedly carries a Names operation"
    );
    let matching_actions = abandon
        .actions
        .iter()
        .filter(|action| action.nullifier == lineage.full_head.state_ref.nullifier)
        .count();
    ensure!(
        matching_actions == 1,
        "out-of-band spend must expose the accepted future nullifier exactly once"
    );
    let abandon_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == abandon_txid))
        .context("canonical out-of-band spend block missing")?;
    let abandoned_height = lineage
        .full_head
        .abandoned_height
        .context("full replay did not record the out-of-band spend height")?;
    ensure!(
        abandoned_height == abandon_block.height,
        "abandonment height does not match the canonical spend block"
    );
    let update = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == update_txid)
        .context("canonical UPDATE disappeared during abandonment verification")?;
    let update_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == update_txid))
        .context("canonical UPDATE block missing during abandonment verification")?;
    let update_operation_index = update
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Update { .. }))
        .context("canonical UPDATE operation index missing during abandonment verification")?;
    let V2Operation::Update {
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &update.operations[update_operation_index]
    else {
        bail!("canonical UPDATE operation kind mismatch during abandonment verification");
    };
    let expected_update_ref = StateRef::new(
        ProducerPosition::new(update_block.height, update.tx_index, update.txid),
        *action_index,
        u32::try_from(update_operation_index).context("UPDATE operation index exceeds u32")?,
        *state_commitment,
        *state_nullifier,
    );
    let accepted = &lineage.full_head;
    ensure!(
        accepted.state_ref == expected_update_ref
            && accepted.data.name_id == lineage.name_id
            && accepted.data.owner_pk == state.owner_pk
            && accepted.data.sequence == 1
            && accepted.data.record.as_slice() == [args.record_byte; 64].as_slice()
            && accepted.data.status == StateStatus::Active
            && accepted.data.terminal_height == 0,
        "accepted state changed unexpectedly when its note was spent"
    );
    let claimable_height = v2
        .head_claimable_from(&accepted.data, Some(abandoned_height))
        .context("abandonment claimability height overflow")?;
    match args.expected_status {
        AbandonResolution::Abandoned => ensure!(
            lineage.tip_height < claimable_height,
            "Abandoned verification must run before claimability"
        ),
        AbandonResolution::Expired => ensure!(
            lineage.tip_height == claimable_height,
            "Expired verification must run at the exact abandonment claimability height"
        ),
    }
    let reveal = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == reveal_txid)
        .context("canonical REVEAL missing during abandonment verification")?;
    let reveal_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == reveal_txid))
        .context("canonical REVEAL block missing during abandonment verification")?;
    let V2Operation::Reveal {
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &reveal.operations[0]
    else {
        bail!("canonical REVEAL operation mismatch during abandonment verification");
    };
    let reveal_ref = StateRef::new(
        ProducerPosition::new(reveal_block.height, reveal.tx_index, reveal.txid),
        *action_index,
        0,
        *state_commitment,
        *state_nullifier,
    );
    ensure!(
        lineage.fresh_anchor == Some(reveal_ref),
        "FreshResolver discovery anchor changed after an out-of-band spend"
    );

    println!("NAMES_FULL_COMMIT_ACCEPTED=yes");
    println!("NAMES_FULL_REVEAL_ACCEPTED=yes");
    println!("NAMES_FULL_UPDATE_ACCEPTED=yes");
    println!("NAMES_FULL_REPLAY_STATUS={:?}", lineage.full_status);
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", lineage.fresh_status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("ABANDON_TXID={}", hex::encode(abandon_txid));
    println!("ABANDON_CANONICAL_HEIGHT={}", abandon_block.height);
    println!("ABANDON_CLAIMABLE_HEIGHT={claimable_height}");
    println!("ABANDONED_HEIGHT={abandoned_height}");
    println!("ABANDON_STATE_UNCHANGED=yes");
    println!("ABANDON_FRESH_ANCHOR_UNCHANGED=yes");
    println!("ABANDON_FRESH_ANCHOR_HEIGHT={}", reveal_ref.producer_height);
    println!(
        "ABANDON_FRESH_ANCHOR_TX_INDEX={}",
        reveal_ref.producer_tx_index
    );
    println!(
        "ABANDON_FRESH_ANCHOR_TXID={}",
        hex::encode(reveal_ref.producer_txid)
    );
    println!(
        "ABANDON_FRESH_ANCHOR_ACTION_INDEX={}",
        reveal_ref.producer_action_index
    );
    println!(
        "ABANDON_FRESH_ANCHOR_OPERATION_INDEX={}",
        reveal_ref.producer_operation_index
    );
    println!("ACCEPTED_SEQUENCE={}", accepted.data.sequence);
    println!("ACCEPTED_RECORD_BYTES={}", accepted.data.record.len());
    println!("ACCEPTED_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!(
        "ACCEPTED_STATE_COMMITMENT={}",
        hex::encode(accepted.commitment)
    );
    println!(
        "ACCEPTED_STATE_FUTURE_NF={}",
        hex::encode(accepted.state_ref.nullifier)
    );
    Ok(())
}

fn verify_renew(args: VerifyRenewArgs) -> Result<()> {
    let params = local_consensus();
    let v2 = v2_parameters();
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let update_txid = parse_txid_hex(&args.update_txid)?;
    let renew_txid = parse_txid_hex(&args.renew_txid)?;
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let mut source = source_for(&args.rpc_url)?;
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let names_verifier = OrchardV2ProofVerifier::from_parts(transition_verifier, genesis_verifier);
    let lineage = replay_names_lineage(
        &mut source,
        &params,
        &rendezvous,
        app_id,
        reveal_txid,
        Some(update_txid),
        Some(renew_txid),
        None,
        &names_verifier,
    )?;
    ensure!(
        lineage.full_status == ResolutionStatus::Active,
        "full replay did not leave the name active after RENEW: {:?}",
        lineage.full_status
    );
    ensure!(
        lineage.fresh_status == ResolutionStatus::Active,
        "FreshResolver did not leave the name active after RENEW: {:?}",
        lineage.fresh_status
    );
    ensure!(
        lineage.full_head == lineage.fresh_head,
        "full replay and FreshResolver disagree after RENEW"
    );
    ensure!(
        lineage
            .machine
            .resolution_at(lineage.name_id, lineage.tip_height)
            == lineage.full_status,
        "full replay machine status does not match its recorded final status"
    );
    let update_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == update_txid))
        .context("canonical UPDATE block missing during RENEW verification")?;
    let renew = lineage
        .blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == renew_txid)
        .context("canonical RENEW transaction disappeared during verification")?;
    let renew_block = lineage
        .blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == renew_txid))
        .context("canonical RENEW block missing")?;
    let renew_operation_index = renew
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Renew { .. }))
        .context("canonical RENEW operation index missing")?;
    let V2Operation::Renew {
        predecessor,
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = &renew.operations[renew_operation_index]
    else {
        bail!("canonical RENEW operation kind mismatch");
    };
    let renew_action = renew
        .action(*action_index)
        .context("canonical RENEW designated action is absent")?;
    ensure!(
        renew_action.nullifier == predecessor.nullifier,
        "canonical RENEW predecessor NF does not match its designated action"
    );
    ensure!(
        renew_action.commitment == *state_commitment,
        "canonical RENEW successor CMX does not match its designated action"
    );
    let expected_renew_height = coppice_names::v2::schedule::next_anchor_height(
        lineage.name_id,
        update_block
            .height
            .checked_add(1)
            .context("RENEW schedule height overflow")?,
        v2,
    )
    .context("no scheduled RENEW height follows the accepted UPDATE")?;
    ensure!(
        renew_block.height == expected_renew_height
            && coppice_names::v2::schedule::is_anchor_height(
                lineage.name_id,
                renew_block.height,
                v2,
            ),
        "canonical RENEW was not mined at the next scheduled anchor height"
    );
    let expected_lease_expiry = v2
        .lease_expiry(renew_block.height)
        .context("canonical RENEW lease expiry overflow")?;
    let expected_position = ProducerPosition::new(renew_block.height, renew.tx_index, renew.txid);
    let accepted = &lineage.full_head;
    ensure!(
        accepted.state_ref.position() == expected_position
            && accepted.state_ref.producer_action_index == *action_index
            && accepted.state_ref.producer_operation_index
                == u32::try_from(renew_operation_index)
                    .context("RENEW operation index exceeds u32")?
            && accepted.commitment == *state_commitment
            && accepted.state_ref.nullifier == *state_nullifier,
        "accepted RENEW state reference does not match the canonical transaction"
    );
    ensure!(
        accepted.data.name_id == lineage.name_id
            && accepted.data.owner_pk == state.owner_pk
            && accepted.data.sequence == 2
            && accepted.data.record.as_slice() == UPDATE_RECORD.as_slice()
            && accepted.data.lease_expiry == expected_lease_expiry
            && accepted.data.lease_expiry > 55
            && accepted.data.status == StateStatus::Active
            && accepted.data.terminal_height == 0,
        "accepted RENEW state values are not the expected sequence-two successor"
    );
    ensure!(
        lineage.fresh_anchor == Some(accepted.state_ref),
        "FreshResolver did not identify the accepted RENEW state as its latest anchor"
    );
    println!("ACTIVATION_HEIGHT={}", lineage.activation_height);
    println!(
        "ACTIVATION_PARENT_HASH={}",
        hex::encode(lineage.activation_parent_hash)
    );
    println!("NAMES_FULL_COMMIT_ACCEPTED=yes");
    println!("NAMES_FULL_REVEAL_ACCEPTED=yes");
    println!("NAMES_FULL_UPDATE_ACCEPTED=yes");
    println!("NAMES_FULL_RENEW_ACCEPTED=yes");
    println!("NAMES_FULL_REPLAY_STATUS={:?}", lineage.full_status);
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", lineage.fresh_status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("RENEW_SCHEDULED_HEIGHT={expected_renew_height}");
    println!("RENEW_CANONICAL_HEIGHT={}", renew_block.height);
    println!("RENEW_CANONICAL_TX_INDEX={}", renew.tx_index);
    println!("RENEW_OPERATION_INDEX={renew_operation_index}");
    println!("RENEW_ACTION_INDEX={action_index}");
    println!("RENEW_LEASE_EXPIRY={expected_lease_expiry}");
    println!(
        "RENEW_FRESH_ANCHOR_HEIGHT={}",
        accepted.state_ref.producer_height
    );
    println!(
        "RENEW_FRESH_ANCHOR_TX_INDEX={}",
        accepted.state_ref.producer_tx_index
    );
    println!(
        "RENEW_FRESH_ANCHOR_TXID={}",
        hex::encode(accepted.state_ref.producer_txid)
    );
    println!(
        "RENEW_FRESH_ANCHOR_ACTION_INDEX={}",
        accepted.state_ref.producer_action_index
    );
    println!(
        "RENEW_FRESH_ANCHOR_OPERATION_INDEX={}",
        accepted.state_ref.producer_operation_index
    );
    println!("ACCEPTED_NAME_ID={}", hex::encode(accepted.data.name_id));
    println!("ACCEPTED_OWNER_PK={}", hex::encode(accepted.data.owner_pk));
    println!("ACCEPTED_SEQUENCE={}", accepted.data.sequence);
    println!("ACCEPTED_RECORD_BYTES={}", accepted.data.record.len());
    println!("ACCEPTED_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!(
        "ACCEPTED_STATE_COMMITMENT={}",
        hex::encode(accepted.commitment)
    );
    println!(
        "ACCEPTED_STATE_FUTURE_NF={}",
        hex::encode(accepted.state_ref.nullifier)
    );
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let params = local_consensus();
    let app_id = names_application_id().to_bytes();
    let rendezvous = CoreRendezvous::try_new(
        &REGTEST.rendezvous.orchard_ivk,
        &REGTEST.rendezvous.orchard_receiver,
    )
    .map_err(|error| anyhow::anyhow!("construct Names rendezvous decoder: {error:?}"))?;
    let mut source = source_for(&args.rpc_url)?;
    let blocks = canonical_chain(&mut source, &params, &rendezvous, app_id)?;
    let commit_txid = parse_txid_hex(&args.commit_txid)?;
    let reveal_txid = parse_txid_hex(&args.reveal_txid)?;
    let commit = blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == commit_txid)
        .context("canonical COMMIT transaction is absent from replay source")?;
    let reveal = blocks
        .values()
        .flat_map(|block| block.transactions.iter())
        .find(|transaction| transaction.txid == reveal_txid)
        .context("canonical REVEAL transaction is absent from replay source")?;
    ensure!(
        commit.operations.len() == 1,
        "canonical COMMIT does not expose exactly one operation"
    );
    ensure!(
        matches!(commit.operations[0], V2Operation::Commit { .. }),
        "canonical COMMIT operation kind mismatch"
    );
    ensure!(
        reveal.operations.len() == 1,
        "canonical REVEAL does not expose exactly one operation"
    );
    let reveal_operation = &reveal.operations[0];
    let V2Operation::Reveal {
        intent,
        commit: commit_ref,
        replacement_predecessor,
        state,
        state_commitment,
        state_nullifier,
        action_index,
        ..
    } = reveal_operation
    else {
        bail!("canonical REVEAL operation kind mismatch");
    };
    let commit_block = blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == commit_txid))
        .context("COMMIT block missing")?;
    let reveal_block = blocks
        .values()
        .find(|block| block.transactions.iter().any(|tx| tx.txid == reveal_txid))
        .context("REVEAL block missing")?;
    let canonical_commit = commit
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Commit { .. }))
        .context("canonical COMMIT operation index missing")
        .and_then(|index| {
            u32::try_from(index).context("canonical COMMIT operation index exceeds u32")
        })?;
    ensure!(
        commit_ref.position.height == commit_block.height,
        "REVEAL CommitRef height mismatch"
    );
    ensure!(
        replacement_predecessor.is_none(),
        "canonical reset REVEAL unexpectedly carries a replacement predecessor"
    );
    ensure!(
        commit_ref.position.tx_index == commit.tx_index,
        "REVEAL CommitRef transaction index mismatch"
    );
    ensure!(
        commit_ref.position.txid == commit_txid,
        "REVEAL CommitRef transaction id mismatch"
    );
    ensure!(
        commit_ref.operation_index == canonical_commit,
        "REVEAL CommitRef operation index mismatch"
    );
    let commit_operation = &commit.operations[canonical_commit as usize];
    let V2Operation::Commit { commitment } = commit_operation else {
        bail!("canonical COMMIT operation changed kind");
    };
    ensure!(
        *commitment == commit_ref.commitment,
        "REVEAL CommitRef commitment mismatch"
    );
    let reveal_action = reveal
        .action(*action_index)
        .context("canonical REVEAL designated action is absent")?;
    ensure!(
        reveal_action.commitment == *state_commitment,
        "canonical REVEAL designated CMX mismatch"
    );
    ensure!(
        commit_txid != reveal_txid,
        "COMMIT and REVEAL txids must differ"
    );
    let v2 = v2_parameters();
    let intent_name_id = intent
        .name_id()
        .map_err(|error| anyhow::anyhow!("derive replay intent name id: {error:?}"))?;
    let reveal_operation_index = reveal
        .operations
        .iter()
        .position(|operation| matches!(operation, V2Operation::Reveal { .. }))
        .context("canonical REVEAL operation index missing")
        .and_then(|index| {
            u32::try_from(index).context("canonical REVEAL operation index exceeds u32")
        })?;
    let activation_height = v2.activation_height;
    let canonical_tip_height = blocks
        .keys()
        .next_back()
        .copied()
        .context("canonical replay source contains no blocks")?;
    let activation_block = blocks
        .get(&activation_height)
        .context("canonical replay source is missing the v2 activation block")?;
    // The parent is taken from the canonical activation block itself. The
    // state machine still authenticates this value against the first block
    // and every subsequent predecessor in apply_block.
    let activation_parent_hash = activation_block.prev_block_hash;
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let verifier = coppice_names::v2::transition::OrchardV2ProofVerifier::from_parts(
        transition_verifier,
        genesis_verifier,
    );
    let mut machine = V2StateMachine::from_activation_parent(v2, activation_parent_hash)
        .map_err(|error| anyhow::anyhow!("construct Names v2 full replay machine: {error:?}"))?;
    let mut commit_full_replay_seen = false;
    let mut reveal_full_replay_seen = false;
    for height in activation_height..=canonical_tip_height {
        let block = blocks
            .get(&height)
            .context("canonical replay source is missing a sequential block")?;
        let applied = machine.apply_block(block, &verifier).map_err(|error| {
            anyhow::anyhow!("Names v2 full replay failed at h{height}: {error:?}")
        })?;
        for transaction in &block.transactions {
            if transaction.txid == commit_txid {
                ensure!(
                    !commit_full_replay_seen,
                    "canonical COMMIT was processed more than once by full replay"
                );
                let operation_index = transaction
                    .operations
                    .iter()
                    .position(|operation| matches!(operation, V2Operation::Commit { .. }))
                    .context("full replay COMMIT operation index missing")
                    .and_then(|index| {
                        u32::try_from(index)
                            .context("full replay COMMIT operation index exceeds u32")
                    })?;
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index
                            && operation.operation_index == operation_index
                    })
                    .context("full replay did not return the canonical COMMIT result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(None) => {}
                    AppliedOperationResult::Accepted(other) => {
                        bail!("full replay COMMIT result was not Accepted(None): {other:?}")
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay COMMIT was rejected: {error:?}")
                    }
                }
                commit_full_replay_seen = true;
            } else if transaction.txid == reveal_txid {
                ensure!(
                    !reveal_full_replay_seen,
                    "canonical REVEAL was processed more than once by full replay"
                );
                let outcome = applied
                    .operations
                    .iter()
                    .find(|operation| {
                        operation.tx_index == transaction.tx_index
                            && operation.operation_index == reveal_operation_index
                    })
                    .context("full replay did not return the canonical REVEAL result")?;
                match &outcome.result {
                    AppliedOperationResult::Accepted(Some((accepted_name_id, kind))) => {
                        ensure!(
                            *accepted_name_id == intent_name_id,
                            "full replay REVEAL accepted the wrong name id"
                        );
                        ensure!(
                            *kind == AppliedOperationKind::Reveal,
                            "full replay REVEAL returned the wrong operation kind"
                        );
                    }
                    AppliedOperationResult::Accepted(other) => {
                        bail!("full replay REVEAL result was not Accepted(name, Reveal): {other:?}")
                    }
                    AppliedOperationResult::Rejected(error) => {
                        bail!("full replay REVEAL was rejected: {error:?}")
                    }
                }
                reveal_full_replay_seen = true;
            }
        }
    }
    ensure!(
        commit_full_replay_seen,
        "full replay did not process the canonical COMMIT"
    );
    ensure!(
        reveal_full_replay_seen,
        "full replay did not process the canonical REVEAL"
    );
    let full_status = machine.resolution_at(intent_name_id, canonical_tip_height);
    ensure!(
        full_status == ResolutionStatus::Active,
        "full Names v2 replay did not accept an active registration: {full_status:?}"
    );
    let full_head = machine
        .head(intent_name_id)
        .context("full Names v2 replay returned no accepted state")?;

    let resolver = FreshResolver::new(v2)
        .map_err(|error| anyhow::anyhow!("construct Names v2 fresh resolver: {error:?}"))?;
    let result = resolver
        .resolve(NAME, &blocks, &verifier)
        .map_err(|error| anyhow::anyhow!("Names v2 canonical replay failed: {error:?}"))?;
    ensure!(
        result.status == ResolutionStatus::Active,
        "Names v2 replay did not accept an active registration: {:?}",
        result.status
    );
    let accepted = result
        .state
        .context("Names v2 replay returned no accepted state")?;
    ensure!(
        accepted.data.name_id == intent_name_id,
        "accepted state name id mismatch"
    );
    ensure!(
        accepted.data.owner_pk == intent.owner_pk,
        "accepted state owner mismatch"
    );
    ensure!(
        accepted.data.sequence == 0,
        "accepted state sequence mismatch"
    );
    ensure!(
        accepted.data.record == state.record,
        "accepted state record mismatch"
    );
    ensure!(
        accepted.data.status == StateStatus::Active,
        "accepted state status mismatch"
    );
    ensure!(
        accepted.data.lease_expiry == state.lease_expiry,
        "accepted state lease expiry mismatch"
    );
    ensure!(
        accepted.commitment == *state_commitment,
        "accepted state commitment mismatch"
    );
    ensure!(
        accepted.state_ref.nullifier == *state_nullifier,
        "accepted state future nullifier mismatch"
    );
    ensure!(
        accepted.state_ref.position()
            == ProducerPosition::new(reveal_block.height, reveal.tx_index, reveal.txid),
        "accepted state producer position mismatch"
    );
    ensure!(
        accepted.state_ref.producer_action_index == *action_index,
        "accepted state action index mismatch"
    );
    ensure!(
        accepted.state_ref.producer_operation_index == 0,
        "accepted state operation index mismatch"
    );
    ensure!(
        full_head == &accepted,
        "full replay and FreshResolver returned different NameState values"
    );
    ensure!(
        machine.resolution_at(intent_name_id, canonical_tip_height) == result.status,
        "full replay and FreshResolver returned different resolution statuses"
    );
    println!("ACTIVATION_HEIGHT={activation_height}");
    println!(
        "ACTIVATION_PARENT_HASH={}",
        hex::encode(activation_parent_hash)
    );
    println!("NAMES_FULL_COMMIT_ACCEPTED=yes");
    println!("NAMES_FULL_REVEAL_ACCEPTED=yes");
    println!("NAMES_FULL_REPLAY_STATUS={full_status:?}");
    println!("NAMES_FRESH_RESOLVER_STATUS={:?}", result.status);
    println!("NAMES_FULL_FRESH_MATCH=yes");
    println!("COMMIT_CANONICAL_HEIGHT={}", commit_block.height);
    println!("COMMIT_CANONICAL_TX_INDEX={}", commit.tx_index);
    println!("COMMIT_OPERATION_INDEX={canonical_commit}");
    println!("REVEAL_CANONICAL_HEIGHT={}", reveal_block.height);
    println!("REVEAL_CANONICAL_TX_INDEX={}", reveal.tx_index);
    println!("REVEAL_ACTION_INDEX={action_index}");
    println!("REPLACEMENT_PREDECESSOR=none");
    println!("ACCEPTED_NAME_ID={}", hex::encode(accepted.data.name_id));
    println!("ACCEPTED_OWNER_PK={}", hex::encode(accepted.data.owner_pk));
    println!("ACCEPTED_SEQUENCE={}", accepted.data.sequence);
    println!("ACCEPTED_RECORD_BYTES={}", accepted.data.record.len());
    println!("ACCEPTED_LEASE_EXPIRY={}", accepted.data.lease_expiry);
    println!(
        "ACCEPTED_STATE_COMMITMENT={}",
        hex::encode(accepted.commitment)
    );
    println!(
        "ACCEPTED_STATE_FUTURE_NF={}",
        hex::encode(accepted.state_ref.nullifier)
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Commit(args) => build_commit(args),
        Command::Target(args) => print_target(args),
        Command::Reveal(args) => reveal(args),
        Command::Verify(args) => verify(args),
        Command::Update(args) => update(args),
        Command::VerifyUpdate(args) => verify_update(args),
        Command::Abandon(args) => abandon(args),
        Command::VerifyAbandon(args) => verify_abandon(args),
        Command::Renew(args) => renew(args),
        Command::VerifyRenew(args) => verify_renew(args),
        Command::Release(args) => release(args),
        Command::VerifyRelease(args) => verify_release(args),
        Command::VerifyReleaseBoundary(args) => verify_release_boundary(args),
        Command::ReclaimCommit(args) => build_reclaim_commit(args),
        Command::ReclaimReveal(args) => reclaim_reveal(args),
        Command::ReclaimResetReveal(args) => reveal_with_replacement(
            args,
            RECLAIM_RECORD,
            RECLAIM_SECRET,
            RECLAIM_SUCCESSOR_SEED,
            None,
            "RESET_REVEAL",
        ),
        Command::ReclaimCheck(args) => reclaim_check(args),
        Command::VerifyReclaim(args) => verify_reclaim(args),
        Command::VerifyReclaimRenew(args) => verify_reclaim_renew(args),
    }
}
