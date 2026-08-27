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
use clap::{Args, Parser, Subcommand};
use coppice::{
    carrier::CoreRendezvous,
    transport::{encode_frames, reconstruct_frames},
};
use coppice_librustzcash::{CanonicalBlockSource, FullTransactionSource};
use coppice_names::{
    carrier::bulletin_address,
    config::REGTEST,
    names_application::names_application_id,
    v2::{
        CanonicalBlock, CanonicalTransaction, CommitRef, FreshResolver, GenesisStatement,
        IronwoodActionRef, NameState, OrchardV2ProofProver, ProducerPosition, RegistrationIntent,
        ResolutionStatus, StateData, StateRef, StateStatus, V2Operation, V2Parameters,
        decode_operation, encode_operation, operation_footprint,
    },
};
use orchard::{
    circuit::state_note_binding::{GenesisWitness, spend_auth_owner_key_bytes},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey},
    note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho},
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
    CarrierOutput, ChangeOutput, FundingSpend, NamesV2IronwoodPlan, NamesV2IronwoodWitness,
    NamesV2PcztPlan, NamesV2SigningPlan, NamesV2WitnessPlan, build_names_v2_bundle,
    build_names_v2_pczt, extract_names_v2_transaction, finalize_names_v2_pczt_io,
    install_names_v2_ironwood_witnesses, prove_names_v2_ironwood_pczt, sign_names_v2_ironwood_pczt,
};

const NAME: &str = "footprint";
const ACTION_INDEX: u32 = 4;
const RECORD: [u8; 64] = [9; 64];
const SECRET: [u8; 32] = [8; 32];
const SUCCESSOR_SEED: u8 = 3;
// Zakura enforces ZIP-317's zero unpaid-action limit. The funded REVEAL has
// thirteen Ironwood actions, so its value balance must pay the conventional
// 13 * 5,000-zatoshi fee rather than the smaller offline fixture balance.
const DESIRED_VALUE_BALANCE: i64 = 65_000;

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

fn names_intent(ask: &SpendAuthorizingKey) -> Result<RegistrationIntent> {
    Ok(RegistrationIntent {
        name: NAME.to_owned(),
        owner_pk: spend_auth_owner_key_bytes(ask),
        record: RECORD.to_vec(),
        secret: SECRET,
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

fn build_commit(args: CommonArgs) -> Result<()> {
    let params = local_consensus();
    let usk = wallet_usk(&params)?;
    let ask = SpendAuthorizingKey::from(usk.orchard());
    let intent = names_intent(&ask)?;
    let commitment = intent
        .commitment()
        .map_err(|error| anyhow::anyhow!("derive COMMIT commitment: {error:?}"))?;
    let operation = V2Operation::Commit { commitment };
    let encoded = encode_operation(&operation)
        .map_err(|error| anyhow::anyhow!("encode COMMIT operation: {error:?}"))?;
    let decoded = decode_operation(&encoded)
        .map_err(|error| anyhow::anyhow!("decode COMMIT operation: {error:?}"))?;
    ensure!(decoded == operation, "COMMIT wire round-trip mismatch");
    let app_id = names_application_id().to_bytes();
    let frames = encode_frames(app_id, &encoded)
        .map_err(|error| anyhow::anyhow!("frame COMMIT operation: {error:?}"))?;
    ensure!(
        frames.len() == 1,
        "deterministic COMMIT must fit one CPV1 frame"
    );
    let raw = build_wallet_carrier_transaction(&args.wallet_dir, build_carrier_request(&frames)?)?;
    let txid = submit_raw(&args.rpc_url, &raw)?;
    println!("COMMIT_TXID={}", hex::encode(txid));
    println!("COMMITMENT={}", hex::encode(commitment));
    println!("COMMIT_OPERATION_BYTES={}", encoded.len());
    println!("COMMIT_CPV1_FRAMES={}", frames.len());
    println!("NAMES_APPLICATION_ID={}", hex::encode(app_id));
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
    let intent = names_intent(&names_ask)?;
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
    let lease_expiry = v2
        .lease_expiry(construction_height)
        .context("Names v2 lease expiry overflow")?;

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
    let successor_note = {
        let rho = Option::<Rho>::from(Rho::from_bytes(&registration_nf))
            .context("registration nullifier is not a valid successor rho")?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([SUCCESSOR_SEED; 32], &rho))
            .context("construct deterministic successor note seed")?;
        Option::<Note>::from(Note::from_parts(
            names_fvk.address_at(0u32, registration.1),
            registration_note.value(),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .context("construct exact successor state note")?
    };
    let successor_commitment =
        ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes();
    let successor_future_nf = successor_note.nullifier(&names_fvk).to_bytes();
    let state_data = StateData {
        name_id,
        owner_pk: intent.owner_pk,
        sequence: 0,
        record: intent.record.clone(),
        lease_expiry,
        status: StateStatus::Active,
        terminal_height: 0,
    };
    // The final producer position is only known after this transaction is
    // mined. GenesisStatement authenticates the state fields and action; the
    // canonical replay path reconstructs the real StateRef from the mined tx.
    let state_ref = StateRef::new(
        ProducerPosition::new(construction_height, 0, [0; 32]),
        ACTION_INDEX,
        0,
        successor_commitment,
        successor_future_nf,
    );
    let state = NameState::new(state_data.clone(), successor_commitment, state_ref)
        .map_err(|error| anyhow::anyhow!("construct Names state: {error:?}"))?;
    let action = IronwoodActionRef {
        action_index: ACTION_INDEX,
        nullifier: registration_nf,
        commitment: successor_commitment,
    };
    let statement = GenesisStatement::from_state(&state, action, v2.minimum_bond_zatoshis)
        .map_err(|error| anyhow::anyhow!("construct Names genesis statement: {error:?}"))?;
    let witness = GenesisWitness::new(
        registration_note,
        successor_note,
        &names_fvk,
        registration.1,
        &names_ask,
        v2.minimum_bond_zatoshis,
    )
    .context("construct real Names genesis witness")?;
    let names_prover = OrchardV2ProofProver::new();
    let proof_started = Instant::now();
    let genesis_proof = names_prover
        .prove_genesis(&statement, witness, OsRng)
        .map_err(|error| anyhow::anyhow!("create Names genesis proof: {error:?}"))?;
    let proof_elapsed = proof_started.elapsed();
    ensure!(!genesis_proof.is_empty(), "Names genesis proof is empty");

    let reveal = V2Operation::Reveal {
        intent: Box::new(intent),
        commit,
        replacement_predecessor: None,
        state: state_data,
        state_commitment: successor_commitment,
        state_nullifier: successor_future_nf,
        action_index: ACTION_INDEX,
        proof: genesis_proof.clone(),
    };
    let encoded_reveal = encode_operation(&reveal)
        .map_err(|error| anyhow::anyhow!("encode REVEAL operation: {error:?}"))?;
    let decoded_reveal = decode_operation(&encoded_reveal)
        .map_err(|error| anyhow::anyhow!("decode REVEAL operation: {error:?}"))?;
    ensure!(decoded_reveal == reveal, "REVEAL wire round-trip mismatch");
    let footprint = operation_footprint(&reveal)
        .map_err(|error| anyhow::anyhow!("measure REVEAL operation: {error:?}"))?;
    let frames = encode_frames(app_id, &encoded_reveal)
        .map_err(|error| anyhow::anyhow!("frame REVEAL operation: {error:?}"))?;
    let reconstructed = reconstruct_frames(&frames, app_id)
        .map_err(|error| anyhow::anyhow!("reconstruct REVEAL frames: {error:?}"))?;
    ensure!(
        reconstructed == encoded_reveal,
        "CPV1 reconstruction changed REVEAL bytes"
    );
    let reconstructed_reveal = decode_operation(&reconstructed)
        .map_err(|error| anyhow::anyhow!("decode reconstructed REVEAL: {error:?}"))?;
    ensure!(
        reconstructed_reveal == reveal,
        "CPV1 decode changed REVEAL operation"
    );
    ensure!(
        frames.len() == footprint.cpv1_frames,
        "CPV1 footprint disagrees with measured operation"
    );

    let anchor_height = db
        .get_target_and_anchor_heights(NonZeroU32::MIN)?
        .context("wallet has no synchronized target/anchor heights")?
        .1;
    let (anchor, paths) = wallet_witnesses(&mut db, anchor_height, [registration.2, funding.2])?;
    let carrier_recipient = names_recipient()?;
    let carriers = frames
        .iter()
        .copied()
        .map(|memo| CarrierOutput {
            recipient: carrier_recipient,
            value: orchard::value::NoteValue::from_raw(1),
            memo,
        })
        .collect::<Vec<_>>();
    let funding_value = funding.3;
    let carrier_value = u64::try_from(carriers.len()).context("carrier count does not fit u64")?;
    let change_value = funding_value
        .checked_sub(carrier_value)
        .and_then(|value| value.checked_sub(u64::try_from(DESIRED_VALUE_BALANCE).ok()?))
        .context("funding note cannot cover carrier outputs and the requested value balance")?;
    let plan = NamesV2IronwoodPlan {
        designated_fvk: names_fvk.clone(),
        designated_spend: registration_note,
        successor_note,
        successor_ovk: None,
        successor_memo: [0; 512],
        carrier_outputs: carriers,
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
        designated_action_index: usize::try_from(ACTION_INDEX)
            .context("designated action index does not fit usize")?,
    };
    let built = build_names_v2_bundle(plan, OsRng)?;
    ensure!(
        built.designated_nullifier == statement.registration_nullifier,
        "wallet designated NF differs from Names genesis statement"
    );
    ensure!(
        built.designated_commitment == statement.commitment,
        "wallet designated CMX differs from Names genesis statement"
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
                    nullifier: funding_note.nullifier(&names_fvk).to_bytes(),
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
                    nullifier: funding_note.nullifier(&names_fvk).to_bytes(),
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
    println!("CNV2_REVEAL_BYTES={}", encoded_reveal.len());
    println!("CPV1_FRAMES={}", frames.len());
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
    let _ = (intent, state);
    let resolver = FreshResolver::new(v2_parameters())
        .map_err(|error| anyhow::anyhow!("construct Names v2 fresh resolver: {error:?}"))?;
    // The verifier key is generated once for this disposable replay process;
    // this is verification only and does not create another application proof.
    let (_, transition_verifier, _, genesis_verifier) =
        orchard::circuit::state_note_binding::keygen();
    let verifier = coppice_names::v2::transition::OrchardV2ProofVerifier::from_parts(
        transition_verifier,
        genesis_verifier,
    );
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
    let intent_name_id = intent
        .name_id()
        .map_err(|error| anyhow::anyhow!("derive replay intent name id: {error:?}"))?;
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
    println!("NAMES_REPLAY_STATUS=Active");
    println!("COMMIT_CANONICAL_HEIGHT={}", commit_block.height);
    println!("COMMIT_CANONICAL_TX_INDEX={}", commit.tx_index);
    println!("COMMIT_OPERATION_INDEX={canonical_commit}");
    println!("REVEAL_CANONICAL_HEIGHT={}", reveal_block.height);
    println!("REVEAL_CANONICAL_TX_INDEX={}", reveal.tx_index);
    println!("REVEAL_ACTION_INDEX={action_index}");
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
    }
}
