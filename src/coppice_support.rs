//! Concrete host integration for Coppice over the wallet's lightwalletd connection.
//!
//! lightwalletd is transport only. The host-selected identities returned by it
//! are reconciled through `coppice-librustzcash`, and fetched transaction bytes
//! remain untrusted until the core runtime validates them.

use std::fmt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow};
use coppice_librustzcash::{
    CanonicalBlockSource, CanonicalTip, FrozenCanonicalBlockSource, FullTransactionSource,
    ReconcileError, ReconcileOutcome, reconcile_canonical_chain_with_progress,
};
use coppice_names::{
    bond_tag,
    config::{DeploymentParameters, REGTEST, TESTNET},
    names_runtime::{CoreReplayActivationCheckpoint, NamesRuntime},
};
use coppice_names_librustzcash::{
    CoppiceProtectionMode, HostCanonicalTipSource, IronwoodViewingCapability,
    PendingRegistrationCollection, WalletAccountId, WalletCanonicalTip, WalletCoppiceLockBackend,
    active_canonical_bond_tags, reconcile_canonical_commit_cache, reconcile_locks,
    with_coppice_spend_guard,
};
use pczt::Pczt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tonic::{Code, transport::Channel};
use uuid::Uuid;
use zcash_client_backend::data_api::{Account, OutputLockStore, WalletRead, wallet::TargetHeight};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, NetworkType, Parameters};

use crate::data::{DEFAULT_WALLET_DIR, get_db_paths};

const SNAPSHOT_FILE: &str = "coppice-runtime-v1.json";
const PENDING_FILE: &str = "coppice-pending-v1.json";
const PROTECTION_FILE: &str = "coppice-protection.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredProtectionMode {
    Enabled,
    GuardOnly,
    Off,
}

impl StoredProtectionMode {
    pub(crate) fn runtime(self) -> CoppiceProtectionMode {
        match self {
            Self::Enabled => CoppiceProtectionMode::Enabled,
            Self::GuardOnly => CoppiceProtectionMode::GuardOnly,
            Self::Off => CoppiceProtectionMode::Off,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredProtection {
    format_version: u32,
    mode: StoredProtectionMode,
}

#[derive(Clone, Copy)]
pub(crate) struct StaticCanonicalTip(pub(crate) WalletCanonicalTip);

impl HostCanonicalTipSource for StaticCanonicalTip {
    type Error = std::convert::Infallible;

    fn canonical_tip(&self) -> Result<WalletCanonicalTip, Self::Error> {
        Ok(self.0)
    }
}

pub(crate) fn wallet_tip<DbT: WalletRead>(wallet_db: &DbT) -> anyhow::Result<StaticCanonicalTip> {
    let metadata = wallet_db
        .block_max_scanned()
        .map_err(|error| anyhow!("wallet canonical tip unavailable: {error:?}"))?
        .ok_or_else(|| anyhow!("wallet has no scanned canonical tip"))?;
    Ok(StaticCanonicalTip(WalletCanonicalTip {
        height: metadata.block_height().into(),
        block_hash: metadata.block_hash().0,
    }))
}

#[derive(Debug)]
enum NetworkSourceError {
    Rpc(tonic::Status),
    InvalidTip,
}

impl fmt::Display for NetworkSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rpc(status) => write!(formatter, "lightwalletd RPC failed: {status}"),
            Self::InvalidTip => formatter.write_str("lightwalletd returned an invalid chain tip"),
        }
    }
}

impl std::error::Error for NetworkSourceError {}

struct LightwalletdCanonicalSource {
    client: CompactTxStreamerClient<Channel>,
}

struct LightwalletdFullTransactionSource {
    client: CompactTxStreamerClient<Channel>,
}

fn block_on_rpc<T>(
    future: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, tonic::Status> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(future)
            .map(tonic::Response::into_inner)
    })
}

impl CanonicalBlockSource for LightwalletdCanonicalSource {
    type Error = NetworkSourceError;

    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
        let tip = block_on_rpc(self.client.get_latest_block(service::ChainSpec::default()))
            .map_err(NetworkSourceError::Rpc)?;
        Ok(CanonicalTip {
            height: u32::try_from(tip.height).map_err(|_| NetworkSourceError::InvalidTip)?,
            block_hash: tip
                .hash
                .as_slice()
                .try_into()
                .map_err(|_| NetworkSourceError::InvalidTip)?,
        })
    }

    fn compact_block(&mut self, height: u32) -> Result<Option<CompactBlock>, Self::Error> {
        block_on_rpc(self.client.get_block(service::BlockId {
            height: u64::from(height),
            hash: vec![],
        }))
        .map(Some)
        .or_else(|status| {
            if status.code() == Code::NotFound {
                Ok(None)
            } else {
                Err(status)
            }
        })
        .map_err(NetworkSourceError::Rpc)
    }
}

impl FullTransactionSource for LightwalletdFullTransactionSource {
    type Error = NetworkSourceError;

    fn full_transaction(&mut self, txid: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        block_on_rpc(self.client.get_transaction(service::TxFilter {
            hash: txid.to_vec(),
            ..Default::default()
        }))
        .map(|transaction| Some(transaction.data))
        .or_else(|status| {
            if status.code() == Code::NotFound {
                Ok(None)
            } else {
                Err(status)
            }
        })
        .map_err(NetworkSourceError::Rpc)
    }
}

pub(crate) fn deployment<P: Parameters>(params: &P) -> anyhow::Result<DeploymentParameters> {
    let frozen = match params.network_type() {
        NetworkType::Test => TESTNET,
        NetworkType::Regtest => REGTEST,
        NetworkType::Main => return Err(anyhow!("Coppice v1 has no Mainnet deployment")),
    };
    Ok(DeploymentParameters {
        network_id: frozen.network_id.to_vec(),
        address_network: params.network_type(),
        activation_height: frozen.activation_height,
        minimum_bond_value: frozen.minimum_bond_value,
        commit_ttl_blocks: 20,
        reuse_delay_blocks: 10,
        bond_note_max_age_blocks: 100,
        rendezvous: frozen.rendezvous,
    })
}

fn snapshot_path(wallet_dir: Option<&String>) -> PathBuf {
    Path::new(wallet_dir.map(String::as_str).unwrap_or(DEFAULT_WALLET_DIR)).join(SNAPSHOT_FILE)
}

fn pending_path(wallet_dir: Option<&String>) -> PathBuf {
    Path::new(wallet_dir.map(String::as_str).unwrap_or(DEFAULT_WALLET_DIR)).join(PENDING_FILE)
}

fn protection_path(wallet_dir: Option<&String>) -> PathBuf {
    Path::new(wallet_dir.map(String::as_str).unwrap_or(DEFAULT_WALLET_DIR)).join(PROTECTION_FILE)
}

pub(crate) fn protection_mode<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
) -> anyhow::Result<StoredProtectionMode> {
    match fs::read(protection_path(wallet_dir)) {
        Ok(bytes) => {
            let stored: StoredProtection =
                serde_json::from_slice(&bytes).context("invalid Coppice protection setting")?;
            if stored.format_version != 1 {
                return Err(anyhow!("unsupported Coppice protection setting format"));
            }
            Ok(stored.mode)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(if params.network_type() == NetworkType::Main {
                StoredProtectionMode::Off
            } else {
                // Existing Testnet/Regtest wallets fail closed. Deliberate Off
                // must be persisted explicitly and cannot be inferred from a
                // missing runtime snapshot.
                StoredProtectionMode::Enabled
            })
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn set_protection_mode(
    wallet_dir: Option<&String>,
    mode: StoredProtectionMode,
) -> anyhow::Result<()> {
    let path = protection_path(wallet_dir);
    let bytes = serde_json::to_vec(&StoredProtection {
        format_version: 1,
        mode,
    })?;
    atomic_write(&path, &bytes, false)
}

fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    let extension = format!("tmp-{}", Uuid::new_v4());
    let temporary = path.with_extension(extension);
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn load_existing<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
) -> anyhow::Result<
    Option<(
        CoppiceProtectionMode,
        NamesRuntime,
        PendingRegistrationCollection,
    )>,
> {
    load_existing_inner(params, wallet_dir, None)
}

/// Load protected Coppice state for a wallet operation at its selected tip.
///
/// Before the deployment activation height, `Enabled` is intentionally
/// equivalent to having no Coppice state to protect. Once activation has been
/// reached, a missing snapshot remains a fail-closed error.
pub(crate) fn load_existing_at_tip<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
    host_tip: WalletCanonicalTip,
) -> anyhow::Result<
    Option<(
        CoppiceProtectionMode,
        NamesRuntime,
        PendingRegistrationCollection,
    )>,
> {
    load_existing_inner(params, wallet_dir, Some(host_tip))
}

fn load_existing_inner<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
    host_tip: Option<WalletCanonicalTip>,
) -> anyhow::Result<
    Option<(
        CoppiceProtectionMode,
        NamesRuntime,
        PendingRegistrationCollection,
    )>,
> {
    let mode = protection_mode(params, wallet_dir)?;
    if mode == StoredProtectionMode::Off {
        return Ok(None);
    }
    let deployment = deployment(params)?;
    if host_tip.is_some_and(|tip| tip.height < deployment.activation_height) {
        return Ok(None);
    }
    let runtime = match fs::read(snapshot_path(wallet_dir)) {
        Ok(bytes) => NamesRuntime::load_snapshot(deployment.clone(), &bytes)
            .map_err(|error| anyhow!("invalid Coppice snapshot: {error:?}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow!(
                "Coppice protection is active but canonical state is unavailable; sync/rebuild is required"
            ));
        }
        Err(error) => return Err(error.into()),
    };
    let pending = match fs::read(pending_path(wallet_dir)) {
        Ok(bytes) => PendingRegistrationCollection::load_local(&deployment, &bytes)
            .map_err(|error| anyhow!("invalid Coppice pending-intent store: {error:?}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PendingRegistrationCollection::new()
        }
        Err(error) => return Err(error.into()),
    };
    Ok(Some((mode.runtime(), runtime, pending)))
}

pub(crate) fn reconcile_wallet_locks<P: Parameters + Clone>(
    runtime: &NamesRuntime,
    pending: &PendingRegistrationCollection,
    wallet_db: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
) -> anyhow::Result<()> {
    let host_tip = wallet_tip(wallet_db)?;
    if host_tip.0 != WalletCanonicalTip::from(runtime.tip()) {
        return Err(anyhow!(
            "wallet and Coppice canonical tips differ after sync"
        ));
    }
    let target = runtime
        .tip()
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("Coppice target height overflow"))?;
    let active = active_canonical_bond_tags(runtime);
    validate_pending_account_ownership(wallet_db, pending)?;
    for account_id in wallet_db
        .get_account_ids()
        .map_err(|error| anyhow!("wallet account inventory failed: {error:?}"))?
    {
        let account = wallet_db
            .get_account(account_id)
            .map_err(|error| anyhow!("wallet account lookup failed: {error:?}"))?
            .ok_or_else(|| anyhow!("wallet account disappeared during lock reconciliation"))?;
        let Some(orchard_fvk) = account.ufvk().and_then(|ufvk| ufvk.orchard()).cloned() else {
            continue;
        };
        let mut backend = WalletCoppiceLockBackend::new(
            wallet_db,
            account_id,
            TargetHeight::from(target),
            &orchard_fvk,
            IronwoodViewingCapability::FullViewing,
        );
        reconcile_locks(
            &active,
            pending,
            WalletAccountId::from_orchard_fvk(&orchard_fvk),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .map_err(|error| anyhow!("Coppice lock reconstruction failed: {error:?}"))?;
    }
    Ok(())
}

fn validate_pending_account_ownership<P: Parameters>(
    wallet_db: &WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    pending: &PendingRegistrationCollection,
) -> anyhow::Result<()> {
    let mut known = std::collections::BTreeSet::new();
    for account_id in wallet_db
        .get_account_ids()
        .map_err(|error| anyhow!("wallet account inventory failed: {error:?}"))?
    {
        let account = wallet_db
            .get_account(account_id)
            .map_err(|error| anyhow!("wallet account lookup failed: {error:?}"))?
            .ok_or_else(|| anyhow!("wallet account disappeared during pending validation"))?;
        if let Some(fvk) = account.ufvk().and_then(|ufvk| ufvk.orchard()) {
            known.insert(WalletAccountId::from_orchard_fvk(fvk));
        }
    }
    if pending.commitments().any(|commitment| {
        pending
            .get(&commitment)
            .is_some_and(|registration| !known.contains(&registration.account_id()))
    }) {
        return Err(anyhow!(
            "Coppice pending registration belongs to an unavailable wallet account"
        ));
    }
    Ok(())
}

/// Removes only exact-owner Coppice advisory locks before a deliberate
/// transition to protection `Off`.
///
/// This does not require runtime state: each owned Ironwood note supplies its
/// canonical bond tag, and `unlock_output` can remove only the matching
/// `LockOwner`. Foreign and unrelated proposal locks are therefore preserved.
pub(crate) fn clear_coppice_advisory_locks<P: Parameters + Clone>(
    wallet_db: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
) -> anyhow::Result<usize> {
    let accounts = wallet_db
        .get_account_ids()
        .map_err(|error| anyhow!("wallet account inventory failed: {error:?}"))?;
    let Some(metadata) = wallet_db
        .block_max_scanned()
        .map_err(|error| anyhow!("wallet canonical tip unavailable: {error:?}"))?
    else {
        for account_id in accounts {
            if !wallet_db
                .get_locked_outputs(account_id)
                .map_err(|error| anyhow!("wallet lock inventory failed: {error:?}"))?
                .is_empty()
            {
                return Err(anyhow!(
                    "wallet has locks but no scanned tip; refusing ambiguous Coppice cleanup"
                ));
            }
        }
        return Ok(0);
    };
    let target = u32::from(metadata.block_height())
        .checked_add(1)
        .ok_or_else(|| anyhow!("wallet target height overflow"))?;
    let empty_active = std::collections::BTreeSet::new();
    let empty_pending = PendingRegistrationCollection::new();
    let mut removed = 0usize;
    for account_id in accounts {
        let account = wallet_db
            .get_account(account_id)
            .map_err(|error| anyhow!("wallet account lookup failed: {error:?}"))?
            .ok_or_else(|| anyhow!("wallet account disappeared during lock cleanup"))?;
        let Some(orchard_fvk) = account.ufvk().and_then(|ufvk| ufvk.orchard()).cloned() else {
            continue;
        };
        let mut backend = WalletCoppiceLockBackend::new(
            wallet_db,
            account_id,
            TargetHeight::from(target),
            &orchard_fvk,
            IronwoodViewingCapability::FullViewing,
        );
        removed += reconcile_locks(
            &empty_active,
            &empty_pending,
            WalletAccountId::from_orchard_fvk(&orchard_fvk),
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .map_err(|error| anyhow!("Coppice lock cleanup failed: {error:?}"))?
        .removed_locks;
    }
    Ok(removed)
}

pub(crate) fn with_spend_protection<P, R, E>(
    params: &P,
    wallet_dir: Option<&String>,
    wallet_db: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    account_id: zcash_client_sqlite::AccountUuid,
    orchard_fvk: Option<&orchard::keys::FullViewingKey>,
    operation: impl FnOnce(&mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>) -> Result<R, E>,
) -> anyhow::Result<Result<R, E>>
where
    P: Parameters + Clone,
    E: std::fmt::Debug,
{
    let host_tip = wallet_tip(wallet_db)?;
    let protected_state = load_existing_at_tip(params, wallet_dir, host_tip.0)?;
    let orchard_fvk = orchard_fvk_for_protection(protected_state.is_some(), orchard_fvk)?;
    match protected_state {
        None => {
            // `Off` and pre-activation `Enabled` are deliberately unprotected,
            // but they must also repair an advisory Coppice lock left by a
            // concurrent or older process. Exact-owner cleanup preserves
            // foreign and non-Coppice locks.
            clear_coppice_advisory_locks(wallet_db)?;
            Ok(operation(wallet_db))
        }
        Some((mode, runtime, pending)) => {
            validate_pending_account_ownership(wallet_db, &pending)?;
            let orchard_fvk = orchard_fvk.expect("protected mode checked above");
            let target = runtime
                .tip()
                .height
                .checked_add(1)
                .ok_or_else(|| anyhow!("Coppice target height overflow"))?;
            let mut backend = WalletCoppiceLockBackend::new(
                wallet_db,
                account_id,
                TargetHeight::from(target),
                orchard_fvk,
                IronwoodViewingCapability::FullViewing,
            );
            let (result, _) = with_coppice_spend_guard(
                mode,
                &host_tip,
                &runtime,
                &pending,
                WalletAccountId::from_orchard_fvk(orchard_fvk),
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                |backend| operation(backend.wallet_db_mut()),
            )
            .map_err(|error| anyhow!("Coppice spend protection failed: {error:?}"))?;
            Ok(result)
        }
    }
}

fn orchard_fvk_for_protection(
    protected: bool,
    orchard_fvk: Option<&orchard::keys::FullViewingKey>,
) -> anyhow::Result<Option<&orchard::keys::FullViewingKey>> {
    if protected && orchard_fvk.is_none() {
        Err(anyhow!(
            "Coppice protection requires an Orchard full viewing key"
        ))
    } else {
        Ok(orchard_fvk)
    }
}

fn contains_protected_bond_spend(
    nullifiers: impl IntoIterator<Item = [u8; 32]>,
    protected: &std::collections::BTreeSet<[u8; 32]>,
) -> bool {
    nullifiers.into_iter().any(|nullifier| {
        bond_tag::derive_v1_bond_tag(&nullifier).is_ok_and(|tag| protected.contains(&tag))
    })
}

pub(crate) fn ensure_external_transaction_respects_coppice<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
    wallet_db: &WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    transaction: &Transaction,
) -> anyhow::Result<()> {
    let nullifiers = transaction
        .ironwood_bundle()
        .into_iter()
        .flat_map(|bundle| bundle.actions())
        .map(|action| action.nullifier().to_bytes());
    ensure_external_ironwood_nullifiers_respect_coppice(params, wallet_dir, wallet_db, nullifiers)
}

pub(crate) fn ensure_external_ironwood_nullifiers_respect_coppice<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
    wallet_db: &WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    nullifiers: impl IntoIterator<Item = [u8; 32]>,
) -> anyhow::Result<()> {
    let host_tip = wallet_tip(wallet_db)?;
    let Some((_, runtime, pending)) = load_existing_at_tip(params, wallet_dir, host_tip.0)? else {
        return Ok(());
    };
    validate_pending_account_ownership(wallet_db, &pending)?;
    coppice_names_librustzcash::require_exact_canonical_tip(&host_tip, &runtime)
        .map_err(|error| anyhow!("Coppice submission protection failed: {error:?}"))?;

    let mut protected = active_canonical_bond_tags(&runtime);
    protected.extend(
        pending
            .commitments()
            .filter_map(|commitment| pending.get(&commitment))
            .map(|registration| registration.bond_tag()),
    );
    if contains_protected_bond_spend(nullifiers, &protected) {
        return Err(anyhow!(
            "signed transaction spends a protected Coppice bond; use explicit Break Bond"
        ));
    }
    Ok(())
}

/// Applies the external Ironwood-spend gate to a wallet-backed PCZT operation.
///
/// PCZT proving, signing, and extraction do not all have a concrete transaction
/// yet, but they do expose the public Ironwood spend nullifiers. Checking those
/// nullifiers before the role mutates or finalizes the PCZT prevents a wallet
/// process from preparing a protected bond spend through an alternate PCZT
/// entry point. A PCZT operation without a wallet context remains an external
/// artifact operation and is checked when it reaches a wallet submission path.
pub(crate) fn ensure_external_pczt_respects_coppice<P: Parameters + Clone>(
    params: &P,
    wallet_dir: Option<&String>,
    pczt: &Pczt,
) -> anyhow::Result<()> {
    let nullifiers = pczt
        .ironwood()
        .actions()
        .iter()
        .map(|action| *action.spend().nullifier())
        .collect::<Vec<_>>();
    if nullifiers.is_empty() {
        return Ok(());
    }

    let Some(wallet_dir) = wallet_dir else {
        return Ok(());
    };
    let (_, db_path) = get_db_paths(Some(wallet_dir));
    let wallet_db = WalletDb::for_path(db_path, params.clone(), SystemClock, OsRng)?;
    ensure_external_ironwood_nullifiers_respect_coppice(
        params,
        Some(wallet_dir),
        &wallet_db,
        nullifiers,
    )
}

pub(crate) fn persist_pending(
    wallet_dir: Option<&String>,
    deployment: &DeploymentParameters,
    pending: &PendingRegistrationCollection,
) -> anyhow::Result<()> {
    let bytes = pending
        .save_local(deployment)
        .map_err(|error| anyhow!("Coppice pending-intent encoding failed: {error:?}"))?;
    atomic_write(&pending_path(wallet_dir), &bytes, true)
}

fn activation_checkpoint_parts(
    tree_state: &service::TreeState,
    activation_block: &CompactBlock,
    activation_base: u32,
) -> anyhow::Result<(
    [u8; 32],
    coppice_names::names_runtime::IronwoodFrontier,
    u32,
)> {
    let chain_state = tree_state
        .to_chain_state()
        .context("invalid activation TreeState hash or frontier encoding")?;
    if chain_state.block_height() != BlockHeight::from_u32(activation_base) {
        return Err(anyhow!("activation TreeState returned the wrong height"));
    }
    let predecessor = activation_block
        .prev_hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("activation CompactBlock has an invalid predecessor hash"))?;
    if chain_state.block_hash().0 != predecessor {
        return Err(anyhow!(
            "activation TreeState hash does not match the activation predecessor"
        ));
    }
    let ironwood_frontier = tree_state
        .ironwood_tree()
        .context("invalid activation Ironwood frontier")?;
    let ironwood_tree_size = u32::try_from(ironwood_frontier.size())
        .map_err(|_| anyhow!("activation Ironwood tree is too large"))?;
    Ok((predecessor, ironwood_frontier, ironwood_tree_size))
}

async fn initial_runtime<P: Parameters>(
    params: &P,
    client: &mut CompactTxStreamerClient<Channel>,
    deployment: DeploymentParameters,
) -> anyhow::Result<NamesRuntime> {
    let activation_base = deployment
        .activation_height
        .checked_sub(1)
        .ok_or_else(|| anyhow!("invalid Coppice activation height"))?;
    let tree_state = client
        .get_tree_state(service::BlockId {
            height: u64::from(activation_base),
            hash: vec![],
        })
        .await?
        .into_inner();
    let activation_block = client
        .get_block(service::BlockId {
            height: u64::from(deployment.activation_height),
            hash: vec![],
        })
        .await?
        .into_inner();
    if activation_block.height != u64::from(deployment.activation_height) {
        return Err(anyhow!("activation CompactBlock returned the wrong height"));
    }
    let (block_hash, ironwood_frontier, ironwood_tree_size) =
        activation_checkpoint_parts(&tree_state, &activation_block, activation_base)?;
    if params.network_type() != deployment.address_network {
        return Err(anyhow!("Coppice deployment network mismatch"));
    }
    NamesRuntime::new(
        deployment,
        CoreReplayActivationCheckpoint {
            height: activation_base,
            block_hash,
            ironwood_frontier,
            ironwood_tree_size,
        },
    )
    .map_err(|error| anyhow!("invalid Coppice activation checkpoint: {error:?}"))
}

fn persist_snapshot(path: &Path, runtime: &NamesRuntime) -> anyhow::Result<()> {
    let bytes = runtime
        .save_snapshot()
        .map_err(|error| anyhow!("Coppice snapshot encoding failed: {error:?}"))?;
    atomic_write(path, &bytes, false)
}

pub(crate) async fn reconcile<P: Parameters>(
    params: &P,
    client: &mut CompactTxStreamerClient<Channel>,
    host_tip: WalletCanonicalTip,
    wallet_dir: Option<&String>,
) -> anyhow::Result<Option<ReconcileOutcome>> {
    if params.network_type() == NetworkType::Main {
        return Ok(None);
    }
    let mode = protection_mode(params, wallet_dir)?;
    if mode == StoredProtectionMode::Off {
        return Ok(None);
    }
    let deployment = deployment(params)?;
    if host_tip.height < deployment.activation_height {
        return Ok(None);
    }
    let path = snapshot_path(wallet_dir);
    let mut runtime = match fs::read(&path) {
        Ok(bytes) => match NamesRuntime::load_snapshot(deployment.clone(), &bytes) {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "Coppice snapshot unusable; rebuilding from activation"
                );
                initial_runtime(params, client, deployment.clone()).await?
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            initial_runtime(params, client, deployment.clone()).await?
        }
        Err(error) => return Err(error.into()),
    };

    let frozen_tip = CanonicalTip {
        height: host_tip.height,
        block_hash: host_tip.block_hash,
    };
    let mut canonical = FrozenCanonicalBlockSource::new(
        LightwalletdCanonicalSource {
            client: client.clone(),
        },
        frozen_tip,
    );
    let mut transactions = LightwalletdFullTransactionSource {
        client: client.clone(),
    };
    let mut persistence_error = None;
    let mut outcome = reconcile_canonical_chain_with_progress(
        params,
        &mut runtime,
        &mut canonical,
        &mut transactions,
        |progress| match persist_snapshot(&path, progress) {
            Ok(()) => true,
            Err(error) => {
                persistence_error = Some(error);
                false
            }
        },
    );
    if matches!(outcome, Err(ReconcileError::NoRetainedCommonAncestor)) {
        runtime = initial_runtime(params, client, deployment.clone()).await?;
        canonical = FrozenCanonicalBlockSource::new(
            LightwalletdCanonicalSource {
                client: client.clone(),
            },
            frozen_tip,
        );
        transactions = LightwalletdFullTransactionSource {
            client: client.clone(),
        };
        outcome = reconcile_canonical_chain_with_progress(
            params,
            &mut runtime,
            &mut canonical,
            &mut transactions,
            |progress| match persist_snapshot(&path, progress) {
                Ok(()) => true,
                Err(error) => {
                    persistence_error = Some(error);
                    false
                }
            },
        );
    }
    if let Some(error) = persistence_error {
        return Err(error.context("persisting intermediate Coppice replay progress"));
    }
    let outcome =
        outcome.map_err(|error| anyhow!("Coppice canonical reconciliation failed: {error:?}"))?;
    persist_snapshot(&path, &runtime)?;
    let mut pending = match fs::read(pending_path(wallet_dir)) {
        Ok(bytes) => PendingRegistrationCollection::load_local(runtime.deployment(), &bytes)
            .map_err(|error| anyhow!("invalid Coppice pending-intent store: {error:?}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PendingRegistrationCollection::new()
        }
        Err(error) => return Err(error.into()),
    };
    reconcile_canonical_commit_cache(&runtime, &mut pending)
        .map_err(|error| anyhow!("Coppice canonical COMMIT cache failed: {error:?}"))?;
    persist_pending(wallet_dir, runtime.deployment(), &pending)?;
    set_protection_mode(wallet_dir, mode)?;
    Ok(Some(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Network;

    #[test]
    fn protection_mode_is_durable_and_missing_protected_state_fails_closed() {
        let directory = std::env::temp_dir().join(format!(
            "zcash-devtool-coppice-protection-{}-test",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let directory = directory.to_string_lossy().into_owned();

        assert_eq!(
            protection_mode(&Network::Test, Some(&directory)).unwrap(),
            StoredProtectionMode::Enabled
        );
        assert!(load_existing(&Network::Test, Some(&directory)).is_err());

        set_protection_mode(Some(&directory), StoredProtectionMode::Off).unwrap();
        assert_eq!(
            protection_mode(&Network::Test, Some(&directory)).unwrap(),
            StoredProtectionMode::Off
        );
        assert!(
            load_existing(&Network::Test, Some(&directory))
                .unwrap()
                .is_none()
        );

        set_protection_mode(Some(&directory), StoredProtectionMode::GuardOnly).unwrap();
        assert!(load_existing(&Network::Test, Some(&directory)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn enabled_pre_activation_tip_has_no_protected_state() {
        let directory = std::env::temp_dir().join(format!(
            "zcash-devtool-coppice-pre-activation-{}-test",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let directory = directory.to_string_lossy().into_owned();
        let activation_height = deployment(&Network::Test).unwrap().activation_height;
        let pre_activation_tip = WalletCanonicalTip {
            height: activation_height - 1,
            block_hash: [0; 32],
        };
        let activation_tip = WalletCanonicalTip {
            height: activation_height,
            block_hash: [0; 32],
        };

        assert_eq!(
            protection_mode(&Network::Test, Some(&directory)).unwrap(),
            StoredProtectionMode::Enabled
        );
        assert!(
            load_existing_at_tip(&Network::Test, Some(&directory), pre_activation_tip)
                .unwrap()
                .is_none()
        );
        assert!(load_existing_at_tip(&Network::Test, Some(&directory), activation_tip).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn mainnet_defaults_to_explicitly_unprotected_until_deployed() {
        let directory = std::env::temp_dir().join(format!(
            "zcash-devtool-coppice-protection-{}-main",
            std::process::id()
        ));
        let directory = directory.to_string_lossy().into_owned();
        assert_eq!(
            protection_mode(&Network::Main, Some(&directory)).unwrap(),
            StoredProtectionMode::Off
        );
    }

    #[test]
    fn activation_tree_state_hash_must_match_activation_predecessor() {
        let mut tree_state = service::TreeState {
            height: 9,
            hash: hex::encode([7u8; 32]),
            ..Default::default()
        };
        let activation_block = CompactBlock {
            height: 10,
            prev_hash: vec![7; 32],
            ..Default::default()
        };
        let (_, frontier, tree_size) =
            activation_checkpoint_parts(&tree_state, &activation_block, 9).unwrap();
        assert_eq!(frontier.size(), 0);
        assert_eq!(tree_size, 0);

        tree_state.hash = hex::encode([8u8; 32]);
        let error = activation_checkpoint_parts(&tree_state, &activation_block, 9).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn external_transaction_gate_rejects_active_or_pending_bond_nullifiers() {
        let nullifier = [1; 32];
        let protected_tag = bond_tag::derive_v1_bond_tag(&nullifier).unwrap();
        let protected = std::collections::BTreeSet::from([protected_tag]);
        assert!(contains_protected_bond_spend([nullifier], &protected));
        assert!(!contains_protected_bond_spend([[2; 32]], &protected));
        assert!(!contains_protected_bond_spend([], &protected));
    }

    #[test]
    fn explicit_off_mode_does_not_require_an_orchard_fvk() {
        assert!(orchard_fvk_for_protection(false, None).unwrap().is_none());
        assert!(orchard_fvk_for_protection(true, None).is_err());
    }

    #[test]
    fn atomic_write_replaces_content_without_leaving_a_temporary_file() {
        let directory = std::env::temp_dir().join(format!(
            "zcash-devtool-coppice-atomic-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.json");

        atomic_write(&path, b"first", true).unwrap();
        atomic_write(&path, b"second", true).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
