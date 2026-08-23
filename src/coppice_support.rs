//! Concrete host integration for Coppice over the wallet's lightwalletd connection.
//!
//! lightwalletd is transport only. The host-selected identities returned by it
//! are reconciled through `coppice-librustzcash`, and fetched transaction bytes
//! remain untrusted until the core reducer validates them.

use std::fmt;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use ::coppice::{
    config::{DeploymentParameters, REGTEST_V0, TESTNET_V0},
    reducer_v1::{ActivationCheckpoint, V1Reducer},
};
use anyhow::{Context, anyhow};
use coppice_librustzcash::{
    CanonicalBlockSource, CanonicalTip, CoppiceProtectionMode, FullTransactionSource,
    HostCanonicalTipSource, IronwoodViewingCapability, PendingRegistrationCollection,
    ReconcileError, ReconcileOutcome, WalletCanonicalTip, WalletCoppiceLockBackend,
    active_canonical_bond_tags, reconcile_canonical_chain_with_progress,
    reconcile_canonical_commit_cache, reconcile_locks, with_coppice_spend_guard,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tonic::{Code, transport::Channel};
use zcash_client_backend::data_api::{Account, WalletRead, wallet::TargetHeight};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_protocol::consensus::{NetworkType, Parameters};

use crate::data::DEFAULT_WALLET_DIR;

const SNAPSHOT_FILE: &str = "coppice-v1.json";
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
        NetworkType::Test => TESTNET_V0,
        NetworkType::Regtest => REGTEST_V0,
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
                // missing reducer snapshot.
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
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(&StoredProtection {
        format_version: 1,
        mode,
    })?;
    let mut file = fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub(crate) fn load_existing<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
) -> anyhow::Result<
    Option<(
        CoppiceProtectionMode,
        V1Reducer,
        PendingRegistrationCollection,
    )>,
> {
    let mode = protection_mode(params, wallet_dir)?;
    if mode == StoredProtectionMode::Off {
        return Ok(None);
    }
    let deployment = deployment(params)?;
    let reducer = match fs::read(snapshot_path(wallet_dir)) {
        Ok(bytes) => V1Reducer::load_snapshot(deployment.clone(), &bytes)
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
    Ok(Some((mode.runtime(), reducer, pending)))
}

pub(crate) fn reconcile_wallet_locks<P: Parameters + Clone>(
    reducer: &V1Reducer,
    pending: &PendingRegistrationCollection,
    wallet_db: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
) -> anyhow::Result<()> {
    let host_tip = wallet_tip(wallet_db)?;
    if host_tip.0 != WalletCanonicalTip::from(reducer.tip()) {
        return Err(anyhow!(
            "wallet and Coppice canonical tips differ after sync"
        ));
    }
    let target = reducer
        .tip()
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow!("Coppice target height overflow"))?;
    let active = active_canonical_bond_tags(reducer);
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
            IronwoodViewingCapability::FullViewing,
            &mut backend,
        )
        .map_err(|error| anyhow!("Coppice lock reconstruction failed: {error:?}"))?;
    }
    Ok(())
}

pub(crate) fn with_spend_protection<P, R, E>(
    params: &P,
    wallet_dir: Option<&String>,
    wallet_db: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    account_id: zcash_client_sqlite::AccountUuid,
    orchard_fvk: &orchard::keys::FullViewingKey,
    operation: impl FnOnce(&mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>) -> Result<R, E>,
) -> anyhow::Result<Result<R, E>>
where
    P: Parameters + Clone,
    E: std::fmt::Debug,
{
    match load_existing(params, wallet_dir)? {
        None => Ok(operation(wallet_db)),
        Some((mode, reducer, pending)) => {
            let host_tip = wallet_tip(wallet_db)?;
            let target = reducer
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
                &reducer,
                &pending,
                IronwoodViewingCapability::FullViewing,
                &mut backend,
                |backend| operation(backend.wallet_db_mut()),
            )
            .map_err(|error| anyhow!("Coppice spend protection failed: {error:?}"))?;
            Ok(result)
        }
    }
}

pub(crate) fn persist_pending(
    wallet_dir: Option<&String>,
    deployment: &DeploymentParameters,
    pending: &PendingRegistrationCollection,
) -> anyhow::Result<()> {
    let bytes = pending
        .save_local(deployment)
        .map_err(|error| anyhow!("Coppice pending-intent encoding failed: {error:?}"))?;
    let path = pending_path(wallet_dir);
    let temporary = path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

async fn initial_reducer<P: Parameters>(
    params: &P,
    client: &mut CompactTxStreamerClient<Channel>,
    deployment: DeploymentParameters,
) -> anyhow::Result<V1Reducer> {
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
    if tree_state.height != u64::from(activation_base) {
        return Err(anyhow!("activation TreeState returned the wrong height"));
    }
    let ironwood_frontier = tree_state
        .ironwood_tree()
        .context("invalid activation Ironwood frontier")?;
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
    let block_hash = activation_block
        .prev_hash
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("activation CompactBlock has an invalid predecessor hash"))?;
    let ironwood_tree_size = u32::try_from(ironwood_frontier.size())
        .map_err(|_| anyhow!("activation Ironwood tree is too large"))?;
    if params.network_type() != deployment.address_network {
        return Err(anyhow!("Coppice deployment network mismatch"));
    }
    V1Reducer::new(
        deployment,
        ActivationCheckpoint {
            height: activation_base,
            block_hash,
            ironwood_frontier,
            ironwood_tree_size,
        },
    )
    .map_err(|error| anyhow!("invalid Coppice activation checkpoint: {error:?}"))
}

fn persist_snapshot(path: &Path, reducer: &V1Reducer) -> anyhow::Result<()> {
    let bytes = reducer
        .save_snapshot()
        .map_err(|error| anyhow!("Coppice snapshot encoding failed: {error:?}"))?;
    let temporary = path.with_extension("json.tmp");
    let mut file = fs::File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

pub(crate) async fn reconcile<P: Parameters>(
    params: &P,
    client: &mut CompactTxStreamerClient<Channel>,
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
    let host_tip = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .into_inner();
    if host_tip.height < u64::from(deployment.activation_height) {
        return Ok(None);
    }
    let path = snapshot_path(wallet_dir);
    let mut reducer = match fs::read(&path) {
        Ok(bytes) => match V1Reducer::load_snapshot(deployment.clone(), &bytes) {
            Ok(reducer) => reducer,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "Coppice snapshot unusable; rebuilding from activation"
                );
                initial_reducer(params, client, deployment.clone()).await?
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            initial_reducer(params, client, deployment.clone()).await?
        }
        Err(error) => return Err(error.into()),
    };

    let mut canonical = LightwalletdCanonicalSource {
        client: client.clone(),
    };
    let mut transactions = LightwalletdFullTransactionSource {
        client: client.clone(),
    };
    let mut persistence_error = None;
    let mut outcome = reconcile_canonical_chain_with_progress(
        params,
        &mut reducer,
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
        reducer = initial_reducer(params, client, deployment.clone()).await?;
        canonical = LightwalletdCanonicalSource {
            client: client.clone(),
        };
        transactions = LightwalletdFullTransactionSource {
            client: client.clone(),
        };
        outcome = reconcile_canonical_chain_with_progress(
            params,
            &mut reducer,
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
        return Err(error.context("persisting incremental Coppice replay progress"));
    }
    let outcome =
        outcome.map_err(|error| anyhow!("Coppice canonical reconciliation failed: {error:?}"))?;
    persist_snapshot(&path, &reducer)?;
    let mut pending = match fs::read(pending_path(wallet_dir)) {
        Ok(bytes) => PendingRegistrationCollection::load_local(reducer.deployment(), &bytes)
            .map_err(|error| anyhow!("invalid Coppice pending-intent store: {error:?}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PendingRegistrationCollection::new()
        }
        Err(error) => return Err(error.into()),
    };
    reconcile_canonical_commit_cache(&reducer, &mut pending)
        .map_err(|error| anyhow!("Coppice canonical COMMIT cache failed: {error:?}"))?;
    persist_pending(wallet_dir, reducer.deployment(), &pending)?;
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
}
