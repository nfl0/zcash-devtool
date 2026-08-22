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
    CanonicalBlockSource, CanonicalTip, FullTransactionSource, ReconcileOutcome,
    reconcile_canonical_chain,
};
use tonic::{Code, transport::Channel};
use zcash_client_backend::proto::{
    compact_formats::CompactBlock,
    service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_protocol::consensus::{NetworkType, Parameters};

use crate::data::DEFAULT_WALLET_DIR;

const SNAPSHOT_FILE: &str = "coppice-v1.json";

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

fn deployment<P: Parameters>(params: &P) -> anyhow::Result<DeploymentParameters> {
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
        Ok(bytes) => V1Reducer::load_snapshot(deployment.clone(), &bytes)
            .map_err(|error| anyhow!("invalid Coppice snapshot: {error:?}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            initial_reducer(params, client, deployment).await?
        }
        Err(error) => return Err(error.into()),
    };

    let mut canonical = LightwalletdCanonicalSource {
        client: client.clone(),
    };
    let mut transactions = LightwalletdFullTransactionSource {
        client: client.clone(),
    };
    let outcome =
        reconcile_canonical_chain(params, &mut reducer, &mut canonical, &mut transactions)
            .map_err(|error| anyhow!("Coppice canonical reconciliation failed: {error:?}"))?;
    persist_snapshot(&path, &reducer)?;
    Ok(Some(outcome))
}
