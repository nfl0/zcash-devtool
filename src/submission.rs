//! Transaction submission boundary shared by ordinary and Coppice carriers.
//!
//! Construction persists a transaction first. This module reads that exact
//! transaction back, serializes it canonically, submits it once, and reports
//! success only after lightwalletd accepts it. Callers advance their own local
//! lifecycle metadata only after this function returns `Ok`.

use anyhow::{Context, anyhow};
use tonic::transport::Channel;
use zcash_client_backend::{
    data_api::WalletRead,
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_primitives::transaction::TxId;

use crate::error;

pub(crate) async fn broadcast_stored_transaction<DbT>(
    wallet: &DbT,
    client: &mut CompactTxStreamerClient<Channel>,
    requested_txid: TxId,
) -> Result<TxId, anyhow::Error>
where
    DbT: WalletRead,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let transaction = wallet
        .get_transaction(requested_txid)?
        .ok_or_else(|| anyhow!("constructed transaction {requested_txid} is unavailable"))?;
    let actual_txid = transaction.txid();
    if actual_txid != requested_txid {
        return Err(anyhow!(
            "stored transaction identity differs from requested txid"
        ));
    }

    let mut raw = service::RawTransaction::default();
    transaction
        .write(&mut raw.data)
        .context("failed to serialize stored transaction")?;
    let response = client.send_transaction(raw).await?.into_inner();
    if response.error_code != 0 {
        return Err(error::Error::SendFailed {
            code: response.error_code,
            reason: response.error_message,
        }
        .into());
    }
    Ok(actual_txid)
}
