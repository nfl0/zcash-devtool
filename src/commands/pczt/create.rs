#![allow(deprecated)]
use std::{
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
};

use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use tokio::{
    fs::File,
    io::{AsyncWriteExt, stdout},
};
use uuid::Uuid;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        Account as _,
        wallet::{
            ConfirmationsPolicy, create_pczt_from_proposal,
            input_selection::{GreedyInputSelector, SpendPolicy},
            propose_transfer,
        },
    },
    fees::{DustOutputPolicy, SplitPolicy, StandardFeeRule, standard::MultiOutputChangeStrategy},
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_protocol::{
    ShieldedPool,
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

use crate::{commands::select_account, config::WalletConfig, data::get_db_paths, error};

// Options accepted for the `pczt create` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to send funds from
    account_id: Option<Uuid>,

    /// The recipient's Unified, Sapling or transparent address
    #[arg(long)]
    address: String,

    /// The amount in zatoshis
    #[arg(long)]
    value: u64,

    /// A memo to send to the recipient
    #[arg(long, conflicts_with = "memo_hex")]
    memo: Option<String>,

    /// Exact binary memo bytes, encoded as 512-byte hexadecimal.
    ///
    /// This is intended for protocol envelopes that are not text. It is
    /// additive; the normal text-memo path is unchanged.
    #[arg(long, conflicts_with = "memo")]
    memo_hex: Option<String>,

    /// Note management: the number of notes to maintain in the wallet
    #[arg(long)]
    #[arg(default_value_t = 4)]
    target_note_count: usize,

    /// Note management: the minimum allowed value for split change amounts
    #[arg(long)]
    #[arg(default_value_t = 10000000)]
    min_split_output_value: u64,

    /// Path to a file to which to write the PCZT. If not provided, writes to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let account = select_account(&db_data, self.account_id)?;

        // Create the PCZT.
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(self.target_note_count)
                    .ok_or(anyhow!("target note count must be nonzero"))?,
                Zatoshis::from_u64(self.min_split_output_value)?,
            ),
        );
        let input_selector = GreedyInputSelector::new();
        let orchard_fvk = account.ufvk().and_then(|ufvk| ufvk.orchard()).cloned();

        let memo = memo_bytes(self.memo, self.memo_hex)?;
        let request = TransactionRequest::new(vec![
            Payment::new(
                ZcashAddress::from_str(&self.address)
                    .map_err(|_| error::Error::InvalidRecipient)?,
                Some(Zatoshis::from_u64(self.value).map_err(|_| error::Error::InvalidAmount)?),
                memo,
                None,
                None,
                vec![],
            )
            .map_err(|e| e.with_index(0))?,
        ])
        .map_err(error::Error::from)?;

        let proposal = crate::coppice_support::with_spend_protection(
            &params,
            wallet_dir.as_ref(),
            &mut db_data,
            account.id(),
            orchard_fvk.as_ref(),
            |db| {
                propose_transfer(
                    db,
                    &params,
                    account.id(),
                    &input_selector,
                    &change_strategy,
                    request,
                    ConfirmationsPolicy::new_symmetrical(
                        NonZeroU32::new(1).expect("one is nonzero"),
                        true,
                    ),
                    &SpendPolicy::default(),
                    None,
                    None,
                )
            },
        )?
        .map_err(error::Error::from)?;

        let pczt = create_pczt_from_proposal(
            &mut db_data,
            &params,
            account.id(),
            OvkPolicy::Sender,
            &proposal,
            // Use the builder-derived expiry and a standard Orchard-pool bundle.
            None,
            zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        )
        .map_err(error::Error::from)?;

        crate::coppice_support::ensure_external_pczt_respects_coppice(
            &params,
            wallet_dir.as_ref(),
            &pczt,
        )?;

        let pczt_bytes = pczt
            .serialize()
            .map_err(|e| anyhow!("Failed to serialize PCZT: {:?}", e))?;
        if let Some(output_path) = &self.output {
            let mut file = File::create(output_path).await?;
            file.write_all(&pczt_bytes).await?;
            file.flush().await?;
        } else {
            let mut stdout = stdout();
            stdout.write_all(&pczt_bytes).await?;
            stdout.flush().await?;
        }

        Ok(())
    }
}

fn memo_bytes(
    text: Option<String>,
    binary_hex: Option<String>,
) -> Result<Option<MemoBytes>, anyhow::Error> {
    match (text, binary_hex) {
        (Some(memo), None) => Ok(Some(MemoBytes::from(Memo::from_str(&memo)?))),
        (None, Some(hex_memo)) => {
            let bytes = hex::decode(hex_memo).map_err(|_| anyhow!("invalid memo hex"))?;
            Ok(Some(MemoBytes::from_bytes(&bytes)?))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => unreachable!("clap rejects conflicting memo options"),
    }
}

#[cfg(test)]
mod tests {
    use super::memo_bytes;

    #[test]
    fn binary_memo_preserves_non_utf8_bytes() {
        let memo = [0xff; 512];
        assert_eq!(
            memo_bytes(None, Some(hex::encode(memo)))
                .unwrap()
                .unwrap()
                .as_slice(),
            memo
        );
    }
}
