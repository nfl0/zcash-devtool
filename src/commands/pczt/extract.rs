use anyhow::anyhow;
use clap::Args;
use pczt::{
    Pczt,
    roles::{spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor},
};
use tokio::io::{AsyncReadExt, stdin};
use zcash_proofs::prover::LocalTxProver;

// Options accepted for the `pczt extract` command
#[derive(Debug, Args)]
pub(crate) struct Command {}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        if wallet_dir.is_some() {
            let config = crate::config::WalletConfig::read(wallet_dir.as_ref())?;
            crate::coppice_support::ensure_external_pczt_respects_coppice(
                &config.network(),
                wallet_dir.as_ref(),
                &pczt,
            )?;
        }

        let prover = LocalTxProver::bundled();
        let (spend_vk, output_vk) = prover.verifying_keys();

        let finalized = SpendFinalizer::new(pczt)
            .finalize_spends()
            .map_err(|e| anyhow!("Failed to finalize PCZT spends: {e:?}"))?;

        let tx = TransactionExtractor::new(finalized)
            .with_sapling(&spend_vk, &output_vk)
            .extract()
            .map_err(|e| anyhow!("Failed to extract transaction from PCZT: {e:?}"))?;
        let txid = tx.txid();
        println!("{txid}");
        Ok(())
    }
}
