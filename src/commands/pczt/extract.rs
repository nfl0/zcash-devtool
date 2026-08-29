use anyhow::anyhow;
use clap::Args;
use pczt::{
    Pczt,
    roles::{spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor},
};
use tokio::io::{AsyncReadExt, stdin};
use zcash_proofs::prover::LocalTxProver;

pub(crate) fn extract_final_transaction(
    pczt: Pczt,
) -> Result<zcash_primitives::transaction::Transaction, anyhow::Error> {
    let prover = LocalTxProver::bundled();
    let (spend_vk, output_vk) = prover.verifying_keys();
    let finalized = SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|e| anyhow!("Failed to finalize PCZT spends: {e:?}"))?;
    TransactionExtractor::new(finalized)
        .with_sapling(&spend_vk, &output_vk)
        .extract()
        .map_err(|e| anyhow!("Failed to extract transaction from PCZT: {e:?}"))
}

// Options accepted for the `pczt extract` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// Print canonical transaction bytes as hexadecimal instead of its txid.
    #[arg(long)]
    raw_hex: bool,
}

impl Command {
    pub(crate) async fn run(self, _wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let tx = extract_final_transaction(pczt)?;
        if self.raw_hex {
            let mut raw = vec![];
            tx.write(&mut raw)
                .map_err(|e| anyhow!("Failed to serialize transaction: {e:?}"))?;
            println!("{}", hex::encode(raw));
        } else {
            println!("{}", tx.txid());
        }
        Ok(())
    }
}
