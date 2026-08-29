use std::path::PathBuf;

use anyhow::anyhow;
use clap::Args;
use pczt::Pczt;
use tokio::{
    fs::File,
    io::{AsyncReadExt, stdin},
};
use zcash_client_backend::data_api::wallet::extract_and_store_transaction_from_pczt;
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_proofs::prover::LocalTxProver;

use crate::{config::WalletConfig, data::get_db_paths, remote::ConnectionArgs};

// Options accepted for the `pczt send` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    #[command(flatten)]
    connection: ConnectionArgs,

    /// Path to a file from which to read the PCZT. If not provided, reads from stdin.
    input: Option<PathBuf>,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, rand::rng())?;

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let mut buf = vec![];
        if let Some(input_path) = &self.input {
            File::open(input_path).await?.read_to_end(&mut buf).await?;
        } else {
            stdin().read_to_end(&mut buf).await?;
        }

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let prover = LocalTxProver::bundled();
        let (spend_vk, output_vk) = prover.verifying_keys();

        let txid = extract_and_store_transaction_from_pczt::<_, ()>(
            &mut db_data,
            pczt,
            Some((&spend_vk, &output_vk)),
            // Passing `None` makes the extractor build an Orchard verifying
            // key for the circuit version the PCZT's consensus branch
            // requires (pre- vs post-NU6.3 circuits differ).
            None,
        )
        .map_err(|e| anyhow!("Failed to extract and store transaction from PCZT: {:?}", e))?;
        // Send the exact stored transaction through the shared lifecycle boundary.
        println!("Sending transaction...");
        let txid =
            crate::submission::broadcast_stored_transaction(&db_data, &mut client, txid).await?;
        println!("{txid}");
        Ok(())
    }
}
