#![allow(deprecated)]

use std::{num::NonZeroUsize, str::FromStr};

use age::Identity;
use anyhow::{Context, anyhow};
use clap::{Args, Subcommand, ValueEnum};
use coppice::bond::V1BondProver;
use coppice_librustzcash::{
    IronwoodViewingCapability, OwnerAuthority, PreparedCarrier, RegistrationBondMaterialSource,
    RegistrationOwner, WalletAccountId, WalletBondPrivateMaterial,
    WalletCommitmentTreesIronwoodWitnessSource, WalletCoppiceLockBackend, abandon_registration,
    begin_registration, complete_registration, create_carrier_transaction,
    observe_canonical_commit, prepare_break_bond, prepare_release, prepare_reveal, prepare_update,
    propose_carrier_transaction, record_commit_broadcast, registration_stage, resolve_for_payment,
    with_coppice_spend_guard,
};
use orchard::keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey};
use rand::{RngCore, rngs::OsRng};
use secrecy::ExposeSecret;
use uuid::Uuid;
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        Account, InputSource, WalletRead,
        wallet::{
            ConfirmationsPolicy, LockRequest, SpendingKeys, TargetHeight,
            create_proposed_transactions,
            input_selection::{
                GreedyInputSelector, GreedyInputSelectorError, LockFilter, SpendPolicy,
            },
            propose_transfer,
        },
    },
    fees::{DustOutputPolicy, SplitPolicy, StandardFeeRule, standard::MultiOutputChangeStrategy},
    wallet::{LockOwner, Note, OvkPolicy},
};
use zcash_client_sqlite::{AccountUuid, WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    ShieldedPool,
    consensus::{NetworkType, Parameters},
    value::Zatoshis,
};
use zip321::{Payment, TransactionRequest};

use crate::{
    commands::select_account, config::WalletConfig, data::get_db_paths, remote::ConnectionArgs,
};

const COPPICE_PRESENTATION_SUFFIX: &str = ".zec";

fn normalize_coppice_name(name: &str) -> anyhow::Result<String> {
    let canonical = name
        .strip_suffix(COPPICE_PRESENTATION_SUFFIX)
        .unwrap_or(name);
    if coppice::envelope::valid_name(canonical) {
        Ok(canonical.to_owned())
    } else {
        Err(anyhow!("invalid Coppice name: {name}"))
    }
}

fn display_coppice_name(canonical_name: &str) -> String {
    format!("{canonical_name}{COPPICE_PRESENTATION_SUFFIX}")
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Show or set durable Coppice spend protection.
    Protection(Protection),
    /// Show the local canonical registry and registration stages.
    Status(Status),
    /// Resolve an active name through the synchronized canonical runtime.
    Resolve(Resolve),
    /// Pay a canonical active name through the fail-closed resolver.
    Pay(Pay),
    /// Lock a fresh bond, persist intent, construct and broadcast COMMIT.
    Register(Register),
    /// Observe a semantic COMMIT in canonical runtime state.
    ObserveCommit(ObserveCommit),
    /// Prove, construct and broadcast REVEAL for a canonical COMMIT.
    Reveal(Reveal),
    /// Construct and broadcast an owner-authorized UPDATE.
    Update(Update),
    /// Construct and broadcast an owner-authorized RELEASE.
    Release(Release),
    /// Complete a canonically activated local registration.
    Complete(Complete),
    /// Explicitly abandon a local registration attempt.
    Abandon(Abandon),
    /// Explicitly spend an active bond using its exact owner-scoped lock.
    BreakBond(BreakBond),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProtectionMode {
    Enabled,
    GuardOnly,
    Off,
}

impl From<ProtectionMode> for crate::coppice_support::StoredProtectionMode {
    fn from(value: ProtectionMode) -> Self {
        match value {
            ProtectionMode::Enabled => Self::Enabled,
            ProtectionMode::GuardOnly => Self::GuardOnly,
            ProtectionMode::Off => Self::Off,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct Protection {
    #[arg(value_enum)]
    mode: Option<ProtectionMode>,
}

#[derive(Debug, Args)]
pub(crate) struct Status {}

#[derive(Debug, Args)]
pub(crate) struct Resolve {
    name: String,
}

#[derive(Debug, Args)]
pub(crate) struct Pay {
    account_id: Option<Uuid>,
    #[arg(short, long)]
    identity: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    value: u64,
    #[command(flatten)]
    connection: ConnectionArgs,
}

#[derive(Debug, Args)]
pub(crate) struct Register {
    account_id: Option<Uuid>,
    #[arg(short, long)]
    identity: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    address: String,
    #[command(flatten)]
    connection: ConnectionArgs,
}

#[derive(Debug, Args)]
pub(crate) struct ObserveCommit {
    commitment: String,
}

#[derive(Debug, Args)]
pub(crate) struct Reveal {
    account_id: Option<Uuid>,
    #[arg(short, long)]
    identity: String,
    commitment: String,
    #[command(flatten)]
    connection: ConnectionArgs,
}

#[derive(Debug, Args)]
pub(crate) struct Update {
    account_id: Option<Uuid>,
    #[arg(short, long)]
    identity: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    address: String,
    #[command(flatten)]
    connection: ConnectionArgs,
}

#[derive(Debug, Args)]
pub(crate) struct Release {
    account_id: Option<Uuid>,
    #[arg(short, long)]
    identity: String,
    #[arg(long)]
    name: String,
    #[command(flatten)]
    connection: ConnectionArgs,
}

#[derive(Debug, Args)]
pub(crate) struct Complete {
    account_id: Option<Uuid>,
    commitment: String,
}

#[derive(Debug, Args)]
pub(crate) struct Abandon {
    account_id: Option<Uuid>,
    commitment: String,
}

#[derive(Debug, Args)]
pub(crate) struct BreakBond {
    account_id: Option<Uuid>,
    #[arg(short, long)]
    identity: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    address: String,
    #[arg(long)]
    value: u64,
    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        match self {
            Self::Protection(command) => command.run(wallet_dir),
            Self::Status(command) => command.run(wallet_dir),
            Self::Resolve(command) => command.run(wallet_dir),
            Self::Pay(command) => command.run(wallet_dir).await,
            Self::Register(command) => command.run(wallet_dir).await,
            Self::ObserveCommit(command) => command.run(wallet_dir),
            Self::Reveal(command) => command.run(wallet_dir).await,
            Self::Update(command) => command.run(wallet_dir).await,
            Self::Release(command) => command.run(wallet_dir).await,
            Self::Complete(command) => command.run(wallet_dir),
            Self::Abandon(command) => command.run(wallet_dir),
            Self::BreakBond(command) => command.run(wallet_dir).await,
        }
    }
}

impl Protection {
    fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        if let Some(mode) = self.mode {
            if config.network().network_type() == NetworkType::Main
                && !matches!(mode, ProtectionMode::Off)
            {
                return Err(anyhow!(
                    "Coppice v1 is not deployed on Mainnet; protection mode must remain off"
                ));
            }
            let requested = crate::coppice_support::StoredProtectionMode::from(mode);
            if requested == crate::coppice_support::StoredProtectionMode::Off {
                let (_, db_path) = get_db_paths(wallet_dir.as_ref());
                let mut db = WalletDb::for_path(db_path, config.network(), SystemClock, OsRng)?;
                crate::coppice_support::clear_coppice_advisory_locks(&mut db)?;
            }
            crate::coppice_support::set_protection_mode(wallet_dir.as_ref(), requested)?;
        }
        println!(
            "{:?}",
            crate::coppice_support::protection_mode(&config.network(), wallet_dir.as_ref())?
        );
        Ok(())
    }
}

impl Status {
    fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let mode = crate::coppice_support::protection_mode(&params, wallet_dir.as_ref())?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let db = WalletDb::for_path(db_path, params, (), ())?;
        let mut wallet_accounts = Vec::new();
        for account_id in db.get_account_ids()? {
            let account = db
                .get_account(account_id)?
                .ok_or_else(|| anyhow!("wallet account disappeared during Coppice status"))?;
            let wallet_account_id = account
                .ufvk()
                .and_then(|ufvk| ufvk.orchard())
                .map(|fvk| hex::encode(WalletAccountId::from_orchard_fvk(fvk).to_bytes()));
            wallet_accounts.push(serde_json::json!({
                "account_uuid": account.id().expose_uuid().to_string(),
                "name": account.name(),
                "wallet_account_id": wallet_account_id,
            }));
        }
        let state = match crate::coppice_support::wallet_tip(&db) {
            Ok(host_tip) => crate::coppice_support::load_existing_at_tip(
                &params,
                wallet_dir.as_ref(),
                host_tip.0,
            )?,
            Err(_) => crate::coppice_support::load_existing(&params, wallet_dir.as_ref())?,
        };
        let output = match state {
            Some((_, runtime, pending)) => serde_json::json!({
                "protection": format!("{mode:?}"),
                "tip_height": runtime.tip().height,
                "tip_hash": hex::encode(runtime.tip().block_hash),
                "names": runtime.state().names.len(),
                "pending_protocol_commits": runtime.state().pending.len(),
                "canonical_names": runtime.state().names.keys().map(|name| {
                    serde_json::json!({
                        "name": name,
                        "display_name": display_coppice_name(name),
                    })
                }).collect::<Vec<_>>(),
                "wallet_accounts": wallet_accounts,
                "local_registrations": pending.commitments().map(|commitment| {
                    let registration = pending.get(&commitment).expect("enumerated commitment exists");
                    serde_json::json!({
                        "commitment": hex::encode(commitment),
                        "name": registration.name(),
                        "display_name": display_coppice_name(registration.name()),
                        "account_id": hex::encode(registration.account_id().to_bytes()),
                        "stage": format!("{:?}", registration_stage(registration)),
                    })
                }).collect::<Vec<_>>(),
            }),
            None => serde_json::json!({
                "protection": format!("{mode:?}"),
                "wallet_accounts": wallet_accounts,
            }),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}

impl Resolve {
    fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let name = normalize_coppice_name(&self.name)?;
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let (_, path) = get_db_paths(wallet_dir.as_ref());
        let db = WalletDb::for_path(path, params, SystemClock, OsRng)?;
        let (_, runtime, _) = require_coppice(&params, wallet_dir.as_ref())?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let destination = resolve_for_payment(&host, &runtime, &name)
            .map_err(|error| anyhow!("Coppice name resolution failed: {error:?}"))?;
        println!("{}", String::from_utf8(destination.address)?);
        Ok(())
    }
}

impl crate::commands::wallet::send::PaymentContext for Pay {
    fn spending_account(&self) -> Option<Uuid> {
        self.account_id
    }

    fn age_identities(&self) -> anyhow::Result<Vec<Box<dyn Identity + Send + Sync>>> {
        Ok(age::IdentityFile::from_file(self.identity.clone())?.into_identities()?)
    }

    fn connection_args(&self) -> &ConnectionArgs {
        &self.connection
    }

    fn target_note_count(&self) -> usize {
        4
    }

    fn min_split_output_value(&self) -> u64 {
        10_000_000
    }

    fn require_confirmation(&self) -> bool {
        false
    }

    fn tx_version(&self) -> Option<zcash_primitives::transaction::TxVersion> {
        None
    }
}

impl Pay {
    async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let name = normalize_coppice_name(&self.name)?;
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let (_, path) = get_db_paths(wallet_dir.as_ref());
        let db = WalletDb::for_path(path, params, SystemClock, OsRng)?;
        let (_, runtime, _) = require_coppice(&params, wallet_dir.as_ref())?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let destination = resolve_for_payment(&host, &runtime, &name)
            .map_err(|error| anyhow!("Coppice name resolution failed: {error:?}"))?;
        let recipient = ZcashAddress::from_str(&String::from_utf8(destination.address)?)
            .map_err(|_| anyhow!("canonical Coppice address could not be parsed"))?;
        let request = TransactionRequest::new(vec![Payment::without_memo(
            recipient,
            Zatoshis::from_u64(self.value)?,
        )])?;
        drop(db);
        crate::commands::wallet::send::pay(wallet_dir, self, request).await
    }
}

impl Register {
    async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let name = normalize_coppice_name(&self.name)?;
        let SpendingContext {
            params,
            mut db,
            account_id,
            usk,
            orchard_fvk,
        } = spending_context(wallet_dir.as_ref(), self.account_id, &self.identity)?;
        let (mode, runtime, mut pending) = require_coppice(&params, wallet_dir.as_ref())?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let target = next_target(&runtime)?;
        let prepared = {
            let mut backend = WalletCoppiceLockBackend::new(
                &mut db,
                account_id,
                target,
                &orchard_fvk,
                IronwoodViewingCapability::Spending,
            );
            begin_registration(
                &host,
                &runtime,
                &mut pending,
                WalletAccountId::from_orchard_fvk(&orchard_fvk),
                IronwoodViewingCapability::Spending,
                &mut backend,
                &name,
                self.address.as_bytes(),
                RegistrationOwner::DefaultSoftware(usk.orchard().to_bytes()),
                OsRng,
            )
            .map_err(|error| anyhow!("registration preparation failed: {error:?}"))?
        };
        crate::coppice_support::persist_pending(
            wallet_dir.as_ref(),
            runtime.deployment(),
            &pending,
        )?;
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let txid = construct_and_broadcast(
            &params,
            mode,
            &host,
            &runtime,
            &pending,
            &mut db,
            account_id,
            &orchard_fvk,
            usk,
            prepared.carrier(),
            &mut client,
        )
        .await?;
        record_commit_broadcast(&mut pending, &prepared.commitment, txid.into())
            .map_err(|error| anyhow!("recording COMMIT broadcast failed: {error:?}"))?;
        crate::coppice_support::persist_pending(
            wallet_dir.as_ref(),
            runtime.deployment(),
            &pending,
        )?;
        println!(
            "commitment={} txid={txid}",
            hex::encode(prepared.commitment)
        );
        Ok(())
    }
}

impl ObserveCommit {
    fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();
        let (_, path) = get_db_paths(wallet_dir.as_ref());
        let db = WalletDb::for_path(path, params, SystemClock, OsRng)?;
        let (_, runtime, mut pending) = require_coppice(&params, wallet_dir.as_ref())?;
        let commitment = hex32(&self.commitment)?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let height = observe_canonical_commit(&host, &runtime, &mut pending, &commitment)
            .map_err(|error| anyhow!("canonical COMMIT observation failed: {error:?}"))?;
        crate::coppice_support::persist_pending(
            wallet_dir.as_ref(),
            runtime.deployment(),
            &pending,
        )?;
        println!("{height}");
        Ok(())
    }
}

impl Update {
    async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let name = normalize_coppice_name(&self.name)?;
        let SpendingContext {
            params,
            mut db,
            account_id,
            usk,
            orchard_fvk,
        } = spending_context(wallet_dir.as_ref(), self.account_id, &self.identity)?;
        let (mode, runtime, pending) = require_coppice(&params, wallet_dir.as_ref())?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let prepared = prepare_update(
            &host,
            &runtime,
            &name,
            self.address.as_bytes(),
            OwnerAuthority::DefaultSoftware(usk.orchard().to_bytes()),
        )
        .map_err(|error| anyhow!("UPDATE preparation failed: {error:?}"))?;
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let txid = construct_and_broadcast(
            &params,
            mode,
            &host,
            &runtime,
            &pending,
            &mut db,
            account_id,
            &orchard_fvk,
            usk,
            prepared.carrier(),
            &mut client,
        )
        .await?;
        println!("{txid}");
        Ok(())
    }
}

impl Release {
    async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let name = normalize_coppice_name(&self.name)?;
        let SpendingContext {
            params,
            mut db,
            account_id,
            usk,
            orchard_fvk,
        } = spending_context(wallet_dir.as_ref(), self.account_id, &self.identity)?;
        let (mode, runtime, pending) = require_coppice(&params, wallet_dir.as_ref())?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let prepared = prepare_release(
            &host,
            &runtime,
            &name,
            OwnerAuthority::DefaultSoftware(usk.orchard().to_bytes()),
        )
        .map_err(|error| anyhow!("RELEASE preparation failed: {error:?}"))?;
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let txid = construct_and_broadcast(
            &params,
            mode,
            &host,
            &runtime,
            &pending,
            &mut db,
            account_id,
            &orchard_fvk,
            usk,
            prepared.carrier(),
            &mut client,
        )
        .await?;
        println!("{txid}");
        Ok(())
    }
}

impl Complete {
    fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        lifecycle_remove(wallet_dir, self.account_id, &self.commitment, true)
    }
}

impl Abandon {
    fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        lifecycle_remove(wallet_dir, self.account_id, &self.commitment, false)
    }
}

impl BreakBond {
    async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let name = normalize_coppice_name(&self.name)?;
        let SpendingContext {
            params,
            mut db,
            account_id,
            usk,
            orchard_fvk,
        } = spending_context(wallet_dir.as_ref(), self.account_id, &self.identity)?;
        let (mode, runtime, pending) = require_coppice(&params, wallet_dir.as_ref())?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let proposal = {
            let mut backend = WalletCoppiceLockBackend::new(
                &mut db,
                account_id,
                next_target(&runtime)?,
                &orchard_fvk,
                IronwoodViewingCapability::Spending,
            );
            let plan = prepare_break_bond(
                &host,
                &runtime,
                &name,
                IronwoodViewingCapability::Spending,
                &backend,
            )
            .map_err(|error| anyhow!("Break Bond preparation failed: {error:?}"))?;
            let request = TransactionRequest::new(vec![Payment::without_memo(
                ZcashAddress::from_str(&self.address)
                    .map_err(|_| anyhow!("invalid Break Bond destination"))?,
                Zatoshis::from_u64(self.value)?,
            )])?;
            let input_selector = GreedyInputSelector::new();
            let change_strategy = standard_change_strategy()?;
            let policy = plan.spend_policy();
            let (proposal, _) = with_coppice_spend_guard(
                mode,
                &host,
                &runtime,
                &pending,
                WalletAccountId::from_orchard_fvk(&orchard_fvk),
                IronwoodViewingCapability::Spending,
                &mut backend,
                |backend| {
                    propose_transfer::<
                        _,
                        _,
                        _,
                        _,
                        zcash_client_sqlite::wallet::commitment_tree::Error,
                    >(
                        backend.wallet_db_mut(),
                        &params,
                        account_id,
                        &input_selector,
                        &change_strategy,
                        request,
                        ConfirmationsPolicy::default(),
                        &policy,
                        None,
                        None,
                    )
                },
            )
            .map_err(|error| anyhow!("Break Bond spend guard failed: {error:?}"))?;
            proposal.map_err(|error| anyhow!("Break Bond proposal failed: {error:?}"))?
        };
        let prover = LocalTxProver::bundled();
        let txids = create_proposed_transactions::<
            _,
            _,
            GreedyInputSelectorError,
            _,
            zcash_primitives::transaction::fees::zip317::FeeError,
            zcash_client_sqlite::ReceivedNoteId,
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
        .map_err(|error| anyhow!("Break Bond construction failed: {error:?}"))?;
        if txids.len() != 1 {
            return Err(anyhow!(
                "Break Bond requires exactly one constructed transaction"
            ));
        }
        let txid = *txids.first();
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let txid = crate::submission::broadcast_stored_transaction(&db, &mut client, txid).await?;
        println!("{txid}");
        Ok(())
    }
}

impl Reveal {
    async fn run(self, wallet_dir: Option<String>) -> anyhow::Result<()> {
        let SpendingContext {
            params,
            mut db,
            account_id,
            usk,
            orchard_fvk,
        } = spending_context(wallet_dir.as_ref(), self.account_id, &self.identity)?;
        let (mode, runtime, pending) = require_coppice(&params, wallet_dir.as_ref())?;
        let commitment = hex32(&self.commitment)?;
        let host = crate::coppice_support::wallet_tip(&db)?;
        let target = next_target(&runtime)?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let prover = V1BondProver::new()
            .map_err(|error| anyhow!("v1 BondProof key construction failed: {error:?}"))?;
        let prepared = {
            let mut witness_db = WalletDb::for_path(db_path.clone(), params, SystemClock, OsRng)?;
            let material_db = WalletDb::for_path(db_path, params, SystemClock, OsRng)?;
            let mut material = SqliteBondMaterialSource {
                wallet: material_db,
                target,
                orchard_spending_key: *usk.orchard().to_bytes(),
            };
            let mut witness = WalletCommitmentTreesIronwoodWitnessSource::new(&mut witness_db);
            let mut backend = WalletCoppiceLockBackend::new(
                &mut db,
                account_id,
                target,
                &orchard_fvk,
                IronwoodViewingCapability::Spending,
            );
            prepare_reveal(
                &host,
                &runtime,
                &pending,
                IronwoodViewingCapability::Spending,
                &mut backend,
                &mut witness,
                &mut material,
                &prover,
                &commitment,
                OsRng,
            )
            .map_err(|error| anyhow!("REVEAL preparation failed: {error:?}"))?
        };
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let txid = construct_and_broadcast(
            &params,
            mode,
            &host,
            &runtime,
            &pending,
            &mut db,
            account_id,
            &orchard_fvk,
            usk,
            prepared.carrier(),
            &mut client,
        )
        .await?;
        println!("txid={txid} proof_len={}", prepared.proof_len);
        Ok(())
    }
}

fn lifecycle_remove(
    wallet_dir: Option<String>,
    account: Option<Uuid>,
    commitment: &str,
    complete: bool,
) -> anyhow::Result<()> {
    let config = WalletConfig::read(wallet_dir.as_ref())?;
    let params = config.network();
    let (_, path) = get_db_paths(wallet_dir.as_ref());
    let mut db = WalletDb::for_path(path, params, SystemClock, OsRng)?;
    let account = select_account(&db, account)?;
    let account_id = account.id();
    let orchard_fvk = account
        .ufvk()
        .and_then(|ufvk| ufvk.orchard())
        .cloned()
        .ok_or_else(|| anyhow!("selected account has no Orchard full viewing key"))?;
    let (_, runtime, mut pending) = require_coppice(&params, wallet_dir.as_ref())?;
    let commitment = hex32(commitment)?;
    let selected_wallet_account_id = WalletAccountId::from_orchard_fvk(&orchard_fvk);
    let pending_registration = pending
        .get(&commitment)
        .ok_or_else(|| anyhow!("unknown Coppice registration commitment"))?;
    if pending_registration.account_id() != selected_wallet_account_id {
        return Err(anyhow!(
            "selected wallet account does not own the Coppice registration"
        ));
    }
    let host = crate::coppice_support::wallet_tip(&db)?;
    let mut backend = WalletCoppiceLockBackend::new(
        &mut db,
        account_id,
        next_target(&runtime)?,
        &orchard_fvk,
        IronwoodViewingCapability::FullViewing,
    );
    if complete {
        complete_registration(
            &host,
            &runtime,
            &mut pending,
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            &commitment,
        )
        .map_err(|error| anyhow!("registration completion failed: {error:?}"))?;
    } else {
        abandon_registration(
            &host,
            &runtime,
            &mut pending,
            IronwoodViewingCapability::FullViewing,
            &mut backend,
            &commitment,
        )
        .map_err(|error| anyhow!("registration abandonment failed: {error:?}"))?;
    }
    crate::coppice_support::persist_pending(wallet_dir.as_ref(), runtime.deployment(), &pending)
}

type ConcreteWallet = WalletDb<rusqlite::Connection, crate::data::Network, SystemClock, OsRng>;

struct SpendingContext {
    params: crate::data::Network,
    db: ConcreteWallet,
    account_id: AccountUuid,
    usk: UnifiedSpendingKey,
    orchard_fvk: FullViewingKey,
}

fn spending_context(
    wallet_dir: Option<&String>,
    account_id: Option<Uuid>,
    identity: &str,
) -> anyhow::Result<SpendingContext> {
    let mut config = WalletConfig::read(wallet_dir)?;
    let params = config.network();
    let (_, path) = get_db_paths(wallet_dir);
    let db = WalletDb::for_path(path, params, SystemClock, OsRng)?;
    let account = select_account(&db, account_id)?;
    let account_id = account.id();
    let derivation = account
        .source()
        .key_derivation()
        .ok_or_else(|| anyhow!("cannot spend from a view-only account"))?;
    let identities = age::IdentityFile::from_file(identity.to_owned())?.into_identities()?;
    let seed = config
        .decrypt_seed(
            identities
                .iter()
                .map(|value| value.as_ref() as &dyn Identity),
        )?
        .ok_or_else(|| anyhow!("wallet seed is unavailable"))?;
    let usk =
        UnifiedSpendingKey::from_seed(&params, seed.expose_secret(), derivation.account_index())?;
    let orchard_fvk = FullViewingKey::from(usk.orchard());
    Ok(SpendingContext {
        params,
        db,
        account_id,
        usk,
        orchard_fvk,
    })
}

fn require_coppice<P: Parameters>(
    params: &P,
    wallet_dir: Option<&String>,
) -> anyhow::Result<(
    coppice_librustzcash::CoppiceProtectionMode,
    coppice::names_runtime::NamesRuntime,
    coppice_librustzcash::PendingRegistrationCollection,
)> {
    crate::coppice_support::load_existing(params, wallet_dir)?.ok_or_else(|| {
        anyhow!("Coppice protection is Off; enable it and synchronize before this operation")
    })
}

fn next_target(runtime: &coppice::names_runtime::NamesRuntime) -> anyhow::Result<TargetHeight> {
    Ok(TargetHeight::from(
        runtime
            .tip()
            .height
            .checked_add(1)
            .ok_or_else(|| anyhow!("target height overflow"))?,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn construct_and_broadcast<P: Parameters + Clone>(
    params: &P,
    mode: coppice_librustzcash::CoppiceProtectionMode,
    host: &crate::coppice_support::StaticCanonicalTip,
    runtime: &coppice::names_runtime::NamesRuntime,
    pending: &coppice_librustzcash::PendingRegistrationCollection,
    db: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    account_id: AccountUuid,
    orchard_fvk: &FullViewingKey,
    usk: UnifiedSpendingKey,
    carrier: &PreparedCarrier,
    client: &mut zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<tonic::transport::Channel>,
) -> anyhow::Result<zcash_primitives::transaction::TxId> {
    let input_selector = GreedyInputSelector::new();
    let change_strategy = standard_change_strategy()?;
    let mut owner = [0u8; 32];
    OsRng.fill_bytes(&mut owner);
    let proposal = propose_carrier_transaction::<
        _,
        _,
        _,
        _,
        _,
        zcash_client_sqlite::wallet::commitment_tree::Error,
    >(
        mode,
        host,
        runtime,
        pending,
        IronwoodViewingCapability::Spending,
        db,
        params,
        account_id,
        orchard_fvk,
        &input_selector,
        &change_strategy,
        ConfirmationsPolicy::default(),
        &SpendPolicy::default(),
        Some(LockRequest::new(LockOwner::new(owner), 20)),
        carrier,
    )
    .map_err(|error| anyhow!("Coppice carrier proposal failed: {error:?}"))?;
    let prover = LocalTxProver::bundled();
    let constructed = create_carrier_transaction::<
        _,
        _,
        GreedyInputSelectorError,
        _,
        zcash_primitives::transaction::fees::zip317::FeeError,
        zcash_client_sqlite::ReceivedNoteId,
    >(
        db,
        params,
        &prover,
        &prover,
        &SpendingKeys::from_unified_spending_key(usk),
        OvkPolicy::Sender,
        proposal,
        None,
    )
    .map_err(|error| anyhow!("Coppice carrier construction failed: {error:?}"))?;
    crate::submission::broadcast_stored_transaction(db, client, constructed.txid).await
}

fn standard_change_strategy<P: InputSource>() -> anyhow::Result<MultiOutputChangeStrategy<P>> {
    Ok(MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Orchard,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(4).expect("four is nonzero"),
            zcash_protocol::value::Zatoshis::from_u64(10_000_000)?,
        ),
    ))
}

struct SqliteBondMaterialSource<P> {
    wallet: WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    target: TargetHeight,
    orchard_spending_key: [u8; 32],
}

impl<P: Parameters + Clone> RegistrationBondMaterialSource for SqliteBondMaterialSource<P> {
    type Error = anyhow::Error;

    fn private_material_for(
        &mut self,
        output_id: &coppice_librustzcash::IronwoodOutputId,
    ) -> Result<WalletBondPrivateMaterial, Self::Error> {
        let received = self
            .wallet
            .get_spendable_note(
                &zcash_primitives::transaction::TxId::from_bytes(output_id.txid()),
                ShieldedPool::Ironwood,
                output_id.output_index(),
                self.target,
                LockFilter::Unfiltered,
            )?
            .ok_or_else(|| anyhow!("selected Ironwood bond note is unavailable"))?;
        let note = match received.note() {
            Note::Orchard {
                note,
                pool: orchard::ValuePool::Ironwood,
            } => *note,
            _ => return Err(anyhow!("selected output is not an Ironwood note")),
        };
        let spending_key =
            Option::<SpendingKey>::from(SpendingKey::from_bytes(self.orchard_spending_key))
                .ok_or_else(|| anyhow!("invalid Orchard spending key"))?;
        Ok(WalletBondPrivateMaterial {
            note,
            full_viewing_key: FullViewingKey::from(&spending_key),
            spend_authorizing_key: SpendAuthorizingKey::from(&spending_key),
        })
    }
}

fn hex32(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value).context("expected 32-byte hexadecimal value")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte hexadecimal value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_names_converge_at_the_wallet_boundary() {
        assert_eq!(normalize_coppice_name("alice").unwrap(), "alice");
        assert_eq!(normalize_coppice_name("alice.zec").unwrap(), "alice");
        assert_eq!(display_coppice_name("alice"), "alice.zec");
        assert!(normalize_coppice_name("alice.zec.zec").is_err());
        assert!(normalize_coppice_name("ALICE.zec").is_err());
    }
}
