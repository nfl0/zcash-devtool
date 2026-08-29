//! Names v1 Ironwood PCZT-bundle construction with one designated action pair.

use anyhow::{Context, Result, bail, ensure};
use orchard::{
    Address,
    builder::{Builder, BundleType, RequestedActionPair},
    bundle::{BundleVersion, Flags, TxVersion},
    keys::{FullViewingKey, OutgoingViewingKey},
    note::{ExtractedNoteCommitment, Note},
    value::NoteValue,
};
use pczt::roles::{
    creator::Creator, io_finalizer::IoFinalizer, prover::Prover, signer::Signer,
    tx_extractor::TransactionExtractor, updater::Updater,
};
use rand::RngCore;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_primitives::transaction::{
    Transaction, TxId, TxVersion as TransactionVersion,
    builder::PcztParts,
    fees::{FeeRule, transparent::InputSize},
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::Zatoshis;

/// One ordinary CPV1 rendezvous output.
pub struct CarrierOutput {
    pub recipient: Address,
    pub value: NoteValue,
    pub memo: [u8; 512],
}

/// An additional real Ironwood spend used for funding.
pub struct FundingSpend {
    pub fvk: FullViewingKey,
    pub note: Note,
}

/// Wallet-controlled Ironwood change.
pub struct ChangeOutput {
    pub fvk: FullViewingKey,
    pub ovk: Option<OutgoingViewingKey>,
    pub recipient: Address,
    pub value: NoteValue,
    pub memo: [u8; 512],
}

/// Wallet-side intent for a Names v1 Ironwood PCZT bundle.
pub struct NamesV1IronwoodPlan {
    pub designated_fvk: FullViewingKey,
    pub designated_spend: Note,
    /// Exact successor opening already bound by the Names proof.
    pub successor_note: Note,
    pub successor_ovk: Option<OutgoingViewingKey>,
    pub successor_memo: [u8; 512],
    pub carrier_outputs: Vec<CarrierOutput>,
    pub funding_spends: Vec<FundingSpend>,
    pub change_outputs: Vec<ChangeOutput>,
    /// Canonical action index carried by the CNV1 operation.
    pub designated_action_index: usize,
    /// Exact intended canonical height of the Names operation. The later
    /// PCZT expiry height must equal this height.
    pub operation_height: u32,
}

/// The public physical shape of a manually assembled Names v1 Ironwood bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamesV1IronwoodShape {
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub action_count: usize,
}

/// Constructed, unproved Ironwood PCZT bundle and verified layout metadata.
pub struct NamesV1BuiltBundle {
    pub bundle: orchard::pczt::Bundle,
    pub designated_action_index: usize,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    /// Positive value contributed by Ironwood toward the transaction fee or other pools.
    pub ironwood_value_balance: i64,
    /// Exact intended canonical height of the Names operation. The later
    /// PCZT expiry height must equal this height.
    pub operation_height: u32,
}

/// Metadata needed to place an already-built Names v1 bundle into a V6 PCZT.
pub struct NamesV1PcztPlan<P: Parameters> {
    pub ironwood: NamesV1BuiltBundle,
    pub params: P,
    pub consensus_branch_id: BranchId,
    pub expiry_height: BlockHeight,
    pub fallback_lock_time: u32,
}

/// Complete, still-unproved Names v1 PCZT and the metadata needed by later roles.
pub struct NamesV1BuiltPczt {
    pub pczt: pczt::Pczt,
    /// The canonical CNV1 action index, encoded as `u32` at this boundary.
    pub designated_action_index: u32,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub ironwood_value_balance: i64,
}

/// Complete Names v1 PCZT after IO finalization, still without real witnesses, proofs, or
/// real spend authorization signatures.
pub struct NamesV1FinalizedPczt {
    pub pczt: pczt::Pczt,
    /// The canonical CNV1 action index, encoded as `u32` at this boundary.
    pub designated_action_index: u32,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub ironwood_value_balance: i64,
}

/// A wallet-provided real Ironwood spend witness, keyed by its canonical nullifier.
pub struct NamesV1IronwoodWitness {
    pub nullifier: [u8; 32],
    pub merkle_path: orchard::tree::MerklePath,
}

/// Anchor and real-spend witnesses to install into an IO-finalized Names v1 PCZT.
pub struct NamesV1WitnessPlan {
    pub anchor: orchard::Anchor,
    pub spends: Vec<NamesV1IronwoodWitness>,
}

/// Names v1 PCZT after real Ironwood anchor and witness installation.
pub struct NamesV1WitnessedPczt {
    pub pczt: pczt::Pczt,
    pub anchor: orchard::Anchor,
    /// `(nullifier, final PCZT action index)` entries in witness-plan order.
    pub witnessed_action_indices: Vec<([u8; 32], usize)>,
    /// The canonical CNV1 action index, encoded as `u32` at this boundary.
    pub designated_action_index: u32,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub ironwood_value_balance: i64,
}

/// Names v1 PCZT after creating the consensus Ironwood bundle proof.
pub struct NamesV1ProvedPczt {
    pub pczt: pczt::Pczt,
    pub anchor: orchard::Anchor,
    /// `(nullifier, final PCZT action index)` entries in witness-plan order.
    pub witnessed_action_indices: Vec<([u8; 32], usize)>,
    /// The canonical CNV1 action index, encoded as `u32` at this boundary.
    pub designated_action_index: u32,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub ironwood_value_balance: i64,
    pub ironwood_proof_byte_len: usize,
}

/// A real Ironwood spend authorization key, keyed by its canonical nullifier.
pub struct NamesV1IronwoodSigningKey {
    pub nullifier: [u8; 32],
    pub ask: orchard::keys::SpendAuthorizingKey,
}

/// Wallet signing requests for the real Ironwood spends in a Names v1 PCZT.
pub struct NamesV1SigningPlan {
    pub spends: Vec<NamesV1IronwoodSigningKey>,
}

/// Names v1 PCZT after both real Ironwood spends have been authorized.
pub struct NamesV1SignedPczt {
    pub pczt: pczt::Pczt,
    pub anchor: orchard::Anchor,
    /// `(nullifier, final PCZT action index)` entries in witness-plan order.
    pub witnessed_action_indices: Vec<([u8; 32], usize)>,
    /// The canonical CNV1 action index, encoded as `u32` at this boundary.
    pub designated_action_index: u32,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub ironwood_value_balance: i64,
    pub ironwood_proof_byte_len: usize,
}

/// Fully authorized consensus transaction extracted from a signed Names v1 PCZT.
pub struct NamesV1ExtractedTransaction {
    pub transaction: Transaction,
    pub txid: TxId,
    pub consensus_tx_size: usize,
    pub anchor: orchard::Anchor,
    pub designated_action_index: u32,
    pub designated_nullifier: [u8; 32],
    pub designated_commitment: [u8; 32],
    pub action_count: usize,
    pub real_spend_count: usize,
    pub requested_output_count: usize,
    pub carrier_output_count: usize,
    pub change_output_count: usize,
    pub ironwood_value_balance: i64,
    pub ironwood_proof_byte_len: usize,
    pub ironwood_spend_authorization_count: usize,
    pub ironwood_binding_signature_present: bool,
}

struct NamesV1SigningMetadata<'a> {
    anchor: orchard::Anchor,
    witnessed_action_indices: &'a [([u8; 32], usize)],
    designated_action_index: u32,
    designated_nullifier: [u8; 32],
    designated_commitment: [u8; 32],
    action_count: usize,
    real_spend_count: usize,
    ironwood_value_balance: i64,
}

/// Computes the exact requested and padded action counts used by the Orchard
/// builder for a Names v1 plan.
pub fn names_v1_ironwood_shape(plan: &NamesV1IronwoodPlan) -> Result<NamesV1IronwoodShape> {
    let real_spend_count = 1usize
        .checked_add(plan.funding_spends.len())
        .context("Names v1 real-spend count overflowed usize")?;
    names_v1_ironwood_shape_from_counts(
        real_spend_count,
        plan.carrier_outputs.len(),
        plan.change_outputs.len(),
        plan.designated_action_index,
    )
}

/// Computes a Names v1 bundle shape when the note objects are not yet needed.
///
/// `real_spend_count` includes the one designated state-operation spend;
/// `requested_output_count` is therefore one successor output plus the
/// supplied carrier and change counts. The action count is delegated to the
/// same `BundleType::UNPADDED` implementation used by the actual builder.
pub fn names_v1_ironwood_shape_from_counts(
    real_spend_count: usize,
    carrier_output_count: usize,
    change_output_count: usize,
    designated_action_index: usize,
) -> Result<NamesV1IronwoodShape> {
    ensure!(
        real_spend_count > 0,
        "Names v1 bundle must contain a designated real spend"
    );
    let requested_output_count = 1usize
        .checked_add(carrier_output_count)
        .and_then(|count| count.checked_add(change_output_count))
        .context("Names v1 requested-output count overflowed usize")?;
    let action_count = BundleType::UNPADDED
        .num_actions(Flags::ENABLED, real_spend_count, requested_output_count)
        .map_err(|error| anyhow::anyhow!("compute Names v1 Ironwood action count: {error}"))?;
    ensure!(
        designated_action_index < action_count,
        "designated Names action index is outside the planned Ironwood shape"
    );
    Ok(NamesV1IronwoodShape {
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        action_count,
    })
}

/// Computes the conventional ZIP-317 fee for a manually assembled Names v1
/// shielded-only transaction.
///
/// The pinned fee rule receives no transparent inputs or outputs and no
/// Sapling or Orchard actions; the shared physical action count represents the
/// complete Ironwood logical-action contribution.
pub fn required_zip317_fee_for_names_v1<P: Parameters>(
    params: &P,
    target_height: BlockHeight,
    shape: NamesV1IronwoodShape,
) -> Result<Zatoshis> {
    StandardFeeRule::Zip317
        .fee_required(
            params,
            target_height,
            std::iter::empty::<InputSize>(),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            shape.action_count,
        )
        .map_err(|error| anyhow::anyhow!("compute ZIP-317 Names v1 fee: {error:?}"))
}

/// Builds the Ironwood portion of a Names v1 PCZT without proving or signing.
pub fn build_names_v1_bundle(
    plan: NamesV1IronwoodPlan,
    rng: impl RngCore,
) -> Result<NamesV1BuiltBundle> {
    let shape = names_v1_ironwood_shape(&plan)?;
    let designated_nullifier = plan.designated_spend.nullifier(&plan.designated_fvk);
    let designated_commitment = ExtractedNoteCommitment::from(plan.successor_note.commitment());
    ensure!(
        plan.successor_note.rho().to_bytes() == designated_nullifier.to_bytes(),
        "successor rho does not derive from the designated input nullifier"
    );

    let mut builder = Builder::new_with_anchor_deferred(
        BundleType::UNPADDED,
        BundleVersion::ironwood_v3(),
        Flags::ENABLED,
        TxVersion::V6,
    )
    .context("create deferred-anchor Ironwood builder")?;
    builder
        .add_spend_unwitnessed(plan.designated_fvk, plan.designated_spend)
        .context("add designated Names spend")?;
    for funding in plan.funding_spends {
        builder
            .add_spend_unwitnessed(funding.fvk, funding.note)
            .context("add Ironwood funding spend")?;
    }

    builder
        .add_output_note(plan.successor_ovk, plan.successor_note, plan.successor_memo)
        .context("add exact Names successor note")?;
    for carrier in plan.carrier_outputs {
        builder
            .add_output(None, carrier.recipient, carrier.value, carrier.memo)
            .context("add CPV1 carrier output")?;
    }
    for change in plan.change_outputs {
        builder
            .add_change_output(
                change.fvk,
                change.ovk,
                change.recipient,
                change.value,
                change.memo,
            )
            .context("add Ironwood change output")?;
    }
    let ironwood_value_balance = builder
        .value_balance::<i64>()
        .context("compute Ironwood value balance")?;

    let (bundle, metadata) = builder
        .build_for_pczt_with_action_pair(
            rng,
            RequestedActionPair {
                spend_index: 0,
                output_index: 0,
                action_index: plan.designated_action_index,
            },
        )
        .context("build designated-pair Ironwood PCZT bundle")?;
    ensure!(
        metadata.spend_action_index(0) == Some(plan.designated_action_index)
            && metadata.output_action_index(0) == Some(plan.designated_action_index),
        "builder metadata did not preserve the designated pair"
    );
    verify_designated_action(
        &bundle,
        plan.designated_action_index,
        designated_nullifier.to_bytes(),
        designated_commitment.to_bytes(),
    )?;

    let matching_actions = bundle
        .actions()
        .iter()
        .filter(|action| {
            action.spend().nullifier().to_bytes() == designated_nullifier.to_bytes()
                && action.output().cmx().to_bytes() == designated_commitment.to_bytes()
        })
        .count();
    ensure!(
        matching_actions == 1,
        "designated NF/CMX pair is not unique"
    );

    let action_count = bundle.actions().len();
    ensure!(
        action_count == shape.action_count,
        "built Ironwood action count differs from the planned shape"
    );
    Ok(NamesV1BuiltBundle {
        bundle,
        designated_action_index: plan.designated_action_index,
        designated_nullifier: designated_nullifier.to_bytes(),
        designated_commitment: designated_commitment.to_bytes(),
        action_count,
        real_spend_count: shape.real_spend_count,
        requested_output_count: shape.requested_output_count,
        carrier_output_count: shape.carrier_output_count,
        change_output_count: shape.change_output_count,
        ironwood_value_balance,
        operation_height: plan.operation_height,
    })
}

/// Embeds a prebuilt, deferred-anchor Ironwood bundle into a complete V6 PCZT.
///
/// `Creator::build_from_parts` is the pinned PCZT injection path: its
/// `PcztParts::ironwood` field accepts the existing `orchard::pczt::Bundle` and
/// converts its fields into the top-level PCZT bundle without rebuilding the
/// actions.
pub fn build_names_v1_pczt<P: Parameters>(plan: NamesV1PcztPlan<P>) -> Result<NamesV1BuiltPczt> {
    let NamesV1PcztPlan {
        ironwood,
        params,
        consensus_branch_id,
        expiry_height,
        fallback_lock_time,
    } = plan;
    ensure!(
        consensus_branch_id == BranchId::Nu6_3,
        "Names v1 Ironwood PCZT requires the NU6.3 V6 consensus branch"
    );

    let NamesV1BuiltBundle {
        bundle,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
        operation_height,
    } = ironwood;
    ensure!(
        expiry_height == BlockHeight::from_u32(operation_height),
        "Names v1 PCZT expiry height {expiry_height} does not equal the operation's intended height {operation_height}"
    );
    let designated_action_index = u32::try_from(designated_action_index)
        .context("convert designated Names action index to CNV1 u32")?;
    let source_action_layout = action_pair_layout(&bundle);

    let pczt = Creator::build_from_parts(PcztParts {
        params,
        version: TransactionVersion::V6,
        consensus_branch_id,
        lock_time: fallback_lock_time,
        expiry_height,
        transparent: None,
        sapling: None,
        orchard: None,
        ironwood: Some(bundle),
    })
    .ok_or_else(|| anyhow::anyhow!("V6 transaction parts are incompatible with PCZTs"))?;

    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;
    ensure!(
        embedded_action_layout(&pczt)? == source_action_layout,
        "Creator changed the Ironwood action ordering or NF/CMX fields"
    );
    ensure!(
        pczt.ironwood().actions().len() == action_count,
        "embedded Ironwood action count changed"
    );
    ensure!(
        *pczt.ironwood().value_sum() == value_sum_parts(ironwood_value_balance)?,
        "embedded Ironwood value balance changed"
    );

    Ok(NamesV1BuiltPczt {
        pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    })
}

/// Runs the pinned PCZT IO Finalizer over a complete Names v1 V6 PCZT.
pub fn finalize_names_v1_pczt_io(built: NamesV1BuiltPczt) -> Result<NamesV1FinalizedPczt> {
    let NamesV1BuiltPczt {
        pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    } = built;
    let before_action_layout = embedded_action_layout(&pczt)?;
    let before_action_count = pczt.ironwood().actions().len();
    ensure!(
        before_action_count == action_count,
        "pre-finalization Ironwood action count changed"
    );
    ensure!(
        *pczt.ironwood().value_sum() == value_sum_parts(ironwood_value_balance)?,
        "pre-finalization Ironwood value balance changed"
    );

    let pczt = IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|error| anyhow::anyhow!("finalize Names v1 PCZT IO: {error:?}"))?;

    ensure!(
        pczt.ironwood().actions().len() == before_action_count,
        "IO finalization changed the Ironwood action count"
    );
    ensure!(
        embedded_action_layout(&pczt)? == before_action_layout,
        "IO finalization changed the ordered Ironwood action layout"
    );
    ensure!(
        *pczt.ironwood().value_sum() == value_sum_parts(ironwood_value_balance)?,
        "IO finalization changed the Ironwood value balance"
    );
    ensure!(
        !pczt.global().inputs_modifiable()
            && !pczt.global().outputs_modifiable()
            && !pczt.global().shielded_modifiable(),
        "IO finalization left transaction effects modifiable"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;

    Ok(NamesV1FinalizedPczt {
        pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    })
}

/// Installs a real Ironwood anchor and witnesses after IO finalization.
///
/// The pinned PCZT updater stores the supplied witness path bytes and does not
/// recompute their roots at this redaction-friendly PCZT boundary. Callers
/// should therefore derive the plan from a trusted commitment-tree fixture or
/// wallet tree; this helper verifies the structural mapping and preserves all
/// existing dummy state.
pub fn install_names_v1_ironwood_witnesses(
    finalized: NamesV1FinalizedPczt,
    plan: NamesV1WitnessPlan,
) -> Result<NamesV1WitnessedPczt> {
    let NamesV1FinalizedPczt {
        pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    } = finalized;
    let NamesV1WitnessPlan { anchor, spends } = plan;

    let before_action_layout = embedded_action_layout(&pczt)?;
    let before_action_count = pczt.ironwood().actions().len();
    ensure!(
        before_action_count == action_count,
        "pre-update Ironwood action count changed"
    );
    ensure!(
        *pczt.ironwood().value_sum() == value_sum_parts(ironwood_value_balance)?,
        "pre-update Ironwood value balance changed"
    );

    // The IO-finalized funded fixture distinguishes the two real spends from
    // the eleven padding spends by their absent witnesses. This also prevents
    // a witness plan from silently omitting a real spend or targeting padding.
    let real_action_indices = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, action)| action.spend().witness().is_none())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ensure!(
        real_action_indices.len() == real_spend_count,
        "unexpected number of unwitnessed real Ironwood spends"
    );
    ensure!(
        spends.len() == real_action_indices.len(),
        "witness plan does not cover exactly the real Ironwood spends"
    );

    let dummy_state = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(index, action)| {
            let witness = action.spend().witness().as_ref().copied()?;
            Some((
                index,
                witness,
                action.spend().spend_auth_sig().as_ref().copied(),
            ))
        })
        .collect::<Vec<_>>();

    let mut updater_witnesses = Vec::with_capacity(spends.len());
    let mut expected_witnesses = Vec::with_capacity(spends.len());
    let mut witnessed_action_indices = Vec::with_capacity(spends.len());
    for witness in spends {
        let mut matching_actions = pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| *action.spend().nullifier() == witness.nullifier);
        let Some((action_index, action)) = matching_actions.next() else {
            bail!(
                "Ironwood witness nullifier is absent from the PCZT: {:02x?}",
                witness.nullifier
            );
        };
        ensure!(
            matching_actions.next().is_none(),
            "Ironwood witness nullifier occurs more than once in the PCZT"
        );
        ensure!(
            action.spend().witness().is_none(),
            "Ironwood witness target already has a witness (or is a padding spend)"
        );
        ensure!(
            !witnessed_action_indices
                .iter()
                .any(|(_, resolved_index)| *resolved_index == action_index),
            "witness plan contains duplicate Ironwood spend targets"
        );

        let expected_witness = (
            witness.merkle_path.position(),
            witness.merkle_path.auth_path().map(|node| node.to_bytes()),
        );
        updater_witnesses.push((action_index, witness.merkle_path));
        expected_witnesses.push((action_index, expected_witness));
        witnessed_action_indices.push((witness.nullifier, action_index));
    }

    let mut resolved_action_indices = witnessed_action_indices
        .iter()
        .map(|(_, index)| *index)
        .collect::<Vec<_>>();
    resolved_action_indices.sort_unstable();
    ensure!(
        resolved_action_indices == real_action_indices,
        "witness plan did not resolve exactly the real Ironwood spends"
    );

    let pczt = Updater::new(pczt)
        .set_ironwood_anchor(anchor)
        .map_err(|error| anyhow::anyhow!("set Names v1 Ironwood anchor: {error:?}"))?
        .set_ironwood_spend_witnesses(updater_witnesses)
        .map_err(|error| anyhow::anyhow!("set Names v1 Ironwood spend witnesses: {error:?}"))?
        .finish();

    let expected_anchor = anchor.to_bytes();
    ensure!(
        pczt.ironwood().anchor().as_ref() == Some(&expected_anchor),
        "Updater did not install the requested Ironwood anchor"
    );
    ensure!(
        pczt.ironwood().actions().len() == before_action_count,
        "Updater changed the Ironwood action count"
    );
    ensure!(
        embedded_action_layout(&pczt)? == before_action_layout,
        "Updater changed the ordered Ironwood action layout"
    );
    ensure!(
        *pczt.ironwood().value_sum() == value_sum_parts(ironwood_value_balance)?,
        "Updater changed the Ironwood value balance"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;

    for (action_index, expected_witness) in expected_witnesses {
        ensure!(
            pczt.ironwood().actions()[action_index]
                .spend()
                .witness()
                .as_ref()
                == Some(&expected_witness),
            "Updater did not install the expected Ironwood witness"
        );
    }
    for (action_index, expected_witness, expected_signature) in dummy_state {
        let action = &pczt.ironwood().actions()[action_index];
        ensure!(
            action.spend().witness().as_ref() == Some(&expected_witness),
            "Updater changed a dummy Ironwood witness"
        );
        ensure!(
            action.spend().spend_auth_sig().as_ref().copied() == expected_signature,
            "Updater changed a dummy Ironwood spend signature"
        );
    }

    Ok(NamesV1WitnessedPczt {
        pczt,
        anchor,
        witnessed_action_indices,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    })
}

/// Creates the consensus Ironwood proof for an anchored, witnessed Names v1 PCZT.
///
/// The pinned Prover performs the authoritative witness-root check immediately
/// before invoking the Ironwood circuit. This wrapper only checks cheap PCZT
/// structure before and after that operation.
pub fn prove_names_v1_ironwood_pczt(
    witnessed: NamesV1WitnessedPczt,
    proving_key: &orchard::circuit::ProvingKey,
) -> Result<NamesV1ProvedPczt> {
    let NamesV1WitnessedPczt {
        pczt,
        anchor,
        witnessed_action_indices,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    } = witnessed;
    let before_action_layout = embedded_action_layout(&pczt)?;
    let before_action_count = pczt.ironwood().actions().len();
    let before_value_balance = *pczt.ironwood().value_sum();
    let expected_anchor = anchor.to_bytes();

    ensure!(
        pczt.ironwood().zkproof().is_none(),
        "Ironwood proof is already present"
    );
    ensure!(
        pczt.ironwood().anchor().as_ref() == Some(&expected_anchor),
        "witnessed PCZT anchor does not match the expected anchor"
    );
    ensure!(
        before_action_count == action_count,
        "pre-proof Ironwood action count changed"
    );
    ensure!(
        before_value_balance == value_sum_parts(ironwood_value_balance)?,
        "pre-proof Ironwood value balance changed"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;

    let mut real_action_indices = witnessed_action_indices
        .iter()
        .map(|(_, action_index)| *action_index)
        .collect::<Vec<_>>();
    ensure!(
        real_action_indices.len() == real_spend_count,
        "witness metadata does not cover exactly the real Ironwood spends"
    );
    real_action_indices.sort_unstable();
    ensure!(
        real_action_indices
            .windows(2)
            .all(|indices| indices[0] != indices[1]),
        "witness metadata contains duplicate real Ironwood spends"
    );
    for action_index in &real_action_indices {
        let action = &pczt.ironwood().actions()[*action_index];
        ensure!(
            action.spend().witness().is_some(),
            "a real Ironwood spend is missing its witness before proving"
        );
        ensure!(
            action.spend().spend_auth_sig().is_none(),
            "a real Ironwood spend is already signed before proving"
        );
    }

    let dummy_signatures = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(action_index, action)| {
            action
                .spend()
                .spend_auth_sig()
                .as_ref()
                .copied()
                .map(|signature| (action_index, signature))
        })
        .collect::<Vec<_>>();
    ensure!(
        dummy_signatures.len()
            == action_count
                .checked_sub(real_spend_count)
                .context("real spend count exceeds Ironwood action count")?,
        "unexpected number of pre-existing dummy Ironwood signatures"
    );

    let pczt = Prover::new(pczt)
        .create_ironwood_proof(proving_key)
        .map_err(|error| anyhow::anyhow!("create Names v1 Ironwood proof: {error:?}"))?
        .finish();

    let proof_byte_len = pczt
        .ironwood()
        .zkproof()
        .as_ref()
        .map(Vec::len)
        .context("Prover returned no Ironwood proof")?;
    ensure!(
        proof_byte_len > 0,
        "Prover returned an empty Ironwood proof"
    );
    ensure!(
        pczt.ironwood().actions().len() == before_action_count,
        "Prover changed the Ironwood action count"
    );
    ensure!(
        embedded_action_layout(&pczt)? == before_action_layout,
        "Prover changed the ordered Ironwood action layout"
    );
    ensure!(
        *pczt.ironwood().value_sum() == before_value_balance,
        "Prover changed the Ironwood value balance"
    );
    ensure!(
        pczt.ironwood().anchor().as_ref() == Some(&expected_anchor),
        "Prover changed the Ironwood anchor"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;
    for action_index in &real_action_indices {
        let action = &pczt.ironwood().actions()[*action_index];
        ensure!(
            action.spend().witness().is_some(),
            "Prover removed a real Ironwood spend witness"
        );
        ensure!(
            action.spend().spend_auth_sig().is_none(),
            "Prover signed a real Ironwood spend"
        );
    }
    for (action_index, expected_signature) in dummy_signatures {
        ensure!(
            pczt.ironwood().actions()[action_index]
                .spend()
                .spend_auth_sig()
                .as_ref()
                .copied()
                == Some(expected_signature),
            "Prover changed a dummy Ironwood spend signature"
        );
    }

    Ok(NamesV1ProvedPczt {
        pczt,
        anchor,
        witnessed_action_indices,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
        ironwood_proof_byte_len: proof_byte_len,
    })
}

/// Signs the two real Ironwood spends in a proved Names v1 PCZT.
pub fn sign_names_v1_ironwood_pczt(
    proved: NamesV1ProvedPczt,
    plan: NamesV1SigningPlan,
) -> Result<NamesV1SignedPczt> {
    let NamesV1ProvedPczt {
        pczt,
        anchor,
        witnessed_action_indices,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
        ironwood_proof_byte_len,
    } = proved;
    let proof_byte_len = pczt
        .ironwood()
        .zkproof()
        .as_ref()
        .map(Vec::len)
        .context("proved PCZT has no Ironwood proof")?;
    ensure!(
        proof_byte_len > 0,
        "proved PCZT has an empty Ironwood proof"
    );
    ensure!(
        proof_byte_len == ironwood_proof_byte_len,
        "proved PCZT Ironwood proof length differs from its metadata"
    );

    let pczt = sign_names_v1_ironwood_pczt_core(
        pczt,
        NamesV1SigningMetadata {
            anchor,
            witnessed_action_indices: &witnessed_action_indices,
            designated_action_index,
            designated_nullifier,
            designated_commitment,
            action_count,
            real_spend_count,
            ironwood_value_balance,
        },
        plan,
    )?;

    ensure!(
        pczt.ironwood().zkproof().as_ref().map(Vec::len) == Some(proof_byte_len),
        "signed PCZT Ironwood proof length changed"
    );

    Ok(NamesV1SignedPczt {
        pczt,
        anchor,
        witnessed_action_indices,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
        ironwood_proof_byte_len,
    })
}

/// Applies real Ironwood signatures while keeping the same logic usable by the
/// cheap unproved fixture test. The public wrapper above additionally requires
/// the consensus proof carried by `NamesV1ProvedPczt`.
fn sign_names_v1_ironwood_pczt_core(
    pczt: pczt::Pczt,
    metadata: NamesV1SigningMetadata<'_>,
    plan: NamesV1SigningPlan,
) -> Result<pczt::Pczt> {
    let NamesV1SigningMetadata {
        anchor,
        witnessed_action_indices,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        ironwood_value_balance,
    } = metadata;
    ensure!(
        real_spend_count == 2,
        "Names v1 Ironwood signing requires exactly two real spends"
    );

    let before_action_layout = embedded_action_layout(&pczt)?;
    let before_action_count = pczt.ironwood().actions().len();
    let before_value_balance = *pczt.ironwood().value_sum();
    let before_anchor = *pczt.ironwood().anchor();
    let before_proof = pczt.ironwood().zkproof().clone();
    let expected_anchor = anchor.to_bytes();

    ensure!(
        before_anchor.as_ref() == Some(&expected_anchor),
        "signing PCZT anchor does not match the expected anchor"
    );
    ensure!(
        before_action_count == action_count,
        "pre-sign Ironwood action count changed"
    );
    ensure!(
        before_value_balance == value_sum_parts(ironwood_value_balance)?,
        "pre-sign Ironwood value balance changed"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;

    let mut witnessed_indices = Vec::with_capacity(witnessed_action_indices.len());
    for (position, (nullifier, action_index)) in witnessed_action_indices.iter().enumerate() {
        ensure!(
            *action_index < before_action_count,
            "witness metadata contains an invalid Ironwood action index"
        );
        ensure!(
            !witnessed_action_indices[..position]
                .iter()
                .any(|(prior_nullifier, _)| prior_nullifier == nullifier),
            "witness metadata contains duplicate real-spend nullifiers"
        );
        ensure!(
            !witnessed_indices.contains(action_index),
            "witness metadata contains duplicate real-spend action indices"
        );
        let action = &pczt.ironwood().actions()[*action_index];
        ensure!(
            *action.spend().nullifier() == *nullifier,
            "witness metadata nullifier does not match its Ironwood action"
        );
        ensure!(
            action.spend().witness().is_some(),
            "a real Ironwood spend is missing its witness before signing"
        );
        ensure!(
            action.spend().spend_auth_sig().is_none(),
            "a real Ironwood spend is already signed before signing"
        );
        witnessed_indices.push(*action_index);
    }
    ensure!(
        witnessed_indices.len() == real_spend_count,
        "witness metadata does not cover exactly the real Ironwood spends"
    );

    let dummy_signatures = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(action_index, action)| {
            action
                .spend()
                .spend_auth_sig()
                .as_ref()
                .copied()
                .map(|signature| (action_index, signature))
        })
        .collect::<Vec<_>>();
    ensure!(
        dummy_signatures.len()
            == action_count
                .checked_sub(real_spend_count)
                .context("real spend count exceeds Ironwood action count")?,
        "unexpected number of pre-existing Ironwood spend signatures"
    );

    let NamesV1SigningPlan { spends } = plan;
    ensure!(
        spends.len() == real_spend_count,
        "signing plan does not cover exactly the real Ironwood spends"
    );
    let mut signing_targets = Vec::with_capacity(spends.len());
    for signing_key in &spends {
        let mut matching_actions = witnessed_action_indices
            .iter()
            .filter(|(nullifier, _)| *nullifier == signing_key.nullifier);
        let Some((_, action_index)) = matching_actions.next() else {
            bail!(
                "signing nullifier is not one of the real witnessed Ironwood spends: {:02x?}",
                signing_key.nullifier
            );
        };
        ensure!(
            matching_actions.next().is_none(),
            "signing nullifier maps to more than one witnessed Ironwood spend"
        );
        ensure!(
            !signing_targets.iter().any(
                |(resolved_index, _): &(usize, &orchard::keys::SpendAuthorizingKey)| {
                    *resolved_index == *action_index
                }
            ),
            "signing plan contains a duplicate real-spend target"
        );
        ensure!(
            *pczt.ironwood().actions()[*action_index].spend().nullifier() == signing_key.nullifier,
            "resolved signing action has an unexpected nullifier"
        );
        signing_targets.push((*action_index, &signing_key.ask));
    }

    let mut resolved_indices = signing_targets
        .iter()
        .map(|(action_index, _)| *action_index)
        .collect::<Vec<_>>();
    resolved_indices.sort_unstable();
    witnessed_indices.sort_unstable();
    ensure!(
        resolved_indices == witnessed_indices,
        "signing plan does not cover every real witnessed Ironwood spend"
    );

    let mut signer = Signer::new(pczt)
        .map_err(|error| anyhow::anyhow!("initialize Names v1 PCZT signer: {error:?}"))?;
    for (action_index, ask) in signing_targets {
        signer
            .sign_ironwood(action_index, ask)
            .map_err(|error| anyhow::anyhow!("sign Names v1 Ironwood spend: {error:?}"))?;
    }
    let pczt = signer.finish();

    ensure!(
        pczt.ironwood().actions().len() == before_action_count,
        "Signer changed the Ironwood action count"
    );
    ensure!(
        embedded_action_layout(&pczt)? == before_action_layout,
        "Signer changed the ordered Ironwood action layout"
    );
    ensure!(
        *pczt.ironwood().value_sum() == before_value_balance,
        "Signer changed the Ironwood value balance"
    );
    ensure!(
        pczt.ironwood().anchor() == &before_anchor,
        "Signer changed the Ironwood anchor"
    );
    ensure!(
        pczt.ironwood().zkproof() == &before_proof,
        "Signer changed the Ironwood proof"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;

    for action_index in &witnessed_indices {
        let action = &pczt.ironwood().actions()[*action_index];
        ensure!(
            action.spend().witness().is_some(),
            "Signer removed a real Ironwood spend witness"
        );
        ensure!(
            action.spend().spend_auth_sig().is_some(),
            "Signer did not authorize a real Ironwood spend"
        );
    }
    for (action_index, expected_signature) in dummy_signatures {
        ensure!(
            pczt.ironwood().actions()[action_index]
                .spend()
                .spend_auth_sig()
                .as_ref()
                .copied()
                == Some(expected_signature),
            "Signer changed a dummy Ironwood spend signature"
        );
    }
    ensure!(
        pczt.ironwood()
            .actions()
            .iter()
            .filter(|action| action.spend().spend_auth_sig().is_some())
            .count()
            == action_count,
        "Signer did not authorize every Ironwood action"
    );

    Ok(pczt)
}

/// Extracts a fully authorized consensus transaction from a signed Names v1 PCZT.
///
/// The pinned Transaction Extractor creates the Ironwood binding signature and performs the
/// authoritative consensus proof and spend-signature verification before returning a frozen
/// transaction. This wrapper checks only the cheap Names-specific invariants around that role.
pub fn extract_names_v1_transaction(
    signed: NamesV1SignedPczt,
) -> Result<NamesV1ExtractedTransaction> {
    let NamesV1SignedPczt {
        pczt,
        anchor,
        witnessed_action_indices: _,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
        ironwood_proof_byte_len,
    } = signed;

    let proof_bytes = pczt
        .ironwood()
        .zkproof()
        .clone()
        .context("signed PCZT has no Ironwood proof")?;
    ensure!(
        !proof_bytes.is_empty(),
        "signed PCZT has an empty Ironwood proof"
    );
    ensure!(
        proof_bytes.len() == ironwood_proof_byte_len,
        "signed PCZT Ironwood proof length differs from its metadata"
    );

    let before_action_layout = embedded_action_layout(&pczt)?;
    let before_action_count = pczt.ironwood().actions().len();
    let before_value_balance = *pczt.ironwood().value_sum();
    let expected_anchor = anchor.to_bytes();
    ensure!(
        before_action_count == action_count,
        "pre-extraction Ironwood action count changed"
    );
    ensure!(
        before_value_balance == value_sum_parts(ironwood_value_balance)?,
        "pre-extraction Ironwood value balance changed"
    );
    ensure!(
        pczt.ironwood().anchor().as_ref() == Some(&expected_anchor),
        "signed PCZT anchor does not match its metadata"
    );
    verify_embedded_designated_action(
        &pczt,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
    )?;

    let pre_extraction_spend_authorization_count = pczt
        .ironwood()
        .actions()
        .iter()
        .filter(|action| action.spend().spend_auth_sig().is_some())
        .count();
    ensure!(
        pre_extraction_spend_authorization_count == action_count,
        "not every Ironwood action has a spend authorization before extraction"
    );

    let transaction = TransactionExtractor::new(pczt)
        .extract()
        .map_err(|error| anyhow::anyhow!("extract Names v1 consensus transaction: {error:?}"))?;

    ensure!(
        transaction.version() == TransactionVersion::V6,
        "extracted transaction is not V6"
    );
    let ironwood = transaction
        .ironwood_bundle()
        .context("extracted transaction has no Ironwood bundle")?;
    let after_action_count = ironwood.actions().len();
    ensure!(
        after_action_count == before_action_count,
        "transaction extraction changed the Ironwood action count"
    );
    let after_action_layout = transaction_action_layout(&transaction)?;
    ensure!(
        after_action_layout == before_action_layout,
        "transaction extraction changed the ordered Ironwood action layout"
    );

    let designated_action_index_usize = usize::try_from(designated_action_index)
        .context("convert extracted CNV1 action index to usize")?;
    let designated_action = ironwood
        .actions()
        .get(designated_action_index_usize)
        .context("extracted designated action index is outside the Ironwood bundle")?;
    ensure!(
        designated_action.nullifier().to_bytes() == designated_nullifier,
        "extracted designated action nullifier mismatch"
    );
    ensure!(
        designated_action.cmx().to_bytes() == designated_commitment,
        "extracted designated action commitment mismatch"
    );
    let matching_designated_pairs = after_action_layout
        .iter()
        .filter(|(nullifier, commitment)| {
            *nullifier == designated_nullifier && *commitment == designated_commitment
        })
        .count();
    ensure!(
        matching_designated_pairs == 1,
        "extracted designated NF/CMX pair is not unique"
    );

    let after_value_balance = i64::from(ironwood.value_balance());
    ensure!(
        after_value_balance == ironwood_value_balance,
        "transaction extraction changed the Ironwood value balance"
    );
    ensure!(
        ironwood.anchor() == &anchor,
        "transaction extraction changed the Ironwood anchor"
    );
    let extracted_proof = ironwood.authorization().proof();
    ensure!(
        !extracted_proof.as_ref().is_empty(),
        "extracted Ironwood proof is empty"
    );
    ensure!(
        extracted_proof.as_ref() == proof_bytes.as_slice(),
        "transaction extraction changed the Ironwood proof bytes"
    );
    let ironwood_spend_authorization_count = ironwood.actions().len();
    ensure!(
        ironwood_spend_authorization_count == action_count,
        "extracted transaction does not contain every Ironwood spend authorization"
    );
    let ironwood_binding_signature_present = {
        let _binding_signature = ironwood.authorization().binding_signature();
        true
    };

    let serialized_transaction = serialize_consensus_transaction(&transaction)?;
    let consensus_tx_size = serialized_transaction.len();

    Ok(NamesV1ExtractedTransaction {
        txid: transaction.txid(),
        transaction,
        consensus_tx_size,
        anchor,
        designated_action_index,
        designated_nullifier,
        designated_commitment,
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
        ironwood_proof_byte_len,
        ironwood_spend_authorization_count,
        ironwood_binding_signature_present,
    })
}

/// Verifies the exact physical action relation expected by the Names host.
pub fn verify_designated_action(
    bundle: &orchard::pczt::Bundle,
    action_index: usize,
    expected_nullifier: [u8; 32],
    expected_commitment: [u8; 32],
) -> Result<()> {
    let Some(action) = bundle.actions().get(action_index) else {
        bail!("designated action index is outside the Ironwood bundle");
    };
    ensure!(
        action.spend().nullifier().to_bytes() == expected_nullifier,
        "designated action nullifier mismatch"
    );
    ensure!(
        action.output().cmx().to_bytes() == expected_commitment,
        "designated action commitment mismatch"
    );
    Ok(())
}

/// Re-verifies a designated action after it has been embedded in the complete PCZT.
pub fn verify_embedded_designated_action(
    pczt: &pczt::Pczt,
    action_index: u32,
    expected_nullifier: [u8; 32],
    expected_commitment: [u8; 32],
) -> Result<()> {
    let action_index =
        usize::try_from(action_index).context("convert embedded CNV1 action index to usize")?;
    let action = pczt
        .ironwood()
        .actions()
        .get(action_index)
        .context("embedded designated action index is outside the Ironwood bundle")?;
    ensure!(
        *action.spend().nullifier() == expected_nullifier,
        "embedded designated action nullifier mismatch"
    );
    let commitment = action
        .output()
        .cmx()
        .as_ref()
        .context("embedded designated action is missing its commitment")?;
    ensure!(
        *commitment == expected_commitment,
        "embedded designated action commitment mismatch"
    );

    let matching_actions = pczt
        .ironwood()
        .actions()
        .iter()
        .filter(|action| {
            *action.spend().nullifier() == expected_nullifier
                && action
                    .output()
                    .cmx()
                    .as_ref()
                    .is_some_and(|cmx| *cmx == expected_commitment)
        })
        .count();
    ensure!(
        matching_actions == 1,
        "embedded designated NF/CMX pair is not unique"
    );
    Ok(())
}

fn action_pair_layout(bundle: &orchard::pczt::Bundle) -> Vec<([u8; 32], [u8; 32])> {
    bundle
        .actions()
        .iter()
        .map(|action| {
            (
                action.spend().nullifier().to_bytes(),
                action.output().cmx().to_bytes(),
            )
        })
        .collect()
}

fn embedded_action_layout(pczt: &pczt::Pczt) -> Result<Vec<([u8; 32], [u8; 32])>> {
    pczt.ironwood()
        .actions()
        .iter()
        .map(|action| {
            let commitment = action
                .output()
                .cmx()
                .as_ref()
                .context("embedded Ironwood action is missing its commitment")?;
            Ok((*action.spend().nullifier(), *commitment))
        })
        .collect()
}

fn transaction_action_layout(transaction: &Transaction) -> Result<Vec<([u8; 32], [u8; 32])>> {
    let ironwood = transaction
        .ironwood_bundle()
        .context("transaction has no Ironwood bundle")?;
    Ok(ironwood
        .actions()
        .iter()
        .map(|action| (action.nullifier().to_bytes(), action.cmx().to_bytes()))
        .collect())
}

fn serialize_consensus_transaction(transaction: &Transaction) -> Result<Vec<u8>> {
    let mut serialized = Vec::new();
    transaction
        .write(&mut serialized)
        .context("serialize consensus transaction")?;
    Ok(serialized)
}

fn value_sum_parts(value_balance: i64) -> Result<(u64, bool)> {
    if value_balance < 0 {
        let magnitude = value_balance
            .checked_neg()
            .context("negative Ironwood value balance overflow")?;
        Ok((
            u64::try_from(magnitude).context("Ironwood value balance does not fit u64")?,
            true,
        ))
    } else {
        Ok((
            u64::try_from(value_balance).context("Ironwood value balance does not fit u64")?,
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names_v1_config::{REGTEST, bulletin_address};
    use coppice_names::v1::names_application_id;
    use coppice_names::v1::{
        CommitRef, GenesisStatement, IronwoodActionRef, NameState, OrchardV1ProofProver,
        ProducerPosition, RegistrationIntent, StateData, StateRef, StateStatus, V1Operation,
        V1Parameters, decode_operation, encode_operation, operation_footprint,
    };
    use incrementalmerkletree::{Marking, Position, Retention};
    use orchard::{
        circuit::state_note_binding::{GenesisWitness, spend_auth_owner_key_bytes},
        keys::{Scope, SpendAuthorizingKey, SpendingKey},
        note::{NoteVersion, RandomSeed, Rho},
    };
    use rand::{SeedableRng, rngs::StdRng};
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use std::{io::Cursor, sync::OnceLock, time::Instant};
    use zcash_protocol::{
        consensus::BlockHeight,
        constants::{V6_TX_VERSION, V6_VERSION_GROUP_ID},
        local_consensus::LocalNetwork,
    };

    fn note(fvk: &FullViewingKey, value: u64, rho_byte: u8, seed_byte: u8) -> Note {
        let recipient = fvk.address_at(0u32, Scope::External);
        let mut rho_bytes = [0; 32];
        rho_bytes[0] = rho_byte;
        let rho = Rho::from_bytes(&rho_bytes).unwrap();
        let rseed = RandomSeed::from_bytes([seed_byte; 32], &rho).unwrap();
        Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap()
    }

    fn successor(fvk: &FullViewingKey, input: &Note, value: u64, seed_byte: u8) -> Note {
        let nf = input.nullifier(fvk);
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let rseed = RandomSeed::from_bytes([seed_byte; 32], &rho).unwrap();
        Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap()
    }

    fn fvk(byte: u8) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([byte; 32]).unwrap())
    }

    fn carriers(
        payload_len: usize,
        expected_count: usize,
        recipient: Address,
    ) -> Vec<CarrierOutput> {
        let frames = coppice::transport::encode_frames([0x42; 32], &vec![0x43; payload_len])
            .expect("fixture payload fits CPV1");
        assert_eq!(frames.len(), expected_count);
        frames
            .into_iter()
            .map(|memo| CarrierOutput {
                recipient,
                value: NoteValue::from_raw(1),
                memo,
            })
            .collect()
    }

    struct FundedRevealFixture {
        plan: NamesV1IronwoodPlan,
        registration_nullifier: [u8; 32],
        registration_commitment: ExtractedNoteCommitment,
        registration_ask: SpendAuthorizingKey,
        funding_nullifier: [u8; 32],
        funding_commitment: ExtractedNoteCommitment,
        funding_ask: SpendAuthorizingKey,
    }

    fn funded_reveal_fixture() -> FundedRevealFixture {
        let registration_sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let names_fvk = FullViewingKey::from(&registration_sk);
        let registration_ask = SpendAuthorizingKey::from(&registration_sk);
        let input = note(&names_fvk, 50_000, 1, 2);
        let successor = successor(&names_fvk, &input, 50_000, 3);
        let registration_nullifier = input.nullifier(&names_fvk).to_bytes();
        let registration_commitment = ExtractedNoteCommitment::from(input.commitment());
        let funding_sk = SpendingKey::from_bytes([8; 32]).unwrap();
        let funding_fvk = FullViewingKey::from(&funding_sk);
        let funding_ask = SpendAuthorizingKey::from(&funding_sk);
        let funding = note(&funding_fvk, 10_000, 4, 5);
        let funding_nullifier = funding.nullifier(&funding_fvk).to_bytes();
        let funding_commitment = ExtractedNoteCommitment::from(funding.commitment());
        let carrier_fvk = fvk(9);
        let carrier_recipient = carrier_fvk.address_at(0u32, Scope::External);
        let change_recipient = funding_fvk.address_at(0u32, Scope::Internal);

        FundedRevealFixture {
            plan: NamesV1IronwoodPlan {
                designated_fvk: names_fvk,
                designated_spend: input,
                successor_note: successor,
                successor_ovk: None,
                successor_memo: [0; 512],
                // This is deliberately CPV1-sized fixture data; semantic CNV1
                // encoding is outside this structural PCZT test.
                carrier_outputs: carriers(5_056, 11, carrier_recipient),
                funding_spends: vec![FundingSpend {
                    fvk: funding_fvk.clone(),
                    note: funding,
                }],
                change_outputs: vec![ChangeOutput {
                    fvk: funding_fvk,
                    ovk: None,
                    recipient: change_recipient,
                    value: NoteValue::from_raw(8_989),
                    memo: [0; 512],
                }],
                designated_action_index: 4,
                // Matches the expiry height every PCZT-based test below uses.
                operation_height: 100,
            },
            registration_nullifier,
            registration_commitment,
            registration_ask,
            funding_nullifier,
            funding_commitment,
            funding_ask,
        }
    }

    fn funded_reveal_plan() -> NamesV1IronwoodPlan {
        funded_reveal_fixture().plan
    }

    fn deterministic_funded_reveal_witness_plan(
        fixture: &FundedRevealFixture,
    ) -> NamesV1WitnessPlan {
        type TestTree = ShardTree<MemoryShardStore<orchard::tree::MerkleHashOrchard, u32>, 32, 4>;

        let mut tree = TestTree::new(MemoryShardStore::empty(), 4);
        tree.append(
            orchard::tree::MerkleHashOrchard::from_cmx(&fixture.registration_commitment),
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        tree.append(
            orchard::tree::MerkleHashOrchard::from_cmx(&fixture.funding_commitment),
            Retention::Checkpoint {
                id: 1,
                marking: Marking::Marked,
            },
        )
        .unwrap();

        let anchor: orchard::Anchor = tree
            .root_at_checkpoint_id(&1)
            .unwrap()
            .expect("deterministic tree has a checkpoint root")
            .into();
        let registration_path: orchard::tree::MerklePath = tree
            .witness_at_checkpoint_id(Position::from(0), &1)
            .unwrap()
            .expect("registration input has a deterministic witness")
            .into();
        let funding_path: orchard::tree::MerklePath = tree
            .witness_at_checkpoint_id(Position::from(1), &1)
            .unwrap()
            .expect("funding input has a deterministic witness")
            .into();

        // Deliberately return the randomized funding spend first. The helper
        // must resolve both entries from their nullifiers, not this order.
        NamesV1WitnessPlan {
            anchor,
            spends: vec![
                NamesV1IronwoodWitness {
                    nullifier: fixture.funding_nullifier,
                    merkle_path: funding_path,
                },
                NamesV1IronwoodWitness {
                    nullifier: fixture.registration_nullifier,
                    merkle_path: registration_path,
                },
            ],
        }
    }

    fn local_v6_params() -> LocalNetwork {
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

    static IRONWOOD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

    fn ironwood_proving_key() -> &'static orchard::circuit::ProvingKey {
        IRONWOOD_PROVING_KEY.get_or_init(|| {
            orchard::circuit::ProvingKey::build(BundleVersion::ironwood_v3().circuit_version())
        })
    }

    #[test]
    fn reveal_shape_preserves_designated_pair_with_funding_and_change() {
        let built =
            build_names_v1_bundle(funded_reveal_plan(), StdRng::from_seed([10; 32])).unwrap();

        assert_eq!(built.designated_action_index, 4);
        assert_eq!(built.real_spend_count, 2);
        assert_eq!(built.requested_output_count, 13);
        assert_eq!(built.carrier_output_count, 11);
        assert_eq!(built.change_output_count, 1);
        assert_eq!(built.action_count, 13);
        assert_eq!(built.ironwood_value_balance, 1_000);
        verify_designated_action(
            &built.bundle,
            built.designated_action_index,
            built.designated_nullifier,
            built.designated_commitment,
        )
        .unwrap();
        let mut wrong_commitment = built.designated_commitment;
        wrong_commitment[0] ^= 1;
        assert!(
            verify_designated_action(
                &built.bundle,
                built.designated_action_index,
                built.designated_nullifier,
                wrong_commitment,
            )
            .is_err()
        );
        assert!(
            verify_designated_action(
                &built.bundle,
                built.designated_action_index + 1,
                built.designated_nullifier,
                built.designated_commitment,
            )
            .is_err()
        );
    }

    #[test]
    fn zip317_fee_planning_uses_shared_reveal_shape_and_previews_update() {
        let fixture = funded_reveal_fixture();
        let reveal_shape = names_v1_ironwood_shape(&fixture.plan).unwrap();
        assert_eq!(reveal_shape.real_spend_count, 2);
        assert_eq!(reveal_shape.requested_output_count, 13);
        assert_eq!(reveal_shape.carrier_output_count, 11);
        assert_eq!(reveal_shape.change_output_count, 1);
        assert_eq!(reveal_shape.action_count, 13);
        assert_eq!(
            required_zip317_fee_for_names_v1(
                &local_v6_params(),
                BlockHeight::from_u32(100),
                reveal_shape,
            )
            .unwrap(),
            Zatoshis::from_u64(65_000).unwrap()
        );

        let built = build_names_v1_bundle(fixture.plan, StdRng::from_seed([10; 32])).unwrap();
        assert_eq!(built.action_count, reveal_shape.action_count);
        assert_eq!(built.real_spend_count, reveal_shape.real_spend_count);
        assert_eq!(
            built.requested_output_count,
            reveal_shape.requested_output_count
        );

        let update = V1Operation::Update {
            predecessor: StateRef::new(
                ProducerPosition::new(950, 2, [4; 32]),
                0,
                0,
                [6; 32],
                [7; 32],
            ),
            state: StateData {
                name_id: [1; 32],
                owner_pk: [5; 32],
                sequence: 1,
                record: vec![6; 65],
                lease_expiry: 2_000,
                status: StateStatus::Active,
                terminal_height: 0,
            },
            state_commitment: [8; 32],
            state_nullifier: [9; 32],
            action_index: 0,
            proof: vec![0; 4_640],
        };
        let update_footprint = operation_footprint(&update).unwrap();
        assert_eq!(update_footprint.operation_bytes, 4_950);
        assert_eq!(update_footprint.proof_bytes, 4_640);
        assert_eq!(update_footprint.cpv1_frames, 10);

        let update_shape =
            names_v1_ironwood_shape_from_counts(2, update_footprint.cpv1_frames, 1, 0).unwrap();
        assert_eq!(update_shape.real_spend_count, 2);
        assert_eq!(update_shape.requested_output_count, 12);
        assert_eq!(update_shape.carrier_output_count, 10);
        assert_eq!(update_shape.change_output_count, 1);
        assert_eq!(update_shape.action_count, 12);
        assert_eq!(
            required_zip317_fee_for_names_v1(
                &local_v6_params(),
                BlockHeight::from_u32(100),
                update_shape,
            )
            .unwrap(),
            Zatoshis::from_u64(60_000).unwrap()
        );
    }

    #[test]
    fn funded_reveal_embeds_directly_in_complete_v6_pczt() {
        let built =
            build_names_v1_bundle(funded_reveal_plan(), StdRng::from_seed([10; 32])).unwrap();
        let source_action_layout = action_pair_layout(&built.bundle);

        let complete = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: built,
            params: local_v6_params(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(100),
            fallback_lock_time: 0,
        })
        .unwrap();

        assert_eq!(complete.pczt.global().tx_version(), &V6_TX_VERSION);
        assert_eq!(
            complete.pczt.global().version_group_id(),
            &V6_VERSION_GROUP_ID
        );
        assert_eq!(
            complete.pczt.global().consensus_branch_id(),
            &u32::from(BranchId::Nu6_3)
        );
        assert_eq!(complete.pczt.global().expiry_height(), &100);
        assert_eq!(complete.real_spend_count, 2);
        assert_eq!(complete.requested_output_count, 13);
        assert_eq!(complete.carrier_output_count, 11);
        assert_eq!(complete.change_output_count, 1);
        assert_eq!(complete.action_count, 13);
        assert_eq!(complete.pczt.ironwood().actions().len(), 13);
        assert_eq!(complete.designated_action_index, 4);
        assert!(complete.pczt.ironwood().anchor().is_none());
        assert!(complete.pczt.ironwood().zkproof().is_none());
        assert_eq!(*complete.pczt.ironwood().value_sum(), (1_000, false));
        assert_eq!(complete.ironwood_value_balance, 1_000);
        verify_embedded_designated_action(
            &complete.pczt,
            complete.designated_action_index,
            complete.designated_nullifier,
            complete.designated_commitment,
        )
        .unwrap();
        assert_eq!(
            embedded_action_layout(&complete.pczt).unwrap(),
            source_action_layout
        );

        let bytes = complete.pczt.clone().serialize().unwrap();
        assert_eq!(&bytes[..4], b"PCZT");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
        let parsed = pczt::Pczt::parse(&bytes).unwrap();
        assert_eq!(parsed.global().tx_version(), &V6_TX_VERSION);
        assert_eq!(parsed.ironwood().actions().len(), 13);
        assert!(parsed.ironwood().anchor().is_none());
        assert!(parsed.ironwood().zkproof().is_none());
        assert_eq!(
            embedded_action_layout(&parsed).unwrap(),
            source_action_layout
        );
        verify_embedded_designated_action(
            &parsed,
            complete.designated_action_index,
            complete.designated_nullifier,
            complete.designated_commitment,
        )
        .unwrap();
        assert_eq!(*parsed.ironwood().value_sum(), (1_000, false));

        let deferred_spend_indices = complete
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().witness().is_none())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let dummy_spend_indices = complete
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().witness().is_some())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(deferred_spend_indices.len(), 2);
        assert_eq!(dummy_spend_indices.len(), 11);

        let pre_finalize_layout = embedded_action_layout(&complete.pczt).unwrap();
        let creator_bytes = complete.pczt.clone().serialize().unwrap();
        let finalized = finalize_names_v1_pczt_io(complete).unwrap();

        assert_eq!(finalized.action_count, 13);
        assert_eq!(finalized.pczt.ironwood().actions().len(), 13);
        assert_eq!(finalized.designated_action_index, 4);
        assert_eq!(
            embedded_action_layout(&finalized.pczt).unwrap(),
            pre_finalize_layout
        );
        verify_embedded_designated_action(
            &finalized.pczt,
            finalized.designated_action_index,
            finalized.designated_nullifier,
            finalized.designated_commitment,
        )
        .unwrap();
        assert_eq!(*finalized.pczt.ironwood().value_sum(), (1_000, false));
        assert_eq!(finalized.ironwood_value_balance, 1_000);
        assert!(!finalized.pczt.global().inputs_modifiable());
        assert!(!finalized.pczt.global().outputs_modifiable());
        assert!(!finalized.pczt.global().shielded_modifiable());
        assert!(!finalized.pczt.global().has_sighash_single());
        assert!(finalized.pczt.ironwood().anchor().is_none());
        assert!(finalized.pczt.ironwood().zkproof().is_none());
        assert!(deferred_spend_indices.iter().all(|index| {
            finalized.pczt.ironwood().actions()[*index]
                .spend()
                .witness()
                .is_none()
                && finalized.pczt.ironwood().actions()[*index]
                    .spend()
                    .spend_auth_sig()
                    .is_none()
        }));
        assert!(dummy_spend_indices.iter().all(|index| {
            finalized.pczt.ironwood().actions()[*index]
                .spend()
                .witness()
                .is_some()
                && finalized.pczt.ironwood().actions()[*index]
                    .spend()
                    .spend_auth_sig()
                    .is_some()
        }));

        // IO finalization materializes binding state and dummy signatures in the PCZT;
        // real witness/proof/signature state remains intentionally deferred.
        let finalized_bytes = finalized.pczt.clone().serialize().unwrap();
        assert_ne!(finalized_bytes, creator_bytes);
        let finalized_parsed = pczt::Pczt::parse(&finalized_bytes).unwrap();
        assert_eq!(
            embedded_action_layout(&finalized_parsed).unwrap(),
            pre_finalize_layout
        );
        verify_embedded_designated_action(
            &finalized_parsed,
            finalized.designated_action_index,
            finalized.designated_nullifier,
            finalized.designated_commitment,
        )
        .unwrap();
        assert_eq!(
            finalized_parsed.clone().serialize().unwrap(),
            finalized_bytes
        );
        assert_eq!(*finalized_parsed.ironwood().value_sum(), (1_000, false));
        assert!(finalized_parsed.ironwood().anchor().is_none());
        assert!(finalized_parsed.ironwood().zkproof().is_none());
    }

    #[test]
    fn funded_reveal_installs_real_witnesses_by_nullifier() {
        let fixture = funded_reveal_fixture();
        let witness_plan = deterministic_funded_reveal_witness_plan(&fixture);
        let built = build_names_v1_bundle(fixture.plan, StdRng::from_seed([10; 32])).unwrap();
        let complete = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: built,
            params: local_v6_params(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(100),
            fallback_lock_time: 0,
        })
        .unwrap();
        let finalized = finalize_names_v1_pczt_io(complete).unwrap();

        let before_layout = embedded_action_layout(&finalized.pczt).unwrap();
        let before_action_count = finalized.pczt.ironwood().actions().len();
        let before_value_balance = *finalized.pczt.ironwood().value_sum();
        assert_eq!(before_action_count, 13);
        assert_eq!(before_value_balance, (1_000, false));
        assert!(finalized.pczt.ironwood().anchor().is_none());
        assert!(finalized.pczt.ironwood().zkproof().is_none());

        let registration_action_index = finalized
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .find(|(_, action)| *action.spend().nullifier() == fixture.registration_nullifier)
            .map(|(index, _)| index)
            .expect("registration nullifier is in the finalized PCZT");
        let funding_action_index = finalized
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .find(|(_, action)| *action.spend().nullifier() == fixture.funding_nullifier)
            .map(|(index, _)| index)
            .expect("funding nullifier is in the finalized PCZT");
        assert_eq!(registration_action_index, 4);
        // The seeded fixture places funding away from its insertion-order slot;
        // the helper must still resolve it from its nullifier.
        assert_ne!(funding_action_index, 1);
        assert_ne!(registration_action_index, funding_action_index);

        let real_action_indices = finalized
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().witness().is_none())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let dummy_state = finalized
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(index, action)| {
                let witness = action.spend().witness().as_ref().copied()?;
                Some((
                    index,
                    witness,
                    action.spend().spend_auth_sig().as_ref().copied(),
                ))
            })
            .collect::<Vec<_>>();
        assert_eq!(real_action_indices.len(), 2);
        assert_eq!(dummy_state.len(), 11);
        assert!(real_action_indices.iter().all(|index| {
            finalized.pczt.ironwood().actions()[*index]
                .spend()
                .spend_auth_sig()
                .is_none()
        }));

        let expected_anchor = witness_plan.anchor;
        let expected_witnesses = witness_plan
            .spends
            .iter()
            .map(|witness| {
                (
                    witness.nullifier,
                    (
                        witness.merkle_path.position(),
                        witness.merkle_path.auth_path().map(|node| node.to_bytes()),
                    ),
                )
            })
            .collect::<Vec<_>>();
        for witness in &witness_plan.spends {
            let commitment = if witness.nullifier == fixture.registration_nullifier {
                fixture.registration_commitment
            } else {
                assert_eq!(witness.nullifier, fixture.funding_nullifier);
                fixture.funding_commitment
            };
            assert_eq!(witness.merkle_path.root(commitment), expected_anchor);
        }

        let witnessed = install_names_v1_ironwood_witnesses(finalized, witness_plan).unwrap();

        assert_eq!(witnessed.anchor, expected_anchor);
        assert_eq!(witnessed.action_count, before_action_count);
        assert_eq!(witnessed.pczt.ironwood().actions().len(), 13);
        assert_eq!(*witnessed.pczt.ironwood().value_sum(), before_value_balance);
        assert_eq!(witnessed.designated_action_index, 4);
        assert_eq!(
            witnessed.witnessed_action_indices,
            vec![
                (fixture.funding_nullifier, funding_action_index),
                (fixture.registration_nullifier, registration_action_index),
            ]
        );
        assert_eq!(
            witnessed.pczt.ironwood().anchor().as_ref().copied(),
            Some(expected_anchor.to_bytes())
        );
        assert!(witnessed.pczt.ironwood().zkproof().is_none());
        assert_eq!(
            embedded_action_layout(&witnessed.pczt).unwrap(),
            before_layout
        );
        verify_embedded_designated_action(
            &witnessed.pczt,
            witnessed.designated_action_index,
            witnessed.designated_nullifier,
            witnessed.designated_commitment,
        )
        .unwrap();

        for (nullifier, expected_witness) in &expected_witnesses {
            let action_index = witnessed
                .witnessed_action_indices
                .iter()
                .find(|(resolved_nullifier, _)| resolved_nullifier == nullifier)
                .map(|(_, index)| *index)
                .expect("witness nullifier has a resolved action index");
            assert_eq!(
                witnessed.pczt.ironwood().actions()[action_index]
                    .spend()
                    .witness()
                    .as_ref(),
                Some(expected_witness)
            );
            assert!(
                witnessed.pczt.ironwood().actions()[action_index]
                    .spend()
                    .spend_auth_sig()
                    .is_none()
            );
        }
        for (action_index, expected_witness, expected_signature) in &dummy_state {
            let action = &witnessed.pczt.ironwood().actions()[*action_index];
            assert_eq!(action.spend().witness().as_ref(), Some(expected_witness));
            assert_eq!(
                action.spend().spend_auth_sig().as_ref().copied(),
                *expected_signature
            );
        }

        let witnessed_bytes = witnessed.pczt.clone().serialize().unwrap();
        let parsed = pczt::Pczt::parse(&witnessed_bytes).unwrap();
        assert_eq!(
            parsed.ironwood().anchor().as_ref().copied(),
            Some(expected_anchor.to_bytes())
        );
        assert!(parsed.ironwood().zkproof().is_none());
        assert_eq!(parsed.ironwood().actions().len(), before_action_count);
        assert_eq!(embedded_action_layout(&parsed).unwrap(), before_layout);
        assert_eq!(*parsed.ironwood().value_sum(), before_value_balance);
        verify_embedded_designated_action(
            &parsed,
            witnessed.designated_action_index,
            witnessed.designated_nullifier,
            witnessed.designated_commitment,
        )
        .unwrap();
        for (_, action_index) in &witnessed.witnessed_action_indices {
            assert!(
                parsed.ironwood().actions()[*action_index]
                    .spend()
                    .witness()
                    .is_some()
            );
            assert!(
                parsed.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .is_none()
            );
        }
        assert!(dummy_state.iter().all(|(action_index, _, signature)| {
            parsed.ironwood().actions()[*action_index]
                .spend()
                .witness()
                .is_some()
                && parsed.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .copied()
                    == *signature
        }));
    }

    #[test]
    fn funded_reveal_signs_two_real_ironwood_spends_by_nullifier() {
        let fixture = funded_reveal_fixture();
        let witness_plan = deterministic_funded_reveal_witness_plan(&fixture);
        let built = build_names_v1_bundle(fixture.plan, StdRng::from_seed([10; 32])).unwrap();
        let complete = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: built,
            params: local_v6_params(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(100),
            fallback_lock_time: 0,
        })
        .unwrap();
        let finalized = finalize_names_v1_pczt_io(complete).unwrap();
        let witnessed = install_names_v1_ironwood_witnesses(finalized, witness_plan).unwrap();
        let NamesV1WitnessedPczt {
            pczt,
            anchor,
            witnessed_action_indices,
            designated_action_index,
            designated_nullifier,
            designated_commitment,
            action_count,
            real_spend_count,
            requested_output_count: _,
            carrier_output_count: _,
            change_output_count: _,
            ironwood_value_balance,
        } = witnessed;

        let before_layout = embedded_action_layout(&pczt).unwrap();
        let before_action_count = pczt.ironwood().actions().len();
        let before_value_balance = *pczt.ironwood().value_sum();
        let before_anchor = anchor;
        let before_proof = pczt.ironwood().zkproof().clone();
        assert_eq!(before_action_count, 13);
        assert_eq!(before_value_balance, (1_000, false));
        assert_eq!(action_count, before_action_count);
        assert_eq!(real_spend_count, 2);
        assert_eq!(ironwood_value_balance, 1_000);
        assert_eq!(designated_action_index, 4);
        assert_eq!(designated_nullifier, fixture.registration_nullifier);
        assert!(before_proof.is_none());

        let mut real_action_indices = witnessed_action_indices
            .iter()
            .map(|(_, action_index)| *action_index)
            .collect::<Vec<_>>();
        real_action_indices.sort_unstable();
        assert_eq!(real_action_indices, vec![4, 7]);
        assert!(real_action_indices.iter().all(|action_index| {
            pczt.ironwood().actions()[*action_index]
                .spend()
                .witness()
                .is_some()
                && pczt.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .is_none()
        }));
        let dummy_signatures = pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(action_index, action)| {
                action
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .copied()
                    .map(|signature| (action_index, signature))
            })
            .collect::<Vec<_>>();
        assert_eq!(dummy_signatures.len(), 11);

        // Deliberately request registration first even though the witness metadata is
        // in funding-first order; both actions must be resolved by nullifier.
        let signing_plan = NamesV1SigningPlan {
            spends: vec![
                NamesV1IronwoodSigningKey {
                    nullifier: fixture.registration_nullifier,
                    ask: fixture.registration_ask.clone(),
                },
                NamesV1IronwoodSigningKey {
                    nullifier: fixture.funding_nullifier,
                    ask: fixture.funding_ask.clone(),
                },
            ],
        };
        // Exercise the same signing core as the proved-stage public wrapper without
        // constructing a proving key or generating another consensus proof.
        let signed = sign_names_v1_ironwood_pczt_core(
            pczt,
            NamesV1SigningMetadata {
                anchor: before_anchor,
                witnessed_action_indices: &witnessed_action_indices,
                designated_action_index,
                designated_nullifier,
                designated_commitment,
                action_count,
                real_spend_count,
                ironwood_value_balance,
            },
            signing_plan,
        )
        .unwrap();

        assert_eq!(signed.ironwood().actions().len(), before_action_count);
        assert_eq!(*signed.ironwood().value_sum(), before_value_balance);
        assert_eq!(signed.ironwood().anchor(), &Some(before_anchor.to_bytes()));
        assert_eq!(signed.ironwood().zkproof(), &before_proof);
        assert_eq!(embedded_action_layout(&signed).unwrap(), before_layout);
        verify_embedded_designated_action(
            &signed,
            designated_action_index,
            designated_nullifier,
            designated_commitment,
        )
        .unwrap();
        for (nullifier, action_index) in &witnessed_action_indices {
            let action = &signed.ironwood().actions()[*action_index];
            assert_eq!(*action.spend().nullifier(), *nullifier);
            assert!(action.spend().witness().is_some());
            assert!(action.spend().spend_auth_sig().is_some());
        }
        for (action_index, expected_signature) in &dummy_signatures {
            assert_eq!(
                signed.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .copied(),
                Some(*expected_signature)
            );
        }
        assert_eq!(
            signed
                .ironwood()
                .actions()
                .iter()
                .filter(|action| action.spend().spend_auth_sig().is_some())
                .count(),
            13
        );

        let signed_bytes = signed.clone().serialize().unwrap();
        let parsed = pczt::Pczt::parse(&signed_bytes).unwrap();
        assert_eq!(parsed.ironwood().actions().len(), before_action_count);
        assert_eq!(*parsed.ironwood().value_sum(), before_value_balance);
        assert_eq!(parsed.ironwood().anchor(), &Some(before_anchor.to_bytes()));
        assert_eq!(parsed.ironwood().zkproof(), &before_proof);
        assert_eq!(embedded_action_layout(&parsed).unwrap(), before_layout);
        verify_embedded_designated_action(
            &parsed,
            designated_action_index,
            designated_nullifier,
            designated_commitment,
        )
        .unwrap();
        assert_eq!(
            parsed
                .ironwood()
                .actions()
                .iter()
                .filter(|action| action.spend().spend_auth_sig().is_some())
                .count(),
            13
        );
        for (_, action_index) in &witnessed_action_indices {
            assert!(
                parsed.ironwood().actions()[*action_index]
                    .spend()
                    .witness()
                    .is_some()
            );
            assert!(
                parsed.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .is_some()
            );
        }
        for (action_index, expected_signature) in &dummy_signatures {
            assert_eq!(
                parsed.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .copied(),
                Some(*expected_signature)
            );
        }
    }

    #[test]
    #[ignore = "expensive Names v1 genesis proving"]
    fn funded_reveal_embeds_one_real_names_v1_reveal_payload() {
        const ACTION_INDEX: u32 = 4;
        const MINIMUM_BOND: u64 = 50_000;

        let fixture = funded_reveal_fixture();

        // These are the exact note/key values that the designated-pair wallet
        // plan will pass to the Ironwood builder below. Cloning them here only
        // lets the application proof consume the same immutable note material
        // before the plan is moved into the builder.
        let registration_note = fixture.plan.designated_spend.clone();
        let successor_note = fixture.plan.successor_note.clone();
        let names_fvk = fixture.plan.designated_fvk.clone();
        let names_ask = fixture.registration_ask.clone();
        let registration_nullifier = fixture.registration_nullifier;
        let successor_commitment =
            ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes();
        let successor_future_nullifier = successor_note.nullifier(&names_fvk).to_bytes();

        let owner_pk = spend_auth_owner_key_bytes(&names_ask);
        let intent = RegistrationIntent {
            name: "footprint".to_owned(),
            owner_pk,
            record: vec![9; 64],
            secret: [8; 32],
        };
        let name_id = intent.name_id().unwrap();
        let intent_commitment = intent.commitment().unwrap();
        let v1 = V1Parameters::testing();
        let operation_height = coppice_names::v1::schedule::next_anchor_height(name_id, 901, v1)
            .expect("synthetic REVEAL needs a scheduled height");

        // This CommitRef is deliberately synthetic. It gives the offline
        // envelope a canonical predecessor shape, but establishes no chain
        // inclusion, maturity, lifetime, or replay acceptance.
        let commit = CommitRef::new(ProducerPosition::new(900, 1, [3; 32]), 0, intent_commitment);

        let state_data = StateData {
            name_id,
            owner_pk,
            sequence: 0,
            record: intent.record.clone(),
            lease_expiry: v1.lease_expiry(operation_height).unwrap(),
            status: StateStatus::Active,
            terminal_height: 0,
        };
        let state_ref = StateRef::new(
            ProducerPosition::new(operation_height, 0, [4; 32]),
            ACTION_INDEX,
            0,
            successor_commitment,
            successor_future_nullifier,
        );
        let state = NameState::new(state_data.clone(), successor_commitment, state_ref).unwrap();
        let action = IronwoodActionRef {
            action_index: ACTION_INDEX,
            nullifier: registration_nullifier,
            commitment: successor_commitment,
        };
        let statement =
            GenesisStatement::from_reveal(&intent, &state, action, operation_height, v1).unwrap();

        assert_eq!(statement.name_id, name_id);
        assert_eq!(statement.owner_pk, owner_pk);
        assert_eq!(statement.commitment, successor_commitment);
        assert_eq!(statement.registration_nullifier, registration_nullifier);
        assert_eq!(statement.state_nullifier, successor_future_nullifier);
        assert_eq!(statement.minimum_bond_zatoshis, MINIMUM_BOND);

        let witness = GenesisWitness::new(
            registration_note,
            successor_note,
            &names_fvk,
            Scope::External,
            MINIMUM_BOND,
        )
        .expect("the funded registration/successor notes form a genesis witness");
        let names_prover = OrchardV1ProofProver::new();
        let proving_started = Instant::now();
        let genesis_proof = names_prover
            .prove_genesis(&statement, witness, StdRng::from_seed([44; 32]))
            .unwrap();
        let proving_elapsed = proving_started.elapsed();
        assert!(!genesis_proof.is_empty());

        let reveal = V1Operation::Reveal {
            intent: Box::new(intent),
            commit,
            replacement_predecessor: None,
            state: state_data,
            state_commitment: successor_commitment,
            state_nullifier: successor_future_nullifier,
            action_index: ACTION_INDEX,
            proof: genesis_proof.clone(),
        };
        let encoded_reveal = encode_operation(&reveal).unwrap();
        assert_eq!(decode_operation(&encoded_reveal).unwrap(), reveal);
        let footprint = operation_footprint(&reveal).unwrap();
        assert_eq!(footprint.operation_bytes, encoded_reveal.len());
        assert_eq!(footprint.proof_bytes, genesis_proof.len());

        let names_application_id = names_application_id().to_bytes();
        let cpv1_frames =
            coppice::transport::encode_frames(names_application_id, &encoded_reveal).unwrap();
        assert_eq!(cpv1_frames.len(), footprint.cpv1_frames);
        let reconstructed_reveal =
            coppice::transport::reconstruct_frames(&cpv1_frames, names_application_id).unwrap();
        assert_eq!(reconstructed_reveal, encoded_reveal);
        assert_eq!(decode_operation(&reconstructed_reveal).unwrap(), reveal);
        assert!(
            coppice::transport::reconstruct_frames(&cpv1_frames, [0x42; 32]).is_err(),
            "CPV1 frames must be bound to the Names application ID"
        );

        let rendezvous_recipient = bulletin_address(REGTEST.rendezvous).unwrap();
        let carrier_outputs = cpv1_frames
            .iter()
            .copied()
            .map(|memo| CarrierOutput {
                recipient: rendezvous_recipient,
                value: NoteValue::from_raw(1),
                memo,
            })
            .collect::<Vec<_>>();
        assert_eq!(carrier_outputs.len(), footprint.cpv1_frames);
        assert!(
            carrier_outputs
                .iter()
                .all(|carrier| carrier.recipient == rendezvous_recipient)
        );

        // Replace only the structural fixture's carrier bytes. All note
        // material, the designated index, and the funding halves stay intact.
        let mut plan = fixture.plan;
        plan.carrier_outputs = carrier_outputs;
        let built = build_names_v1_bundle(plan, StdRng::from_seed([10; 32])).unwrap();

        assert_eq!(built.designated_action_index, ACTION_INDEX as usize);
        assert_eq!(built.real_spend_count, 2);
        assert_eq!(built.carrier_output_count, footprint.cpv1_frames);
        assert_eq!(built.requested_output_count, footprint.cpv1_frames + 2);
        assert_eq!(built.change_output_count, 1);
        assert_eq!(built.action_count, 13);
        assert_eq!(built.ironwood_value_balance, 1_000);
        assert_eq!(built.designated_nullifier, statement.registration_nullifier);
        assert_eq!(built.designated_commitment, statement.commitment);
        verify_designated_action(
            &built.bundle,
            built.designated_action_index,
            statement.registration_nullifier,
            statement.commitment,
        )
        .unwrap();

        let complete = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: built,
            params: local_v6_params(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(100),
            fallback_lock_time: 0,
        })
        .unwrap();
        assert_eq!(complete.pczt.ironwood().actions().len(), 13);
        assert_eq!(*complete.pczt.ironwood().value_sum(), (1_000, false));
        assert_eq!(complete.designated_action_index, ACTION_INDEX);
        assert_eq!(complete.carrier_output_count, footprint.cpv1_frames);
        verify_embedded_designated_action(
            &complete.pczt,
            complete.designated_action_index,
            statement.registration_nullifier,
            statement.commitment,
        )
        .unwrap();

        eprintln!(
            "Names v1 semantic REVEAL: app_id={}, operation_bytes={}, proof_bytes={}, cpv1_frames={}, minimum_actions={}, actions={}, real_spends={}, outputs={}, value_balance={}, proving_elapsed_ms={}, registration_nf={}, successor_cmx={}, successor_future_nf={}",
            hex::encode(names_application_id),
            footprint.operation_bytes,
            footprint.proof_bytes,
            footprint.cpv1_frames,
            footprint.minimum_ironwood_actions,
            complete.action_count,
            complete.real_spend_count,
            complete.requested_output_count,
            complete.ironwood_value_balance,
            proving_elapsed.as_millis(),
            hex::encode(registration_nullifier),
            hex::encode(successor_commitment),
            hex::encode(successor_future_nullifier),
        );
    }

    #[test]
    #[ignore = "generates a real Ironwood consensus proof; run via `cargo test -- --ignored` or the scripted release qualification"]
    fn funded_reveal_proves_signs_and_extracts_one_consensus_transaction() {
        let fixture = funded_reveal_fixture();
        let witness_plan = deterministic_funded_reveal_witness_plan(&fixture);
        let expected_anchor = witness_plan.anchor;
        let built = build_names_v1_bundle(fixture.plan, StdRng::from_seed([10; 32])).unwrap();
        let complete = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: built,
            params: local_v6_params(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(100),
            fallback_lock_time: 0,
        })
        .unwrap();
        let finalized = finalize_names_v1_pczt_io(complete).unwrap();
        let witnessed = install_names_v1_ironwood_witnesses(finalized, witness_plan).unwrap();

        let before_layout = embedded_action_layout(&witnessed.pczt).unwrap();
        let before_action_count = witnessed.pczt.ironwood().actions().len();
        let before_value_balance = *witnessed.pczt.ironwood().value_sum();
        let before_designated_action_index = witnessed.designated_action_index;
        let before_designated_nullifier = witnessed.designated_nullifier;
        let before_designated_commitment = witnessed.designated_commitment;
        let before_anchor = witnessed.anchor;
        assert_eq!(before_action_count, 13);
        assert_eq!(before_value_balance, (1_000, false));
        assert_eq!(before_designated_action_index, 4);
        assert_eq!(before_designated_nullifier, fixture.registration_nullifier);
        assert_eq!(before_anchor, expected_anchor);
        assert_eq!(
            witnessed.pczt.ironwood().anchor().as_ref().copied(),
            Some(expected_anchor.to_bytes())
        );
        assert!(witnessed.pczt.ironwood().zkproof().is_none());

        let mut real_action_indices = witnessed
            .witnessed_action_indices
            .iter()
            .map(|(_, action_index)| *action_index)
            .collect::<Vec<_>>();
        real_action_indices.sort_unstable();
        assert_eq!(real_action_indices, vec![4, 7]);
        assert!(real_action_indices.iter().all(|action_index| {
            witnessed.pczt.ironwood().actions()[*action_index]
                .spend()
                .witness()
                .is_some()
                && witnessed.pczt.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .is_none()
        }));
        let dummy_signatures = witnessed
            .pczt
            .ironwood()
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(action_index, action)| {
                action
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .copied()
                    .map(|signature| (action_index, signature))
            })
            .collect::<Vec<_>>();
        assert_eq!(dummy_signatures.len(), 11);

        let proved = prove_names_v1_ironwood_pczt(witnessed, ironwood_proving_key()).unwrap();

        assert_eq!(proved.anchor, before_anchor);
        assert_eq!(proved.action_count, before_action_count);
        assert_eq!(proved.pczt.ironwood().actions().len(), 13);
        assert_eq!(*proved.pczt.ironwood().value_sum(), before_value_balance);
        assert_eq!(proved.designated_action_index, 4);
        assert_eq!(proved.designated_nullifier, before_designated_nullifier);
        assert_eq!(proved.designated_commitment, before_designated_commitment);
        assert_eq!(embedded_action_layout(&proved.pczt).unwrap(), before_layout);
        assert_eq!(
            proved.pczt.ironwood().anchor().as_ref().copied(),
            Some(before_anchor.to_bytes())
        );
        let proof_len = proved
            .pczt
            .ironwood()
            .zkproof()
            .as_ref()
            .map(Vec::len)
            .expect("Prover produced an Ironwood proof");
        assert!(proof_len > 0);
        assert_eq!(proof_len, proved.ironwood_proof_byte_len);
        verify_embedded_designated_action(
            &proved.pczt,
            proved.designated_action_index,
            proved.designated_nullifier,
            proved.designated_commitment,
        )
        .unwrap();
        for action_index in &real_action_indices {
            let action = &proved.pczt.ironwood().actions()[*action_index];
            assert!(action.spend().witness().is_some());
            assert!(action.spend().spend_auth_sig().is_none());
        }
        for (action_index, expected_signature) in &dummy_signatures {
            assert_eq!(
                proved.pczt.ironwood().actions()[*action_index]
                    .spend()
                    .spend_auth_sig()
                    .as_ref()
                    .copied(),
                Some(*expected_signature)
            );
        }

        let proved_bytes = proved.pczt.clone().serialize().unwrap();
        let parsed = pczt::Pczt::parse(&proved_bytes).unwrap();
        assert!(
            parsed
                .ironwood()
                .zkproof()
                .as_ref()
                .is_some_and(|proof| { !proof.is_empty() })
        );
        assert_eq!(
            parsed.ironwood().anchor().as_ref().copied(),
            Some(before_anchor.to_bytes())
        );
        assert_eq!(parsed.ironwood().actions().len(), before_action_count);
        assert_eq!(embedded_action_layout(&parsed).unwrap(), before_layout);
        assert_eq!(*parsed.ironwood().value_sum(), before_value_balance);
        verify_embedded_designated_action(
            &parsed,
            proved.designated_action_index,
            proved.designated_nullifier,
            proved.designated_commitment,
        )
        .unwrap();

        let proved_proof = proved.pczt.ironwood().zkproof().clone();
        let signed = sign_names_v1_ironwood_pczt(
            proved,
            NamesV1SigningPlan {
                spends: vec![
                    NamesV1IronwoodSigningKey {
                        nullifier: fixture.registration_nullifier,
                        ask: fixture.registration_ask.clone(),
                    },
                    NamesV1IronwoodSigningKey {
                        nullifier: fixture.funding_nullifier,
                        ask: fixture.funding_ask.clone(),
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!(signed.pczt.ironwood().zkproof(), &proved_proof);
        assert_eq!(signed.pczt.ironwood().actions().len(), 13);
        assert_eq!(embedded_action_layout(&signed.pczt).unwrap(), before_layout);
        assert_eq!(*signed.pczt.ironwood().value_sum(), before_value_balance);
        assert_eq!(
            signed.pczt.ironwood().anchor().as_ref().copied(),
            Some(before_anchor.to_bytes())
        );
        assert_eq!(
            signed
                .pczt
                .ironwood()
                .actions()
                .iter()
                .filter(|action| action.spend().spend_auth_sig().is_some())
                .count(),
            13
        );

        let extracted = extract_names_v1_transaction(signed).unwrap();
        assert_eq!(extracted.transaction.version(), TransactionVersion::V6);
        assert_eq!(extracted.action_count, before_action_count);
        assert_eq!(
            extracted
                .transaction
                .ironwood_bundle()
                .unwrap()
                .actions()
                .len(),
            13
        );
        assert_eq!(extracted.designated_action_index, 4);
        assert_eq!(extracted.designated_nullifier, before_designated_nullifier);
        assert_eq!(
            extracted.designated_commitment,
            before_designated_commitment
        );
        assert_eq!(extracted.anchor, before_anchor);
        assert_eq!(extracted.ironwood_value_balance, 1_000);
        assert_eq!(extracted.ironwood_proof_byte_len, proof_len);
        assert_eq!(extracted.ironwood_spend_authorization_count, 13);
        assert!(extracted.ironwood_binding_signature_present);
        let extracted_layout = transaction_action_layout(&extracted.transaction).unwrap();
        assert_eq!(extracted_layout, before_layout);
        assert_eq!(
            extracted_layout
                .iter()
                .filter(|(nullifier, commitment)| {
                    *nullifier == before_designated_nullifier
                        && *commitment == before_designated_commitment
                })
                .count(),
            1
        );
        let extracted_designated_action =
            &extracted.transaction.ironwood_bundle().unwrap().actions()[4];
        assert_eq!(
            extracted_designated_action.nullifier().to_bytes(),
            before_designated_nullifier
        );
        assert_eq!(
            extracted_designated_action.cmx().to_bytes(),
            before_designated_commitment
        );

        let mut consensus_bytes = Vec::new();
        extracted.transaction.write(&mut consensus_bytes).unwrap();
        assert_eq!(consensus_bytes.len(), extracted.consensus_tx_size);
        eprintln!(
            "Names v1 extracted consensus transaction: size={}, txid={}",
            extracted.consensus_tx_size, extracted.txid
        );

        let reparsed_transaction =
            Transaction::read(Cursor::new(&consensus_bytes), BranchId::Nu6_3).unwrap();
        assert_eq!(reparsed_transaction.txid(), extracted.txid);
        assert_eq!(reparsed_transaction.version(), TransactionVersion::V6);
        assert_eq!(
            reparsed_transaction
                .ironwood_bundle()
                .unwrap()
                .actions()
                .len(),
            13
        );
        assert_eq!(
            transaction_action_layout(&reparsed_transaction).unwrap(),
            before_layout
        );
        assert_eq!(
            reparsed_transaction.ironwood_bundle().unwrap().actions()[4]
                .nullifier()
                .to_bytes(),
            before_designated_nullifier
        );
        assert_eq!(
            reparsed_transaction.ironwood_bundle().unwrap().actions()[4]
                .cmx()
                .to_bytes(),
            before_designated_commitment
        );
        assert_eq!(
            i64::from(
                reparsed_transaction
                    .ironwood_bundle()
                    .unwrap()
                    .value_balance()
            ),
            1_000
        );
    }

    #[test]
    fn update_shape_keeps_ten_carriers_off_the_designated_action() {
        let names_fvk = fvk(11);
        let input = note(&names_fvk, 50_000, 6, 7);
        let successor = successor(&names_fvk, &input, 50_000, 8);
        let carrier_fvk = fvk(12);
        let built = build_names_v1_bundle(
            NamesV1IronwoodPlan {
                designated_fvk: names_fvk,
                designated_spend: input,
                successor_note: successor,
                successor_ovk: None,
                successor_memo: [0; 512],
                carrier_outputs: carriers(4_950, 10, carrier_fvk.address_at(0u32, Scope::External)),
                funding_spends: vec![],
                change_outputs: vec![],
                designated_action_index: 0,
                operation_height: 0,
            },
            StdRng::from_seed([13; 32]),
        )
        .unwrap();
        assert_eq!(built.action_count, 11);
        assert_eq!(built.carrier_output_count, 10);
        assert_eq!(built.designated_action_index, 0);
        assert_eq!(built.ironwood_value_balance, -10);
    }
}
