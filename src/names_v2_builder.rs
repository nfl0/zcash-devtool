//! Names v2 Ironwood PCZT-bundle construction with one designated action pair.

use anyhow::{Context, Result, bail, ensure};
use orchard::{
    Address,
    builder::{Builder, BundleType, RequestedActionPair},
    bundle::{BundleVersion, Flags, TxVersion},
    keys::{FullViewingKey, OutgoingViewingKey},
    note::{ExtractedNoteCommitment, Note},
    value::NoteValue,
};
use pczt::roles::creator::Creator;
use rand::RngCore;
use zcash_primitives::transaction::{TxVersion as TransactionVersion, builder::PcztParts};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

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

/// Wallet-side intent for a Names v2 Ironwood PCZT bundle.
pub struct NamesV2IronwoodPlan {
    pub designated_fvk: FullViewingKey,
    pub designated_spend: Note,
    /// Exact successor opening already bound by the Names proof.
    pub successor_note: Note,
    pub successor_ovk: Option<OutgoingViewingKey>,
    pub successor_memo: [u8; 512],
    pub carrier_outputs: Vec<CarrierOutput>,
    pub funding_spends: Vec<FundingSpend>,
    pub change_outputs: Vec<ChangeOutput>,
    /// Canonical action index carried by the CNV2 operation.
    pub designated_action_index: usize,
}

/// Constructed, unproved Ironwood PCZT bundle and verified layout metadata.
pub struct NamesV2BuiltBundle {
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
}

/// Metadata needed to place an already-built Names v2 bundle into a V6 PCZT.
pub struct NamesV2PcztPlan<P: Parameters> {
    pub ironwood: NamesV2BuiltBundle,
    pub params: P,
    pub consensus_branch_id: BranchId,
    pub expiry_height: BlockHeight,
    pub fallback_lock_time: u32,
}

/// Complete, still-unproved Names v2 PCZT and the metadata needed by later roles.
pub struct NamesV2BuiltPczt {
    pub pczt: pczt::Pczt,
    /// The canonical CNV2 action index, encoded as `u32` at this boundary.
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

/// Builds the Ironwood portion of a Names v2 PCZT without proving or signing.
pub fn build_names_v2_bundle(
    plan: NamesV2IronwoodPlan,
    rng: impl RngCore,
) -> Result<NamesV2BuiltBundle> {
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
    let real_spend_count = 1 + plan.funding_spends.len();
    for funding in plan.funding_spends {
        builder
            .add_spend_unwitnessed(funding.fvk, funding.note)
            .context("add Ironwood funding spend")?;
    }

    builder
        .add_output_note(plan.successor_ovk, plan.successor_note, plan.successor_memo)
        .context("add exact Names successor note")?;
    let carrier_output_count = plan.carrier_outputs.len();
    for carrier in plan.carrier_outputs {
        builder
            .add_output(None, carrier.recipient, carrier.value, carrier.memo)
            .context("add CPV1 carrier output")?;
    }
    let change_output_count = plan.change_outputs.len();
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
    let requested_output_count = 1 + carrier_output_count + change_output_count;
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
    Ok(NamesV2BuiltBundle {
        bundle,
        designated_action_index: plan.designated_action_index,
        designated_nullifier: designated_nullifier.to_bytes(),
        designated_commitment: designated_commitment.to_bytes(),
        action_count,
        real_spend_count,
        requested_output_count,
        carrier_output_count,
        change_output_count,
        ironwood_value_balance,
    })
}

/// Embeds a prebuilt, deferred-anchor Ironwood bundle into a complete V6 PCZT.
///
/// `Creator::build_from_parts` is the pinned PCZT injection path: its
/// `PcztParts::ironwood` field accepts the existing `orchard::pczt::Bundle` and
/// converts its fields into the top-level PCZT bundle without rebuilding the
/// actions.
pub fn build_names_v2_pczt<P: Parameters>(plan: NamesV2PcztPlan<P>) -> Result<NamesV2BuiltPczt> {
    let NamesV2PcztPlan {
        ironwood,
        params,
        consensus_branch_id,
        expiry_height,
        fallback_lock_time,
    } = plan;
    ensure!(
        consensus_branch_id == BranchId::Nu6_3,
        "Names v2 Ironwood PCZT requires the NU6.3 V6 consensus branch"
    );

    let NamesV2BuiltBundle {
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
    } = ironwood;
    let designated_action_index = u32::try_from(designated_action_index)
        .context("convert designated Names action index to CNV2 u32")?;
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

    Ok(NamesV2BuiltPczt {
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
        usize::try_from(action_index).context("convert embedded CNV2 action index to usize")?;
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
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{NoteVersion, RandomSeed, Rho},
    };
    use rand::{SeedableRng, rngs::StdRng};
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

    fn funded_reveal_plan() -> NamesV2IronwoodPlan {
        let names_fvk = fvk(7);
        let input = note(&names_fvk, 50_000, 1, 2);
        let successor = successor(&names_fvk, &input, 50_000, 3);
        let funding_fvk = fvk(8);
        let funding = note(&funding_fvk, 10_000, 4, 5);
        let carrier_fvk = fvk(9);
        let carrier_recipient = carrier_fvk.address_at(0u32, Scope::External);
        let change_recipient = funding_fvk.address_at(0u32, Scope::Internal);

        NamesV2IronwoodPlan {
            designated_fvk: names_fvk,
            designated_spend: input,
            successor_note: successor,
            successor_ovk: None,
            successor_memo: [0; 512],
            // This is deliberately CPV1-sized fixture data; semantic CNV2
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

    #[test]
    fn reveal_shape_preserves_designated_pair_with_funding_and_change() {
        let built =
            build_names_v2_bundle(funded_reveal_plan(), StdRng::from_seed([10; 32])).unwrap();

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
    fn funded_reveal_embeds_directly_in_complete_v6_pczt() {
        let built =
            build_names_v2_bundle(funded_reveal_plan(), StdRng::from_seed([10; 32])).unwrap();
        let source_action_layout = action_pair_layout(&built.bundle);

        let complete = build_names_v2_pczt(NamesV2PcztPlan {
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
    }

    #[test]
    fn update_shape_keeps_ten_carriers_off_the_designated_action() {
        let names_fvk = fvk(11);
        let input = note(&names_fvk, 50_000, 6, 7);
        let successor = successor(&names_fvk, &input, 50_000, 8);
        let carrier_fvk = fvk(12);
        let built = build_names_v2_bundle(
            NamesV2IronwoodPlan {
                designated_fvk: names_fvk,
                designated_spend: input,
                successor_note: successor,
                successor_ovk: None,
                successor_memo: [0; 512],
                carrier_outputs: carriers(4_950, 10, carrier_fvk.address_at(0u32, Scope::External)),
                funding_spends: vec![],
                change_outputs: vec![],
                designated_action_index: 0,
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
