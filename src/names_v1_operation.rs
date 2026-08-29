//! High-level Names v1 operation construction.
//!
//! This module sits between the canonical protocol layer in `coppice-names`
//! and the low-level Ironwood PCZT builder in [`crate::names_v1_builder`]. It
//! turns typed caller-supplied inputs into the canonical [`V1Operation`]s,
//! their CNV1 encodings and CPV1 carrier frames, and the designated-pair
//! Ironwood bundle plan. It contains no qualification-fixture values: names,
//! records, secrets, seeds, action indices, and canonical positions are all
//! caller-supplied.
//!
//! Construction is two-stage for state operations:
//!
//! 1. [`prepare_reveal`], [`prepare_update`], [`prepare_renew`], or
//!    [`prepare_release`] binds the exact statement, witness, and successor
//!    state note. At this stage everything except the Names proof is already
//!    cryptographically/protocol-bound.
//! 2. The caller generates the genesis or transition proof with
//!    `coppice_names::v1::OrchardV1ProofProver` and calls `finalize` on the
//!    preparation, producing the complete [`V1Operation`], its CNV1 bytes,
//!    CPV1 frames, and the typed successor material for later wallet stages.
//!
//! [`prepare_commit`] is single-stage: COMMIT carries no proof and no
//! designated Ironwood action.
//!
//! Positions are handled asymmetrically and deliberately. The producer
//! position of the operation's own successor state is assigned by the chain
//! after mining and is bound by neither the proofs nor the wire format, so
//! preparations carry a placeholder there. By contrast a REVEAL's
//! [`CommitRef`] and a transition's predecessor [`StateRef`] must already be
//! canonical: they are bound into the operation and its proof.

use anyhow::{Context, Result, ensure};
use coppice::transport::{encode_frames, reconstruct_frames};
use coppice_names::v1::names_application_id;
use coppice_names::v1::schedule::is_anchor_height;
use coppice_names::v1::wire::OperationFootprint;
use coppice_names::v1::{
    CommitRef, GenesisStatement, IronwoodActionRef, NameState, OperationKind, ProducerPosition,
    RegistrationIntent, StateData, StateRef, StateStatus, TransitionStatement, V1Operation,
    V1Parameters, decode_operation, encode_operation, operation_footprint,
};
use orchard::circuit::state_note_binding::{
    GenesisWitness, TransitionWitness, spend_auth_owner_key_bytes,
};
use orchard::keys::{FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey};
use orchard::note::{ExtractedNoteCommitment, Note, NoteVersion, RandomSeed, Rho};
use orchard::value::NoteValue;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;

use crate::names_v1_builder::{
    CarrierOutput, ChangeOutput, FundingSpend, NamesV1IronwoodPlan, NamesV1IronwoodShape,
    names_v1_ironwood_shape, names_v1_ironwood_shape_from_counts, required_zip317_fee_for_names_v1,
};

/// The canonical pre-broadcast COMMIT for a hidden registration intent.
///
/// COMMIT is carried by ordinary carrier outputs and has no designated
/// Ironwood action and no proof. This type intentionally exposes no producer
/// position: the canonical [`CommitRef`] referenced by REVEAL only exists
/// once the COMMIT transaction has a canonical producer position.
pub struct PreparedCommit {
    commitment: [u8; 32],
    operation: V1Operation,
    encoded: Vec<u8>,
    frames: Vec<[u8; 512]>,
}

/// Prepares the canonical `V1Operation::Commit` transport for `intent`.
///
/// The returned value already carries the final CNV1 bytes and CPV1 frames;
/// the caller broadcasts them by ordinary carrier outputs and later locates
/// the canonical [`CommitRef`] in the chain for the REVEAL it enables.
pub fn prepare_commit(intent: &RegistrationIntent) -> Result<PreparedCommit> {
    let commitment = intent
        .commitment()
        .map_err(|error| anyhow::anyhow!("derive Names v1 COMMIT commitment: {error:?}"))?;
    let operation = V1Operation::Commit { commitment };
    let encoded = encode_operation(&operation)
        .map_err(|error| anyhow::anyhow!("encode Names v1 COMMIT operation: {error:?}"))?;
    let decoded = decode_operation(&encoded)
        .map_err(|error| anyhow::anyhow!("decode Names v1 COMMIT operation: {error:?}"))?;
    ensure!(
        decoded == operation,
        "Names v1 COMMIT wire round-trip mismatch"
    );
    let frames = encode_frames(names_application_id().to_bytes(), &encoded)
        .map_err(|error| anyhow::anyhow!("frame Names v1 COMMIT operation: {error:?}"))?;
    Ok(PreparedCommit {
        commitment,
        operation,
        encoded,
        frames,
    })
}

impl PreparedCommit {
    /// The hidden COMMIT value that REVEAL must reference and match.
    pub const fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// The canonical COMMIT operation.
    pub const fn operation(&self) -> &V1Operation {
        &self.operation
    }

    /// Canonical CNV1 encoding of the COMMIT operation.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// CPV1 carrier frames; each becomes one carrier output.
    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }
}

/// Typed inputs for one canonical REVEAL. One constructor serves first
/// registrations and replacement registrations; they differ only in
/// [`RevealInputs::replacement_predecessor`].
pub struct RevealInputs {
    /// The disclosed registration intent; its commitment must match the
    /// referenced COMMIT.
    pub intent: RegistrationIntent,
    /// Exact canonical COMMIT reference. This only exists after the COMMIT
    /// transaction has a canonical producer position.
    pub commit: CommitRef,
    /// `Some(exact prior terminal state reference)` selects the explicit
    /// replacement path against that exact accepted head. `None` means
    /// either a first registration for a name with no prior accepted head,
    /// or a bounded-history no-predecessor reset. Whether a `None` reset is
    /// canonically eligible is a state-machine/replay semantic check and is
    /// deliberately not evaluated here.
    pub replacement_predecessor: Option<StateRef>,
    /// The bond input note spent by the designated REVEAL action. Its value
    /// is carried intact into the successor state note.
    pub registration_note: Note,
    /// Spending-key scope of `registration_note`; fixes the successor
    /// recipient diversifier.
    pub scope: Scope,
    /// Owner spending authority; must match `intent.owner_pk`.
    pub fvk: FullViewingKey,
    /// Spend authorizing key backing `fvk`; used by the genesis witness.
    pub ask: SpendAuthorizingKey,
    /// Exact Ironwood action index designated for this REVEAL. It is encoded
    /// in the operation and must be occupied by the designated
    /// spend/successor pair in the final transaction.
    pub designated_action_index: u32,
    /// Height at which the REVEAL will be mined. The initial lease is derived
    /// from the authoritative schedule at this height.
    pub operation_height: u32,
    /// Fresh successor-note seed bytes, bound to the derived rho. Draw them
    /// from the wallet RNG for every operation.
    pub successor_seed: [u8; 32],
}

/// A REVEAL prepared up to, but not including, its genesis proof.
pub struct RevealPreparation {
    intent: RegistrationIntent,
    commit: CommitRef,
    replacement_predecessor: Option<StateRef>,
    state_data: StateData,
    fvk: FullViewingKey,
    registration_note: Note,
    successor_note: Note,
    designated_action_index: u32,
    operation_height: u32,
    statement: GenesisStatement,
    witness: GenesisWitness,
}

/// Prepares a canonical REVEAL from typed inputs.
///
/// Locally enforces the typed binding between `inputs.intent` and
/// `inputs.commit` via the authoritative [`RegistrationIntent::commitment`]:
/// a reference to a different intent fails before any proof work. Canonical
/// COMMIT authenticity, maturity, TTL, anchoring, and reset eligibility
/// remain the caller's replay/state-machine responsibility.
///
/// Binds the intent, the exact COMMIT reference, the optional replacement
/// predecessor, the initial lease from `params` at `inputs.operation_height`,
/// the exact successor note and its commitment/future nullifier, the
/// designated action index, and the genesis statement and witness. The only
/// missing protocol-bound value is the genesis proof.
pub fn prepare_reveal(inputs: RevealInputs, params: V1Parameters) -> Result<RevealPreparation> {
    let RevealInputs {
        intent,
        commit,
        replacement_predecessor,
        registration_note,
        scope,
        fvk,
        ask,
        designated_action_index,
        operation_height,
        successor_seed,
    } = inputs;
    let expected_commitment = intent
        .commitment()
        .map_err(|error| anyhow::anyhow!("derive REVEAL commitment: {error:?}"))?;
    ensure!(
        expected_commitment == commit.commitment,
        "REVEAL intent commitment does not match the supplied COMMIT reference"
    );
    ensure!(
        intent.owner_pk == spend_auth_owner_key_bytes(&ask),
        "REVEAL owner key does not match the supplied spend authorizing key"
    );
    let name_id = intent
        .name_id()
        .map_err(|error| anyhow::anyhow!("derive REVEAL name id: {error:?}"))?;
    // Local typed height bindings only: the intended REVEAL height must land
    // inside this COMMIT's lifetime at the name's scheduled anchor. Canonical
    // COMMIT authenticity, reorg state, name availability, replacement
    // validity, and reset eligibility remain replay/state-machine checks.
    ensure!(
        operation_height > commit.position.height,
        "intended REVEAL height must be strictly after the canonical COMMIT height"
    );
    ensure!(
        operation_height
            <= commit
                .position
                .height
                .checked_add(params.commit_ttl_blocks)
                .context("Names v1 COMMIT lifetime overflow")?,
        "intended REVEAL height is beyond the canonical COMMIT lifetime"
    );
    ensure!(
        is_anchor_height(name_id, operation_height, params),
        "intended REVEAL height is not the name's scheduled anchor height"
    );
    let registration_nullifier = registration_note.nullifier(&fvk).to_bytes();
    let successor_note = successor_state_note(
        &fvk,
        scope,
        &registration_note,
        registration_nullifier,
        successor_seed,
    )?;
    let successor_commitment =
        ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes();
    let successor_future_nullifier = successor_note.nullifier(&fvk).to_bytes();
    let lease_expiry = params
        .lease_expiry(operation_height)
        .context("Names v1 lease expiry overflow at the REVEAL height")?;
    let state_data = StateData {
        name_id,
        owner_pk: intent.owner_pk,
        sequence: 0,
        record: intent.record.clone(),
        lease_expiry,
        status: StateStatus::Active,
        terminal_height: 0,
    };
    let state_ref = StateRef::new(
        // Placeholder position: the chain assigns the canonical producer
        // position when the REVEAL is mined, and neither the genesis proof
        // nor the wire format binds it.
        ProducerPosition::new(operation_height, 0, [0; 32]),
        designated_action_index,
        0,
        successor_commitment,
        successor_future_nullifier,
    );
    let state = NameState::new(state_data.clone(), successor_commitment, state_ref)
        .map_err(|error| anyhow::anyhow!("construct REVEAL successor state: {error:?}"))?;
    let action = IronwoodActionRef {
        action_index: designated_action_index,
        nullifier: registration_nullifier,
        commitment: successor_commitment,
    };
    let statement =
        GenesisStatement::from_reveal(&intent, &state, action, operation_height, params)
            .map_err(|error| anyhow::anyhow!("construct Names v1 genesis statement: {error:?}"))?;
    let witness = GenesisWitness::new(
        registration_note.clone(),
        successor_note.clone(),
        &fvk,
        scope,
        params.minimum_bond_zatoshis,
    )
    .context("registration bond does not satisfy the genesis minimum")?;
    Ok(RevealPreparation {
        intent,
        commit,
        replacement_predecessor,
        state_data,
        fvk,
        registration_note,
        successor_note,
        designated_action_index,
        operation_height,
        statement,
        witness,
    })
}

impl RevealPreparation {
    /// The genesis statement bound to the exact successor.
    pub const fn statement(&self) -> &GenesisStatement {
        &self.statement
    }

    /// The genesis witness consumed by `prove_genesis`.
    pub const fn witness(&self) -> &GenesisWitness {
        &self.witness
    }

    /// The exact successor state note created by the designated action.
    pub const fn successor_note(&self) -> &Note {
        &self.successor_note
    }

    /// The exact designated Ironwood action index committed by the operation.
    pub const fn designated_action_index(&self) -> u32 {
        self.designated_action_index
    }

    /// The exact intended canonical height of this operation.
    pub const fn operation_height(&self) -> u32 {
        self.operation_height
    }

    /// Attaches the generated genesis proof and completes the canonical
    /// REVEAL operation, its CNV1 bytes, and its CPV1 frames.
    pub fn finalize(self, genesis_proof: Vec<u8>) -> Result<FinalizedOperation> {
        ensure!(!genesis_proof.is_empty(), "Names v1 genesis proof is empty");
        let operation = V1Operation::Reveal {
            intent: Box::new(self.intent),
            commit: self.commit,
            replacement_predecessor: self.replacement_predecessor,
            state: self.state_data,
            state_commitment: self.statement.commitment,
            state_nullifier: self.statement.state_nullifier,
            action_index: self.designated_action_index,
            proof: genesis_proof,
        };
        finalize_operation(
            operation,
            self.fvk,
            self.registration_note,
            self.successor_note,
            self.operation_height,
        )
    }
}

/// Exact predecessor material for one UPDATE, RENEW, or RELEASE.
pub struct TransitionInputs {
    /// The exact accepted canonical head being spent. Its `StateRef` is bound
    /// into the operation and its transition proof.
    pub predecessor: NameState,
    /// The wallet-controlled note opening of `predecessor`. Its value is
    /// carried intact into the successor state note.
    pub predecessor_note: Note,
    /// Spending-key scope of `predecessor_note`; fixes the successor
    /// recipient diversifier.
    pub scope: Scope,
    /// Owner spending authority; must match `predecessor.data.owner_pk`.
    pub fvk: FullViewingKey,
    /// Spend authorizing key backing `fvk`; used by the transition witness.
    pub ask: SpendAuthorizingKey,
    /// Height at which the operation will be mined. It must precede the
    /// predecessor lease, and for RENEW it must be the name's scheduled
    /// anchor height.
    pub operation_height: u32,
    /// Exact Ironwood action index designated for this operation. It is
    /// encoded in the operation and must be occupied by the designated
    /// predecessor/successor pair in the final transaction.
    pub designated_action_index: u32,
    /// Fresh successor-note seed bytes, bound to the derived rho. Draw them
    /// from the wallet RNG for every operation.
    pub successor_seed: [u8; 32],
}

/// A state transition prepared up to, but not including, its transition proof.
pub struct TransitionPreparation {
    statement: TransitionStatement,
    witness: TransitionWitness,
    predecessor_state_ref: StateRef,
    state_data: StateData,
    fvk: FullViewingKey,
    predecessor_note: Note,
    successor_note: Note,
    designated_action_index: u32,
    operation_height: u32,
}

/// Prepares a canonical UPDATE from typed inputs.
///
/// The successor changes the canonical record to `record` and preserves the
/// predecessor owner, lease, Active status, and zero terminal height, with
/// sequence increased by one. The record must differ from the predecessor
/// record, as the state machine requires.
pub fn prepare_update(
    inputs: TransitionInputs,
    record: Vec<u8>,
    params: V1Parameters,
) -> Result<TransitionPreparation> {
    ensure!(
        record != inputs.predecessor.data.record,
        "UPDATE must change the canonical record"
    );
    let mut successor_data = active_successor_data(&inputs.predecessor.data)?;
    successor_data.record = record;
    prepare_transition(inputs, successor_data, OperationKind::Update, params)
}

/// Prepares a canonical RENEW from typed inputs.
///
/// The successor preserves the predecessor record and owner, stays Active
/// with zero terminal height, increases the sequence by one, and extends the
/// lease to the authoritative value for the name's scheduled anchor height
/// at `inputs.operation_height`. Construction fails if that height is not a
/// scheduled anchor or would not strictly extend the lease.
pub fn prepare_renew(
    inputs: TransitionInputs,
    params: V1Parameters,
) -> Result<TransitionPreparation> {
    let name_id = inputs.predecessor.data.name_id;
    ensure!(
        is_anchor_height(name_id, inputs.operation_height, params),
        "RENEW must be constructed at the name's scheduled anchor height"
    );
    let lease_expiry = params
        .lease_expiry(inputs.operation_height)
        .context("Names v1 lease expiry overflow at the RENEW height")?;
    ensure!(
        lease_expiry > inputs.predecessor.data.lease_expiry,
        "RENEW lease must strictly extend the predecessor lease"
    );
    let mut successor_data = active_successor_data(&inputs.predecessor.data)?;
    successor_data.lease_expiry = lease_expiry;
    prepare_transition(inputs, successor_data, OperationKind::Renew, params)
}

/// Prepares a canonical RELEASE from typed inputs.
///
/// The successor preserves the predecessor record, owner, and lease, carries
/// `Released` status, and terminates at `inputs.operation_height`, with
/// sequence increased by one.
pub fn prepare_release(
    inputs: TransitionInputs,
    params: V1Parameters,
) -> Result<TransitionPreparation> {
    let mut successor_data = active_successor_data(&inputs.predecessor.data)?;
    successor_data.status = StateStatus::Released;
    successor_data.terminal_height = inputs.operation_height;
    prepare_transition(inputs, successor_data, OperationKind::Release, params)
}

impl TransitionPreparation {
    /// The transition statement bound to the exact predecessor and successor.
    pub const fn statement(&self) -> &TransitionStatement {
        &self.statement
    }

    /// The transition witness consumed by `prove_transition`.
    pub const fn witness(&self) -> &TransitionWitness {
        &self.witness
    }

    /// The exact successor state note created by the designated action.
    pub const fn successor_note(&self) -> &Note {
        &self.successor_note
    }

    /// The exact designated Ironwood action index committed by the operation.
    pub const fn designated_action_index(&self) -> u32 {
        self.designated_action_index
    }

    /// The exact intended canonical height of this operation.
    pub const fn operation_height(&self) -> u32 {
        self.operation_height
    }

    /// Attaches the generated transition proof and completes the canonical
    /// operation, its CNV1 bytes, and its CPV1 frames.
    pub fn finalize(self, transition_proof: Vec<u8>) -> Result<FinalizedOperation> {
        ensure!(
            !transition_proof.is_empty(),
            "Names v1 transition proof is empty"
        );
        let operation = match self.statement.operation {
            OperationKind::Update => V1Operation::Update {
                predecessor: self.predecessor_state_ref,
                state: self.state_data,
                state_commitment: self.statement.successor_commitment,
                state_nullifier: self.statement.successor_nullifier,
                action_index: self.designated_action_index,
                proof: transition_proof,
            },
            OperationKind::Renew => V1Operation::Renew {
                predecessor: self.predecessor_state_ref,
                state: self.state_data,
                state_commitment: self.statement.successor_commitment,
                state_nullifier: self.statement.successor_nullifier,
                action_index: self.designated_action_index,
                proof: transition_proof,
            },
            OperationKind::Release => V1Operation::Release {
                predecessor: self.predecessor_state_ref,
                state: self.state_data,
                state_commitment: self.statement.successor_commitment,
                state_nullifier: self.statement.successor_nullifier,
                action_index: self.designated_action_index,
                proof: transition_proof,
            },
        };
        finalize_operation(
            operation,
            self.fvk,
            self.predecessor_note,
            self.successor_note,
            self.operation_height,
        )
    }
}

/// Carrier-output policy for one finalized state operation's CPV1 frames.
///
/// Every CPV1 frame becomes one distinct Ironwood rendezvous output with this
/// recipient and value; the frame memo is the output memo. The value is a
/// wallet funding decision, bounded below by the protocol dust threshold.
pub struct CarrierPlan {
    /// Recipient of every carrier output.
    pub recipient: orchard::Address,
    /// Value of every carrier output.
    pub value: NoteValue,
}

/// Transport policy for the successor state-note output.
///
/// The note opening itself is already fixed by the finalized operation; this
/// selects only how the output is transmitted. A wallet that must later spend
/// the state note from a restored wallet database should supply its own
/// outgoing viewing key; with `ovk: None` the constructor supplies no OVK and
/// makes no recoverability guarantee through any outgoing ciphertext. The
/// empty memo is the canonical Orchard default and carries no Names
/// semantics.
pub struct SuccessorTransport {
    /// Outgoing viewing key under which the successor output is recoverable.
    pub ovk: Option<OutgoingViewingKey>,
    /// Orchard memo carried by the successor output.
    pub memo: [u8; 512],
}

/// Ordinary wallet funding for one designated-pair state operation bundle.
///
/// Zero or more additional funding spends and zero or more wallet change
/// outputs are allowed. The designated predecessor/bond value is preserved
/// exactly into the successor state note, so it contributes nothing net to
/// the fee: the additional funding spends pay the carrier outputs, the
/// ZIP-317 fee, and any change. The designated spend and the exact successor
/// always occupy the encoded designated action; funding and change occupy
/// other actions.
pub struct OperationFunding {
    /// Additional real Ironwood spends used for funding.
    pub funding_spends: Vec<FundingSpend>,
    /// Wallet-controlled Ironwood change outputs.
    pub change_outputs: Vec<ChangeOutput>,
}

/// Physical shape and ZIP-317 fee preview taken before funding is sized.
///
/// The fee is planned at exactly the finalized operation's intended height;
/// there is no independent height argument to drift. Returns the shape
/// implied by the finalized operation plus `funding_spend_count` additional
/// real spends and `change_output_count` change outputs, and the ZIP-317 fee
/// that shape requires at that height. A wallet uses the fee and its own
/// carrier value policy to size funding and change before calling
/// [`plan_state_operation`].
pub fn planned_state_operation_shape_and_fee<P: Parameters>(
    params: &P,
    finalized: &FinalizedOperation,
    funding_spend_count: usize,
    change_output_count: usize,
) -> Result<(NamesV1IronwoodShape, Zatoshis)> {
    let carrier_count = finalized.frames().len();
    let designated_action_index = usize::try_from(finalized.designated_action_index())
        .context("designated Names action index does not fit usize")?;
    let real_spend_count = 1usize
        .checked_add(funding_spend_count)
        .context("Names v1 real-spend count overflowed usize")?;
    let shape = names_v1_ironwood_shape_from_counts(
        real_spend_count,
        carrier_count,
        change_output_count,
        designated_action_index,
    )?;
    let fee = required_zip317_fee_for_names_v1(
        params,
        BlockHeight::from_u32(finalized.operation_height()),
        shape,
    )?;
    Ok((shape, fee))
}

/// The designated-pair Ironwood plan for one finalized state operation,
/// together with the ZIP-317 fee the planned shape requires.
pub struct StateOperationPlan {
    /// Plan for [`crate::names_v1_builder::build_names_v1_bundle`]. The
    /// designated spend and the exact successor occupy the same action,
    /// which is the action index already encoded in the operation, and the
    /// plan carries the operation's intended height for the later PCZT
    /// expiry binding.
    pub plan: NamesV1IronwoodPlan,
    /// Physical shape `plan` must produce.
    pub planned_shape: NamesV1IronwoodShape,
    /// ZIP-317 fee required for `planned_shape` at the operation height. The
    /// built bundle's value balance must equal this fee.
    pub required_fee: Zatoshis,
    /// Total value paid out by the carrier outputs.
    pub carrier_value_total: u64,
    /// The finalized operation's intended canonical height.
    pub operation_height: u32,
}

/// Assembles the designated-pair Ironwood plan for a finalized state operation.
///
/// The fee and shape are planned at exactly the finalized operation's
/// intended height; the carrier outputs are derived from the operation's
/// CPV1 frames under `carriers`; the successor output is transmitted under
/// `successor`; funding and change are supplied exactly as the wallet sized
/// them. The plan fails closed unless the supplied inputs contribute exactly
/// `required_fee` after paying the carrier and change outputs, so underfunded
/// or overfunding shapes are rejected before any proving or signing. The
/// designated action index is taken from the encoded operation, so a later
/// stage cannot move or reassign the designated pair.
pub fn plan_state_operation<P: Parameters>(
    params: &P,
    finalized: &FinalizedOperation,
    carriers: CarrierPlan,
    successor: SuccessorTransport,
    funding: OperationFunding,
) -> Result<StateOperationPlan> {
    let operation_height = finalized.operation_height();
    let carrier_outputs = finalized
        .frames()
        .iter()
        .copied()
        .map(|memo| CarrierOutput {
            recipient: carriers.recipient,
            value: carriers.value,
            memo,
        })
        .collect::<Vec<_>>();
    let designated_action_index = usize::try_from(finalized.designated_action_index())
        .context("designated Names action index does not fit usize")?;
    let real_spend_count = 1usize
        .checked_add(funding.funding_spends.len())
        .context("Names v1 real-spend count overflowed usize")?;
    let planned_shape = names_v1_ironwood_shape_from_counts(
        real_spend_count,
        carrier_outputs.len(),
        funding.change_outputs.len(),
        designated_action_index,
    )?;
    let required_fee = required_zip317_fee_for_names_v1(
        params,
        BlockHeight::from_u32(operation_height),
        planned_shape,
    )?;
    let carrier_value_total = carriers
        .value
        .inner()
        .checked_mul(
            u64::try_from(carrier_outputs.len()).context("carrier count does not fit u64")?,
        )
        .context("carrier output value overflowed u64")?;

    // The designated bond value returns to the successor output (the
    // construction preserves value exactly), so the fee is funded by the
    // additional funding spends net of carrier and change outputs.
    let funding_value_total = funding
        .funding_spends
        .iter()
        .try_fold(0u64, |total, spend| {
            total
                .checked_add(spend.note.value().inner())
                .context("funding spend value overflowed u64")
        })?;
    let change_value_total = funding
        .change_outputs
        .iter()
        .try_fold(0u64, |total, output| {
            total
                .checked_add(output.value.inner())
                .context("change output value overflowed u64")
        })?;
    let contributed_fee = finalized
        .designated_note
        .value()
        .inner()
        .checked_add(funding_value_total)
        .and_then(|value| value.checked_sub(finalized.successor_note.value().inner()))
        .and_then(|value| value.checked_sub(carrier_value_total))
        .and_then(|value| value.checked_sub(change_value_total))
        .context("funding does not cover the carrier outputs and change outputs")?;
    ensure!(
        contributed_fee == required_fee.into_u64(),
        "Names v1 funding does not balance: supplied inputs contribute {contributed_fee} zatoshis toward a required ZIP-317 fee of {}",
        required_fee.into_u64()
    );

    let plan = NamesV1IronwoodPlan {
        designated_fvk: finalized.owner_fvk.clone(),
        designated_spend: finalized.designated_note.clone(),
        successor_note: finalized.successor_note.clone(),
        successor_ovk: successor.ovk,
        successor_memo: successor.memo,
        carrier_outputs,
        funding_spends: funding.funding_spends,
        change_outputs: funding.change_outputs,
        designated_action_index,
        operation_height,
    };
    ensure!(
        names_v1_ironwood_shape(&plan)? == planned_shape,
        "Names v1 plan shape changed after fee planning"
    );
    Ok(StateOperationPlan {
        plan,
        planned_shape,
        required_fee,
        carrier_value_total,
        operation_height,
    })
}

/// A complete, proof-carrying state operation and its canonical transport.
///
/// Everything exposed here is protocol-bound: the operation commits to its
/// designated action index, the CNV1 bytes are final, and the successor note
/// is the exact opening created by the designated action.
pub struct FinalizedOperation {
    operation: V1Operation,
    encoded: Vec<u8>,
    frames: Vec<[u8; 512]>,
    footprint: OperationFootprint,
    owner_fvk: FullViewingKey,
    designated_note: Note,
    successor_note: Note,
    operation_height: u32,
}

impl FinalizedOperation {
    /// The canonical, proof-carrying operation.
    pub const fn operation(&self) -> &V1Operation {
        &self.operation
    }

    /// Canonical CNV1 encoding of the operation.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// CPV1 carrier frames; each becomes one carrier output.
    pub fn frames(&self) -> &[[u8; 512]] {
        &self.frames
    }

    /// Encoded operation, proof, and CPV1 transport footprint.
    pub const fn footprint(&self) -> &OperationFootprint {
        &self.footprint
    }

    /// The exact successor state note created by the designated action. The
    /// wallet must retain this opening to spend the successor later.
    pub const fn successor_note(&self) -> &Note {
        &self.successor_note
    }

    /// The exact designated Ironwood action index committed by the operation.
    pub fn designated_action_index(&self) -> u32 {
        self.operation
            .action_index()
            .expect("state operations carry an action index")
    }

    /// The exact intended canonical height of this operation. Fee planning
    /// and the later PCZT expiry height are bound to this value.
    pub const fn operation_height(&self) -> u32 {
        self.operation_height
    }
}

/// Constructs the exact successor state note bound to one spent state note:
/// same value, recipient derived from the owner key at `scope`, rho equal to
/// the spent note's nullifier, and seed bound to that rho.
fn successor_state_note(
    fvk: &FullViewingKey,
    scope: Scope,
    spent: &Note,
    spent_nullifier: [u8; 32],
    successor_seed: [u8; 32],
) -> Result<Note> {
    let rho = Option::<Rho>::from(Rho::from_bytes(&spent_nullifier))
        .context("spent state-note nullifier is not a valid successor rho")?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(successor_seed, &rho))
        .context("successor note seed is not canonical for its rho")?;
    Ok(Option::<Note>::from(Note::from_parts(
        fvk.address_at(0u32, scope),
        spent.value(),
        rho,
        rseed,
        NoteVersion::V3,
    ))
    .context("construct exact successor state note")?)
}

/// The Active sequence+1 successor skeleton preserving identity, record, and
/// lease; individual operations override their distinct policy fields.
fn active_successor_data(predecessor: &StateData) -> Result<StateData> {
    Ok(StateData {
        name_id: predecessor.name_id,
        owner_pk: predecessor.owner_pk,
        sequence: predecessor
            .sequence
            .checked_add(1)
            .context("Names v1 successor sequence overflow")?,
        record: predecessor.record.clone(),
        lease_expiry: predecessor.lease_expiry,
        status: StateStatus::Active,
        terminal_height: 0,
    })
}

/// Shared transition primitive: validates the predecessor binding, builds the
/// exact successor note, and constructs the statement and witness.
fn prepare_transition(
    inputs: TransitionInputs,
    successor_data: StateData,
    kind: OperationKind,
    params: V1Parameters,
) -> Result<TransitionPreparation> {
    let TransitionInputs {
        predecessor,
        predecessor_note,
        scope,
        fvk,
        ask,
        operation_height,
        designated_action_index,
        successor_seed,
    } = inputs;
    ensure!(
        predecessor.data.owner_pk == spend_auth_owner_key_bytes(&ask),
        "transition owner key does not match the supplied spend authorizing key"
    );
    ensure!(
        predecessor.data.status == StateStatus::Active && predecessor.data.terminal_height == 0,
        "transition predecessor is not an active non-terminal state"
    );
    ensure!(
        operation_height < predecessor.data.lease_expiry,
        "transition height is at or beyond the predecessor lease expiry"
    );
    let predecessor_commitment =
        ExtractedNoteCommitment::from(predecessor_note.commitment()).to_bytes();
    ensure!(
        predecessor_commitment == predecessor.commitment,
        "supplied predecessor note does not match the accepted state head"
    );
    let predecessor_nullifier = predecessor_note.nullifier(&fvk).to_bytes();
    ensure!(
        predecessor_nullifier == predecessor.state_ref.nullifier,
        "supplied predecessor note nullifier differs from the accepted state head"
    );
    let successor_note = successor_state_note(
        &fvk,
        scope,
        &predecessor_note,
        predecessor_nullifier,
        successor_seed,
    )?;
    let successor_commitment =
        ExtractedNoteCommitment::from(successor_note.commitment()).to_bytes();
    let successor_future_nullifier = successor_note.nullifier(&fvk).to_bytes();
    let successor_state_ref = StateRef::new(
        // Placeholder position: the chain assigns the canonical producer
        // position when the operation is mined, and neither the transition
        // proof nor the wire format binds it.
        ProducerPosition::new(operation_height, 0, [0; 32]),
        designated_action_index,
        0,
        successor_commitment,
        successor_future_nullifier,
    );
    let successor = NameState::new(
        successor_data.clone(),
        successor_commitment,
        successor_state_ref,
    )
    .map_err(|error| anyhow::anyhow!("construct transition successor state: {error:?}"))?;
    let action = IronwoodActionRef {
        action_index: designated_action_index,
        nullifier: predecessor_nullifier,
        commitment: successor_commitment,
    };
    let statement = TransitionStatement::from_states(
        &predecessor,
        &successor,
        action,
        kind,
        operation_height,
        params,
    )
    .map_err(|error| anyhow::anyhow!("construct Names v1 transition statement: {error:?}"))?;
    let witness = TransitionWitness::new(
        predecessor_note.clone(),
        successor_note.clone(),
        &fvk,
        scope,
    );
    Ok(TransitionPreparation {
        statement,
        witness,
        predecessor_state_ref: predecessor.state_ref,
        state_data: successor_data,
        fvk,
        predecessor_note,
        successor_note,
        designated_action_index,
        operation_height,
    })
}

/// Encodes a proof-carrying operation and verifies its CNV1 and CPV1 round
/// trips before anything is exposed to the caller.
fn finalize_operation(
    operation: V1Operation,
    owner_fvk: FullViewingKey,
    designated_note: Note,
    successor_note: Note,
    operation_height: u32,
) -> Result<FinalizedOperation> {
    let encoded = encode_operation(&operation)
        .map_err(|error| anyhow::anyhow!("encode Names v1 operation: {error:?}"))?;
    let decoded = decode_operation(&encoded)
        .map_err(|error| anyhow::anyhow!("decode Names v1 operation: {error:?}"))?;
    ensure!(decoded == operation, "Names v1 wire round-trip mismatch");
    let footprint = operation_footprint(&operation)
        .map_err(|error| anyhow::anyhow!("measure Names v1 operation: {error:?}"))?;
    let app_id = names_application_id().to_bytes();
    let frames = encode_frames(app_id, &encoded)
        .map_err(|error| anyhow::anyhow!("frame Names v1 operation: {error:?}"))?;
    let reconstructed = reconstruct_frames(&frames, app_id)
        .map_err(|error| anyhow::anyhow!("reconstruct Names v1 frames: {error:?}"))?;
    ensure!(
        reconstructed == encoded,
        "CPV1 reconstruction changed the CNV1 bytes"
    );
    let reconstructed_operation = decode_operation(&reconstructed)
        .map_err(|error| anyhow::anyhow!("decode reconstructed Names v1 operation: {error:?}"))?;
    ensure!(
        reconstructed_operation == operation,
        "CPV1 decode changed the Names v1 operation"
    );
    ensure!(
        frames.len() == footprint.cpv1_frames,
        "CPV1 footprint disagrees with the framed operation"
    );
    Ok(FinalizedOperation {
        operation,
        encoded,
        frames,
        footprint,
        owner_fvk,
        designated_note,
        successor_note,
        operation_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names_v1_builder::{
        NamesV1PcztPlan, build_names_v1_bundle, build_names_v1_pczt,
        required_zip317_fee_for_names_v1,
    };
    use coppice_names::v1::schedule::next_anchor_height;
    use orchard::keys::SpendingKey;
    use rand::{SeedableRng, rngs::StdRng};
    use zcash_protocol::consensus::BranchId;
    use zcash_protocol::local_consensus::LocalNetwork;

    /// Deterministic local v6 consensus parameters (regtest-shaped).
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

    fn key_material(byte: u8) -> (FullViewingKey, SpendAuthorizingKey) {
        let spending_key = SpendingKey::from_bytes([byte; 32]).unwrap();
        (
            FullViewingKey::from(&spending_key),
            SpendAuthorizingKey::from(&spending_key),
        )
    }

    /// A synthetic bond input note with a deterministic rho and seed.
    fn bond_note(fvk: &FullViewingKey, value: u64, rho_byte: u8, seed_byte: u8) -> Note {
        let mut rho_bytes = [0; 32];
        rho_bytes[0] = rho_byte;
        let rho = Rho::from_bytes(&rho_bytes).unwrap();
        let rseed = RandomSeed::from_bytes([seed_byte; 32], &rho).unwrap();
        Option::<Note>::from(Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .expect("deterministic bond note is valid")
    }

    fn test_intent(
        ask: &SpendAuthorizingKey,
        record_byte: u8,
        secret_byte: u8,
    ) -> RegistrationIntent {
        RegistrationIntent {
            name: "prodtest".to_owned(),
            owner_pk: spend_auth_owner_key_bytes(ask),
            record: vec![record_byte; 64],
            secret: [secret_byte; 32],
        }
    }

    /// A frozen canonical COMMIT reference at height 30 plus the first legal
    /// REVEAL height for the intent's name: strictly after the COMMIT, inside
    /// its TTL, and at the name's scheduled anchor.
    fn reveal_commit_and_height(
        intent: &RegistrationIntent,
        params: V1Parameters,
    ) -> (CommitRef, u32) {
        let commit_height = 30;
        let reveal_height =
            next_anchor_height(intent.name_id().unwrap(), commit_height + 1, params)
                .expect("every COMMIT admits a scheduled reveal inside its lifetime");
        (
            CommitRef::new(
                ProducerPosition::new(commit_height, 1, [3; 32]),
                0,
                intent.commitment().unwrap(),
            ),
            reveal_height,
        )
    }

    /// Builds the canonical predecessor head a machine would reconstruct from
    /// a mined operation.
    fn accepted_head(
        operation: &V1Operation,
        producer_height: u32,
        producer_txid: [u8; 32],
    ) -> NameState {
        let (state, commitment, nullifier, action_index) = match operation {
            V1Operation::Reveal {
                state,
                state_commitment,
                state_nullifier,
                action_index,
                ..
            }
            | V1Operation::Update {
                state,
                state_commitment,
                state_nullifier,
                action_index,
                ..
            }
            | V1Operation::Renew {
                state,
                state_commitment,
                state_nullifier,
                action_index,
                ..
            }
            | V1Operation::Release {
                state,
                state_commitment,
                state_nullifier,
                action_index,
                ..
            } => (
                state.clone(),
                *state_commitment,
                *state_nullifier,
                *action_index,
            ),
            V1Operation::Commit { .. } => panic!("COMMIT does not create a state head"),
        };
        let state_ref = StateRef::new(
            ProducerPosition::new(producer_height, 0, producer_txid),
            action_index,
            0,
            commitment,
            nullifier,
        );
        NameState::new(state, commitment, state_ref).expect("mined operation state is a valid head")
    }

    #[test]
    fn commit_preparation_matches_intent_and_round_trips() {
        let (_, ask) = key_material(7);
        let intent = test_intent(&ask, 3, 5);
        let prepared = prepare_commit(&intent).unwrap();
        let expected_commitment = intent.commitment().unwrap();

        assert_eq!(prepared.commitment(), expected_commitment);
        assert_eq!(
            prepared.operation(),
            &V1Operation::Commit {
                commitment: expected_commitment
            }
        );
        assert_eq!(
            decode_operation(prepared.encoded()).unwrap(),
            *prepared.operation()
        );
        let app_id = names_application_id().to_bytes();
        let reconstructed = reconstruct_frames(prepared.frames(), app_id).unwrap();
        assert_eq!(reconstructed, prepared.encoded());
        assert_eq!(
            decode_operation(&reconstructed).unwrap(),
            *prepared.operation()
        );
    }

    #[test]
    fn first_reveal_binds_exact_successor_statement_and_wire() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(11);
        let registration_note = bond_note(&fvk, 50_000, 1, 2);
        let registration_nullifier = registration_note.nullifier(&fvk).to_bytes();
        let intent = test_intent(&ask, 4, 6);
        let (commit, height) = reveal_commit_and_height(&intent, params);
        let action_index = 2;

        let preparation = prepare_reveal(
            RevealInputs {
                intent: intent.clone(),
                commit,
                replacement_predecessor: None,
                registration_note: registration_note.clone(),
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: action_index,
                operation_height: height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();

        let statement = preparation.statement();
        assert_eq!(
            statement.commitment,
            ExtractedNoteCommitment::from(preparation.successor_note().commitment()).to_bytes()
        );
        assert_eq!(statement.registration_nullifier, registration_nullifier);
        assert_eq!(
            statement.state_nullifier,
            preparation.successor_note().nullifier(&fvk).to_bytes()
        );
        assert_eq!(statement.lease_expiry, params.lease_expiry(height).unwrap());
        assert_eq!(statement.sequence, 0);
        assert_eq!(
            statement.minimum_bond_zatoshis,
            params.minimum_bond_zatoshis
        );
        assert_eq!(
            preparation.successor_note().rho().to_bytes(),
            registration_nullifier
        );
        assert_eq!(
            preparation.successor_note().value(),
            registration_note.value()
        );
        assert_eq!(preparation.designated_action_index(), action_index);

        let successor_commitment = statement.commitment;
        let successor_future_nullifier = statement.state_nullifier;
        let lease_expiry = statement.lease_expiry;
        let dummy_proof = vec![0x5A; 1_920];
        let finalized = preparation.finalize(dummy_proof.clone()).unwrap();

        // The manual composition below reproduces the pre-extraction live
        // construction from the same typed inputs; CNV1 bytes must be
        // identical.
        let manual = V1Operation::Reveal {
            intent: Box::new(intent.clone()),
            commit,
            replacement_predecessor: None,
            state: StateData {
                name_id: intent.name_id().unwrap(),
                owner_pk: intent.owner_pk,
                sequence: 0,
                record: intent.record.clone(),
                lease_expiry,
                status: StateStatus::Active,
                terminal_height: 0,
            },
            state_commitment: successor_commitment,
            state_nullifier: successor_future_nullifier,
            action_index,
            proof: dummy_proof.clone(),
        };
        assert_eq!(encode_operation(&manual).unwrap(), finalized.encoded());
        assert_eq!(
            decode_operation(finalized.encoded()).unwrap(),
            *finalized.operation()
        );
        match finalized.operation() {
            V1Operation::Reveal {
                replacement_predecessor,
                state,
                state_commitment,
                state_nullifier,
                action_index: encoded_action_index,
                proof,
                ..
            } => {
                assert!(replacement_predecessor.is_none());
                assert_eq!(state.record, intent.record);
                assert_eq!(state.sequence, 0);
                assert_eq!(state.status, StateStatus::Active);
                assert_eq!(state.terminal_height, 0);
                assert_eq!(state.lease_expiry, lease_expiry);
                assert_eq!(*state_commitment, successor_commitment);
                assert_eq!(*state_nullifier, successor_future_nullifier);
                assert_eq!(*encoded_action_index, action_index);
                assert_eq!(*proof, dummy_proof);
            }
            other => panic!("unexpected operation kind: {other:?}"),
        }
        let app_id = names_application_id().to_bytes();
        assert_eq!(
            reconstruct_frames(finalized.frames(), app_id).unwrap(),
            finalized.encoded()
        );
        let footprint = finalized.footprint();
        assert_eq!(footprint.operation_bytes, finalized.encoded().len());
        assert_eq!(footprint.proof_bytes, dummy_proof.len());
        assert_eq!(footprint.cpv1_frames, finalized.frames().len());
    }

    #[test]
    fn replacement_reveal_carries_the_exact_prior_terminal_reference() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(12);
        let registration_note = bond_note(&fvk, 50_000, 2, 3);
        let intent = test_intent(&ask, 5, 7);
        let (commit, reveal_height) = reveal_commit_and_height(&intent, params);
        let prior_terminal = StateRef::new(
            ProducerPosition::new(30, 1, [8; 32]),
            4,
            0,
            [1; 32],
            [2; 32],
        );

        let inputs = |replacement_predecessor| RevealInputs {
            intent: intent.clone(),
            commit,
            replacement_predecessor,
            registration_note: registration_note.clone(),
            scope: Scope::External,
            fvk: fvk.clone(),
            ask: ask.clone(),
            designated_action_index: 2,
            operation_height: reveal_height,
            successor_seed: [9; 32],
        };

        let first = prepare_reveal(inputs(None), params)
            .unwrap()
            .finalize(vec![0x5A; 64])
            .unwrap();
        let replacement = prepare_reveal(inputs(Some(prior_terminal)), params)
            .unwrap()
            .finalize(vec![0x5A; 64])
            .unwrap();
        for (finalized, expected_predecessor) in [
            (&first, None::<StateRef>),
            (&replacement, Some(prior_terminal)),
        ] {
            match finalized.operation() {
                V1Operation::Reveal {
                    replacement_predecessor,
                    ..
                } => assert_eq!(*replacement_predecessor, expected_predecessor),
                other => panic!("unexpected operation kind: {other:?}"),
            }
        }
        // The two operations are identical apart from the replacement
        // reference: one protocol operation, two typed inputs.
        assert_ne!(first.encoded(), replacement.encoded());
    }

    #[test]
    fn reveal_rejects_commit_reference_for_a_different_intent() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(17);
        let registration_note = bond_note(&fvk, 40_000, 7, 8);
        let intent_a = test_intent(&ask, 5, 7);
        let intent_b = test_intent(&ask, 6, 7);
        assert_ne!(
            intent_a.commitment().unwrap(),
            intent_b.commitment().unwrap()
        );
        let commit_for_b = CommitRef::new(
            ProducerPosition::new(30, 1, [3; 32]),
            0,
            intent_b.commitment().unwrap(),
        );

        let error = prepare_reveal(
            RevealInputs {
                intent: intent_a,
                commit: commit_for_b,
                replacement_predecessor: None,
                registration_note,
                scope: Scope::External,
                fvk,
                ask,
                designated_action_index: 2,
                operation_height: 40,
                successor_seed: [9; 32],
            },
            params,
        )
        .err()
        .expect("REVEAL must reject a COMMIT reference bound to a different intent");
        assert!(
            error
                .to_string()
                .contains("does not match the supplied COMMIT reference"),
            "failure should be the intent/COMMIT binding check, got: {error}"
        );
    }

    #[test]
    fn update_changes_record_and_preserves_lease() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(13);
        let registration_note = bond_note(&fvk, 40_000, 2, 3);
        let intent = test_intent(&ask, 5, 7);
        let (commit, reveal_height) = reveal_commit_and_height(&intent, params);
        let reveal_preparation = prepare_reveal(
            RevealInputs {
                intent,
                commit,
                replacement_predecessor: None,
                registration_note,
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: 2,
                operation_height: reveal_height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();
        let predecessor_note = reveal_preparation.successor_note().clone();
        let reveal_finalized = reveal_preparation.finalize(vec![0x5A; 1_920]).unwrap();
        let predecessor = accepted_head(reveal_finalized.operation(), reveal_height, [7; 32]);

        let update_record = vec![6; 40];
        let update_height = reveal_height + 1;
        let update_preparation = prepare_update(
            TransitionInputs {
                predecessor: predecessor.clone(),
                predecessor_note: predecessor_note.clone(),
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                operation_height: update_height,
                designated_action_index: 3,
                successor_seed: [10; 32],
            },
            update_record.clone(),
            params,
        )
        .unwrap();

        let statement = update_preparation.statement();
        assert_eq!(statement.operation, OperationKind::Update);
        assert_eq!(
            statement.predecessor_ref_digest,
            predecessor.state_ref.digest()
        );
        assert_eq!(statement.predecessor_commitment, predecessor.commitment);
        assert_eq!(
            statement.predecessor_nullifier,
            predecessor_note.nullifier(&fvk).to_bytes()
        );
        assert_eq!(statement.predecessor_sequence, predecessor.data.sequence);
        assert_eq!(statement.successor_sequence, predecessor.data.sequence + 1);
        assert_eq!(
            statement.successor_lease_expiry,
            predecessor.data.lease_expiry
        );
        assert_ne!(
            statement.successor_record_digest,
            statement.predecessor_record_digest
        );
        assert_eq!(statement.successor_status, StateStatus::Active.code());
        assert_eq!(statement.successor_terminal_height, 0);
        assert_eq!(statement.operation_height, update_height);

        let update_successor_note = update_preparation.successor_note().clone();
        let successor_commitment = statement.successor_commitment;
        let successor_future_nullifier = statement.successor_nullifier;
        let dummy_proof = vec![0xA5; 1_920];
        let finalized = update_preparation.finalize(dummy_proof.clone()).unwrap();

        let manual = V1Operation::Update {
            predecessor: predecessor.state_ref,
            state: StateData {
                name_id: predecessor.data.name_id,
                owner_pk: predecessor.data.owner_pk,
                sequence: predecessor.data.sequence + 1,
                record: update_record.clone(),
                lease_expiry: predecessor.data.lease_expiry,
                status: StateStatus::Active,
                terminal_height: 0,
            },
            state_commitment: successor_commitment,
            state_nullifier: successor_future_nullifier,
            action_index: 3,
            proof: dummy_proof.clone(),
        };
        assert_eq!(encode_operation(&manual).unwrap(), finalized.encoded());
        match finalized.operation() {
            V1Operation::Update {
                predecessor: encoded_predecessor,
                state,
                action_index: encoded_action_index,
                ..
            } => {
                assert_eq!(*encoded_predecessor, predecessor.state_ref);
                assert_eq!(state.record, update_record);
                assert_eq!(state.lease_expiry, predecessor.data.lease_expiry);
                assert_eq!(state.status, StateStatus::Active);
                assert_eq!(state.terminal_height, 0);
                assert_eq!(*encoded_action_index, 3);
            }
            other => panic!("unexpected operation kind: {other:?}"),
        }
        assert_eq!(
            update_successor_note.value(),
            predecessor_note.value(),
            "transition preserves the bond value"
        );
        assert_eq!(
            update_successor_note.rho().to_bytes(),
            predecessor_note.nullifier(&fvk).to_bytes()
        );

        // A record-identical UPDATE is invalid construction.
        assert!(
            prepare_update(
                TransitionInputs {
                    predecessor: predecessor.clone(),
                    predecessor_note: predecessor_note.clone(),
                    scope: Scope::External,
                    fvk: fvk.clone(),
                    ask: ask.clone(),
                    operation_height: update_height,
                    designated_action_index: 3,
                    successor_seed: [10; 32],
                },
                predecessor.data.record.clone(),
                params,
            )
            .is_err()
        );
    }

    #[test]
    fn renew_preserves_record_and_extends_lease_at_scheduled_height() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(14);
        let registration_note = bond_note(&fvk, 40_000, 3, 4);
        let intent = test_intent(&ask, 5, 7);
        let name_id = intent.name_id().unwrap();
        let (commit, reveal_height) = reveal_commit_and_height(&intent, params);
        let reveal_preparation = prepare_reveal(
            RevealInputs {
                intent,
                commit,
                replacement_predecessor: None,
                registration_note,
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: 2,
                operation_height: reveal_height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();
        let predecessor_note = reveal_preparation.successor_note().clone();
        let reveal_finalized = reveal_preparation.finalize(vec![0x5A; 1_920]).unwrap();
        let predecessor = accepted_head(reveal_finalized.operation(), reveal_height, [7; 32]);

        let inputs = |operation_height, designated_action_index| TransitionInputs {
            predecessor: predecessor.clone(),
            predecessor_note: predecessor_note.clone(),
            scope: Scope::External,
            fvk: fvk.clone(),
            ask: ask.clone(),
            operation_height,
            designated_action_index,
            successor_seed: [10; 32],
        };

        // RENEW is only constructible at the name's scheduled anchor height.
        let renew_height = next_anchor_height(name_id, reveal_height + 1, params).unwrap();
        assert!(renew_height < predecessor.data.lease_expiry);
        let renew_preparation = prepare_renew(inputs(renew_height, 1), params).unwrap();

        let statement = renew_preparation.statement();
        assert_eq!(statement.operation, OperationKind::Renew);
        assert_eq!(
            statement.predecessor_ref_digest,
            predecessor.state_ref.digest()
        );
        assert_eq!(statement.predecessor_sequence, predecessor.data.sequence);
        assert_eq!(statement.successor_sequence, predecessor.data.sequence + 1);
        assert_eq!(
            statement.predecessor_record_digest,
            statement.successor_record_digest
        );
        assert_eq!(
            statement.predecessor_lease_expiry,
            predecessor.data.lease_expiry
        );
        assert_eq!(
            statement.successor_lease_expiry,
            params.lease_expiry(renew_height).unwrap()
        );
        assert!(statement.successor_lease_expiry > statement.predecessor_lease_expiry);
        assert_eq!(statement.predecessor_status, StateStatus::Active.code());
        assert_eq!(statement.successor_status, StateStatus::Active.code());
        assert_eq!(statement.successor_terminal_height, 0);
        assert_eq!(statement.operation_height, renew_height);

        let renew_successor_note = renew_preparation.successor_note().clone();
        let successor_commitment = statement.successor_commitment;
        let successor_future_nullifier = statement.successor_nullifier;
        let successor_lease_expiry = statement.successor_lease_expiry;
        let finalized = renew_preparation.finalize(vec![0xA5; 1_920]).unwrap();
        let manual = V1Operation::Renew {
            predecessor: predecessor.state_ref,
            state: StateData {
                name_id: predecessor.data.name_id,
                owner_pk: predecessor.data.owner_pk,
                sequence: predecessor.data.sequence + 1,
                record: predecessor.data.record.clone(),
                lease_expiry: successor_lease_expiry,
                status: StateStatus::Active,
                terminal_height: 0,
            },
            state_commitment: successor_commitment,
            state_nullifier: successor_future_nullifier,
            action_index: 1,
            proof: vec![0xA5; 1_920],
        };
        assert_eq!(encode_operation(&manual).unwrap(), finalized.encoded());
        match finalized.operation() {
            V1Operation::Renew { state, .. } => {
                assert_eq!(state.record, predecessor.data.record);
                assert_eq!(state.lease_expiry, successor_lease_expiry);
                assert_eq!(state.status, StateStatus::Active);
                assert_eq!(state.terminal_height, 0);
            }
            other => panic!("unexpected operation kind: {other:?}"),
        }
        assert_eq!(
            renew_successor_note.rho().to_bytes(),
            predecessor_note.nullifier(&fvk).to_bytes()
        );

        let non_anchor_height = (reveal_height + 1..predecessor.data.lease_expiry)
            .find(|height| !coppice_names::v1::schedule::is_anchor_height(name_id, *height, params))
            .unwrap();
        assert!(prepare_renew(inputs(non_anchor_height, 1), params).is_err());
    }

    #[test]
    fn release_preserves_record_and_lease_and_terminates_at_operation_height() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(15);
        let registration_note = bond_note(&fvk, 40_000, 4, 5);
        let intent = test_intent(&ask, 5, 7);
        let (commit, reveal_height) = reveal_commit_and_height(&intent, params);
        let reveal_preparation = prepare_reveal(
            RevealInputs {
                intent,
                commit,
                replacement_predecessor: None,
                registration_note,
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: 2,
                operation_height: reveal_height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();
        let predecessor_note = reveal_preparation.successor_note().clone();
        let reveal_finalized = reveal_preparation.finalize(vec![0x5A; 1_920]).unwrap();
        let predecessor = accepted_head(reveal_finalized.operation(), reveal_height, [7; 32]);

        let release_height = reveal_height + 1;
        let release_preparation = prepare_release(
            TransitionInputs {
                predecessor: predecessor.clone(),
                predecessor_note: predecessor_note.clone(),
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                operation_height: release_height,
                designated_action_index: 0,
                successor_seed: [11; 32],
            },
            params,
        )
        .unwrap();

        let statement = release_preparation.statement();
        assert_eq!(statement.operation, OperationKind::Release);
        assert_eq!(
            statement.predecessor_ref_digest,
            predecessor.state_ref.digest()
        );
        assert_eq!(statement.predecessor_sequence, predecessor.data.sequence);
        assert_eq!(statement.successor_sequence, predecessor.data.sequence + 1);
        assert_eq!(
            statement.predecessor_record_digest,
            statement.successor_record_digest
        );
        assert_eq!(
            statement.successor_lease_expiry,
            predecessor.data.lease_expiry
        );
        assert_eq!(statement.predecessor_status, StateStatus::Active.code());
        assert_eq!(statement.successor_status, StateStatus::Released.code());
        assert_eq!(statement.predecessor_terminal_height, 0);
        assert_eq!(statement.successor_terminal_height, release_height);
        assert_eq!(statement.operation_height, release_height);

        let successor_commitment = statement.successor_commitment;
        let successor_future_nullifier = statement.successor_nullifier;
        let finalized = release_preparation.finalize(vec![0xA5; 1_920]).unwrap();
        let manual = V1Operation::Release {
            predecessor: predecessor.state_ref,
            state: StateData {
                name_id: predecessor.data.name_id,
                owner_pk: predecessor.data.owner_pk,
                sequence: predecessor.data.sequence + 1,
                record: predecessor.data.record.clone(),
                lease_expiry: predecessor.data.lease_expiry,
                status: StateStatus::Released,
                terminal_height: release_height,
            },
            state_commitment: successor_commitment,
            state_nullifier: successor_future_nullifier,
            action_index: 0,
            proof: vec![0xA5; 1_920],
        };
        assert_eq!(encode_operation(&manual).unwrap(), finalized.encoded());
        match finalized.operation() {
            V1Operation::Release { state, .. } => {
                assert_eq!(state.record, predecessor.data.record);
                assert_eq!(state.lease_expiry, predecessor.data.lease_expiry);
                assert_eq!(state.status, StateStatus::Released);
                assert_eq!(state.terminal_height, release_height);
            }
            other => panic!("unexpected operation kind: {other:?}"),
        }

        // A transition at or beyond the predecessor lease is invalid.
        let lease = predecessor.data.lease_expiry;
        assert!(
            prepare_release(
                TransitionInputs {
                    predecessor,
                    predecessor_note,
                    scope: Scope::External,
                    fvk: fvk.clone(),
                    ask: ask.clone(),
                    operation_height: lease,
                    designated_action_index: 0,
                    successor_seed: [11; 32],
                },
                params,
            )
            .is_err()
        );
    }

    #[test]
    fn state_operation_plan_matches_shape_fee_and_designated_pair() {
        let params = V1Parameters::testing();
        let consensus_params = local_v6_params();
        let (fvk, ask) = key_material(16);
        let registration_note = bond_note(&fvk, 40_000, 5, 6);
        let intent = test_intent(&ask, 5, 7);
        let (commit, reveal_height) = reveal_commit_and_height(&intent, params);
        let reveal_preparation = prepare_reveal(
            RevealInputs {
                intent,
                commit,
                replacement_predecessor: None,
                registration_note,
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: 2,
                operation_height: reveal_height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();
        let predecessor_note = reveal_preparation.successor_note().clone();
        let predecessor_nullifier = predecessor_note.nullifier(&fvk).to_bytes();
        let reveal_finalized = reveal_preparation.finalize(vec![0x5A; 1_920]).unwrap();
        let predecessor = accepted_head(reveal_finalized.operation(), reveal_height, [7; 32]);

        let update_height = reveal_height + 1;
        let update_preparation = prepare_update(
            TransitionInputs {
                predecessor,
                predecessor_note,
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                operation_height: update_height,
                designated_action_index: 3,
                successor_seed: [10; 32],
            },
            vec![6; 40],
            params,
        )
        .unwrap();
        let finalized = update_preparation.finalize(vec![0xA5; 1_920]).unwrap();

        let funding_note = bond_note(&fvk, 60_000, 6, 7);
        let carrier_recipient = key_material(30).0.address_at(0u32, Scope::External);
        let (shape, fee) =
            planned_state_operation_shape_and_fee(&consensus_params, &finalized, 1, 1).unwrap();
        let carrier_value_total = u64::try_from(finalized.frames().len()).unwrap();
        let change_value = funding_note
            .value()
            .inner()
            .checked_sub(carrier_value_total)
            .and_then(|value| value.checked_sub(fee.into_u64()))
            .unwrap();
        let planned = plan_state_operation(
            &consensus_params,
            &finalized,
            CarrierPlan {
                recipient: carrier_recipient,
                value: NoteValue::from_raw(1),
            },
            SuccessorTransport {
                ovk: None,
                memo: [0; 512],
            },
            OperationFunding {
                funding_spends: vec![FundingSpend {
                    fvk: fvk.clone(),
                    note: funding_note.clone(),
                }],
                change_outputs: vec![ChangeOutput {
                    fvk: fvk.clone(),
                    ovk: None,
                    recipient: fvk.address_at(0u32, Scope::Internal),
                    value: NoteValue::from_raw(change_value),
                    memo: [0; 512],
                }],
            },
        )
        .unwrap();
        assert_eq!(planned.planned_shape, shape);
        assert_eq!(planned.required_fee, fee);
        assert_eq!(planned.carrier_value_total, carrier_value_total);

        assert_eq!(
            planned.plan.designated_action_index as u32,
            finalized.designated_action_index()
        );
        assert_eq!(planned.plan.successor_note, *finalized.successor_note());
        assert_eq!(planned.plan.carrier_outputs.len(), finalized.frames().len());
        assert!(
            planned
                .plan
                .carrier_outputs
                .iter()
                .all(|carrier| carrier.recipient == carrier_recipient
                    && carrier.value == NoteValue::from_raw(1))
        );
        assert_eq!(
            planned.planned_shape,
            names_v1_ironwood_shape(&planned.plan).unwrap()
        );
        assert_eq!(
            planned.required_fee,
            required_zip317_fee_for_names_v1(
                &consensus_params,
                BlockHeight::from_u32(update_height),
                planned.planned_shape,
            )
            .unwrap()
        );

        let built = build_names_v1_bundle(planned.plan, StdRng::from_seed([77; 32])).unwrap();
        assert_eq!(built.action_count, planned.planned_shape.action_count);
        assert_eq!(
            built.ironwood_value_balance,
            i64::try_from(planned.required_fee.into_u64()).unwrap()
        );
        assert_eq!(built.designated_nullifier, predecessor_nullifier);
        assert_eq!(
            built.designated_commitment,
            ExtractedNoteCommitment::from(finalized.successor_note().commitment()).to_bytes()
        );
    }

    #[test]
    fn state_operation_plan_supports_zero_and_multi_note_funding() {
        let params = V1Parameters::testing();
        let consensus_params = local_v6_params();
        let (fvk, ask) = key_material(18);
        let carrier_recipient = key_material(31).0.address_at(0u32, Scope::External);

        // Zero additional funding spends cannot fund a fee: the designated
        // bond value returns intact to the successor output, so carrier
        // outputs and the fee must come from separate funding.
        let small_intent = RegistrationIntent {
            record: vec![5; 8],
            ..test_intent(&ask, 5, 7)
        };
        let designated_note = bond_note(&fvk, 40_000, 8, 9);
        let reveal_intent_commitment = small_intent.commitment().unwrap();
        let (reveal_commit, reveal_height) = {
            let commit_height = 30;
            (
                CommitRef::new(
                    ProducerPosition::new(commit_height, 1, [3; 32]),
                    0,
                    reveal_intent_commitment,
                ),
                next_anchor_height(small_intent.name_id().unwrap(), commit_height + 1, params)
                    .unwrap(),
            )
        };
        let reveal_preparation = prepare_reveal(
            RevealInputs {
                intent: small_intent,
                commit: reveal_commit,
                replacement_predecessor: None,
                registration_note: designated_note,
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: 2,
                operation_height: reveal_height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();
        let finalized = reveal_preparation.finalize(vec![0x5A; 320]).unwrap();
        assert!(finalized.frames().len() >= 1);
        let zero_funding = plan_state_operation(
            &consensus_params,
            &finalized,
            CarrierPlan {
                recipient: carrier_recipient,
                value: NoteValue::from_raw(1),
            },
            SuccessorTransport {
                ovk: None,
                memo: [0; 512],
            },
            OperationFunding {
                funding_spends: vec![],
                change_outputs: vec![],
            },
        );
        assert!(
            zero_funding.is_err(),
            "zero funding cannot pay the carriers and fee; must fail closed"
        );

        // Two funding notes with the change split across both owners balance
        // exactly like the single-note shape.
        let funding_one = bond_note(&fvk, 30_000, 10, 11);
        let funding_two = bond_note(&fvk, 40_000, 11, 12);
        let (shape, fee) =
            planned_state_operation_shape_and_fee(&consensus_params, &finalized, 2, 2).unwrap();
        let carrier_total = u64::try_from(finalized.frames().len()).unwrap();
        let change_one = 20_000u64;
        let change_two = funding_one
            .value()
            .inner()
            .checked_add(funding_two.value().inner())
            .and_then(|value| value.checked_sub(carrier_total))
            .and_then(|value| value.checked_sub(fee.into_u64()))
            .and_then(|value| value.checked_sub(change_one))
            .unwrap();
        let multi_funding = plan_state_operation(
            &consensus_params,
            &finalized,
            CarrierPlan {
                recipient: carrier_recipient,
                value: NoteValue::from_raw(1),
            },
            SuccessorTransport {
                ovk: None,
                memo: [0; 512],
            },
            OperationFunding {
                funding_spends: vec![
                    FundingSpend {
                        fvk: fvk.clone(),
                        note: funding_one.clone(),
                    },
                    FundingSpend {
                        fvk: fvk.clone(),
                        note: funding_two.clone(),
                    },
                ],
                change_outputs: vec![
                    ChangeOutput {
                        fvk: fvk.clone(),
                        ovk: None,
                        recipient: fvk.address_at(0u32, Scope::Internal),
                        value: NoteValue::from_raw(change_one),
                        memo: [0; 512],
                    },
                    ChangeOutput {
                        fvk: fvk.clone(),
                        ovk: None,
                        recipient: fvk.address_at(0u32, Scope::External),
                        value: NoteValue::from_raw(change_two),
                        memo: [0; 512],
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!(multi_funding.planned_shape, shape);
        let built = build_names_v1_bundle(multi_funding.plan, StdRng::from_seed([79; 32])).unwrap();
        assert_eq!(
            built.ironwood_value_balance,
            i64::try_from(multi_funding.required_fee.into_u64()).unwrap()
        );
        assert_eq!(built.real_spend_count, 3);

        // Unbalanced funding fails closed before any proving.
        let underfunded = plan_state_operation(
            &consensus_params,
            &finalized,
            CarrierPlan {
                recipient: carrier_recipient,
                value: NoteValue::from_raw(1),
            },
            SuccessorTransport {
                ovk: None,
                memo: [0; 512],
            },
            OperationFunding {
                funding_spends: vec![FundingSpend {
                    fvk: fvk.clone(),
                    note: funding_one.clone(),
                }],
                change_outputs: vec![],
            },
        );
        assert!(
            underfunded.is_err(),
            "unbalanced funding must fail at planning time"
        );
    }

    #[test]
    fn reveal_rejects_heights_outside_the_commit_lifetime_or_schedule() {
        let params = V1Parameters::testing();
        let (fvk, ask) = key_material(19);
        let registration_note = bond_note(&fvk, 40_000, 12, 13);
        let intent = test_intent(&ask, 5, 7);
        let name_id = intent.name_id().unwrap();
        let commit_height = 30;
        let commit = CommitRef::new(
            ProducerPosition::new(commit_height, 1, [3; 32]),
            0,
            intent.commitment().unwrap(),
        );
        let legal_height = next_anchor_height(name_id, commit_height + 1, params).unwrap();
        assert!(legal_height > commit_height);
        assert!(legal_height <= commit_height + params.commit_ttl_blocks);

        let inputs = |operation_height| RevealInputs {
            intent: intent.clone(),
            commit,
            replacement_predecessor: None,
            registration_note: registration_note.clone(),
            scope: Scope::External,
            fvk: fvk.clone(),
            ask: ask.clone(),
            designated_action_index: 2,
            operation_height,
            successor_seed: [9; 32],
        };

        // Same height as the COMMIT: rejected before any proof work.
        assert!(
            prepare_reveal(inputs(commit_height), params)
                .err()
                .unwrap()
                .to_string()
                .contains("strictly after the canonical COMMIT height")
        );
        // Beyond the COMMIT lifetime: rejected.
        assert!(
            prepare_reveal(inputs(commit_height + params.commit_ttl_blocks + 1), params)
                .err()
                .unwrap()
                .to_string()
                .contains("beyond the canonical COMMIT lifetime")
        );
        // Inside the lifetime but off the name's scheduled anchor: rejected.
        let non_anchor = (commit_height + 1..legal_height)
            .find(|height| !coppice_names::v1::schedule::is_anchor_height(name_id, *height, params))
            .expect("a scheduled anchor window contains non-anchor heights");
        assert!(
            prepare_reveal(inputs(non_anchor), params)
                .err()
                .unwrap()
                .to_string()
                .contains("scheduled anchor height")
        );
        // The legal scheduled height prepares.
        assert!(prepare_reveal(inputs(legal_height), params).is_ok());
    }

    #[test]
    fn finalized_operation_binds_fee_planning_and_pczt_expiry_to_its_height() {
        let params = V1Parameters::testing();
        let consensus_params = local_v6_params();
        let (fvk, ask) = key_material(20);
        let registration_note = bond_note(&fvk, 60_000, 14, 15);
        let intent = test_intent(&ask, 5, 7);
        let (commit, reveal_height) = reveal_commit_and_height(&intent, params);
        let preparation = prepare_reveal(
            RevealInputs {
                intent,
                commit,
                replacement_predecessor: None,
                registration_note: registration_note.clone(),
                scope: Scope::External,
                fvk: fvk.clone(),
                ask: ask.clone(),
                designated_action_index: 2,
                operation_height: reveal_height,
                successor_seed: [9; 32],
            },
            params,
        )
        .unwrap();
        assert_eq!(preparation.operation_height(), reveal_height);
        let finalized = preparation.finalize(vec![0x5A; 1_920]).unwrap();
        assert_eq!(finalized.operation_height(), reveal_height);

        // Fee planning carries no height argument: it plans at exactly the
        // finalized operation height.
        let (shape, fee) =
            planned_state_operation_shape_and_fee(&consensus_params, &finalized, 1, 1).unwrap();
        assert_eq!(
            fee,
            required_zip317_fee_for_names_v1(
                &consensus_params,
                BlockHeight::from_u32(reveal_height),
                shape,
            )
            .unwrap()
        );
        let carrier_recipient = key_material(32).0.address_at(0u32, Scope::External);
        let carrier_value_total = finalized.frames().len() as u64;
        let funding_note = bond_note(&fvk, 60_000, 16, 17);
        let planned = plan_state_operation(
            &consensus_params,
            &finalized,
            CarrierPlan {
                recipient: carrier_recipient,
                value: NoteValue::from_raw(1),
            },
            SuccessorTransport {
                ovk: None,
                memo: [0; 512],
            },
            OperationFunding {
                funding_spends: vec![FundingSpend {
                    fvk: fvk.clone(),
                    note: funding_note.clone(),
                }],
                change_outputs: vec![ChangeOutput {
                    fvk: fvk.clone(),
                    ovk: None,
                    recipient: fvk.address_at(0u32, Scope::Internal),
                    value: NoteValue::from_raw(
                        funding_note
                            .value()
                            .inner()
                            .checked_sub(carrier_value_total)
                            .and_then(|value| value.checked_sub(fee.into_u64()))
                            .unwrap(),
                    ),
                    memo: [0; 512],
                }],
            },
        )
        .unwrap();
        assert_eq!(planned.operation_height, reveal_height);
        assert_eq!(planned.carrier_value_total, carrier_value_total);

        let built = build_names_v1_bundle(planned.plan, StdRng::from_seed([80; 32])).unwrap();
        assert_eq!(built.operation_height, reveal_height);

        // A PCZT expiry height different from the Names operation height is
        // rejected before any PCZT construction. Each rebuilt bundle pairs its
        // own designated spend with a successor whose rho derives from it.
        let rebuilt = |operation_height, rho_byte: u8, seed_byte: u8| {
            let designated = bond_note(&fvk, 60_000, rho_byte, seed_byte);
            let successor = successor_state_note(
                &fvk,
                Scope::External,
                &designated,
                designated.nullifier(&fvk).to_bytes(),
                [9; 32],
            )
            .unwrap();
            build_names_v1_bundle(
                NamesV1IronwoodPlan {
                    designated_fvk: fvk.clone(),
                    designated_spend: designated,
                    successor_note: successor,
                    successor_ovk: None,
                    successor_memo: [0; 512],
                    carrier_outputs: Vec::new(),
                    funding_spends: vec![FundingSpend {
                        fvk: fvk.clone(),
                        note: bond_note(&fvk, 60_000, rho_byte + 1, seed_byte + 1),
                    }],
                    change_outputs: vec![ChangeOutput {
                        fvk: fvk.clone(),
                        ovk: None,
                        recipient: fvk.address_at(0u32, Scope::Internal),
                        value: NoteValue::from_raw(45_000),
                        memo: [0; 512],
                    }],
                    designated_action_index: 1,
                    operation_height,
                },
                StdRng::from_seed([rho_byte; 32]),
            )
            .unwrap()
        };
        let mismatched = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: rebuilt(reveal_height, 20, 21),
            params: consensus_params.clone(),
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(reveal_height + 1),
            fallback_lock_time: 0,
        });
        assert!(
            mismatched.is_err(),
            "PCZT expiry height must equal the Names operation height"
        );

        // The exact operation height builds the complete PCZT.
        let aligned = build_names_v1_pczt(NamesV1PcztPlan {
            ironwood: rebuilt(reveal_height, 22, 23),
            params: consensus_params,
            consensus_branch_id: BranchId::Nu6_3,
            expiry_height: BlockHeight::from_u32(reveal_height),
            fallback_lock_time: 0,
        });
        assert!(aligned.is_ok());
    }
}
