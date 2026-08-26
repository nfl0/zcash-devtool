//! Emits the frozen CA01/CPV1 memo frame for the live Receipts WATCH.

use coppice::{identity::CoreRuntimeId, publish::PreparedApplicationPublication};
use coppice_names::{
    config::{DeploymentParameters, Rendezvous},
    names_application::names_v1_core_runtime_parameters,
};
use coppice_receipts::{ReceiptsApplication, RequiredBundleFlags, WatchRequest};
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::NetworkType;

fn deployment() -> DeploymentParameters {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../coppice-names/test-vectors/deployment.json"
    ))
    .expect("deployment vector");
    let input = &fixture["input"];
    DeploymentParameters {
        network_id: hex::decode(input["network_id_hex"].as_str().expect("network id"))
            .expect("network id hex"),
        address_network: NetworkType::Regtest,
        activation_height: input["activation_height"].as_u64().expect("activation") as u32,
        minimum_bond_value: input["minimum_bond_value"].as_u64().expect("minimum"),
        commit_ttl_blocks: input["commit_ttl_blocks"].as_u64().expect("ttl") as u32,
        reuse_delay_blocks: input["reuse_delay_blocks"].as_u64().expect("reuse") as u32,
        bond_note_max_age_blocks: input["bond_note_max_age_blocks"].as_u64().expect("age") as u32,
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(input["rendezvous_ivk_hex"].as_str().expect("ivk"))
                .expect("ivk hex")
                .try_into()
                .expect("ivk len"),
            orchard_receiver: hex::decode(
                input["rendezvous_receiver_hex"].as_str().expect("receiver"),
            )
            .expect("receiver hex")
            .try_into()
            .expect("receiver len"),
        },
    }
}

fn main() {
    let nullifier: [u8; 32] =
        hex::decode("1f7780de3acbf7b2c2dbe12db0245a3f0863b17f5eca7acdb1673240fce42926")
            .expect("nullifier hex")
            .try_into()
            .expect("nullifier len");
    let deployment = deployment();
    let parameters = names_v1_core_runtime_parameters(&deployment).expect("names core parameters");
    let runtime_id: CoreRuntimeId = parameters.core_runtime_id();
    let receipt_id = *b"zallet-watch-live-receipt-id-000";
    let request = WatchRequest::new(receipt_id, nullifier, RequiredBundleFlags::spends_enabled());
    let app = ReceiptsApplication::new(
        deployment.activation_height,
        coppice::application::ApplicationTip {
            height: deployment.activation_height - 1,
            block_hash: [0; 32],
        },
        16,
    )
    .expect("receipts app");
    let publication: PreparedApplicationPublication = app
        .prepare_watch_publication(runtime_id, request)
        .expect("publication");
    assert_eq!(
        publication.frames().len(),
        1,
        "WATCH must fit one CPV1 frame"
    );
    println!("runtime_id={}", hex::encode(runtime_id.to_bytes()));
    println!("receipt_id={}", hex::encode(receipt_id));
    println!("ca01_len={}", publication.envelope().len());
    println!("ca01_hex={}", hex::encode(publication.envelope()));
    println!("cpv1_frames={}", publication.frames().len());
    println!("memo_len={}", publication.frames()[0].len());
    println!("memo_hex={}", hex::encode(publication.frames()[0]));
    let orchard = orchard::Address::from_raw_address_bytes(&deployment.rendezvous.orchard_receiver)
        .expect("configured rendezvous receiver");
    let ua = UnifiedAddress::from_receivers(Some(orchard), None, None).expect("orchard-only UA");
    println!(
        "rendezvous_ua={}",
        ua.to_zcash_address(NetworkType::Regtest)
    );
}
