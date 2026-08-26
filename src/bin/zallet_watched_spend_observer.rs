//! Narrow live qualification: a Zallet-built WATCH followed by an externally finalized spend.

use coppice::{
    application::ApplicationTip, compositor::CoppiceRuntime, replay::CoreReplayActivationCheckpoint,
};
use coppice_librustzcash::{
    CanonicalBlockSource, CanonicalTip, FullTransactionSource, prepare_canonical_block,
};
use coppice_names::{
    config::{DeploymentParameters, Rendezvous},
    names_runtime::{NamesRuntime, NamesTransactionOutcome},
};
use coppice_receipts::{ReceiptsApplication, WatchOutcome};
use coppice_zcash_rpc::{
    HttpTransport, HttpTransportError, RpcAdapterConfig, RpcCanonicalBlockSource, RpcError,
    RpcTransport, ZcashRpcClient, ZcashRpcConfig,
};
use serde_json::{Value, json};
use std::{cell::RefCell, rc::Rc};
use zcash_protocol::{
    consensus::{BlockHeight, NetworkType},
    local_consensus::LocalNetwork,
};

const ENDPOINT: &str = "http://127.0.0.1:20232";
const WATCH: &str = "493c11641817cd6152844440772fd85f5a843a3a75aff03cc49ee4909ca44f9f";
const SPEND: &str = "990e86667402478569c90c6d11916c8171f0a2023596ca688548ee9e1bae2320";
const WATCHED_NULLIFIER: &str = "1f7780de3acbf7b2c2dbe12db0245a3f0863b17f5eca7acdb1673240fce42926";
type Source = RpcCanonicalBlockSource<LocalNetwork, HttpTransport>;
type SourceError = RpcError<HttpTransportError>;

#[derive(Clone)]
struct Shared(Rc<RefCell<Source>>);
impl CanonicalBlockSource for Shared {
    type Error = SourceError;
    fn canonical_tip(&mut self) -> Result<CanonicalTip, Self::Error> {
        self.0.borrow_mut().canonical_tip()
    }
    fn compact_block(
        &mut self,
        h: u32,
    ) -> Result<Option<zcash_client_backend::proto::compact_formats::CompactBlock>, Self::Error>
    {
        self.0.borrow_mut().compact_block(h)
    }
}
impl FullTransactionSource for Shared {
    type Error = SourceError;
    fn full_transaction(&mut self, t: [u8; 32]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.borrow_mut().full_transaction(t)
    }
}
fn params() -> LocalNetwork {
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
    }
}
fn deployment() -> DeploymentParameters {
    let v: Value = serde_json::from_str(include_str!(
        "../../../coppice-names/test-vectors/deployment.json"
    ))
    .unwrap();
    let i = &v["input"];
    DeploymentParameters {
        network_id: hex::decode(i["network_id_hex"].as_str().unwrap()).unwrap(),
        address_network: NetworkType::Regtest,
        activation_height: i["activation_height"].as_u64().unwrap() as u32,
        minimum_bond_value: i["minimum_bond_value"].as_u64().unwrap(),
        commit_ttl_blocks: i["commit_ttl_blocks"].as_u64().unwrap() as u32,
        reuse_delay_blocks: i["reuse_delay_blocks"].as_u64().unwrap() as u32,
        bond_note_max_age_blocks: i["bond_note_max_age_blocks"].as_u64().unwrap() as u32,
        rendezvous: Rendezvous {
            orchard_ivk: hex::decode(i["rendezvous_ivk_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            orchard_receiver: hex::decode(i["rendezvous_receiver_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    }
}
fn source() -> Shared {
    Shared(Rc::new(RefCell::new(RpcCanonicalBlockSource::new(
        params(),
        ZcashRpcClient::new(HttpTransport::new(ZcashRpcConfig::new(ENDPOINT)).unwrap()),
        RpcAdapterConfig::new(NetworkType::Regtest, 9),
    ))))
}
fn display(mut id: [u8; 32]) -> String {
    id.reverse();
    hex::encode(id)
}
fn rpc(method: &str, params: Value) -> Value {
    let mut t = HttpTransport::new(ZcashRpcConfig::new(ENDPOINT)).unwrap();
    let b = serde_json::to_vec(&json!({"jsonrpc":"1.0","id":1,"method":method,"params":params}))
        .unwrap();
    let v: Value = serde_json::from_slice(&t.send(&b).unwrap()).unwrap();
    assert!(v["error"].is_null(), "{v}");
    v["result"].clone()
}
fn main() {
    let mut source = source();
    let checkpoint: CoreReplayActivationCheckpoint =
        source.0.borrow_mut().activation_checkpoint(10).unwrap();
    let names = NamesRuntime::from_names_deployment(deployment(), checkpoint).unwrap();
    let tip = ApplicationTip {
        height: 9,
        block_hash: names.core().tip().block_hash,
    };
    let receipts = ReceiptsApplication::new(10, tip, 16).unwrap();
    let mut runtime =
        CoppiceRuntime::new(names.core().clone(), (names.names().clone(), receipts)).unwrap();
    for h in 10..=115 {
        let b = source.compact_block(h).unwrap().unwrap();
        let input = prepare_canonical_block(&params(), &runtime, &b, &mut source).unwrap();
        if h == 115 {
            let tx = input
                .transactions
                .iter()
                .find(|t| display(t.txid) == WATCH)
                .unwrap();
            assert_eq!(format!("{:?}", tx.full_transaction_acquisition), "Carrier");
            assert!(tx.full_transaction.is_some());
            println!(
                "watch height={} index={} acquisition={:?}",
                h, tx.tx_index, tx.full_transaction_acquisition
            );
        }
        let applied = runtime.apply_block(&input).unwrap();
        if h == 115 {
            let index = input
                .transactions
                .iter()
                .find(|tx| display(tx.txid) == WATCH)
                .unwrap()
                .tx_index as usize;
            assert_eq!(
                applied.applications.0.transaction_outcomes[index],
                NamesTransactionOutcome::NoOperation
            );
            assert_eq!(
                applied.applications.1.transaction_outcomes[index].watch,
                WatchOutcome::Accepted
            );
        }
    }
    assert_eq!(runtime.applications().1.active_watches().len(), 1);
    println!(
        "watch installed root={}",
        hex::encode(runtime.applications().1.state_root())
    );
    let raw: Value = serde_json::from_str(
        &std::fs::read_to_string("/tmp/coppice-zallet-live.JpfYDC/prebuilt-extract.json").unwrap(),
    )
    .unwrap();
    let bytes = hex::decode(raw["result"]["hex"].as_str().unwrap()).unwrap();
    assert_eq!(raw["result"]["txid"].as_str(), Some(SPEND));
    let mut c = ZcashRpcClient::new(HttpTransport::new(ZcashRpcConfig::new(ENDPOINT)).unwrap());
    let returned = display(c.submit_raw_transaction(&bytes).unwrap());
    assert_eq!(returned, SPEND);
    println!("submitted_txid={returned} raw_len={}", bytes.len());
    rpc("generate", json!([1]));
    let h = 116;
    let b = source.compact_block(h).unwrap().unwrap();
    let input = prepare_canonical_block(&params(), &runtime, &b, &mut source).unwrap();
    let tx = input
        .transactions
        .iter()
        .find(|t| display(t.txid) == SPEND)
        .unwrap();
    assert_eq!(
        format!("{:?}", tx.full_transaction_acquisition),
        "ExtendedEffects"
    );
    assert!(tx.full_transaction.is_some());
    assert!(
        tx.ironwood_nullifiers
            .iter()
            .any(|nullifier| hex::encode(nullifier) == WATCHED_NULLIFIER)
    );
    println!(
        "spend height={} index={} acquisition={:?}",
        h, tx.tx_index, tx.full_transaction_acquisition
    );
    let index = tx.tx_index as usize;
    let applied = runtime.apply_block(&input).unwrap();
    let core_tx = applied
        .core
        .core()
        .transactions()
        .iter()
        .find(|tx| display(tx.txid()) == SPEND)
        .unwrap();
    assert!(core_tx.ironwood_effects().extended().is_some());
    assert!(
        core_tx
            .ironwood_effects()
            .nullifiers()
            .iter()
            .any(|nullifier| hex::encode(nullifier) == WATCHED_NULLIFIER)
    );
    assert_eq!(
        applied.applications.0.transaction_outcomes[index],
        NamesTransactionOutcome::NoOperation
    );
    assert_eq!(
        applied.applications.1.transaction_outcomes[index].watch,
        WatchOutcome::NoMessage
    );
    assert_eq!(
        applied.applications.1.transaction_outcomes[index]
            .settled_receipt_ids
            .len(),
        1
    );
    assert!(runtime.applications().1.active_watches().is_empty());
    println!(
        "settled root={}",
        hex::encode(runtime.applications().1.state_root())
    );
}
