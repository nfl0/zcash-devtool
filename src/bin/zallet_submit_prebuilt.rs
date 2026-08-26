//! Submits preserved, externally finalized transaction bytes through Coppice's RPC adapter.

use coppice_zcash_rpc::{HttpTransport, ZcashRpcClient, ZcashRpcConfig};

fn main() {
    let raw = std::fs::read_to_string("/tmp/coppice-zallet-live.JpfYDC/prebuilt-extract.json")
        .expect("prebuilt extraction evidence");
    let response: serde_json::Value = serde_json::from_str(&raw).expect("extraction json");
    let bytes =
        hex::decode(response["result"]["hex"].as_str().expect("raw hex")).expect("raw hex bytes");
    let expected = "990e86667402478569c90c6d11916c8171f0a2023596ca688548ee9e1bae2320";
    assert_eq!(response["result"]["txid"].as_str(), Some(expected));
    let transport =
        HttpTransport::new(ZcashRpcConfig::new("http://127.0.0.1:20232")).expect("transport");
    let mut client = ZcashRpcClient::new(transport);
    let mut returned = client
        .submit_raw_transaction(&bytes)
        .expect("submit raw transaction");
    returned.reverse();
    assert_eq!(hex::encode(returned), expected);
    println!("submitted_txid={}", expected);
    println!("raw_len={}", bytes.len());
}
